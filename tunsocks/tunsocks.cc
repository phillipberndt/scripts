// tunsocks -- Tunnel a process through a socks server
// Copyright (c) 2016, Phillip Berndt
//
// This is a new approach: The program sets up a TUN device inside an anonymous
// network namespace and relays all traffic through that device to the proxy.
// The device is set as the namespace's default route. The target process is
// then started within said namespace.
//
// This has some benefits over existing solutions:
//
// tsocks uses LD_PRELOAD to patch the socket() etc. calls. This can be easily
// circumvented.
//
// redsocks does transparent proxying by using iptables' REDIRECT. This is
// feasible for system-wide redirection, but it is hard to isolate a single
// process. The only options to to that were either to use a different UID,
// which is pretty secure, but also restricts what you can to with the
// process in other ways, or to use network namespaces with virtual devices,
// and to set up the rule only for traffic from the endpoint in the global
// namespace. It is a pain to configure this.
//
// It should be noted that programs opening a TUN device and forwarding
// everything to a SOCKS server exist. See e.g.
//  https://github.com/ambrop72/badvpn/blob/master/tun2socks/
// This program therefore does not expose the functionality to *only* set up a
// tunnel to the user.
//
// For information on the SOCKS5 protocol, see http://tools.ietf.org/html/rfc1928
//
// TODO:
//  * Add ipv6 support
//  * Add a DNS cache (all requests are currently relayed to TCP DNS)
//  * Add UDP support (not included currently, because the author's main
//    application is tunneling through SSH, which does not support SSH)
//  * Adjust the different MTUs assumed all over the code to match ;-)
//
#include <string>
#include <stdexcept>
#include <iostream>
#include <functional>
#include <map>
#include <tuple>

#include <tins/tins.h>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include <netinet/ip.h>
#include <linux/if_tun.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

namespace linux_route {
	// This must be placed into its own namespace, because tins also pollutes
	// the global namespace. Not a problem though, because only a struct from
	// this header is used below.
	#include <linux/route.h>
}

const std::string status_prefix = "\033[1m[\033[31m*\033[0;1m]\033[0m ";

class TunDevice {
	// Encapsulation of a TUN device. Takes care of setting a (fixed) IP and
	// setting up a default route through the tunnel. Currently IPv4 only.

	public:
		typedef std::function<void(Tins::IP)> packet_handler;

		const std::string tun_ip = "10.2.3.4";
		const std::string tun_endpoint = "10.2.3.5";

	private:
		boost::asio::posix::stream_descriptor stream_descriptor;
		std::string if_name;
		uint8_t readbuf[1500];
		packet_handler handler_function;

		void async_read_packet() {
			stream_descriptor.async_read_some(boost::asio::buffer(readbuf),
					boost::bind(&TunDevice::read_packet_done, this, boost::asio::placeholders::error,
						boost::asio::placeholders::bytes_transferred));
		}

		void read_packet_done(const boost::system::error_code& error, size_t bytes_transferred) {
			if(error) {
				throw std::runtime_error("Failed to read from TUN device");
			}

			if(readbuf[2] == 8 /* IPv4 packet */) {
				handler_function(Tins::IP(&readbuf[4], bytes_transferred - 4));
			}

			async_read_packet();
		}

		void assign_tun_ip() {
			int sock = socket(AF_INET, SOCK_DGRAM, 0);

			struct ifreq ifr;
			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ);
			ifr.ifr_addr.sa_family = AF_INET;
			struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;

			inet_pton(AF_INET, tun_ip.c_str(), &addr->sin_addr);
			ioctl(sock, SIOCSIFADDR, &ifr);

			inet_pton(AF_INET, tun_endpoint.c_str(), &addr->sin_addr);
			ioctl(sock, SIOCSIFDSTADDR, &ifr);

			ifr.ifr_mtu = 1492 - 10; // SOCKS5 header has 10 bytes; not really
			                         // necessary, because UDP isn't supported anyway
			                         // and TCP only sends the header in the first packet
			ioctl(sock, SIOCSIFMTU, (caddr_t)&ifr);

			ioctl(sock, SIOCGIFFLAGS, &ifr);
			ifr.ifr_flags |= (IFF_UP | IFF_RUNNING | IFF_POINTOPOINT);
			ioctl(sock, SIOCSIFFLAGS, &ifr);

			close(sock);
		}

		void assign_tun_route() {
			int sock = socket(AF_INET, SOCK_DGRAM, 0);

			struct linux_route::rtentry rt;

			struct sockaddr_in *sockinfo = (struct sockaddr_in *)&rt.rt_gateway;
			sockinfo->sin_family = AF_INET;
			inet_pton(AF_INET, tun_endpoint.c_str(), &sockinfo->sin_addr);

			sockinfo = (struct sockaddr_in *)&rt.rt_dst;
			sockinfo->sin_family = AF_INET;
			sockinfo->sin_addr.s_addr = INADDR_ANY;

			sockinfo = (struct sockaddr_in *)&rt.rt_genmask;
			sockinfo->sin_family = AF_INET;
			sockinfo->sin_addr.s_addr = INADDR_ANY;

			rt.rt_flags = RTF_UP | RTF_GATEWAY;
			rt.rt_dev = NULL;

			ioctl(sock, SIOCADDRT, &rt);
			close(sock);
		}


	public:
		TunDevice(boost::asio::io_service &io_service, packet_handler receiver) : stream_descriptor(io_service), handler_function(receiver) {
			int tun_fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
			if(tun_fd < 0) {
				throw std::runtime_error("Failed to open tun device node /dev/net/tun");
			}

			struct ifreq ifr;
			memset(&ifr, 0, sizeof(ifr));
			ifr.ifr_flags = IFF_TUN;
			if(ioctl(tun_fd, TUNSETIFF, &ifr) < 0) {
				close(tun_fd);
				throw std::runtime_error("Failed to create tun device");
			}
			if_name = ifr.ifr_name;

			assign_tun_ip();
			assign_tun_route();

			stream_descriptor.assign(tun_fd);
			async_read_packet();
		}

		const std::string &device() {
			return if_name;
		}

		void send_packet(const std::vector<uint8_t> &packet) {
			uint8_t *packet_copy = new uint8_t[4 + packet.size()];
			packet_copy[0] = 0;
			packet_copy[1] = 0;
			packet_copy[2] = 8;
			packet_copy[3] = 0;
			std::copy(packet.begin(), packet.end(), &packet_copy[4]);

			boost::asio::async_write(stream_descriptor, boost::asio::buffer(packet_copy, 4 + packet.size()),
					[packet_copy] (const boost::system::error_code& error, std::size_t bytes_transferred) {
						delete[] packet_copy;
					}
			);
		}

		void send_packet(Tins::IP &packet) {
			send_packet(packet.serialize());
		}
};

class ProxiedConnection {
	// Abstract base class for proxied connections.

	private:
		std::array<uint8_t, 4096> socks_receive_buffer;
		boost::asio::ip::tcp::endpoint socks_address;

		void socks_receive_handler(const boost::system::error_code& error, std::size_t bytes_transferred) {
			if(error) {
				on_socks_connection_lost();
				return;
			}
			handle_socks_packet(std::vector<uint8_t>(&socks_receive_buffer[0], &socks_receive_buffer[bytes_transferred]));
			socks_socket.async_receive(boost::asio::buffer(&socks_receive_buffer[0], socks_receive_buffer.size()), boost::bind(&ProxiedConnection::socks_receive_handler, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
		}

	protected:
		boost::asio::ip::tcp::socket socks_socket;
		Tins::IP response_template;
		TunDevice *link;

		// The close callback is invoked when the object decides it reached its
		// end of life. It should delete it.
		std::function<void()> close_callback;

		// Called when the connection through socks is established
		virtual void on_connected() { };

		// Called when the connection through socks cannot be established
		virtual void on_connect_failure() { };

		// Called when the socks server closed the connection
		virtual void on_socks_connection_lost() { };

		void socks_connect(uint8_t cmd, uint32_t target_address, uint32_t port) {
			// Connect to socks
			socks_socket.async_connect(socks_address, [this, cmd, target_address, port] (const boost::system::error_code& error) {
				if(error) {
					std::cerr << status_prefix << "Failed to connect to socks proxy " << socks_address << "\n";
					on_connect_failure();
					close_callback();
					return;
				}

				boost::asio::socket_base::enable_connection_aborted option(true);
				socks_socket.set_option(option);

				// Authenticate
				boost::asio::write(socks_socket, boost::asio::buffer(std::vector<uint8_t> { 5, 1, 0 })); // Version 5, one auth method, namely 0 == no authenentication
				socks_socket.async_receive(boost::asio::buffer(&socks_receive_buffer[0], 2), [this, cmd, target_address, port] (const boost::system::error_code& error, std::size_t bytes_transferred) {
					if(error || socks_receive_buffer[0] != 5 || socks_receive_buffer[1] != 0) {
						std::cerr << status_prefix << "Socks proxy refuses authentication attempt\n";
						on_connect_failure();
						close_callback();
						return;
					}

					// Proxy connect command
					std::vector<uint8_t> connection_request;
					connection_request.push_back(5);   // Version 5
					connection_request.push_back(cmd); // Command: 1 is connect, 3 UDP connect
					connection_request.push_back(0);   // Reserved
					connection_request.push_back(1);   // Address type: v4 address
					connection_request.push_back((target_address & 0xff));
					connection_request.push_back((target_address & 0xff00) >> 8);
					connection_request.push_back((target_address & 0xff0000) >> 16);
					connection_request.push_back((target_address & 0xff000000) >> 24);   // v4 address: 4 bytes
					connection_request.push_back((port & 0xff00) >> 8);                     // v4 port: 2 bytes
					connection_request.push_back(port & 0x00ff);

					boost::asio::write(socks_socket, boost::asio::buffer(connection_request));

					socks_socket.async_receive(boost::asio::buffer(&socks_receive_buffer[0], 10), [this, cmd, port] (const boost::system::error_code& error, std::size_t bytes_transferred) {
						if(socks_receive_buffer[1] == 0) {
							on_connected();
							socks_socket.async_receive(boost::asio::buffer(&socks_receive_buffer[0], 4096), boost::bind(&ProxiedConnection::socks_receive_handler, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
						}
						else {
							std::cerr << status_prefix << "Connection to " << response_template.src_addr().to_string() << ":" << port << " through proxy failed\n";
							on_connect_failure();
							close_callback();
							return;
						}
					});
				});
			});
		}

		virtual void handle_socks_packet(const std::vector<uint8_t> packet) = 0;

	public:
		ProxiedConnection(TunDevice *link, std::function<void()> close_callback, Tins::IP &packet, boost::asio::io_service &io_service, boost::asio::ip::tcp::endpoint socks_address)
				: link(link), close_callback(close_callback), socks_socket(io_service), socks_address(socks_address) {
			response_template.protocol(packet.protocol());
			response_template.src_addr(packet.dst_addr());
			response_template.dst_addr(packet.src_addr());

			if(!this->close_callback) {
				this->close_callback = [this]() { delete this; };
			}
		}

		virtual ~ProxiedConnection() {
		}

		virtual void handle_tun_packet(Tins::IP packet) = 0;
};

class ProxiedTCPConnection : public ProxiedConnection {
	// This class encapsulates an open TCP connection through the proxy
	// The implementation optimistically assumes that package loss cannot
	// happen within a TUN, e.g., everything is acknowledged and nothing is
	// ever resent.

	uint32_t tcp_seq, tcp_ack_seq;
	std::vector<uint8_t> outstanding_data;
	bool fin_sent;
	bool fin_received;

	protected:
		virtual void on_connect_failure() {
			auto reply = response_template.clone();
			auto reply_tcp = reply->find_pdu<Tins::TCP>();
			reply_tcp->flags(Tins::TCP::RST);
			link->send_packet(*reply);
			delete reply;
		};

		virtual void on_connected() {
			auto reply = response_template.clone();
			auto reply_tcp = reply->find_pdu<Tins::TCP>();
			reply_tcp->flags(Tins::TCP::ACK | Tins::TCP::SYN);
			link->send_packet(*reply);
			delete reply;

			tcp_seq++;

			if(!outstanding_data.empty()) {
				boost::asio::write(socks_socket, boost::asio::buffer(outstanding_data));
				outstanding_data.clear();
			}
		};

		virtual void on_socks_connection_lost() {
			auto reply = response_template.clone();
			auto reply_tcp = reply->find_pdu<Tins::TCP>();
			reply_tcp->flags(Tins::TCP::FIN | Tins::TCP::ACK);
			reply_tcp->seq(tcp_seq);
			link->send_packet(*reply);

			tcp_seq++;

			fin_sent = true;
			if(fin_received) {
				close_callback();
			}
		};

		virtual void handle_socks_packet(const std::vector<uint8_t> packet) {
			if(fin_sent) {
				return;
			}

			auto reply = response_template.clone();
			auto reply_tcp = reply->find_pdu<Tins::TCP>();
			reply_tcp->flags(Tins::TCP::ACK);
			reply_tcp->ack_seq(tcp_ack_seq);
			reply_tcp->seq(tcp_seq);
			reply_tcp /= Tins::RawPDU(&packet[0], packet.size());
			link->send_packet(*reply);
			delete reply;

			tcp_seq += packet.size();
		}

	public:
		ProxiedTCPConnection(TunDevice *link, std::function<void()> close_callback, Tins::IP &packet, boost::asio::io_service &io_service, boost::asio::ip::tcp::endpoint socks_address)
				: ProxiedConnection(link, close_callback, packet, io_service, socks_address), tcp_seq(0), fin_sent(false), fin_received(false) {

			auto tcp = packet.find_pdu<Tins::TCP>();
			Tins::TCP template_tcp(tcp->sport(), tcp->dport());
			tcp_ack_seq = tcp->seq() + 1;
			template_tcp.ack_seq(tcp_ack_seq);
			template_tcp.flags(Tins::TCP::ACK);
			response_template /= template_tcp;

			if(tcp->flags() == Tins::TCP::ACK) {
				// Ignore plain ACKs. This is a hack to simplify termination
				// handling: We do not have to wait for the final
				// acknowledgement. (This works on the assumption that a
				// tun device will never loose packets.)
				close_callback();
				return;
			}

			if(tcp->flags() != Tins::TCP::SYN) {
				auto reply = response_template.clone();
				auto reply_tcp = reply->find_pdu<Tins::TCP>();
				reply_tcp->flags(Tins::TCP::RST);
				reply_tcp->ack_seq(0);
				reply_tcp->seq(0);
				link->send_packet(*reply);
				delete reply;
				close_callback();
				return;
			}

			try {
				const Tins::RawPDU& raw = tcp->rfind_pdu<Tins::RawPDU>();
				outstanding_data = raw.payload();
			}
			catch(Tins::pdu_not_found) {
				// Safe to ignore; initial SYN had no payload
			}

			socks_connect(1 /* CONNECT */, packet.dst_addr(), tcp->dport());
		}

		void handle_tun_packet(Tins::IP packet) {
			auto tcp = packet.find_pdu<Tins::TCP>();

			bool ack_sent = false;
			try {
				const Tins::RawPDU& raw = tcp->rfind_pdu<Tins::RawPDU>();
				const Tins::RawPDU::payload_type& payload = raw.payload();

				auto template_tcp = response_template.find_pdu<Tins::TCP>();
				template_tcp->seq(tcp_seq);
				template_tcp->ack_seq(tcp->seq() + payload.size());

				link->send_packet(response_template);
				ack_sent = true;

				boost::asio::write(socks_socket, boost::asio::buffer(payload));
			}
			catch(Tins::pdu_not_found) {
				// Safe to ignore, e.g. ACKs and FINs do not have to have a payload
			}

			if(tcp->flags() & Tins::TCP::FIN) {
				fin_received = true;
				if(!ack_sent) {
					auto template_tcp = response_template.find_pdu<Tins::TCP>();
					template_tcp->seq(tcp_seq);
					template_tcp->ack_seq(tcp->seq() + 1);
					link->send_packet(response_template);
				}
				if(fin_sent) {
					socks_socket.close();
					close_callback();
				}
				else {
					socks_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
				}
			}
		}
};

class ProxiedUDPDNSConnection : public ProxiedConnection {
	// This class encapsulates UDP DNS requests: The are relayed to the same
	// server via TCP, and the answer is then sent back as UDP.

	std::vector<uint8_t> outstanding_data;

	protected:
		virtual void handle_socks_packet(const std::vector<uint8_t> packet) {
			response_template /= Tins::RawPDU(&packet[2], packet.size() - 2);
			link->send_packet(response_template);
			socks_socket.close();
		}

		virtual void on_socks_connection_lost() {
			close_callback();
		}

		virtual void on_connected() {
			uint16_t length = htons(outstanding_data.size());
			std::vector<boost::asio::const_buffer> buffers;
			buffers.push_back(boost::asio::buffer(&length, sizeof(uint16_t)));
			buffers.push_back(boost::asio::buffer(outstanding_data));
			boost::asio::write(socks_socket, buffers);
		}

	public:
		ProxiedUDPDNSConnection(TunDevice *link, std::function<void()> close_callback, Tins::IP &packet, boost::asio::io_service &io_service, boost::asio::ip::tcp::endpoint socks_address)
				: ProxiedConnection(link, close_callback, packet, io_service, socks_address) {
			auto udp = packet.find_pdu<Tins::UDP>()->clone();
			Tins::UDP template_udp(udp->sport(), udp->dport());
			response_template /= template_udp;

			try {
				const Tins::RawPDU& raw = udp->rfind_pdu<Tins::RawPDU>();
				outstanding_data = raw.payload();
			}
			catch(Tins::pdu_not_found) {
				close_callback();
				return;
			}

			// Redirect requests to 127.0.0.0/8 to Google's DNS
			uint32_t target_address = packet.dst_addr();
			if(packet.dst_addr().is_loopback()) {
				target_address = Tins::IPv4Address("8.8.8.8");
			}

			socks_connect(1, target_address, udp->dport());
		}

		void handle_tun_packet(Tins::IP packet) {
			// Deliberately empty - this class's objects aren't added to the connections map
		}
};

void tun2socks_main(boost::asio::ip::tcp::endpoint socks_address, int namespace_fd) {
	// Main function for the TUN device driver

	boost::asio::io_service io_service;

	// This map holds all open connections, which are handled by ProxiedConnection instances
	std::map<std::tuple<uint16_t, uint16_t, uint32_t, uint16_t>, std::unique_ptr<ProxiedConnection>> connections;

	// If a namespace was given, switch to it now such that the tunnel is created within
	int original_namespace = 0;
	if(namespace_fd > -1) {
		original_namespace = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
		setns(namespace_fd, CLONE_NEWNET);
	}

	TunDevice link(io_service, [&](Tins::IP packet) {
		// Handler function for incoming packets
		if(packet.protocol() == IPPROTO_ICMP) {
			// Reply to all echo requests
			auto icmp = packet.find_pdu<Tins::ICMP>();
			if(icmp->type() == Tins::ICMP::ECHO_REQUEST) {
				Tins::IP::address_type old_src = packet.src_addr();
				packet.src_addr(packet.dst_addr());
				packet.dst_addr(old_src);

				icmp->type(Tins::ICMP::ECHO_REPLY);
				link.send_packet(packet);
			}
		}
		else if(packet.protocol() == IPPROTO_TCP) {
			auto tcp = packet.find_pdu<Tins::TCP>();
			auto identifier = std::make_tuple<uint16_t, uint16_t, uint32_t, uint16_t>(IPPROTO_TCP, tcp->sport(), packet.dst_addr(), tcp->dport());

			try {
				connections.at(identifier)->handle_tun_packet(packet);
			}
			catch (const std::out_of_range &oor) {
				connections.emplace(std::make_pair(identifier, std::unique_ptr<ProxiedConnection>(new ProxiedTCPConnection(&link, [&connections, identifier]() { connections.erase(identifier); }, packet, io_service, socks_address))));
			}
		}
		else if(packet.protocol() == IPPROTO_UDP) {
			auto udp = packet.find_pdu<Tins::UDP>();
			auto identifier = std::make_tuple<uint16_t, uint16_t, uint32_t, uint16_t>(IPPROTO_UDP, udp->sport(), packet.dst_addr(), udp->dport());

			// UDP forwarding is currently not implemented, but could by easily
			// by subclassing ProxiedConnection. Tunneling through SSH is my main
			// application for this program, and SSH does not support UDP, so
			// this isn't a priority for me.

			if(udp->dport() == 53) {
				// DNS, on the other hand, must work. Relay DNS requests to
				// TCP. Since UDP is stateless and one packet == one request,
				// do not place the connection into the connections map.
				// Instead, just create an anonymous instance that later
				// deletes itself.
				new ProxiedUDPDNSConnection(&link, nullptr, packet, io_service, socks_address);
			}
		}
	});

	// Switch back to the old namespace such that socks connections are opened
	// outside the jailed one.
	if(namespace_fd > -1) {
		setns(original_namespace, CLONE_NEWNET);
		close(original_namespace);
	}

	// Also, now that the TUN device is opened, privileges are no longer
	// required.
	setresgid((gid_t)65534, (gid_t)65534, (gid_t)65534);
	setresuid((uid_t)65534, (uid_t)65534, (uid_t)65534);

	io_service.run();
}

int main(int argc, char *argv[]) {
	int status;
	boost::asio::ip::tcp::endpoint socks_address(boost::asio::ip::address::from_string("127.0.0.1"), 8080);
	char **target_argv = &argv[1];

	if(geteuid() != 0) {
		std::cerr << "This program must be SETUID root. It will drop privileges before running the target process.\n";
		return 1;
	}

	bool help_required = argc < 2;
	if(argc >= 2) {
		if(argv[1][0] == '-') {
			help_required = true;
		}
		else if(argv[1][0] == '@') {
			std::string target = &argv[1][1];
			size_t colon_pos = target.find(":");
			if(colon_pos == std::string::npos) {
				help_required = true;
			}
			else {
				std::string host = target.substr(0, colon_pos);
				std::string port = target.substr(colon_pos + 1);
				if(port.empty()) port = "8080";
				if(host.empty()) host = "127.0.0.1";

				boost::asio::io_service io_service;
				boost::asio::ip::tcp::resolver resolver(io_service);
				try {
					socks_address = *resolver.resolve(boost::asio::ip::tcp::resolver::query(host, port));
				}
				catch(std::exception e) {
					std::cerr << "Failed to resolve " << host << ":" << port << " to an IPv4 address\n";
					return 1;
				}
			}
			target_argv++;
		}
	}
	if(help_required) {
		std::cout << "tunsocks -- Tunnel a process through a socks server\n" <<
			"Syntax: " << argv[0] << " [@[<proxy host>]:[<proxy port>]] <program to run> ..<args>..\n" <<
			"Host and port default to 127.0.0.1:8080\n\n";
		return 0;
	}

	// Create a new netns; this must be done here, and must be done via a dummy
	// clone, because the tun2socks child requires access to the original and
	// jailed netns, program requires access only to the jailed netns, and the
	// tun2socks child must be created first. It would of course be possible
	// to explicitly pass around file descriptors, but that's even more
	// complicated.
	int8_t child_stack[1024];
	pid_t namespace_owner = clone((int (*) (void *))&pause, &child_stack[1023], SIGCHLD | CLONE_NEWNET, 0);
	int namespace_fd = open((std::string("/proc/") + std::to_string(namespace_owner) + std::string("/ns/net")).c_str(), O_RDONLY | O_CLOEXEC);
	kill(namespace_owner, SIGTERM);
	waitpid(namespace_owner, &status, 0);

	// Create the tun device that passes data to the socks proxy
	pid_t child = fork();
	if(child == 0) {
		tun2socks_main(socks_address, namespace_fd);
		exit(1);
	}

	// Run the child program with dropped privileges
	pid_t program = fork();
	if(program == 0) {
		if(setns(namespace_fd, CLONE_NEWNET) < 0) {
			std::cerr << "Failed to assign network namespace\n";
			exit(1);
		}

		if(setresgid(getgid(), getgid(), getgid()) != 0) {
			std::cerr << "Failed to drop privileges for child program\n";
			exit(1);
		}

		if(setresuid(getuid(), getuid(), getuid()) != 0) {
			std::cerr << "Failed to drop privileges for child program\n";
			exit(1);
		}

		execvp(target_argv[0], &target_argv[0]);

		std::cerr << "Failed to start child program\n";
	}

	// Wait for it to complete, then kill the tunnel and terminate.
	waitpid(program, &status, 0);

	kill(child, SIGTERM);
	waitpid(child, &status, 0);
}
