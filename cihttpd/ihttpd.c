/*
 * C version of my testing HTTP web server
 */
// for strcasestr
#define _GNU_SOURCE

#include <stdio.h>
#include <limits.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#ifdef USE_MAGIC
#include <magic.h>
magic_t magic_lib;
pthread_mutex_t magic_lib_mutex = PTHREAD_MUTEX_INITIALIZER;

void get_mime_type(const char *file, char *type) {
	pthread_mutex_lock(&magic_lib_mutex);
	const char *magic_type = magic_file(magic_lib, file);
	if(magic_type) {
		strncpy(type, magic_type, 255);
	}
	else {
		strcpy(type, "application/octet-stream");
	}
	pthread_mutex_unlock(&magic_lib_mutex);
}
#else
struct mime_type_t { const char *ext, *type; } mime_types[] = {
	{ ".txt", "text/plain" },
	{ ".html", "text/html" },
	{ ".php", "application/x+php" },
	{ ".css", "text/css" },
	{ ".js", "text/js" },
	{ ".gif", "image/gif" },
	{ ".png", "image/png" },
	{ ".jpg", "image/jpg" },
	{ ".jpeg", "image/jpg" },
	{ NULL, NULL }
};

void get_mime_type(const char *file, char *type) {
	const char *ext = strrchr(file, '.');

	if(ext) {
		struct mime_type_t *t;
		for(t = mime_types; t->ext; t++) {
			if(strcasecmp(ext, t->ext) == 0) {
				strcpy(type, t->type);
				return;
			}
		}
	}

	strcpy(type, "application/octet-stream");
}
#endif

#define TRUE  1
#define FALSE 0

#ifndef LOG_LEVEL
#define LOG_LEVEL 5
#endif

#define L_DEBUG 5
#define L_INFO  4
#define L_WARN  3
#define L_ERROR 2
#define L_FATAL 1

#if LOG_LEVEL > 0
static int plog(int level, const char *fmt, ...) {
	if(level > LOG_LEVEL) return;

	FILE *file = level < L_INFO ? stderr : stdout;

	if(level < L_WARN) {
		fputs("\033[31m", file);
	}
	else if(level == L_WARN) {
		fputs("\033[33m", file);
	}
	else if(level == L_INFO) {
		fputs("\033[32m", file);
	}

	char time_s[30];
	time_s[0] = '[';
	time_t now = time(NULL);
	ctime_r(&now, &time_s[1]);
	time_s[strlen(time_s) - 2] = ']';
	time_s[strlen(time_s) - 1] = ' ';
	time_s[strlen(time_s)]     = 0;
	fputs(time_s, file);

	if(level > L_WARN) {
		fputs("\033[0m", file);
	}

	va_list args;
	va_start(args, fmt);
	vfprintf(file, fmt, args);
	va_end(args);

	fputc('\n', file);

	if(level == L_FATAL) {
		exit(1);
	}
}
#else
#define plog(...)
#endif

struct buffered_socket_t {
	int socket;
	char *buffer;
	size_t buffer_pos;
	size_t buffer_size;
};

struct buffered_socket_t *buffered_socket_new(int socket) {
	struct buffered_socket_t *ret = (struct buffered_socket_t *)malloc(sizeof(struct buffered_socket_t));
	ret->socket = socket;
	ret->buffer_size = 10240;
	ret->buffer_pos = 0;
	ret->buffer = (char *)malloc(ret->buffer_size);
	if(!ret->buffer) {
		free(ret);
		return NULL;
	}
	return ret;
}

void buffered_socket_destroy(struct buffered_socket_t *wrapper) {
	free(wrapper->buffer);
	free(wrapper);
}

int buffered_socket_fill_buffer(struct buffered_socket_t *wrapper, int minimal_size) {
	if(wrapper->buffer_size < minimal_size) {
		wrapper->buffer = realloc(wrapper->buffer, minimal_size + 10240);
	}
	if(!wrapper->buffer) {
		return -1;
	}
	while(wrapper->buffer_pos < minimal_size) {
		int ret = recv(wrapper->socket, wrapper->buffer + wrapper->buffer_pos, wrapper->buffer_size - wrapper->buffer_pos, 0);
		if(ret <= 0) {
			return -1;
		}
		wrapper->buffer_pos += ret;
	}
	return wrapper->buffer_pos;
}

int buffered_socket_read(struct buffered_socket_t *wrapper, char *buffer, int count) {
	if(buffered_socket_fill_buffer(wrapper, count) < 0) {
		return -1;
	}
	memcpy(buffer, wrapper->buffer, count);
	memcpy(wrapper->buffer + count, wrapper->buffer, wrapper->buffer_pos - count);
	wrapper->buffer_pos -= count;
}

char *buffered_socket_read_until_delemiter(struct buffered_socket_t *wrapper, char delemiter) {
	size_t newline_pos = 0;
	int n_th_run = 0;
	while(newline_pos < wrapper->buffer_pos && wrapper->buffer[newline_pos] != delemiter) newline_pos++;
	while(wrapper->buffer[newline_pos] != '\n') {
		if(buffered_socket_fill_buffer(wrapper, wrapper->buffer_pos + 1) < 0) {
			return NULL;
		}
		while(newline_pos < wrapper->buffer_pos && wrapper->buffer[newline_pos] != delemiter) newline_pos++;
	}
	char *ret = (char *)malloc(newline_pos + 2);
	if(!ret) {
		return NULL;
	}
	memcpy(ret, wrapper->buffer, newline_pos + 1);
	ret[newline_pos + 1] = 0;
	memcpy(wrapper->buffer, wrapper->buffer + newline_pos + 1, wrapper->buffer_pos - newline_pos);
	wrapper->buffer_pos -= newline_pos + 1;
	return ret;
}

char *buffered_socket_read_until_token(struct buffered_socket_t *wrapper, const char *token) {
	int token_length = strlen(token);
	if(wrapper->buffer_pos < wrapper->buffer_size) wrapper->buffer[wrapper->buffer_pos + 1] = 0;
	char *found;
	int is_crlf = token[0] == '\r' && token[1] == '\n' && token[2] == '\r' && token[3] == '\n' && !token[4];
	while((found = strstr(wrapper->buffer, token) ) == NULL) {
		if(buffered_socket_fill_buffer(wrapper, wrapper->buffer_pos + 1) < 0) {
			return NULL;
		}
		if(wrapper->buffer_pos < wrapper->buffer_size) wrapper->buffer[wrapper->buffer_pos + 1] = 0;
		if(is_crlf && (found = strstr(wrapper->buffer, "\n\n")) != NULL) {
			break;
		}
	}
	char *ret = (char *)malloc(found - wrapper->buffer + token_length + 1);
	if(!ret) {
		return NULL;
	}
	memcpy(ret, wrapper->buffer, found - wrapper->buffer + token_length);
	ret[found - wrapper->buffer + token_length] = 0;
	memcpy(wrapper->buffer, found + token_length, wrapper->buffer_pos - (found - wrapper->buffer));
	wrapper->buffer_pos -= (found - wrapper->buffer) + token_length;

	return ret;
}

void urldecode(char *dest, const char *uri) {
	for(; *uri; uri++, dest++) {
		if(*uri == '%' && uri[1] && uri[2]) {
			*dest = (uri[1] >= 'a' ? uri[1] - 'a' + 10 : uri[1] - '0') * 16 +
			        (uri[2] >= 'a' ? uri[2] - 'a' + 10 : uri[2] - '0');
			uri += 2;
		}
		else {
			*dest = *uri;
		}
	}
	*dest = 0;
}

char *extract_header(const char *headers, const char *header) {
	int header_length = strlen(header);
	char *search = alloca(2 + header_length);
	sprintf(search, "\n%s: ", header);
	const char *header_pos = strcasestr(headers, search);

	if(!header_pos) {
		sprintf(search, "%s: ", header);
		if(strncasecmp(headers, search, header_length + 2) == 0) {
			header_pos = headers;
			header_pos--; // This is one shorter than the other one, see below
		}
	}
	if(!header_pos) return FALSE;

	header_pos += header_length + 3;

	const char *header_end = strchr(header_pos, '\n');
	while(header_end && (header_end[1] == ' ' || header_end[1] == '\t')) {
		header_end = strchr(header_end + 1, '\n');
	}
	if(!header_end) {
		header_end = header_pos + strlen(header_pos);
	}

	char *ret = (char *)malloc(header_end - header_pos);
	memcpy(ret, header_pos, header_end - header_pos - 1);
	ret[header_end - header_pos] = 0;

	return ret;
}

void client_send_error(struct buffered_socket_t *socket_wrapper, int code) {
	char buf[1024];
	const char *message;
	switch(code) {
		case 400: message = "Invalid request"; break;
		case 404: message = "File not found"; break;
		case 413: message = "Request too long"; break;
		case 414: message = "Request URI too long"; break;
		case 500: message = "Internal server error"; break;
		case 501: message = "Method not implemented"; break;
		default:  message = "Unknown error";
	}
	int length = snprintf(buf, 1024, "HTTP/1.1 %d %s\r\nTransfer-Encoding: chunked\r\n\r\n%lx\r\n<h1>%03d %s</h1>\r\n0\r\n\r\n", code, message, 4 + 3 + 1 + strlen(message) + 5 , code, message);
	plog(L_WARN, "Request failed with error %d %s", code, message);
	send(socket_wrapper->socket, buf, length, 0);
}

void client_fail_with_error(struct buffered_socket_t *socket_wrapper, int code) {
	client_send_error(socket_wrapper, code);
	fsync(socket_wrapper->socket);
	close(socket_wrapper->socket);
	buffered_socket_destroy(socket_wrapper);
	pthread_exit(NULL);
}

struct client_thread_data_t {
	struct sockaddr client_addr;
	socklen_t client_addr_length;
	int client_socket;
};

struct request_t {
	char *raw_head_data;

	char *method;
	char *uri;
	char *http_version;

	char *headers;
	char *post_data;
};

int client_read_request(struct buffered_socket_t *socket_wrapper, struct request_t *request) {
	// Read the whole request
	char *request_data = request->raw_head_data = buffered_socket_read_until_token(socket_wrapper, "\r\n\r\n");
	if(!request_data) {
		close(socket_wrapper->socket);
		buffered_socket_destroy(socket_wrapper);
		pthread_exit(NULL);
	}

	// Parse it
	// Request method
	char *request_work = strchr(request_data, ' ');
	if(!request_work) {
		plog(L_WARN, "Invalid request: Expected space after method");
		free(request_data);
		client_fail_with_error(socket_wrapper, 400);
	}
	*request_work = 0;
	request->method = request_data;
	if(!*request->method) {
		return FALSE;
	}
	request_work++;

	// URI
	char *request_work_after = strchr(request_work, ' ');
	if(!request_work_after) {
		plog(L_WARN, "Invalid request: Expected space after URI");
		free(request_data);
		client_fail_with_error(socket_wrapper, 413);
	}
	*request_work_after = 0;
	request->uri = request_work;
	if(!*request->uri) {
		return FALSE;
	}
	request_work = request_work_after + 1;

	// HTTP version
	request_work_after = strchr(request_work, '\n');
	if(!request_work_after) {
		plog(L_WARN, "Invalid request: Expected new line after HTTP version");
		free(request_data);
		client_fail_with_error(socket_wrapper, 400);
	}
	*request_work_after = 0;
	if(*(request_work_after - 1) == '\r') {
		*(request_work_after - 1) = 0;
	}
	request->http_version = request_work;
	if(!request->http_version) {
		return FALSE;
	}

	request->headers = ++request_work_after;

	// Check if the remaining headers are valid
	int state = 0;
	if((*request_work_after != '\r' || request_work_after[1] != '\n') && *request_work_after != '\n') {
		for(; *request_work_after; request_work_after++) {
			if     (state == 0 && *request_work_after == ':') state = 1;
			else if(state == 0 && *request_work_after > ' ') 1;
			else if(state == 1 && *request_work_after == '\n') state = 2;
			else if(state == 1) 1;
			else if(state == 2 && (*request_work_after == ' ' || *request_work_after == '\t')) state = 1;
			else if(state == 2 && (*request_work_after == '\r' || *request_work_after == '\n')) break;
			else if(state == 2) state = 0;
			else {
				plog(L_DEBUG, "Parsing of headers failed at: `%s'", request_work_after);
				return FALSE;
			}
		}
	}

	plog(L_INFO, "%s %s %s", request->http_version, request->method, request->uri);
	return TRUE;
}

void *client_thread(struct client_thread_data_t *client_info_ptr) {
	struct client_thread_data_t client_info = *client_info_ptr;
	free(client_info_ptr);
	int socket = client_info.client_socket;
	struct buffered_socket_t *socket_wrapper = buffered_socket_new(socket);

	// TODO Maybe implement FTP in here, too?

	char client_hostname[NI_MAXHOST];
	int errcode;
	if((errcode = getnameinfo(&client_info.client_addr, client_info.client_addr_length, client_hostname, NI_MAXHOST, NULL, 0, 0)) != 0) {
		plog(L_WARN, "Incoming connection with an unresolvable remote side: %s [%d]", gai_strerror(errcode), errcode);
	}
	else {
		plog(L_DEBUG, "Incoming connection from %s", client_hostname);
	}

	while(TRUE) {
		// Read a single request
		struct request_t request;
		if(!client_read_request(socket_wrapper, &request)) {
			client_fail_with_error(socket_wrapper, 400);
		}

		int is_keep_alive = 1;
		const char *connection_type = "keep-alive";
		if(strcmp(request.http_version, "HTTP/1.0") == 0 || strcasestr(request.headers, "connection: close") != NULL) {
			connection_type = "close";
			is_keep_alive = 0;
		}

		// TODO URL rewriting

		// Extract possible file name
		if(strstr(request.uri, "/../") != NULL) {
			client_fail_with_error(socket_wrapper, 400);
		}
		struct stat file_info;
		memset(&file_info, 0, sizeof(struct stat));
		char *full_file = alloca(strlen(request.uri) + 2);
		full_file[0] = '.';
		urldecode(full_file + 1, request.uri);
		char *query_part = strchr(full_file, '?');
		char *path_info = NULL;
		if(query_part != NULL) {
			*query_part = 0;
			query_part++;
		}
		while(stat(full_file, &file_info) != 0) {
			char *new_path_info = strrchr(full_file, '/');
			if(path_info == NULL) {
				break;
			}
			if(path_info != NULL) {
				*path_info = '/';
			}
			path_info = new_path_info;
			*path_info = 0;
		}
		if(path_info != NULL) {
			path_info++;
		}

		if(!file_info.st_ino) {
			client_send_error(socket_wrapper, 404);
		}
		else if(S_ISDIR(file_info.st_mode)) {
			if(full_file[strlen(full_file) - 1] != '/') {
				// Redirect to file with slash in the end
				char *header = alloca(100 + strlen(request.uri));
				int header_length = snprintf(header, PATH_MAX + 1024, "HTTP/1.1 301 Permanent redirect\r\nConnection: %s\r\nTransfer-Encoding: chunked\r\nLocation: %s/\r\n\r\n0\r\n\r\n", connection_type, request.uri);
				send(socket, header, header_length, 0);
			}
			else {
				plog(L_DEBUG, "Is a directory. Sending directory index.");

				char header[1024];
				int header_length = snprintf(header, 1024, "HTTP/1.1 200 Ok\r\nConnection: %s\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\n\r\n1f\r\n<h1>Directory contents</h1><ul>\r\n", connection_type);
				send(socket, header, header_length, 0);

				DIR *dir = opendir(full_file);
				struct dirent *dir_contents;
				if(readdir(dir) && strcmp(".", request.uri) != 0) {
					while(dir_contents = readdir(dir)) {
						char buf[255 * 2 + 10];
						if(dir_contents->d_type == DT_DIR) {
							int pos = strlen(dir_contents->d_name);
							if(pos < PATH_MAX) {
								dir_contents->d_name[pos] = '/';
								dir_contents->d_name[pos + 1] = 0;
							}
						}
						int length = snprintf(buf, sizeof(buf), "%lx\r\n<li><a href='%s'>%s</a></li>\r\n", 24 + 2 * strlen(dir_contents->d_name), dir_contents->d_name, dir_contents->d_name);
						send(socket, buf, length, 0);
					}
				}

				send(socket, "0\r\n\r\n", 5, 0);
				closedir(dir);
			}
		}
		else if(!file_info.st_mode & S_IROTH) {
			client_send_error(socket_wrapper, 404);
		}
		else if(S_ISREG(file_info.st_mode)) {
			if(file_info.st_mode & S_IXOTH) {
				// TODO Invoke CGI
				// TODO Handle PHP (is not CGI usually :/)
			}

			int file = open(full_file, O_RDONLY);
			char header[1024];

			size_t file_length = file_info.st_size;
			size_t file_start = 0;

			char *range_header = extract_header(request.headers, "range");
			if(range_header) {
				char *equal_pos = strchr(range_header, '=');
				if(!equal_pos) {
					plog(L_DEBUG, "Range header: Equal sign not found");
					free(range_header);
					client_fail_with_error(socket_wrapper, 400);
				}
				char *until_pos = strchr(equal_pos, '-');
				if(!until_pos) {
					plog(L_DEBUG, "Range header: Minus sign not found");
					free(range_header);
					client_fail_with_error(socket_wrapper, 400);
				}
				*equal_pos = 0;
				*until_pos = 0;

				if(strcmp(range_header, "bytes") != 0) {
					plog(L_DEBUG, "Range header: First word is %s, not bytes", range_header);
					free(range_header);
					client_fail_with_error(socket_wrapper, 416);
				}

				size_t bytes_from = atol(equal_pos + 1);
				size_t bytes_to = atol(until_pos + 1);

				free(range_header);

				if(bytes_to == 0) {
					bytes_to = file_info.st_size - 1;
				}

				file_length = bytes_to - bytes_from;
				file_start = bytes_from;

				char type[255];
				get_mime_type(full_file, type);
				int length = snprintf(header, 1024, "HTTP/1.1 206 Partial Content\r\nConnection: %s\r\nContent-Type: %s\r\nContent-Length: %lu\r\nContent-Range: bytes %lu-%lu/%lu\r\nAccept-Ranges: bytes\r\n\r\n",
					connection_type,
					type,
					file_length,
					bytes_from,
					bytes_to,
					file_info.st_size);

				plog(L_DEBUG, "Is a regular file. Sending the file: size=%lu, type=%s with range %lu-%lu", file_info.st_size, type, bytes_from, bytes_to);
				if(length < 0 || length > 1024) {
					client_fail_with_error(socket_wrapper, 500);
				}
				send(socket, header, length, 0);
			}
			else {
				char type[255];
				get_mime_type(full_file, type);
				int length = snprintf(header, 1024, "HTTP/1.1 200 Ok\r\nConnection: %s\r\nContent-Type: %s\r\nContent-Length: %lu\r\n\r\n",
					connection_type,
					type,
					file_info.st_size);

				plog(L_DEBUG, "Is a regular file. Sending the file: size=%lu, type=%s", file_info.st_size, type);
				if(length < 0 || length > 1024) {
					client_fail_with_error(socket_wrapper, 500);
				}
				send(socket, header, length, 0);
			}

			if(strcmp(request.method, "HEAD") != 0) {
				sendfile(socket, file, &file_start, file_length);
			}

			close(file);
		}
		else {
			client_send_error(socket_wrapper, 403);
		}

		free(request.raw_head_data);
		if(request.post_data) {
			free(request.post_data);
		}

		if(!is_keep_alive) {
			break;
		}
	}

	//  TODO CGI

	fsync(socket);
	close(socket);
	buffered_socket_destroy(socket_wrapper);
}

int create_server(unsigned int port) {
	int server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(!server_socket) {
		plog(L_FATAL, "Failed to create socket");
	}

	int yes = 1;
	if(setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		plog(L_FATAL, "Failed to set reuse socket option");
	}

	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(struct sockaddr_in));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	if(bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		return 0;
	}

	return server_socket;
}

int main(int argc, char *argv[]) {
	unsigned int port = 1234;

	int server_socket = create_server(port);
	if(!server_socket) {
		plog(L_FATAL, "Failed to create socket on port %d", port);
	}
	listen(server_socket, 5);
	plog(L_INFO, "Created server on port %d", port);

#ifdef USE_MAGIC
	magic_lib = magic_open(MAGIC_MIME_TYPE);
	magic_load(magic_lib, NULL);
#endif

	signal(SIGPIPE, SIG_IGN);

	struct sockaddr client_addr;
	socklen_t client_addr_length = sizeof(struct sockaddr);
	int client_socket;
	while(client_socket = accept(server_socket, &client_addr, &client_addr_length)) {
		struct client_thread_data_t *data;
		data = malloc(sizeof(struct client_thread_data_t));
		data->client_addr = client_addr;
		data->client_socket = client_socket;
		data->client_addr_length = client_addr_length;

		pthread_t client_thread_id;
		pthread_create(&client_thread_id, NULL, (void *(*)(void *))client_thread, data);
		pthread_detach(client_thread_id);

		client_addr_length = sizeof(client_addr);
	}

	plog(L_INFO, "Terminating");
}

