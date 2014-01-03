/*
 * C version of my testing HTTP web server
 */
// for strcasestr
#define _GNU_SOURCE

#include <sys/wait.h>

#include <ctype.h>
#include <sys/sendfile.h>
#include <arpa/inet.h>
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
#include <netinet/in.h>
#include <netinet/tcp.h>

#define TRUE  1
#define FALSE 0

const char *directory_index_extensions[] = {
	".html",
	".php",
	".pl",
	NULL
};

/* MAGIC MIME TYPE DETECTION ****/
const struct mime_type_t { const char *ext, *type; } mime_types[] = {
	{ ".txt", "text/plain" },
	{ ".html", "text/html" },
	{ ".php", "text/x-php" },
	{ ".css", "text/css" },
	{ ".js", "text/js" },
	{ ".gif", "image/gif" },
	{ ".png", "image/png" },
	{ ".jpg", "image/jpg" },
	{ ".jpeg", "image/jpg" },
	{ NULL, NULL }
};

#ifdef USE_MAGIC
#include <magic.h>

magic_t magic_lib;
pthread_mutex_t magic_lib_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

void get_mime_type(const char *file, char *type) {
	const char *ext = strrchr(file, '.');

	if(ext) {
		const struct mime_type_t *t;
		for(t = mime_types; t->ext; t++) {
			if(strcasecmp(ext, t->ext) == 0) {
				strcpy(type, t->type);
				return;
			}
		}
	}

#ifdef USE_MAGIC
	pthread_mutex_lock(&magic_lib_mutex);
	const char *magic_type = magic_file(magic_lib, file);
	if(magic_type) {
		strncpy(type, magic_type, 255);
	}
	pthread_mutex_unlock(&magic_lib_mutex);
#endif

	strcpy(type, "application/octet-stream");
}

#ifdef WITH_CGI
/** CGI HANDLER ****/
const struct cgi_handler_t { const char *ext, *handler; } cgi_handlers[] = {
	{ ".php", "php-cgi" },
	{ ".pl", "perl" },
	{ NULL, NULL }
};

const char *find_cgi_helper(const char *file) {
	const char *ext = strrchr(file, '.');
	if(ext) {
		const struct cgi_handler_t *t;
		for(t = cgi_handlers; t->ext; t++) {
			if(strcasecmp(ext, t->ext) == 0) {
				return t->handler;
			}
		}
	}
	return NULL;
}

#endif // WITH_CGI

/** LOGGING ******/

#ifndef LOG_LEVEL
#define LOG_LEVEL 5
#endif

#define L_DEBUG 5
#define L_INFO  4
#define L_WARN  3
#define L_ERROR 2
#define L_FATAL 1

#if LOG_LEVEL > 0
static void plog(int level, const char *fmt, ...) {
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

/* URL REWRITING *****/
#ifdef WITH_REWRITE
#include <regex.h>

char *htaccess_rewrite_url(const char *unescaped_url_ptr) {
	char path[PATH_MAX];

	char rewritten[PATH_MAX];
	strcpy(rewritten, unescaped_url_ptr);

	char *unescaped_url = alloca(strlen(unescaped_url_ptr) + 1);
	strcpy(unescaped_url,  unescaped_url_ptr);

	int did_rewrite = 0;

	char *slash_pos;
	for(slash_pos = strrchr(unescaped_url, '/'); slash_pos && slash_pos > path; slash_pos = strrchr(unescaped_url, '/')) {
		*slash_pos = 0;
		snprintf(path, PATH_MAX, ".%s/.htaccess", unescaped_url);
		if(access(path, R_OK) == 0) {
			plog(L_DEBUG, "htaccess file found at %s", path);
			FILE *htaccess_file = fopen(path, "r");

			char line[2048];
			char *line_worker;
			while((line_worker = fgets(line, 2048, htaccess_file))) {
				while(*line_worker == ' ' || *line_worker == '\t') line_worker++;
				if(strncasecmp(line_worker, "rewriterule", 11) != 0) continue;
				while(*line_worker != ' ' && *line_worker != '\t' && *line_worker != 0) line_worker++;
				if(!*line_worker) continue;
				while(*line_worker == ' ' || *line_worker == '\t') line_worker++;
				char *regex_string = line_worker;
				while(*line_worker != ' ' && *line_worker != '\t' && *line_worker != 0) line_worker++;
				if(!*line_worker) continue;
				*line_worker = 0;
				line_worker++;
				char *space_seeker = line_worker;
				while(*space_seeker != ' ' && *space_seeker != '\t' && *space_seeker != 0) space_seeker++;
				if(*space_seeker) *space_seeker = 0;

				regex_t regex;
				int regex_error;
				plog(L_DEBUG, "Match %s against %s", unescaped_url_ptr, regex_string);
				if((regex_error = regcomp(&regex, regex_string, REG_ICASE | REG_EXTENDED))) {
					char err_str[255];
					regerror(regex_error, &regex, err_str, 255);
					plog(L_WARN, "Failed to compile regex `%s' in %s: %s", regex_string, path, err_str);
					continue;
				}
				regmatch_t matches[10];
				int status = regexec(&regex, rewritten, 10, matches, 0);
				regfree(&regex);
				if(status != 0) continue;

				char new_str[PATH_MAX];
				int new_str_length = 0;
				if(new_str_length + matches[0].rm_so >= PATH_MAX) return NULL;
				memcpy(new_str, rewritten, matches[0].rm_so);
				new_str_length += matches[0].rm_so;
				for(; *line_worker && *line_worker != '\r' && *line_worker != '\n'; line_worker++) {
					if(*line_worker == '\\' || *line_worker == '$') {
						int match = line_worker[1] - '0';
						line_worker++;

						int len = matches[match].rm_eo - matches[match].rm_so;
						if(new_str_length + len >= PATH_MAX) return NULL;
						memcpy(new_str + new_str_length, rewritten + matches[match].rm_so, len);
						new_str_length += len;
					}
					else {
						if(new_str_length + 1 >= PATH_MAX) return NULL;
						new_str[new_str_length++] = *line_worker;
					}
				}
				if(new_str_length + strlen(rewritten) - matches[0].rm_eo >= PATH_MAX) return NULL;
				strcpy(new_str + new_str_length, rewritten + matches[0].rm_eo);

				plog(L_DEBUG, "Rewrite: `%s' → `%s'", unescaped_url_ptr, new_str);
				strcpy(rewritten, new_str);
				did_rewrite = 1;
			}

			fclose(htaccess_file);
		}
	}

	if(did_rewrite) {
		char *ret = malloc(strlen(rewritten) + 1);
		strcpy(ret, rewritten);
		return ret;
	}
	return NULL;
}
#endif

/* BUFFERED SOCKET INPUT ********/
struct buffered_fd_t {
	int fd;
	char *buffer;
	size_t buffer_pos;
	size_t buffer_size;
};

struct buffered_fd_t *buffered_fd_new(int fd) {
	struct buffered_fd_t *ret = (struct buffered_fd_t *)malloc(sizeof(struct buffered_fd_t));
	ret->fd = fd;
	ret->buffer_size = 10240;
	ret->buffer_pos = 0;
	ret->buffer = (char *)malloc(ret->buffer_size);
	if(!ret->buffer) {
		free(ret);
		return NULL;
	}
	ret->buffer[0] = 0;
	return ret;
}

void buffered_fd_destroy(struct buffered_fd_t *wrapper) {
	free(wrapper->buffer);
	free(wrapper);
}

int buffered_fd_fill_buffer(struct buffered_fd_t *wrapper, size_t minimal_size) {
	if(wrapper->buffer_size < minimal_size) {
		wrapper->buffer = realloc(wrapper->buffer, minimal_size + 10240);
	}
	if(!wrapper->buffer) {
		return -1;
	}
	while(wrapper->buffer_pos < minimal_size) {
		int ret = read(wrapper->fd, wrapper->buffer + wrapper->buffer_pos, wrapper->buffer_size - wrapper->buffer_pos);
		if(ret <= 0) {
			return -1;
		}
		wrapper->buffer_pos += ret;
	}
	return wrapper->buffer_pos;
}

int buffered_fd_read(struct buffered_fd_t *wrapper, char *buffer, size_t count) {
	if(buffered_fd_fill_buffer(wrapper, count) < 0) {
		return -1;
	}
	memcpy(buffer, wrapper->buffer, count);
	memmove(wrapper->buffer, wrapper->buffer + count, wrapper->buffer_pos - count);
	wrapper->buffer_pos -= count;
	return 0;
}

char *buffered_fd_read_until_delemiter(struct buffered_fd_t *wrapper, char delemiter) {
	size_t newline_pos = 0;
	while(newline_pos < wrapper->buffer_pos && wrapper->buffer[newline_pos] != delemiter) newline_pos++;
	while(wrapper->buffer[newline_pos] != delemiter) {
		if(buffered_fd_fill_buffer(wrapper, wrapper->buffer_pos + 1) < 0) {
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
	memmove(wrapper->buffer, wrapper->buffer + newline_pos + 1, wrapper->buffer_pos - newline_pos);
	wrapper->buffer_pos -= newline_pos + 1;
	return ret;
}

char *buffered_fd_read_until_token(struct buffered_fd_t *wrapper, const char *token) {
	int token_length = strlen(token);
	if(wrapper->buffer_pos < wrapper->buffer_size) wrapper->buffer[wrapper->buffer_pos] = 0;
	char *found;
	int is_crlf = token[0] == '\r' && token[1] == '\n' && token[2] == '\r' && token[3] == '\n' && !token[4];
	while((found = strstr(wrapper->buffer, token)) == NULL) {
		if(is_crlf && (found = strstr(wrapper->buffer, "\n\n")) != NULL) {
			token_length -= 2;
			break;
		}
		if(buffered_fd_fill_buffer(wrapper, wrapper->buffer_pos + 1) < 0) {
			return NULL;
		}
		wrapper->buffer[wrapper->buffer_pos] = 0;
	}
	if(is_crlf && *found == '\r') {
		char *alternative = strstr(wrapper->buffer, "\n\n");
		if(alternative && alternative < found) {
			found = alternative;
			token_length -= 2;
		}
	}
	char *ret = (char *)malloc(found - wrapper->buffer + token_length + 1);
	if(!ret) {
		return NULL;
	}
	memcpy(ret, wrapper->buffer, found - wrapper->buffer + token_length);
	ret[found - wrapper->buffer + token_length] = 0;
	memmove(wrapper->buffer, found + token_length, wrapper->buffer_pos - (found - wrapper->buffer));
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

/* HTTP HELPERS ***/
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
	if(*(header_end - 1) != '\r') {
		header_end++;
	}

	char *ret = (char *)malloc(header_end - header_pos);
	memmove(ret, header_pos, header_end - header_pos - 1);
	ret[header_end - header_pos - 1] = 0;

	return ret;
}

void client_send_error(struct buffered_fd_t *socket_wrapper, int code) {
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
	write(socket_wrapper->fd, buf, length);
}

struct request_t {
	char *raw_head_data;

	char *method;
	char *uri;
	char *http_version;

	char *headers;
};

void client_fail_with_error(struct buffered_fd_t *socket_wrapper, struct request_t *request, int code) {
	client_send_error(socket_wrapper, code);
	fsync(socket_wrapper->fd);
	close(socket_wrapper->fd);
	buffered_fd_destroy(socket_wrapper);
	if(request && request->raw_head_data) {
		free(request->raw_head_data);
	}
	pthread_exit(NULL);
}

struct client_thread_data_t {
	struct sockaddr client_addr;
	socklen_t client_addr_length;
	int client_socket;
};

int client_read_request(struct buffered_fd_t *socket_wrapper, struct request_t *request) {
	// Read the whole request
	char *request_data = request->raw_head_data = buffered_fd_read_until_token(socket_wrapper, "\r\n\r\n");
	if(!request_data) {
		close(socket_wrapper->fd);
		buffered_fd_destroy(socket_wrapper);
		pthread_exit(NULL);
	}

	// Parse it
	// Request method
	char *request_work = strchr(request_data, ' ');
	if(!request_work) {
		plog(L_WARN, "Invalid request: Expected space after method");
		free(request_data);
		client_fail_with_error(socket_wrapper, request, 400);
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
		client_fail_with_error(socket_wrapper, request, 413);
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
		client_fail_with_error(socket_wrapper, request, 400);
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
			else if(state == 0 && *request_work_after > ' ');
			else if(state == 1 && *request_work_after == '\n') state = 2;
			else if(state == 1);
			else if(state == 2 && (*request_work_after == ' ' || *request_work_after == '\t')) state = 1;
			else if(state == 2 && (*request_work_after == '\r' || *request_work_after == '\n')) break;
			else if(state == 2) state = 0;
			else {
				plog(L_DEBUG, "Parsing of headers failed at: `%s'", request_work_after);
				return FALSE;
			}
		}
	}

	return TRUE;
}

int client_read_post_data(struct buffered_fd_t *socket_wrapper, struct request_t *request, int fd_target, int forward_chunk_headers_to_target) {
	if(strcmp(request->method, "POST") != 0 && strcmp(request->method, "PUT") != 0) {
		return -1;
	}

	// Read POST data
	char *length_header = extract_header(request->headers, "content-length");
	if(length_header) {
		size_t content_length = atol(length_header);

		char buffer[10240];
		while(content_length > 0) {
			size_t size = content_length > 10240 ? 10240 : content_length;
			if(buffered_fd_read(socket_wrapper, buffer, size) < 0) {
				client_fail_with_error(socket_wrapper, request, 400);
			}
			if(fd_target > 0) {
				write(fd_target, buffer, size);
			}
			content_length -= size;
		}
	}
	else {
		char *transfer_encoding = extract_header(request->headers, "transfer-encoding");
		if(!transfer_encoding) {
			client_fail_with_error(socket_wrapper, request, 400);
		}
		if(strcmp(transfer_encoding, "chunked") != 0) {
			free(transfer_encoding);
			client_fail_with_error(socket_wrapper, request, 400);
		}
		free(transfer_encoding);

		char *post_data_buffer;
		size_t chunk_size;
		while(TRUE) {
			char *line = buffered_fd_read_until_delemiter(socket_wrapper, '\n');
			if(!line || sscanf(line, "%lx", &chunk_size) == 0) {
				if(line) free(line);
				plog(L_WARN, "Failed to read chunked POST data length");
				client_fail_with_error(socket_wrapper, request, 400);
			}
			if(fd_target > 0 && forward_chunk_headers_to_target) {
				write(fd_target, line, strlen(line));
			}
			free(line);
			if(chunk_size == 0) {
				line = buffered_fd_read_until_delemiter(socket_wrapper, '\n');
				if(line) {
					// We do not accept headers after the body. This is a violation of the HTTP
					// standard
					// TODO I should implement this someday
					if(line[0] != '\n' && (line[0] != '\r' || line[1] != '\n')) {
						plog(L_ERROR, "Client attempted to send headers after chunked body. This is unsupported.");
						client_fail_with_error(socket_wrapper, request, 400);
					}
					if(fd_target > 0 && forward_chunk_headers_to_target) {
						write(fd_target, line, strlen(line));
					}
					free(line);
					break;
				}
			}
			post_data_buffer = (char *)malloc(chunk_size);
			if(!post_data_buffer) {
				plog(L_ERROR, "Failed to allocate memory for post data");
				client_fail_with_error(socket_wrapper, request, 500);
			}
			if(buffered_fd_read(socket_wrapper, post_data_buffer, chunk_size) < 0) {
				free(post_data_buffer);
				client_fail_with_error(socket_wrapper, request, 500);
			}
			if(fd_target > 0) {
				write(fd_target, post_data_buffer, chunk_size);
			}
			free(post_data_buffer);
			line = buffered_fd_read_until_delemiter(socket_wrapper, '\n');
			if(line) {
				if(fd_target > 0 && forward_chunk_headers_to_target) {
					write(fd_target, line, strlen(line));
				}
				free(line);
			}
		}
	}
	return 0;
}

void client_flush_post_data(struct buffered_fd_t *socket_wrapper, struct request_t *request) {
	client_read_post_data(socket_wrapper, request, 0, 0);
}

void env_var_assign(char **pointer_location, const char *name, const char *value) {
	if(!value) value = "";
	int nlen = strlen(name);
	int vlen = strlen(value);
	*pointer_location = (char *)malloc(nlen + vlen + 2);
	memcpy(*pointer_location, name, nlen);
	(*pointer_location)[nlen] = '=';
	memcpy(*pointer_location + nlen + 1, value, vlen);
	(*pointer_location)[nlen + vlen + 1] = 0;
}
void *client_thread(struct client_thread_data_t *client_info_ptr) {
	struct client_thread_data_t client_info = *client_info_ptr;
	free(client_info_ptr);
	int socket = client_info.client_socket;
	struct buffered_fd_t *socket_wrapper = buffered_fd_new(socket);

	char client_hostname[NI_MAXHOST];
	char client_ip[INET6_ADDRSTRLEN];
	inet_ntop(client_info.client_addr.sa_family, &((struct sockaddr_in6 *)&client_info.client_addr)->sin6_addr, client_ip, INET6_ADDRSTRLEN);
	int errcode;
	if((errcode = getnameinfo(&client_info.client_addr, client_info.client_addr_length, client_hostname, NI_MAXHOST, NULL, 0, 0)) != 0) {
		plog(L_WARN, "Incoming connection with an unresolvable remote side from %s: %s [%d]", client_ip, gai_strerror(errcode), errcode);
		*client_hostname = 0;
	}
	else {
		plog(L_DEBUG, "Incoming connection from %s [%s]", client_ip, client_hostname);
	}

	while(TRUE) {
		// Read a single request
		struct request_t request;
		request.raw_head_data = NULL;
		if(!client_read_request(socket_wrapper, &request)) {
			client_fail_with_error(socket_wrapper, &request, 400);
		}
		plog(L_INFO, "%s [%s]: %s %s %s", client_hostname, client_ip, request.http_version, request.method, request.uri);

		int is_keep_alive = 1;
		const char *connection_type = "keep-alive";
		if(strcmp(request.http_version, "HTTP/1.0") == 0 || strcasestr(request.headers, "connection: close") != NULL) {
			connection_type = "close";
			is_keep_alive = 0;
		}

		// Extract possible file name
		if(strstr(request.uri, "/../") != NULL) {
			client_fail_with_error(socket_wrapper, &request, 400);
		}
		struct stat file_info;
		memset(&file_info, 0, sizeof(struct stat));
		if(strlen(request.uri) + 2 > PATH_MAX) {
			client_fail_with_error(socket_wrapper, &request, 400);
		}
		char full_file[PATH_MAX];
		full_file[0] = '.';
		urldecode(full_file + 1, request.uri);
		char *hash_part = strchr(full_file, '#');
		if(hash_part) {
			*hash_part = 0;
		}
		char *query_part = strchr(full_file, '?');
#ifdef WITH_REWRITE
		int file_exists = 0;
		if(query_part) {
			*query_part = 0;
			file_exists = access(full_file, F_OK);
			*query_part = '?';
		}
		else {
			file_exists = access(full_file, F_OK);
		}
		if(file_exists != 0) {
			char *target_file = htaccess_rewrite_url(full_file + 1);
			if(target_file) {
				// htaccess rewriting was successful
				char full_file[PATH_MAX];
				full_file[0] = '.';
				int index = 1;
				if(full_file[0] != '/') {
					index = 2;
					full_file[1] = '/';
				}
				strcpy(full_file + index, target_file);
				free(target_file);
				query_part = strchr(full_file, '?');
			}
		}
#endif
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
			client_flush_post_data(socket_wrapper, &request);

			// Display directory index if this is a directory and one exists
			int found_index = 0;
			char alternative[PATH_MAX];
			const char **index_name;
			for(index_name = directory_index_extensions; *index_name; index_name++) {
				snprintf(alternative, PATH_MAX, "%s/index%s", full_file, *index_name);
				if(access(alternative, F_OK) == 0) {
					// Redirect to directory index
					char header[PATH_MAX + 1024];
					const char *index_prefix = "index";
					if(full_file[strlen(full_file) - 1] != '/') {
						index_prefix = "/index";
					}
					int header_length = snprintf(header, PATH_MAX + 1024, "HTTP/1.1 302 Found\r\nConnection: %s\r\nTransfer-Encoding: chunked\r\nLocation: %s%s%s\r\n\r\n0\r\n\r\n", connection_type, full_file + 1, index_prefix, *index_name);
					send(socket, header, header_length, 0);
					found_index = 1;
				}
			}

			if(found_index) {
				// Nothing
			}
			else if(full_file[strlen(full_file) - 1] != '/') {
				// Redirect to file with slash in the end
				char header[PATH_MAX + 1024];
				int header_length = snprintf(header, PATH_MAX + 1024, "HTTP/1.1 301 Moved permamently\r\nConnection: %s\r\nTransfer-Encoding: chunked\r\nLocation: %s/\r\n\r\n0\r\n\r\n", connection_type, request.uri);
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
					while((dir_contents = readdir(dir))) {
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
		else if(!(file_info.st_mode & S_IROTH)) {
			client_flush_post_data(socket_wrapper, &request);
			client_send_error(socket_wrapper, 404);
		}
		else if(S_ISREG(file_info.st_mode)) {
			char type[255];
			get_mime_type(full_file, type);

#ifdef WITH_CGI
			const char *cgi_helper = find_cgi_helper(full_file);
			if(cgi_helper || file_info.st_mode & S_IXOTH) {
				if(!cgi_helper) cgi_helper = full_file;

				plog(L_DEBUG, "Using CGI helper %s to serve %s", cgi_helper, full_file);

				int child_writer[2];
				int child_reader[2];
				if(pipe(child_writer) < 0) {
					client_fail_with_error(socket_wrapper, &request, 500);
				}
				if(pipe(child_reader) < 0) {
					close(child_writer[0]);
					close(child_writer[1]);
					client_fail_with_error(socket_wrapper, &request, 500);
				}

				pid_t child = fork();
				if(child == 0) {
					close(0);
					dup2(child_writer[0], 0);
					close(1);
					dup2(child_reader[1], 1);

					char *child_envp[40];
					child_envp[0] = "GATEWAY_INTERFACE=CGI/1.1";
					env_var_assign(&child_envp[1], "SERVER_PROTOCOL", request.http_version);
					env_var_assign(&child_envp[2], "REQUEST_METHOD", request.method);
					env_var_assign(&child_envp[3], "PATH_TRANSLATED", full_file);
					env_var_assign(&child_envp[4], "SCRIPT_NAME", full_file + 1);
					env_var_assign(&child_envp[5], "QUERY_STRING", query_part);
					env_var_assign(&child_envp[6], "REMOTE_HOST", client_hostname);
					env_var_assign(&child_envp[7], "REMOTE_ADDR", client_ip);
					const char *path = getenv("PATH");
					if(path) {
						env_var_assign(&child_envp[8], "PATH", path);
					}
					else {
						env_var_assign(&child_envp[8], "PATH", "/bin:/usr/bin:/usr/local/bin");
					}
					int header_count = 8;

					char *content_type = extract_header(request.headers, "content-type");
					if(content_type) {
						env_var_assign(&child_envp[++header_count], "CONTENT_TYPE", content_type);
						free(content_type);
					}
					char *content_length = extract_header(request.headers, "content-length");
					if(content_length) {
						env_var_assign(&child_envp[++header_count], "CONTENT_LENGTH", content_length);
						free(content_length);
					}
					if(path_info) {
						env_var_assign(&child_envp[++header_count], "PATH_INFO", path_info);
					}
					char *header_ptr = request.headers;
					while(header_count < 39) {
						while(*header_ptr == '\r' || *header_ptr == '\n' || *header_ptr == ' ') header_ptr++;
						char *next_colon = strchr(header_ptr, ':');
						if(!next_colon) break;
						char the_header[128];
						memcpy(the_header, header_ptr, next_colon - header_ptr);
						the_header[next_colon - header_ptr] = 0;
						char *header_contents = extract_header(request.headers, the_header);
						if(!header_contents) {
							plog(L_ERROR, "Failed to find field `%s' in headers though it should be there", the_header);
							break;
						}
						char header_name[128];
						strcpy(header_name, "HTTP_");
						int i;
						for(i=0; i<127 && the_header[i]; i++) header_name[i + 5] = the_header[i] == '-' ? '_' : toupper(the_header[i]);
						header_name[i + 5] = 0;
						env_var_assign(&child_envp[++header_count], header_name, header_contents);
						header_ptr = next_colon + 1 + strlen(header_contents) + 2;
						free(header_contents);
					}
					child_envp[++header_count] = NULL;

					const char *const child_argv[] = {
						cgi_helper,
						full_file,
						NULL
					};

					execvpe(cgi_helper, (char * const *)child_argv, (char * const *)child_envp);
					plog(L_ERROR, "Failed to execute CGI child process");
					exit(1);
				}

				close(child_writer[0]);
				close(child_reader[1]);

				// Write POST data to child
				client_read_post_data(socket_wrapper, &request, child_writer[1], 1);
				fsync(child_writer[1]);
				close(child_writer[1]);

				// Read headers from child reader into socket
				struct buffered_fd_t *child_wrapper = buffered_fd_new(child_reader[0]);
				char *headers = buffered_fd_read_until_token(child_wrapper, "\r\n\r\n");
				if(!headers) {
					client_fail_with_error(socket_wrapper, &request, 500);
				}

				// Cork socket
				int cork = 1;
				setsockopt(socket, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));

				char *status_header = extract_header(headers, "status");
				if(status_header) {
					char out[128];
					int len = snprintf(out, 128, "HTTP/1.1 %s\r\n", status_header);
					write(socket, out, len);
					free(status_header);
				}
				else {
					const char header[] = "HTTP/1.1 200 Ok\r\n";
					write(socket, header, sizeof(header) - 1);
				}

				char *header;
				for(header = headers; *header != '\n' && (header[0] != '\r' || header[1] != '\n'); ) {
					char *next = strchr(header, '\n');
					if(*(next - 1) == '\r') {
						char after1 = next[1];
						next[1] = 0;
						write(socket, header, strlen(header));
						next[1] = after1;
					}
					else {
						char after1 = next[1];
						char after2 = next[2];
						next[0] = '\r';
						next[1] = '\n';
						next[2] = 0;
						write(socket, header, strlen(header));
						next[1] = after1;
						next[2] = after2;
					}
					header = next + 1;
				}

				int is_chunked = 0;
				char *connection = extract_header(headers, "connection");
				if(connection) {
					if(strcasecmp(connection, "close") == 0) {
						is_keep_alive = 0;
					}
					free(connection);
				}
				else {
					const char keep_alive[] = "Connection: Keep-Alive\r\n";
					write(socket, keep_alive, sizeof(keep_alive) - 1);
				}
				char *transfer_encoding = extract_header(headers, "transfer-encoding");
				if(transfer_encoding) {
					free(transfer_encoding);
				}
				else {
					is_chunked = 1;
					const char chunked[] = "Transfer-Encoding: chunked\r\n";
					write(socket, chunked, sizeof(chunked) - 1);
				}
				char *length_header = extract_header(headers, "content-length");
				ssize_t cgi_content_length = -1;
				if(length_header) {
					cgi_content_length = atol(length_header);
					free(length_header);
				}
				write(socket, "\r\n", 2);

				// Read from child reader into socket
				if(child_wrapper->buffer_pos) {
					if(is_chunked) {
						char chunk_header[128];
						int len = snprintf(chunk_header, 128, "%lx\r\n", child_wrapper->buffer_pos);
						write(socket, chunk_header, len);
					}

					write(socket, child_wrapper->buffer, child_wrapper->buffer_pos);
					if(cgi_content_length > 0) cgi_content_length -= child_wrapper->buffer_pos;
					if(is_chunked) {
						write(socket, "\r\n", 2);
					}
				}
				buffered_fd_destroy(child_wrapper);

				// Uncork socket
				cork = 0;
				setsockopt(socket, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));

				while(TRUE) {
					char buffer[10241];
					ssize_t bytes_read = read(child_reader[0], buffer, 10240);
					if(is_chunked) {
						cork = 1; setsockopt(socket, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
						char chunk_header[128];
						int len = snprintf(chunk_header, 128, "%lx\r\n", bytes_read);
						write(socket, chunk_header, len);
					}
					if(bytes_read && write(socket, buffer, bytes_read) <= 0) {
						break;
					}
					if(is_chunked) {
						write(socket, "\r\n", 2);
						cork = 0; setsockopt(socket, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
					}
					if(cgi_content_length > 0) cgi_content_length -= bytes_read;
					if(bytes_read == 0) {
						break;
					}
				}

				close(child_reader[0]);
				int status;
				waitpid(child, &status, 0);

				if(cgi_content_length > 0) {
					// There were bytes left to send. Abort connection.
					plog(L_WARN, "CGI aborted with %ld bytes remaining.", cgi_content_length);
					free(request.raw_head_data);
					break;
				}
			}
			else {
#endif
				client_flush_post_data(socket_wrapper, &request);

				int file = open(full_file, O_RDONLY);
				char header[1024];

				size_t file_length = file_info.st_size;
				off_t file_start = 0;

				char *range_header = extract_header(request.headers, "range");
				if(range_header) {
					char *equal_pos = strchr(range_header, '=');
					if(!equal_pos) {
						plog(L_DEBUG, "Range header: Equal sign not found");
						free(range_header);
						client_fail_with_error(socket_wrapper, &request, 400);
					}
					char *until_pos = strchr(equal_pos, '-');
					if(!until_pos) {
						plog(L_DEBUG, "Range header: Minus sign not found");
						free(range_header);
						client_fail_with_error(socket_wrapper, &request, 400);
					}
					*equal_pos = 0;
					*until_pos = 0;

					if(strcmp(range_header, "bytes") != 0) {
						plog(L_DEBUG, "Range header: First word is %s, not bytes", range_header);
						free(range_header);
						client_fail_with_error(socket_wrapper, &request, 416);
					}

					size_t bytes_from = atol(equal_pos + 1);
					size_t bytes_to = atol(until_pos + 1);

					free(range_header);

					if(bytes_to == 0) {
						bytes_to = file_info.st_size - 1;
					}

					file_length = bytes_to - bytes_from;
					file_start = bytes_from;
					int length = snprintf(header, 1024, "HTTP/1.1 206 Partial Content\r\nConnection: %s\r\nContent-Type: %s\r\nContent-Length: %lu\r\nContent-Range: bytes %lu-%lu/%lu\r\nAccept-Ranges: bytes\r\n\r\n",
						connection_type,
						type,
						file_length,
						bytes_from,
						bytes_to,
						file_info.st_size);

					plog(L_DEBUG, "Is a regular file. Sending the file: size=%lu, type=%s with range %lu-%lu", file_info.st_size, type, bytes_from, bytes_to);
					if(length < 0 || length > 1024) {
						client_fail_with_error(socket_wrapper, &request, 500);
					}
					send(socket, header, length, 0);
				}
				else {
					int length = snprintf(header, 1024, "HTTP/1.1 200 Ok\r\nConnection: %s\r\nContent-Type: %s\r\nContent-Length: %lu\r\n\r\n",
						connection_type,
						type,
						file_info.st_size);

					plog(L_DEBUG, "Is a regular file. Sending the file: size=%lu, type=%s", file_info.st_size, type);
					if(length < 0 || length > 1024) {
						client_fail_with_error(socket_wrapper, &request, 500);
					}
					send(socket, header, length, 0);
				}

				if(strcmp(request.method, "HEAD") != 0) {
					sendfile(socket, file, &file_start, file_length);
				}

				close(file);
#ifdef WITH_CGI
			}
#endif
		}
		else {
			client_flush_post_data(socket_wrapper, &request);
			client_send_error(socket_wrapper, 403);
		}

		if(request.raw_head_data) {
			free(request.raw_head_data);
			request.raw_head_data = NULL;
		}

		if(!is_keep_alive) {
			break;
		}
	}

	fsync(socket);
	close(socket);
	buffered_fd_destroy(socket_wrapper);
	return NULL;
}

int create_server(unsigned int port) {
	int server_socket = socket(AF_INET6, SOCK_STREAM, 0);
	if(!server_socket) {
		plog(L_FATAL, "Failed to create socket");
	}

	int yes = 1;
	if(setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		plog(L_FATAL, "Failed to set reuse socket option");
	}

	struct sockaddr_in6 server_addr;
	memset(&server_addr, 0, sizeof(struct sockaddr_in6));
	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_port = htons(port);

	if(bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		return 0;
	}

	return server_socket;
}

int main(int argc, char *argv[]) {
	unsigned int port = 1234;

	if(argc > 1) {
		port = atoi(argv[1]);
		if(port == 0) {
			plog(L_FATAL, "The port argument must be a positive integer");
		}
	}

	int server_socket = create_server(port);
	if(!server_socket) {
		plog(L_FATAL, "Failed to create socket on port %d: %m", port);
	}
	if(listen(server_socket, 5) < 0) {
		plog(L_FATAL, "Failed to listen on port %d: %m", port);
	}
	plog(L_INFO, "Created server on port %d", port);

#ifdef USE_MAGIC
	magic_lib = magic_open(MAGIC_MIME_TYPE);
	magic_load(magic_lib, NULL);
#endif

	signal(SIGPIPE, SIG_IGN);

	struct sockaddr client_addr;
	socklen_t client_addr_length = sizeof(struct sockaddr);
	int client_socket;
	while((client_socket = accept(server_socket, &client_addr, &client_addr_length))) {
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
	return 0;
}

