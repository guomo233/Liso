#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <sys/mman.h>
#include "http.h"
#include "fdpool.h"
#include "log.h"

#ifdef __APPLE__
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
static ssize_t _sendfile (int out_fd, int in_fd, off_t *offset, size_t count)
{
	off_t len = count ;
	
	if (sendfile(in_fd, out_fd, *offset, &len, NULL, 0) < 0)
		return -1 ;
	else
	{
		*offset += len ;
		return len ;
	}
}
#else
#include <sys/sendfile.h>
#define _sendfile sendfile
#endif

extern char *www_folder, *cgi_folder ;
extern int http_port ;
extern fd_pool fdp ;

char status_msg[506][50] = {
	[200] = "OK",
	[400] = "Bad Request",
	[404] = "Not Found",
	[411] = "Length Required",
	[405] = "Method Not Allowed",
	[500] = "Internal Server Error",
	[501] = "Not Implemented",
	[505] = "HTTP Version Not Supported"
} ;

static int min (int a, int b)
{
	return a < b ? a : b ;
}

void free_req_buf (req_buffer *req_buf)
{
	free (req_buf->buf) ;
}

void free_resp_buf (resp_buffer *resp_buf)
{
	free (resp_buf->buf) ;
}

int init_req_buf (req_buffer *req_buf)
{
	req_buf->size = 0 ;
	req_buf->offset = 0 ;
	req_buf->header_size = 0 ;
	req_buf->body_size = 0 ;
	req_buf->req = NULL ;
	req_buf->capacity = BUF_SIZE ;
	req_buf->buf = (char *) malloc (BUF_SIZE) ;
	if (!req_buf->buf)
	{
		LOG_ERROR ("Can not alloc memory for client requst.") ;
		return -1 ;
	}
	
	return 0 ;
}

int init_resp_buf (resp_buffer *resp_buf)
{
	resp_buf->cgi = NULL ;
	resp_buf->resp_f.fd = -1 ;
	resp_buf->resp_f.offset = 0 ;
	resp_buf->resp_f.size = 0 ;
	resp_buf->size = 0 ;
	resp_buf->offset = 0 ;
	resp_buf->capacity = BUF_SIZE ;
	resp_buf->buf = (char *) malloc (BUF_SIZE) ;
	if (!resp_buf->buf)
	{
		LOG_ERROR ("Can not alloc memory for client response.") ;
		return -1 ;
	}
	
	return 0 ;
}

int parse_req (req_buffer *req_buf)
{
	char *body_size ;
	int parse_ret ;
	
	if (req_buf->req)
		return SUCCESS ;
	
	req_buf->req = parse (req_buf->buf, min(req_buf->size, 8192), &req_buf->header_size, &parse_ret) ;
	
	if (req_buf->req)
	{
		body_size = get_header (req_buf->req, "Content-Length") ;
		req_buf->body_size = body_size ? atoi (body_size) : 0 ;
		// TODO check valid of content length
		return SUCCESS ;
	}
	else if (req_buf->size > 8192 || parse_ret == BAD_REQ)
	// TODO receive is done ( < 8192) but can not parse
		return BAD_REQ ;
		
	return REQ_UNFIN ;
}

void clr_req_buf (req_buffer *req_buf)
{
	req_buf->size = 0 ;
	req_buf->header_size = 0 ;
	req_buf->body_size = 0 ;
	if (req_buf->req) free_request (req_buf->req) ;
	req_buf->req = NULL ;
}

void clr_resp_buf (resp_buffer *resp_buf)
{
	resp_buf->size = 0 ;
	resp_buf->offset = 0 ;
	
	resp_buf->resp_f.offset = 0 ;
	resp_buf->resp_f.size = 0 ;
	if (resp_buf->resp_f.fd > 0)
	{
		close (resp_buf->resp_f.fd) ;
		resp_buf->resp_f.fd = -1 ;
	}
	
	if (resp_buf->cgi)
	{
		free_cgi (resp_buf->cgi) ;
		resp_buf->cgi = NULL ;
	}
}

void reply (int scode, Response *resp, resp_buffer *resp_buf)
{
	int i ;
	char date[256] ;
	time_t timep ;
	struct tm *gmp ;
	
	if (resp == NULL)
	{
		resp = new_response() ;
		fill_header ("Content-Length", "0", resp) ;
		// TODO show error page
	}
	
	fill_header("Server", SERVER_NAME, resp) ;
	
	time (&timep) ;
	gmp = gmtime (&timep) ;
	strftime(date, 256, "%a, %d %b %Y %H:%M:%S %Z", gmp) ;
	fill_header("Date", date, resp) ;
	
	// TODO check if buf full
	resp_buf->size = sprintf (resp_buf->buf, "%s %d %s\r\n", HTTP_VERSION, scode, status_msg[scode]) ;
	for (i = 0; i < resp->header_count; i++)
		resp_buf->size += sprintf (resp_buf->buf + resp_buf->size, 
									"%s: %s\r\n", resp->headers[i].header_name, resp->headers[i].header_value) ;
	resp_buf->size += sprintf (resp_buf->buf + resp_buf->size, "\r\n") ;
	
	free_response(resp) ;
	resp_buf->evt.callback (resp_buf->evt.arg) ;
}

static char *get_ext (char *filename)
{
	char *ext = filename + strlen(filename) - 1 ;
	for (; ext >= filename; ext--)
		if (*ext == '.')
			return ext + 1 ;
	
	return NULL ;
}

static void get_mime (char *filename, char *mime)
{
	char *ext = get_ext (filename) ;
	
	// TODO ext not exist
	if (!strcmp(ext, "html"))
		strcpy (mime, "text/html") ;
	else if (!strcmp(ext, "css"))
		strcpy (mime, "text/css") ;
	else if (!strcmp(ext, "png"))
		strcpy (mime, "image/png") ;
	else if (!strcmp(ext, "jpeg"))
		strcpy (mime, "image/jpeg") ;
	else if (!strcmp(ext, "gif"))
		strcpy (mime, "image/gif") ;
	// TODO other
}

static void handle_head (Request *req, resp_buffer *resp_buf)
{
	char req_path[4096], mime[64], date[256], f_size[16] ;
	char *ext ;
	Response *resp ;
	struct stat st ;
	struct tm *gmp ;
	
	// TODO check req_file full
	strcpy (req_path, www_folder) ;
	// TODO www_folder may end by '/'
	strcat (req_path, req->http_uri) ;
	
	ext = get_ext(req_path) ;
	if (!ext)
		strcat (req_path, "index.html") ;
	
	if (access(req_path, F_OK | R_OK) < 0)
	{
		reply(404, NULL, resp_buf) ;
		return ;
	}
	
	resp = new_response() ;
	
	get_mime (req_path, mime) ;
	fill_header("Content-Type", mime, resp) ;
	
	stat (req_path, &st) ;
	gmp = gmtime (&st.st_mtime) ;
	strftime(date, 256, "%a, %d %b %Y %H:%M:%S %Z", gmp) ;
	fill_header("Last-Modified", date, resp) ;
	sprintf(f_size, "%lld", st.st_size) ;
	fill_header("Content-Length", f_size, resp) ;
	
	reply(200, resp, resp_buf) ;
}

static void cgi_tobe_read (int fd, void *arg)
{
	resp_buffer *resp_buf = (resp_buffer *) arg ;
	int remain, ret ;
	
	remain = resp_buf->capacity - resp_buf->size ;
	if (remain <= 0)
	{
		LOG_ERROR ("Size of response buffer out of range.") ;
		// TODO reply
		return ;
	}
	
	ret = read(fd, resp_buf->buf + resp_buf->size, remain) ;
	if (ret < 0)
	{
		LOG_ERROR("Error reading to CGI.\n");
		// TODO reply
		return ;
	}
	else if (ret == 0)
	{
		fdpool_remove (&fdp, fd, READ_FD) ;
		resp_buf->cgi->in = -1 ;
		resp_buf->evt.callback (resp_buf->evt.arg) ;
		return ;
	}
	
	resp_buf->size += ret ;
	LOG_INFO ("Received %d bytes from CGI.", ret) ;
}

static void cgi_tobe_write (int fd, void *arg)
{
	req_buffer *req_buf = (void *) arg ;
	int remain, ret ;
	
	remain = req_buf->header_size + req_buf->body_size - req_buf->offset ;
	if (remain > 0)
	{
		ret = write (fd, req_buf->buf + req_buf->offset, remain) ;
		if (ret < 0)
		{
			LOG_ERROR("Error writing to CGI.\n");
			// TODO reply
			return ;
		}
		
		req_buf->offset += ret ;
		LOG_INFO ("Send %d bytes to CGI.", ret) ;
	}
	
	if (req_buf->offset >= req_buf->header_size + req_buf->body_size)
	{
		fdpool_remove (&fdp, fd, WRITE_FD) ;
		close (fd) ;
	}
}

static void handle_cgi (Request *req, resp_buffer *resp_buf)
{
	char req_path[4096], port_str[8], *argv[2] ;
	char *cgi_filename, *cgi_query ;
	CGI_envp *cgi_envp ;
	fd_event evt ;
	
	// TODO check req_file full
	strcpy (req_path, cgi_folder) ;
	// TODO www_folder may end by '/'
	strcat (req_path, req->http_uri + 4) ;
	
	cgi_query = get_cgi_query (req_path) ;
	if (cgi_query)
		cgi_query[-1] = '\0' ;
	
	cgi_filename = req_path ;
	if (access(cgi_filename, F_OK | R_OK) < 0)
	{
		reply(404, NULL, resp_buf) ;
		return ;
	}
	
	if ((cgi_envp = new_cgi_envp ()) == NULL)
	{
		LOG_ERROR ("Can not alloc envp for cgi.") ;
		return ;
	}
	
	fill_cgi_envp (cgi_envp, "REQUEST_METHOD", "GET") ;
	if (cgi_query)
		fill_cgi_envp (cgi_envp, "QUERY_STRING", cgi_query) ;
	fill_cgi_envp (cgi_envp, "SCRIPT_NAME", cgi_filename) ;
	sprintf (port_str, "%d", http_port) ;
	fill_cgi_envp (cgi_envp, "SERVER_PORT", port_str) ;
	fill_cgi_envp (cgi_envp, "HTTP_ACCEPT", get_header(req, "Accept")) ;
	fill_cgi_envp (cgi_envp, "SERVER_PROTOCOL", HTTP_VERSION) ;
	fill_cgi_envp (cgi_envp, "SERVER_NAME", SERVER_NAME) ;
	fill_cgi_envp (cgi_envp, "SERVER_SOFTWARE", SERVER_NAME) ;
	fill_cgi_envp (cgi_envp, "GATEWAY_INTERFACE", CGI_VERSION) ;
	fill_cgi_envp (cgi_envp, "REMOTE_ADDR", "127.0.0.1") ;
	fill_cgi_envp (cgi_envp, "REMOTE_HOST", "localhost") ;
	
	argv[0] = cgi_filename ;
	argv[1] = NULL ;
	
	if ((resp_buf->cgi = new_cgi(argv, cgi_envp)) == NULL)
	{
		LOG_ERROR ("Faild to create CGI [%s].", req_path) ;
		// TODO reply
		return ;
	}
	
	free_cgi_envp (cgi_envp) ;
	
	evt.callback = cgi_tobe_read ;
	evt.arg = (void *) resp_buf ;
	fdpool_add (&fdp, resp_buf->cgi->in, READ_FD, evt) ;
}

static void handle_static (Request *req, resp_buffer *resp_buf)
{
	char req_path[4096], mime[64], date[256], f_size[16] ;
	char *ext ;
	Response *resp ;
	struct stat st ;
	struct tm *gmp ;
	
	// TODO check req_file full
	strcpy (req_path, www_folder) ;
	// TODO www_folder may end by '/'
	strcat (req_path, req->http_uri) ;
	
	ext = get_ext(req_path) ;
	if (!ext)
		strcat (req_path, "index.html") ;
	
	if (access(req_path, F_OK | R_OK) < 0)
	{
		reply(404, NULL, resp_buf) ;
		return ;
	}
	
	resp = new_response() ;
	
	get_mime (req_path, mime) ;
	fill_header("Content-Type", mime, resp) ;
	
	stat (req_path, &st) ;
	gmp = gmtime (&st.st_mtime) ;
	strftime(date, 256, "%a, %d %b %Y %H:%M:%S %Z", gmp) ;
	fill_header("Last-Modified", date, resp) ;
	sprintf(f_size, "%lld", st.st_size) ;
	fill_header("Content-Length", f_size, resp) ;
	
	// TODO open failed
	resp_buf->resp_f.fd = open (req_path, O_RDONLY) ;
	resp_buf->resp_f.size = st.st_size ;
	resp_buf->resp_f.offset = 0 ;
	
	reply(200, resp, resp_buf) ;
}

static void handle_post (Request *req, req_buffer *req_buf, resp_buffer *resp_buf)
{
	fd_event evt ;
	
	if (req_buf->body_size == 0)
	{
		reply(411, NULL, resp_buf) ;
		return ;
	}
	
	if (strncmp(req->http_uri, "/cgi/", 5))
	{
		reply (405, NULL, resp_buf) ;
		return ;
	}
	
	handle_cgi (req, resp_buf) ;
	
	req_buf->offset = req_buf->header_size ;
	
	evt.callback = cgi_tobe_write ;
	evt.arg = (void *) req_buf ;
	fdpool_add (&fdp, resp_buf->cgi->out, WRITE_FD, evt) ;
}

static void handle_get (Request *req, resp_buffer *resp_buf)
{
	if (!strncmp(req->http_uri, "/cgi/", 5))
	{
		handle_cgi (req, resp_buf) ;
		close (resp_buf->cgi->out) ;
	}
	else
		handle_static (req, resp_buf) ;
}

bool handle_request (req_buffer *req_buf, resp_buffer *resp_buf)
{
	char *connection ;
	Request *req = req_buf->req ;
	
	if (strcmp(req->http_version, HTTP_VERSION))
	{
		reply (505, NULL, resp_buf) ;
		return 0 ;
	}
	
	if (!strcmp(req->http_method, "GET"))
		handle_get (req, resp_buf) ;
	else if (!strcmp(req->http_method, "POST"))
		handle_post (req, req_buf, resp_buf) ;
	else if (!strcmp(req->http_method, "HEAD"))
		handle_head (req, resp_buf) ;
	else
	{
		reply (501, NULL, resp_buf) ;
		return 0 ;
	}
	
	connection = get_header (req, "Connection") ;
	if (connection && !strcmp(connection, "Close"))
		return 1 ;
	
	return 0 ;
}

bool req_read_done (req_buffer *req_buf)
{
	return req_buf->req && req_buf->size >= req_buf->header_size + req_buf->body_size ;
}

static bool buf_send_done (resp_buffer *resp_buf)
{
	return resp_buf->size == resp_buf->offset ;
}

static bool file_send_done (resp_buffer *resp_buf)
{
	return resp_buf->resp_f.fd <= 0 || resp_buf->resp_f.offset == resp_buf->resp_f.size ;
}

static bool cgi_send_done (resp_buffer *resp_buf)
{
	return !resp_buf->cgi || resp_buf->cgi->in < 0 ;
}

bool resp_tobe_send (resp_buffer *resp_buf)
{
	return !buf_send_done (resp_buf) || !file_send_done (resp_buf) ;
}

bool resp_send_done (resp_buffer *resp_buf)
{
	return buf_send_done (resp_buf) && file_send_done (resp_buf) && cgi_send_done (resp_buf) ;
}

int read_req (int fd, req_buffer *req_buf, SSL *ssl)
{
	int remain, ret ;
	
	remain = req_buf->capacity - req_buf->size ;
	if (remain <= 0)
	{
		LOG_ERROR ("Size of request buffer out of range.") ;
		return -1 ;
	}
	
	if (ssl)
		ret = SSL_read (ssl, req_buf->buf + req_buf->size, remain) ;
	else
		ret = recv (fd, req_buf->buf + req_buf->size, remain, 0) ;
	
	if (ret < 0)
		return -1 ;
	else if (ret == 0)
		return 0 ;
	
	req_buf->size += ret ;
	LOG_INFO ("Received %d bytes.", ret) ;
	return ret ;
}

static int send_buf (int fd, resp_buffer *resp_buf, SSL *ssl)
{
	int remain, ret ;
	
	remain = resp_buf->size - resp_buf->offset ;
	if (remain <= 0)
		return 0 ;
	
	if (ssl)
		ret = SSL_write(ssl, resp_buf->buf + resp_buf->offset, remain) ;
	else
		ret = send(fd, resp_buf->buf + resp_buf->offset, remain, 0) ;
	
	if (ret < 0)
		return -1 ;
	
	resp_buf->offset += ret ;
	LOG_INFO ("Send response %d bytes.", ret) ;
	return ret ;
}

static int send_file (int fd, resp_file *resp_f, SSL *ssl)
{
	char *f_mmap ;
	int remain, ret ;
	
	remain = resp_f->size - resp_f->offset ;
	if (remain <= 0)
		return 0 ;
	
	if (ssl)
	{
		// TODO use KTLS
		f_mmap = mmap (NULL, remain, PROT_READ, MAP_PRIVATE, resp_f->fd, resp_f->offset) ;
		ret = SSL_write (ssl, f_mmap, remain) ;
		munmap (f_mmap, remain) ;
		
		if (ret > 0) resp_f->offset += ret ;
	}
	else
		ret = _sendfile(fd, resp_f->fd, &resp_f->offset, resp_f->size) ;
		
	if (ret < 0)
		return -1 ;
	
	LOG_INFO ("Send file %d bytes.", ret) ;
	return ret ;
}

int send_resp (int fd, resp_buffer *resp_buf, SSL *ssl)
{
	if (send_buf (fd, resp_buf, ssl) < 0)
		return -1 ;
	
	if (buf_send_done(resp_buf) && !file_send_done(resp_buf))
		if (send_file (fd, &resp_buf->resp_f, ssl) < 0)
			return -1 ;
	
	return 0 ;
}

void set_resp_evt (resp_buffer *resp_buf, resp_event evt)
{
	resp_buf->evt = evt ;
}