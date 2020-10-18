#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "http.h"
#include "log.h"

extern char *www_folder, *cgi_folder ;
extern int http_port ;

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

Response *new_response ()
{
	Response *resp = (Response *) malloc (sizeof(Response)) ;
	resp->header_count = 0 ;
	resp->header_capacity = 8 ;
	resp->headers = (Response_header *) malloc (sizeof(Response_header) * resp->header_capacity) ;
	return resp ;
}

void free_request (Request *req)
{
	free (req->headers) ;
	free (req) ;
}

void free_response (Response *resp)
{
	free (resp->headers) ;
	free (resp) ;
}

void write_resp (const int scode, Response *resp, resp_buffer *resp_buf)
{
	int i ;
	char date[256] ;
	time_t timep ;
	struct tm *gmp ;
	
	if (resp == NULL)
		resp = new_response() ;
	
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
}

int fill_header (const char *name, const char *value, Response *resp)
{
	if (resp->header_count == resp->header_capacity)
	{
		resp->header_capacity <<= 1 ;
		if ((resp->headers = (Response_header *) realloc(resp->headers, 
		     sizeof(Response_header) * resp->header_capacity)) == NULL)
		{
			LOG_ERROR ("Can not allocate memory for HTTP response headers.") ;
			return -1 ;
		}
	}
	
	strcpy (resp->headers[resp->header_count].header_name, name) ;
	strcpy (resp->headers[resp->header_count].header_value, value) ;
	resp->header_count++ ;
	return 0 ;
}

char *get_header (const Request *req, const char *name)
{
	int i ;
	
	// TODO lowcast upcast compatibility
	for (i = 0; i < req->header_count; i++)
		if (!strcmp(req->headers[i].header_name, name))
			return req->headers[i].header_value ;
			
	return NULL ;
}

const char *get_ext (const char *filename)
{
	const char *ext = filename + strlen(filename) - 1 ;
	for (; ext >= filename; ext--)
		if (*ext == '.')
			return ext + 1 ;
	
	return NULL ;
}

void get_mime (const char *filename, char *mime)
{
	const char *ext = get_ext (filename) ;
	
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

void handle_head (const Request *req, resp_buffer *resp_buf)
{
	char req_path[4096], mime[64], date[256], f_size[16] ;
	const char *ext ;
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
		write_resp(404, NULL, resp_buf) ;
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
	
	write_resp(200, resp, resp_buf) ;
}

void handle_cgi (const Request *req, resp_buffer *resp_buf)
{
	char req_path[4096], port_str[8], *argv[2] ;
	char *cgi_filename, *cgi_query ;
	CGI_envp *cgi_envp ;
	
	// TODO check req_file full
	strcpy (req_path, cgi_folder) ;
	// TODO www_folder may end by '/'
	strcat (req_path, req->http_uri + 4) ;
	
	cgi_filename = get_cgi_filename(req_path) ;
	cgi_query = get_cgi_query (req_path) ;
	
	if (access(cgi_filename, F_OK | R_OK) < 0)
	{
		write_resp(404, NULL, resp_buf) ;
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
}

void handle_static (const Request *req, resp_buffer *resp_buf)
{
	char req_path[4096], mime[64], date[256], f_size[16] ;
	const char *ext ;
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
		write_resp(404, NULL, resp_buf) ;
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
	
	write_resp(200, resp, resp_buf) ;
}

void handle_post (const Request *req, const char *post_buf, size_t body_size, resp_buffer *resp_buf)
{
	if (body_size == 0)
	{
		write_resp(411, NULL, resp_buf) ;
		return ;
	}
	
	if (strncmp(req->http_uri, "/cgi/", 5))
	{
		write_resp (405, NULL, resp_buf) ;
		return ;
	}
	
	handle_cgi (req, resp_buf) ;
}

void handle_get (const Request *req, resp_buffer *resp_buf)
{
	if (!strncmp(req->http_uri, "/cgi/", 5))
		handle_cgi (req, resp_buf) ;
	else
		handle_static (req, resp_buf) ;
}

bool handle_request (req_buffer *req_buf, resp_buffer *resp_buf)
{
	char *connection ;
	Request *req = req_buf->req ;
	
	if (strcmp(req->http_version, HTTP_VERSION))
	{
		write_resp (505, NULL, resp_buf) ;
		return 0 ;
	}
	
	if (!strcmp(req->http_method, "GET"))
		handle_get (req, resp_buf) ;
	else if (!strcmp(req->http_method, "POST"))
		handle_post (req, req_buf->buf + req_buf->header_size, req_buf->body_size, resp_buf) ;
	else if (!strcmp(req->http_method, "HEAD"))
		handle_head (req, resp_buf) ;
	else
	{
		write_resp (501, NULL, resp_buf) ;
		return 0 ;
	}
	
	connection = get_header (req, "Connection") ;
	if (connection && !strcmp(connection, "Close"))
		return 1 ;
		
	return 0 ;
}