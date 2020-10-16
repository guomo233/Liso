#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "http.h"
#include "parse.h"
#include "cpool.h"
#include "log.h"

extern char *www_folder ;

char status_msg[506][50] = {
	[200] = "OK",
	[400] = "Bad Request",
	[404] = "Not Found",
	[411] = "Length Required",
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

void send_resp (const int scode, Response *resp, resp_buffer *resp_buf)
{
	int i ;
	
	if (resp == NULL)
		resp = new_response() ;
	
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
	time_t timep ;
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
		send_resp(404, NULL, resp_buf) ;
		return ;
	}
	
	resp = new_response() ;
	
	fill_header("Server", SERVER_STR, resp) ;
	
	get_mime (req_path, mime) ;
	fill_header("Content-Type", mime, resp) ;
	
	stat (req_path, &st) ;
	gmp = gmtime (&st.st_mtime) ;
	strftime(date, 256, "%a, %d %b %Y %H:%M:%S %Z", gmp) ;
	sprintf(f_size, "%lld", st.st_size) ;
	fill_header("Content-Length", f_size, resp) ;
	fill_header("Last-Modified", date, resp) ;
	
	time (&timep) ;
	gmp = gmtime (&timep) ;
	strftime(date, 256, "%a, %d %b %Y %H:%M:%S %Z", gmp);
	fill_header("Date", date, resp) ;
	
	send_resp(200, resp, resp_buf) ;
}

void handle_get (const Request *req, resp_buffer *resp_buf)
{
	char req_path[4096], mime[64], date[256], f_size[16] ;
	const char *ext ;
	Response *resp ;
	struct stat st ;
	time_t timep ;
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
		send_resp(404, NULL, resp_buf) ;
		return ;
	}
	
	resp = new_response() ;
	
	fill_header("Server", SERVER_STR, resp) ;
	
	get_mime (req_path, mime) ;
	fill_header("Content-Type", mime, resp) ;
	
	stat (req_path, &st) ;
	gmp = gmtime (&st.st_mtime) ;
	strftime(date, 256, "%a, %d %b %Y %H:%M:%S %Z", gmp) ;
	sprintf(f_size, "%lld", st.st_size) ;
	fill_header("Content-Length", f_size, resp) ;
	fill_header("Last-Modified", date, resp) ;
	
	time (&timep) ;
	gmp = gmtime (&timep) ;
	strftime(date, 256, "%a, %d %b %Y %H:%M:%S %Z", gmp);
	fill_header("Date", date, resp) ;
	
	// TODO open failed
	resp_buf->fd = open (req_path, O_RDONLY) ;
	resp_buf->f_size = st.st_size ;
	resp_buf->f_offset = 0 ;
	
	send_resp(200, resp, resp_buf) ;
}

void handle_post (const Request *req, const char *post_buf, size_t body_size, resp_buffer *resp_buf)
{
	if (body_size == 0)
	{
		send_resp(411, NULL, resp_buf) ;
		return ;
	}
	
	// TODO
}

void handle_request (req_buffer *req_buf, resp_buffer *resp_buf)
{
	char *connection ;
	Request *req = req_buf->req ;
	
	if (strcmp(req->http_version, HTTP_VERSION))
	{
		send_resp (505, NULL, resp_buf) ;
		return ;
	}
	
	if (!strcmp(req->http_method, "GET"))
		handle_get (req, resp_buf) ;
	else if (!strcmp(req->http_method, "POST"))
		handle_post (req, req_buf->buf + req_buf->header_size, req_buf->body_size, resp_buf) ;
	else if (!strcmp(req->http_method, "HEAD"))
		handle_head (req, resp_buf) ;
	else
	{
		send_resp (501, NULL, resp_buf) ;
		return ;
	}
	
	connection = get_header (req, "Connection") ;
	if (connection && !strcmp(connection, "Close"))
		resp_buf->close = true ;
}