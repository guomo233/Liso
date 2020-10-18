#include <sys/mman.h>
#include <unistd.h>
#include "cio.h"
#include "log.h"
#include "http.h"

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
		LOG_ERROR ("Can not alloc memory for client.") ;
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
		LOG_ERROR ("Can not alloc memory for client.") ;
		return -1 ;
	}
	
	return 0 ;
}

bool req_read_done (req_buffer *req_buf)
{
	return req_buf->req && req_buf->size >= req_buf->header_size + req_buf->body_size ;
}

bool buf_send_done (resp_buffer *resp_buf)
{
	return resp_buf->size == resp_buf->offset ;
}

bool file_send_done (resp_buffer *resp_buf)
{
	return resp_buf->resp_f.fd <= 0 || resp_buf->resp_f.offset == resp_buf->resp_f.size ;
}

bool cgi_send_done (resp_buffer *resp_buf)
{
	return !resp_buf->cgi || resp_buf->cgi->in_done ;
}

bool resp_tobe_send (resp_buffer *resp_buf)
{
	return !buf_send_done (resp_buf) || !file_send_done (resp_buf) ;
}

bool resp_send_done (resp_buffer *resp_buf)
{
	return buf_send_done (resp_buf) && file_send_done (resp_buf) && cgi_send_done (resp_buf) ;
}

int parse_req (req_buffer *req_buf)
{
	const char *body_size ;
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

int send_buf (int fd, resp_buffer *resp_buf, SSL *ssl)
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

int send_resp (int fd, resp_buffer *resp_buf, SSL *ssl)
{
	if (send_buf (fd, resp_buf, ssl) < 0)
		return -1 ;
	
	if (buf_send_done(resp_buf) && !file_send_done(resp_buf))
		if (send_file (fd, &resp_buf->resp_f, ssl) < 0)
			return -1 ;
	
	return 0 ;
}

int send_file (int fd, resp_file *resp_f, SSL *ssl)
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
	if (resp_buf->resp_f.fd > 0) close (resp_buf->resp_f.fd) ;
	resp_buf->resp_f.fd = -1 ;
	
	if (resp_buf->cgi) free_cgi (resp_buf->cgi) ;
	resp_buf->cgi = NULL ;
}