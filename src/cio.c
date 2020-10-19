#include <sys/mman.h>
#include <unistd.h>
#include "cio.h"
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