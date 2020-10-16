#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include "log.h"
#include "http.h"

static int max (int a, int b)
{
	return a > b ? a : b ;
}

static void swap (client *a, client *b)
{
	client tmp = *a ;
	*a = *b ;
	*b = tmp ;
}

void pool_init (client_pool *pool, fd_set *read_set, fd_set *write_set)
{
	pool->n_cli = 0 ;		
	pool->maxfd = 0 ;
	pool->read_set = read_set ;
	pool->write_set = write_set ;
}

int pool_add (client_pool *pool, int cfd, SSL *ssl)
{
	pool->cli[pool->n_cli].req_buf.size = 0 ;
	pool->cli[pool->n_cli].req_buf.header_size = 0 ;
	pool->cli[pool->n_cli].req_buf.body_size = 0 ;
	pool->cli[pool->n_cli].req_buf.req = NULL ;
	pool->cli[pool->n_cli].req_buf.capacity = BUF_SIZE ;
	pool->cli[pool->n_cli].req_buf.buf = (char *) malloc (BUF_SIZE) ;
	if (!pool->cli[pool->n_cli].req_buf.buf)
	{
		LOG_ERROR ("Can not alloc memory for client.") ;
		return -1 ;
	}

	pool->cli[pool->n_cli].resp_buf.close = false ;
	pool->cli[pool->n_cli].resp_buf.fd = -1 ;
	pool->cli[pool->n_cli].resp_buf.f_offset = 0 ;
	pool->cli[pool->n_cli].resp_buf.f_size = 0 ;
	pool->cli[pool->n_cli].resp_buf.size = 0 ;
	pool->cli[pool->n_cli].resp_buf.offset = 0 ;
	pool->cli[pool->n_cli].resp_buf.capacity = BUF_SIZE ;
	pool->cli[pool->n_cli].resp_buf.buf = (char *) malloc (BUF_SIZE) ;
	if (!pool->cli[pool->n_cli].resp_buf.buf)
	{
		LOG_ERROR ("Can not alloc memory for client.") ;
		return -1 ;
	}
	
	pool->cli[pool->n_cli].fd = cfd ;
	pool->cli[pool->n_cli++].ssl = ssl ;
	pool->maxfd = max (pool->maxfd, cfd) ;
	
	FD_SET (cfd, pool->read_set) ;
	
	LOG_INFO ("Client conntected.") ;
	return 0 ;
}

void pool_remove (client_pool *pool, int cfd)
{
	int i ;
	
	pool->maxfd = 0 ;
	for (i = 0; i < pool->n_cli; i++)
	{
		if (cfd == pool->cli[i].fd)
		{
			free (pool->cli[i].req_buf.buf) ;
			free (pool->cli[i].resp_buf.buf) ;
			
			FD_CLR (cfd, pool->read_set) ;
			FD_CLR (cfd, pool->write_set) ;
			
			if (pool->cli[i].ssl)
			{
				SSL_shutdown (pool->cli[i].ssl) ;
				SSL_free (pool->cli[i].ssl) ;
			}
			close (cfd) ;
			swap (&pool->cli[i], &pool->cli[--pool->n_cli]) ;
			
			LOG_INFO ("Client closed.") ;
		}
		
		if (i < pool->n_cli)
			pool->maxfd = max (pool->maxfd, pool->cli[i].fd) ;
	}
}

void clr_req_buf (req_buffer *req_buf)
{
	req_buf->size = 0 ;
	req_buf->header_size = 0 ;
	req_buf->body_size = 0 ;
	free_request (req_buf->req) ;
	req_buf->req = NULL ;
}

void clr_resp_buf (resp_buffer *resp_buf, int type)
{
	if (type & BUF_CLR)
	{
		resp_buf->size = 0 ;
		resp_buf->offset = 0 ;
	}
	
	if (type & FILE_CLR)
	{
		resp_buf->f_offset = 0 ;
		resp_buf->f_size = 0 ;
		close (resp_buf->fd) ;
		resp_buf->fd = -1 ;
	}
}