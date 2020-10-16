#ifndef FDPOOL_H
#define FDPOOL_H

#include <sys/select.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include "parse.h"

#define BUF_SIZE 10000
#define BUF_CLR 1
#define FILE_CLR 2

typedef struct
{
	char *buf ;
	size_t size ;
	size_t capacity ;
	Request *req ;
	size_t header_size ;
	size_t body_size ;
} req_buffer ;

typedef struct
{
	char *buf ;
	size_t size ;
	off_t offset ;
	size_t capacity ;
	int fd ;
	off_t f_offset ;
	size_t f_size ;
	bool close ;
} resp_buffer ;

typedef struct
{
	int fd ;
	SSL *ssl ;
	req_buffer req_buf ;
	resp_buffer resp_buf ;
} client ;

typedef struct
{
	int maxfd ;
	fd_set *read_set ;
	fd_set *write_set ;
	int n_cli ;
	client cli[FD_SETSIZE] ;
} client_pool ;

void pool_init (client_pool *pool, fd_set *read_set, fd_set *write_set) ;
int pool_add (client_pool *pool, int cfd, SSL *ssl) ;
void pool_remove (client_pool *pool, int cfd) ;
void clr_resp_buf (resp_buffer *resp_buf, int type) ;
void clr_req_buf (req_buffer *req_buf) ;

#endif