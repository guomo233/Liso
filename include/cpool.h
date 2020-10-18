#ifndef CPOOL_H
#define CPOOL_H

#include <openssl/ssl.h>
#include <sys/select.h>
#include <stdbool.h>
#include "cio.h"

typedef struct
{
	int fd ;
	SSL *ssl ;
	req_buffer req_buf ;
	resp_buffer resp_buf ;
	bool close ;
} client ;

typedef struct
{
	int n_cli ;
	client cli[FD_SETSIZE] ;
} client_pool ;

int cpool_add (client_pool *cpool, int cfd, SSL *ssl) ;
void cpool_remove (client_pool *cpool, int cid) ;

#endif