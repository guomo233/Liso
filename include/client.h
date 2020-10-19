#ifndef CPOOL_H
#define CPOOL_H

#include <stdbool.h>
#include "http.h"

typedef struct
{
	int cfd ;
	SSL *ssl ;
	req_buffer req_buf ;
	resp_buffer resp_buf ;
	bool close ;
} client ;

client *new_client (int cfd, SSL *ssl) ;
void free_client (client *cli) ;

#endif