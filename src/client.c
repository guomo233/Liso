#include <openssl/ssl.h>
#include "client.h"
#include "log.h"

client *new_client (int cfd, SSL *ssl)
{
	client *cli ;
	
	if ((cli = (client *) malloc (sizeof(client))) == NULL)
	{
		LOG_ERROR ("Can not alloc memory for client.") ;
		return NULL ;
	}
	
	if (init_req_buf(&cli->req_buf) < 0)
		return NULL ;
	if (init_resp_buf(&cli->resp_buf) < 0)
		return NULL ;
	
	cli->cfd = cfd ;
	cli->ssl = ssl ;
	cli->close = false ;
	
	return cli ;
}

void free_client (client *cli)
{
	free_req_buf (&cli->req_buf) ;
	free_resp_buf (&cli->resp_buf) ;
	
	if (cli->ssl)
	{
		SSL_shutdown (cli->ssl) ;
		SSL_free (cli->ssl) ;
	}
	
	free (cli) ;
}