#include "cpool.h"
#include "log.h"

static void swap (client *a, client *b)
{
	client tmp = *a ;
	*a = *b ;
	*b = tmp ;
}

int cpool_add (client_pool *cpool, int cfd, SSL *ssl)
{
	if (init_req_buf (&cpool->cli[cpool->n_cli].req_buf) < 0)
		return -1 ;
	if (init_resp_buf (&cpool->cli[cpool->n_cli].resp_buf) < 0)
		return -1 ;
	
	cpool->cli[cpool->n_cli].fd = cfd ;
	cpool->cli[cpool->n_cli].ssl = ssl ;
	cpool->cli[cpool->n_cli].close = false ;
	cpool->n_cli++ ;
	
	return 0 ;
}

void cpool_remove (client_pool *cpool, int cid)
{
	free_req_buf (&cpool->cli[cid].req_buf) ;
	free_resp_buf (&cpool->cli[cid].resp_buf) ;
	
	if (cpool->cli[cid].ssl)
	{
		SSL_shutdown (cpool->cli[cid].ssl) ;
		SSL_free (cpool->cli[cid].ssl) ;
	}
	
	swap (&cpool->cli[cid], &cpool->cli[--cpool->n_cli]) ;
}