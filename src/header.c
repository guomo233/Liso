#include <stdlib.h>
#include <string.h>
#include "header.h"
#include "log.h"

char *get_header (Request *req, char *name)
{
	int i ;
	
	// TODO lowcast upcast compatibility
	for (i = 0; i < req->header_count; i++)
		if (!strcmp(req->headers[i].header_name, name))
			return req->headers[i].header_value ;
			
	return NULL ;
}

void free_request (Request *req)
{
	free (req->headers) ;
	free (req) ;
}

Response *new_response ()
{
	Response *resp = (Response *) malloc (sizeof(Response)) ;
	resp->header_count = 0 ;
	resp->header_capacity = 8 ;
	resp->headers = (Response_header *) malloc (sizeof(Response_header) * resp->header_capacity) ;
	return resp ;
}

void free_response (Response *resp)
{
	free (resp->headers) ;
	free (resp) ;
}

int fill_header (char *name, char *value, Response *resp)
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