#ifndef HEADER_H
#define HEADER_H

typedef struct
{
	char header_name[4096];
	char header_value[4096];
} Response_header;

typedef struct
{
	Response_header *headers;
	int header_count;
	int header_capacity ;
} Response ;

typedef struct
{
	char header_name[4096];
	char header_value[4096];
} Request_header;

//HTTP Request Header
typedef struct
{
	char http_version[50];
	char http_method[50];
	char http_uri[4096];
	Request_header *headers;
	int header_count;
	int header_capacity ;
} Request;

char *get_header (Request *req, char *name) ;
void free_request (Request *req) ;
Response *new_response () ;
void free_response (Response *resp) ;
int fill_header (char *name, char *value, Response *resp) ;

#endif