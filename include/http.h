#ifndef HTTP_HANDLER_H
#define HTTP_HANDLER_H

#include <stdbool.h>
#include "parse.h"
#include "cio.h"
#include "cgi.h"

#define HTTP_VERSION "HTTP/1.1"
#define SERVER_NAME "Liso/0.0.1"

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

const char *get_ext (const char *filename) ;
Response *new_response () ;
void free_request (Request *req) ;
void free_response (Response *resp) ;
void write_resp (const int scode, Response *resp, resp_buffer *resp_buf) ;
int fill_header (const char *name, const char *value, Response *resp) ;
char *get_header (const Request *req, const char *name) ;
void get_mime (const char *filename, char *mime) ;
Response *gen_response (const Request *req) ;
void handle_head (const Request *req, resp_buffer *resp_buf) ;
void handle_post (const Request *req, const char *post_buf, size_t body_size, resp_buffer *resp_buf) ;
bool handle_request (req_buffer *req_buf, resp_buffer *resp_buf) ;

#endif