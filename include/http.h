#ifndef HTTP_HANDLER_H
#define HTTP_HANDLER_H

#include <stdbool.h>
#include "parse.h"
#include "cgi.h"

#define HTTP_VERSION "HTTP/1.1"
#define SERVER_NAME "Liso/0.0.1"

#define BUF_SIZE 10000 // TODO use double buffer
#define BUF_CLR 1
#define FILE_CLR 2
#define CGI_CLR 4
#define ALL_CLR 7

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
	char *buf ;
	size_t size ;
	off_t offset ;
	size_t capacity ;
	Request *req ;
	size_t header_size ;
	size_t body_size ;
} req_buffer ;

typedef struct
{
	int fd ;
	off_t offset ;
	size_t size ;
} resp_file ;

typedef struct
{
	char *buf ;
	size_t size ;
	off_t offset ;
	size_t capacity ;
	resp_file resp_f ;
	CGI *cgi ;
} resp_buffer ;

void free_req_buf (req_buffer *req_buf) ;
void free_resp_buf (resp_buffer *resp_buf) ;
int init_req_buf (req_buffer *req_buf) ;
int init_resp_buf (resp_buffer *resp_buf) ;
void clr_req_buf (req_buffer *req_buf) ;
void clr_resp_buf (resp_buffer *resp_buf) ;
int parse_req (req_buffer *req_buf) ;
char *get_ext (char *filename) ;
Response *new_response () ;
void free_request (Request *req) ;
void free_response (Response *resp) ;
void write_resp (int scode, Response *resp, resp_buffer *resp_buf) ;
int fill_header (char *name, char *value, Response *resp) ;
char *get_header (Request *req, char *name) ;
void get_mime (char *filename, char *mime) ;
Response *gen_response (Request *req) ;
void handle_head (Request *req, resp_buffer *resp_buf) ;
void handle_post (Request *req, char *post_buf, size_t body_size, resp_buffer *resp_buf) ;
bool handle_request (req_buffer *req_buf, resp_buffer *resp_buf) ;

#endif