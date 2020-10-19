#ifndef HTTP_H
#define HTTP_H

#include <stdbool.h>
#include "parse.h"
#include "cgi.h"
#include "header.h"

#define HTTP_VERSION "HTTP/1.1"
#define SERVER_NAME "Liso/0.0.1"

#define BUF_SIZE 10000 // TODO use double buffer

typedef struct
{
	void (*callback) (void *arg) ;
	void *arg ;
} resp_event ;

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
	resp_event evt ;
} resp_buffer ;

int init_req_buf (req_buffer *req_buf) ;
int init_resp_buf (resp_buffer *resp_buf) ;
void clr_req_buf (req_buffer *req_buf) ;
void clr_resp_buf (resp_buffer *resp_buf) ;
void free_req_buf (req_buffer *req_buf) ;
void free_resp_buf (resp_buffer *resp_buf) ;
int parse_req (req_buffer *req_buf) ;

int read_req (int fd, req_buffer *req_buf, SSL *ssl) ;
bool req_read_done (req_buffer *req_buf) ;
int send_resp (int fd, resp_buffer *resp_buf, SSL *ssl) ;
bool resp_send_done (resp_buffer *resp_buf) ;
bool resp_tobe_send (resp_buffer *resp_buf) ;
void reply (int scode, Response *resp, resp_buffer *resp_buf) ;

void set_resp_evt (resp_buffer *resp_buf, resp_event evt) ;
bool handle_request (req_buffer *req_buf, resp_buffer *resp_buf) ;

#endif