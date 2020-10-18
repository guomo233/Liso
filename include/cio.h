#ifndef CIO_H
#define CIO_H

#include <openssl/ssl.h>
#include <stdbool.h>
#include "parse.h"
#include "cgi.h"

#define BUF_SIZE 10000 // TODO use double buffer
#define BUF_CLR 1
#define FILE_CLR 2
#define CGI_CLR 4
#define ALL_CLR 7

typedef struct
{
	char *buf ;
	size_t size ;
	size_t capacity ;
	Request *req ;
	off_t offset ;
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
bool req_read_done (req_buffer *req_buf) ;
bool resp_send_done (resp_buffer *resp_buf) ;
bool buf_send_done (resp_buffer *resp_buf) ;
bool file_send_done (resp_buffer *resp_buf) ;
bool cgi_send_done (resp_buffer *resp_buf) ;
int send_buf (int fd, resp_buffer *resp_buf, SSL *ssl) ;
bool resp_tobe_send (resp_buffer *resp_buf) ;
int parse_req (req_buffer *req_buf) ;
int read_req (int fd, req_buffer *req_buf, SSL *ssl) ;
int send_resp (int fd, resp_buffer *resp_buf, SSL *ssl) ;
int send_file (int fd, resp_file *resp_f, SSL *ssl) ;
void clr_req_buf (req_buffer *req_buf) ;
void clr_resp_buf (resp_buffer *resp_buf) ;

#endif