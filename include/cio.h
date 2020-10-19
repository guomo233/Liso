#ifndef CIO_H
#define CIO_H

#include <openssl/ssl.h>
#include <stdbool.h>
#include "http.h"

bool req_read_done (req_buffer *req_buf) ;
bool resp_send_done (resp_buffer *resp_buf) ;
bool buf_send_done (resp_buffer *resp_buf) ;
bool file_send_done (resp_buffer *resp_buf) ;
bool cgi_send_done (resp_buffer *resp_buf) ;
int send_buf (int fd, resp_buffer *resp_buf, SSL *ssl) ;
bool resp_tobe_send (resp_buffer *resp_buf) ;
int read_req (int fd, req_buffer *req_buf, SSL *ssl) ;
int send_resp (int fd, resp_buffer *resp_buf, SSL *ssl) ;
int send_file (int fd, resp_file *resp_f, SSL *ssl) ;

#endif