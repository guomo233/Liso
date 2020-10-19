#ifndef CGI_H
#define CGI_H

#include <stdbool.h>

#define CGI_VERSION "CGI/1.1"

typedef struct
{
	char *buf ;
	size_t size ;
	off_t offset ;
	size_t capacity ;
} CGI_buffer ;

typedef struct
{
	int in ;
	int out ;
	bool in_done ;
	CGI_buffer *in_buf ;
	CGI_buffer *out_buf ;
} CGI ;

typedef struct
{
	char **envp ;
	int capacity ;
	int size ;
} CGI_envp ;

CGI *new_cgi (char *argv[], CGI_envp *cgi_envp) ;
void free_cgi (CGI *cgi) ;
CGI_envp *new_cgi_envp () ;
void free_cgi_envp (CGI_envp *cgi_envp) ;
int fill_cgi_envp (CGI_envp *cgi_envp, const char *name, const char *value) ;
char *get_cgi_query (char *req_path) ;
char *get_cgi_filename (char *req_path) ;

#endif