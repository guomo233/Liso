#ifndef CGI_H
#define CGI_H

#include <stdbool.h>

#define CGI_VERSION "CGI/1.1"

typedef struct
{
	int in ;
	int out ;
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
int fill_cgi_envp (CGI_envp *cgi_envp, const char *name, const char *value) ;
void free_cgi_envp (CGI_envp *cgi_envp) ;
char *get_cgi_query (char *req_path) ;

#endif