#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "cgi.h"
#include "log.h"

CGI_envp *new_cgi_envp ()
{
	CGI_envp *cgi_envp ;
	
	if ((cgi_envp = (CGI_envp *) malloc (sizeof(CGI_envp))) == NULL)
		return NULL ;
	
	cgi_envp->capacity = 8 ;
	cgi_envp->size = 0 ;
	if ((cgi_envp->envp = (char **) malloc (cgi_envp->capacity * sizeof(char **))) == NULL)
		return NULL ;
	
	cgi_envp->envp[0] = NULL ;
	return cgi_envp ;
}

void free_cgi_envp (CGI_envp *cgi_envp)
{
	int i ;
	
	for (i = 0; i < cgi_envp->size; i++)
		free (cgi_envp->envp[i]) ;
	
	free (cgi_envp->envp) ;
	free (cgi_envp) ;
}

int fill_cgi_envp (CGI_envp *cgi_envp, const char *name, const char *value)
{
	if (cgi_envp->size + 1 == cgi_envp->capacity)
	{
		cgi_envp->capacity <<= 1 ;
		if ((cgi_envp->envp = (char **) realloc (cgi_envp->envp, cgi_envp->capacity * sizeof(char **))) == NULL)
		{
			LOG_ERROR ("Can not alloc envp for cgi.") ;
			return -1 ;
		}
	}
	
	if ((cgi_envp->envp[cgi_envp->size] = (char *) malloc (strlen(name) + strlen(value) + 2)) == NULL)
	{
		LOG_ERROR ("Can not alloc envp for cgi.") ;
		return -1 ;
	}
	
	strcpy (cgi_envp->envp[cgi_envp->size], name) ;
	strcat (cgi_envp->envp[cgi_envp->size], "=") ;
	strcat (cgi_envp->envp[cgi_envp->size], value) ;
	
	cgi_envp->size++ ;
	cgi_envp->envp[cgi_envp->size] = NULL ;
	return 0 ;
}

char *get_cgi_filename (char *req_path)
{
	char *qmark = strstr (req_path, "?") ;
	
	if (qmark)
		*qmark = '\0' ;
	return req_path ;
}

char *get_cgi_query (char *req_path)
{
	char *qmark = strstr (req_path, "?") ;
	
	if (qmark)
		return qmark + 1 ;
	return NULL ;
}

CGI *new_cgi (char *argv[], CGI_envp *cgi_envp)
{
	CGI *cgi ;
	int stdin_pipe[2] ;
	int stdout_pipe[2] ;
	
	if (argv[0] == NULL)
	{
		LOG_ERROR ("No CGI filename in the argument.");
		return NULL ;
	}
	
	if (pipe(stdin_pipe) < 0)
	{
		LOG_ERROR ("Error piping for stdin.");
		return NULL ;
	}

	if (pipe(stdout_pipe) < 0)
	{
		LOG_ERROR ("Error piping for stdout.");
		return NULL ;
	}

	switch (fork())
	{
	case -1:
		LOG_ERROR ("Faild to fork.") ;
		return NULL ;
	case 0:
		close(stdout_pipe[0]) ;
		close(stdin_pipe[1]) ;
		dup2 (stdin_pipe[0], STDIN_FILENO) ;
		dup2 (stdout_pipe[1], STDOUT_FILENO) ;
		if (execve(argv[0], argv, cgi_envp->envp))
		{
			LOG_ERROR ("Error execute CGI [%s].", argv[0]);
			return NULL ;
		}
	default:
		close(stdout_pipe[1]) ;
		close(stdin_pipe[0]) ;
		cgi = (CGI *) malloc (sizeof(CGI)) ;
		cgi->in = stdout_pipe[0] ;
		cgi->out = stdin_pipe[1] ;
		cgi->in_done = false ;
		cgi->in_buf = NULL ;
		cgi->out_buf = NULL ;
	}
	
	return cgi ;
}

void free_cgi (CGI *cgi)
{
	close (cgi->in) ;
	close (cgi->out) ;
	free (cgi) ;
}