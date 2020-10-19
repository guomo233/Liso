/******************************************************************************
* echo_server.c                                                               *
*                                                                             *
* Description: This file contains the C source code for an echo server.  The  *
*              server runs on a hard-coded port and simply write back anything*
*              sent to it by connected clients.  It does not support          *
*              concurrent clients.                                            *
*                                                                             *
* Authors: Athula Balachandran <abalacha@cs.cmu.edu>,                         *
*          Wolf Richter <wolf@cs.cmu.edu>                                     *
*                                                                             *
*******************************************************************************/

#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include "client.h"
#include "fdpool.h"
#include "http.h"
#include "log.h"

fd_pool fdp ;
static int http_listenfd, https_listenfd ;
static SSL_CTX *ssl_ctx ;
char *www_folder, *cgi_folder ;
int http_port, https_port ;
FILE *logfile ;

static int close_socket(int sock)
{
	if (close(sock))
	{
		LOG_ERROR("Failed closing socket.");
		return 1;
	}
	return 0;
}

static void server_shutdown (int state)
{
	if (http_listenfd > 0) close_socket (http_listenfd) ;
	if (https_listenfd > 0) close_socket (https_listenfd) ;
	if (ssl_ctx) SSL_CTX_free (ssl_ctx) ;
	exit (state) ;
}

static int open_listenfd (int port)
{
	int sock, optval ;
	struct sockaddr_in addr;
	
	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1)
	{
		LOG_ERROR("Failed creating socket.") ;
		return -1 ;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	
	optval = 1 ;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) ;

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)))
	{
		close_socket(sock);
		LOG_ERROR("Failed binding socket.");
		return -1 ;
	}

	if (listen(sock, 5))
	{
		close_socket(sock);
		LOG_ERROR("Error listening on socket.");
		return -1;
	}
	
	return sock ;
}

static void ssl_init (const char *cert_path, const char *pkey_path)
{
	SSL_library_init();
	if ((ssl_ctx = SSL_CTX_new(TLSv1_server_method())) == NULL)
	{
		LOG_ERROR ("Faild to create SSL context create.") ;
		server_shutdown (EXIT_FAILURE) ;
	}
	
	if (SSL_CTX_use_certificate_file(ssl_ctx, cert_path, SSL_FILETYPE_PEM) < 0)
	{
		LOG_ERROR ("Faild to load certificate file.") ;
		server_shutdown (EXIT_FAILURE) ;
	}
	
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, pkey_path, SSL_FILETYPE_PEM) < 0)
	{
		LOG_ERROR ("Faild to load private key file.") ;
		server_shutdown (EXIT_FAILURE) ;
	}
	
	if (!SSL_CTX_check_private_key(ssl_ctx))
	{
		LOG_ERROR ("Private key and certificate don't match.") ;
		server_shutdown (EXIT_FAILURE) ;
	}
}

static void signal_handler (int sig)
{
	switch(sig)
	{
	case SIGHUP:
		// TODO rehash the server
		break ;
	case SIGTERM: server_shutdown (EXIT_SUCCESS) ;
	default: LOG_ERROR ("Unhandled signal [%d].", sig) ;
	}       
}

static void daemonize (const char *lock_file, const int log_fd)
{
	int i, stdin_fd, lock_fd ;
	char pid[8] ;
	
	switch (fork())
	{
	case -1:
		LOG_ERROR ("Faild to fork.") ;
		server_shutdown (EXIT_FAILURE) ;
	case 0: break ;
	default: server_shutdown (EXIT_SUCCESS) ;
	}
	
	if (setsid() < 0)
	{
		LOG_ERROR ("Faild to create new session.") ;
		server_shutdown (EXIT_FAILURE) ;
	}
	
	switch (fork())
	{
	case -1:
		LOG_ERROR ("Faild to fork.") ;
		server_shutdown (EXIT_FAILURE) ;
	case 0: break ;
	default: server_shutdown (EXIT_SUCCESS) ;
	}
	
	umask(027);
	
	for (i = getdtablesize(); i>=0; i--)
		if (i != log_fd)
			close(i);

	stdin_fd = open("/dev/null", O_RDWR) ;
	if (stdin_fd != STDIN_FILENO)
	{
		LOG_ERROR ("Faild to reopen STDIN_FILENO to /dev/null.") ;
		server_shutdown (EXIT_FAILURE) ;
	}
	if (dup2 (STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO)
	{
		LOG_ERROR ("Faild to reopen STDOUT_FILENO to /dev/null.") ;
		server_shutdown (EXIT_FAILURE) ;
	}
	if (dup2 (STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO)
	{
		LOG_ERROR ("Faild to reopen STDERR_FILENO to /dev/null.") ;
		server_shutdown (EXIT_FAILURE) ;
	}
	
	if ((lock_fd = open (lock_file, O_RDWR | O_CREAT, 0640)) < 0)
	{
		LOG_ERROR ("Faild to open lock file [%s].", lock_file) ;
		server_shutdown (EXIT_FAILURE) ;
	}
	
	if (lockf(lock_fd, F_TLOCK, 0) < 0)
	{
		LOG_ERROR ("Faild to lock file [%s].", lock_file) ;
		server_shutdown (EXIT_SUCCESS) ;
	}
	
	sprintf (pid, "%d\n", getpid());
	if (write (lock_fd, pid, strlen(pid)) < 0)
	{
		LOG_ERROR ("Faild to write pid to lock file [%s].", lock_file) ;
		server_shutdown (EXIT_FAILURE) ;
	}
	
	signal (SIGCHLD, SIG_IGN) ;
	signal (SIGHUP, signal_handler) ;
	signal (SIGTERM, signal_handler) ;
}

static void server_init (int argc, char* argv[])
{
	const char *cert_path, *pkey_path, *lock_file ;
	
	if (argc != 9)
	{
		fprintf (stderr, "Usage: lisod <HTTP port> <HTTPS port> <log file> <lock file> <www folder> <CGI script path> <private key file> <certificate file>\n") ;
		server_shutdown (EXIT_SUCCESS) ;
	}
	
	lock_file = argv[4] ;
	www_folder = argv[5] ;
	cgi_folder = argv[6] ;
	pkey_path = argv[7] ;
	cert_path = argv[8] ;
	
	if ((logfile = fopen (argv[3], "a")) == NULL)
	{
		fprintf (stderr, "Log file can not open.\n") ;
		server_shutdown (EXIT_FAILURE) ;
	}
	
	http_port = atoi (argv[1]) ;
	if (!http_port)
	{
		LOG_ERROR ("The format of HTTP port error.") ;
		server_shutdown (EXIT_SUCCESS) ;
	}
	
	https_port = atoi (argv[2]) ;
	if (!https_port)
	{
		LOG_ERROR ("The format of HTTPS port error.") ;
		server_shutdown (EXIT_SUCCESS) ;
	}
	
    daemonize (lock_file, fileno(logfile)) ;
	
	if ((http_listenfd = open_listenfd(http_port)) < 0)
	{
		LOG_ERROR ("Open listen fd faild.") ;
		server_shutdown (EXIT_FAILURE) ;
	}
	
	if ((https_listenfd = open_listenfd(https_port)) < 0)
	{
		LOG_ERROR ("Open listen fd faild.") ;
		server_shutdown (EXIT_FAILURE) ;
	}
	
	ssl_init (cert_path, pkey_path) ;
	
	fdpool_init (&fdp) ;
	
	LOG_INFO ("Server start HTTP port [%d] HTTPS prot [%d].", http_port, https_port) ;
}

// For cp1
//void handle_echo (req_buffer *req_buf, resp_buffer *resp_buf)
//{
//    memcpy (resp_buf->buf, req_buf->buf, req_buf->size) ;
//    resp_buf->size = req_buf->size ;
//}

void write_client (int cfd, void *arg)
{
	client *cli = (client *) arg ;
	
	if (send_resp(cfd, &cli->resp_buf, cli->ssl) < 0)
	{
		LOG_ERROR("Error sending to client socket.");
		reply (500, NULL, &cli->resp_buf) ;
		return ;
	}
	
	if (!resp_tobe_send(&cli->resp_buf))
		fdpool_remove (&fdp, cfd, WRITE_FD) ;
	
	if (resp_send_done(&cli->resp_buf))
	{
		clr_req_buf (&cli->req_buf) ;
		clr_resp_buf (&cli->resp_buf) ;
		
		if (cli->close)
		{
			fdpool_remove (&fdp, cfd, READ_FD) ;
			close (cfd) ;
			free_client (cli) ;
		}
	}
}

void set_writeable (void *arg)
{
	client *cli = (client *) arg ;
	fd_event evt ;
	
	evt.callback = write_client ;
	evt.arg = cli ;
	fdpool_add (&fdp, cli->cfd, WRITE_FD, evt) ;
}

void read_client (int cfd, void *arg)
{
	client *cli = (client *) arg ;
	int ret ;
	
	if (cli->close)
		return ;
	
	ret = read_req (cfd, &cli->req_buf, cli->ssl) ;
	if (ret < 0)
	{
		reply (500, NULL, &cli->resp_buf) ;
		return ;
	}
	else if (ret == 0)
	{
		LOG_INFO ("Client shutdown.") ;
		cli->close = true ;
		return ;
	}
	
	if (parse_req (&cli->req_buf) < 0)
	{
		reply (400, NULL, &cli->resp_buf) ;
		return ;
	}
	
	if (req_read_done(&cli->req_buf))
		// handle_echo (req_buf, resp_buf) ; // For cp1
		cli->close = handle_request (&cli->req_buf, &cli->resp_buf) ;
}

void accept_client (int listenfd, void *arg)
{
	bool https = (bool) arg ;
	int cli_sock ;
	socklen_t cli_size ;
	struct sockaddr_in cli_addr ;
	SSL *ssl = NULL ;
	client *cli ;
	fd_event fd_evt ;
	resp_event resp_evt ;
	
	cli_size = sizeof(cli_addr) ;
	if ((cli_sock = accept(listenfd, (struct sockaddr *) &cli_addr,
								&cli_size)) == -1)
	{
		LOG_ERROR ("Faild to accept client.") ;
		return ;
	}

	if (https)
	{
		ssl = SSL_new(ssl_ctx) ;
		SSL_set_fd (ssl, cli_sock) ;
		if (SSL_accept(ssl) < 0)
		{
			LOG_ERROR("Faild to create SSL connection.") ;
			close_socket (cli_sock) ;
			return ;
		}
	}

	fcntl (cli_sock, F_SETFL, O_NONBLOCK) ;
	cli = new_client (cli_sock, ssl) ;
	
	if (cli == NULL)
	{
		LOG_ERROR ("Faild to add client to pool.") ;
		close_socket(cli_sock) ;
		return ;
	}
	
	fd_evt.callback = read_client ;
	fd_evt.arg = (void *) cli ;
	fdpool_add (&fdp, cli_sock, READ_FD, fd_evt) ;
	
	resp_evt.callback = set_writeable ;
	resp_evt.arg = (void *) cli ;
	set_resp_evt (&cli->resp_buf, resp_evt) ;
}

int main(int argc, char* argv[])
{
	fd_event http_evt ;
	fd_event https_evt ;
	
	server_init (argc, argv) ;
	
	http_evt.callback = accept_client ;
	http_evt.arg = (void *) 0 ;
	fdpool_add (&fdp, http_listenfd, READ_FD, http_evt) ;
	
	https_evt.callback = accept_client ;
	https_evt.arg = (void *) 1 ;
	fdpool_add (&fdp, https_listenfd, READ_FD, https_evt) ;
	
	event_loop (&fdp) ;

	server_shutdown (EXIT_SUCCESS) ;
}