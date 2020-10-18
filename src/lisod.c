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
#include "cpool.h"
#include "fdpool.h"
#include "cio.h"
#include "http.h"
#include "log.h"

static client_pool cpool ;
static fd_pool fdp ;
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
    fdpool_add (&fdp, http_listenfd, READ_FD) ;
    fdpool_add (&fdp, https_listenfd, READ_FD) ;
    
    LOG_INFO ("Server start HTTP port [%d] HTTPS prot [%d].", http_port, https_port) ;
}

// For cp1
//void handle_echo (req_buffer *req_buf, resp_buffer *resp_buf)
//{
//    memcpy (resp_buf->buf, req_buf->buf, req_buf->size) ;
//    resp_buf->size = req_buf->size ;
//}

static void handle_clients ()
{
    int i, ret ;
    int remain ;
    CGI *cgi ;
    resp_buffer *resp_buf ;
    req_buffer *req_buf ;
    SSL *ssl ;
    
    for (i = 0; i < cpool.n_cli; i++)
    {
        if (!cpool.cli[i].close && readable(&fdp, cpool.cli[i].fd))
        {
            ret = read_req (cpool.cli[i].fd, &cpool.cli[i].req_buf, cpool.cli[i].ssl) ;
            if (ret < 0)
            {
                write_resp (500, NULL, &cpool.cli[i].resp_buf) ;
                continue ;
            }
            else if (ret == 0)
            {
                LOG_INFO ("Client shutdown.") ;
                cpool.cli[i].close = true ;
                continue ;
            }
            
            if (parse_req (&cpool.cli[i].req_buf) < 0)
            {
                write_resp (400, NULL, &cpool.cli[i].resp_buf) ;
                continue ;
            }
            
            if (req_read_done(&cpool.cli[i].req_buf))
            {
                // handle_echo (req_buf, resp_buf) ; // For cp1
                cpool.cli[i].close = handle_request (&cpool.cli[i].req_buf, &cpool.cli[i].resp_buf) ;
                
                if (resp_tobe_send(&cpool.cli[i].resp_buf))
                    fdpool_add (&fdp, cpool.cli[i].fd, WRITE_FD) ;
                    
                if (cpool.cli[i].resp_buf.cgi)
                {
                    if (cpool.cli[i].req_buf.body_size > 0)
                    {
                        cpool.cli[i].req_buf.offset = cpool.cli[i].req_buf.header_size ;
                        fdpool_add (&fdp, cpool.cli[i].resp_buf.cgi->out, WRITE_FD) ;
                    }
                    fdpool_add (&fdp, cpool.cli[i].resp_buf.cgi->in, READ_FD) ;
                }
            }
        }
        
        if (writeable(&fdp, cpool.cli[i].fd))
        {
            if (send_resp (cpool.cli[i].fd, &cpool.cli[i].resp_buf, cpool.cli[i].ssl) < 0)
            {
                LOG_ERROR("Error sending to client socket.");
                write_resp (500, NULL, &cpool.cli[i].resp_buf) ;
                continue ;
            }
            
            if (!resp_tobe_send(&cpool.cli[i].resp_buf))
                fdpool_remove (&fdp, cpool.cli[i].fd, WRITE_FD) ;
            
            if (resp_send_done(&cpool.cli[i].resp_buf))
            {
                clr_req_buf (&cpool.cli[i].req_buf) ;
                clr_resp_buf (&cpool.cli[i].resp_buf) ;
                
                if (cpool.cli[i].close)
                {
                    cpool_remove (&cpool, i) ;
                    fdpool_remove (&fdp, cpool.cli[i].fd, READ_FD) ;
                    close (cpool.cli[i].fd) ;
                }
            }
        }
        
        if (cpool.cli[i].resp_buf.cgi && readable(&fdp, cpool.cli[i].resp_buf.cgi->in))
        {
            cgi = cpool.cli[i].resp_buf.cgi ;
            resp_buf = &cpool.cli[i].resp_buf ;
            
            remain = resp_buf->capacity - resp_buf->size ;
            if (remain <= 0)
            {
                LOG_ERROR ("Size of response buffer out of range.") ;
                // TODO reply
                continue ;
            }
            
            ret = read(cgi->in, resp_buf->buf + resp_buf->size, remain) ;
            if (ret < 0)
            {
                LOG_ERROR("Error reading to CGI.\n");
                // TODO reply
                continue ;
            }
            else if (ret == 0)
            {
                fdpool_remove (&fdp, cgi->in, READ_FD) ;
                close (cgi->in) ;
                cgi->in_done = true ;
                continue ;
            }
            
            resp_buf->size += ret ;
            fdpool_add (&fdp, cpool.cli[i].fd, WRITE_FD) ;
            LOG_INFO ("Received %d bytes from CGI.", ret) ;
        }
        
        if (cpool.cli[i].resp_buf.cgi && writeable(&fdp, cpool.cli[i].resp_buf.cgi->out))
        {
            req_buf = &cpool.cli[i].req_buf ;
            resp_buf = &cpool.cli[i].resp_buf ;
            ssl = cpool.cli[i].ssl ;
            cgi = resp_buf->cgi ;
            
            remain = req_buf->header_size + req_buf->body_size - req_buf->offset ;
            if (remain > 0)
            {
                ret = write (cgi->out, req_buf->buf + req_buf->offset, remain) ;
                if (ret < 0)
                {
                    LOG_ERROR("Error writing to CGI.\n");
                    // TODO reply
                    continue ;
                }
                
                req_buf->offset += ret ;
                LOG_INFO ("Send %d bytes to CGI.", ret) ;
            }
            
            if (req_buf->offset >= req_buf->header_size + req_buf->body_size)
            {
                fdpool_remove (&fdp, cgi->out, WRITE_FD) ;
                close (cgi->out) ;
            }
        }
    }
}

int accept_client (int listenfd, SSL *ssl)
{
    int client_sock ;
    socklen_t cli_size ;
    struct sockaddr_in cli_addr ;
    
    cli_size = sizeof(cli_addr) ;
    if ((client_sock = accept(listenfd, (struct sockaddr *) &cli_addr,
                                &cli_size)) == -1)
        return -1 ;

    if (ssl)
    {
        SSL_set_fd (ssl, client_sock) ;
        if (SSL_accept(ssl) < 0)
        {
            LOG_ERROR("Faild to create SSL connection.") ;
            close_socket (client_sock) ;
            return -1 ;
        }
    }

    fcntl (client_sock, F_SETFL, O_NONBLOCK) ;
    cpool_add (&cpool, client_sock, ssl) ;
    fdpool_add (&fdp, client_sock, READ_FD) ;
    
    return client_sock ;
}

int main(int argc, char* argv[])
{
    int client_sock ;
    SSL *ssl;
    
    server_init (argc, argv) ;
    
    while (1)
    {
        wait_event (&fdp) ;
        
        if (readable(&fdp, http_listenfd))
            if ((client_sock = accept_client(http_listenfd, NULL)) < 0)
            {
                LOG_ERROR("Error accepting HTTP connection.") ;
                continue ;
            }
        
        if (readable(&fdp, https_listenfd))
        {
            ssl = SSL_new(ssl_ctx) ;
            if ((client_sock = accept_client(https_listenfd, ssl)) < 0)
            {
                LOG_ERROR("Error accepting HTTP connection.") ;
                continue ;
            }
        }
        
        handle_clients () ;
    }

    server_shutdown (EXIT_SUCCESS) ;
}