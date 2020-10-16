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
#include <sys/mman.h>
#include <openssl/ssl.h>
#include "parse.h"
#include "cpool.h"
#include "http.h"
#include "log.h"

#ifdef __APPLE__
#include <sys/uio.h>
static ssize_t _sendfile (int out_fd, int in_fd, off_t *offset, size_t count)
{
    off_t len = count ;
    
    if (sendfile(in_fd, out_fd, *offset, &len, NULL, 0) < 0)
        return -1 ;
    else
    {
        *offset += len ;
        return len ;
    }
}
#else
#include <sys/sendfile.h>
#define _sendfile sendfile
#endif

#define MAX_SEND 4096
#define MAX_RECV 4096

static client_pool pool ;
static fd_set read_set, write_set ;
static int http_listenfd, https_listenfd ;
static SSL_CTX *ssl_ctx ;
char *lock_file, *www_folder, *cgi_path ;
FILE *logfile ;

static int min (int a, int b)
{
    return a < b ? a : b ;
}

static int max (int a, int b)
{
    return a > b ? a : b ;
}

int close_socket(int sock)
{
    if (close(sock))
    {
        LOG_ERROR("Failed closing socket.\n");
        return 1;
    }
    return 0;
}

int open_listenfd (int port)
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

SSL_CTX * ssl_init (const char *cert_path, const char *pkey_path)
{
    SSL_CTX *ctx ;
    
    SSL_library_init();
    if ((ctx = SSL_CTX_new(TLSv1_server_method())) == NULL)
    {
        LOG_ERROR ("Faild to create SSL context create.") ;
        return NULL ;
    }
    
    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) < 0)
    {
        LOG_ERROR ("Faild to load certificate file.") ;
        return NULL ;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, pkey_path, SSL_FILETYPE_PEM) < 0)
    {
        LOG_ERROR ("Faild to load private key file.") ;
        return NULL ;
    }
    
    if (!SSL_CTX_check_private_key(ctx))
    {
        LOG_ERROR ("Private key and certificate don't match.") ;
        return NULL ;
    }
    
    return ctx ;
}

int server_init (int argc, char* argv[])
{
    int http_port, https_port ;
    const char *cert_path, *pkey_path ;
    
    if (argc != 9)
    {
        fprintf (stderr, "Usage: lisod <HTTP port> <HTTPS port> <log file> <lock file> <www folder> <CGI script path> <private key file> <certificate file>\n") ;
        return -1 ;
    }
    
    lock_file = argv[4] ;
    www_folder = argv[5] ;
    cgi_path = argv[6] ;
    pkey_path = argv[7] ;
    cert_path = argv[8] ;
    
    if ((logfile = fopen (argv[3], "a")) == NULL)
    {
        fprintf (stderr, "Log file can not open.\n") ;
        return -1 ;
    }
    
    http_port = atoi (argv[1]) ;
    if (!http_port)
    {
        LOG_ERROR ("The format of HTTP port error.") ;
        return -1 ;
    }
    
    https_port = atoi (argv[2]) ;
    if (!https_port)
    {
        LOG_ERROR ("The format of HTTPS port error.") ;
        return -1 ;
    }
    
    if ((http_listenfd = open_listenfd(http_port)) < 0)
    {
        LOG_ERROR ("Open listen fd faild.") ;
        return -1 ;
    }
    
    if ((https_listenfd = open_listenfd(https_port)) < 0)
    {
        LOG_ERROR ("Open listen fd faild.") ;
        return -1 ;
    }
    
    FD_SET (http_listenfd, &read_set) ;
    FD_SET (https_listenfd, &read_set) ;
    
    if ((ssl_ctx = ssl_init(cert_path, pkey_path)) == NULL)
    {
        LOG_ERROR ("Faild to initialize SSL.") ;
        return -1 ;
    }
    
    pool_init (&pool, &read_set, &write_set) ;
    
    fprintf(stdout, "----- Liso Server -----\n");
    LOG_INFO ("[Server start] HTTP port: %d HTTPS prot: %d", http_port, https_port) ;
    return 0 ;
}

// For cp1
//void handle_echo (req_buffer *req_buf, resp_buffer *resp_buf)
//{
//    memcpy (resp_buf->buf, req_buf->buf, req_buf->size) ;
//    resp_buf->size = req_buf->size ;
//}

void handle_clients (fd_set *ready_read, fd_set *ready_write)
{
    int i, cfd, parse_ret, ret ;
    size_t remain ;
    const char *body_size ;
    char *f_mmap ;
    resp_buffer *resp_buf ;
    req_buffer *req_buf ;
    SSL *ssl ;
    
    for (i = 0; i < pool.n_cli; i++)
    {
        if (FD_ISSET(pool.cli[i].fd, ready_read) && !pool.cli[i].resp_buf.close)
        {
            req_buf = &pool.cli[i].req_buf ;
            resp_buf = &pool.cli[i].resp_buf ;
            cfd = pool.cli[i].fd ;
            ssl = pool.cli[i].ssl ;
            
            remain = req_buf->capacity - req_buf->size ;
            if (remain <= 0)
            {
                LOG_ERROR ("Size of request buffer out of range.") ;
                // TODO reply
                continue ;
            }
            
            if (ssl)
                ret = SSL_read(ssl, req_buf->buf + req_buf->size, min (MAX_RECV, remain));
            else
                ret = recv(cfd, req_buf->buf + req_buf->size, min (MAX_RECV, remain), 0) ;
            if (ret < 0)
            {
                LOG_ERROR("Error reading from client socket.\n");
                // TODO reply
                continue ;
            }
            else if (ret == 0)
            {
                LOG_INFO ("Client shutdown.") ;
                resp_buf->close = true ;
                continue ;
            }
            
            LOG_INFO ("Received %d bytes.", ret) ;
            req_buf->size += ret ;
            if (!req_buf->req)
            {
                req_buf->req = parse (req_buf->buf, min(req_buf->size, 8192), &req_buf->header_size, &parse_ret) ;
                if (req_buf->req)
                {
                    body_size = get_header (req_buf->req, "Content-Length") ;
                    req_buf->body_size = body_size ? atoi (body_size) : 0 ;
                    // TODO check valid of content length
                }
                else if (req_buf->size > 8192 || parse_ret == BAD_REQ)
                // TODO receive is done ( < 8192) but can not parse
                    send_resp (400, NULL, resp_buf) ;
            }
            
            if (req_buf->req && req_buf->size >= req_buf->header_size + req_buf->body_size)
                handle_request (req_buf, resp_buf) ;
                // handle_echo (req_buf, resp_buf) ; // For cp1
            
            if (resp_buf->size - resp_buf->offset > 0 || 
                 resp_buf->fd > 0)
                FD_SET (cfd, &write_set) ;
        }
        
        if (FD_ISSET(pool.cli[i].fd, ready_write))
        {
            req_buf = &pool.cli[i].req_buf ;
            resp_buf = &pool.cli[i].resp_buf ;
            cfd = pool.cli[i].fd ;
            ssl = pool.cli[i].ssl ;
            
            remain = resp_buf->size - resp_buf->offset ;
            if (remain > 0)
            {
                if (ssl)
                    ret = SSL_write(ssl, resp_buf->buf + resp_buf->offset, min(MAX_SEND, remain)) ;
                else
                    ret = send(cfd, resp_buf->buf + resp_buf->offset, min(MAX_SEND, remain), 0) ;
                if (ret < 0)
                {
                    LOG_ERROR("Error sending to client socket.\n");
                    // TODO reply
                    continue ;
                }
                
                LOG_INFO ("Send %d bytes.", ret) ;
                resp_buf->offset += ret ;
                if (resp_buf->size == resp_buf->offset)
                    clr_resp_buf (resp_buf, BUF_CLR) ;
            }
            
            if (resp_buf->size == 0 && resp_buf->fd > 0)
            {
                if (ssl)
                {
                    // TODO use KTLS
                    remain = resp_buf->f_size - resp_buf->f_offset ;
                    f_mmap = mmap (NULL, remain, PROT_READ, MAP_PRIVATE, resp_buf->fd, resp_buf->f_offset) ;
                    if ((ret = SSL_write(ssl, f_mmap, min(MAX_SEND, remain))) < 0)
                    {
                        LOG_ERROR("Error sending to client socket.\n");
                        send_resp (500, NULL, resp_buf) ;
                        continue ;
                    }
                    munmap (f_mmap, remain) ;
                    
                    resp_buf->f_offset += ret ;
                }
                else
                {
                    if (_sendfile(cfd, resp_buf->fd, &resp_buf->f_offset, min(MAX_SEND, resp_buf->f_size)) < 0)
                    {
                        LOG_ERROR("Error sending to client socket.\n");
                        send_resp (500, NULL, resp_buf) ;
                        continue ;
                    }
                }
                
                if (resp_buf->f_offset == resp_buf->f_size)
                    clr_resp_buf (resp_buf, FILE_CLR) ;
            }
            
            if (resp_buf->size == 0 && resp_buf->fd < 0)
            {
                // TODO 2 or more request were read at once
                clr_req_buf (req_buf) ;
                FD_CLR (cfd, &write_set) ;
                
                if (resp_buf->close)
                    pool_remove (&pool, cfd) ;
            }
        }
    }
}

int main(int argc, char* argv[])
{
    int client_sock, maxfd ;
    struct sockaddr_in cli_addr;
    socklen_t cli_size ;
    fd_set ready_read, ready_write ;
    SSL *ssl;
    
    if (server_init (argc, argv) < 0)
        return EXIT_FAILURE ;
    
    /* finally, loop waiting for input and then write it back */
    LOG_INFO ("Event loop begin.") ;
    while (1)
    {
        ready_read = read_set ;
        ready_write = write_set ;
        maxfd = max (max(pool.maxfd, pool.maxfd),
                    max(http_listenfd, https_listenfd)) ;
        select (maxfd + 1, &ready_read, &ready_write, NULL, NULL) ;
        
        if (FD_ISSET(http_listenfd, &ready_read))
        {
            cli_size = sizeof(cli_addr) ;
            if ((client_sock = accept(http_listenfd, (struct sockaddr *) &cli_addr,
                                        &cli_size)) == -1)
            {
                LOG_ERROR("Error accepting HTTP connection.") ;
                continue ;
            }
            
            fcntl (client_sock, F_SETFL, O_NONBLOCK) ;
            pool_add (&pool, client_sock, NULL) ;
        }
        
        if (FD_ISSET(https_listenfd, &ready_read))
        {
            cli_size = sizeof(cli_addr) ;
            if ((client_sock = accept(https_listenfd, (struct sockaddr *) &cli_addr,
                                        &cli_size)) == -1)
            {
                LOG_ERROR("Error accepting HTTPS connection.") ;
                continue ;
            }

            ssl = SSL_new(ssl_ctx) ;
            SSL_set_fd (ssl, client_sock) ;
            if (SSL_accept(ssl) < 0)
            {
                LOG_ERROR("Faild to create SSL connection.") ;
                close_socket (client_sock) ;
                continue ;
            }

            fcntl (client_sock, F_SETFL, O_NONBLOCK) ;
            pool_add (&pool, client_sock, ssl) ;
        }
        
        handle_clients (&ready_read, &ready_write) ;
    }

    close_socket(http_listenfd);
    SSL_CTX_free (ssl_ctx) ;

    return EXIT_SUCCESS;
}