#ifndef FDPOOL_H
#define FDPOOL_H

#include <sys/select.h>
#include <stdbool.h>

#define READ_FD 1
#define WRITE_FD 2

typedef struct
{
	void (*callback) (int fd, void *arg) ;
	void *arg ;
} fd_event ;

typedef struct
{
	int maxfd ;
	fd_set read_set ;
	fd_set write_set ;
	fd_set ready_read ;
	fd_set ready_write ;
	int fd[FD_SETSIZE] ;
	int n_fd ;
} fd_pool ;

void fdpool_remove (fd_pool *fdp, int fd, int type) ;
void fdpool_add (fd_pool *fdp, int fd, int type, fd_event evt) ;
void fdpool_init (fd_pool *fdp) ;
void event_loop (fd_pool *fdp) ;

#endif