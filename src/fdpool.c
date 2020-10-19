#include <stdlib.h>
#include "fdpool.h"

static fd_event rd_evt[FD_SETSIZE], wr_evt[FD_SETSIZE] ;

static int max (int a, int b)
{
	return a > b ? a : b ;
}

static void swap (int *a, int *b)
{
	int tmp = *a ;
	*a = *b ;
	*b = tmp ;
}

void fdpool_init (fd_pool *fdp)
{
	FD_ZERO (&fdp->read_set) ;
	FD_ZERO (&fdp->write_set) ;
	fdp->n_fd = 0 ;
	fdp->maxfd = 0 ;
}

void fdpool_add (fd_pool *fdp, int fd, int type, fd_event evt)
{
	if (!FD_ISSET(fd, &fdp->read_set) && !FD_ISSET(fd, &fdp->write_set))
	{
		fdp->maxfd = max (fdp->maxfd, fd) ;
		fdp->fd[fdp->n_fd++] = fd ;
	}
	
	if (type & READ_FD)
	{
		FD_SET (fd, &fdp->read_set) ;
		rd_evt[fd] = evt ;
	}
		
	if (type & WRITE_FD)
	{
		FD_SET (fd, &fdp->write_set) ;
		wr_evt[fd] = evt ;
	}
}

void fdpool_remove (fd_pool *fdp, int fd, int type)
{
	int i ;
	
	if (!FD_ISSET(fd, &fdp->read_set) && !FD_ISSET(fd, &fdp->write_set))
		return ;
	
	if (type & READ_FD)
		FD_CLR (fd, &fdp->read_set) ;

	if (type & WRITE_FD)
		FD_CLR (fd, &fdp->write_set) ;
	
	if (!FD_ISSET(fd, &fdp->read_set) && !FD_ISSET(fd, &fdp->write_set))
	{
		// TODO use heap
		fdp->maxfd = 0 ;
		for (i = 0; i < fdp->n_fd; i++)
		{
			if (fdp->fd[i] == fd)
				swap (&fdp->fd[i], &fdp->fd[--fdp->n_fd]) ;
			
			if (i < fdp->n_fd)
				fdp->maxfd = max (fdp->maxfd, fdp->fd[i]) ;
		}
	}
}

static bool readable (fd_pool *fdp, int fd)
{
	return FD_ISSET (fd, &fdp->ready_read) ;
}

static bool writeable (fd_pool *fdp, int fd)
{
	return FD_ISSET (fd, &fdp->ready_write) ;
}

void event_loop (fd_pool *fdp)
{
	int i ;
	
	while (1)
	{
		fdp->ready_read = fdp->read_set ;
		fdp->ready_write = fdp->write_set ;
		select (fdp->maxfd + 1, &fdp->ready_read, &fdp->ready_write, NULL, NULL) ;
		
		for (i = 0; i < fdp->n_fd; i++)
		{
			if (readable(fdp, fdp->fd[i]))
				rd_evt[fdp->fd[i]].callback (fdp->fd[i], rd_evt[fdp->fd[i]].arg) ;
				
			if (writeable(fdp, fdp->fd[i]))
				wr_evt[fdp->fd[i]].callback (fdp->fd[i], wr_evt[fdp->fd[i]].arg) ;
		}
	}
}