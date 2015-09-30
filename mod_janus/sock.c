
/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

/* barrows heavily from linux/file.h and linux/net/socket.c */

#define __NO_VERSION__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>

#include <linux/sched.h>        /* for wait queues and current  and find_task */
#include<linux/fs.h>
#include<linux/file.h>
#include "modtools.h"
/*
 * Check whether the specified fd has an open file.
 */
static struct file * check_fd(struct task_struct * tp,unsigned int fd)
{
	struct file * file = NULL;
    kassert(tp);
    kassert(tp->files);
    
	if (fd < tp->files->max_fds)
		file = tp->files->fd[fd];

	return file;
}

struct file * get_file(struct task_struct * tp,unsigned int fd)
{
	struct file * file;
    kassert(tp);

    file = check_fd(tp,fd);

	return file;
}

static struct socket * sock_inode_lookup(struct inode *inode)
{
	return &inode->u.socket_i;
}


struct socket * lookup_socket(struct task_struct * tp,
    int fd, int *err)
{
	struct file *file;
	struct inode *inode;
	struct socket *sock;
    
    kassert(tp);

	if (!(file = get_file(tp,fd))) {
		*err = -EBADF;
		return NULL;
	}

	inode = file->f_dentry->d_inode;

	if (!inode || !inode->i_sock || !(sock = sock_inode_lookup(inode))) {
		*err = -ENOTSOCK;
		return NULL;
	}

	if (sock->file != file) {
		printk(KERN_ERR "socki_lookup: socket file changed!\n");
        return NULL;
	}

	return sock;
}


