/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/*
 * Raghavendra Suvvari, 2014
 * Stony Brook University
 *
 * Adopted wrapfs code to develop u2fs
*/


#include "wrapfs.h"

/*
 * returns: -ERRNO if error (returned to user)
 *          0: tell VFS to invalidate dentry
 *          1: dentry is valid
 */

/* In u2fs we are not using revalidate function
		to validate the dentry. */
static int wrapfs_d_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	/*struct path lower_path, saved_path;
	struct dentry *lower_dentry;*/
	int err = 1;

	/*if (nd && nd->flags & LOOKUP_RCU)
		return -ECHILD;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_op || !lower_dentry->d_op->d_revalidate)
		goto out;
	pathcpy(&saved_path, &nd->path);
	pathcpy(&nd->path, &lower_path);
	err = lower_dentry->d_op->d_revalidate(lower_dentry, nd);
	pathcpy(&nd->path, &saved_path);
out:
	wrapfs_put_lower_path(dentry, &lower_path);	*/
	return err;
}

static void wrapfs_d_release(struct dentry *dentry)
{

	/* release and reset the lower paths */
	if (!dentry)
		return;
	/* wrapfs_put_reset_lower_path(dentry); */
	free_dentry_private_data(dentry);
	return;
}

const struct dentry_operations wrapfs_dops = {
	.d_revalidate	= wrapfs_d_revalidate,
	.d_release	= wrapfs_d_release,
};
