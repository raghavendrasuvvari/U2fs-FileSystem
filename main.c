
/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009      Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
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
#include <linux/module.h>


/*
 * make sure the branch we just looked up (nd) makes sense:
 *
 * 1) we're not trying to stack unionfs on top of unionfs
 * 2) it exists
 * 3) is a directory
 */
int check_branch(const struct path *path)
{
	if (!strcmp(path->dentry->d_sb->s_type->name, WRAPFS_NAME))
		return -EINVAL;
	if (!path->dentry->d_inode)
		return -ENOENT;
	if (!S_ISDIR(path->dentry->d_inode->i_mode))
		return -ENOTDIR;
	return 0;
}
/* checks if two lower_dentries have overlapping branches */
static int is_branch_overlap(struct dentry *dent1, struct dentry *dent2)
{
	struct dentry *dent = NULL;

	dent = dent1;
	while ((dent != dent2) && (dent->d_parent != dent))
		dent = dent->d_parent;

	if (dent == dent2)
		return 1;
	dent = dent2;
	while ((dent != dent1) && (dent->d_parent != dent))
		dent = dent->d_parent;

	return (dent == dent1);
}

static void wrapfs_fill_inode(struct dentry *dentry,
				struct inode *inode)
{
	struct inode *lower_inode;
	struct dentry *lower_dentry;
	int i = 0, id1 = 0, id2 = 0;
	for (i = 0; i <= 1; i++) {
		lower_dentry = wrapfs_lower_dentry_idx(dentry, i);
		if (!lower_dentry) {
			wrapfs_set_lower_inode_idx(inode, i, NULL);
			continue;
		}
		if (!lower_dentry->d_inode)
			continue;

		wrapfs_set_lower_inode_idx(inode, i,
			igrab(lower_dentry->d_inode));
		id1++;
		id2 = i;
	}
	/* Use attributes from the first branch */
	if (id1 == i)
		lower_inode = wrapfs_lower_inode(inode);
	else {
		lower_inode = wrapfs_lower_inode_idx(inode, id2);
		if (id2 == 1)
			wrapfs_set_lower_inode_idx(inode, 0, NULL);
		else
			wrapfs_set_lower_inode_idx(inode, 1, NULL);
}
	/* Use different set of inode ops for symlinks and directories*/
	if (S_ISLNK(lower_inode->i_mode))
		inode->i_op = &wrapfs_symlink_iops;
	else if (S_ISDIR(lower_inode->i_mode))
		inode->i_op = &wrapfs_dir_iops;
	if (S_ISDIR(lower_inode->i_mode))
		inode->i_fop = &wrapfs_dir_fops;
	if (S_ISBLK(lower_inode->i_mode) || S_ISCHR(lower_inode->i_mode) ||
		S_ISFIFO(lower_inode->i_mode) || S_ISSOCK(lower_inode->i_mode))
				init_special_inode(inode, lower_inode->i_mode,
					lower_inode->i_rdev);
	fsstack_copy_attr_all(inode, lower_inode);
	fsstack_copy_inode_size(inode, lower_inode);
}

static struct wrapfs_dentry_info *wrapfs_parse_options(struct super_block *sb,
							char *options)
{
	struct wrapfs_dentry_info *lower_root_info;
	struct path path;
	struct dentry *dent1, *dent2;
	char *optname;
	int err = 0, branches = 2;
	int dirsfound = 0;
	int i = 0;
	bool is_ldir_present = false;
	bool is_rdir_present = false;

	lower_root_info =
		kzalloc(sizeof(struct wrapfs_dentry_info), GFP_KERNEL);
	if (unlikely(!lower_root_info))
		goto out_error;

	WRAPFS_SB(sb)->data = kcalloc(branches,
				sizeof(struct wrapfs_data), GFP_KERNEL);

	if (unlikely(!WRAPFS_SB(sb)->data)) {
		err = -ENOMEM;
		goto out_return;
	}
	lower_root_info->lower_paths = kcalloc(branches,
				sizeof(struct path), GFP_KERNEL);

	if (unlikely(!lower_root_info->lower_paths)) {
		err = -ENOMEM;
		kfree(WRAPFS_SB(sb)->data);
		WRAPFS_SB(sb)->data = NULL;
		goto out_return;
	}

	while ((optname = strsep(&options, ",")) != NULL) {
		char *optarg;
		if (!optname || !*optname)
			continue;
		optarg = strchr(optname, '=');
		if (optarg)
			*optarg++ = '\0';
		if (!optarg) {
			printk(KERN_ERR "u2fs: %s requires an argument\n",
				optname);
			err = -EINVAL;
			goto out_error;
		}
		if (!strcmp("ldir", optname)) {
			if (++dirsfound > 1) {
				printk(KERN_ERR
					"u2fs: multiple ldirs specified\n");
				err = -EINVAL;
				goto out_error;
			}
			err = kern_path(optarg,
					LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
					&path);
			if (err) {
				printk(KERN_ERR "u2fs: error accessing "
						"lower directory '%s'\n",
					optarg);
				goto out_error;
			}

			err = check_branch(&path);
			if (err) {
				printk(KERN_ERR "u2fs: lower directory "
						"'%s' is not a valid branch\n",
						optarg);
				path_put(&path);
				goto out_error;
			}

			lower_root_info->lower_paths[0].dentry = path.dentry;
			lower_root_info->lower_paths[0].mnt = path.mnt;

			WRAPFS_SB(sb)->data[0].branchperms =
					MAY_READ|MAY_WRITE;
			set_branch_count(sb, 0, 0);
			new_branch_id(sb, 0);

			is_ldir_present = true;
			continue;
		}
		if (!strcmp("rdir", optname)) {
			if (!is_ldir_present)
				printk(KERN_ERR "u2fs: ldir not specified\n");
			if (++dirsfound > 2) {
				printk(KERN_ERR
					"u2fs: multiple rdirs specified\n");
				err = -EINVAL;
				goto out_error;
			}
			err = kern_path(optarg,
				LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
				&path);
			if (err) {
				printk(KERN_ERR "u2fs: error accessing "
						"lower directory '%s'\n",
						optarg);
				goto out_error;
			}
			lower_root_info->lower_paths[1].dentry = path.dentry;
			lower_root_info->lower_paths[1].mnt = path.mnt;

			WRAPFS_SB(sb)->data[1].branchperms = MAY_READ;
			set_branch_count(sb, 1, 0);
			new_branch_id(sb, 1);

			is_rdir_present = true;
			continue;
		}
		err = -EINVAL;
		printk(KERN_ERR "u2fs: unrecognized options '%s'\n", optname);
		goto out_error;
	}
	if (is_ldir_present && is_rdir_present) {
		/* Ensuring no overlaps */
		dent1 = lower_root_info->lower_paths[0].dentry;
		dent2 = lower_root_info->lower_paths[1].dentry;
		if (is_branch_overlap(dent1, dent2)) {
			printk(KERN_ERR "u2fs:"
			"branches ldir and rdir overlap\n");
			err = -EINVAL;
			goto out_error;
		}
	} else {
		printk(KERN_ERR "u2fs: no branches specified\n");
		err = -EINVAL;
		goto out_error;
		}
	goto out_return;
out_error:
	if (lower_root_info && lower_root_info->lower_paths) {
		for (i = 0; i < branches; i++)
			path_put(&lower_root_info->lower_paths[i]);

		kfree(lower_root_info->lower_paths);
		kfree(lower_root_info);
		kfree(WRAPFS_SB(sb)->data);
		lower_root_info->lower_paths = NULL;
		WRAPFS_SB(sb)->data = NULL;
		lower_root_info = ERR_PTR(err);
	}
out_return:
	return lower_root_info;
}

/* Connect a wrapfs inode dentry/inode with several lower ones.  This is
 * the classic stackable file system "vnode interposition" action.
 *
 * @dentry: wrapfs's dentry which interposes on lower one
 * @sb: wrapfs's super_block
 * @lower_path: the lower path (caller does path_get/put)
 */
int wrapfs_interpose(struct dentry *dentry, struct super_block *sb,
			struct path *lower_path)
{
	int err = 0;
	struct inode *inode;

	struct inode *lower_inode;
	struct super_block *lower_sb;


	lower_inode = lower_path->dentry->d_inode;
	lower_sb = wrapfs_lower_super(sb);

	/* check that the lower file system didn't cross a mount point */
	if (lower_inode->i_sb != lower_sb) {
		err = -EXDEV;
		goto out;
	}

	/*
	* We allocate our new inode below by calling wrapfs_iget,
	* which will initialize some of the new inode's fields
	*/
	/* inherit lower inode number for wrapfs's inode */
	inode = wrapfs_new_iget(sb, iunique(sb, 1));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}
	if (atomic_read(&inode->i_count) > 1)
		goto out_add;
	wrapfs_fill_inode(dentry, inode);
	printk(KERN_INFO" U2fs_interpose success\n");
out_add:
	d_add(dentry, inode);
out:
	return err;
}



/*
 * There is no need to lock the wrapfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int wrapfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0, i = 0;
	struct wrapfs_dentry_info *lower_root_info = NULL;
	struct inode *inode = NULL;
	if (!raw_data) {
		printk(KERN_ERR
			"u2fs: read_super: missing data argument\n");
		err = -EINVAL;
		goto out;
	}

	/* allocate superblock private data */

	sb->s_fs_info = kzalloc(sizeof(struct wrapfs_sb_info), GFP_KERNEL);
	if (!WRAPFS_SB(sb)) {
		printk(KERN_CRIT "u2fs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	atomic_set(&WRAPFS_SB(sb)->generation, 1);
	WRAPFS_SB(sb)->high_branch_id = -1;
/*      Parsing the Inputs      */
	lower_root_info = wrapfs_parse_options(sb, raw_data);
	if (IS_ERR(lower_root_info)) {
		printk(KERN_ERR
			"u2fs: read_super: error while parsing options"
			"(err = %ld)\n", PTR_ERR(lower_root_info));

		err = PTR_ERR(lower_root_info);
		lower_root_info = NULL;
		goto out_free;
	}

	/* set the lower superblock field of upper superblock */
	for (i = 0; i <= 1; i++) {
		struct dentry *d = lower_root_info->lower_paths[i].dentry;
		atomic_inc(&d->d_sb->s_active);
		wrapfs_set_lower_super_idx(sb, i, d->d_sb);
	}

	/* inherit maxbytes from highest priority branch */
	sb->s_maxbytes = wrapfs_lower_super_idx(sb, 0)->s_maxbytes;

	/*
	* Our c/m/atime granularity is 1 ns because we may stack on file
	* systems whose granularity is as good.
	*/
	sb->s_time_gran = 1;
	sb->s_op = &wrapfs_sops;

	/* get a new inode and allocate our root dentry */

	inode = wrapfs_new_iget(sb, iunique(sb, 1));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}

	sb->s_root = d_alloc_root(inode);
	if (unlikely(!sb->s_root)) {
		err = -ENOMEM;
		goto out_iput;
	}

	d_set_d_op(sb->s_root, &wrapfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (unlikely(err))
		goto out_freeroot;

	/* if get here: cannot have error */
	/* set the lower dentries for s_root */

	for (i = 0; i <= 1 ; i++) {
		struct dentry *d;
		struct vfsmount *m;
		d = lower_root_info->lower_paths[i].dentry;
		m = lower_root_info->lower_paths[i].mnt;
		wrapfs_set_lower_dentry_idx(sb->s_root, i, d);
		wrapfs_set_lower_mnt_idx(sb->s_root, i, m);
	}
	atomic_set(&WRAPFS_D(sb->s_root)->generation, 1);
	if (atomic_read(&inode->i_count) <= 1)
		wrapfs_fill_inode(sb->s_root, inode);
	/*
	* No need to call interpose because we already have a positive
	* dentry, which was instantiated by d_alloc_root.  Just need to
	* d_rehash it.
	*/
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
			"u2fs: mounted on top of type\n");
	goto out;

	/* all is well */
	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	if (WRAPFS_D(sb->s_root)) {
		kfree(WRAPFS_D(sb->s_root)->lower_paths);
		free_dentry_private_data(sb->s_root);
	}
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	if (lower_root_info && !IS_ERR(lower_root_info)) {
		for (i = 0; i <= 1; i++) {
			struct dentry *d;
			d = lower_root_info->lower_paths[i].dentry;
			atomic_dec(&d->d_sb->s_active);
			path_put(&lower_root_info->lower_paths[i]);
		}
		kfree(lower_root_info->lower_paths);
		kfree(lower_root_info);
		lower_root_info = NULL;
	}
out_free:
	kfree(WRAPFS_SB(sb)->data);
	kfree(WRAPFS_SB(sb));
	sb->s_fs_info = NULL;
out:
	if (lower_root_info && !IS_ERR(lower_root_info)) {
		kfree(lower_root_info->lower_paths);
		kfree(lower_root_info);
	}
	return err;
}

struct dentry *wrapfs_mount(struct file_system_type *fs_type, int flags,
				const char *dev_name, void *raw_data)
{
	struct dentry *dentry;
	dentry = mount_nodev(fs_type, flags, raw_data, wrapfs_read_super);
	if (!IS_ERR(dentry))
		WRAPFS_SB(dentry->d_sb)->dev_name =
			kstrdup(dev_name, GFP_KERNEL);
	return dentry;
}
static struct file_system_type wrapfs_fs_type = {
	.owner          = THIS_MODULE,
	.name           = WRAPFS_NAME,
	.mount          = wrapfs_mount,
	.kill_sb        = generic_shutdown_super,
	.fs_flags       = FS_REVAL_DOT,
};

static int __init init_wrapfs_fs(void)
{
	int err;
	pr_info("Registering u2fs " WRAPFS_VERSION "\n");
	err = wrapfs_init_inode_cache();
	if (err)
		goto out;
	err = wrapfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&wrapfs_fs_type);
out:
	if (err) {
		wrapfs_destroy_inode_cache();
		wrapfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_wrapfs_fs(void)
{
	wrapfs_destroy_inode_cache();
	wrapfs_destroy_dentry_cache();
	unregister_filesystem(&wrapfs_fs_type);
	pr_info("Completed u2fs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
		" (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Wrapfs-u2fs " WRAPFS_VERSION
		" (http://wrapfs.filesystems.org/)");
MODULE_LICENSE("GPL");
module_init(init_wrapfs_fs);
module_exit(exit_wrapfs_fs);
