/*
 * Raghavendra Suvvari, 2014
 * Stony Brook University
 *
 * Adopted wrapfs code to develop u2fs
*/

#ifndef _WRAPFS_H_
#define _WRAPFS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/poll.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/statfs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>
#include <linux/xattr.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/log2.h>
#include <linux/poison.h>
#include <linux/mman.h>
#include <linux/backing-dev.h>
#include <linux/splice.h>
#include <linux/sched.h>
#include <asm/system.h>

/* the file system name */
#define WRAPFS_NAME "u2fs"
/* wrapfs root inode number */
#define WRAPFS_ROOT_INO     1

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

/* operations vectors defined in specific files */
extern const struct file_operations wrapfs_main_fops;
extern const struct file_operations wrapfs_dir_fops;
extern const struct inode_operations wrapfs_main_iops;
extern const struct inode_operations wrapfs_dir_iops;
extern const struct inode_operations wrapfs_symlink_iops;
extern const struct super_operations wrapfs_sops;
extern const struct dentry_operations wrapfs_dops;
extern const struct address_space_operations wrapfs_aops, wrapfs_dummy_aops;
extern const struct vm_operations_struct wrapfs_vm_ops;
extern int wrapfs_init_inode_cache(void);
extern void wrapfs_destroy_inode_cache(void);
extern int wrapfs_init_dentry_cache(void);
extern void wrapfs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *wrapfs_lookup(struct inode *dir, struct dentry *dentry,
					struct nameidata *nd);
extern struct inode *wrapfs_iget(struct super_block *sb,
				struct inode *lower_inode);
extern struct inode *wrapfs_new_iget(struct super_block *sb,
					unsigned long ino);
extern int wrapfs_interpose(struct dentry *dentry, struct super_block *sb,
				struct path *lower_path);

extern struct dentry *create_parents(struct inode *dir, struct dentry *dentry,
				     const char *name, int bindex);

/* copies a file from dbstart to newbindex branch */
extern int copyup_file(struct inode *dir, struct file *file, int bstart,
		       int newbindex, loff_t size);
extern int copyup_named_file(struct inode *dir, struct file *file,
			     char *name, int bstart, int new_bindex,
			     loff_t len);
/* copies a dentry from dbstart to newbindex branch */
extern int copyup_dentry(struct inode *dir, struct dentry *dentry,
			 int bstart, int new_bindex, const char *name,
			 int namelen, struct file **copyup_file, loff_t len);
/* helper functions for post-copyup actions */
extern void wrapfs_postcopyup_setmnt(struct dentry *dentry);
extern void wrapfs_postcopyup_release(struct dentry *dentry);


/* file private data */
struct wrapfs_file_info {
	int branchID;
	atomic_t generation;
	struct wrapfs_dir_state *rdstate;
	bool wrote_to_file;
	struct file **lower_files;
	const struct vm_operations_struct *lower_vm_ops;
};

/* wrapfs inode data in memory */
struct wrapfs_inode_info {
	int branchID;
	atomic_t generation;
	spinlock_t rdlock;
	struct list_head readdircache;
	int rdcount;
	int hashsize;
	int cookie;

	struct inode **lower_inodes;
	struct inode vfs_inode;

};
/* wrapfs dentry data in memory */
struct wrapfs_dentry_info {
	int branchID;
	struct mutex lock;
	int bopaque; /* For deletion*/
	int bcount;
	atomic_t generation;

	struct path *lower_paths;
};

/* wrapfs super-block data in memory */
struct wrapfs_sb_info {
	atomic_t generation;

	int high_branch_id; /* last unique branch ID given*/
	char *dev_name;
	struct wrapfs_data *data;
};

struct wrapfs_data {
	struct super_block *sb; /* lower super-block */
	atomic_t open_files;    /* no of open files on branch */
	int branchperms;
	int branch_id;          /* unique banch ID at re/mount time*/
};

struct filldir_node {
	struct list_head file_list; /* List for directory entries*/
	char *name;
	int hash;
	int namelen;
	int bindex;
	int whiteout;
	char iname[DNAME_INLINE_LEN];
};

/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * wrapfs_inode_info structure, WRAPFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct wrapfs_inode_info *WRAPFS_I(const struct inode *inode)
{
	return container_of(inode, struct wrapfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define WRAPFS_D(dent) ((struct wrapfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define WRAPFS_SB(super) ((struct wrapfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define WRAPFS_F(file) ((struct wrapfs_file_info *)((file)->private_data))
/* path based (dentry/mnt) macros */

static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}

/* Returns struct path.  Caller must path_put it. */
static inline void wrapfs_get_lower_path(const struct dentry *dent,
					struct path *lower_path)
{
	/*spin_lock(&WRAPFS_D(dent)->lock);*/
	pathcpy(lower_path, &WRAPFS_D(dent)->lower_paths[0]);
	path_get(lower_path);
	/*spin_unlock(&WRAPFS_D(dent)->lock);*/
	return;
}

static inline void wrapfs_get_lower_path_idx(const struct dentry *dent,
						struct path *lower_path,
						int idx)
{
	pathcpy(lower_path, &WRAPFS_D(dent)->lower_paths[idx]);
	path_get(lower_path);
	return;
}
static inline void wrapfs_put_lower_path(const struct dentry *dent,
					struct path *lower_path)
{
	path_put(lower_path);
	return;
}
static inline void wrapfs_set_lower_path(const struct dentry *dent,
					struct path *lower_path)
{
	/*spin_lock(&WRAPFS_D(dent)->lock);*/
	pathcpy(&WRAPFS_D(dent)->lower_paths[0], lower_path);
	/*spin_unlock(&WRAPFS_D(dent)->lock);*/
	return;
}
static inline void wrapfs_set_lower_path_idx(const struct dentry *dent,
					struct path *lower_path,
					int idx)
{
	/*spin_lock(&WRAPFS_D(dent)->lock);*/
	pathcpy(&WRAPFS_D(dent)->lower_paths[idx], lower_path);
	/*spin_unlock(&WRAPFS_D(dent)->lock);*/
	return;
}


static inline void wrapfs_reset_lower_path(const struct dentry *dent)
{
	/*spin_lock(&WRAPFS_D(dent)->lock);*/
	WRAPFS_D(dent)->lower_paths[0].dentry = NULL;
	WRAPFS_D(dent)->lower_paths[0].mnt = NULL;
	/*spin_unlock(&WRAPFS_D(dent)->lock);*/
	return;
}
static inline void wrapfs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;
	/*spin_lock(&WRAPFS_D(dent)->lock);*/
	pathcpy(&lower_path, &WRAPFS_D(dent)->lower_paths[0]);
	WRAPFS_D(dent)->lower_paths[0].dentry = NULL;
	WRAPFS_D(dent)->lower_paths[0].mnt = NULL;
	/*spin_unlock(&WRAPFS_D(dent)->lock);*/
	path_put(&lower_path);
	return;
}

static inline void wrapfs_put_reset_lower_path_idx(const struct dentry *dent,
							int idx)
{
	struct path lower_path;
	/*spin_lock(&WRAPFS_D(dent)->lock);*/
	pathcpy(&lower_path, &WRAPFS_D(dent)->lower_paths[idx]);
	WRAPFS_D(dent)->lower_paths[idx].dentry = NULL;
	WRAPFS_D(dent)->lower_paths[idx].mnt = NULL;
	/*spin_unlock(&WRAPFS_D(dent)->lock);*/
	path_put(&lower_path);
	return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}
#endif  /* not _WRAPFS_H_ */

#define OPEN_WRITE_FLAGS (O_WRONLY | O_RDWR | O_APPEND)
#define IS_WRITE_FLAG(flag) ((flag) & OPEN_WRITE_FLAGS)
#define WRPAPFS_SB(super) ((struct wrapfs_sb_info *)(super)->s_fs_info)
/* inline int branch_count(const struct super_block *sb, int index)
{
	BUG_ON(!sb || index < 0);
	return atomic_read(&WRAPFS_SB(sb)->data[index].open_files);
}
*/
static inline void set_branch_count(struct super_block *sb, int index, int val)
{
	BUG_ON(!sb || index < 0);
	atomic_set(&WRAPFS_SB(sb)->data[index].open_files, val);
}

static inline void branchget(struct super_block *sb, int index)
{
	BUG_ON(!sb || index < 0);
	atomic_inc(&WRAPFS_SB(sb)->data[index].open_files);
}

static inline void branchput(struct super_block *sb, int index)
{
	BUG_ON(!sb || index < 0);
	atomic_dec(&WRAPFS_SB(sb)->data[index].open_files);
}

/* macros to manipulate branch IDs in stored in our superblock */
static inline int branch_id(struct super_block *sb, int index)
{
	BUG_ON(!sb || index < 0);
	return WRAPFS_SB(sb)->data[index].branch_id;
}
static inline void set_branch_id(struct super_block *sb, int index, int val)
{
	BUG_ON(!sb || index < 0);
	WRAPFS_SB(sb)->data[index].branch_id = val;
}

static inline void new_branch_id(struct super_block *sb, int index)
{
	BUG_ON(!sb || index < 0);
	set_branch_id(sb, index, ++WRAPFS_SB(sb)->high_branch_id);
}

/* Dentry Macros */
static inline void wrapfs_set_lower_dentry_idx(struct dentry *dent, int index,
						struct dentry *val)
{
	BUG_ON(!dent || index < 0);
	WRAPFS_D(dent)->lower_paths[index].dentry = val;
}

static inline struct dentry *wrapfs_lower_dentry_idx(
					const struct dentry *dent,
					int index)
{
	BUG_ON(!dent || index < 0);
	return WRAPFS_D(dent)->lower_paths[index].dentry;
}

static inline struct dentry *wrapfs_lower_dentry(const struct dentry *dent)
{
	BUG_ON(!dent);
	return wrapfs_lower_dentry_idx(dent, 0);
}

static inline void wrapfs_set_lower_mnt_idx(struct dentry *dent, int index,
					struct vfsmount *mnt)
{
	BUG_ON(!dent || index < 0);
	WRAPFS_D(dent)->lower_paths[index].mnt = mnt;
}

static inline struct vfsmount *wrapfs_lower_mnt_idx(
						const struct dentry *dent,
						int index)
{
	BUG_ON(!dent || index < 0);
	return WRAPFS_D(dent)->lower_paths[index].mnt;
}

static inline struct vfsmount *wrapfs_lower_mnt(const struct dentry *dent)
{
	BUG_ON(!dent);
	return wrapfs_lower_mnt_idx(dent, 0);
}

/* Superblock to lower superblock */
static inline struct super_block *wrapfs_lower_super(
				const struct super_block *sb)
{
	BUG_ON(!sb);
	return WRAPFS_SB(sb)->data[0].sb;
}

static inline struct super_block *wrapfs_lower_super_idx(
						const struct super_block *sb,
						int index)
{
	BUG_ON(!sb || index < 0);
	return WRAPFS_SB(sb)->data[index].sb;
}

static inline void wrapfs_set_lower_super_idx(struct super_block *sb,
						int index,
						struct super_block *val)
{
	BUG_ON(!sb || index < 0);
	WRAPFS_SB(sb)->data[index].sb = val;
}

static inline void wrapfs_set_lower_super(struct super_block *sb,
					struct super_block *val)
{
	BUG_ON(!sb);
	WRAPFS_SB(sb)->data[0].sb = val;
}

/* Inode to lower inode. */
static inline struct inode *wrapfs_lower_inode(const struct inode *i)
{
	BUG_ON(!i);
	return WRAPFS_I(i)->lower_inodes[0];
}

static inline void wrapfs_set_lower_inode(struct inode *i, struct inode *val)
{
	BUG_ON(!i);
	WRAPFS_I(i)->lower_inodes[0] = val;
}

static inline void wrapfs_set_lower_inode_idx(struct inode *i, int index,
					struct inode *val)
{
	BUG_ON(!i || index < 0);
	WRAPFS_I(i)->lower_inodes[index] = val;
}

static inline struct inode *wrapfs_lower_inode_idx(const struct inode *i,
							int index)
{
	BUG_ON(!i || index < 0);
	return WRAPFS_I(i)->lower_inodes[index];
}

/* File to lower file*/
static inline struct file *wrapfs_lower_file(const struct file *f)
{
	BUG_ON(!f);
	return WRAPFS_F(f)->lower_files[0];
}

static inline struct file *wrapfs_lower_file_idx(const struct file *f,
						int index)
{
	BUG_ON(!f || index < 0);
	return WRAPFS_F(f)->lower_files[index];
}

static inline void wrapfs_set_lower_file_idx(struct file *f, int index,
						struct file *val)
{
	BUG_ON(!f);
	WRAPFS_F(f)->lower_files[index] = val;
/*	WRAPFS_F(f)->saved_branch_ids[index] =
		branch_id((f)->f_path.dentry->d_sb, index);*/
}

static inline void wrapfs_set_lower_file(struct file *f, struct file *val)
{
	BUG_ON(!f);
	wrapfs_set_lower_file_idx((f), 0, (val));
}
static inline void path_put_lowers(struct dentry *dentry,
				int bstart, int bend, bool free_lower)
{
	struct dentry *lower_dentry;
	struct vfsmount *lower_mnt;
	int bindex;

	BUG_ON(!dentry);
	BUG_ON(!WRAPFS_D(dentry));
	BUG_ON(bstart < 0);

	for (bindex = bstart; bindex <= bend; bindex++) {
		lower_dentry = wrapfs_lower_dentry_idx(dentry, bindex);
		if (lower_dentry) {
			wrapfs_set_lower_dentry_idx(dentry, bindex, NULL);
			dput(lower_dentry);
		}
		lower_mnt = wrapfs_lower_mnt_idx(dentry, bindex);
		if (lower_mnt) {
			wrapfs_set_lower_mnt_idx(dentry, bindex, NULL);
			mntput(lower_mnt);
		}
	}

	if (free_lower) {
		kfree(WRAPFS_D(dentry)->lower_paths);
		WRAPFS_D(dentry)->lower_paths = NULL;
	}
}
static inline void path_put_lowers_all(struct dentry *dentry, bool free_lower)
{
	int bstart = 0, bend = 1;

	BUG_ON(!dentry);
	BUG_ON(!WRAPFS_D(dentry));
	/*bstart = dbstart(dentry);*/
	/*bend = dbend(dentry);*/
	BUG_ON(bstart < 0);

	path_put_lowers(dentry, bstart, bend, free_lower);
	/*dbstart(dentry) = dbend(dentry) = -1;*/
}

/* lock base inode mutex before calling lookup_one_len */
static inline struct dentry *lookup_lck_len(const char *name,
						struct dentry *base, int len)
{
	struct dentry *d;
	d = lookup_one_len(name, base, len);
	return d;
}

/* Macros for locking a dentry. */
enum wrapfs_dentry_lock_class {
	WRAPFS_DMUTEX_NORMAL,
	WRAPFS_DMUTEX_ROOT,
	WRAPFS_DMUTEX_PARENT,
	WRAPFS_DMUTEX_CHILD,
	WRAPFS_DMUTEX_WHITEOUT,
	WRAPFS_DMUTEX_REVAL_PARENT, /* for file/dentry revalidate */
	WRAPFS_DMUTEX_REVAL_CHILD,   /* for file/dentry revalidate */
};


static inline struct dentry *lock_parent_wh(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	mutex_lock_nested(&dir->d_inode->i_mutex, WRAPFS_DMUTEX_WHITEOUT);
	return dir;
}

