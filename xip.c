/*
 * BRIEF DESCRIPTION
 *
 * XIP operations.
 *
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <asm/cpufeature.h>
#include <asm/pgtable.h>
#include "pmfs.h"
#include "xip.h"
/*dedup new add include*/
#include <linux/kernel.h>
// #include <linux/module.h>
// #include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/spinlock.h>
// #include <linux/scatterlist.h>
// #include <linux/err.h>


#include "dedup.c"

/* dedup claim start */
#define DEDUP_HEAD 1026
#define DEDUPNODE_SIZE sizeof(struct dedupnode)
#define REFNODE_SIZE sizeof(struct refnode)
#define DINDEX pmfs_get_block(sb, DEDUP_HEAD<<PAGE_SHIFT)
DEFINE_SPINLOCK(dedup_index_lock);
DEFINE_SPINLOCK(dnode_rbtree_lock);

// static LIST_HEAD(hash_map_addr_list);
// struct list_head *last_hit;
// struct list_head *new_list = &hash_map_addr_list;
struct list_head *dedupnode_allocation_pos = NULL;
// char dedup_model = 0xFF;
short dnode_hit = 0;
bool rnode_hit = false;
struct list_head *last_dnode_list;
struct list_head *last_rnode_list;
bool filesystem_restart = true;
// struct rb_root root = RB_ROOT;
long circle_count = 0;

size_t dedup_interval = 1;
/*
	dedup rbtree function
*/
void new_unused_dedupnode(struct super_block *sb){
	unsigned long blocknr;
	struct dedupnode *dnode;
	unsigned offset = 0;
	void *xmem;
	struct dedup_index *dindex = DINDEX;
	
	pmfs_new_block(sb, &blocknr, PMFS_BLOCK_TYPE_4K, 1);
	xmem = pmfs_get_block(sb, blocknr<<PAGE_SHIFT);
	
	while(offset + DEDUPNODE_SIZE < 4096)
	{	
		dnode = xmem + offset;
		INIT_LIST_HEAD(&dnode->list);
		list_add_tail(&dnode->list, &dindex->hma_unused);
		offset += DEDUPNODE_SIZE;
	}
}

void new_unused_refnode(struct super_block *sb){
	unsigned long blocknr;
	struct refnode *rnode;
	unsigned offset = 0;
	void *xmem;
	struct dedup_index *dindex = DINDEX;

	pmfs_new_block(sb, &blocknr, PMFS_BLOCK_TYPE_4K, 1);
	xmem = pmfs_get_block(sb, blocknr<<PAGE_SHIFT);

	while(offset + REFNODE_SIZE < 4096)
	{
		rnode = xmem + offset;
		INIT_LIST_HEAD(&rnode->list);
		list_add_tail(&rnode->list, &dindex->ref_unused);
		offset += REFNODE_SIZE;
	}
}

struct dedupnode *alloc_dedupnode(struct super_block *sb){
	struct dedupnode *dnode;
	struct list_head *p;
	struct dedup_index *dindex = DINDEX;
	unsigned long flags;

	// if(filesystem_restart){
	// 	filesystem_restart = false;
	// 	list_splice(&dindex->hma_writing, &dindex->hma_unused);
	// }

	spin_lock_irqsave(&dedup_index_lock, flags);

	if(list_empty(&dindex->hma_unused))
		new_unused_dedupnode(sb);
	
	p = dindex->hma_unused.next;
	dnode = list_entry(p, struct dedupnode, list);
	dnode->flag = 0;
	// list_move_tail(p, &dindex->hma_head);
	list_move_tail(p, &dindex->hma_writing);

	spin_unlock_irqrestore(&dedup_index_lock, flags);
	return dnode;
}

bool free_dedupnode(struct super_block *sb, void *dedupnode){
	struct dedup_index *dindex;
	struct rb_root *droot;
	struct dedupnode *dnode;; 

	dindex = DINDEX;
	droot = &dindex->dedupnode_root;
	dnode = (struct dedupnode*)dedupnode;

	if(dnode->flag!=1)
		return false;
		
	dnode->flag = 0;
	atomic_dec(&dnode->atomic_ref_count);
	// pmfs_free_block(sb, dnode->blocknr, PMFS_BLOCK_TYPE_4K);
	// rb_erase(&dnode->node, droot);
	// list_move_tail(&dnode->list, &dindex->hma_unused);
	return true;
}

struct refnode *alloc_refnode(struct super_block *sb){
	struct list_head *p;
	struct refnode *rnode;
	struct dedup_index *dindex = DINDEX;
	if(list_empty(&dindex->ref_unused))
		new_unused_refnode(sb);
	
	p = dindex->ref_unused.next;
	list_move_tail(p, &dindex->ref_head);
	rnode = list_entry(p, struct refnode, list);
	return rnode;
}

bool free_refnode(struct super_block *sb, struct refnode *rnode){
	// struct dedup_index *dindex;
	// struct rb_root *rroot;

	// if(rnode == NULL)
	// 	return false;
	
	// dindex = DINDEX;
	// rroot = &dindex->refroot;
	// //remove from the red black tree
	// rb_erase(&rnode->node, rroot);
	// //flag set 0, remove to unused list
	// list_move_tail(&rnode->list, &dindex->ref_unused);
	return true;
}

struct dedupnode *dedupnode_low_overhead_check(struct dedupnode *dnode_new){
	struct dedupnode *dnode_entry;
	long result;

	if(last_dnode_list!=NULL && last_dnode_list->next!=NULL){
		dnode_entry = list_entry(last_dnode_list->next, struct dedupnode, list);
		result = dnode_new->hashval - dnode_entry->hashval;
		if(result==0)
			result =  memcmp(dnode_new->strength_hashval, dnode_entry->strength_hashval, 16);

		if(result==0){
			// printk("hit in low_overhead_check!");
			return dnode_entry;
		}
	}
	return NULL;
}

struct dedupnode *dedupnode_tree_update(struct super_block *sb
,struct dedupnode *dnode_new){
	struct dedup_index *dindex = DINDEX;
	struct rb_root *droot = &(dindex->dedupnode_root);
	struct rb_node **entry_node = &(droot->rb_node);
	struct rb_node *parent = NULL;
	struct dedupnode *dnode_entry;
	long result;
	unsigned long flags;

	// printk("tree update 1");
	// printk("dnode_new->hashval:%ld", dnode_new->hashval);

	while(*entry_node){
		parent = *entry_node;
		dnode_entry = rb_entry(*entry_node, struct dedupnode, node);
		result = dnode_new->hashval - dnode_entry->hashval;
		if(result < 0)
			entry_node = &(*entry_node)->rb_left;
		else if(result > 0)
			entry_node = &(*entry_node)->rb_right;
		else{
			result = memcmp(dnode_new->strength_hashval
			,dnode_entry->strength_hashval, 16);
			// printk("result:%ld", result);
			if(result < 0)
				entry_node = &(*entry_node)->rb_left;
			else if(result > 0)
				entry_node = &(*entry_node)->rb_right;
			else{
				// printk("dnode_entry:%u", dnode_entry->count);
				// printk("hit in rbtree");
				return dnode_entry;
			}
		}
	}

	spin_lock_irqsave(&dnode_rbtree_lock, flags);
	rb_link_node(&dnode_new->node, parent, entry_node);
	rb_insert_color(&dnode_new->node, droot);
	spin_unlock_irqrestore(&dnode_rbtree_lock, flags);

	return NULL;
}

struct refnode *refnode_insert(struct super_block *sb, unsigned long ino
	, unsigned long index){
	struct dedup_index *dindex = DINDEX;
	struct rb_root *rroot = &dindex->refroot;
	struct rb_node **entry_node;
	struct rb_node *parent = NULL;
	struct refnode *rnode_entry = NULL;
	struct refnode *rnode_new;
	long result;

	//search from last hit node


	entry_node = &(rroot->rb_node);
	while(*entry_node){
		parent = *entry_node;
		rnode_entry = rb_entry(*entry_node, struct refnode, node);
		result = ino - rnode_entry->ino;
		if(result < 0)
			entry_node = &(*entry_node)->rb_left;
		else if(result > 0)
			entry_node = &(*entry_node)->rb_right;
		else{
			result = index - rnode_entry->index;
			if(result < 0)
				entry_node = &(*entry_node)->rb_left;
			else if(result > 0)
				entry_node = &(*entry_node)->rb_right;
			else{
				atomic_dec(&rnode_entry->dnode->atomic_ref_count);// rnode_entry->dnode->count--;
				return rnode_entry;
			}
		}		
	}

	rnode_new = alloc_refnode(sb);
	rnode_new->ino = ino;
	rnode_new->index = index;
	rnode_new->dnode = NULL;

	// printk("refnode insert 1");
	rb_link_node(&rnode_new->node, parent, entry_node);
	rb_insert_color(&rnode_new->node, rroot);

	return rnode_new;
}

struct refnode *refnode_search(struct super_block *sb
,unsigned ino, unsigned long index){
	struct dedup_index *dindex = DINDEX;
	struct rb_node *entry_node = dindex->refroot.rb_node;
	struct refnode *rnode_entry = NULL;
	long result;

	while(entry_node){
		rnode_entry = rb_entry(entry_node, struct refnode, node);
		result = ino - rnode_entry->ino;
		if(result < 0)
			entry_node = entry_node->rb_left;
		else if(result > 0)
			entry_node = entry_node->rb_right;
		else{
			result = index - rnode_entry->index;
			if(result < 0)
				entry_node = entry_node->rb_left;
			else if(result > 0)
				entry_node = entry_node->rb_right;
			else{
				// printk("rnode_entry->dnode->blocknr:%lu", 
				// 	rnode_entry->dnode->blocknr);
				return rnode_entry;
				}
		}
	}
	return NULL;
}

bool short_hash(size_t *hashing, char *xmem, size_t len)
{
	// size_t trace = len >> 3;
	size_t data_remainder = len & (sizeof(size_t)-1);
	size_t k;//,hash_offset=0;

	size_t thin_internal = len >> 10;
	size_t thick_internal_count = (len&1023) >> 3;

	*hashing = 0;
				 
	if(data_remainder!=0)
		memcpy(hashing, xmem+len-data_remainder, data_remainder);

	for(k=0;(k+sizeof(size_t))<len;){
		*hashing += *(size_t*)(xmem + k);
		*hashing += (*hashing << 1);
		*hashing ^= (*hashing >> 2);
		if(thick_internal_count>0){
			k += sizeof(size_t);	
			thick_internal_count--;
		}
		k += (thin_internal<<3);
	}
	
	return true;
}

bool strength_hash(char *result, char* data, size_t len){
	// struct shash_desc *desc;
	// desc = kmalloc(sizeof(*desc), GFP_KERNEL);
	// desc->tfm = crypto_alloc_shash("md5", 0, CRYPTO_ALG_ASYNC);

	// if(desc->tfm == NULL)
	// 	return false;

	// crypto_shash_init(desc);
	// crypto_shash_update(desc, data, len);
	// crypto_shash_final(desc, result);
	// crypto_free_shash(desc->tfm);
	
	
	int i, cycles;

	memset(result, 0, 16);
	memcpy(result, data+len-(len&15), len&15); //remainder divided by 16
	cycles = len>>4;
	
	for(i=0;i<cycles;i++){
		*(u64*)result += *(u64*)( data+(i<<4) );
		*(u64*)result ^= *(u64*)result >> 1;
		*(u64*)result += *(u64*)result >> 3;
		*(u64*)(result+8) += *(u64*)( data+(i<<4)+8 );
		*(u64*)(result+8) ^= *(u64*)result >> 1;
	}



	return true;
}

/* claim end */

static ssize_t
do_xip_mapping_read(struct address_space *mapping,
		    struct file_ra_state *_ra,
		    struct file *filp,
		    char __user *buf,
		    size_t len,
		    loff_t *ppos)
{
	struct inode *inode = mapping->host;
	pgoff_t index, end_index;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0;
	timing_t memcpy_time;
	struct super_block *sb = inode->i_sb;

	pos = *ppos;
	index = pos >> PAGE_SHIFT;
	offset = pos & ~PAGE_MASK;

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	end_index = (isize - 1) >> PAGE_SHIFT;

	do {
		unsigned long nr, left;
		void *xip_mem = NULL;
		unsigned long xip_pfn;
		int zero = 0;

		/* read dedup data block start */
		struct refnode *rnode;
		/* end */

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_SIZE;
		
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~PAGE_MASK) + 1;
		
			if (nr <= offset) {
				goto out;
			}
		}
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;

		/* dedup new code start */
		if(rnode_hit){
			rnode = list_entry(last_rnode_list->next, struct refnode, list);
			if(inode->i_ino==rnode->ino && index==rnode->index){
				xip_mem = pmfs_get_block(sb, rnode->dnode->blocknr<<PAGE_SHIFT);
				error = 0;
				rnode_hit = true;
				last_rnode_list = last_rnode_list->next;
				goto rnode_find;
			}
		}
		rnode = refnode_search(sb, inode->i_ino, index);
		if(rnode){
			rnode_hit = true;
			error = 0;
			last_rnode_list = &rnode->list;
			xip_mem = pmfs_get_block(sb, rnode->dnode->blocknr<<PAGE_SHIFT);
		}else
			error = pmfs_get_xip_mem(mapping, index, 0, &xip_mem, &xip_pfn);
		rnode_find:

		if (unlikely(error)) {
			if (error == -ENODATA) {
				/* sparse */
				zero = 1;
			} else
				goto out;
		}

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		if (mapping_writably_mapped(mapping))
			/* address based flush */ ;

		/*
		 * Ok, we have the mem, so now we can copy it to user space...
		 *
		 * The actor routine returns how many bytes were actually used..
		 * NOTE! This may not be the same as how much of a user buffer
		 * we filled up (we may be padding etc), so we can only update
		 * "pos" here (the actor routine has to update the user buffer
		 * pointers and the remaining count).
		 */
		PMFS_START_TIMING(memcpy_r_t, memcpy_time);
		if (!zero)
			left = __copy_to_user(buf+copied, xip_mem+offset, nr);
		else
			left = __clear_user(buf + copied, nr);
		
		PMFS_END_TIMING(memcpy_r_t, memcpy_time);

		if (left) {
			error = -EFAULT;
			goto out;
		}

		copied += (nr - left);
		offset += (nr - left);
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;
	} while (copied < len);

out:
	*ppos = pos + copied;
	if (filp){
		file_accessed(filp);
	}
	return (copied ? copied : error);
}

ssize_t
xip_file_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	if (!access_ok(VERIFY_WRITE, buf, len))
		return -EFAULT;

	return do_xip_mapping_read(filp->f_mapping, &filp->f_ra, filp,
			    buf, len, ppos);
}

/*
 * Wrappers. We need to use the rcu read lock to avoid
 * concurrent truncate operation. No problem for write because we held
 * i_mutex.
 */
ssize_t pmfs_xip_file_read(struct file *filp, char __user *buf,
			    size_t len, loff_t *ppos)
{
	ssize_t res;
	timing_t xip_read_time;

	PMFS_START_TIMING(xip_read_t, xip_read_time);
//	rcu_read_lock();
	res = xip_file_read(filp, buf, len, ppos);
//	rcu_read_unlock();
	PMFS_END_TIMING(xip_read_t, xip_read_time);
	return res;
}

static inline void pmfs_flush_edge_cachelines(loff_t pos, ssize_t len,
	void *start_addr)
{
	if (unlikely(pos & 0x7))
		pmfs_flush_buffer(start_addr, 1, false);
	if (unlikely(((pos + len) & 0x7) && ((pos & (CACHELINE_SIZE - 1)) !=
			((pos + len) & (CACHELINE_SIZE - 1)))))
		pmfs_flush_buffer(start_addr + len, 1, false);
}

static inline size_t memcpy_to_nvmm(char *kmem, loff_t offset,
	const char __user *buf, size_t bytes)
{
	size_t copied;

	if (support_clwb) {
		copied = bytes - __copy_from_user(kmem + offset, buf, bytes);
		pmfs_flush_buffer(kmem + offset, copied, 0);
	} else {
		copied = bytes - __copy_from_user_inatomic_nocache(kmem +
						offset, buf, bytes);
	}
	return copied;
}

static ssize_t
__pmfs_xip_file_write(struct address_space *mapping, const char __user *buf,
          size_t count, loff_t pos, loff_t *ppos)
{
	struct inode    *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	long        status = 0;
	size_t      bytes;
	ssize_t     written = 0;
	struct pmfs_inode *pi;
	timing_t memcpy_time, write_time;
	int i;
	char *devnull = kmalloc(4096, GFP_KERNEL);

	PMFS_START_TIMING(internal_write_t, write_time);
	pi = pmfs_get_inode(sb, inode->i_ino);

	do {
		unsigned long index;
		unsigned long offset;
		size_t copied;
		void *xmem;
		unsigned long xpfn;

		offset = (pos & (sb->s_blocksize - 1)); /* Within page */
		index = pos >> sb->s_blocksize_bits;
		bytes = sb->s_blocksize - offset;
		if (bytes > count)
			bytes = count;
		
		status = pmfs_get_xip_mem(mapping, index, 1, &xmem, &xpfn);
		
		if (status)
			break;

		copied = bytes;

		PMFS_START_TIMING(memcpy_w_t, memcpy_time);
		pmfs_xip_mem_protect(sb, xmem + offset, bytes, 1);
		for(i=0;i<10;i++)
            copied = memcpy_to_nvmm((char *)devnull, offset, buf, bytes);
		copied = memcpy_to_nvmm((char *)xmem, offset, buf, bytes);
		pmfs_xip_mem_protect(sb, xmem + offset, bytes, 0);
		PMFS_END_TIMING(memcpy_w_t, memcpy_time);

		/* if start or end dest address is not 8 byte aligned, 
	 	 * __copy_from_user_inatomic_nocache uses cacheable instructions
	 	 * (instead of movnti) to write. So flush those cachelines. */
		pmfs_flush_edge_cachelines(pos, copied, xmem + offset); 
		
        if (likely(copied > 0)) {
			status = copied;

			if (status >= 0) {
				written += status;
				count -= status;
				pos += status;
				buf += status;
			}
		}
		if (unlikely(copied != bytes))
			if (status >= 0)
				status = -EFAULT;
		if (status < 0)
			break;	
	} while (count);
	kfree(devnull);
	*ppos = pos;
	
	/*
 	* No need to use i_size_read() here, the i_size
 	* cannot change under us because we hold i_mutex.
 	*/
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		pmfs_update_isize(inode, pi);
	}

	PMFS_END_TIMING(internal_write_t, write_time);
	return written ? written : status;
}

/* optimized path for file write that doesn't require a transaction. In this
 * path we don't need to allocate any new data blocks. So the only meta-data
 * modified in path is inode's i_size, i_ctime, and i_mtime fields */
static ssize_t pmfs_file_write_fast(struct super_block *sb, struct inode *inode,
	struct pmfs_inode *pi, const char __user *buf, size_t count, loff_t pos,
	loff_t *ppos, u64 block)
{
	void *xmem = pmfs_get_block(sb, block);
	size_t copied, ret = 0, offset;
	timing_t memcpy_time;

	offset = pos & (sb->s_blocksize - 1);

	PMFS_START_TIMING(memcpy_w_t, memcpy_time);
	pmfs_xip_mem_protect(sb, xmem + offset, count, 1);
	copied = memcpy_to_nvmm((char *)xmem, offset, buf, count);
	pmfs_xip_mem_protect(sb, xmem + offset, count, 0);
	PMFS_END_TIMING(memcpy_w_t, memcpy_time);

	pmfs_flush_edge_cachelines(pos, copied, xmem + offset);

	if (likely(copied > 0)) {
		pos += copied;
		ret = copied;
	}
	if (unlikely(copied != count && copied == 0))
		ret = -EFAULT;
	*ppos = pos;
	inode->i_ctime = inode->i_mtime = current_time(inode);
	if (pos > inode->i_size) {
		/* make sure written data is persistent before updating
	 	* time and size */
		PERSISTENT_MARK();
		i_size_write(inode, pos);
		PERSISTENT_BARRIER();
		pmfs_memunlock_inode(sb, pi);
		pmfs_update_time_and_size(inode, pi);
		pmfs_memlock_inode(sb, pi);
	} else {
		u64 c_m_time;
		/* update c_time and m_time atomically. We don't need to make the data
		 * persistent because the expectation is that the close() or an explicit
		 * fsync will do that. */
		c_m_time = (inode->i_ctime.tv_sec & 0xFFFFFFFF);
		c_m_time = c_m_time | (c_m_time << 32);
		pmfs_memunlock_inode(sb, pi);
		pmfs_memcpy_atomic(&pi->i_ctime, &c_m_time, 8);
		pmfs_memlock_inode(sb, pi);
	}
	pmfs_flush_buffer(pi, 1, false);
	return ret;
}

/*
 * blk_off is used in different ways depending on whether the edge block is
 * at the beginning or end of the write. If it is at the beginning, we zero from
 * start-of-block to 'blk_off'. If it is the end block, we zero from 'blk_off' to
 * end-of-block
 */
static inline void pmfs_clear_edge_blk (struct super_block *sb, struct
	pmfs_inode *pi, bool new_blk, unsigned long block, size_t blk_off,
	bool is_end_blk)
{
	void *ptr;
	size_t count;
	unsigned long blknr;

	if (new_blk) {
		blknr = block >> (pmfs_inode_blk_shift(pi) -
			sb->s_blocksize_bits);
		ptr = pmfs_get_block(sb, __pmfs_find_data_block(sb, pi, blknr));
		if (ptr != NULL) {
			if (is_end_blk) {
				ptr = ptr + blk_off - (blk_off % 8);
				count = pmfs_inode_blk_size(pi) -
					blk_off + (blk_off % 8);
			} else
				count = blk_off + (8 - (blk_off % 8));
			pmfs_memunlock_range(sb, ptr,  pmfs_inode_blk_size(pi));
			memset_nt(ptr, 0, count);
			pmfs_memlock_range(sb, ptr,  pmfs_inode_blk_size(pi));
		}
	}
}

ssize_t pmfs_xip_file_write(struct file *filp, const char __user *buf,
          size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode    *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	pmfs_transaction_t *trans;
	struct pmfs_inode *pi;
	ssize_t     written = 0;
	loff_t pos;
	u64 block;
	bool new_sblk = false, new_eblk = false;
	size_t count, offset, eblk_offset, ret;
	unsigned long start_blk, end_blk, num_blocks, max_logentries;
	bool same_block;
	timing_t xip_write_time, xip_write_fast_time;

	//dedup claiming start
	size_t i,j,dedup_offset;	
	bool local_hit = false;
	// struct dedup_index *dindex;
	struct dedup_index *dindex = DINDEX;
	struct rb_root *droot = &(dindex->dedupnode_root);

	// printk("pmfs xip file write start!");
	//end

	PMFS_START_TIMING(xip_write_t, xip_write_time);

	sb_start_write(inode->i_sb);
	inode_lock(inode);

	if (!access_ok(VERIFY_READ, buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	pos = *ppos;
	count = len;
	if (count == 0) {
		ret = 0;
		goto out;
	}

	pi = pmfs_get_inode(sb, inode->i_ino);

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	/* offset in the actual block size block */
	offset = pos & (pmfs_inode_blk_size(pi) - 1);
	start_blk = pos >> sb->s_blocksize_bits;
	end_blk = start_blk + num_blocks - 1;

	block = pmfs_find_data_block(inode, start_blk);

	/* Referring to the inode's block size, not 4K */
	same_block = (((count + offset - 1) >>
			pmfs_inode_blk_shift(pi)) == 0) ? 1 : 0;

	if (block && same_block) {
		PMFS_START_TIMING(xip_write_fast_t, xip_write_fast_time);
		ret = pmfs_file_write_fast(sb, inode, pi, buf, count, pos,
			ppos, block);
		PMFS_END_TIMING(xip_write_fast_t, xip_write_fast_time);
		goto out;
	}
	max_logentries = num_blocks / MAX_PTRS_PER_LENTRY + 2;
	if (max_logentries > MAX_METABLOCK_LENTRIES)
		max_logentries = MAX_METABLOCK_LENTRIES;

	trans = pmfs_new_transaction(sb, MAX_INODE_LENTRIES + max_logentries);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}
	pmfs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);

	ret = file_remove_privs(filp);
	if (ret) {
		pmfs_abort_transaction(sb, trans);
		goto out;
	}
	inode->i_ctime = inode->i_mtime = current_time(inode);
	pmfs_update_time(inode, pi);

	/* insert dedup code start*/

	i = count;
	dedup_offset = offset;

	// if(!dnode_hit && (start_blk&1023))
	// 	goto nondedup;
	
	for(j = 0; j < num_blocks; j++ ){
		struct dedupnode *dnode;
		struct refnode *rnode;
		unsigned block_len;
		void *xmem = NULL;
		size_t hashing = 0;
		char strength_hashing[16];
		// bool new_dnode_status = false;
		//The following variable use in rbtree update and hashing
		struct rb_node **entry_node = &(droot->rb_node);
		struct rb_node *parent = NULL;
		struct dedupnode *dnode_entry;
		struct dedupnode *dnode_obsolete=NULL;
		long result;

		// chunk divide equally
		block_len = (4096-dedup_offset)<i?(4096-dedup_offset):i;
		rnode = refnode_insert(sb, inode->i_ino, j+start_blk);
		
		if(rnode->dnode){
			dnode_entry = rnode->dnode;
			xmem = kmalloc(pmfs_inode_blk_size(pi), GFP_KERNEL);
			// memcpy(xmem, pmfs_get_block(sb, dnode_entry->blocknr<<PAGE_SHIFT), dnode_entry->length);

			atomic_dec(&dnode_entry->atomic_ref_count);
			
			if(atomic_read(&dnode_entry->atomic_ref_count)>1){
			// 	//update with multi-version
			// 	// overwrite_flag = 1;
			// 	// printk("update Copy and Write");
				;
			}	
			else{
				// atomic_dec(&dnode_entry->atomic_ref_count);
				dnode_obsolete = dnode_entry;//
				// free_dedupnode(sb, dnode_entry);
				// printk("udpate in-place!");
			}

			dnode = alloc_dedupnode(sb);
			// dnode->flag = 0;
			dnode->length = dnode_entry->length>(dedup_offset+block_len)?dnode_entry->length:(dedup_offset+block_len);
			// dnode->count = 1;
			atomic_set(&dnode->atomic_ref_count, 1);
			// new_dnode_status = true;
		}
		else{
			dnode = alloc_dedupnode(sb);
			// dnode->flag = 0;
			dnode->length = dedup_offset+block_len;
			// dnode->count = 1;
			atomic_set(&dnode->atomic_ref_count, 1);
			xmem = kmalloc(pmfs_inode_blk_size(pi), GFP_KERNEL);
			//build a new dnode
			// new_dnode_status = true;
		}
		// printk("pmfs write 1");

		//alloc and init dnode
		copy_from_user(xmem + dedup_offset, buf+count-i, block_len);
		dedup_offset = 0;
		dnode->hash_status = 0;
		short_hash(&hashing, xmem, block_len);
		dnode->hashval = hashing;
		dnode->hash_status = 1;
		// dnode->count = 1;
		atomic_set(&dnode->atomic_ref_count, 1);
		dnode->strength_hash_status = 0;
		if(dnode_hit>-32){
			strength_hash(strength_hashing, xmem, block_len);
			memcpy(dnode->strength_hashval, strength_hashing, 16);
			dnode->strength_hash_status = 1;
			printk("Recover the strength hashing compute!");
		}
		else{
			printk("Bypass the strength hashing compute!");
		}
		// memset(dnode->strength_hashval, 0, 16); 

		if(dnode_hit > 0){
			// dnode_entry = dedupnode_low_overhead_check(dnode);
			if(last_dnode_list!=NULL && last_dnode_list->next!=NULL){
				dnode_entry = list_entry(last_dnode_list->next, struct dedupnode, list);
				result = dnode->hashval - dnode_entry->hashval;
				if(result==0){
					// if(!dnode->strength_hash_status){
					// 	strength_hash(dnode->strength_hashval, xmem, dedup_offset+block_len);
					// 	dnode->strength_hash_status = 1;
					// } 
					if(!dnode_entry->strength_hash_status){
						strength_hash(dnode_entry->strength_hashval,
						pmfs_get_block(sb, dnode_entry->blocknr<<PAGE_SHIFT), dnode_entry->length);
						dnode_entry->strength_hash_status = 1;
						// printk("add strength hashing of dnode_entry!");
					}

					result =  memcmp(dnode->strength_hashval, dnode_entry->strength_hashval, 16);
					
				}
				if(result==0){
					printk("hit in low_overhead_check!");
					goto strength_hashing_hit;
				}
			}
		}
		// dnode_entry = dedupnode_tree_update(sb, dnode);
		while(*entry_node){
			parent = *entry_node;
			dnode_entry = rb_entry(*entry_node, struct dedupnode, node);
			result = dnode->hashval - dnode_entry->hashval;
			if(result < 0)
				entry_node = &(*entry_node)->rb_left;
			else if(result > 0)
				entry_node = &(*entry_node)->rb_right;
			else{
				if(!dnode->strength_hash_status){
					strength_hash(dnode->strength_hashval, xmem, block_len);
					dnode->strength_hash_status = 1;
					// printk("add strength hashing of dnode!");
				} 
				if(!dnode_entry->strength_hash_status){
					strength_hash(dnode_entry->strength_hashval,
					 pmfs_get_block(sb, dnode_entry->blocknr<<PAGE_SHIFT), dnode_entry->length);
					 dnode_entry->strength_hash_status = 1;
					//  printk("add strength hashing of dnode_entry!");
				}			
				
				result = memcmp(dnode->strength_hashval, dnode_entry->strength_hashval, 16);
				// printk("result:%ld", result);
				if(result < 0)
					entry_node = &(*entry_node)->rb_left;
				else if(result > 0)
					entry_node = &(*entry_node)->rb_right;
				else{
					printk("hit in rb_tree_search!");
					goto strength_hashing_hit;
				}
			}
		}
		rb_link_node(&dnode->node, parent, entry_node);
		rb_insert_color(&dnode->node, droot);
		dnode_entry = NULL;

		strength_hashing_hit:
		if(dnode_entry){
			list_move_tail(&dnode->list, &dindex->hma_unused);
			dnode = dnode_entry;
			// dnode->count++;
			atomic_inc(&dnode->atomic_ref_count);
			dnode_hit = 1;
			last_dnode_list = &dnode->list; //note down last hit node
			local_hit = true;
			/*add reference content */
		}else{
			dnode_hit--;
			// printk("dnode is new!");
			pmfs_new_block(sb, &dnode->blocknr, PMFS_BLOCK_TYPE_4K, 1);
			memcpy(pmfs_get_block(sb, dnode->blocknr<<PAGE_SHIFT), xmem
			, dnode->length);
		}
		
		kfree(xmem);
			
		dnode->flag = 1;
		// list_move_tail(&dnode->list, &dindex->hma_head);
		rnode->dnode = dnode;
		// if(dnode_obsolete)
		// 	if(!atomic_read(&dnode_obsolete->atomic_ref_count)){
		// 		dnode_obsolete->flag = 1;
		// 		free_dedupnode(sb, dnode_obsolete);
		// 	}
		 
		//part end 
		i -= block_len;
	}


	// printk("pmfswrite 7");
	if(local_hit){
		written = count;
		*ppos = pos + count;
		if (*ppos > inode->i_size) {
			i_size_write(inode, count+pos);
			pmfs_update_isize(inode, pi);
			// printk("isize chance!");
		}
		// printk("dedup system in work!");
	}else{
		// printk("raw pmfs write");
		/* We avoid zeroing the alloc'd range, which is going to be overwritten
		 * by this system call anyway */
		if (offset != 0) {
			if (pmfs_find_data_block(inode, start_blk) == 0)
		 	   new_sblk = true;
		}

		eblk_offset = (pos + count) & (pmfs_inode_blk_size(pi) - 1);
		if ((eblk_offset != 0) &&
			(pmfs_find_data_block(inode, end_blk) == 0))
			new_eblk = true;

		/* don't zero-out the allocated blocks */
		pmfs_alloc_blocks(trans, inode, start_blk, num_blocks, false);

		/* now zero out the edge blocks which will be partially written */
		pmfs_clear_edge_blk(sb, pi, new_sblk, start_blk, offset, false);
		pmfs_clear_edge_blk(sb, pi, new_eblk, end_blk, eblk_offset, true);

		written = __pmfs_xip_file_write(mapping, buf, count, pos, ppos);
		// printk("data write in pmfs");
	}

	if (written < 0 || written != count)
		pmfs_dbg_verbose("write incomplete/failed: written %ld len %ld"
			" pos %llx start_blk %lx num_blocks %lx\n",
			written, count, pos, start_blk, num_blocks);
	
	pmfs_commit_transaction(sb, trans);
	ret = written;
out:
	inode_unlock(inode);
	sb_end_write(inode->i_sb);
	//dedup part
	// printk("pmfs write out");
	// printk("pmfs xip file write end!");
	//part end
	PMFS_END_TIMING(xip_write_t, xip_write_time);
	return ret;
}

/* OOM err return with xip file fault handlers doesn't mean anything.
 * It would just cause the OS to go an unnecessary killing spree !
 */
static int __pmfs_xip_file_fault(struct vm_area_struct *vma,
				  struct vm_fault *vmf)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	pgoff_t size;
	void *xip_mem;
	unsigned long xip_pfn;
	int err;
	struct super_block *sb = inode->i_sb;
	struct refnode *rnode = NULL;

	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (vmf->pgoff >= size) {
		pmfs_dbg("[%s:%d] pgoff >= size(SIGBUS). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx), size 0x%lx\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->address, size);
		return VM_FAULT_SIGBUS;
	}
	
	//rnode search
	if(rnode_hit){
		rnode = list_entry(last_rnode_list->next, struct refnode, list);
		// printk("xip file fault function try hit");
		if(inode->i_ino==rnode->ino && (size_t)vmf->pgoff==rnode->index){
			xip_pfn = pmfs_get_pfn(sb, rnode->dnode->blocknr<<PAGE_SHIFT);
			err = 0;
			rnode_hit = true;
			last_rnode_list = last_rnode_list->next;
			// printk("xip file fault function hit!");
			goto rnode_find;
		}
	}
	rnode = refnode_search(sb, inode->i_ino, (size_t)vmf->pgoff);
	if(rnode){
		rnode_hit = true;
		err = 0;
		last_rnode_list = &rnode->list;
		// printk("rnode->dnode->blocknr:%lu", rnode->dnode->blocknr);
		xip_pfn = pmfs_get_pfn(sb, rnode->dnode->blocknr<<PAGE_SHIFT);
	}
	else
		err = pmfs_get_xip_mem(mapping, vmf->pgoff, 1, &xip_mem, &xip_pfn);
	rnode_find:
	//end

	if (unlikely(err)) {
		pmfs_dbg("[%s:%d] get_xip_mem failed(OOM). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx)\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->address);
		return VM_FAULT_SIGBUS;
	}

	pmfs_dbg_mmapv("[%s:%d] vm_start(0x%lx), vm_end(0x%lx), pgoff(0x%lx), "
			"BlockSz(0x%lx), VA(0x%lx)->PA(0x%lx)\n", __func__,
			__LINE__, vma->vm_start, vma->vm_end, vmf->pgoff,
			PAGE_SIZE, (unsigned long)vmf->address,
			(unsigned long)xip_pfn << PAGE_SHIFT);

	err = vm_insert_mixed(vma, (unsigned long)vmf->address,
			pfn_to_pfn_t(xip_pfn));

	if (err == -ENOMEM)
		return VM_FAULT_SIGBUS;
	/*
	 * err == -EBUSY is fine, we've raced against another thread
	 * that faulted-in the same page
	 */
	if (err != -EBUSY)
		BUG_ON(err);
	return VM_FAULT_NOPAGE;
}

static int pmfs_xip_file_fault(struct vm_fault *vmf)
{
	int ret = 0;
	timing_t fault_time;

	PMFS_START_TIMING(mmap_fault_t, fault_time);
	rcu_read_lock();
	ret = __pmfs_xip_file_fault(vmf->vma, vmf);
	rcu_read_unlock();
	PMFS_END_TIMING(mmap_fault_t, fault_time);
	return ret;
}

static int pmfs_find_and_alloc_blocks(struct inode *inode, sector_t iblock,
				       sector_t *data_block, int create)
{
	int err = -EIO;
	u64 block;
	pmfs_transaction_t *trans;
	struct pmfs_inode *pi;

	block = pmfs_find_data_block(inode, iblock);

	if (!block) {
		struct super_block *sb = inode->i_sb;
		if (!create) {
			err = -ENODATA;
			goto err;
		}

		pi = pmfs_get_inode(sb, inode->i_ino);
		trans = pmfs_current_transaction();
		if (trans) {
			err = pmfs_alloc_blocks(trans, inode, iblock, 1, true);
			if (err) {
				pmfs_dbg_verbose("[%s:%d] Alloc failed!\n",
					__func__, __LINE__);
				goto err;
			}
		} else {
			/* 1 lentry for inode, 1 lentry for inode's b-tree */
			trans = pmfs_new_transaction(sb, MAX_INODE_LENTRIES);
			if (IS_ERR(trans)) {
				err = PTR_ERR(trans);
				goto err;
			}

			rcu_read_unlock();
			inode_lock(inode);

			pmfs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY,
				LE_DATA);
			err = pmfs_alloc_blocks(trans, inode, iblock, 1, true);

			pmfs_commit_transaction(sb, trans);

			inode_unlock(inode);
			rcu_read_lock();
			if (err) {
				pmfs_dbg_verbose("[%s:%d] Alloc failed!\n",
					__func__, __LINE__);
				goto err;
			}
		}
		block = pmfs_find_data_block(inode, iblock);
		if (!block) {
			pmfs_dbg("[%s:%d] But alloc didn't fail!\n",
				  __func__, __LINE__);
			err = -ENODATA;
			goto err;
		}
	}
	pmfs_dbg_mmapvv("iblock 0x%lx allocated_block 0x%llx\n", iblock,
			 block);

	*data_block = block;
	err = 0;

err:
	return err;
}

static inline int __pmfs_get_block(struct inode *inode, pgoff_t pgoff,
				    int create, sector_t *result)
{
	int rc = 0;

	rc = pmfs_find_and_alloc_blocks(inode, (sector_t)pgoff, result,
					 create);
	return rc;
}

int pmfs_get_xip_mem(struct address_space *mapping, pgoff_t pgoff, int create,
		      void **kmem, unsigned long *pfn)
{
	int rc, dedup_rc;
	sector_t block = 0;
	struct inode *inode = mapping->host;

	rc = __pmfs_get_block(inode, pgoff, create, &block);
	dedup_rc = rc;

	if (rc) {
		pmfs_dbg1("[%s:%d] rc(%d), sb->physaddr(0x%llx), block(0x%llx),"
			" pgoff(0x%lx), flag(0x%x), PFN(0x%lx)\n", __func__,
			__LINE__, rc, PMFS_SB(inode->i_sb)->phys_addr,
			block, pgoff, create, *pfn);
		return rc;
	}

	*kmem = pmfs_get_block(inode->i_sb, block);
	*pfn = pmfs_get_pfn(inode->i_sb, block);

	pmfs_dbg_mmapvv("[%s:%d] sb->physaddr(0x%llx), block(0x%lx),"
		" pgoff(0x%lx), flag(0x%x), PFN(0x%lx)\n", __func__, __LINE__,
		PMFS_SB(inode->i_sb)->phys_addr, block, pgoff, create, *pfn);

	return 0;
}

static const struct vm_operations_struct pmfs_xip_vm_ops = {
	.fault	= pmfs_xip_file_fault,
};

int pmfs_xip_file_mmap(struct file *file, struct vm_area_struct *vma)
{
//	BUG_ON(!file->f_mapping->a_ops->get_xip_mem);

	file_accessed(file);

	vma->vm_flags |= VM_MIXEDMAP;

	vma->vm_ops = &pmfs_xip_vm_ops;
	pmfs_dbg_mmap4k("[%s:%d] MMAP 4KPAGE vm_start(0x%lx),"
			" vm_end(0x%lx), vm_flags(0x%lx), "
			"vm_page_prot(0x%lx)\n", __func__,
			__LINE__, vma->vm_start, vma->vm_end,
			vma->vm_flags, pgprot_val(vma->vm_page_prot));

	return 0;
}