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
#include <linux/string.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include "dedup.c"

/* dedup claim start */

static LIST_HEAD(hash_map_addr_list);
struct list_head *last_hit;
struct list_head *new_list = &hash_map_addr_list;
bool find_flag = false;
struct rb_root root = RB_ROOT;

struct list_head *last_ref;
bool ref_find_flag = false;
struct rb_root ref_root = RB_ROOT;
static LIST_HEAD(dedup_ref_list);

size_t dedup_interval = 1;
/*
	dedup rbtree function
*/
// char *do_digest(char* code, size_t len){
// 	struct scatterlist sg[2];
// 	char result[128];
// 	struct crypto_ahash *tfm;
// 	struct ahash_request *req;
	
// 	tfm = crypto_alloc_ahash("md5", 0, CRYPTO_ALG_ASYNC);
// 	if (IS_ERR(tfm))
// 		fail();

// 	ahash_request_set_callback(req, 0, NULL, NULL);
// 	ahash_request_set_crypt(req, sg, result, 2);

// 	if (crypto_ahash_digest(req))
// 		fail();
	
// 	ahash_request_free(req);
// 	crypto_free_ahash(tfm);
	
// 	return result;
// }

struct hash_map_addr *rb_search_insert_node(
	struct rb_root *root, struct hash_map_addr *hash_map_addr_new)
{
	struct rb_node **entry_node = &(root->rb_node);
	struct rb_node *parent = NULL;
	struct hash_map_addr *hash_map_addr_entry;
	struct list_head *hashing_list_temp;
	// bool test_printk_flag = true;

	while(*entry_node){
		parent = *entry_node;
		hash_map_addr_entry = rb_entry(*entry_node, struct hash_map_addr, node);
		if(hash_map_addr_new->hashing < hash_map_addr_entry->hashing)
			entry_node = &(*entry_node)->rb_left;
		else if(hash_map_addr_new->hashing > hash_map_addr_entry->hashing)
			entry_node = &(*entry_node)->rb_right;
		else{
			hashing_list_temp = &hash_map_addr_entry->hashing_list;
			while(hash_map_addr_new->length != hash_map_addr_entry->length ||
				memcmp(hash_map_addr_new->addr,hash_map_addr_entry->addr,hash_map_addr_new->length)!=0){
				if(hash_map_addr_entry->hashing_list.next == hashing_list_temp 
				/* ||hash_map_addr_entry->hashing_list.next == NULL */ ){
					// not find duplication, return NULL
					// printk("hash collision and not find duplication, add new node");
					list_add_tail(&hash_map_addr_new->hashing_list, hashing_list_temp);
					return NULL; 
				}
				else{
					hash_map_addr_entry = list_entry(
						hash_map_addr_entry->hashing_list.next, struct hash_map_addr, hashing_list);
					// if(test_printk_flag){
					// 	printk("This hash value has multiple nodes!");
					// 	test_printk_flag = false;
					// }
				}	
			}
			// printk("same data block, dedup");
			return hash_map_addr_entry;
		}	
	}
	rb_link_node(&hash_map_addr_new->node, parent, entry_node);
	rb_insert_color(&hash_map_addr_new->node, root);
	// printk("new node in rbtree");
	
	return NULL;
}

void ref_insert_node(struct rb_root *ref_root, struct ref_map *ref_map_new)
{
	struct rb_node **entry_node = &(ref_root->rb_node);
	struct rb_node *parent = NULL;
	struct ref_map *ref_map_entry;

	while(*entry_node){
		parent = *entry_node;
		ref_map_entry = rb_entry(*entry_node, struct ref_map, node);
		if(ref_map_new->virt_addr < ref_map_entry->virt_addr)
			entry_node = &(*entry_node)->rb_left;
		else if(ref_map_new->virt_addr > ref_map_entry->virt_addr)
			entry_node = &(*entry_node)->rb_right;
		else{
			if(ref_map_new->index < ref_map_entry->index)
				entry_node = &(*entry_node)->rb_left;
			else if(ref_map_new->index > ref_map_entry->index)
				entry_node = &(*entry_node)->rb_right;
			else{
				ref_map_entry->hma->count--;
				// printk("new count:%lu",ref_map_new->hma->count);
				ref_map_entry->hma = ref_map_new->hma;
				//  = ref_map_new->hma;
				// rb_erase(*entry_node, ref_root);
				// kfree(ref_map_entry);
				return;
			}	
		}		
	}
	rb_link_node(&ref_map_new->node, parent, entry_node);
	rb_insert_color(&ref_map_new->node, ref_root);
}

struct ref_map *ref_search_node(struct rb_root *ref_root, void *inode, size_t index)
{
	struct rb_node *entry_node = ref_root->rb_node;
	struct ref_map *ref_map_entry;

	while(entry_node){
		ref_map_entry = rb_entry(entry_node, struct ref_map, node);
		if(inode < ref_map_entry->virt_addr)
			entry_node = entry_node->rb_left;
		else if(inode > ref_map_entry->virt_addr)
			entry_node = entry_node->rb_right;
		else
		{
			if(index < ref_map_entry->index)
				entry_node = entry_node->rb_left;
			else if(index > ref_map_entry->index)
				entry_node = entry_node->rb_right;
			else
				return ref_map_entry;
		}	
	}
	return NULL;
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

	pos = *ppos;
	index = pos >> PAGE_SHIFT;
	offset = pos & ~PAGE_MASK;

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	end_index = (isize - 1) >> PAGE_SHIFT;
	printk("-------------------------------");
	// printk("mapping:%lu",(size_t)mapping);
	// printk("ra:%lu",(size_t)_ra);
	// printk("filp:%lu",(size_t)filp);
	// printk("buf:%lu",(size_t)buf);
	// printk("len:%lu",len);
	// printk("ppos:%llu",*ppos);
	// printk("\n");
	do {
		unsigned long nr, left;
		void *xip_mem;
		unsigned long xip_pfn;
		int zero = 0;

		/* read dedup data block start */
		struct ref_map *ref_map_temp;
		/* end */

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_SIZE;
		printk("index:%lu",index);
		printk("pos:%llu",pos);
		// printk("len>>12:%lu",len>>12);
		// printk("+");
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~PAGE_MASK) + 1;
			// printk("nr:%lu", nr);
			// printk("isize:%llu", isize);
			// printk("~PAGE_MASK:%lu", ~PAGE_MASK);
			// printk("offset:%lu",offset);
			if (nr <= offset) {
				goto out;
			}
		}
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;

		/* dedup new code start */
		if( (index>0 && ref_find_flag) && 
		(&dedup_ref_list!=last_ref->next && last_ref->next!=NULL)){
			ref_map_temp = list_entry(last_ref->next, struct ref_map, list);
			if(inode == ref_map_temp->virt_addr && index == ref_map_temp->index)
			{
				// if(memcmp(ref_map_temp->hma->addr, xip_mem, nr)!=0){
				// 	printk("read fault, diff data!");
				// }
				// if(nr != ref_map_temp->hma->length){
				// 	printk("read fault, diff length!");
				// }
				xip_mem = *ref_map_temp->phys_addr;
				printk("xip_mem:%lu",(size_t)xip_mem);
				ref_find_flag = true;
				// printk("read datablock from fast link!");
				last_ref = last_ref->next;
				error = 0;
				goto read_redirect;
			}
		}
		ref_map_temp = ref_search_node(&ref_root, inode, index);
		
		if(ref_map_temp != NULL)
		{
			xip_mem = *ref_map_temp->phys_addr;
			error = 0;
			last_ref = &ref_map_temp->list;
			ref_find_flag = true;
			// printk("xip_mem after redirect:%lu", (size_t)xip_mem);
			goto read_redirect;
		}
		
		error = pmfs_get_xip_mem(mapping, index, 0, &xip_mem, &xip_pfn);
		ref_find_flag = false;

		read_redirect:

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
		// printk("left:%lu", left);
		// printk("offset:%lu", offset); 
		// printk("nr:%lu",nr); 
		// printk("xip_mem:%.*s", nr, (char*)(xip_mem+offset));
		// printk("\n");
		
		PMFS_END_TIMING(memcpy_r_t, memcpy_time);

		if (left) {
			error = -EFAULT;
			goto out;
		}

		copied += (nr - left);
		offset += (nr - left);
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;
		// printk("offset:%lu",offset);
		// printk("left:%lu",left);
		// printk("len-copied>>12:%ld",(long)(len>>12)-(long)(copied>>12));
		// printk("len>>12:%lu",len>>12);
		// printk("copied>>12:%lu",copied>>12);
		// printk("\n");
	} while (copied < len);

out:
	*ppos = pos + copied;
	if (filp){
		file_accessed(filp);
		// printk("file_accessed(filp)");
		// printk("*ppos:%llu",(long long)*ppos);
		// printk("\n");
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

	PMFS_START_TIMING(internal_write_t, write_time);
	pi = pmfs_get_inode(sb, inode->i_ino);

	// printk("++++++++++++++++++++++++++++++++++++++++++++");
	do {
		unsigned long index;
		unsigned long offset;
		size_t copied;
		void *xmem;
		unsigned long xpfn;
		//dedup claiming start
		// unsigned hashing = 0;
		// unsigned long *temp = kmalloc(sizeof(unsigned long), GFP_KERNEL);
		
		struct hash_map_addr *hash_map_addr_entry;//, *hash_map_addr_temp;
		// hash_map_addr_temp = kmalloc(sizeof(*hash_map_addr_temp), GFP_KERNEL);
		//end

		offset = (pos & (sb->s_blocksize - 1)); /* Within page */
		index = pos >> sb->s_blocksize_bits;
		bytes = sb->s_blocksize - offset;
		if (bytes > count)
			bytes = count;
		
		// status = pmfs_get_xip_mem(mapping, index, 1, &xmem, &xpfn);
		// printk("status%lu",status);
		
		// if (status)
		// 	break;
		status = 0;
		copied = bytes;

		// PMFS_START_TIMING(memcpy_w_t, memcpy_time);
		// pmfs_xip_mem_protect(sb, xmem + offset, bytes, 1);
		// copied = memcpy_to_nvmm((char *)xmem, offset, buf, bytes);
		// pmfs_xip_mem_protect(sb, xmem + offset, bytes, 0);
		// PMFS_END_TIMING(memcpy_w_t, memcpy_time);

		if(new_list->next!=&hash_map_addr_list && new_list->next!=NULL){
			/* add physical address */
			hash_map_addr_entry = list_entry(new_list->next, struct hash_map_addr, list);
			if(hash_map_addr_entry->hashing_md5 == buf){
				// offset = (pos & (sb->s_blocksize - 1)); /* Within page */
				// index = pos >> sb->s_blocksize_bits;
				// bytes = sb->s_blocksize - offset;
				// if (bytes > count)
				// bytes = count;

				status = pmfs_get_xip_mem(mapping, index, 1, &xmem, &xpfn);
		
				if (status)
					break;
	
				PMFS_START_TIMING(memcpy_w_t, memcpy_time);
				pmfs_xip_mem_protect(sb, xmem + offset, bytes, 1);
				copied = memcpy_to_nvmm((char *)xmem, offset, buf, bytes);
				pmfs_xip_mem_protect(sb, xmem + offset, bytes, 0);
				PMFS_END_TIMING(memcpy_w_t, memcpy_time);
				// printk("new_list hashing:%lu",hash_map_addr_entry->hashing);
				if(hash_map_addr_entry->addr!=NULL)
					kfree(hash_map_addr_entry->addr);
				hash_map_addr_entry->addr = (void*)xmem;
				hash_map_addr_entry->pfn = (void*)xpfn;
				// printk("data_block content:%s:",(char *)hash_map_addr_entry->addr);
				// rb_insert_node(&root, list_entry(new_list->next, struct hash_map_addr, list));
				new_list = new_list->next;
				hash_map_addr_entry->flag = true;
				hash_map_addr_entry->hashing_md5 = NULL;
				// printk("new data block");
				// pmfs_flush_edge_cachelines(pos, copied, xmem + offset);
				// printk("flush");
				goto test;
			}
		}else{
			printk("No new data block");
		}

		/* if start or end dest address is not 8 byte aligned, 
	 	 * __copy_from_user_inatomic_nocache uses cacheable instructions
	 	 * (instead of movnti) to write. So flush those cachelines. */


		test:
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

	//dedup insert rbtree node start
	// printk("============================================\n");
	
	// printk("============================================");
	//end

	*ppos = pos;
	printk("pos:%lu", (size_t)pos);
	
	/*
 	* No need to use i_size_read() here, the i_size
 	* cannot change under us because we hold i_mutex.
 	*/
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		pmfs_update_isize(inode, pi);
		printk("inode->i_size:%lu", (size_t)inode->i_size);
		printk("isize update!");
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
	size_t i,j,hashing;	
	struct hash_map_addr *hash_map_addr_entry;
	unsigned long actual_num_blocks = 0;
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
	printk("num_blocks:%lu",num_blocks);
	/* offset in the actual block size block */
	offset = pos & (pmfs_inode_blk_size(pi) - 1);
	start_blk = pos >> sb->s_blocksize_bits;
	end_blk = start_blk + num_blocks - 1;

	block = pmfs_find_data_block(inode, start_blk);
	printk("block:%llu", block);

	/* Referring to the inode's block size, not 4K */
	same_block = (((count + offset - 1) >>
			pmfs_inode_blk_shift(pi)) == 0) ? 1 : 0;
	printk("same_block:%d",same_block);	
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
	// xmem = kmalloc(count, GFP_KERNEL);
	// copy_from_user(xmem, buf, count);
	for(j = 0; j < 32; j++ ){
		struct hash_map_addr *hash_map_addr_temp;
		struct ref_map *ref_map_temp;
		unsigned k, dedup_ret = 1, data_remainder;
		void *xmem = NULL;
		bool hash_flag = true;
		size_t trace = 512; /* 1/4 of pmfs_inode_blk_size(pi) */

		hashing = 0;
		hash_map_addr_temp = kmalloc(sizeof(*hash_map_addr_temp), GFP_KERNEL);
		hash_map_addr_temp->length = pmfs_inode_blk_size(pi);
		hash_map_addr_temp->flag = false;
		hash_map_addr_temp->hashing_md5 = (void*)buf + count - i;
		hash_map_addr_temp->addr = NULL;
		
		if((j&(dedup_interval-1)) != 0 && find_flag){
			// ;
			// printk("j:%lu",j);
		}

		if(i <= pmfs_inode_blk_size(pi)){
			hash_map_addr_temp->length = i;
			dedup_ret = 0;
			if(!hash_flag){
				goto direct_write_out;
			}
			xmem = kmalloc(i, GFP_KERNEL);
			copy_from_user(xmem, buf+count-i, i);
			if(i>>3<trace){	
				trace = i>>3;
				data_remainder = i&(sizeof(size_t)-1); 
				if(data_remainder!=0)
					memcpy(&hashing, xmem+i-data_remainder, data_remainder);
			}
		}else{
			if(!hash_flag){
				goto direct_write_out;
			}
			xmem = kmalloc(pmfs_inode_blk_size(pi), GFP_KERNEL);
			copy_from_user(xmem, buf+count-i, pmfs_inode_blk_size(pi));
		}

		for(k=0;k<trace;k++){
			hashing += *(size_t*)(xmem+k*8);
			hashing += (hashing << 3);
			hashing ^= (hashing >> 2);
		}
		// printk("sizeof(size_t):%lu",sizeof(size_t));
		// printk("i>>3:%lu",i>>3);
		printk("hashing:%lu",hashing);
		// printk("\n");
		hash_map_addr_temp->hashing = hashing;
		hash_map_addr_temp->count = 1;
		hash_map_addr_temp->addr = xmem;
		INIT_LIST_HEAD(&hash_map_addr_temp->hashing_list);

		if(find_flag == true && last_hit != NULL )
		{	
			hash_map_addr_entry = list_entry(last_hit->next, struct hash_map_addr, list);
			if(hashing == hash_map_addr_entry->hashing /*&& 
			memcmp(hash_map_addr_temp->addr,hash_map_addr_entry->addr,hash_map_addr_temp->length) == 0*/
			){
				hash_map_addr_entry->count++;
				last_hit = &hash_map_addr_entry->list;
				kfree(hash_map_addr_temp);
				if(xmem!=NULL)
					kfree(xmem);
				hash_map_addr_temp = hash_map_addr_entry;
				printk("fast hit!");
				/* add reference content */
				dedup_interval = 0;
				goto find;
			}
			else
				find_flag = false;
		}

		hash_map_addr_entry = rb_search_insert_node(&root, hash_map_addr_temp);
		if(hash_map_addr_entry){
			/* hashing conflict decision */
			hash_map_addr_entry->count++;
			last_hit = &hash_map_addr_entry->list;
			find_flag = true;
			kfree(hash_map_addr_temp);
			if(xmem!=NULL)
				kfree(xmem);
			hash_map_addr_temp = hash_map_addr_entry;
			printk("fit!");
			goto find;
			/*add reference content */
		}
		// else{
		// 	// dedup_interval = (31 & ((dedup_interval<<1) - 1)) + 1;
		// 	// printk("dedup_interval:%lu",dedup_interval);
		// 	;
		// }

		// printk("hashing:%lu",hashing);
		// rb_insert_node(&root, hash_map_addr_temp);
		direct_write_out:
		INIT_LIST_HEAD(&hash_map_addr_temp->list);
		list_add_tail(&hash_map_addr_temp->list, &hash_map_addr_list);
		actual_num_blocks++;
		
		find:
		//less than 32, break;
		ref_map_temp = kmalloc(sizeof(*ref_map_temp), GFP_KERNEL);
		ref_map_temp->virt_addr = inode;
		ref_map_temp->index = j+start_blk;
		ref_map_temp->hma = hash_map_addr_temp;
		ref_map_temp->phys_addr = &hash_map_addr_temp->addr;
		ref_map_temp->pfn = &hash_map_addr_temp->pfn;
		ref_insert_node(&ref_root, ref_map_temp);
		INIT_LIST_HEAD(&ref_map_temp->list);
		list_add_tail(&ref_map_temp->list, &dedup_ref_list);

		// printk("inode:%lu",(size_t)ref_map_temp->virt_addr);
		// printk("index:%lu",ref_map_temp->index);
		// printk("length:%lu",hash_map_addr_temp->length);
		
		if(dedup_ret == 0)
			break;
		else
			i -= pmfs_inode_blk_size(pi);	
	}
	

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
	// if(actual_num_blocks!=0){
	// 	pmfs_alloc_blocks(trans, inode, start_blk, actual_num_blocks, false);
	/* now zero out the edge blocks which will be partially written */
	// pmfs_clear_edge_blk(sb, pi, new_sblk, start_blk, offset, false);
	// pmfs_clear_edge_blk(sb, pi, new_eblk, end_blk, eblk_offset, true);
	// }

	printk("actual_num_blocks:%lu", actual_num_blocks);
	written = __pmfs_xip_file_write(mapping, buf, count, pos, ppos);
	printk("written:%ld",written);

	if (written < 0 || written != count)
		pmfs_dbg_verbose("write incomplete/failed: written %ld len %ld"
			" pos %llx start_blk %lx num_blocks %lx\n",
			written, count, pos, start_blk, num_blocks);
	
	pmfs_commit_transaction(sb, trans);
	ret = written;
out:
	inode_unlock(inode);
	sb_end_write(inode->i_sb);
	PMFS_END_TIMING(xip_write_t, xip_write_time);
	printk("return ret");
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
	//dedup insert code
	struct ref_map *ref_map_temp;

	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (vmf->pgoff >= size) {
		pmfs_dbg("[%s:%d] pgoff >= size(SIGBUS). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx), size 0x%lx\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->address, size);
		return VM_FAULT_SIGBUS;
	}
	
	err = pmfs_get_xip_mem(mapping, vmf->pgoff, 1, &xip_mem, &xip_pfn);
	
	//dedup insert
	ref_map_temp = ref_search_node(&ref_root, inode, (size_t)(vmf->pgoff));
	if(ref_map_temp!=NULL)
	{
		// printk("pfn in fault:%lu",(size_t)(*ref_map_temp->pfn));
		xip_pfn = (size_t)*ref_map_temp->pfn;
		// printk("err:%d",err);
	}
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
	int rc;
	sector_t block = 0;
	struct inode *inode = mapping->host;

	rc = __pmfs_get_block(inode, pgoff, create, &block);
	// printk("rc:%d",rc);
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

	/* dedup start */
	// printk("PMFS_SB(inode->i_sb)->phys_addr:%llu\n", PMFS_SB(inode->i_sb)->phys_addr);
	// printk("block:%lu\n",block);
	// printk("block value:%lu\n",block>>12);
	// printk("pfn<<PAGE_SHIFT:%lu\n",(size_t)*pfn<<PAGE_SHIFT);
	// printk("kmem:%lu",(size_t)*kmem);
	/* end */

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