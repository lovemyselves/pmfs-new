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
// #include <linux/string.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
// #include <crypto/internal/hash.h>
// #include <crypto/scatterwalk.h>
#include <linux/scatterlist.h>
#include <linux/err.h>
// #include <linux/gfp.h>
// #include <linux/slab.h>
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

// static struct kmem_cache *pmfs_dedup_cachep;

size_t dedup_interval = 1;
/*
	dedup rbtree function
*/

// struct sdesc {
//     struct shash_desc shash;
//     char ctx[];
// };

// static struct sdesc *init_sdesc(struct crypto_shash *alg)
// {
//     struct sdesc *sdesc;
//     int size;

//     size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
//     sdesc = kmalloc(size, GFP_KERNEL);
//     if (!sdesc)
//         return ERR_PTR(-ENOMEM);
//     sdesc->shash.tfm = alg;
//     sdesc->shash.flags = 0x0;
//     return sdesc;
// }

// static int calc_hash(struct crypto_shash *alg,
//              const unsigned char *data, unsigned int datalen,
//              unsigned char *digest) {
//     struct sdesc *sdesc;
//     int ret;

//     sdesc = init_sdesc(alg);
//     if (IS_ERR(sdesc)) {
//         pr_info("trusted_key: can't alloc %s\n", alg);
//         return PTR_ERR(sdesc);
//     }

//     ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
//     kfree(sdesc);
//     return ret;
// }

struct hash_map_addr *rb_search_insert_node(
	struct rb_root *root, struct hash_map_addr *hash_map_addr_new)
{
	struct rb_node **entry_node = &(root->rb_node);
	struct rb_node *parent = NULL;
	struct hash_map_addr *hash_map_addr_entry;
	struct list_head *hashing_list_temp;

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
				memcmp(hash_map_addr_new->hashing_md5, hash_map_addr_entry->hashing_md5, sizeof(char)<<4)
				){
				if(hash_map_addr_entry->hashing_list.next == hashing_list_temp 
				|| hash_map_addr_entry->hashing_list.next == NULL){
					list_add_tail(&hash_map_addr_new->hashing_list, hashing_list_temp);
					return NULL; 
				}
				else{
					hash_map_addr_entry = list_entry(
						hash_map_addr_entry->hashing_list.next, struct hash_map_addr, hashing_list);
				}	
			}
			return hash_map_addr_entry;
		}	
	}
	rb_link_node(&hash_map_addr_new->node, parent, entry_node);
	rb_insert_color(&hash_map_addr_new->node, root);
	
	return NULL;
}

struct ref_map* ref_insert_node(struct rb_root *ref_root, struct ref_map *ref_map_new)
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
				kfree(ref_map_new);
				return ref_map_entry;
			}	
		}		
	}
	rb_link_node(&ref_map_new->node, parent, entry_node);
	rb_insert_color(&ref_map_new->node, ref_root);

	return NULL;
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

bool short_hash(size_t *hashing, char *xmem, size_t len)
{
	size_t trace = len >> 3;
	size_t data_remainder = len & (sizeof(size_t)-1);
	size_t k,hash_offset=0;

	size_t thin_internal = len >> 10;
	size_t thick_internal_count = (len&1023) >> 3;

	if(*hashing!=0)
		return false;
				 
	if(data_remainder!=0)
		memcpy(hashing, xmem+len-data_remainder, data_remainder);
	
	// for(k=0;k<trace;k++){
	// 		*hashing += *(size_t*)(xmem + hash_offset);
	// 		*hashing += (*hashing << 3);
	// 		*hashing ^= (*hashing >> 2);
	// 		hash_offset += sizeof(size_t);
	// }

	for(k=0;k<len;){
		*hashing += *(size_t*)(xmem + k);
		*hashing += (*hashing << 3);
		*hashing ^= (*hashing >> 2);
		if(thick_internal_count>0){
			k += sizeof(size_t);	
		}
		k += (thin_internal<<3);
	}
	printk("sizeof(size_t):%d",sizeof(size_t));
	
	return true;
}

bool strength_hash(char *result, char* data, size_t len){
	struct shash_desc *desc;
	desc = kmalloc(sizeof(*desc), GFP_KERNEL);
	desc->tfm = crypto_alloc_shash("md5", 0, CRYPTO_ALG_ASYNC);

	if(desc->tfm == NULL)
		return false;

	crypto_shash_init(desc);
	crypto_shash_update(desc, data, len);
	crypto_shash_final(desc, result);
	crypto_free_shash(desc->tfm);

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

	pos = *ppos;
	index = pos >> PAGE_SHIFT;
	offset = pos & ~PAGE_MASK;

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	end_index = (isize - 1) >> PAGE_SHIFT;

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
		if( (index>0 && ref_find_flag) && 
		(&dedup_ref_list!=last_ref->next && last_ref->next!=NULL)){
			ref_map_temp = list_entry(last_ref->next, struct ref_map, list);
			if(inode == ref_map_temp->virt_addr && index == ref_map_temp->index)
			{
				xip_mem = *ref_map_temp->phys_addr;
				ref_find_flag = true;
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

	PMFS_START_TIMING(internal_write_t, write_time);
	pi = pmfs_get_inode(sb, inode->i_ino);

	do {
		unsigned long index;
		unsigned long offset;
		size_t copied;
		void *xmem;
		unsigned long xpfn;
		//dedup claiming start
		
		// struct hash_map_addr *hash_map_addr_entry;//, *hash_map_addr_temp;

		offset = (pos & (sb->s_blocksize - 1)); /* Within page */
		index = pos >> sb->s_blocksize_bits;
		bytes = sb->s_blocksize - offset;
		if (bytes > count)
			bytes = count;
		
		status = pmfs_get_xip_mem(mapping, index, 1, &xmem, &xpfn);
		// status = 0;
		
		if (status)
			break;

		copied = bytes;

		// printk("a __write call");

		PMFS_START_TIMING(memcpy_w_t, memcpy_time);
		pmfs_xip_mem_protect(sb, xmem + offset, bytes, 1);
		copied = memcpy_to_nvmm((char *)xmem, offset, buf, bytes);
		pmfs_xip_mem_protect(sb, xmem + offset, bytes, 0);
		PMFS_END_TIMING(memcpy_w_t, memcpy_time);

		// if(new_list->next!=&hash_map_addr_list && new_list->next!=NULL){
		// 	/* add physical address */
		// 	hash_map_addr_entry = list_entry(new_list->next, struct hash_map_addr, list);
			
		// 	// copied = memcpy_to_nvmm((char *)xmem, offset, buf, bytes);
		// 	if(!hash_map_addr_entry->flag){	
		// 		// if(hash_map_addr_entry->addr!=NULL)
		// 		// 	kfree(hash_map_addr_entry->addr);
		// 		// hash_map_addr_entry->addr = (void*)xmem;
		// 		hash_map_addr_entry->pfn = xpfn;
		// 		hash_map_addr_entry->hashing_md5 = NULL;
		// 		hash_map_addr_entry->flag = true;
		// 	}
		// 	// pmfs_flush_edge_cachelines(pos, copied, xmem + offset);
		// 	j++;
		// 	// printk("a new data block");
		// 	new_list = new_list->next;
		// }

		/* if start or end dest address is not 8 byte aligned, 
	 	 * __copy_from_user_inatomic_nocache uses cacheable instructions
	 	 * (instead of movnti) to write. So flush those cachelines. */
		pmfs_flush_edge_cachelines(pos, copied, xmem + offset); 
	
		// dedup:
        if (likely(copied > 0)) {
			status = copied;

			if (status >= 0) {
				written += status;
				count -= status;
				pos += status;
				buf += status;
				// printk("status:%lu",status);
			}
		}
		if (unlikely(copied != bytes))
			if (status >= 0)
				status = -EFAULT;
		if (status < 0)
			break;	
	} while (count);

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
	for(j = 0; j < num_blocks; j++ ){
		struct hash_map_addr *hash_map_addr_temp;
		struct ref_map *ref_map_temp, *insert_ret = NULL;
		unsigned block_len;
		void *xmem = NULL;
		// bool hash_flag = true;
		size_t overwrite_flag = 0;
		// size_t trace = 512; /* 1/4 of pmfs_inode_blk_size(pi) */
		size_t hashing = 0;
		char* strength_hashval = kmalloc(sizeof(char)<<4, GFP_KERNEL);

		ref_map_temp = kmalloc(sizeof(*ref_map_temp), GFP_KERNEL);
		ref_map_temp->virt_addr = inode;
		ref_map_temp->index = j+start_blk;
		
		insert_ret = ref_insert_node(&ref_root, ref_map_temp);
		
		// printk("pos 1");
		if(insert_ret){
			ref_map_temp = insert_ret;
			printk("ref count:%lu", ref_map_temp->hma->count);
			if(ref_map_temp->hma->count!=0){
				overwrite_flag = 1;
				printk("should update COW");
			}
			else{
				printk("should update in-place");
				ref_map_temp->hma->count = 1;
				overwrite_flag = 2;
			}
		}else{
			printk("new data block");
		}

		if(overwrite_flag!=2){
			hash_map_addr_temp = kmalloc(sizeof(*hash_map_addr_temp), GFP_KERNEL);
			hash_map_addr_temp->flag = false;
			hash_map_addr_temp->hashing_md5 = NULL;
		}
		// printk("pos 2");		

		if(i+dedup_offset <= pmfs_inode_blk_size(pi))
			block_len = i;
		else
			block_len = pmfs_inode_blk_size(pi) - dedup_offset;

		// spin_lock_irq(&in_place_lock);

		if(overwrite_flag == 2){
			copy_from_user(ref_map_temp->hma->addr + dedup_offset, buf+count-i, block_len);
		}else if(overwrite_flag == 1){
			xmem = kmalloc(pmfs_inode_blk_size(pi), GFP_KERNEL);
			memcpy(xmem, *ref_map_temp->phys_addr, dedup_offset + block_len);
			copy_from_user(xmem + dedup_offset, buf+count-i, block_len);
			hash_map_addr_temp->addr = xmem;
			hash_map_addr_temp->length = dedup_offset + block_len;
		}else{
			xmem = kmalloc(pmfs_inode_blk_size(pi), GFP_KERNEL);
			copy_from_user(xmem + dedup_offset, buf+count-i, block_len);
			hash_map_addr_temp->addr = xmem;
			hash_map_addr_temp->length = block_len + dedup_offset;
		}
		// spin_unlock_irq(&in_place_lock);
		// printk("pos 3");
		
		dedup_offset = 0;
		
		if(overwrite_flag==2){
			goto direct_write_out;
		}

		if(short_hash(&hashing, hash_map_addr_temp->addr, hash_map_addr_temp->length))
			printk("2hashing:%lu",hashing);
	
		hash_map_addr_temp->hashing = hashing;
		hash_map_addr_temp->count = 1;
		
		hash_map_addr_temp->pfn = start_blk + j;
		INIT_LIST_HEAD(&hash_map_addr_temp->hashing_list);

		if(strength_hash(strength_hashval, hash_map_addr_temp->addr, hash_map_addr_temp->length)){
			printk("strength_hash:%c",*strength_hashval);
			hash_map_addr_temp->hashing_md5 = (void *)strength_hashval;
		}
		// printk("pos 4");

		if(find_flag == true && last_hit != NULL )
		{	
			hash_map_addr_entry = list_entry(last_hit->next, struct hash_map_addr, list);
			if(hashing == hash_map_addr_entry->hashing // && 
			// memcmp(hash_map_addr_temp->addr,hash_map_addr_entry->addr,hash_map_addr_temp->length) == 0
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
		
		// printk("pos 5");
		INIT_LIST_HEAD(&hash_map_addr_temp->list);
		list_add_tail(&hash_map_addr_temp->list, &hash_map_addr_list);
		direct_write_out:
		actual_num_blocks++;
		// printk("pos 6");
		find:
		//less than 32, break;
		if(!insert_ret){
			ref_map_temp->hma = hash_map_addr_temp;
			ref_map_temp->phys_addr = &hash_map_addr_temp->addr;
			ref_map_temp->pfn = &hash_map_addr_temp->pfn;
		
			INIT_LIST_HEAD(&ref_map_temp->list);
			list_add_tail(&ref_map_temp->list, &dedup_ref_list);
		}else if(overwrite_flag == 1){
			ref_map_temp->phys_addr = &hash_map_addr_temp->addr;
			ref_map_temp->hma = hash_map_addr_temp;
		}
		i -= block_len;
	}
	
	/* don't zero-out the allocated blocks */
	pmfs_alloc_blocks(trans, inode, start_blk, num_blocks, false);

	/* We avoid zeroing the alloc'd range, which is going to be overwritten
	 * by this system call anyway */
	if (offset != 0) {
		if (pmfs_find_data_block(inode, start_blk) == 0)
		    new_sblk = true;
	}

	// end_blk = start_blk + actual_num_blocks - 1;

	eblk_offset = (pos + count) & (pmfs_inode_blk_size(pi) - 1);
	if ((eblk_offset != 0) &&
			(pmfs_find_data_block(inode, end_blk) == 0))
		new_eblk = true;

	// if(actual_num_blocks!=0){
	// 	pmfs_alloc_blocks(trans, inode, start_blk, actual_num_blocks, false);
	/* now zero out the edge blocks which will be partially written */
	pmfs_clear_edge_blk(sb, pi, new_sblk, start_blk, offset, false);
	pmfs_clear_edge_blk(sb, pi, new_eblk, end_blk, eblk_offset, true);
	// }

	// printk("actual_num_blocks:%lu", actual_num_blocks);
	written = __pmfs_xip_file_write(mapping, buf, count, pos, ppos);
	// if (pos+count > inode->i_size) {
	// 	i_size_write(inode, pos+count);
	// 	pmfs_update_isize(inode, pi);
	// 	printk("inode->i_size:%lu", (size_t)inode->i_size);
	// 	printk("isize update!");
	// }

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
	// struct ref_map *ref_map_temp;

	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (vmf->pgoff >= size) {
		pmfs_dbg("[%s:%d] pgoff >= size(SIGBUS). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx), size 0x%lx\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->address, size);
		return VM_FAULT_SIGBUS;
	}
	
	// err = pmfs_get_xip_mem(mapping, vmf->pgoff, 1, &xip_mem, &xip_pfn);
	// printk("err:%d",err);
	
	//dedup insert
	// ref_map_temp = ref_search_node(&ref_root, inode, (size_t)(vmf->pgoff));
	// if(ref_map_temp!=NULL)
	// {
	// 	// printk("pfn in fault:%lu",(size_t)(*ref_map_temp->pfn));
	// 	xip_pfn = *ref_map_temp->pfn;
	// 	err = 0;
	// }else
	// 	err = pmfs_get_xip_mem(mapping, vmf->pgoff, 1, &xip_mem, &xip_pfn);
	//end

	err = pmfs_get_xip_mem(mapping, vmf->pgoff, 1, &xip_mem, &xip_pfn);

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
	// sector_t dedup_block = 0;
	struct inode *inode = mapping->host;
	// struct ref_map *ref_map_temp;

	rc = __pmfs_get_block(inode, pgoff, create, &block);
	dedup_rc = rc;
	// printk("*******");
	// printk("rc:%d",rc);
	// printk("a call of pmfs_get_xip_mem");
	// printk("*******");

	if (rc) {
		pmfs_dbg1("[%s:%d] rc(%d), sb->physaddr(0x%llx), block(0x%llx),"
			" pgoff(0x%lx), flag(0x%x), PFN(0x%lx)\n", __func__,
			__LINE__, rc, PMFS_SB(inode->i_sb)->phys_addr,
			block, pgoff, create, *pfn);
		return rc;
	}

	*kmem = pmfs_get_block(inode->i_sb, block);
	*pfn = pmfs_get_pfn(inode->i_sb, block);

	// ref_map_temp = ref_search_node(&ref_root, inode, pgoff);
	// if(ref_map_temp != NULL)
	// {
	// 	// *kmem = *ref_map_temp->phys_addr;
	// 	rc = 0;
	// 	// printk("find a read-dedup metadata");
	// 	// if(*kmem == *ref_map_temp->phys_addr)
	// 	// printk("read a raw data block");
	// 	// last_ref = &ref_map_temp->list;
	// 	// ref_find_flag = true;
	// 	// printk("xip_mem after redirect:%lu", (size_t)xip_mem);
	// 	// goto read_redirect;
	// }

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