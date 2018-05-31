#include <linux/list.h>
#include <linux/rbtree.h>

struct hash_map_addr{
    unsigned hashing;
    unsigned long hashing_md5;
    void *addr;
    unsigned int count;
    struct list_head list; 
};

struct __hash_map_addr{
    unsigned hashing;
    void *hashing_md5;
    void *addr;
    unsigned int count;
    struct list_head list;
    struct rb_node node;     
};

struct __hash_map_addr * search_node(struct rb_root *root, unsigned hashing)
{
	struct rb_node *entry_node = root->rb_node;
	int result;
	struct __hash_map_addr *hash_map_addr_entry;
	
	while(entry_node){
		// hash_map_addr_entry = rb_entry(entry_node, struct __hash_map_addr, node);
		// result = hash_map_addr_entry->hashing - hashing;
		// if(result < 0)
		// 	entry_node = entry_node->rb_left;
		// else if(result > 0)
		// 	entry_node = entry_node->rb_right;
		// else
		// 	return hash_map_addr_entry;
	}
	return NULL;
}
