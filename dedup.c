#include <linux/list.h>
#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/kernel.h>

struct hash_map_addr{
    unsigned long hashing;
    unsigned long hashing_md5;
    void *addr;
    unsigned int count;
    struct list_head list; 
};


