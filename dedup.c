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
    unsigned long hashing_md5;
    void *addr;
    unsigned int count;
    struct rb_node *rb_left;
    struct rb_node *rb_right;  
};
