#include <linux/list.h>
#include <linux/rbtree.h>

struct hash_map_addr{
    size_t hashing;
    void *hashing_md5;
    void *addr;
    unsigned long pfn;
    size_t length;
    size_t count;
    struct list_head list;
    bool flag; 
    struct rb_node node;
    struct list_head hashing_list;
};

struct ref_map{
    void *virt_addr;
    size_t index;
    void **phys_addr;
    unsigned long *pfn;
    struct hash_map_addr *hma;
    struct list_head list;
    struct rb_node node;
};

struct dedup_inode{
    size_t end_blk;
    size_t length;
    const char __user buf[32];
};

struct dedup_index{
    struct list_head hma_head;
    struct list_head hma_unused;
    struct list_head ref_head;
    struct list_head ref_unused;
};