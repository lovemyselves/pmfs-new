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
    struct list_head hashing_list;
    struct rb_node node;
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

struct dedupnode{
    size_t hashval;
    __le8 hashing_status;
    char strength_hashval[16];
    __le8 strength_hash_status;
    unsigned long blocknr;
    unsigned length;
    unsigned count;
    unsigned int flag;
    struct list_head list;
    struct rb_node node;
};

struct refnode{
    unsigned long ino;
    unsigned long index;
    unsigned long blocknr;
    struct dedupnode *dnode;
    unsigned int flag;
    struct list_head list;
    struct rb_node node;
};

struct dedup_index{
    struct list_head hma_head;
    struct list_head hma_unused;
    struct rb_root dedupnode_root;
    struct list_head ref_head;
    struct list_head ref_unused;
    struct rb_root refroot;
    int update_flag;
};