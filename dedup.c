#include <linux/list.h>
#include <linux/rbtree.h>

struct hash_map_addr{
    size_t hashval;
    char strength_hashval[16];
    // unsigned short strength_hash_status;
    unsigned long blocknr;
    short length;
    short count;
    // unsigned int flag;
    char status; //similar chmod command, 111 respectively represent transaction, short hash, strength hash
    struct list_head list;
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
    unsigned short hash_status;
    char strength_hashval[16];
    unsigned short strength_hash_status;
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