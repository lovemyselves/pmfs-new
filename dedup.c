#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/types.h>

struct hash_map_addr{
    size_t hashval;
    char strength_hashval[16];
    // unsigned short strength_hash_status;
    unsigned long blocknr;
    short length;
    short count;
    // unsigned int flag;
    u8 status; //similar chmod command, 111 respectively represent transaction, short hash, strength hash
    u8 node_flag; //101, list_head update success mean 100, rb_node update success mean 001
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
    atomic_t atomic_ref_count;
    unsigned int flag;
    struct list_head list;
    struct rb_node node;
};

struct refnode{
    unsigned long ino;
    unsigned long index;
    unsigned long blocknr;
    struct dedupnode *dnode;
    unsigned int flag; //means the status of this struct node
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
    unsigned long update_flags;
};