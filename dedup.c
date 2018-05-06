#include <linux/list.h>
#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/kernel.h>

struct hash_map_ppn{
    unsigned long hashing;
    char ppn[6];
    unsigned int count;
    struct list_head list; 
};

struct lpn_map_ppn{
    char lpn[6];
    struct hash_map_ppn *pnode;
};

