#include <linux/list.h>
#include <linux/types.h>
#include <linux/rbtree.h>

struct hash_map_ppn{
    unsigned long hashing = 0;
    unsigned char ppn[6];
    unsigned int count = 0;
    struct list_head list; 
};

struct lpn_map_ppn{
    unsigned char lpn[6];
    struct hash_map_ppn *pnode;
};

