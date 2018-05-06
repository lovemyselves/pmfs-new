#include <linux/list.h>
#include <linux/types.h>
#include <linux/rbtree.h>

struct hash_map_ppn{
    unsigned unsigned long hashing;
    unsigned char ppn[6];
    unsigned int count;
    struct list_head list; 
};

struct lpn_map_ppn{
    unsigned char lpn[6];
    struct hash_map_ppn *pnode;
};

