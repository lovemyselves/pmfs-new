#include <linux/list.h>
#include <linux/types.h>
#include <linux/rbtree.h>

struct hash_map_ppn{
    unsigned char* hashing;
    unsigned char* ppn;
    unsigned u16 count;
    struct list_head list; 
};

struct lpn_map_ppn{
    unsigned char* lpn;
    struct *hash_map_ppn ppn_state;
};

