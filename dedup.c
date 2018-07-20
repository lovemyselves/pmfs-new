#include <linux/list.h>
#include <linux/rbtree.h>
#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/scatterlist.h>

// struct hash_map_addr{
//     unsigned hashing;
//     unsigned long hashing_md5;
//     void *addr;
//     unsigned int count;
//     struct list_head list; 
// };

struct hash_map_addr{
    size_t hashing;
    void *hashing_md5;
    void *addr;
    void *pfn;
    size_t length;
    size_t count;
    struct list_head list;
    struct rb_node node;
    struct list_head hashing_list;
    bool flag;     
};

struct ref_map{
    void *virt_addr;
    size_t index;
    void **phys_addr;
    void **pfn;
    struct hash_map_addr *hma;
    struct list_head list;
    struct rb_node node;
};


struct scatterlist sg[2];
char result[128];
struct crypto_ahash *tfm;
struct ahash_request *req;
	
tfm = crypto_alloc_ahash("md5", 0, CRYPTO_ALG_ASYNC);
if (IS_ERR(tfm))
	fail();
	
/* ... set up the scatterlists ... */

req = ahash_request_alloc(tfm, GFP_ATOMIC);
if (!req)
	fail();

ahash_request_set_callback(req, 0, NULL, NULL);
ahash_request_set_crypt(req, sg, result, 2);
	
if (crypto_ahash_digest(req))
	fail();

ahash_request_free(req);
crypto_free_ahash(tfm);