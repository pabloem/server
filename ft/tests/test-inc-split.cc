/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
// vim: ft=cpp:expandtab:ts=8:sw=4:softtabstop=4:
#ident "$Id$"
#ident "Copyright (c) 2007-2012 Tokutek Inc.  All rights reserved."
/* The goal of this test:  Make sure that when we aggressively promote 
 * that we don't get a fencepost error on the size.  (#399, I think)

 * 
 * For various values of I do the following:
 *
 *   Make a tree of height 3 (that is, the root is of height 2)
 *   use small nodes (say 4KB)
 *   you have this tree:
 *                   A
 *                     B
 *                      C0 C1 C2 .. C15
 *   A has only one child.  B has as many children as it can get.
 *   Fill the C nodes (the leaves) all almost full.
 *   Fill B's buffer up with a big message X for C15, and a slightly smaller message Y for C1.
 *   Put into A's buffer a little message Z aimed at C0.
 *   Now when insert a message of size I aimed at C0.  I and Z together are too big to fit in A.
 *   First: X will be pushed into C15, resulting in this split
 *    A
 *     B0
 *       C0 C1 ... C8
 *     B1
 *       C9 C10 ... C15 C16
 *   At this point C0 through C14 are full, Y is in B0's buffer, and A's buffer contains I and Z.
 *   So we try to push Z if it fits.  Which it does.
 *   So then we try to I if it fits.  If we calculated wrong, everything  breaks now.
 *  
 */

#include "test.h"
#include "includes.h"

static TOKUTXN const null_txn = 0;
static DB * const null_db = 0;

enum { NODESIZE = 1024, KSIZE=NODESIZE-100, TOKU_PSIZE=20 };

CACHETABLE ct;
FT_HANDLE t;
int fnamelen;
char *fname;

static void
doit (int ksize __attribute__((__unused__))) {
    BLOCKNUM cnodes[FT_FANOUT], bnode, anode;

    char *keys[FT_FANOUT-1];
    int keylens[FT_FANOUT-1];
    int i;
    int r;
    
    fnamelen = strlen(__SRCFILE__) + 20;
    XMALLOC_N(fnamelen, fname);

    snprintf(fname, fnamelen, "%s.ft_handle", __SRCFILE__);
    r = toku_create_cachetable(&ct, 16*1024, ZERO_LSN, NULL_LOGGER); assert(r==0);
    unlink(fname);
    r = toku_open_ft_handle(fname, 1, &t, NODESIZE, NODESIZE, TOKU_DEFAULT_COMPRESSION_METHOD, ct, null_txn, toku_builtin_compare_fun);
    assert(r==0);
    toku_free(fname);

    toku_testsetup_initialize();  // must precede any other toku_testsetup calls

    for (i=0; i<FT_FANOUT; i++) {
	r=toku_testsetup_leaf(t, &cnodes[i], 1, NULL, NULL);
	assert(r==0);
	char key[KSIZE+10];
	int keylen = 1+snprintf(key, KSIZE, "%08d%0*d", i*10000+1, KSIZE-9, 0);
	char val[1];
	char vallen=0;
	r=toku_testsetup_insert_to_leaf(t, cnodes[i], key, keylen, val, vallen);
	assert(r==0);
    }

    // Now we have a bunch of leaves, all of which are with 100 bytes of full.
    for (i=0; i+1<FT_FANOUT; i++) {
	char key[TOKU_PSIZE];
	keylens[i]=1+snprintf(key, TOKU_PSIZE, "%08d", (i+1)*10000);
	keys[i]=toku_strdup(key);
    }

    r = toku_testsetup_nonleaf(t, 1, &bnode, FT_FANOUT, cnodes, keys, keylens);
    assert(r==0);

    for (i=0; i+1<FT_FANOUT; i++) {
	toku_free(keys[i]);
    }

    {
	const int magic_size = (NODESIZE-toku_testsetup_get_sersize(t, bnode))/2-25;
	//printf("magic_size=%d\n", magic_size);
	char key [KSIZE];
	int keylen = 1+snprintf(key, KSIZE, "%08d%0*d", 150002, magic_size, 0);
	char val[1];
	char vallen=0;
	r=toku_testsetup_insert_to_nonleaf(t, bnode, FT_INSERT, key, keylen, val, vallen);

	keylen = 1+snprintf(key, KSIZE, "%08d%0*d", 2, magic_size-1, 0);
	r=toku_testsetup_insert_to_nonleaf(t, bnode, FT_INSERT, key, keylen, val, vallen);
    }
    //printf("%lld sersize=%d\n", bnode, toku_testsetup_get_sersize(t, bnode));
    // Now we have an internal node which has full children and the buffers are nearly full

    r = toku_testsetup_nonleaf(t, 2, &anode, 1,          &bnode, 0, 0);
    assert(r==0);
    {
	char key[20];
	int keylen = 1+snprintf(key, 20, "%08d", 3);
	char val[1];
	char vallen=0;
	r=toku_testsetup_insert_to_nonleaf(t, anode, FT_INSERT, key, keylen, val, vallen);
    }
    if (0)
    {
	const int magic_size = 1; //NODESIZE-toku_testsetup_get_sersize(t, anode)-100;
	DBT k,v;
	char key[20];
	char data[magic_size];
	int keylen=1+snprintf(key, sizeof(key), "%08d", 4);
	int vallen=magic_size;
	snprintf(data, magic_size, "%*s", magic_size-1, " ");
	r=toku_ft_insert(t,
			  toku_fill_dbt(&k, key, keylen),
			  toku_fill_dbt(&v, data, vallen),
			  null_txn);
    }

    r = toku_testsetup_root(t, anode);
    assert(r==0);

    r = toku_close_ft_handle_nolsn(t, 0);    assert(r==0);
    r = toku_cachetable_close(&ct); assert(r==0);

    //printf("ksize=%d, unused\n", ksize);

}

int
test_main (int argc __attribute__((__unused__)), const char *argv[] __attribute__((__unused__))) {
    doit(53);
#if 0
    //Skip remaining tests. 
{
    int i;

    for (i=1; i<NODESIZE/2; i++) {
	printf("extrasize=%d\n", i);
	doit(i);
    }
}
#endif
    
    return 0;
}