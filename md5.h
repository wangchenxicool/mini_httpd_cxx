/* MD5.H - header file for MD5C.C
 */
#ifndef _MD5_H_
#define _MD5_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "safe.h"

#define TEST_BLOCK_LEN 1000
#define TEST_BLOCK_COUNT 1000

/* PROTOTYPES should be set to one if and only if the compiler supports
  function argument prototyping.
The following makes PROTOTYPES default to 0 if it has not already
  been defined with C compiler flags.
 */
#ifndef PROTOTYPES
#define PROTOTYPES 0
#endif

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
typedef unsigned short int UINT2;

/* UINT4 defines a four byte word */
typedef unsigned long int UINT4;

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
  returns an empty list.
 */
#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif

/* MD5 context. */
typedef struct {
    UINT4 state[4];             /* state (ABCD) */
    UINT4 count[2];             /* number of bits, modulo 2^64 (lsb first) */
    unsigned char buffer[64];   /* input buffer */
} MD5_CTX;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

    void auth_generate_key (char *key, int key_len, const char *mac, const time_t *timestamp);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
