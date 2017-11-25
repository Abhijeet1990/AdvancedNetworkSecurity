#define _XOPEN_SOURCE 500 /* Enable certain library functions (strdup) on linux.  See feature_test_macros(7) */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>

/***we need to form a unique key based on the source IP, destination IP and the port number. The value to be stored are the payload*/


struct Key {
	char *src_ip;
	char *dest_ip;
	char *src_port;
	char *dest_port;
	char *key_name;
};

struct entry_s {
	struct Key key;
	const unsigned char *value;
	struct entry_s *next;
};

typedef struct entry_s entry_t;

struct hashtable_s {
	int size;
	struct entry_s **table;	
};

typedef struct hashtable_s hashtable_t;


/* Create a new hashtable. */
hashtable_t *ht_create( int size );


/* Hash a string for a particular hash table. */
int ht_hash( hashtable_t *hashtable, struct Key **key );

/* Create a key-value pair. */
entry_t *ht_newpair( struct Key **key, const unsigned char *value );

/* Insert a key-value pair into a hash table. */
void ht_set( hashtable_t *hashtable,struct Key **key, const unsigned char *value );

/* Retrieve a key-value pair from a hash table. */
char *ht_get( hashtable_t *hashtable, struct Key **key );






