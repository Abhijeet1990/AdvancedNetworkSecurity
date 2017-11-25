#define _XOPEN_SOURCE 500 /* Enable certain library functions (strdup) on linux.  See feature_test_macros(7) */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include"hashtable.h"



/* Create a new hashtable. */
hashtable_t *ht_create( int size ) {

	hashtable_t *hashtable = NULL;
	int i;

	if( size < 1 ) return NULL;

	/* Allocate the table itself. */
	if( ( hashtable = malloc( sizeof( hashtable_t ) ) ) == NULL ) {
		return NULL;
	}

	/* Allocate pointers to the head nodes. */
	if( ( hashtable->table = malloc( sizeof( entry_t * ) * size ) ) == NULL ) {
		return NULL;
	}
	for( i = 0; i < size; i++ ) {
		hashtable->table[i] = NULL;
	}

	hashtable->size = size;

	return hashtable;	
}

/* Hash a string for a particular hash table. */
int ht_hash( hashtable_t *hashtable, struct Key key ) {

	unsigned long int hashval;
	int i = 0;

	/* Convert our string to an integer */
	while( hashval < ULONG_MAX && i < strlen( key.key_name ) ) {
		hashval = hashval << 8;
		hashval += key.key_name[ i ];
		i++;
	}

	return hashval % hashtable->size;
}

/* Create a key-value pair. */
entry_t *ht_newpair( struct Key key, const unsigned char *value ) {
	entry_t *newpair;

	if( ( newpair = malloc( sizeof( entry_t ) ) ) == NULL ) {
		return NULL;
	}

	if( ( newpair->key.key_name = strdup( key.key_name )
		) == NULL ) {
		return NULL;
	}
	if( ( newpair->key.src_ip = strdup( key.src_ip )
		) == NULL ) {
		return NULL;
	}
	if( ( newpair->key.dest_ip = strdup( key.dest_ip )
		) == NULL ) {
		return NULL;
	}
	if( ( newpair->key.src_port = strdup( key.src_port )
		) == NULL ) {
		return NULL;
	}
	if( ( newpair->key.dest_port = strdup( key.dest_port )
		) == NULL ) {
		return NULL;
	}

	if( ( newpair->value = strdup( value ) ) == NULL ) {
		return NULL;
	}

	newpair->next = NULL;

	return newpair;
}

/* Insert a key-value pair into a hash table. */
void ht_set( hashtable_t *hashtable, struct Key key, const unsigned char *value ) {
	int bin = 0;
	entry_t *newpair = NULL;
	entry_t *next = NULL;
	entry_t *last = NULL;

	bin = ht_hash( hashtable, key);

	next = hashtable->table[ bin ];
	printf("bin: %d",bin);
	while( next != NULL && next->key.key_name != NULL && strcmp( key.key_name, next->key.key_name ) > 0 ) {
		
		last = next;
		next = next->next;
	}
	//printf("the key value %s %s %s %s %s \n",key.key_name,key.src_ip,key.dest_ip,key.src_port,key.dest_port);
	//printf("the next keyvalue %s  \n",next->key.key_name);
	/* There's already a pair.  Let's add to that string.  */
	if( next != NULL && next->key.key_name != NULL && strcmp(key.src_ip, next->key.src_ip)==0
					      && strcmp(key.dest_ip, next->key.dest_ip)==0
					      && strcmp(key.src_port, next->key.src_port)==0
					      && strcmp(key.dest_port, next->key.dest_port)==0 ){
		//printf("the key value %s %s %s %s %s \n",key.key_name,key.src_ip,key.dest_ip,key.src_port,key.dest_port);
		strcat(next->value,strdup(value));

	/* Nope, could't find it.  Time to grow a pair. */
	} else {
		newpair = ht_newpair( key, value );

		/* We're at the start of the linked list in this bin. */
		if( next == hashtable->table[ bin ] ) {
			newpair->next = next;
			hashtable->table[ bin ] = newpair;
	
		/* We're at the end of the linked list in this bin. */
		} else if ( next == NULL ) {
			last->next = newpair;
	
		/* We're in the middle of the list. */
		} else  {
			newpair->next = next;
			last->next = newpair;
		}
	}
}

/* Retrieve a key-value pair from a hash table. */
char *ht_get( hashtable_t *hashtable, struct Key key ) {
	int bin = 0;
	entry_t *pair;

	bin = ht_hash( hashtable, key );

	/* Step through the bin, looking for our value. */
	pair = hashtable->table[ bin ];
	while( pair != NULL && pair->key.key_name != NULL && strcmp( key.key_name, pair->key.key_name ) > 0 ) {
		pair = pair->next;
	}

	/* Did we actually find anything? */
	if( pair == NULL || pair->key.key_name == NULL || (strcmp( key.src_ip, pair->key.src_ip ) != 0) 
						&& (strcmp( key.dest_ip, pair->key.dest_ip ) != 0)
						&& (strcmp( key.src_port, pair->key.src_port ) != 0)
						&& (strcmp( key.dest_port, pair->key.dest_port ) != 0)) {
		return NULL;

	} else {
		return pair->value;
	}
	
}

int main( int argc, char **argv ) {
	int i,j;
	hashtable_t *hashtable = ht_create( 65536 );
	struct Key key[3];
	
	key[0].key_name="Key1";
	key[0].src_ip="10.10.10.1";
	key[0].dest_ip="11.11.11.1";
	key[0].src_port="232";
	key[0].dest_port="80";

	key[1].key_name="Key2";
	key[1].src_ip="10.10.10.17";
	key[1].dest_ip="11.11.11.1";
	key[1].src_port="232";
	key[1].dest_port="80";

	key[2].key_name="Key3";
	key[2].src_ip="10.10.10.1";
	key[2].dest_ip="11.11.11.1";
	key[2].src_port="232";
	key[2].dest_port="80";

	for(i=1;i<3;i++)
	     for(j=0;j<i;j++)
		{if(key[i].src_ip==key[j].src_ip && key[i].dest_ip==key[j].dest_ip && key[i].src_port==key[j].src_port && key[i].dest_port==key[j].dest_port)
		{printf("hahah");
		key[i].key_name=key[j].key_name;}
		}
	//strcpy(key3.key_name,key1.key_name);
/*	strcpy(key3.key_name, key3.src_ip);
	strcat(key3.key_name, key3.dest_ip);
	strcat(key3.key_name, key3.src_port);
	strcat(key3.key_name, key3.dest_port);*/
	
	
	ht_set( hashtable, key[0], "inky" );
	ht_set( hashtable, key[1], "blinky" );
	ht_set( hashtable, key[2], "pinky" );
	

	printf( "%s\n", ht_get( hashtable, key[0] ) );
	printf( "%s\n", ht_get( hashtable, key[1] ) );
	printf( "%s\n", ht_get( hashtable, key[2] ) );
	

	return 0;
}
