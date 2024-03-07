/*
*
*  sfghash.c
*
*  Generic hash table library.
*
*  This hash table maps unique keys to void data pointers.
*
*  Features:
*    1) Keys may be ascii strings of variable size, or
*       fixed length (per table) binary byte sequences.  This
*       allows use as a Mapping for String+Data pairs, or a 
*       generic hashing.
*    2) User can allocate keys, or pass copies and we can 
*       allocate space and save keys.
*    3) User can pass a free function to free up user data
*       when the table is deleted.
*    4) Table rows sizes can be automatically adjusted to
*       the nearest prime number size.
*
*  6/10/03 - man - Upgraded the hash function to a Hardened hash function,
*      it has no predictable cycles, and each hash table gets a different
*      randomized hashing function. So even with the source code, you cannot predict 
*      anything with this function.  If an  attacker can can setup a feedback
*      loop he might gain some knowledge of how to muck with us, buit even in that case
*      his odds are astronomically skinny.  This is actually the same problem as solved
*      early on with hashing functions where degenerate data with close keys could
*      produce very long bucket chains.
*
*  Copyright (C) 2001 Marc A Norton
*  Copyright (C) 2003 Sourcefire,Inc.
*
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sfghash.h"

/*
*  uncomment this include to use xmalloc functions
*/

/*
*  Private Malloc
*/
static 
void * s_malloc( int n )
{
     return malloc( n );
}

/*
*  Private Free
*/
static 
void s_free( void * p )
{
   if( p )free( p );
}

/*
*  A classic hash routine using prime numbers
*
*  Constants for the Prime No. based hash routines
*/


/*
*   Primiitive Prime number test, not very fast nor efficient, but should be ok for
*   hash table sizes of typical size.
*/
static 
int isPrime(int num )
{
   int i;
   for(i=2;i<num;i++)
   {
      if( (num % i) == 0 ) break;//oops not prime, should have a remainder
   }
   if( i == num ) return 1;
   return 0;
}
/*
*  Iterate number till we find a prime.
*/
static
int calcNextPrime(int num )
{
	while( !isPrime( num ) ) num++;
	return num;
}

/*
*
*    Create a new hash table
*
*    nrows    : number of rows in hash table, primes are best.
*               > 0  => we calc the nearest prime .ge. nrows internally
*               < 0  => we use the magnitude as nrows.
*    keysize  : > 0 => bytes in each key, keys are binary bytes,
*               all keys are the same size.
*               ==0 => keys are strings and are null terminated, 
*               allowing random key lengths. 
*    userkeys : > 0 => indicates user owns the key data
*               and we should not allocate or free space for it,
*               nor should we attempt to free the user key. We just
*               save the pointer to the key. 
*               ==0 => we should copy the keys and manage them internally
*    userfree : routine to free users data, null if we should not 
*               free user data in sfghash_delete(). The routine
*               should be of the form 'void userfree(void * userdata)',
*               'free' works for simple allocations.
*/
SFGHASH * sfghash_new( int nrows, int keysize, int userkeys, void (*userfree)(void*p) )
{
   int    i;
   SFGHASH * h;

   if( nrows > 0 ) /* make sure we have a prime number */
   {
      nrows = calcNextPrime( nrows );
   }
   else   /* use the magnitude or nrows as is */
   { 
      nrows = -nrows;
   }


   h = (SFGHASH*)s_malloc( sizeof(SFGHASH) );
   if( !h ) return 0;

   memset( h, 0, sizeof(SFGHASH) );

   h->sfhashfcn = sfhashfcn_new( nrows );
   if( !h->sfhashfcn ) return 0;

   h->table = (SFGHASH_NODE**) s_malloc( sizeof(SFGHASH_NODE*) * nrows );
   if( !h->table ) return 0;

   for( i=0; i<nrows; i++ )
   {
      h->table[i] = 0;
   }

   h->userkey = userkeys;

   h->keysize = keysize;

   h->nrows = nrows;

   h->count = 0;

   h->userfree = userfree;

   h->crow = 0; // findfirst/next current row

   h->cnode = 0; // findfirst/next current node ptr

   return h;
}

/*
*  Set Splay mode : Splays nodes to front of list on each access
*/
void sfghash_splaymode( SFGHASH * t, int n )
{
   t->splay = n;
}


SFDICT * sfdict_new( int nitems )
{
   return sfghash_new( nitems, 0, GH_COPYKEYS, NULL );
}

void sfdict_delete( SFDICT * h )
{
    sfghash_delete( h );
}

/*
*  Delete the hash Table 
*
*  free key's, free node's, and free the users data.
*/
void sfghash_delete( SFGHASH * h )
{
  int            i;
  SFGHASH_NODE * node, * onode;

  if( !h ) return;
 
  sfhashfcn_free( h->sfhashfcn );

  if( h->table )
  {  
    for(i=0;i<h->nrows;i++)
    {
      for( node=h->table[i]; node;  )
      {
        onode = node;
        node  = node->next;

        if( !h->userkey && onode->key ) 
            s_free( onode->key );

        if( h->userfree && onode->data )
            h->userfree( onode->data ); /* free users data, with users function */

        s_free( onode );
      }
    }
    s_free( h->table );
    h->table = 0;
  }

  s_free( h );
}

/*
*  Get the # of Nodes in HASH the table
*/
int sfghash_count( SFGHASH * t )
{
  return t->count;
}

int sfdict_count( SFDICT * t )
{
  return t->count;
}


/*
*  Add a key + data pair
*  ---------------------
*
*  key + data should both be non-zero, although data can be zero
*
*  t    - hash table
*  key  - users key data (should be unique in this table)
*         may be ascii strings or fixed size binary keys
*  data - users data pointer
*
*  returns  SF_HASH_NOMEM: malloc error
*           SF_HASH_INTABLE : key already in table (t->cnode points to the node)
*           SF_OK: added a node for this key + data pair
*
*  Notes:
*  If the key node already exists, then t->cnode points to it on return,
*  this allows you to do something with the node - like add the data to a 
*  linked list of data items held by the node, or track a counter, or whatever.
*
*/
int sfghash_add( SFGHASH * t, void * key, void * data )
{
    unsigned    hashkey;
	int         klen;
    int         index;
    SFGHASH_NODE  *hnode;

    /*
    *   Get proper Key Size
    */  
    if( t->keysize > 0  )
    {
        klen = t->keysize;
    }
    else
    {
	/* need the nul byte for strcmp() in sfghash_find() */
        klen = strlen( (char*)key ) + 1;
    }
    
    hashkey = t->sfhashfcn->hash_fcn(  t->sfhashfcn, (unsigned char*) key, klen );
    
    index = hashkey % t->nrows;

    /*
    *  Uniqueness: 
    *  Check 1st to see if the key is already in the table
    *  Just bail if it is.
    */
    for( hnode=t->table[index]; hnode; hnode=hnode->next )
    {
       if( t->keysize > 0 )
       {
          if( !t->sfhashfcn->keycmp_fcn(hnode->key,key,klen) )
          {
              t->cnode = hnode; /* save pointer to the node */
              return SFGHASH_INTABLE; /* found it */
          }
       }
       else
       {
         if( !strcmp((const char *)hnode->key,(const char*)key) )
         {
             t->cnode = hnode; /* save pointer to the node */
             return SFGHASH_INTABLE; /* found it */
         }
       }
    }

    /* 
    *  Create new node 
    */
    hnode = (SFGHASH_NODE*)s_malloc(sizeof(SFGHASH_NODE));
    if( !hnode )
         return SFGHASH_NOMEM;
    
    /* Add the Key */
    if( t->userkey )
    {
      /* Use the Users key */
      hnode->key = key;
    }
    else
    {
      /* Create new key */
      hnode->key = s_malloc( klen );
      if( !hnode->key )
           return SFGHASH_NOMEM;

      /* Copy key  */
      memcpy(hnode->key,key,klen);
    }
    
    /* Add The Node */
    if( t->table[index] ) /* add the node to the existing list */
    {
        hnode->prev = 0;  // insert node as head node
        hnode->next=t->table[index];
        hnode->data=data;
        t->table[index]->prev = hnode;
        t->table[index] = hnode;
    }
    else /* 1st node in this list */
    {
        hnode->prev=0;
        hnode->next=0;
        hnode->data=data;
        t->table[index] = hnode;
    }

    t->count++;

    return SFGHASH_OK;
}

/*
*
*/
int sfdict_add( SFGHASH * t, char * key, void * data )
{
   return sfghash_add( t, key, data );
}
/*
*  move a node to the front of the list
*/
static void movetofront( SFGHASH *t , int index, SFGHASH_NODE * n )
{
    if( t->table[index] != n ) // if not at fron of list already...
    {
      /* Unlink the node */
      if( n->prev ) n->prev->next = n->next;
      if( n->next ) n->next->prev = n->prev;
      
      /* Link at front of list */
      n->prev=0;
      n->next=t->table[index];
      t->table[index]->prev=n;
    }
}

/*
*  Find a Node based on the key, return users data.
*/
static SFGHASH_NODE * sfghash_find_node( SFGHASH * t, void * key)
{
    unsigned    hashkey;
    int         index, klen;
    SFGHASH_NODE  *hnode;

    if( t->keysize  )
    {
	klen = t->keysize;
    }
    else
    {
	klen = strlen( (char*) key ) + 1;
    }

    hashkey = t->sfhashfcn->hash_fcn(  t->sfhashfcn, (unsigned char*) key, klen );
    
    index = hashkey % t->nrows;
   
    for( hnode=t->table[index]; hnode; hnode=hnode->next )
    {
        if( t->keysize == 0 )
        {
           if( !strcmp((char*)hnode->key,(char*)key) )
           {
               if( t->splay  > 0 )
                   movetofront(t,index,hnode);

               return hnode;
           }
        }
        else
        {
           if( !t->sfhashfcn->keycmp_fcn(hnode->key,key,t->keysize) )
           {
               if( t->splay  > 0 )
                   movetofront(t,index,hnode);

               return hnode;
           }
        }
    }

   return NULL;
}

/*
*  Find a Node based on the key, return users data.
*/
void * sfghash_find( SFGHASH * t, void * key)
{
    SFGHASH_NODE * hnode;

    hnode = sfghash_find_node( t, key );

    if( hnode ) return hnode->data;

    return NULL;
}

/*
*  Unlink and free the node
*/
static int sfghash_free_node( SFGHASH * t, unsigned index, SFGHASH_NODE * hnode )
{
    if( !t->userkey && hnode->key ) 
        s_free( hnode->key );
    hnode->key = 0;

    if( t->userfree && hnode->data )
        t->userfree( hnode->data ); /* free users data, with users function */

    if( hnode->prev )  // not the 1st node
    {
          hnode->prev->next = hnode->next;
          if( hnode->next ) hnode->next->prev = hnode->prev;
    }
    else if( t->table[index] )  // 1st node
    {
           t->table[index] = t->table[index]->next;
           if( t->table[index] )t->table[index]->prev = 0;
    }

    s_free( hnode );

    t->count--;

    return SFGHASH_OK;
}

/*
*  Remove a Key/Data Pair from the table - find it, unlink it, and free the memory for it.
*
*  returns : 0 - OK
*           -1 - node not found
*/
int sfghash_remove( SFGHASH * t, void * key)
{
    SFGHASH_NODE * hnode;
    int klen;
    unsigned hashkey, index;

    if( t->keysize > 0 )
    {
       klen = t->keysize;
    }
    else
    {
       klen = strlen((char*)key) + 1;
    }

    hashkey = t->sfhashfcn->hash_fcn(  t->sfhashfcn, (unsigned char*) key, klen );
    
    index = hashkey % t->nrows;

    for( hnode=t->table[index]; hnode; hnode=hnode->next )
    {
       if( t->keysize > 0 )
       {
         if( !t->sfhashfcn->keycmp_fcn(hnode->key,key,klen) )
         {
             return sfghash_free_node( t, index, hnode );
         }
       }
       else
       {
         if( !strcmp((const char *)hnode->key,(const char*)key) )
         {
             return sfghash_free_node( t, index, hnode );
         }
       }
    }

   return SFGHASH_ERR;  
}

/*
*
*/
int sfdict_remove( SFGHASH * t, char * key)
{
   return sfghash_remove( t, key);
}

/*
*   Get First Hash Table Node
*/
SFGHASH_NODE * sfghash_findfirst1( SFGHASH * t )
{
    /* Start with 1st row */
    for( t->crow=0; t->crow < t->nrows; t->crow++ )
    {    
       /* Get 1st Non-Null node in row list */
       t->cnode = t->table[t->crow];

       if( t->cnode ) return t->cnode;
    }
  return NULL;
}

/*
*   Get Next Hash Table Node
*/
SFGHASH_NODE * sfghash_findnext1( SFGHASH * t )
{
    if( t->cnode ) /* get next in this list */
    {
       /* Next node in current node list */
       t->cnode = t->cnode->next;
       if( t->cnode )
       {
           return t->cnode;
       }
    }

    /* Get 1st node in next non-emtoy row/node list */
    for( t->crow++; t->crow < t->nrows; t->crow++ )
    {    
       t->cnode = t->table[ t->crow ];
       if( t->cnode ) 
       {
           return t->cnode;
       }
    }

    return  NULL;
}

/* Internal use only */
static void sfghash_next( SFGHASH * t )
{
    if( !t->cnode )
        return ;
 
    /* Next node in current node list */
    t->cnode = t->cnode->next;
    if( t->cnode )
    {
        return;
    }

    /* Next row */ 
    /* Get 1st node in next non-emtoy row/node list */
    for( t->crow++; t->crow < t->nrows; t->crow++ )
    {    
       t->cnode = t->table[ t->crow ];
       if( t->cnode ) 
       {
           return;
       }
    }
}
/*
*   Get First Hash Table Node
*/
SFGHASH_NODE * sfghash_findfirst( SFGHASH * t )
{
    SFGHASH_NODE * n;

    /* Start with 1st row */
    for( t->crow=0; t->crow < t->nrows; t->crow++ )
    {    
       /* Get 1st Non-Null node in row list */
       t->cnode = t->table[ t->crow ];

       if( t->cnode )
       {
         n = t->cnode;

         sfghash_next( t ); // load t->cnode with the next entry

         return n;
       }
    }
  return NULL;
}

/*
*   Get Next Hash Table Node
*/
SFGHASH_NODE * sfghash_findnext( SFGHASH * t )
{
    SFGHASH_NODE * n;

    n = t->cnode;

    if( !n ) /* Done, no more entries */
    {
        return NULL;
    }

    /*
       Preload next node into current node 
    */
    sfghash_next( t ); 

    return  n;
}

/*
*
*
*   ATOM SUPPORT  - A Global String+DataPtr Hash Table
*
*   Data Pointers are not free'd automatically, the user
*   must do this.
*/
/*
*   
*/
static SFGHASH * g_atom=0;       /* atom hash table */
static int       atom_first=1; /* supports auto init on 1st add_atom call */
static int       natoms=1000;  /* # rows in hash table - more makes it faster access */

/*
*   set size of atom hash table
*/
int sfatom_setsize( int n )
{
    natoms = n;
    return 0;
}
/*
*   
*/
int sfatom_init()
{
   if( !atom_first ) return 0;

   /* Create a Hash Table */
   g_atom = sfghash_new( natoms, 0 /* string keys */, GH_COPYKEYS, NULL /* User frees data */ );

   if( !g_atom  )
   {
       return SFGHASH_ERR;
   }

   atom_first = 0;

   return SFGHASH_OK;
}
/*
*
*/
int sfatom_reset()
{
    atom_first = 1;

    sfghash_delete( g_atom );

    if( sfatom_init() )
    {
      return SFGHASH_ERR;
    }

    return SFGHASH_OK;
}
/*
*
*/
int sfatom_add(char * str, void * data)
{
   if( atom_first )
   { 
      if( sfatom_init() )
      {
         return SFGHASH_ERR;
      }
    }

    if( !g_atom ) 
    {
        return SFGHASH_ERR;
    }

    sfghash_add( g_atom, strdup(str), data );

    return SFGHASH_OK;
}
/*
*
*/
int sfatom_remove(char * str)
{
    return sfghash_remove( g_atom, str );
}
/*
*
*/
void * sfatom_find(char * str)
{
    return (void*) sfghash_find( g_atom, str );
}
/*
*
*/
int sfatom_count()
{
    return g_atom->count;
}
/*
*
*/
SFGHASH_NODE * sfatom_findfirst()
{
   SFGHASH_NODE * node = sfghash_findfirst( g_atom );

   if( node ) return node;

   return NULL;
}
/*
*
*/
SFGHASH_NODE * sfatom_findnext()
{
   SFGHASH_NODE * node = sfghash_findnext( g_atom );

   if( node ) return node;

   return NULL;
}


/*
*
*   Test Driver for Hashing
*  
*/

#ifdef SFGHASH_MAIN 

void myfree ( void * p )
{
	printf("freeing '%s'\n",p);
	free(p);
}

/*
*       Hash test program  
*/
int main ( int argc, char ** argv )
{
   int         i;
   SFGHASH      * t;
   SFGHASH_NODE * n, *m;
   char str[256],*p;
   int  num=100;

   if( argc > 1 )
       num = atoi(argv[1]);

   sfatom_init();

   /* Create a Hash Table */
   t = sfghash_new( 1000, 0 , GH_COPYKEYS , myfree  );

   /* Add Nodes to the Hash Table */
   for(i=0;i<num;i++) 
   {
       sprintf(str,"KeyWord%d",i+1);
       sfghash_add( t, str,  strupr(strdup(str)) );

       sfatom_add( str,  strupr(strdup(str)) );
   }  

   /* Find and Display Nodes in the Hash Table */
   printf("\n** FIND KEY TEST\n");

   for(i=0;i<num;i++) 
   {
      sprintf(str,"KeyWord%d",i+1);

      p = (char*) sfghash_find( t, str );

      printf("Hash-key=%*s, data=%*s\n", strlen(str),str, strlen(str), p );

      p = (char*) sfatom_find( str );

      printf("Atom-key=%*s, data=%*s\n", strlen(str),str, strlen(str), p );
   }  

   /* Display All Nodes in the Hash Table */
   printf("\n** FINDFIRST / FINDNEXT TEST\n");

   for( n = sfghash_findfirst(t); n; n = sfghash_findnext(t) )
   {
      printf("hash-findfirst/next: key=%s, data=%s\n", n->key, n->data );

      // hashing code frees user data using 'myfree' above ....
      if( sfghash_remove(t,n->key) ) 
            printf("Could not remove the key node\n");
      else  
            printf("key node removed\n");
   }

   for( n = sfatom_findfirst(); n; n = sfatom_findnext() )
   {
      printf("atom-findfirst/next: key=%s, data=%s\n", n->key, n->data );

      free( n->data );  //since atom data is not freed automatically
   }

   /* Free the table and it's user data */
   printf("****sfghash_delete\n");
   sfghash_delete( t );

   printf("****sfatom_reset\n");
   sfatom_reset();

   printf("\nnormal pgm finish\n\n");

   return 0;
}



#endif


