/**
**  @file       hi_hbm.c
**  
**  @author     Marc Norton <mnorton@sourcefire.com>
**  
**  @brief      Implementation of a Horspool method of Boyer-Moore
**  
*/

#include <stdlib.h>

#include "hi_util_hbm.h"

/*
*
*  Boyer-Moore-Horspool for small pattern groups
*    
*/
#ifndef WIN32  /* To avoid naming conflict, Win32 will use the hbm_prepx() in mwm.c */
HBM_STRUCT * hbm_prepx(HBM_STRUCT *p, unsigned char * pat, int m)
{
     int     k;

     if( !m ) return 0;
     if( !p ) return 0;


     p->P = pat;

     p->M = m;

     /* Compute normal Boyer-Moore Bad Character Shift */
     for(k = 0; k < 256; k++) p->bcShift[k] = m;
     for(k = 0; k < m; k++)   p->bcShift[pat[k]] = m - k - 1;

     return p;
}
#endif

/*
*
*/
#ifndef WIN32  /* To avoid naming conflict, Win32 will use the hbm_prep() in mwm.c */
HBM_STRUCT * hbm_prep(unsigned char * pat, int m)
{
     HBM_STRUCT    *p;

     p = (HBM_STRUCT*)malloc( sizeof(HBM_STRUCT) );
     if( !p ) return 0;

     return hbm_prepx( p, pat, m );
}
#endif

/*
*   Boyer-Moore Horspool
*   Does NOT use Sentinel Byte(s)
*   Scan and Match Loops are unrolled and separated
*   Optimized for 1 byte patterns as well
*/
unsigned char * hbm_match(HBM_STRUCT * px, unsigned char *text, int n)
{
  unsigned char *pat, *t, *et, *q;
  int            m1, k;
  short    *bcShift;

  m1     = px->M-1;
  pat    = px->P;
  bcShift= px->bcShift;

  t  = text + m1;  
  et = text + n; 

  /* Handle 1 Byte patterns - it's a faster loop */
  /*
  if( !m1 )
  {
    for( ;t<et; t++ ) 
      if( *t == *pat ) return t;
    return 0;
  }
  */
 
  /* Handle MultiByte Patterns */
  while( t < et )
  {
    /* Scan Loop - Bad Character Shift */
    do 
    {
      t += bcShift[*t];
      if( t >= et )return 0;;

      t += (k=bcShift[*t]);      
      if( t >= et )return 0;

    } while( k );

    /* Unrolled Match Loop */
    k = m1;
    q = t - m1;
    while( k >= 4 )
    {
      if( pat[k] != q[k] )goto NoMatch;  k--;
      if( pat[k] != q[k] )goto NoMatch;  k--;
      if( pat[k] != q[k] )goto NoMatch;  k--;
      if( pat[k] != q[k] )goto NoMatch;  k--;
    }
    /* Finish Match Loop */
    while( k >= 0 )
    {
      if( pat[k] != q[k] )goto NoMatch;  k--;
    }
    /* If matched - return 1st char of pattern in text */
    return q;

NoMatch:
    
    /* Shift by 1, this replaces the good suffix shift */
    t++; 
  }

  return 0;
}

