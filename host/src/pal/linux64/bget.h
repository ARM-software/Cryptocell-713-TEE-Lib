
/*

    Interface definitions for bget.c, the memory management package.

*/

#ifndef _
#ifdef PROTOTYPES
#define  _(x)  x		      /* If compiler knows prototypes */
#else
#define  _(x)  ()                     /* It it doesn't */
#endif /* PROTOTYPES */
#endif

typedef long bufsize;
void	bpool(void *buffer, bufsize len);
void   *bget(bufsize size);
void   *bgetz(bufsize size);
void	brel(void *buf);
