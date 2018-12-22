#ifndef BC_MISC_H__
#define BC_MISC_H__

#include <stdio.h>
#include <stdint.h>
#include <string.h>


/**************************************************************************
 * macros
 **************************************************************************/

#define CALLOC      calloc
#define REALLOC     realloc
#define MALLOC      malloc
#define FREE        free
#define MEMCPY      memcpy
#define MEMSET      memset
#define MEMCMP      memcmp
#define STRCPY      strcpy
#define STRCMP      strcmp
#define STRLEN      strlen

#define ARRAY_SIZE(a)       (sizeof(a) / sizeof(a[0]))

#endif /* BC_MISC_H__ */
