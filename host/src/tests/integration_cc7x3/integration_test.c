/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>

#include "test_engine.h"
#include "menu_engine.h"
#include "test_pal_thread.h"

/******************************************************************
 * Defines
 ******************************************************************/
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)    (uint32_t)(sizeof(x)/sizeof(x[0]))
#endif

/******************************************************************
 * Types
 ******************************************************************/
typedef struct IntegrationTestEntry_t {
    const char *name;
    int (*regCallback)(void);
} IntegrationTestEntry_t;

typedef struct Args_t {
    int argc;
    char **argv;
    int res;
} Args_t;
/******************************************************************
 * Externs
 ******************************************************************/
LIB_INIT_EXERNS

/* Every flavour should implement these two functions to initiate the library and finalise it */
/* The definition should be placed in the file wrappers.c */
extern int TE_initHostLib(void);
extern void TE_finHostLib(void);

/******************************************************************
 * Globals
 ******************************************************************/
IntegrationTestEntry_t gIntegrationTests[] = { LIB_INIT_FUNCS };
Args_t gArgs;

/******************************************************************
 * Static Prototypes
 ******************************************************************/
static int TE_registerTests(void);

/******************************************************************
 * Static functions
 ******************************************************************/
static int TE_registerTests(void)
{
    TE_rc_t res = TE_RC_SUCCESS;
    uint32_t index;

    for (index = 0; index < ARRAY_SIZE(gIntegrationTests); ++index)
    {
        TE_ASSERT(gIntegrationTests[index].regCallback != NULL);
        TE_ASSERT_ERR(gIntegrationTests[index].regCallback(), 0, TE_RC_FAIL);
    }

bail:
	return res;
}

static void *executerFunc(void * ctx)
{
    Args_t *pArgs = (Args_t*) ctx;

    if (pArgs->argc == 1) {
        pArgs->res = TE_execute();
        TE_printTests();
    } else {
        pArgs->res = MENU_execute(pArgs->argc, pArgs->argv);
    }

    return NULL;
}
/******************************************************************
 * Public
 ******************************************************************/
int main(int argc, char** argv)
{
    TE_rc_t res = TE_RC_SUCCESS;
    ThreadHandle threadHandle = NULL;
    void *threadRet = NULL;

    const char* threadName = "executer";

    /* flavour specific initialisation of the test */
    TE_ASSERT(TE_initHostLib() == TE_RC_SUCCESS);

    /* init test engine library */
    TE_ASSERT(TE_initLib(MODULE_NAME, TE_NUM_OF_ITER) == TE_RC_SUCCESS);

    /* init menu engine library */
    TE_ASSERT(MENU_initLib() == MENU_RC_SUCCESS);

    TE_ASSERT(TE_registerTests() == TE_RC_SUCCESS);

    gArgs.argc = argc;
    gArgs.argv = argv;
    gArgs.res = 0;

    threadHandle = Test_PalThreadCreate(Test_PalGetMinimalStackSize(),
                                        executerFunc,
                                        Test_PalGetDefaultPriority(),
                                        &gArgs,
                                        threadName,
                                        strlen(threadName),
                                        true);
    TE_ASSERT(threadHandle != NULL);

    TE_ASSERT(Test_PalThreadJoin(threadHandle, threadRet) == 0);

    TE_ASSERT(Test_PalThreadDestroy(threadHandle) == 0);

    res = (gArgs.res == 0) ? TE_RC_SUCCESS : TE_RC_FAIL;

    TE_finilizeLib();

bail:

    MENU_finLib();
    TE_finHostLib();

    return res == TE_RC_SUCCESS ? 0 : 1;
}
