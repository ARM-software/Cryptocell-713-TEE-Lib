/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <string.h>
#include <stdbool.h>

#include "test_pal_thread.h"
#include "test_proj_common.h"
#include "tests_log.h"

#define LINUX_MIN_THREAD_STACK_SIZE (1024 * 1024)
/*
 * Tests_Runthread
 * Run a function in a thread.
 * threadFunc [in]- function to run
 * args [in] - arguments to the function
 *
 * return value is -1 if thread creation, join, or destruction didn't work,
 * otherwise - value returned from running the function threadFunc.
 *
 * */
int Tests_Runthread(void *(*threadFunc)(void *), void *args)
{

    int threadRc;
    ThreadHandle threadHandle;
    uint32_t rc = 0;

    threadHandle = Test_PalThreadCreate(LINUX_MIN_THREAD_STACK_SIZE,
                                        threadFunc,
                                        Test_PalGetDefaultPriority(),
                                        args,
                                        NULL,
                                        0,
                                        true);
    if (threadHandle == NULL) {
        TEST_LOG_ERROR("Test_PalThreadCreate failed\n");
        return -1;
    }
    threadRc = Test_PalThreadJoin(threadHandle, (void *) &rc);
    if (threadRc != 0) {
        TEST_LOG_ERROR("Test_PalThreadJoin failed\n");
        return -1;
    }

    threadRc = Test_PalThreadDestroy(threadHandle);
    if (threadRc != 0) {
        TEST_LOG_ERROR("Test_PalThreadDestroy failed\n");
        rc = -1;
    }

    TEST_LOG_TRACE("Finished running thread. Returned rc = %d\n", rc);

    return rc;
}
