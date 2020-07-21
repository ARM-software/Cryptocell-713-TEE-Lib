/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <stdio.h>
#include <stdint.h>
#include "test_engine.h"
#include "cc_util_backup_restore.h"
#include "cc_util.h"
#include "cc_rnd.h"
#include "te_backup_restore.h"

/******************************************************************
 * Defines
 ******************************************************************/

#define TE_BACKUP_RESTORE_SOURCE_SIZE_IN_BYTES          2000
#define TE_BACKUP_RESTORE_MAC_SIZE_IN_BYTES             16
#define TE_BACKUP_RESTORE_DEST_SIZE_IN_BYTES            TE_BACKUP_RESTORE_SOURCE_SIZE_IN_BYTES\
                                                            + TE_BACKUP_RESTORE_MAC_SIZE_IN_BYTES

/******************************************************************
 * Types
 ******************************************************************/

/******************************************************************
 * Externs
 ******************************************************************/

extern CCRndState_t* pRndState_proj;
extern CCRndGenerateVectWorkFunc_t pRndFunc_proj;

/******************************************************************
 * Globals
 ******************************************************************/

static uint32_t backupBuff[TE_BACKUP_RESTORE_SOURCE_SIZE_IN_BYTES] = { 0x0 };
static uint32_t compBuff[TE_BACKUP_RESTORE_SOURCE_SIZE_IN_BYTES] = { 0xA5 };
static uint32_t restoreBuff[TE_BACKUP_RESTORE_DEST_SIZE_IN_BYTES] = { 0x0 };

/******************************************************************
 * Static Prototypes
 ******************************************************************/

static TE_rc_t backup_restore_exec(void* pContext);

/******************************************************************
 * Static functions
 ******************************************************************/

static TE_rc_t backup_restore_exec(void* pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_perfIndex_t cookie = 0;
    uint8_t *pSrcBuff = (uint8_t *) backupBuff;
    uint8_t *pCmpBuff = (uint8_t *) compBuff;
    uint8_t *pDstBuff = (uint8_t *) restoreBuff;
    TE_UNUSED(pContext);

    /* Set the session key */
    /*---------------------*/
    cookie = TE_perfOpenNewEntry("backup-restore", "set-session-key");
    TE_ASSERT(CC_UtilSetSessionKey(pRndFunc_proj, pRndState_proj) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Backup */
    /*--------*/
    cookie = TE_perfOpenNewEntry("backup-restore", "backup");
    TE_ASSERT(CC_UTIL_RAM_BACKUP(pSrcBuff,
                                 pDstBuff,
                                 TE_BACKUP_RESTORE_SOURCE_SIZE_IN_BYTES) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Restore */
    /*---------*/
    cookie = TE_perfOpenNewEntry("backup-restore", "restore");
    TE_ASSERT(CC_UTIL_RAM_RESTORE(pDstBuff,
                                  pCmpBuff,
                                  TE_BACKUP_RESTORE_SOURCE_SIZE_IN_BYTES) == CC_OK);
    TE_perfCloseEntry(cookie);

    /* Compare source and comparison buffers, should be equal */
    /*---------------------------------------------------*/
    TE_ASSERT(memcmp(pSrcBuff, pCmpBuff, TE_BACKUP_RESTORE_SOURCE_SIZE_IN_BYTES) == 0);

bail:
    return res;
}

/******************************************************************
 * Public
 ******************************************************************/

int TE_init_backup_restore_test(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_perfEntryInit("backup-restore", "set-session-key");
    TE_perfEntryInit("backup-restore", "backup");
    TE_perfEntryInit("backup-restore", "restore");

    TE_ASSERT(TE_registerFlow("backup-restore",
                              "",
                              "",
                              NULL,
                              backup_restore_exec,
                              NULL,
                              NULL,
                              NULL) == TE_RC_SUCCESS);

bail:
	return res;
}
