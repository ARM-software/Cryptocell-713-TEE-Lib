/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_INFRA

#include "hw_queue.h"
#include "cc_plat.h"

#ifdef HW_DESC_DUMP_HOST_BUF
#define HOST_DESC_BUF_ADDRESS     0x10000000
#define HOST_DESC_BUF_SIZE     0x10000000
uint8_t *pDescDumpHostBuf = (uint8_t *)HOST_DESC_BUF_ADDRESS;
#endif

#define QUEUE_LOG_SIZE  (16)

int queue_log[HW_DESC_SIZE_WORDS * QUEUE_LOG_SIZE];
int queue_log_index;

typedef enum _debug_mode_type {
    TYPE_UNKNOWN = 0,
    TYPE_AES = 1,
    TYPE_DES = 2,
    TYPE_C2 = 3,
    TYPE_HASH = 4,
    TYPE_AES_MAC = 5,
    TYPE_COMBINED = 6
} debug_mode_type;

typedef struct _debug_mode_data {
    char *str;
    debug_mode_type type;
} debug_data;

debug_data g_debug_mode[] = {
    {"BYPASS",                          TYPE_UNKNOWN},
    {"DIN-AES-DOUT ",                   TYPE_AES},
    {"AES-to-HASH ",                    TYPE_COMBINED},
    {"AES-and-HASH  ",                  TYPE_COMBINED},
    {"DIN-DES-DOUT",                    TYPE_DES},
    {"DES-to-HASH",                     TYPE_UNKNOWN},
    {"DES-and-HASH",                    TYPE_UNKNOWN},
    {"DIN-HASH",                        TYPE_HASH},
    {"DIN-HASH-and-BYPASS",             TYPE_HASH},
    {"AES-MAC-and-BYPASS",              TYPE_AES_MAC},
    {"AES-to-HASH-and -DOUT",           TYPE_UNKNOWN},
    {"DIN-RC4-DOUT",                    TYPE_UNKNOWN},
    {"DES-to-HASH-and -DOUT",           TYPE_UNKNOWN},
    {"AES-to-AES-to-HASH-and DOUT",     TYPE_UNKNOWN},
    {"AES-to-AES-to-HASH",              TYPE_UNKNOWN},
    {"AES-to-HASH-and-AES",             TYPE_UNKNOWN},
    {"DIN-C2-DOUT.",                    TYPE_C2},
    {"DIN-AES-AESMAC",                  TYPE_UNKNOWN},
    {"HASH-to-DOUT",                    TYPE_HASH},
    {NULL,                              TYPE_UNKNOWN},
    {NULL,                              TYPE_UNKNOWN},
    {NULL,                              TYPE_UNKNOWN},
    {NULL,                              TYPE_UNKNOWN},
    {NULL,                              TYPE_UNKNOWN},
    {NULL,                              TYPE_UNKNOWN},
    {NULL,                              TYPE_UNKNOWN},
    {NULL,                              TYPE_UNKNOWN},
    {NULL,                              TYPE_UNKNOWN},
    {NULL,                              TYPE_UNKNOWN},
    {NULL,                              TYPE_UNKNOWN},
    {NULL,                              TYPE_UNKNOWN},
    {NULL,                              TYPE_UNKNOWN},
    {"S_DIN-to AES",                    TYPE_AES},
    {"S_DIN-to_AES2",                   TYPE_AES},
    {"S_DIN-to-DES.",                   TYPE_DES},
    {"S_DIN-to-RC4.",                   TYPE_UNKNOWN},
    {"S_DIN-to-C2.",                    TYPE_C2},
    {"S_Din-to-HASH",                   TYPE_HASH},
    {"S_AES-to-DOUT.",                  TYPE_AES},
    {"S_AES2-to-DOUT",                  TYPE_AES},
    {"S_C2-to-DOUT.",                   TYPE_C2},
    {"S_RC4-to-DOUT.",                  TYPE_UNKNOWN},
    {"S_DES-to-DOUT",                   TYPE_DES},
    {"S_HASH_to_DOUT",                  TYPE_HASH},
    {"SET-FLOW-ID. ",                   TYPE_UNKNOWN}
};

int createDetailedDump(HwDesc_s *pDesc)
{
#if defined(UART_PRINTF) || defined(HOST_PRINTF)
    unsigned int DinDmaMode = CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, DIN_DMA_MODE, (pDesc)->word[1]);
    unsigned int DoutDmaMode = CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, DIN_DMA_MODE, (pDesc)->word[3]);
    unsigned int DinConst = CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, DIN_CONST_VALUE, (pDesc)->word[1]);
    unsigned int DataFlowMode = CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD4, DATA_FLOW_MODE, (pDesc)->word[4]);
    unsigned int CipherDo = CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD4, CIPHER_DO, (pDesc)->word[4]);
    unsigned int CipherMode = CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD4, CIPHER_MODE, (pDesc)->word[4]);
    unsigned int AckNeeded = CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD4, ACK_NEEDED, (pDesc)->word[4]);
    unsigned int setupOp = CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD4, SETUP_OPERATION, (pDesc)->word[4]);
    static int descCount = 0;

    PRINTF("Desc #%d: ", descCount++);
    if (AckNeeded)
    PRINTF("COMPLETION (id = %d)\n", AckNeeded);
    else
    PRINTF("FlowMode = %s %s\n", g_debug_mode[DataFlowMode].str == NULL?"":g_debug_mode[DataFlowMode].str,
                    setupOp?"(SETUP)":"(DATA)");

    PRINTF("DIN:\t %s = 0x%08X  ",DinConst?"Const":"Addr",(int)pDesc->word[0]);
    PRINTF("Size = %u  ",(int)CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, DIN_SIZE, (pDesc)->word[1]));
    switch (DinDmaMode)
    {
        case NO_DMA:
        PRINTF("NO DMA");
        break;
        case DMA_SRAM:
        PRINTF("SRAM");
        break;
        case DMA_DLLI:
        PRINTF("DLLI");
        break;
        case DMA_MLLI:
        PRINTF("MLLI");
        break;
    }
    PRINTF("\n");
    PRINTF("\t NS bit = %lu  ", CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, NS_BIT, (pDesc)->word[1]));
    PRINTF("AXI ID = %lu  ", CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, DIN_VIRTUAL_HOST, (pDesc)->word[1]));
    PRINTF("NotLast = %lu  ", CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, NOT_LAST, (pDesc)->word[1]));
    PRINTF("Lock Q = %lu  ", CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, LOCK_QUEUE, (pDesc)->word[1]));
    PRINTF("Const = %u\n", DinConst);

    PRINTF("DOUT:\t Addr = 0x%08X  ",(int)pDesc->word[2]);
    PRINTF("Size = %lu  ", CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD3, DOUT_SIZE, (pDesc)->word[3]));
    switch (DoutDmaMode)
    {
        case NO_DMA:
        PRINTF("NO DMA");
        break;
        case DMA_SRAM:
        PRINTF("SRAM");
        break;
        case DMA_DLLI:
        PRINTF("DLLI");
        break;
        case DMA_MLLI:
        PRINTF("MLLI");
        break;
    }
    PRINTF("\n");
    PRINTF("\t NS bit = %u  ",(int)CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD3, NS_BIT, (pDesc)->word[3]));
    PRINTF("AXI ID = %u  ",(int)CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD3, DOUT_VIRTUAL_HOST, (pDesc)->word[3]));
    PRINTF("DOUT Last = %u  ",(int)CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD3, DOUT_LAST_IND, (pDesc)->word[3]));

    if (g_debug_mode[DataFlowMode].type == TYPE_HASH) {
        PRINTF("CipherDo = %d %s ", CipherDo, CipherDo==1?"(DO_PAD)":"");
    } else {
        PRINTF("CipherDo = %d ", CipherDo);
    }
    //PRINTF("hash select = %u\n",CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD4, AES_HASH_SEL, (pDesc)->word[4]));
    PRINTF("Ack = %u\n",AckNeeded);
    PRINTF("Setup Op = %u  ",setupOp);
    PRINTF("Cipher Mode = %d  ", CipherMode);
    PRINTF("Keysize = %u\n",(int)CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD4, KEY_SIZE, (pDesc)->word[4]));
    PRINTF("conf0 = %u  ",(int)CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD4, CIPHER_CONF0, (pDesc)->word[4]));
    PRINTF("conf1 = %u  ",(int)CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD4, CIPHER_CONF1, (pDesc)->word[4]));
    PRINTF("conf2 = %u  \n",(int)CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD4, CIPHER_CONF2, (pDesc)->word[4]));
    PRINTF("XOR KEY = %u  ",(int)CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD4, AES_XOR_CRYPTO_KEY, (pDesc)->word[4]));
    PRINTF("CMAC S0 = %u\n",(int)CC_REG_FLD_GET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD4, CMAC_SIZE0, (pDesc)->word[4]));

    PRINTF("\t");
#endif
    return 0;
}

#ifdef HW_DESC_DUMP_HOST_BUF
void descriptor_log(HwDesc_s *desc)
{
    CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(0), desc);
    CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(1), (sizeof(HwDesc_s) << 2)|1);
    CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(2), pDescDumpHostBuf);
    CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(3), (sizeof(HwDesc_s) << 2)|2);
    CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(4), 0);
    CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(5), 0);
    pDescDumpHostBuf += sizeof(HwDesc_s);
    if ( pDescDumpHostBuf >= HOST_DESC_BUF_ADDRESS+HOST_DESC_BUF_SIZE-sizeof(HwDesc_s) ) {
        pDescDumpHostBuf = HOST_DESC_BUF_ADDRESS;
    }
    HW_QUEUE_POLL_QUEUE_UNTIL_FREE_SLOTS(1);
}
#else
void descriptor_log(HwDesc_s *desc)
{
    queue_log[queue_log_index * HW_DESC_SIZE_WORDS + 0] = desc->word[0];
    queue_log[queue_log_index * HW_DESC_SIZE_WORDS + 1] = desc->word[1];
    queue_log[queue_log_index * HW_DESC_SIZE_WORDS + 2] = desc->word[2];
    queue_log[queue_log_index * HW_DESC_SIZE_WORDS + 3] = desc->word[3];
    queue_log[queue_log_index * HW_DESC_SIZE_WORDS + 4] = desc->word[4];
    queue_log[queue_log_index * HW_DESC_SIZE_WORDS + 5] = desc->word[5];

    queue_log_index++;
    queue_log_index &= (QUEUE_LOG_SIZE - 1);
}
#endif

