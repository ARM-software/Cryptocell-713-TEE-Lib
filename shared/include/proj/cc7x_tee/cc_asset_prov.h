/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _CC_ASSET_PROV_H
#define  _CC_ASSET_PROV_H

#ifdef __cplusplus
extern "C"
{
#endif
#include "cc_pal_types.h"

#define ASSET_PROV_TOKEN                      0x20052001
#define ASSET_PROV_VERSION                    0x00000002

#define CC_ASSET_PROV_NONCE_SIZE              12
#define CC_ASSET_PROV_TAG_SIZE                16
#define CC_ASSET_PROV_BLOCK_SIZE              16
#define CC_ASSET_PROV_MAX_ASSET_SIZE          (4 * CC_1K_SIZE_IN_BYTES)
#define CC_ASSET_PROV_ADATA_SIZE              (4 * CC_32BIT_WORD_SIZE)  // token||version||assetSize||assetId

typedef struct {
    uint32_t token;
    uint32_t version;
    uint32_t assetSize;
    uint32_t assetId;
    uint8_t nonce[CC_ASSET_PROV_NONCE_SIZE];
    uint8_t encAsset[CC_ASSET_PROV_MAX_ASSET_SIZE + CC_ASSET_PROV_TAG_SIZE];
} CCAssetProv_t;

#ifdef __cplusplus
}
#endif

#endif /*_CC_ASSET_PROV_H */
