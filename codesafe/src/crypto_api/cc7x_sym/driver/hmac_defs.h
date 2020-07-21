/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  _HMAC_DEFS_H__
#define  _HMAC_DEFS_H__

/* this files provides definitions required for HMAC engine drivers */
#define HMAC_DECRYPTED_OPAD_CONST_BLOCK 0x601D1102, 0xAD34E4AA, 0xB9351FAA, 0xD7356DF1
#define HMAC_DECRYPTED_IPAD_CONST_BLOCK 0xA8473C7E, 0x2AE67627, 0x50ADFC61, 0xEE6F3117

#define AES_CTR_NO_COUNTER_INC_REG_ADDR    0x4D8

#endif /*_HMAC_DEFS_H__*/

