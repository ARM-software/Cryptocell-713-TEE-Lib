/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef VALIDATE_CC_BYPASS_H
#define VALIDATE_CC_BYPASS_H

/*!
 * validate DMA object structure
 *
 * \param dmaObj the DMA object
 * \param dataSize Data size given by the user (relevent only for SRAM data)
 *
 * \return 0 on success, (-1) if ( dataSize != dma object data size), (-2) if sram pointer is out of range
 */

int validateParams(uint8_t *data, uint32_t dataSize);

#endif
