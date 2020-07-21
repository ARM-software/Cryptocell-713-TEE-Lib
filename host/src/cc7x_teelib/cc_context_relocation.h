/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

/*! \file cc_context_relocation.h
 * Handle relocation of crypto context in the context buffer given
 * by the user to assure it does not cross a page boundary
 */

#ifndef _CC_CONTEXT_RELOCATION_H_
#define _CC_CONTEXT_RELOCATION_H_

#define CC_CTX_BUFF_PROPS_SIZE_BYTES	12

/*!
 * Initialize the context offset for a new buffer given to INIT phase
 *
 * \param bufferStart The address of the context buffer given by the user
 * \param bufferSize The size of the user buffer in bytes
 * \param contextSize The required size (in bytes) of the context
 *
 * \return The address of the context within the buffer
 */
void *RcInitUserCtxLocation(void *bufferStart, unsigned long bufferSize, unsigned long contextSize);

/*!
 * Return the context address in the given buffer
 * If previous context offset is now crossing a page the context data
 * would be moved to a good location.
 *
 * \param bufferStart The address of the context buffer given by the user
 *
 * \return The address of the context within the buffer
 */
void *RcGetUserCtxLocation(void *bufferStart);

#endif /*_CC_CONTEXT_RELOCATION_H_*/
