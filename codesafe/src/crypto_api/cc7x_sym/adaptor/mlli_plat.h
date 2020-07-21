/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef  MLLI_PLAT_H
#define  MLLI_PLAT_H

/******************************************************************************
 *				DEFINITIONS
 ******************************************************************************/
/*!
 * indexes of logical tables in the MLLI buffer
 */
typedef enum MLLI_table_t {
    MLLI_TABLE_1, /*!< MLLI_TABLE_1 */
    MLLI_TABLE_2, /*!< MLLI_TABLE_2 */
} MLLI_table_t;

/******************************************************************************
 *				TYPE DEFINITIONS
 ******************************************************************************/
#define MLLI_getIsMlliExternalAlloc() 0

/******************************************************************************
 *				FUNCTION PROTOTYPES
 ******************************************************************************/

/*!
 * \brief Returns the head of one of possible tables in MLLI buffer.
 *
 * \param tableIndex        index of the table to return
 * \return CCSramAddr_t.
 */
CCSramAddr_t MLLI_getWorkspace(MLLI_table_t tableIndex);

#endif /*MLLI_PLAT_H*/

