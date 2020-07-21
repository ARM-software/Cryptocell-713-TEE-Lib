/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef _TEST_PROJ_MAP_H_
#define _TEST_PROJ_MAP_H_

/****************************************************************************/
/*   							External API  								*/
/*
 * @brief This function Maps the proj HW.
 *  map the REE CC HW base, to write to some registers to enable TEE work
 *
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return rc - 0 for success, 1 for failure.
 */
int Test_ProjReeMap(void);

/****************************************************************************/
/*
 * @brief This function unmaps the proj HW.
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return none.
 */
void Test_ProjReeUnmap(void);

/****************************************************************************/
/*
 * @brief This function Maps the proj HW.
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return rc - 0 for success, 1 for failure.
 */
int Test_ProjTeeMap(void);

/****************************************************************************/
/*
 * @brief This function unmaps the proj HW.
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return none.
 */
void Test_ProjTeeUnmap(void);



#endif /* _TEST_PROJ_MAP_H_ */
