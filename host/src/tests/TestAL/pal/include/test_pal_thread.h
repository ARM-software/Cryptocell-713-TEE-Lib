/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 *
 */

#ifndef TEST_PAL_THREAD_H_
#define TEST_PAL_THREAD_H_

/*!
 @file
 @brief This file contains the PAL thread integration tests.
 */

/*!
 @addtogroup pal_thread_test
 @{
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *ThreadHandle; /*! Thread handle */

/******************************************************************************/
/*!
 * @brief This function returns the minimal stack size in bytes.
 *
 *
 * @return Minimal stack size in bytes.
 */
size_t Test_PalGetMinimalStackSize(void);

/******************************************************************************/
/*!
 * @brief This function returns the highest thread priority.
 *
 *
 * @return Highest thread priority.
 */
uint32_t Test_PalGetHighestPriority(void);

/******************************************************************************/
/*!
 * @brief This function returns the lowest thread priority.
 *
 *
 * @return Lowest thread priority.
 */
uint32_t Test_PalGetLowestPriority(void);

/******************************************************************************/
/*!
 * @brief This function returns the default thread priority.
 *
 *
 * @return Default thread priority.
 */
uint32_t Test_PalGetDefaultPriority(void);

/******************************************************************************/
/*!
 * @brief This function creates a thread. The user should call
 * Test_PalThreadJoin() in order to wait until the thread ends and then to
 * Test_PalThreadDestroy() in order to free resources.
 * In case of a thread without an end, the user should not call
 * Test_PalThreadJoin() which will not return. Instead, the user should call
 * Test_PalThreadDestroy() which will cancel the thread and free
 * its resources.
 *
 *
 * @return Thread handle address on success
 * @return NULL on failure.
 */
ThreadHandle Test_PalThreadCreate(
 /*! Thread stack size in bytes. The allocated stack size
 is greater from stackSize and the minimal stack size. */
 size_t stackSize,
 /*! Thread function. The function returns
 a pointer to the returned value or NULL. If TZM is supported,
 this function must have the same security attribute as TestAL (either Secure
 or Non-secure). */
 void *(*threadFunc)(void *),
 /*! Thread priority. Highest and lowest priorities can be
 received by calling Test_PalGetLowestPriority() and
 Test_PalGetHighestPriority() accordingly. */
 int priority,
 /*! Function input arguments. */
 void *args,
 /*! Thread name. Not in use for Linux. */
 const char *threadName,
 /*! Thread name length. Not in use for Linux. */
 uint8_t nameLen,
 /*! Determines whether the stack should be DMA-able (true). */
 uint8_t dmaAble
);

/******************************************************************************/
/*!
 * @brief This function waits for a thread to terminate (BLOCKING).
 * If that thread has already terminated it returns immediately.
 *
 *
 * \note Note that threadRet is not changed, yet \c threadRet is changed and
 * can be NULL. Therefore, do not try to access \c threadRet without
 * checking that \c threadRet is not NULL.
 *
 *
 * @return 0 on success
 * @return 1 on failure.
 */
uint32_t Test_PalThreadJoin(
 /*! Thread structure. */
 ThreadHandle threadHandle,
 /*! A pointer to the returned value of the target thread. */
 void **threadRet
);

/******************************************************************************/
/*!
 * @brief This function destroys a thread (if it is still running) and frees
 * its resources.
 * In order to free thread resources only after thread's end this function
 * should be called after Test_PalThreadJoin().
 * In order to cancel the thread immediately and free its resources, this
 * function should be called alone (without Test_PalThreadJoin()), which
 * must eventually be called in any case.
 *
 *
 * \note This function does not deallocate the memory that the
 * thread itself allocates. This must be done by the thread itself.
 *
 *
 * @return 0 on success.
 * @return 1 on failure.
 */
uint32_t Test_PalThreadDestroy(
 /*! Thread structure. */
 ThreadHandle threadHandle
);

#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif /* TEST_PAL_THREAD_H_ */
