/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef TEST_ENGINE_H_
#define TEST_ENGINE_H_

#include "test_engine_helper.h"
#include "test_engine_log.h"
#include "test_engine_profiler.h"
#include "test_engine_types.h"

/**
 * Can be initialised only once.
 * Can be called again if TE_finilizeLib was called.
 *
 * @param pModuleName               can be freed after function returns.
 *                                  this value is copied and not stored.
 * @param numOfPrifilerIterations   number of iterations to perform in the profiler
 *
 * @return                          TE_RC_SUCCESS on success, TE_RC_FAIL otherwise
 */
TE_rc_t TE_initLib(const char *pModuleName, uint32_t numOfPrifilerIterations);

/**
 * Finalise the library. free memory and such.
 * After calling this function it is legitimate to call TE_initLib again if needed
 *
 * @return                          TE_RC_SUCCESS on success, TE_RC_FAIL otherwise
 */
TE_rc_t TE_finilizeLib(void);

/**
 * Adds a test of type flow to the test engine.
 *
 * @param pName                     name to be displayed in the results
 * @param pFeatureName              feature to be displayed in the results
 * @param pSubFeatureName           sub feature to be displayed in the results
 * @param prepareFunc               pointer to callback that will perform the preparation towards the test
 * @param execFlowFunc              pointer to callback that will perform the actual test
 * @param verifyFunc                pointer to callback that will perform the veification of the test result
 * @param cleanFunc                 pointer to callback that will perform the clean up after the test
 * @param pContext                  a pointer to the context object that will be passed between the callbacks.
 *
 * @return                          TE_RC_SUCCESS on success, TE_RC_FAIL otherwise
 */
TE_rc_t TE_registerFlow(const char *pName,
                        const char *pFeatureName,
                        const char *pSubFeatureName,
                        fPrepare prepareFunc,
                        fExecFlow execFlowFunc,
                        fVerify verifyFunc,
                        fClean cleanFunc,
                        void *pContext);

/**
 * Adds a test of type flow to the test engine.
 *
 * @param pName                     name to be displayed in the results
 * @param pFeatureName              feature to be displayed in the results
 * @param pSubFeatureName           sub feature to be displayed in the results
 * @param prepareFunc               pointer to callback that will perform the preparation towards the test
 * @param execSuiteFunc             pointer to callback that will perform the actual test
 * @param cleanFunc                 pointer to callback that will perform the clean up after the test
 * @param pTestVecList              a pointer to an array of vectors that will be iterated over using the callback
 *                                  execSuiteFunc.
 *
 *                                  for each vector in pTestVecList:
 *                                      execSuiteFunc (vector, &result)
 *
 * @return                          TE_RC_SUCCESS on success, TE_RC_FAIL otherwise
 */
TE_rc_t TE_registerSuite(const char *pName,
                         const char *pFeatureName,
                         const char *pSubFeatureName,
                         fPrepare prepareFunc,
                         fExecSuite execSuiteFunc,
                         fClean cleanFunc,
                         TE_TestVecList_t *pTestVecList);

/**
 * Trigger the execution of the engine
 *
 * @return                          TE_RC_SUCCESS on success, TE_RC_FAIL otherwise
 */
TE_rc_t TE_execute(void);

/**
 * Print the results.
 *
 * @return                          TE_RC_SUCCESS on success, TE_RC_FAIL otherwise
 */
TE_rc_t TE_printTests(void);

#endif /* TEST_ENGINE_H_ */
