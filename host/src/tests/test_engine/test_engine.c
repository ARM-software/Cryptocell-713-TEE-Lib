/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "test_engine.h"

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

/****************************************************************************
 *
 * defines
 *
 ****************************************************************************/
/** maximum allowed test in a single list */
#define TE_NUM_OF_ITERATIONS       10

/** maximum length of the names stored in each test */
#define TE_NAME_LEN                20
#define TE_PRINT_ONLY_FAILED_VEC   1
/****************************************************************************
 *
 * Types
 *
 ****************************************************************************/
/** the stages of every test */
typedef enum TE_stage_t {
    PREPARE,
    EXECUTE,
    VERIFY,
    CLEAN,
    DONE,
} TE_stage_t;

/** tests type */
typedef enum TE_TestType_t {
    TE_TEST_TYPE_SUITE,
    TE_TEST_TYPE_FLOW,
    TE_TEST_TYPE_MAX
} TE_TestType_t;

/** test suite data */
typedef struct TE_TestSuite_t {
    /** function callbacks */
    fPrepare prepareFunc;
    fExecSuite execSuiteFunc;
    fVerify verifyFunc;
    fClean cleanFunc;

    /** array of vectors */
    TE_TestVecList_t *pTestVec;

    /** array of verctor results */
    TE_TestRc_t *pResults;
} TE_TestSuite_t;

/** test flow data */
typedef struct TE_TestFlow_t {
    /** function callbacks */
    fPrepare prepareFunc;
    fExecFlow execFlowFunc;
    fVerify verifyFunc;
    fClean cleanFunc;

    /** pointer to the context the test will pass to the callbacks */
    void *pContext;
} TE_TestFlow_t;

/** aunion of both test type structs */
typedef union TE_TestInstance_t {
    TE_TestFlow_t testFlow;
    TE_TestSuite_t testSuite;
} TE_TestInstance_t;

/** a single test entry */
typedef struct TE_TestData_t {
    /** feature identification */
    char name[TE_NAME_LEN];
    char featureName[TE_NAME_LEN];
    char subFeatureName[TE_NAME_LEN];

    /** callbacks */
    TE_TestType_t testType;
    TE_TestInstance_t testInst;

    /** result saved to be displayed later */
    TE_rc_t result;
    TE_stage_t failStage;

    /** pointer to the next item in the list */
    struct TE_TestData_t *next;
} TE_TestData_t;

/** used internally to manage the tests and the core engine's state */
typedef struct TE_coreMgmt_t {

    /** a list of the registered tests */
    TE_TestData_t *listOfTests;

    /** pointer to the tail of the list */
    TE_TestData_t *lastTest;

    /** number of iteration to perform to achieve sufficient profiling accuracy */
    uint32_t numOfProfilerIterations;

    /** number of registered tests */
    size_t numOfTests;

    /** a flag inidicating that the library was initiated */
    bool isLibInited;

    /** the name of the project (slim/703/713) */
    char moduleName[TE_NAME_LEN];

} TE_coreMgmt_t;


/****************************************************************************
 *
 * globals
 *
 ****************************************************************************/
/** Initialise the core management variables */
static TE_coreMgmt_t gCoreMgmt = { .listOfTests = NULL, .lastTest = NULL,
    .numOfProfilerIterations = TE_NUM_OF_ITERATIONS, .numOfTests = 0, .isLibInited = false,
    .moduleName = { 0 } };

/****************************************************************************
 *
 * static prototypes
 *
 ****************************************************************************/
static TE_rc_t TE_registerCommon(const char *pName,
                                 const char *pFeatureName,
                                 const char *pSubFeatureName,
                                 TE_TestData_t **poTestToAdd);
static const char *TE_getStageStr(TE_stage_t stage);
static TE_rc_t TE_executeTestInstance(TE_TestData_t *pTestData);
static void TE_printSectionHeader(size_t len, const char *format, ...);
static void TE_printSectionFooter(size_t len, const char *format, ...);
static TE_rc_t TE_printTestFlows(void);
static TE_rc_t TE_printTestSuites(void);
/****************************************************************************
 *
 * static functions
 *
 ****************************************************************************/
/**
 * This function should be called after the library was initialised, and before it was finalised
 *
 * @param pName
 * @param pFeatureName
 * @param pSubFeatureName
 * @param prepareFunc       can be NULL
 * @param testFunc          should not be NULL
 * @param cleanFunc         can be NULL
 * @param pContext
 *
 * @return                  TE_rc_t
 */
static TE_rc_t TE_registerCommon(const char *pName,
                                 const char *pFeatureName,
                                 const char *pSubFeatureName,
                                 TE_TestData_t **poTestToAdd)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_TestData_t *pTestToAdd = NULL;

    TE_LOG_TRACE("registering test %s\n", pName);

    TE_ASSERT(gCoreMgmt.isLibInited == true);

    TE_ASSERT(pName != NULL);
    TE_ASSERT(pFeatureName != NULL);
    TE_ASSERT(pSubFeatureName != NULL);

    TE_ALLOC(pTestToAdd, sizeof(*pTestToAdd));

    /* set last test ptr */
    if (gCoreMgmt.lastTest != NULL && gCoreMgmt.numOfTests > 0)
        gCoreMgmt.lastTest->next = pTestToAdd;
    else
        gCoreMgmt.listOfTests = pTestToAdd;

    strncpy(pTestToAdd->name, pName, TE_NAME_LEN - 1);
    strncpy(pTestToAdd->featureName, pFeatureName, TE_NAME_LEN - 1);
    strncpy(pTestToAdd->subFeatureName, pSubFeatureName, TE_NAME_LEN - 1);
    pTestToAdd->next = NULL;

    gCoreMgmt.lastTest = pTestToAdd;
    gCoreMgmt.numOfTests++;

    TE_LOG_TRACE("core listOfTests[%p] lastTest[%p] numOfTests[%zu] isLibInited[%u] moduleName[%s]\n",
                 gCoreMgmt.listOfTests,
                 gCoreMgmt.lastTest,
                 gCoreMgmt.numOfTests,
                 gCoreMgmt.isLibInited,
                 gCoreMgmt.moduleName);

    *poTestToAdd = pTestToAdd;

bail:
    return res;
}

static const char *TE_getStageStr(TE_stage_t stage)
{
    switch (stage)
    {
        case PREPARE:
            return "prepare";
        case EXECUTE:
            return "execute";
        case VERIFY:
            return "verify";
        case CLEAN:
            return "cleanup";
        case DONE:
            return "";
        default:
            return "unknown";
    }
}

static TE_rc_t TE_executeTestInstance(TE_TestData_t *pTestData)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_TestInstance_t *pTestInst = &pTestData->testInst;

    TE_ASSERT(pTestData->testType < TE_TEST_TYPE_MAX);

    if (pTestData->testType == TE_TEST_TYPE_FLOW)
    {
        TE_TestFlow_t *pTestFlow = &pTestInst->testFlow;

        pTestData->failStage = PREPARE;
        if (pTestFlow->prepareFunc)
            if ((res = pTestFlow->prepareFunc(pTestFlow->pContext)) != TE_RC_SUCCESS)
                goto bail;

        pTestData->failStage = EXECUTE;
        if ((res = pTestFlow->execFlowFunc(pTestFlow->pContext)) != TE_RC_SUCCESS)
            goto bail;

        pTestData->failStage = VERIFY;
        if (pTestFlow->verifyFunc)
            if ((res = pTestFlow->verifyFunc(pTestFlow->pContext)) != TE_RC_SUCCESS)
                goto bail;

        pTestData->failStage = CLEAN;
        if (pTestFlow->cleanFunc)
            if ((res = pTestFlow->cleanFunc(pTestFlow->pContext)) != TE_RC_SUCCESS)
                goto bail;
    }
    else
    {
        TE_TestSuite_t *pTestSuite = &pTestInst->testSuite;
        uint32_t index;

        pTestData->failStage = PREPARE;
        if (pTestSuite->prepareFunc)
            if ((res = pTestSuite->prepareFunc(NULL)) != TE_RC_SUCCESS)
                goto bail;

        pTestData->failStage = EXECUTE;
        for (index = 0; index < pTestSuite->pTestVec->count; index++)
        {
            TE_TestVec_t *pVector = &pTestSuite->pTestVec->pData[index];
            const char *pVectorName = pTestSuite->pTestVec->pData[index].name;
            TE_rc_t *pVecResult = &pTestSuite->pResults[index];

            TE_LOG_TRACE("testing name[%s] feature[%s] sunFeature[%s] vector[%s]\n",
                         pTestData->name,
                         pTestData->featureName,
                         pTestData->subFeatureName,
                         pVectorName);

            pTestSuite->execSuiteFunc(pVector, pVecResult);
            if (*pVecResult != TE_RC_SUCCESS) {
                TE_LOG_TRACE("Failed with 0x%x\n", *pVecResult);
                res = *pVecResult;
            }
        }
        if (res != TE_RC_SUCCESS) {
            goto bail;
        }

        pTestData->failStage = CLEAN;
        if (pTestSuite->cleanFunc) {
            if ((res = pTestSuite->cleanFunc(NULL)) != TE_RC_SUCCESS) {
                goto bail;
            }
        }
    }

bail:
    return res;
}

static void TE_printSectionHeader(size_t len, const char *format, ...)
{
    uint32_t i;
    va_list args;
    char buff[TE_MAX_LOG_LINE];
    va_start(args, format);
    TE_PRINT("\n\n");
    for (i = 0; i < len; i++)
        TE_PRINT("-");
    TE_PRINT("\n");
    vsnprintf(buff, TE_MAX_LOG_LINE - 1, format, args);
    TE_PRINT("|    %-*s|\n", (int)len - 4 - 2, buff);
    va_end(args);
}

static void TE_printSectionFooter(size_t len, const char *format, ...)
{
    uint32_t i;
    va_list args;
    char buff[TE_MAX_LOG_LINE];
    va_start(args, format);
    vsnprintf(buff, TE_MAX_LOG_LINE - 1, format, args);
    TE_PRINT("|    %-*s|\n", (int)len - 4 - 2, buff);
    for (i = 0; i < len; i++)
        TE_PRINT("-");
    TE_PRINT("\n\n");
    va_end(args);
}

static TE_rc_t TE_printTestFlows(void)
{
    TE_rc_t res = TE_RC_SUCCESS;
    size_t index = 0;
    static const char * dash = "--------------------------------------------------------------";
    uint16_t numOfFailed = 0;
    uint16_t numOfTotlaTests = 0;
    char resultBuff[11] = { 0 };
    bool isTestExist = false;

    TE_TestData_t *pTestIter = gCoreMgmt.listOfTests;

    TE_ASSERT(gCoreMgmt.isLibInited == true);

    /* header */
    TE_printSectionHeader(102, "%s Test Flows", gCoreMgmt.moduleName);

    /* seperator */
    TE_PRINT("--%3.3s---%-20.20s---%-20.20s---%-20.20s---%-10.10s---%-10.10s--\n",
             dash,
             dash,
             dash,
             dash,
             dash,
             dash);
    TE_PRINT("| %3.3s | %-20.20s | %-20.20s | %-20.20s | %-10.10s | %-10.10s |\n",
             "Num",
             "Name",
             "Module Name",
             "Sub ModuleName",
             "Result",
             "fail stage");
    /* seperator */
    TE_PRINT("--%3.3s---%-20.20s---%-20.20s---%-20.20s---%-10.10s---%-10.10s--\n",
             dash,
             dash,
             dash,
             dash,
             dash,
             dash);

    /* print all flow tests */
    for (index = 0; index < gCoreMgmt.numOfTests; ++index, pTestIter = pTestIter->next)
    {
        if (pTestIter->testType != TE_TEST_TYPE_FLOW)
            continue;

        numOfTotlaTests += 1;

        if (pTestIter->result == TE_RC_SUCCESS)
        {
            strcpy(resultBuff, "Passed");
        }
        else
        {
            numOfFailed++;
            sprintf(resultBuff, "0x%08x", pTestIter->result);
        }

        isTestExist = true;

        TE_PRINT("| %3u | %-20.20s | %-20.20s | %-20.20s | %-10.10s | %-10.10s |\n",
                 numOfTotlaTests,
                 pTestIter->name,
                 pTestIter->featureName,
                 pTestIter->subFeatureName,
                 resultBuff,
                 TE_getStageStr(pTestIter->failStage));

    }

    /* no tests found */
    if (isTestExist == false)
    {
        TE_PRINT("| %3.3s   %-20.20s   %-20.20s   %-20.20s   %-10.10s   %-10.10s | \n",
                 "",
                 "No tests registered",
                 "",
                 "",
                 "",
                 "");
    }

    /* Separator */
    TE_PRINT("--%3.3s---%-20.20s---%-20.20s---%-20.20s---%-10.10s---%-10.10s--\n",
             dash,
             dash,
             dash,
             dash,
             dash,
             dash);

    TE_printSectionFooter(102, "%u/%u tests failed", numOfFailed, numOfTotlaTests);

bail:
    return res;
}

static TE_rc_t TE_printTestSuites(void)
{
    TE_rc_t res = TE_RC_SUCCESS;
    size_t index = 0;
    static const char * dash = "--------------------------------------------------------------";
    uint16_t numOfFailed = 0;
    uint16_t numOfTotlaTests = 0;
    char resultBuff[11] = { 0 };
    char stageBuff[11] = { 0 };
    bool isTestExist = false;

    TE_TestData_t *pTestIter = gCoreMgmt.listOfTests;

    TE_ASSERT(gCoreMgmt.isLibInited == true);

    /* header */
    TE_printSectionHeader(145, "%s Test suite", gCoreMgmt.moduleName);

    /* seperator */
    TE_PRINT("--%3.3s---%-20.20s---%-20.20s---%-20.20s---%-40.40s---%-10.10s---%-10.10s--\n",
             dash,
             dash,
             dash,
             dash,
             dash,
             dash,
             dash);
    TE_PRINT("| %3.3s | %-20.20s | %-20.20s | %-20.20s | %-40.40s | %-10.10s | %-10.10s |\n",
             "Num",
             "Name",
             "Module Name",
             "Sub ModuleName",
             "Vector",
             "Result",
             "fail stage");
    /* seperator */
    TE_PRINT("--%3.3s---%-20.20s---%-20.20s---%-20.20s---%-40.40s---%-10.10s---%-10.10s--\n",
             dash,
             dash,
             dash,
             dash,
             dash,
             dash,
             dash);

    for (index = 0; index < gCoreMgmt.numOfTests; ++index, pTestIter = pTestIter->next)
    {
        uint32_t vecCounter = 0;
        TE_TestVec_t *pData = NULL;
        uint32_t count = 0;

        if (pTestIter->testType != TE_TEST_TYPE_SUITE)
            continue;

        pData = pTestIter->testInst.testSuite.pTestVec->pData;
        count = pTestIter->testInst.testSuite.pTestVec->count;

        /* print out all failed vectors */
        for (vecCounter = 0; vecCounter < count; vecCounter++, pData++)
        {
            TE_rc_t vecResult = pTestIter->testInst.testSuite.pResults[vecCounter];

            numOfTotlaTests += 1;
            isTestExist = true;

            if (vecResult == TE_RC_SUCCESS)
            {
#if !TE_PRINT_ONLY_FAILED_VEC
                continue;
#endif
                sprintf(resultBuff, "%8.8s", "");
                sprintf(stageBuff, "%-10.10s", "");
            }
            else
            {
                numOfFailed++;
                sprintf(resultBuff, "0x%08x", vecResult);
                sprintf(stageBuff, "%-10.10s", TE_getStageStr(pTestIter->failStage));
            }

            TE_PRINT("| %3u | %-20.20s | %-20.20s | %-20.20s | %-40.40s | %-10.10s | %-10.10s | \n",
                     numOfTotlaTests,
                     pTestIter->name,
                     pTestIter->featureName,
                     pTestIter->subFeatureName,
                     pData->name,
                     resultBuff,
                     stageBuff);
        }

    }

    /* no tests found, print a line that says that no tests were found */
    if (isTestExist == false)
    {
        TE_PRINT("| %3.3s   %-20.20s   %-20.20s   %-20.20s   %-40.40s   %-10.10s   %-10.10s | \n",
                 "",
                 "No tests registered",
                 "",
                 "",
                 "",
                 "",
                 "");
    }

    /* seperator */
    TE_PRINT("--%3.3s---%-20.20s---%-20.20s---%-20.20s---%-40.40s---%-10.10s---%-10.10s--\n",
             dash,
             dash,
             dash,
             dash,
             dash,
             dash,
             dash);
    TE_printSectionFooter(145, "%u/%u vectors failed", numOfFailed, numOfTotlaTests);

bail:
    return res;
}

TE_rc_t TE_printTests(void)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_ASSERT(TE_printTestSuites() == TE_RC_SUCCESS);
    TE_ASSERT(TE_printTestFlows() == TE_RC_SUCCESS);

    TE_printSectionHeader(190, "%s Profiling data", gCoreMgmt.moduleName);
    TE_perfDump();
bail:
    return res;
}

/****************************************************************************
 *
 * public
 *
 ****************************************************************************/
TE_rc_t TE_initLib(const char *pModuleName, uint32_t numOfPrifilerIterations)
{
    TE_rc_t res = TE_RC_SUCCESS;

    TE_ASSERT(pModuleName != NULL);
    TE_ASSERT(gCoreMgmt.isLibInited == false);

    strncpy(gCoreMgmt.moduleName, pModuleName, TE_NAME_LEN - 1);

    gCoreMgmt.isLibInited = 1;
    gCoreMgmt.listOfTests = NULL;
    gCoreMgmt.numOfTests = 0;
    gCoreMgmt.lastTest = gCoreMgmt.listOfTests;
    gCoreMgmt.numOfProfilerIterations = numOfPrifilerIterations;

    TE_perfInit();

bail:
	return res;
}

TE_rc_t TE_finilizeLib(void)
{
    TE_rc_t res = TE_RC_SUCCESS;
    size_t index = 0;
    TE_TestData_t *pTestIter = gCoreMgmt.listOfTests;

    TE_LOG_TRACE("cleaning test database\n");

    TE_ASSERT(gCoreMgmt.isLibInited == true);

    for (index = 0; index < gCoreMgmt.numOfTests; ++index)
    {
        TE_TestData_t *pNextTest = pTestIter->next;

        if (pTestIter->testType == TE_TEST_TYPE_SUITE)
        {
            TE_FREE(pTestIter->testInst.testSuite.pResults);
        }

        TE_FREE(pTestIter);

        pTestIter = pNextTest;
    }

    TE_perfFin();

    gCoreMgmt.isLibInited = false;

bail:
	return res;
}

TE_rc_t TE_registerFlow(const char *pName,
                        const char *pFeatureName,
                        const char *pSubFeatureName,
                        fPrepare prepareFunc,
                        fExecFlow execFlowFunc,
                        fVerify verifyFunc,
                        fClean cleanFunc,
                        void *pContext)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_TestData_t *pTestToAdd = NULL;

    TE_ASSERT(execFlowFunc != NULL);
    TE_ASSERT(TE_registerCommon(pName, pFeatureName, pSubFeatureName, &pTestToAdd)
                    == TE_RC_SUCCESS);

    pTestToAdd->testType = TE_TEST_TYPE_FLOW;
    pTestToAdd->testInst.testFlow.prepareFunc = prepareFunc;
    pTestToAdd->testInst.testFlow.execFlowFunc = execFlowFunc;
    pTestToAdd->testInst.testFlow.verifyFunc = verifyFunc;
    pTestToAdd->testInst.testFlow.cleanFunc = cleanFunc;
    pTestToAdd->testInst.testFlow.pContext = pContext;

bail:
	return res;
}

TE_rc_t TE_registerSuite(const char *pName,
                         const char *pFeatureName,
                         const char *pSubFeatureName,
                         fPrepare prepareFunc,
                         fExecSuite execSuiteFunc,
                         fClean cleanFunc,
                         TE_TestVecList_t *pTestVec)
{
    TE_rc_t res = TE_RC_SUCCESS;
    TE_TestData_t *pTestToAdd = NULL;

    TE_LOG_TRACE("registering test %s\n", pName);

    TE_ASSERT(execSuiteFunc != NULL);
    TE_ASSERT(pTestVec != NULL);
    TE_ASSERT(TE_registerCommon(pName, pFeatureName, pSubFeatureName, &pTestToAdd)
              == TE_RC_SUCCESS);

    pTestToAdd->testType = TE_TEST_TYPE_SUITE;
    pTestToAdd->testInst.testSuite.prepareFunc = prepareFunc;
    pTestToAdd->testInst.testSuite.execSuiteFunc = execSuiteFunc;
    pTestToAdd->testInst.testSuite.cleanFunc = cleanFunc;
    pTestToAdd->testInst.testSuite.pTestVec = pTestVec;

    /* allocate array for results */
    TE_ALLOC(pTestToAdd->testInst.testSuite.pResults,
             sizeof(*pTestToAdd->testInst.testSuite.pResults) * pTestVec->count);

bail:
	return res;
}

TE_rc_t TE_execute(void)
{
    TE_rc_t res = TE_RC_SUCCESS;
    size_t index = 0;
    uint32_t iter = 0;
    uint32_t isFailed = 0;

    TE_ASSERT(gCoreMgmt.isLibInited == true);

    for (iter = 0; iter < gCoreMgmt.numOfProfilerIterations; ++iter)
    {
        TE_TestData_t *pTestIter = gCoreMgmt.listOfTests;

        for (index = 0; index < gCoreMgmt.numOfTests; ++index)
        {
            TE_rc_t rc = TE_RC_SUCCESS;

            TE_LOG_TRACE("Executing Test[%zu:%s:%s:%s]\n",
                         index,
                         pTestIter->name,
                         pTestIter->featureName,
                         pTestIter->subFeatureName);

            rc = TE_executeTestInstance(pTestIter);
            if (rc != TE_RC_SUCCESS)
            {
                isFailed++;
                goto next_test;
            }

            pTestIter->failStage = DONE;

next_test:
            pTestIter->result = rc;
            pTestIter = pTestIter->next;
        }
    }

bail:
    res = (isFailed ? TE_RC_FAIL : TE_RC_SUCCESS);
    return res;

}
