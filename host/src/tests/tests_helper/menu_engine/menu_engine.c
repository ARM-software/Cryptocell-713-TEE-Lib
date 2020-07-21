/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

#include "menu_engine.h"

#include "tests_log.h"
#include "tests_utils.h"
#include "tests_thread.h"

#include "dx_reg_base_host.h"

/****************************************************************************
 *
 * defines
 *
 ****************************************************************************/
#define MENU_PATH_MAX_ITEM     30 /* per level */

/****************************************************************************
 *
 * macros
 *
 ****************************************************************************/
#define MENU_PATH_COMPILE(_buff, _path, _level)                                             \
    do {                                                                                    \
        uint32_t _depth = 0;                                                                \
        _buff[0] = '\0';                                                                    \
        for (_depth = 0; _depth < _level; ++_depth)                                         \
        {                                                                                   \
            snprintf(_buff + strlen(_buff), 100 - strlen(_buff), "%s/", _path[_depth]);     \
        }                                                                                   \
        for (_depth = _level; _depth < MENU_PATH_DEPTH_MAX; ++_depth)                       \
        {                                                                                   \
            snprintf(_buff + strlen(_buff), 100 - strlen(_buff), "%s/", "NULL");            \
        }                                                                                   \
    }while(0)

#ifdef TEE_OS_IS_NO_OS
#define EXECUTE_CALLBACK(args) Tests_Runthread(MENU_menuExecuteCallback, args)
#else
#define EXECUTE_CALLBACK(args) (Menu_rc_t)MENU_menuExecuteCallback(args)
#endif

/****************************************************************************
 *
 * Types
 *
 ****************************************************************************/
typedef enum MENU_MenuCallbackType_t
{
    MENU_CB_SIMPLE,
    MENU_CB_PARAM,
} MENU_MenuCallbackType_t;

typedef union MENU_MenuCallback_t
{
    struct {
        MENU_Callback_func menuCallbackFunc;
        void *menuCallbackContext;
    } simple;

    struct {
        MENU_CallbackParams_func menuCallbackParamsFunc;
    } params;

} MENU_MenuCallback_t;

typedef struct MENU_MenuItem_t
{
    MENU_MenuPath_t path;
    uint32_t pathDepth;
    MENU_MenuCallback_t cb;
    MENU_MenuCallbackType_t cbType;
    struct MENU_MenuItem_t *nextItem;
} MENU_MenuItem_t;

typedef struct MENU_MenuDataBase
{
    MENU_MenuItem_t *pItemList;
    MENU_MenuItem_t *lastItem;
    uint32_t numOfItems;
    bool isInitialised;
} MENU_MenuDataBase;

typedef struct MENU_MenuItemAndParams_t
{
    MENU_MenuItem_t *pMenuItem;
    int param1;
    char **param2;
} MENU_MenuItemAndParams_t;

/****************************************************************************
 *
 * globals
 *
 ****************************************************************************/
MENU_MenuDataBase menuDB;

/****************************************************************************
 *
 * static prototypes
 *
 ****************************************************************************/
static bool MENU_menuIsPath1inPath2(MENU_MenuPath_t path1,
                                    uint32_t pathDepth1,
                                    MENU_MenuPath_t path2,
                                    uint32_t pathDepth2);

static Menu_rc_t MENU_printMenuChildren(MENU_MenuPath_t path,
                                        uint32_t level,
                                        MENU_MenuItem_t *pChildrenList[MENU_PATH_MAX_ITEM],
                                        uint32_t *numOfChildren);

static Menu_rc_t MENU_menuFind(MENU_MenuPath_t path, uint32_t pathDepth, MENU_MenuItem_t **poMenuItem,
                               bool *isLeaf);

static Menu_rc_t MENU_menuFindChildren(MENU_MenuPath_t path,
                                       uint32_t pathDepth,
                                       MENU_MenuItem_t *pChildrenList[MENU_PATH_MAX_ITEM],
                                       uint32_t *numOfChildren);

static void MENU_printItem(MENU_MenuItem_t *pItem);

static void MENU_printDataBase(void);

static void MENU_printCurrentPath(MENU_MenuItem_t *pMenuItem, uint32_t depth);

static Menu_rc_t MENU_menuExecute(MENU_MenuItem_t *pMenuItem, int argc, char **argv);

/****************************************************************************
 *
 * static functions
 *
 ****************************************************************************/
static bool MENU_menuIsPath1inPath2(MENU_MenuPath_t path1, uint32_t pathDepth1,
                                  MENU_MenuPath_t path2, uint32_t pathDepth2)
{
    uint32_t depth;

    if (pathDepth1 > pathDepth2)
    {
        return false;
    }

#ifdef MENU_MENU_DEBUG
    {
        char buff1[100] = { 0 }, buff2[100] = { 0 };
        MENU_PATH_COMPILE(buff1, path1, pathDepth1);
        MENU_PATH_COMPILE(buff2, path2, pathDepth2);
        TEST_LOG_DEBUG("comparing path1[%s][%d] with path2[%s][%d\n", buff1, pathDepth1, buff2, pathDepth2);
    }
#endif

    for (depth = 0; depth < pathDepth1; ++depth)
    {
        if (strncmp(path1[depth], path2[depth], MENU_PATH_MAX) != 0)
        {
            return false;
        }

    }

    return true;
}

static Menu_rc_t MENU_printMenuChildren(MENU_MenuPath_t path, uint32_t level, MENU_MenuItem_t *pChildrenList[MENU_PATH_MAX_ITEM], uint32_t *numOfChildren)
{
    Menu_rc_t res = MENU_RC_SUCCESS;

    uint32_t i;
    uint32_t pathIndex = level - 1;

    memset(pChildrenList, 0, sizeof(*pChildrenList));
    *numOfChildren = 0;

    TEST_PRINT("\n");

    if (MENU_menuFindChildren(path, level, pChildrenList, numOfChildren) == MENU_RC_SUCCESS)
    {
        TEST_PRINT("Menu\n");
        TEST_PRINT("----------------------------------------------------------\n");

        for (i = 0; i < *numOfChildren; ++i)
        {
            TEST_PRINT("%2u. %s\n", i + 1, pChildrenList[i]->path[pathIndex]);
        }

        TEST_PRINT(" q. back\n");
        TEST_PRINT(" x. exit\n");
    }

    TEST_PRINT("\n$ ");

    return res;
}

static Menu_rc_t MENU_menuFindChildren(MENU_MenuPath_t path, uint32_t pathDepth, MENU_MenuItem_t *pChildrenList[MENU_PATH_MAX_ITEM], uint32_t *numOfChildren)
{

    Menu_rc_t res = MENU_RC_SUCCESS;
    uint32_t depth, i;
    MENU_MenuItem_t *pItem = NULL;

    /* calling this API is not valid before the module is initialised */
    if (menuDB.isInitialised != true)
    {
        TEST_LOG_ERROR("Library is not initialised\n");
        res = MENU_RC_FAIL;
        goto bail;
    }

    /* head ptr - not root*/
    pItem = menuDB.pItemList->nextItem;

    {
        char buff[50] = { 0 };
        MENU_PATH_COMPILE(buff, path, pathDepth - 1);
        TEST_LOG_DEBUG("looking for children of item[%s]:\n", buff);
    }

    /* iterate over all items */
    for (i = 0; i < menuDB.numOfItems - 1; ++i, pItem = pItem->nextItem)
    {
        /* check that all "pathDepth" levels match */
        for (depth = 0; depth < pathDepth - 1; ++depth)
        {
            char *currStr = path[depth];
            if (!currStr || strncmp(currStr, pItem->path[depth], MENU_PATH_MAX) != 0)
            {
                /* No match */
                break;
            }
        }

        /* did all pathDepth levels match */
        if (depth >= pathDepth - 1)
        {
            uint32_t child;


            for (child = 0; child < *numOfChildren; ++child)
            {
                if (MENU_menuIsPath1inPath2(pItem->path, pathDepth, pChildrenList[child]->path, pChildrenList[child]->pathDepth) == true)
                {
                    /* not uniqe */
                    break;
                }
            }

            /* uniqe */
            if (child == *numOfChildren)
            {
                pChildrenList[*numOfChildren] = pItem;
                *numOfChildren += 1;
            }
        }
    }

bail:
    return res;

}

static Menu_rc_t MENU_menuFind(MENU_MenuPath_t path, uint32_t pathDepth, MENU_MenuItem_t **poMenuItem, bool *isLeaf)
{
    Menu_rc_t res = MENU_RC_FAIL;
    uint32_t depth, i;
    MENU_MenuItem_t *pItem = NULL;

    /* calling this API is not valid before the module is initialised */
    if (menuDB.isInitialised != true)
    {
        TEST_LOG_ERROR("Library is not initialised\n");
        res = MENU_RC_FAIL;
        goto bail;
    }

    /* head ptr */
    pItem = menuDB.pItemList;


    /* iterate over all items */
    for (i = 0; i < menuDB.numOfItems; ++i, pItem = pItem->nextItem)
    {
        /* check that all "pathDepth" levels match */
        for (depth = 0; depth < pathDepth; ++depth)
        {
            char *currStr = path[depth];
            if (strncmp(currStr, pItem->path[depth], MENU_PATH_MAX) != 0)
            {
                /* No match */
                break;
            }
        }

        /* did all pathDepth levels match */
        if (depth == pathDepth)
        {
            if (isLeaf)
            {
                /* check whether a leaf or not by seeing if not depth exists in path */
                *isLeaf = depth == pItem->pathDepth;
            }

            *poMenuItem = pItem;
            res = MENU_RC_SUCCESS;
            goto bail;
        }
    }

bail:
    return res;
}

static uint32_t MENU_menuGenPath(const char *path0,
                               const char *path1,
                               const char *path2,
                               const char *path3,
                               const char *path4,
                               MENU_MenuPath_t path)
{
    uint32_t pathDepth = 0;

#define MENU_CHECK_PATH(_depth, _a) \
    do { \
        memset(path[_depth], 0, MENU_PATH_MAX); \
        if (_a && strlen(_a)) \
            { \
                strncpy(path[_depth], _a, MENU_PATH_MAX - 1); \
                pathDepth += 1; \
            }  \
    } while(0)

    MENU_CHECK_PATH(0, path0);
    MENU_CHECK_PATH(1, path1);
    MENU_CHECK_PATH(2, path2);
    MENU_CHECK_PATH(3, path3);
    MENU_CHECK_PATH(4, path4);

#undef MENU_CHECK_PATH
    return pathDepth;
}
static Menu_rc_t MENU_menuFromPathString(MENU_MenuPath_t currPath, uint32_t *pCurrDepth, char *buffIn, MENU_MenuItem_t **poMenuItem, bool *isLeaf)
{
    Menu_rc_t res = MENU_RC_SUCCESS;
    MENU_MenuPath_t localPath = { 0 };
    uint32_t localDepth = 0;
    char *tok = NULL;
    char del[2] = "/";

    tok = strtok(buffIn, del);
    while (tok != NULL)
    {
        strncpy(localPath[localDepth++], tok, MENU_PATH_MAX - 1);
        tok = strtok(NULL, del);
    }

    res = MENU_menuFind(localPath, localDepth, poMenuItem, isLeaf);

    if (res != MENU_RC_SUCCESS)
    {
        char buff[100] = { 0 };
        MENU_PATH_COMPILE(buff, localPath, localDepth);
        TEST_LOG_ERROR("Couldn't find path[%s] res[0x%08x]\n", buff, res);
        res = MENU_RC_FAIL;
        goto bail;
    }

    if (poMenuItem == NULL)
    {
        char buff[100] = { 0 };
        MENU_PATH_COMPILE(buff, localPath, localDepth);
        TEST_LOG_ERROR("Couldn't find path[%s] poMenuItem is NULL\n", buff);
        res = MENU_RC_FAIL;
        goto bail;
    }

    memcpy(currPath, localPath, sizeof(MENU_MenuPath_t));
    *pCurrDepth = localDepth;

bail:
    return res;
}

static void MENU_printItem(MENU_MenuItem_t *pItem)
{
    char buff[100] = { 0 };

    MENU_PATH_COMPILE(buff, pItem->path, pItem->pathDepth);

    TEST_LOG_TRACE("menuItem[%p] path[%s]\n", pItem, buff);

}

static void MENU_printDataBase(void)
{
    uint32_t itemCount = 0;

    TEST_LOG_TRACE("printing DB\n");

    /* head ptr */
    MENU_MenuItem_t *pItem = menuDB.pItemList;

    for (itemCount = 0; itemCount < menuDB.numOfItems; ++itemCount, pItem = pItem->nextItem)
    {
        MENU_printItem(pItem);
    }
}

static void MENU_printCurrentPath(MENU_MenuItem_t *pMenuItem, uint32_t depth)
{
    char _buff[100] = { 0 };

    uint32_t _depth = 0;

    _buff[0] = '\0';

    for (_depth = 0; _depth < depth; ++_depth)
    {
        snprintf(_buff + strlen(_buff), 100 - strlen(_buff), "%s/", pMenuItem->path[_depth]);
    }

    TEST_PRINT("Current path: %s\n", _buff);
}

static void *MENU_menuExecuteCallback(void *pMenuItemAndParamsInput)
{
    Menu_rc_t res = MENU_RC_SUCCESS;
    MENU_MenuItemAndParams_t *pMenuItemAndParams = (MENU_MenuItemAndParams_t *)pMenuItemAndParamsInput;

    if (pMenuItemAndParams->pMenuItem->cbType == MENU_CB_SIMPLE)
    {
        /* execute callback - send context as parameter */
        res = pMenuItemAndParams->pMenuItem->cb.simple.menuCallbackFunc(pMenuItemAndParams->pMenuItem->cb.simple.menuCallbackContext);
    }
    else
    {
        /* execute callback - send 2 parameters */
        res = pMenuItemAndParams->pMenuItem->cb.params.menuCallbackParamsFunc(pMenuItemAndParams->param1, pMenuItemAndParams->param2);
    }

    return (void *)res;
}

static Menu_rc_t MENU_menuExecute(MENU_MenuItem_t *pMenuItem, int argc, char **argv)
{
    Menu_rc_t res = MENU_RC_SUCCESS;
    MENU_MenuItemAndParams_t menuItemAndParams;
    menuItemAndParams.pMenuItem = pMenuItem;

    if (pMenuItem->cbType == MENU_CB_SIMPLE)
    {
        /* execute callback */
        res = EXECUTE_CALLBACK(&menuItemAndParams);
    }

    if (pMenuItem->cbType == MENU_CB_PARAM)
    {

        /* only app and -m flag was given */
        if (argc == 2)
        {
            char *buffIn = NULL;
            char *localArgv[10] = { 0 };
            char del[2] = "/";
            char *ptr = NULL;
            uint32_t cnt = 0;

            TEST_ALLOC(buffIn, (size_t)256);

            TEST_PRINT("Enter arguments (/ separated)\n");

            if (scanf("%20s", buffIn) < 0) {
                TEST_LOG_ERROR("Couldn't read input\n");
                TEST_FREE(buffIn);
                res = MENU_RC_FAIL;
                goto bail;
            }

            ptr = strtok(buffIn, del);
            while (ptr != NULL && cnt < 10)
            {
                localArgv[cnt++] = ptr;
                ptr = strtok(NULL, del);
            }

            if (cnt > 10)
            {
                TEST_LOG_ERROR("Can not accept more then 10 arguments\n");
            }
            else
            {
                /* execute callback */
                menuItemAndParams.param1 = cnt;
                menuItemAndParams.param2 = localArgv;
                res = EXECUTE_CALLBACK(&menuItemAndParams);
            }

            TEST_FREE(buffIn);
        }
        else
        {
            /* execute callback */
            menuItemAndParams.param1 = argc;
            menuItemAndParams.param2 = argv;
            res = EXECUTE_CALLBACK(&menuItemAndParams);
        }

    }

    TEST_LOG_DEBUG("execution of path completed with res[0x%08x]\n", res);

bail:
    return res;
}

/****************************************************************************
 *
 * public
 *
 ****************************************************************************/
Menu_rc_t MENU_initLib(void)
{
    Menu_rc_t res = MENU_RC_SUCCESS;

    TEST_ASSERT(menuDB.isInitialised == false, MENU_RC_FAIL);

    memset(&menuDB, 0, sizeof(menuDB));

    menuDB.isInitialised = true;

    TEST_ASSERT(MENU_register(NULL, NULL, NULL, NULL, NULL, NULL, NULL) == MENU_RC_SUCCESS, MENU_RC_FAIL);

    /* CR because of pal printouts */
    TEST_PRINT("\n");

bail:
    return res;
}

Menu_rc_t MENU_register(const char *path0,
                        const char *path1,
                        const char *path2,
                        const char *path3,
                        const char *path4,
                        MENU_Callback_func menuCallbackFunc,
                        void *menuCallbackContext)
{
    Menu_rc_t res = MENU_RC_SUCCESS;
    MENU_MenuItem_t *pMenuItem = NULL;
    MENU_MenuPath_t path;
    uint32_t pathDepth;
    uint32_t depth;


    TEST_ALLOC(pMenuItem, sizeof(MENU_MenuItem_t));
    memset(pMenuItem, 0, sizeof(MENU_MenuItem_t));

    pathDepth = MENU_menuGenPath(path0, path1, path2, path3, path4, path);
    TEST_ASSERT(pathDepth <= MENU_PATH_DEPTH_MAX, MENU_RC_FAIL);

    for (depth = 0; depth < pathDepth; ++depth)
    {
        /* path[depth] should include a null terminater */
        TEST_ASSERT(strnlen(path[depth], MENU_PATH_MAX) < MENU_PATH_MAX, MENU_RC_FAIL);

        /* just in case, and to quiet coverity */
        path[depth][MENU_PATH_MAX -1] = '\0';
        strncpy(pMenuItem->path[depth], path[depth], MENU_PATH_MAX - 1);
    }

    pMenuItem->pathDepth = pathDepth;
    pMenuItem->cb.simple.menuCallbackFunc = menuCallbackFunc;
    pMenuItem->cb.simple.menuCallbackContext = menuCallbackContext;
    pMenuItem->cbType = MENU_CB_SIMPLE;
    pMenuItem->nextItem = NULL;

    if (menuDB.numOfItems > 0)
    {
        menuDB.lastItem->nextItem = pMenuItem;
        menuDB.lastItem = pMenuItem;
    }
    else
    {
        menuDB.pItemList = pMenuItem;
        menuDB.lastItem = pMenuItem;
    }

    menuDB.numOfItems += 1;

bail:
    return res;
}

Menu_rc_t MENU_registerParams(const char *path0,
                              const char *path1,
                              const char *path2,
                              const char *path3,
                              const char *path4,
                              MENU_CallbackParams_func menuCallbackFunc)
{
    Menu_rc_t res = MENU_RC_SUCCESS;
    MENU_MenuItem_t *pMenuItem = NULL;
    MENU_MenuPath_t path;
    uint32_t pathDepth;
    uint32_t depth;


    TEST_ALLOC(pMenuItem, sizeof(MENU_MenuItem_t));
    memset(pMenuItem, 0, sizeof(MENU_MenuItem_t));

    pathDepth = MENU_menuGenPath(path0, path1, path2, path3, path4, path);
    TEST_ASSERT(pathDepth <= MENU_PATH_DEPTH_MAX, MENU_RC_FAIL);

    for (depth = 0; depth < pathDepth; ++depth)
    {
        /* path[depth] should include a null terminator */
        TEST_ASSERT(strnlen(path[depth], MENU_PATH_MAX) < MENU_PATH_MAX, MENU_RC_FAIL);

        /* just in case, and to quiet coverity */
        path[depth][MENU_PATH_MAX -1] = '\0';
        strncpy(pMenuItem->path[depth], path[depth], MENU_PATH_MAX - 1);
    }

    pMenuItem->pathDepth = pathDepth;
    pMenuItem->cb.params.menuCallbackParamsFunc = menuCallbackFunc;
    pMenuItem->cbType = MENU_CB_PARAM;
    pMenuItem->nextItem = NULL;

    if (menuDB.numOfItems > 0)
    {
        menuDB.lastItem->nextItem = pMenuItem;
        menuDB.lastItem = pMenuItem;
    }
    else
    {
        menuDB.pItemList = pMenuItem;
        menuDB.lastItem = pMenuItem;
    }

    menuDB.numOfItems += 1;

bail:
    return res;
}

Menu_rc_t MENU_execute(int argc, char **argv)
{
    Menu_rc_t res = MENU_RC_SUCCESS;
    char buffIn[(MENU_PATH_MAX + 2) * MENU_PATH_DEPTH_MAX] = { 0 };
    bool isDone = false;
    bool isLeaf = false;

    MENU_MenuItem_t *pCurrItem = NULL;
    uint32_t currDepth = 0;
    char currPath[MENU_PATH_DEPTH_MAX][MENU_PATH_MAX];

    MENU_MenuItem_t *pChildrenList[MENU_PATH_MAX_ITEM] = { 0 };
    uint32_t numOfChildren = 0, choice = 0;

    TEST_UNUSED(MENU_printDataBase());

    if (argc > 1 && strcmp(argv[1], "-m") == 0)
    {
        pCurrItem = menuDB.pItemList->nextItem;
    }
    else if (argc > 1)
    {
        /* get to the menu received from args */
        TEST_ASSERT(MENU_menuFromPathString(currPath, &currDepth, argv[1], &pCurrItem, &isLeaf) == MENU_RC_SUCCESS, MENU_RC_FAIL);

        if (isLeaf)
        {

            MENU_printCurrentPath(pCurrItem, currDepth);

            /* execute callback */
            res = MENU_menuExecute(pCurrItem, argc, argv);

            goto bail;
        }
    }

    while (isDone == false)
    {

#ifdef MENU_MENU_DEBUG
        {
            char buff[100] = { 0 };
            MENU_PATH_COMPILE(buff, currPath, currDepth);
            TEST_LOG_DEBUG("new current path[%s] depth[%d]\n", buff, currDepth);
        }
#endif

        /* interactive mode */
        MENU_printMenuChildren(pCurrItem->path, currDepth + 1, pChildrenList, &numOfChildren);

        if (scanf("%20s", buffIn) < 0) {
            TEST_LOG_ERROR("Couldn't read from input\n");
            res = MENU_RC_FAIL;
            goto bail;
        }

        if (buffIn[0] == 'q')
        {
            if (currDepth == 0)
            {
                goto bail;
            }

            currDepth -= 1;
            continue;
        }

        if (buffIn[0] == 'x')
        {
            goto bail;
        }

        choice = strtoul(buffIn, NULL, 10);

        if (choice == 0)
        {
            MENU_MenuPath_t localPath;
            uint32_t localDepth = currDepth;
            MENU_MenuItem_t *poMenuItem = NULL;
            Menu_rc_t localRes = MENU_RC_SUCCESS;
            uint32_t depth = 0;
            char *tok = NULL;
            char del[2] = "/";

            memset(&localPath, 0, sizeof(localPath));
            for (depth = 0; depth < currDepth; ++depth)
            {
                strncpy(localPath[depth], currPath[depth], MENU_PATH_MAX - 1);
            }

            tok = strtok(buffIn, del);
            while (tok != NULL)
            {
                strncpy(localPath[localDepth++], tok, MENU_PATH_MAX - 1);
                tok = strtok(NULL, del);
            }

            localRes = MENU_menuFind(localPath, localDepth, &poMenuItem, NULL);

            if (localRes != MENU_RC_SUCCESS)
            {
                char buff[100] = { 0 };
                MENU_PATH_COMPILE(buff, localPath, localDepth);
                TEST_LOG_ERROR("Couldn't find path[%s] localRes[0x%08x]\n", buff, localRes);
                continue;
            }

            if (poMenuItem == NULL)
            {
                char buff[100] = { 0 };
                MENU_PATH_COMPILE(buff, localPath, localDepth);
                TEST_LOG_ERROR("Couldn't find path[%s] poMenuItem is NULL\n", buff);
                continue;
            }

            memcpy(currPath, localPath, sizeof(MENU_MenuPath_t));
            currDepth = localDepth;

        }
        else
        {
            if (choice > numOfChildren)
            {
                TEST_LOG_ERROR("%s not a valid input\n", buffIn);
                continue;
            }

            TEST_LOG_DEBUG("adding %s to path level[%d]\n",  pChildrenList[choice - 1]->path[currDepth], currDepth);

            strncpy(currPath[currDepth], pChildrenList[choice - 1]->path[currDepth], MENU_PATH_MAX - 1);
            currDepth += 1;
        }

        if (MENU_RC_SUCCESS != MENU_menuFind(currPath, currDepth, &pCurrItem, &isLeaf))
        {
            TEST_LOG_ERROR("path is not valid\n");
            currDepth -= 1;
        }
        else
        {
            if (isLeaf)
            {
                MENU_printCurrentPath(pCurrItem, currDepth);

                /* execute callback */
                res = MENU_menuExecute(pCurrItem, argc, argv);

                currDepth -= 1;
            }
            else
            {
                /* print next menu level */
                continue;
            }
        }
    }

bail:
    return res;
}

Menu_rc_t MENU_finLib(void)
{
    Menu_rc_t res = MENU_RC_SUCCESS;
    uint32_t i;
    MENU_MenuItem_t *iter = menuDB.pItemList;

    TEST_ASSERT(menuDB.isInitialised == true, MENU_RC_FAIL);

    for (i = 0; iter && i < menuDB.numOfItems; ++i)
    {
        MENU_MenuItem_t *next = iter->nextItem;

        TEST_FREE(iter)

        iter = next;
    }

    menuDB.lastItem = NULL;
    menuDB.isInitialised = false;
    menuDB.numOfItems = 0;

bail:
    return res;
}
