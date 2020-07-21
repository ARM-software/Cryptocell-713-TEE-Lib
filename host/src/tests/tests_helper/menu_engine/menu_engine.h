/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#ifndef MENU_ENGINE_MENU_H_
#define MENU_ENGINE_MENU_H_

/****************************************************************************
 *
 * defines
 *
 ****************************************************************************/
#define MENU_PATH_MAX          20
#define MENU_PATH_DEPTH_MAX    5

/****************************************************************************
 *
 * mcaros
 *
 ****************************************************************************/

/****************************************************************************
 *
 * types
 *
 ****************************************************************************/
typedef enum MENU_rc_t
{
    MENU_RC_SUCCESS,
    MENU_RC_FAIL,
} Menu_rc_t;

typedef char MENU_MenuPath_t[MENU_PATH_DEPTH_MAX][MENU_PATH_MAX];
typedef Menu_rc_t (*MENU_Callback_func)(void *context);
typedef Menu_rc_t (*MENU_CallbackParams_func)(int argc, char **argv);

/****************************************************************************
 *
 * public
 *
 ****************************************************************************/
Menu_rc_t MENU_initLib(void);

Menu_rc_t MENU_register(const char *path0,
                        const char *path1,
                        const char *path2,
                        const char *path3,
                        const char *path4,
                        MENU_Callback_func menuCallbackFunc,
                        void *menuCallbackContext);

Menu_rc_t MENU_registerParams(const char *path0,
                              const char *path1,
                              const char *path2,
                              const char *path3,
                              const char *path4,
                              MENU_CallbackParams_func menuCallbackFunc);

Menu_rc_t MENU_finLib(void);

Menu_rc_t MENU_execute(int argc, char **argv);

#endif /* MENU_ENGINE_MENU_H_ */
