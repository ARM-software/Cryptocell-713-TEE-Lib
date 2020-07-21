/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include "cc_axi_ctrl.h"
#include "cc_hal.h"
#include "cc_regs.h"


/******************************************************************************
*               DEFINITIONS
******************************************************************************/

#define  SET_AXI_FIELD(reg_name, fld_name, regVal, pAxiFields) {    \
     BITFIELD_SET(regVal,                                           \
                CC_ ## reg_name ## _ ## fld_name ## _BIT_SHIFT,     \
                CC_ ## reg_name ## _ ## fld_name ## _BIT_SIZE,      \
                pAxiFields->reg_name.bitField.fld_name);            \
}

#define  GET_AXI_FIELD(reg_name, fld_name, regVal, pAxiFields) {    \
     pAxiFields->reg_name.bitField.fld_name = BITFIELD_GET(regVal,  \
                CC_ ## reg_name ## _ ## fld_name ## _BIT_SHIFT,     \
                CC_ ## reg_name ## _ ## fld_name ## _BIT_SIZE);     \
}
/******************************************************************************
*               GLOBALS
******************************************************************************/

/******************************************************************************
*               PRIVATE FUNCTIONS
******************************************************************************/

/******************************************************************************
*               FUNCTIONS
******************************************************************************/
CCError_t CC_HalSetCacheParams(CCAxiFields_t  *pAxiFields)
{
    uint32_t aceRegVal = 0;
    uint32_t cacheRegVal = 0;

    if (pAxiFields == NULL) {
        return CC_AXI_CTRL_ILEGALL_INPUT_ERROR;
    }

    /* Set fields in  AXIM_ACE_CONST and AXIM_CACHE_PARAMS registers */
    SET_AXI_FIELD(AXIM_ACE_CONST, ARDOMAIN, aceRegVal, pAxiFields);
    SET_AXI_FIELD(AXIM_ACE_CONST, AWDOMAIN, aceRegVal, pAxiFields);
    SET_AXI_FIELD(AXIM_ACE_CONST, ARBAR, aceRegVal, pAxiFields);
    SET_AXI_FIELD(AXIM_ACE_CONST, AWBAR, aceRegVal, pAxiFields);
    SET_AXI_FIELD(AXIM_ACE_CONST, ARSNOOP, aceRegVal, pAxiFields);
    SET_AXI_FIELD(AXIM_ACE_CONST, AWSNOOP_NOT_ALIGNED, aceRegVal, pAxiFields);
    SET_AXI_FIELD(AXIM_ACE_CONST, AWSNOOP_ALIGNED, aceRegVal, pAxiFields);
    SET_AXI_FIELD(AXIM_ACE_CONST, AWADDR_NOT_MASKED, aceRegVal, pAxiFields);
    SET_AXI_FIELD(AXIM_ACE_CONST, AWLEN_VAL, aceRegVal, pAxiFields);

    SET_AXI_FIELD(AXIM_CACHE_PARAMS, AWCACHE_LAST, cacheRegVal, pAxiFields);
    SET_AXI_FIELD(AXIM_CACHE_PARAMS, AWCACHE, cacheRegVal, pAxiFields);
    SET_AXI_FIELD(AXIM_CACHE_PARAMS, ARCACHE, cacheRegVal, pAxiFields);

    /* Write registers */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, AXIM_ACE_CONST)  ,aceRegVal);
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, AXIM_CACHE_PARAMS)  ,cacheRegVal);

    return CC_OK;

}

CCError_t CC_HalGetCacheParams(CCAxiFields_t  *pAxiFields)
{
    uint32_t aceRegVal = 0;
    uint32_t cacheRegVal = 0;

    if (pAxiFields == NULL) {
        return CC_AXI_CTRL_ILEGALL_INPUT_ERROR;
    }

    /* Read AXIM_ACE_CONST and AXIM_CACHE_PARAMS registers  */
    aceRegVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, AXIM_ACE_CONST));
    cacheRegVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, AXIM_CACHE_PARAMS));

    /* Set fields in  AXIM_ACE_CONST and AXIM_CACHE_PARAMS registers */
    GET_AXI_FIELD(AXIM_ACE_CONST, ARDOMAIN, aceRegVal, pAxiFields);
    GET_AXI_FIELD(AXIM_ACE_CONST, AWDOMAIN, aceRegVal, pAxiFields);
    GET_AXI_FIELD(AXIM_ACE_CONST, ARBAR, aceRegVal, pAxiFields);
    GET_AXI_FIELD(AXIM_ACE_CONST, AWBAR, aceRegVal, pAxiFields);
    GET_AXI_FIELD(AXIM_ACE_CONST, ARSNOOP, aceRegVal, pAxiFields);
    GET_AXI_FIELD(AXIM_ACE_CONST, AWSNOOP_NOT_ALIGNED, aceRegVal, pAxiFields);
    GET_AXI_FIELD(AXIM_ACE_CONST, AWSNOOP_ALIGNED, aceRegVal, pAxiFields);
    GET_AXI_FIELD(AXIM_ACE_CONST, AWADDR_NOT_MASKED, aceRegVal, pAxiFields);
    GET_AXI_FIELD(AXIM_ACE_CONST, AWLEN_VAL, aceRegVal, pAxiFields);

    GET_AXI_FIELD(AXIM_CACHE_PARAMS, AWCACHE_LAST, cacheRegVal, pAxiFields);
    GET_AXI_FIELD(AXIM_CACHE_PARAMS, AWCACHE, cacheRegVal, pAxiFields);
    GET_AXI_FIELD(AXIM_CACHE_PARAMS, ARCACHE, cacheRegVal, pAxiFields);

    return CC_OK;

}
