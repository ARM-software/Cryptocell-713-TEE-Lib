/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#ifndef _CC_AXI_CTRL_H
#define _CC_AXI_CTRL_H

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains the AXI configuration control definitions.
*/

/*!
 @addtogroup cc_axi_config
 @{
     */

#include "cc_pal_types.h"
#include "cc_error.h"

/************************ Defines ******************************/
/*! This error is returned when one of the function inputs is illegal */
#define CC_AXI_CTRL_ILEGALL_INPUT_ERROR         (CC_AXI_CTRL_MODULE_ERROR_BASE + 0x01)

/************************ Typedefs  *****************************/
/*! List ACE configuration for the Secure AXI transactions. */
typedef union {
    /*! A bit field structure defining the ACE configuration. */
    struct {
        uint32_t  ARDOMAIN : 2;         /*!< ACE ARDOMAIN constant value. */
        uint32_t  AWDOMAIN : 2;         /*!< ACE AWDOMAIN constant value. */
        uint32_t  ARBAR : 2;            /*!< ACE ARBAR constant value. */
        uint32_t  AWBAR : 2;            /*!< ACE AWBAR constant value. */
        uint32_t  ARSNOOP : 4;          /*!< ACE ARSNOOP constant value. */
        uint32_t  AWSNOOP_NOT_ALIGNED : 3; /*!< ACE AWSNOOP constant value when unaligned transaction is used. */
        uint32_t  AWSNOOP_ALIGNED : 3;  /*!< ACE AWSNOOP constant value when unaligned transaction is used. */
        uint32_t  AWADDR_NOT_MASKED : 7; /*!< AWADDRESS not mask value. */
        uint32_t  AWLEN_VAL : 4;        /*!< AWLEN value. */
    } bitField;
    /*! Reserved. */
    uint32_t word;
}CCAxiAceConst_t;

/*! AXI master configuration for DMA. */
typedef union {
    /*! A bit field structure defining the AXI master configuration. */
    struct {
        uint32_t  AWCACHE_LAST : 4; /*!< Configure the AWCACHE last transaction for DMA. */
        uint32_t  AWCACHE : 4;      /*!< Configure the AWCACHE transaction for DMA. */
        uint32_t  ARCACHE : 4;      /*!< Configure the ARCACHE last transaction for DMA. */
    } bitField;
    /*! Reserved. */
    uint32_t word;
}CCAximCacheParams_t;

/*! Structure holding the AXI configuration. */
typedef struct {
    CCAxiAceConst_t  AXIM_ACE_CONST;       /*!< List ACE configuration for the Secure AXI transactions. */
    CCAximCacheParams_t AXIM_CACHE_PARAMS; /*!< AXI master configuration for DMA. */
}CCAxiFields_t;


/*----------------------------
      PUBLIC FUNCTIONS
------------------------------*/



#ifdef __cplusplus
}
#endif

#endif /* _CC_AXI_CTRL_H*/

/**
@}
 */

