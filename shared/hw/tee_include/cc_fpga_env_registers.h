/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 *
 */

#ifndef __CC_FPGA_ENV_REGISTERS_H__
#define __CC_FPGA_ENV_REGISTERS_H__

// --------------------------------------
// BLOCK: FPGA_ENV_REGS
// --------------------------------------
#define CC_ENV_FPGA_CC_HOST_INT_REG_OFFSET 	0x00A0UL
#define CC_ENV_FPGA_CC_HOST_INT_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_CC_HOST_INT_VALUE_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_CC_PUB_HOST_INT_REG_OFFSET 	0x00A4UL
#define CC_ENV_FPGA_CC_PUB_HOST_INT_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_CC_PUB_HOST_INT_VALUE_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_CC_RST_N_REG_OFFSET 	0x00A8UL
#define CC_ENV_FPGA_CC_RST_N_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_CC_RST_N_VALUE_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_ROSC_RST_N_REG_OFFSET 	0x00ACUL
#define CC_ENV_FPGA_ROSC_RST_N_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_ROSC_RST_N_VALUE_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_CC_POR_N_ADDR_REG_OFFSET 	0x00E0UL
#define CC_ENV_FPGA_CC_POR_N_ADDR_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_CC_POR_N_ADDR_VALUE_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_CC_COLD_RST_REG_OFFSET 	0x00FCUL
#define CC_ENV_FPGA_CC_COLD_RST_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_CC_COLD_RST_VALUE_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_DUMMY_ADDR_REG_OFFSET 	0x0108UL
#define CC_ENV_FPGA_DUMMY_ADDR_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_DUMMY_ADDR_VALUE_BIT_SIZE 	0x20UL
#define CC_ENV_FPGA_COUNTER_CLR_REG_OFFSET 	0x0118UL
#define CC_ENV_FPGA_COUNTER_CLR_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_COUNTER_CLR_VALUE_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_COUNTER_RD_REG_OFFSET 	0x011CUL
#define CC_ENV_FPGA_COUNTER_RD_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_COUNTER_RD_VALUE_BIT_SIZE 	0x20UL
#define CC_ENV_FPGA_CC_LCS_REG_OFFSET 	0x043CUL
#define CC_ENV_FPGA_CC_LCS_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_CC_LCS_VALUE_BIT_SIZE 	0x8UL
#define CC_ENV_FPGA_CC_LCS_IS_VALID_REG_OFFSET 	0x0448UL
#define CC_ENV_FPGA_CC_LCS_IS_VALID_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_CC_LCS_IS_VALID_VALUE_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_VERSION_REG_OFFSET 	0x0488UL
#define CC_ENV_FPGA_VERSION_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_VERSION_VALUE_BIT_SIZE 	0x20UL
#define CC_ENV_FPGA_ROSC_WRITE_REG_OFFSET 	0x048CUL
#define CC_ENV_FPGA_ROSC_WRITE_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_ROSC_WRITE_VALUE_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_ROSC_ADDR_REG_OFFSET 	0x0490UL
#define CC_ENV_FPGA_ROSC_ADDR_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_ROSC_ADDR_VALUE_BIT_SIZE 	0x8UL
#define CC_ENV_FPGA_AXIM_USER_PARAMS_REG_OFFSET 	0x0600UL
#define CC_ENV_FPGA_AXIM_USER_PARAMS_ARUSER_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_AXIM_USER_PARAMS_ARUSER_BIT_SIZE 	0x5UL
#define CC_ENV_FPGA_AXIM_USER_PARAMS_AWUSER_BIT_SHIFT 	0x5UL
#define CC_ENV_FPGA_AXIM_USER_PARAMS_AWUSER_BIT_SIZE 	0x5UL
#define CC_ENV_FPGA_SECURITY_MODE_OVERRIDE_REG_OFFSET 	0x0604UL
#define CC_ENV_FPGA_SECURITY_MODE_OVERRIDE_AWPROT_NS_BIT_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_SECURITY_MODE_OVERRIDE_AWPROT_NS_BIT_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_SECURITY_MODE_OVERRIDE_AWPROT_NS_OVERRIDE_BIT_SHIFT 	0x1UL
#define CC_ENV_FPGA_SECURITY_MODE_OVERRIDE_AWPROT_NS_OVERRIDE_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_SECURITY_MODE_OVERRIDE_ARPROT_NS_BIT_BIT_SHIFT 	0x2UL
#define CC_ENV_FPGA_SECURITY_MODE_OVERRIDE_ARPROT_NS_BIT_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_SECURITY_MODE_OVERRIDE_ARPROT_NS_OVERRIDE_BIT_SHIFT 	0x3UL
#define CC_ENV_FPGA_SECURITY_MODE_OVERRIDE_ARPROT_NS_OVERRIDE_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_APB_FIPS_ADDR_REG_OFFSET 	0x0650UL
#define CC_ENV_FPGA_APB_FIPS_ADDR_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_APB_FIPS_ADDR_VALUE_BIT_SIZE 	0xCUL
#define CC_ENV_FPGA_APB_FIPS_VAL_REG_OFFSET 	0x0654UL
#define CC_ENV_FPGA_APB_FIPS_VAL_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_APB_FIPS_VAL_VALUE_BIT_SIZE 	0x20UL
#define CC_ENV_FPGA_APB_FIPS_MASK_REG_OFFSET 	0x0658UL
#define CC_ENV_FPGA_APB_FIPS_MASK_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_APB_FIPS_MASK_VALUE_BIT_SIZE 	0x20UL
#define CC_ENV_FPGA_APB_FIPS_CNT_REG_OFFSET 	0x065CUL
#define CC_ENV_FPGA_APB_FIPS_CNT_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_APB_FIPS_CNT_VALUE_BIT_SIZE 	0x20UL
#define CC_ENV_FPGA_APB_FIPS_NEW_ADDR_REG_OFFSET 	0x0660UL
#define CC_ENV_FPGA_APB_FIPS_NEW_ADDR_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_APB_FIPS_NEW_ADDR_VALUE_BIT_SIZE 	0xCUL
#define CC_ENV_FPGA_APB_FIPS_NEW_VAL_REG_OFFSET 	0x0664UL
#define CC_ENV_FPGA_APB_FIPS_NEW_VAL_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_APB_FIPS_NEW_VAL_VALUE_BIT_SIZE 	0x20UL
#define CC_ENV_FPGA_APBS_PPROT_OVERRIDE_REG_OFFSET      0x0668UL
#define CC_ENV_FPGA_APBS_PPROT_OVERRIDE_VALUE_BIT_SHIFT   0x0UL
#define CC_ENV_FPGA_APBS_PPROT_OVERRIDE_VALUE_BIT_SIZE    0x3UL
#define CC_ENV_FPGA_APBS_PPROT_OVERRIDE_CNTRL_BIT_SHIFT   0x3UL
#define CC_ENV_FPGA_APBS_PPROT_OVERRIDE_CNTRL_BIT_SIZE    0x1UL
#define CC_ENV_FPGA_APBP_FIPS_ADDR_REG_OFFSET 	0x0670UL
#define CC_ENV_FPGA_APBP_FIPS_ADDR_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_APBP_FIPS_ADDR_VALUE_BIT_SIZE 	0xCUL
#define CC_ENV_FPGA_APBP_FIPS_VAL_REG_OFFSET 	0x0674UL
#define CC_ENV_FPGA_APBP_FIPS_VAL_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_APBP_FIPS_VAL_VALUE_BIT_SIZE 	0x20UL
#define CC_ENV_FPGA_APBP_FIPS_MASK_REG_OFFSET 	0x0678UL
#define CC_ENV_FPGA_APBP_FIPS_MASK_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_APBP_FIPS_MASK_VALUE_BIT_SIZE 	0x20UL
#define CC_ENV_FPGA_APBP_FIPS_CNT_REG_OFFSET 	0x067CUL
#define CC_ENV_FPGA_APBP_FIPS_CNT_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_APBP_FIPS_CNT_VALUE_BIT_SIZE 	0x20UL
#define CC_ENV_FPGA_APBP_FIPS_NEW_ADDR_REG_OFFSET 	0x0680UL
#define CC_ENV_FPGA_APBP_FIPS_NEW_ADDR_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_APBP_FIPS_NEW_ADDR_VALUE_BIT_SIZE 	0xCUL
#define CC_ENV_FPGA_APBP_FIPS_NEW_VAL_REG_OFFSET 	0x0684UL
#define CC_ENV_FPGA_APBP_FIPS_NEW_VAL_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_APBP_FIPS_NEW_VAL_VALUE_BIT_SIZE 	0x20UL
#define CC_ENV_FPGA_APBP_PPROT_OVERRIDE_REG_OFFSET      0x0688UL
#define CC_ENV_FPGA_APBP_PPROT_OVERRIDE_VALUE_BIT_SHIFT   0x0UL
#define CC_ENV_FPGA_APBP_PPROT_OVERRIDE_VALUE_BIT_SIZE    0x3UL
#define CC_ENV_FPGA_APBP_PPROT_OVERRIDE_CNTRL_BIT_SHIFT   0x3UL
#define CC_ENV_FPGA_APBP_PPROT_OVERRIDE_CNTRL_BIT_SIZE    0x1UL
#define CC_ENV_FPGA_CC_STATIC_CONFIGURATION_REG_OFFSET 	0x0710UL
#define CC_ENV_FPGA_USER_OTP_FILTERING_DISABLE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_USER_OTP_FILTERING_DISABLE_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_CC_SLIM_BIT_SHIFT 	0x1UL
#define CC_ENV_FPGA_CC_SLIM_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_SG_NPWRUP_BIT_SHIFT 0x2UL
#define CC_ENV_FPGA_SG_NPWRUP_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_NVM_APB_PSLVERR_EN_REG_OFFSET 	0x0714UL
#define CC_ENV_FPGA_NVM_APB_PSLVERR_EN_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_NVM_APB_PSLVERR_EN_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_NVM_APB_PSLVERR_REG_OFFSET 	0x0718UL
#define CC_ENV_FPGA_NVM_APB_PSLVERR_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_NVM_APB_PSLVERR_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_AO_FATAL_ERR_REG_OFFSET 	0x0720UL
#define CC_ENV_FPGA_AO_FATAL_ERR_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_AO_FATAL_ERR_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_AXIM_ARSTREAMID_REG_OFFSET 	0x0724UL
#define CC_ENV_FPGA_ARSTREAMID_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_ARSTREAMID_BIT_SIZE 	0x10UL
#define CC_ENV_FPGA_AXIM_AWSTREAMID_REG_OFFSET 	0x0728UL
#define CC_ENV_FPGA_AWSTREAMID_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_AWSTREAMID_BIT_SIZE 	0x10UL
#define CC_ENV_FPGA_PUB_HOST_INT_REQ_REG_OFFSET	0x0730UL
#define CC_ENV_FPGA_PUB_HOST_INT_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_PUB_HOST_INT_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_QREQN_REG_OFFSET	        0x0740UL
#define CC_ENV_FPGA_QREQN_BIT_SHIFT 		0x0UL
#define CC_ENV_FPGA_QREQN_BIT_SIZE 		0x1UL
#define CC_ENV_FPGA_QACCEPTN_REG_OFFSET	        0x0744UL
#define CC_ENV_FPGA_QACCEPTN_BIT_SHIFT 		0x0UL
#define CC_ENV_FPGA_QACCEPTN_BIT_SIZE 		0x1UL
#define CC_ENV_FPGA_QDENY_REG_OFFSET	        0x0748UL
#define CC_ENV_FPGA_QDENY_BIT_SHIFT 		0x0UL
#define CC_ENV_FPGA_QDENY_BIT_SIZE 		0x1UL
#define CC_ENV_FPGA_QACTIVE_REG_OFFSET	        0x074CUL
#define CC_ENV_FPGA_QACTIVE_BIT_SHIFT 		0x0UL
#define CC_ENV_FPGA_QACTIVE_BIT_SIZE 		0x1UL
#define CC_ENV_FPGA_SP_RST_REQ_REG_OFFSET 	0x0750UL
#define CC_ENV_FPGA_SP_RST_REQ_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_SP_RST_REQ_VALUE_BIT_SIZE 	0x1UL
#define CC_ENV_FPGA_SP_RST_EN_REG_OFFSET 	0x0754UL
#define CC_ENV_FPGA_SP_RST_EN_VALUE_BIT_SHIFT 	0x0UL
#define CC_ENV_FPGA_SP_RST_EN_VALUE_BIT_SIZE 	0x1UL

#endif	/* __CC_FPGA_ENV_REGISTERS_H__ */
