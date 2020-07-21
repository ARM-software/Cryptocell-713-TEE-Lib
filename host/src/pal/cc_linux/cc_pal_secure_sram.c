/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */


#include "cc_pal_types.h"
#include "cc_regs.h"
#include "cc_hal_plat.h"

#if defined(CC_PAL_CPU_CORTEX_A9) // ZYNQ
    /**
     * This assembly code was built for 'arm-br-7.3' toolchain
     */

    /**
     * @brief   Reads a word from a specific address in the secure SRAM and write it to a specific address in OTP or to a shadow register.
     *          The read of the word is done in-direct and the write of the word is implemented with inline assembler.
     *          It is implemented this way in order to bypass the stack and not leave in it parts of the secrets.
     *          An external loop need to call this API 4 times in a row
     *
     * @param[in] sramAddr    - TEE SRAM Word address
     * @param[in] destRegAddr - Shadow Register/OTP address
     *
     * @return None
     */
    void CC_PalCopyWordFromSecureSram(unsigned long srcRegAddr, unsigned long destRegAddr)
    {
        //Load from SRAM_DATA and store in destRegAddr
        __asm__ __volatile__("ldr r4, %1\n\t"   /* One word   */
                             "ldr r5, [r4]\n\t"
                             "ldr r4, %0\n\t"
                             "str r5, [r4]\n\t"
                             "dsb sy\n\t"
                            :"=m" (destRegAddr) /* 0 - Output */
                            :"m" (srcRegAddr), "m" (destRegAddr)   /* 1 - Input  */
                            :"r4","r5","memory" /* Clobbers   */
                            );
    }

    /**
     * @brief   Reads a word from a specific address in the secure SRAM and compares it to a specific input value.
     *          The read and compare of the word is implemented with inline assembler.
     *          It is implemented this way in order to bypass the stack and not leave in it parts of the secrets.
     *          An external loop need to call this API 4 times in a row
     *
     * @param[in] srcAddr  - TEE SRAM Word address
     * @param[in] cmpValue - Value to compare to.
     *
     * @return Comparison result: 0 or 1
     */
    uint32_t CC_PalIsSramWordValid(unsigned long srcAddr, uint32_t cmpValue)
    {
        uint32_t cmpFlag = 0;

        //Load from SRAM_DATA and compare to 'cmpValue'
        __asm__ __volatile__("ldr r7, %1\n\t"   /* Load SRAM Word value to r5 */
                             "ldr r5, [r7]\n\t"
                             "ldr r9, %2\n\t"   /* Load cmpValue value to r9 */
                             "cmp r5, r9\n\t"
                             "moveq r7, #1\n\t"
                             "movne r7, #0\n\t"
                             "str r7, %0\n\t"
                             "dsb sy\n\t"
                            :"=m" (cmpFlag)                /* 0 - Output */
                            :"m" (srcAddr), "m" (cmpValue) /* 1, 2 - Input  */
                            :"r7","r5","r9", "memory"      /* Clobbers   */
                            );
        return cmpFlag;
    }

    void CC_PalReadWordFromReg(unsigned long srcAddr)
    {
        //Read from srcAddr
        __asm__ __volatile__("ldr r4, %0\n\t"   /* One word   */
                             "ldr r5, [r4]\n\t"
                             "dsb sy\n\t"
                            :                   /* */
                            :"m" (srcAddr)      /* 0 - Input  */
                            :"r4","r5","memory" /* Clobbers   */
                            );
        return;
    }

#else // None
    #error You must implement an assembly code that supports your CPU and TOOLCHAIN
#endif
