/****************************************************************************
* The confidential and proprietary information contained in this file may   *
* only be used by a person authorised under and to the extent permitted     *
* by a subsisting licensing agreement from Arm Limited (or its affiliates). *
*     (C) COPYRIGHT [2018-2020] Arm Limited (or its affiliates).                 *
*         ALL RIGHTS RESERVED                                               *
* This entire notice must be reproduced on all copies of this file          *
* and copies of this file may only be made by a person if such person is    *
* permitted to do so under the terms of a subsisting license agreement      *
* from Arm Limited (or its affiliates).                                     *
*****************************************************************************/
#ifndef _TE_CPP_DOXYGEN_H
#define _TE_CPP_DOXYGEN_H

/*!
  @file
  @brief This file describes the CryptoCell CPP integration test flow.
*/

  /*!
    @addtogroup  cpp_test
  @{
  @details
  \section cpp_test_sec1 Generating the CPP test
  The following flow describes how to generate the CPP test:

  <li>Compile the code: Compiles the ccree module and compiles the TEE test with
  KCAPI lib</li>
  */
   /*!

  @addtogroup cpp_test

 \section cpp_test_sec2 The CPP test
  The following flow describes the CPP test flow:

  <ol><li>Before starting the test, load the ccree module.</li>
      <li>The test created a new TEE thread, the main thread function:
      <ol><li>Reads the IMR register, needs to make sure that REE operations
          interrupt is enabled.</li>
          <li>Disables Watchdog, the user can enable Watchdog and the Watchdog
          Timeout.</li>
          <li>Registers the TEE CPP handler function, which is called when
          TEE received the CPP interrupt. This function checks the validity of
          the operation. If approved, the function set the Stream ID and CPP
          key into the shadow registers.</li></ol></li>
      <li>The test uses the KCAPI to start REE CryptoCell operation with the CPP
      slot key.</li>
      <li>The REE sets interrupt to the TEE and the TEE CPP Handler approves or
      rejects the operation.</li>
	  <li>Unload the ccree module at the end of the test.</li>
		  </ol>
*/
/*! @}
*/



/**
@}
 */

#endif /* _TE_CPP_DOXYGEN_H */


