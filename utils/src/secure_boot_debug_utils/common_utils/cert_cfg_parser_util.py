#!/usr/local/bin/python3
#
# Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
#

import sys
import configparser
from global_defines import *
from cert_dbg_util_gen import *
from cert_basic_utilities import *
from cert_dbg_util_data import *
from flags_global_defines import *

# Parse given configuration file and return attributes as dictionary
def key_cert_config_file_parser(config_fname, log_file, ProjDict):

    try:
        config_file = open(config_fname, 'r')
    except IOError as e:
        print_and_log(log_file,"Failed opening " + config_fname + " (" + e.strerror + ")\n")
        sys.exit(e.errno)

    config = configparser.ConfigParser()
    config.readfp(config_file)
    config_file.close()

    local_dict = dict()

    # key config header name
    section_name = "KEY-CFG"
    if not config.has_section(section_name):
        print_and_log(log_file, "section " + section_name + " wasn't found in cfg file\n")
        return None, None

    # RSA keypair file
    if not config.has_option(section_name, 'cert-keypair'):
        print_and_log(log_file, "cert-keypair: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['cert_keypair'] = config.get(section_name, 'cert-keypair')
    log_sync(log_file,"cert-keypair: " + local_dict['cert_keypair'] + "\n")

    # RSA keypair passphrase (optional)
    if config.has_option(section_name, 'cert-keypair-pwd'):
        local_dict['cert_keypair_pwd'] = config.get(section_name, 'cert-keypair-pwd')
        log_sync(log_file,"cert-keypair-pwd: " + local_dict['cert_keypair_pwd'] + "\n")
    else:
        local_dict['cert_keypair_pwd'] = ''

    # OTP HBK ID
    if not config.has_option(section_name, 'hbk-id'):
        print_and_log(log_file, "hbk-id: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['hbk_id'] = int(config.get(section_name, 'hbk-id'))
    if (local_dict['hbk_id'] != int(0) and local_dict['hbk_id'] != int(1) and local_dict['hbk_id'] != int(2)) :
            log_sync(log_file, "Illegal hbk-id defined - exiting\n")
            return None, None
    log_sync(log_file,"hbk-id: " + str(local_dict['hbk_id']) + "\n")

    # NV counter value
    if not config.has_option(section_name, 'nvcounter-val'):
        print_and_log(log_file, "nvcounter-val: " + " wasn't found in cfg file\n")
        return None, None
    nvcounter_val = int(config.get(section_name, 'nvcounter-val'))
    nvcounter_word = nvcounter_val

    if ProjDict['is_iot_cert'] == 0:
        # NV counter ID (supported only for cc7x)
        if not config.has_option(section_name, 'nvcounter-id'):
            print_and_log(log_file, "nvcounter-id: " + " wasn't found in cfg file\n")
            return None, None
        nvcounter_id = int(config.get(section_name, 'nvcounter-id'))
        if (nvcounter_id != int(0) and nvcounter_id != int(1)) :
            log_sync(log_file, "Illegal nvcounter_id - exiting\n")
            return None, None
        # set max value per NV counter id
        if nvcounter_id == int(0):
            maxVal = SW_REVOCATION_MAX_NUM_OF_BITS_SECURE
        else:
            maxVal = SW_REVOCATION_MAX_NUM_OF_BITS_NON_SECURE
        nvcounter_word = nvcounter_word | (nvcounter_id << NVCOUNTER_ID_OFFSET_BIT_POS)
    else:
        # set max value per HBK (case cc3x)
        if local_dict['hbk_id'] == int(0):
            maxVal = SW_REVOCATION_MAX_NUM_OF_BITS_HBK0
        else:
            if local_dict['hbk_id'] == int(1):
                maxVal = SW_REVOCATION_MAX_NUM_OF_BITS_HBK1
            else:
                maxVal = SW_REVOCATION_MAX_NUM_OF_BITS_HBK2

    if (nvcounter_val > maxVal):
        log_sync(log_file, "Ilegal nvcounter-val\n")
        return None, None
    local_dict['nvcounter_word'] = nvcounter_word
    log_sync(log_file,"nvcounter_word: " + str(local_dict['nvcounter_word']) + "\n")

    # additional data file
    if ProjDict['is_add_data'] == 1:
        if not config.has_option(section_name, 'add-data'):
            print_and_log(log_file, "add-data: " + " wasn't found in cfg file\n")
            return None, None
        local_dict['add_data'] = config.get(section_name, 'add-data')
        log_sync(log_file,"add_data: " + local_dict['add_data'] + "\n")
    else:
        local_dict['add_data'] = ''

    # RSA public key for next certificate in chain
    if not config.has_option(section_name, 'next-cert-pubkey'):
        print_and_log(log_file, "next-cert-pubkey: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['next_cert_pubkey'] = config.get(section_name, 'next-cert-pubkey')
    log_sync(log_file,"next-cert-pubkey: " + local_dict['next_cert_pubkey'] + "\n")

    # certificate output file name
    if not config.has_option(section_name, 'cert-pkg'):
        print_and_log(log_file, "cert-pkg: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['cert_pkg'] = config.get(section_name, 'cert-pkg')
    log_sync(log_file,"cert-pkg: " + local_dict['cert_pkg'] + "\n")

    return local_dict, config

# Parse given configuration file and return attributes as dictionary
def content_cert_config_file_parser (config_fname, log_file, ProjDict):

    try:
        config_file = open(config_fname, 'r')
    except IOError as e:
        print_and_log(log_file,"Failed opening " + config_fname + " (" + e.strerror + ")\n")
        sys.exit(e.errno)

    config = configparser.ConfigParser()
    config.readfp(config_file)
    config_file.close()

    local_dict = dict()

    # content config header name
    section_name = "CNT-CFG"
    if not config.has_section(section_name):
        print_and_log(log_file, "section " + section_name + " wasn't found in cfg file\n")
        return None, None

    # RSA keypair file
    if not config.has_option(section_name, 'cert-keypair'):
        print_and_log(log_file, "cert-keypair: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['cert_keypair'] = config.get(section_name, 'cert-keypair')
    log_sync(log_file,"cert-keypair: " + local_dict['cert_keypair'] + "\n")

    # RSA keypair passphrase (optional)
    if config.has_option(section_name, 'cert-keypair-pwd'):
        local_dict['cert_keypair_pwd'] = config.get(section_name, 'cert-keypair-pwd')
        log_sync(log_file,"cert-keypair-pwd: " + local_dict['cert_keypair_pwd'] + "\n")
    else:
        local_dict['cert_keypair_pwd'] = ''

    if ProjDict['is_iot_cert'] == 0:
        # OTP HBK ID (supported only for cc7x)
        if not config.has_option(section_name, 'hbk-id'):
            print_and_log(log_file, "hbk-id: " + " wasn't found in cfg file\n")
            return None, None
        local_dict['hbk_id'] = int(config.get(section_name, 'hbk-id'))
        if (local_dict['hbk_id'] != int(0) and local_dict['hbk_id'] != int(1) and local_dict['hbk_id'] != int(2)) :
                log_sync(log_file, "Illegal hbk-id defined - exiting\n")
                return None, None
    else:
        local_dict['hbk_id'] = int('0xf',16)
    log_sync(log_file,"hbk-id: " + str(local_dict['hbk_id']) + "\n")

    # NV counter value
    if not config.has_option(section_name, 'nvcounter-val'):
        print_and_log(log_file, "nvcounter-val: " + " wasn't found in cfg file\n")
        return None, None
    nvcounter_val = int(config.get(section_name, 'nvcounter-val'))
    nvcounter_word = nvcounter_val

    if ProjDict['is_iot_cert'] == 0:
        # NV counter ID (supported only for cc7x)
        if not config.has_option(section_name, 'nvcounter-id'):
            print_and_log(log_file, "nvcounter-id: " + " wasn't found in cfg file\n")
            return None, None
        nvcounter_id = int(config.get(section_name, 'nvcounter-id'))
        if (nvcounter_id != int(0) and nvcounter_id != int(1)) :
            log_sync(log_file, "Illegal nvcounter_id - exiting\n")
            return None, None
        # set max value per NV counter id
        if nvcounter_id == int(0):
            maxVal = SW_REVOCATION_MAX_NUM_OF_BITS_SECURE
        else:
            maxVal = SW_REVOCATION_MAX_NUM_OF_BITS_NON_SECURE
        nvcounter_word = nvcounter_word | (nvcounter_id << NVCOUNTER_ID_OFFSET_BIT_POS)
    else:
        # case 3x: verify nvcounter_val according to maximum HBK size
        maxVal = SW_REVOCATION_MAX_NUM_OF_BITS_HBK2

    if (nvcounter_val > maxVal):
        log_sync(log_file, "Ilegal nvcounter-val\n")
        return None, None
    local_dict['nvcounter_word'] = nvcounter_word
    log_sync(log_file,"nvcounter_word: " + str(local_dict['nvcounter_word']) + "\n")

    # image verification scheme indication
    if not config.has_option(section_name, 'load-verify-scheme'):
        print_and_log(log_file, "load-verify-scheme: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['load_verify_scheme'] = int(config.get(section_name, 'load-verify-scheme'))
    if (local_dict['load_verify_scheme'] != int(0) and local_dict['load_verify_scheme'] != int(1) and local_dict['load_verify_scheme'] != int(2) and local_dict['load_verify_scheme'] != int(3)) :
            log_sync(log_file, "Illegal load_verify_scheme defined - exiting\n")
            return None, None
    log_sync(log_file,"load-verify-scheme: " + str(local_dict['load_verify_scheme']) + "\n")

    # SW image encryption key type
    if not config.has_option(section_name, 'aes-ce-id'):
        print_and_log(log_file, "aes-ce-id: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['aes_ce_id'] = int(config.get(section_name, 'aes-ce-id'))
    if (local_dict['aes_ce_id'] != int(0) and local_dict['aes_ce_id'] != int(1) and local_dict['aes_ce_id'] != int(2)):
            log_sync(log_file, "Illegal aes_ce_id defined - exiting\n")
            return None, None
    log_sync(log_file,"aes-ce-id: " + str(local_dict['aes_ce_id']) + "\n")

    if (local_dict['aes_ce_id'] != int(0)):
        # SW image encryption key file
        if not config.has_option(section_name, 'aes-enc-key'):
            print_and_log(log_file, "aes-enc-key: " + " wasn't found in cfg file\n")
            return None, None
        local_dict['aes_enc_key'] = config.get(section_name, 'aes-enc-key')
        log_sync(log_file,"aes-enc-key: " + local_dict['aes_enc_key'] + "\n")
        # SW image cryptographic verification & encryption mode
        if not config.has_option(section_name, 'crypto-type'):
            print_and_log(log_file, "crypto-type: " + " wasn't found in cfg file\n")
            return None, None
        local_dict['crypto_type'] = int(config.get(section_name, 'crypto-type'))
        if (local_dict['crypto_type'] != int(0) and local_dict['crypto_type'] != int(1)) :
                log_sync(log_file, "Illegal crypto_type defined - exiting\n")
                return None, None
    else:
        local_dict['aes_enc_key'] = None
        local_dict['crypto_type'] = int(0)
    log_sync(log_file,"aes_enc_key: " + str(local_dict['aes_enc_key']) + "\n")
    log_sync(log_file,"crypto-type: " + str(local_dict['crypto_type']) + "\n")

    # SW image table file
    if not config.has_option(section_name, 'images-table'):
        print_and_log(log_file, "images-table: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['images_table'] = config.get(section_name, 'images-table')
    log_sync(log_file,"images-table: " + local_dict['images_table'] + "\n")

    # additional data file
    if ProjDict['is_add_data'] == 1:
        if not config.has_option(section_name, 'add-data'):
            print_and_log(log_file, "add-data: " + " wasn't found in cfg file\n")
            return None, None
        local_dict['add_data'] = config.get(section_name, 'add-data')
        log_sync(log_file,"add_data: " + local_dict['add_data'] + "\n")
    else:
        local_dict['add_data'] = ''

    # certificate output file name
    if not config.has_option(section_name, 'cert-pkg'):
        print_and_log(log_file, "cert-pkg: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['cert-pkg'] = config.get(section_name, 'cert-pkg')
    log_sync(log_file,"cert-pkg: " + local_dict['cert-pkg'] + "\n")

    return local_dict, config


# Parse given test configuration file and return test attributes as dictionary
def enabler_cert_config_file_parser (config_fname, log_file, ProjDict):

    try:
        config_file = open(config_fname, 'r')
    except IOError as e:
        print_and_log(log_file,"Failed opening " + config_fname + " (" + e.strerror + ")\n")
        sys.exit(e.errno)

    config = configparser.ConfigParser()
    config.readfp(config_file)
    config_file.close()

    local_dict = dict()

    # enabler config header name
    section_name = "ENABLER-DBG-CFG"
    if not config.has_section(section_name):
        log_sync(log_file, "section " + section_name + " wasn't found in cfg file\n")
        return None, None

    is_debug = 0
    if config.has_option(section_name, 'debug-mask[0-31]'):
        debug_mask0 = int(config.get(section_name, 'debug-mask[0-31]'), 16)
        debug_mask1 = int(config.get(section_name, 'debug-mask[32-63]'), 16)
        debug_mask2 = int(config.get(section_name, 'debug-mask[64-95]'), 16)
        debug_mask3 = int(config.get(section_name, 'debug-mask[96-127]'), 16)

        debug_lock0 = int(config.get(section_name, 'debug-lock[0-31]'), 16)
        debug_lock1 = int(config.get(section_name, 'debug-lock[32-63]'), 16)
        debug_lock2 = int(config.get(section_name, 'debug-lock[64-95]'), 16)
        debug_lock3 = int(config.get(section_name, 'debug-lock[96-127]'), 16)
        is_debug = 1

    is_rma = 0
    if config.has_option(section_name, 'rma-mode'):
        rma_mode = int(config.get(section_name, 'rma-mode'))
        if rma_mode != int(0):
            log_sync(log_file, "rma_mode " + str(rma_mode) + "\n")
            is_rma = 1

    is_hbk = 0
    if config.has_option(section_name, 'hbk-id'):
        hbk_id = int(config.get(section_name, 'hbk-id'))
        if (hbk_id == int(0) or hbk_id == int(1) or hbk_id == int(2)):
                log_sync(log_file, "hbk_id " + str(hbk_id) + "\n")
                is_hbk = 1
        else:
            log_sync(log_file, "Invalid HBK ID - exiting\n")
            return None, None


    is_key_pkg = 0
    if config.has_option(section_name, 'key-cert-pkg'):
        key_pkg = config.get(section_name, 'key-cert-pkg')
        log_sync(log_file, "key_pkg " + key_pkg + "\n")
        is_key_pkg = 1

    if is_rma == 1  and is_debug == 1:
        log_sync(log_file, "Both RMA and debug mode are defined - exiting\n")
        return None, None
    if is_rma == 0 and is_debug == 0:
        log_sync(log_file, "RMA nor Debug mode not defined - exiting\n")
        return None, None

    if is_key_pkg == 0 and is_hbk == 0:
        log_sync(log_file, "hbk-id nor key-cert-pkg not defined - exiting\n")
        return None, None

    if is_key_pkg == 1 and is_hbk == 1:
        log_sync(log_file, "hbk-id and key-cert-pkg defined - exiting\n")
        return None, None


    local_dict['debug_mask0'] = int(0)
    local_dict['debug_mask1'] = int(0)
    local_dict['debug_mask2'] = int(0)
    local_dict['debug_mask3'] = int(0)
    local_dict['debug_lock0'] = int(0)
    local_dict['debug_lock1'] = int(0)
    local_dict['debug_lock2'] = int(0)
    local_dict['debug_lock3'] = int(0)
    local_dict['rma_mode'] = int(0)
    local_dict['hbk_id'] = int(0xF)
    local_dict['key_cert_pkg'] = ""

    if is_debug == 1:
        local_dict['debug_mask0'] = debug_mask0
        log_sync(log_file,"debug-mask0: " + str(local_dict['debug_mask0']) + "\n")
        local_dict['debug_mask1'] = debug_mask1
        log_sync(log_file,"debug-mask1: " + str(local_dict['debug_mask1']) + "\n")
        local_dict['debug_mask2'] = debug_mask2
        log_sync(log_file,"debug-mask2: " + str(local_dict['debug_mask2']) + "\n")
        local_dict['debug_mask3'] = debug_mask3
        log_sync(log_file,"debug-mask3: " + str(local_dict['debug_mask3']) + "\n")
        local_dict['debug_lock0'] = debug_lock0
        log_sync(log_file,"debug-lock0: " + str(local_dict['debug_lock0']) + "\n")
        local_dict['debug_lock1'] = debug_lock1
        log_sync(log_file,"debug-lock1: " + str(local_dict['debug_lock1']) + "\n")
        local_dict['debug_lock2'] = debug_lock2
        log_sync(log_file,"debug-lock2: " + str(local_dict['debug_lock2']) + "\n")
        local_dict['debug_lock3'] = debug_lock3
        log_sync(log_file,"debug-lock3: " + str(local_dict['debug_lock3']) + "\n")

    if is_hbk == 1:
        local_dict['hbk_id'] = hbk_id
        log_sync(log_file,"hbk-id: " + str(local_dict['hbk_id']) + "\n")

    if is_key_pkg == 1:
        local_dict['key_cert_pkg'] = key_pkg

    if is_rma == 1:
        local_dict['rma_mode'] = int(1)
        log_sync(log_file,"rma-mode: " + str(local_dict['rma_mode']) + "\n")

    # RSA keypair file
    if not config.has_option(section_name, 'cert-keypair'):
        print_and_log(log_file, "cert-keypair: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['cert_keypair'] = config.get(section_name, 'cert-keypair')
    log_sync(log_file,"cert-keypair: " + str(local_dict['cert_keypair']) + "\n")

    # RSA keypair passphrase (optional)
    if config.has_option(section_name, 'cert-keypair-pwd'): #used for testing
        local_dict['cert_keypair_pwd'] = config.get(section_name, 'cert-keypair-pwd')
        log_sync(log_file,"cert-keypair-pwd: " + str(local_dict['cert_keypair_pwd']) + "\n")
    else:
        local_dict['cert_keypair_pwd'] = ''

    # LCS
    if not config.has_option(section_name, 'lcs'):
        print_and_log(log_file, "lcs: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['lcs'] = int(config.get(section_name, 'lcs'))
    log_sync(log_file,"lcs: " + str(local_dict['lcs']) + "\n")
    if local_dict['lcs'] == int(0):
        local_dict['lcs'] = CC_MNG_CHIP_MANUFACTURE_LCS
    elif local_dict['lcs'] == int(1):
        local_dict['lcs'] = CC_MNG_DEVICE_MANUFACTURE_LCS
    elif local_dict['lcs'] == int(5):
        local_dict['lcs'] = CC_MNG_SECURE_LCS
    elif local_dict['lcs'] == int(7):
        local_dict['lcs'] = CC_MNG_RMA_LCS
    else:
        log_sync(log_file, "Ilegal lcs defined - exiting\n")
        return None, None

    # additional data file
    if ProjDict['is_add_data'] == 1:
        if not config.has_option(section_name, 'add-data'):
            print_and_log(log_file, "add-data: " + " wasn't found in cfg file\n")
            return None, None
        local_dict['add_data'] = config.get(section_name, 'add-data')
        log_sync(log_file,"add_data: " + local_dict['add_data'] + "\n")
    else:
        local_dict['add_data'] = ''

    # RSA public key for next certificate in chain
    if not config.has_option(section_name, 'next-cert-pubkey'):
        print_and_log(log_file, "next-cert-pubkey: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['next_cert_pubkey'] = config.get(section_name, 'next-cert-pubkey')
    log_sync(log_file,"next-cert-pubkey: " + str(local_dict['next_cert_pubkey']) + "\n")

    # certificate output file name
    if not config.has_option(section_name, 'cert-pkg'):
        print_and_log(log_file, "cert-pkg: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['cert_pkg'] = str.encode(config.get(section_name, 'cert-pkg'))
    log_sync(log_file,"cert-pkg: " + str(local_dict['cert_pkg']) + "\n")

    return local_dict, config


# Parse given test configuration file and return test attributes as dictionary
def developer_cert_config_file_parser (config_fname, log_file, ProjDict):
    try:
        config_file = open(config_fname, 'r')
    except IOError as e:
        print_and_log(log_file,"Failed opening " + config_fname + " (" + e.strerror + ")\n")
        sys.exit(e.errno)

    config = configparser.ConfigParser()
    config.readfp(config_file)
    config_file.close()

    local_dict = dict()

    # developer config header name
    section_name = "DEVELOPER-DBG-CFG"
    if not config.has_section(section_name):
        log_sync(log_file, "section " + section_name + " wasn't found in cfg file\n")
        return None, None

    # RSA keypair file
    if not config.has_option(section_name, 'cert-keypair'):
        print_and_log(log_file, "cert-keypair: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['cert_keypair'] = config.get(section_name, 'cert-keypair')
    log_sync(log_file,"cert-keypair: " + str(local_dict['cert_keypair']) + "\n")

    # RSA keypair passphrase (optional)
    if config.has_option(section_name, 'cert-keypair-pwd'): #used for testing
        local_dict['cert_keypair_pwd'] = config.get(section_name, 'cert-keypair-pwd')
        log_sync(log_file,"cert-keypair-pwd: " + str(local_dict['cert_keypair_pwd']) + "\n")
    else:
        local_dict['cert_keypair_pwd'] = ''

    # SOC ID file
    if not config.has_option(section_name, 'soc-id'):
        print_and_log(log_file, "soc-id: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['soc_id'] = config.get(section_name, 'soc-id')
    log_sync(log_file,"soc-id: " + local_dict['soc_id'] + "\n")

    # DCU mask bits (optional)
    if not config.has_option(section_name, 'debug-mask[0-31]'):
        print_and_log(log_file, "debug-mask[0-31]: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['debug_mask0'] = int(config.get(section_name, 'debug-mask[0-31]'), 16)
    log_sync(log_file,"debug-mask0: " + str(local_dict['debug_mask0']) + "\n")
    if not config.has_option(section_name, 'debug-mask[32-63]'):
        print_and_log(log_file, "debug-mask[32-63]: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['debug_mask1'] = int(config.get(section_name, 'debug-mask[32-63]'), 16)
    log_sync(log_file,"debug-mask1: " + str(local_dict['debug_mask1']) + "\n")
    if not config.has_option(section_name, 'debug-mask[64-95]'):
        print_and_log(log_file, "debug-mask[64-95]: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['debug_mask2'] = int(config.get(section_name, 'debug-mask[64-95]'), 16)
    log_sync(log_file,"debug-mask2: " + str(local_dict['debug_mask2']) + "\n")
    if not config.has_option(section_name, 'debug-mask[96-127]'):
        print_and_log(log_file, "debug-mask[96-127]: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['debug_mask3'] = int(config.get(section_name, 'debug-mask[96-127]'), 16)
    log_sync(log_file,"debug-mask3: " + str(local_dict['debug_mask3']) + "\n")

    # additional data file
    if ProjDict['is_add_data'] == 1:
        if not config.has_option(section_name, 'add-data'):
            print_and_log(log_file, "add-data: " + " wasn't found in cfg file\n")
            return None, None
        local_dict['add_data'] = config.get(section_name, 'add-data')
        log_sync(log_file,"add_data: " + local_dict['add_data'] + "\n")
    else:
        local_dict['add_data'] = ''

    # enabler certificate package name
    if not config.has_option(section_name, 'enabler-cert-pkg'):
        print_and_log(log_file, "enabler_cert_pkg: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['enabler_cert_pkg'] = config.get(section_name, 'enabler-cert-pkg')
    log_sync(log_file,"enabler-cert-pkg: " + str(local_dict['enabler_cert_pkg']) + "\n")

    # certificate output file name
    if not config.has_option(section_name, 'cert-pkg'):
        print_and_log(log_file, "cert-pkg: " + " wasn't found in cfg file\n")
        return None, None
    local_dict['cert_pkg'] = config.get(section_name, 'cert-pkg')
    log_sync(log_file,"cert-pkg: " + str(local_dict['cert_pkg']) + "\n")

    return local_dict, config


# build flags word
# accordinf to EnablerFlags_t
def build_flag_word_enabler (isRmaCert, hbkId, lcsId):
    flag = 0x00000000
    flag = flag + (hbkId << HBK_ID_FLAG_BIT_OFFSET)
    flag = flag + (lcsId << LCS_ID_FLAG_BIT_OFFSET)
    flag = flag + (isRmaCert << RMA_CERT_FLAG_BIT_OFFSET)

    return flag
# End of build_flag_word_enabler

# build flags word
# accordinf to EnablerFlags_t
def build_flag_word_developer ():
    flag = 0x00000000

    return flag
# End of build_flag_word_enabler


# the function builds the certificate header, header contains token, version, flags, length
def build_certificate_header (log_file, token, ProjDict, LIST_OF_CONF_PARAMS, isRmaCert, hbkId, lcsId, userAddDataFile):

    certVersion = ProjDict['cert_version']
    if userAddDataFile == '':
        certLength = 0
    else:
        certLength = USER_ADDITIONAL_DATA_SIZE_IN_BYTES
    certLength = certLength + HEADER_SIZE_IN_BYTES # token + version + length + flags
    certLength = certLength + PUBKEY_SIZE_BYTES + NP_SIZE_IN_BYTES # certificate public key + Np

    if token == DEBUG_ENABLER_TOKEN:
        certLength = certLength  + 4*BYTES_WITHIN_WORD + 4*BYTES_WITHIN_WORD + SHA_256_HASH_SIZE_IN_BYTES  #debug mask + debug lock + developer pubKey hash
        flag = build_flag_word_enabler(isRmaCert, hbkId, lcsId)
    else:
        certLength = certLength + 4*BYTES_WITHIN_WORD + SOC_ID_SIZE_IN_BYTES   #debug mask + socId
        flag = build_flag_word_developer()

    certLength = (certLength >> 2)  # size in certificate is word size
    addDataStrBin = bytes()
    if ProjDict['is_add_data'] == 1:
        if userAddDataFile == '':
            print_and_log(log_file, "userAddDataFile: is missing\n")
            return None
        addDataStrBin = GetDataFromBinFile(log_file, userAddDataFile)
        if (len(addDataStrBin) != USER_ADDITIONAL_DATA_SIZE_IN_BYTES):
            print_and_log(log_file, "userAddDataFile size: is unsupported\n")
            return None

    headerStrBin = struct.pack('<I', token) + struct.pack('<I', certVersion) + struct.pack('<I', certLength) + struct.pack('<I', flag)
    addDataStrBin = byte2string(addDataStrBin + headerStrBin)

    return addDataStrBin
# End of build_certificate_header
