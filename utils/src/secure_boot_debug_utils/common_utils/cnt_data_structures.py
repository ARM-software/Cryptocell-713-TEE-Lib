#!/usr/local/bin/python3
#
# Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
#


import struct
import math
import sys, traceback
from global_defines import *
from flags_global_defines import *
from hash_basic_utility import *
from ctypes import *
from cert_basic_utilities import *

####################################################################
# Filename - datastructures.py
# Description - This file contains the data structures used in the
#               SB utility
####################################################################


# The ReverseBytesInString function reverse the bytes in a string and returns the reversed string
def tempReverseBytesInBytesArray(array, size):

    reversedArray = c_ubyte * size
    revArray = reversedArray()
    for i in range(size//4):
        # reverse each word
        for j in range(4):
            revArray[4*i + j] = array[4*i + 3 - j]
    return revArray
# End of ReverseBytesInString


# This class represent a record info structure. It includes the SW image destination address,
# the Size of the record, the place holder and the HASH result
class CertRecordInfo:
    FlashAddr = 0xabc
    MemDstAddr = 0x100
    MemDstAddrList = list()
    ImgSizeInWords = int(0)
    AesCodeEncUsed = int(0)
    SwHASHResult = ""

    # Constructor
    def __init__(self, log, loadVerifyScheme, RecFlashAddr, RecMemAddr, RecMemAddrList, RecImgSizeInBytes, RecIsCeUsed, RecHash, RecProjDict):

        self.ProjDict = RecProjDict
        if self.ProjDict['is_iot_cert'] == 1:
            mem_addr_unload_flag = MEM_ADDR32_UNLOAD_FLAG
        else:
            mem_addr_unload_flag = MEM_ADDR64_UNLOAD_FLAG

        # load address can be 0xffffffff only in case of "verify only in flash" mode
        if (loadVerifyScheme == VERIFY_IMAGE_IN_FLASH and RecMemAddr != mem_addr_unload_flag) :
            print_and_log(log, "Illegal load address defined - exiting\n")
            sys.exit(1)

        if (loadVerifyScheme != VERIFY_IMAGE_IN_FLASH and RecMemAddr == mem_addr_unload_flag) :
            print_and_log(log, "Illegal load address defined - exiting\n")
            sys.exit(1)

        # flash storage address can be 0xffffffff only in case of "verify only in mem" mode
        if (loadVerifyScheme == VERIFY_IMAGE_IN_MEM and RecFlashAddr != mem_addr_unload_flag) :
            print_and_log(log, "Illegal flash address defined - exiting\n")
            sys.exit(1)

        if (loadVerifyScheme != VERIFY_IMAGE_IN_MEM and RecFlashAddr == mem_addr_unload_flag) :
            print_and_log(log, "Illegal flash address defined - exiting\n")
            sys.exit(1)

        self.FlashAddr = RecFlashAddr
        self.MemDstAddr = RecMemAddr
        self.MemDstAddrList = RecMemAddrList
        self.ImgSizeInWords = RecImgSizeInBytes
        self.AesCodeEncUsed = RecIsCeUsed
        self.SwHASHResult = RecHash

    # The method VarsToBinStringHashComp creates a binary string out of the hash of component
    # and the memory destination address
    def VarsToBinStringHashComp(self):
        DataBinStr = str()
        DataBinStr1 = str()
        DataBinStr2 = str()
        DataBinStr3 = str()

        DataBinStr = self.SwHASHResult

        if self.ProjDict['is_iot_cert'] == 1:
            DataBinStr1 = struct.pack('<I', self.MemDstAddr)
        else:
            DataBinStr1 = struct.pack('<Q', self.MemDstAddr)

        DataBinStr2 = struct.pack('<I', self.ImgSizeInWords)

        DataBinStr3 = struct.pack('<I', self.AesCodeEncUsed)

        DataBinStr = DataBinStr + DataBinStr1 + DataBinStr2 + DataBinStr3
        return byte2string(DataBinStr)

    # The method VarsToBinStringParamComp creates a binary string out of the component size
    # and the source address
    def VarsToBinStringParamComp(self):
        DataBinStr = str()

        if self.ProjDict['is_iot_cert'] == 1:
            DataBinStr = struct.pack('<I', self.FlashAddr)
        else:
            DataBinStr = struct.pack('<Q', self.FlashAddr)

        return byte2string(DataBinStr)

    # Return the load address
    def GetDstAddress(self):
        return self.MemDstAddr

# End of CertRecordInfo


# This class holds the AES encryption needed information
class CodeEncryptionData:

    # Constructor
    def __init__(self, logFile, keyFileName, dstAddressList, nonce, cryptoType, ProjDict):
        self.ProjDict = ProjDict
        self.keyIntArray = self.extractAESKeyFromFile(keyFileName)
        self.nonceStrBin = str()
        self.cryptoType = cryptoType
        self.IVIntArray = self.combineAESIV(dstAddressList, nonce)

    # This method extracts the key from the file
    def extractAESKeyFromFile(self, keyFileName):
        try:
            IntArrayKeyParam = c_ubyte * AES_DECRYPT_KEY_SIZE_IN_BYTES
            keyIntArray = IntArrayKeyParam()

            # Get the key data from binary file.
            fob = open(keyFileName, "rb")
            fileData = fob.read()
            fob.close()
            # Take each of the hex representation and save it as Int in the array
            keyList = list(fileData)

            i = 0
            for obj in keyList:
                if i == AES_DECRYPT_KEY_SIZE_IN_BYTES:
                    print("aes key file is in illegal size")
                    break
                keyIntArray[i] = obj
                i = i + 1

        except IOError as Error1:
            (errno, strerror) = Error1.args
            print("Error in opening file - %s" %FileName)
            sys.exit(1)
        return keyIntArray

    # This method combines the IV
    def combineAESIV(self, dstAddressList, nonce):
        try:
            self.nonceStrBin = nonce
            IntArrayIVParam = c_ubyte * AES_IV_SIZE_IN_BYTES
            IVIntArray = IntArrayIVParam()
            fillZeroes = 0

            i = 0
            for char in self.nonceStrBin:
                IVIntArray[i] = struct.unpack("B",char)[0]
                i = i + 1

            # The IV is composed of - nonce (8 bytes) + destination address (8/4 bytes)
            # first need to verify that the list size is as expected
            if self.ProjDict['is_iot_cert'] == 1:
                numOfAddressBytes = MEM_ADDR32_BYTES_WIDTH
            else:
                numOfAddressBytes = MEM_ADDR64_BYTES_WIDTH

            if len(dstAddressList) < numOfAddressBytes: # need to fill zeroes before
                    fillZeroes = numOfAddressBytes - len(dstAddressList)

            for j in range(fillZeroes):
                IVIntArray[i] = int("0")
                i = i + 1
             # copy each byte as int to the array
            for j in range(int(numOfAddressBytes)-fillZeroes):
                IVIntArray[i] = int(dstAddressList[j], 16)
                i = i + 1

            # return the IV
        except NameError:
            print("\n combineAESIV failed !! ")
            sys.exit(1)
        return IVIntArray

    # This method is responsible to write the encrypted data
    def AESEncryptDataAndHash(self, inputFileName, SBU_Crypto):
        try:
            newFileName = inputFileName[:-4] + SW_COMP_FILE_NAME_POSTFIX
            image_size = c_uint()
            OutputDataIntArray = create_string_buffer(SHA_256_HASH_SIZE_IN_BYTES)

            result = SBU_Crypto.SBU_AES_CTR_EncryptFile(str.encode(inputFileName), str.encode(newFileName), self.keyIntArray, AES_DECRYPT_KEY_SIZE_IN_BYTES,self.IVIntArray, OutputDataIntArray, byref(image_size), self.cryptoType)

            if result != 0:
                raise NameError

        except NameError:
            print("\n SBU_Crypto.SBU_AES_CTR_EncryptFile returned an error !!" + str(result))
            sys.exit(1)

        return dict(Hash = OutputDataIntArray.raw, ImageSize = image_size.value)


# This class is used to keep the random nonce
class KeyNonce:
    #The function creates a random nonce (2 words)
    def __init__(self, codeEncId, DLLHandle):
        try:
            #generate 8 bytes of random data, in binary format
            if codeEncId != USE_AES_CE_ID_NONE:
                self.randStr = create_string_buffer(8)
                result = DLLHandle.SBU_RAND_Bytes(8, self.randStr)
                if result <= 0:
                    raise NameError
            else:
                self.randStr = create_string_buffer(8)
                for i in range(8):
                        self.randStr[i] = 0


        except NameError:
            print("\n CreateNonce failed, failed to create random number! ")
            sys.exit(1)

        return

    # This method is used to return the Nonce as binary string
    # The nonce is a byte array of 8 bytes but it is read in the sb code as 2 words, therefore in case of little endian
    # it is reversed and in case of BIG lest as is.
    def VarsToBinString(self):
        str1 = byte2stringBytesArray(self.randStr)
        return str1

#End of CreateNonce
########### Data Records analyzer functions ###########

# The ImageFileAnalyzer function analyzes the files list file and return a list of data records objects.
# The function does the following steps:
# Step 1 - Open the file (that contain the files list)
# Step 2 - Get each line in the file and insert it into a list of dictionaries
#          each dictionary contain:
#               image name (SW component name),
#               Memory destination address
#               Flash source address of the image
# Step 3 - For each SW image (SW component) calculate its HASH and add to dictionary along with its size
# Step 4 - Create a record object and insert the data into it
def ImageFileAnalyzer(logFile, FileName, loadVerifyScheme, codeEncId, SBU_DLLHandle, keyFileName, nonce, cryptoType, ProjDict):

    DataRecsList = list()

    # SB does not support encrypted images in case of "loading only" and "verify only in flash" modes
    if (loadVerifyScheme == VERIFY_IMAGE_IN_FLASH and codeEncId != USE_AES_CE_ID_NONE) :
        print_and_log(logFile, "Verify encrypted image in Flash is illegal - exiting\n")
        sys.exit(1)

    if (loadVerifyScheme == LOADING_ONLY_IMAGE and codeEncId != USE_AES_CE_ID_NONE) :
        print_and_log(logFile, "Loading only encrypted image is illegal - exiting\n")
        sys.exit(1)

    # Open the file (that contain the files list)
    try:
        FileObj = open(FileName , "r")
        LinesDictList = list()
        FileLines = FileObj.readlines()
        # If the file is empty the data record list will be returned empty
        if len(FileLines) == 0 :
            print_and_log(logFile, "illegal number of images = 0 !")
            sys.exit(1)
        # Get each line in the file and insert it into a list of dictionaries
        # each dictionary contain the image name (SW component name), memory load address and the Flash address
        # of the image
        for lineObj in FileLines:
            # if it is comment ignore
            if re.match(r'^#', lineObj):
                continue
            LinesDictList.append(LineAnalyzer(logFile, lineObj))
        # For each SW image (SW component) calculate its HASH and add to dictionary (hash and size)
        for ListObj in LinesDictList:
            ListObj.update(HashResOnSWComponent(logFile, ListObj.get('ImgName'), ListObj.get('isAesCodeEncUsed'), codeEncId, SBU_DLLHandle,ListObj.get('MemDstAddrList'), keyFileName, nonce, cryptoType, ProjDict))
            # Create a record object and insert the data into it
            CertRecordInfoObj = CertRecordInfo(logFile, loadVerifyScheme, ListObj.get('FlashSrcAddr'), ListObj.get('MemDstAddr'), ListObj.get('MemDstAddrList'), ListObj.get('ImageSize'), ListObj.get('isAesCodeEncUsed'), ListObj.get('Hash'), ProjDict)
            DataRecsList.append(CertRecordInfoObj)

    except IOError as Error1:
        (errno, strerror) = Error1.args
        print_and_log(logFile, "\n Error in openning file - %s" %FileName)
        sys.exit(1)

    return DataRecsList
# End of ImageFileAnalyzer

# The LineAnalyzer function takes each line in the files list file and separate it
# Each line is expected to be in the following structure:
# <s/w_comp_name> <mem_dest_addr> <flash_source_addr> <aes-ce-used>
# The function returns a dictionary with the line data. (ImgName, MemDstAddr, FlashSrcAddr, isAesCodeEncUsed)
# In case the functions reads an illegal image address (not word alligned) an exception is raised
def LineAnalyzer(logFile, FileLine):
    try:
        LineList = FileLine.split(" ")
        MemDstAddr = int(LineList[1],16)
        if MemDstAddr == 0:
            print_and_log(logFile, "\n Illegal Address - 0 is not allowed as load address !!")
            sys.exit(1)
        MemDstAddrList = createAddrList(LineList[1][2:])
        FlashSrcAddr = int(LineList[2],16)
        isAesCodeEncUsed = int(LineList[3],16)

    except NameError:
        print_and_log(logFile, "\n Illegal Address - not word alligned !!")
        sys.exit(1)

    return dict(ImgName = LineList[0], MemDstAddr = MemDstAddr, MemDstAddrList = MemDstAddrList, FlashSrcAddr = FlashSrcAddr, isAesCodeEncUsed = isAesCodeEncUsed)
# End of LineAnalyzer

# The HashResOnSWComponent decides on which HASH algorithm should be used and call the correct function
# Currently HASH SHA256 output & SHA 256 output is trucated to 128 bits output are supported
def HashResOnSWComponent(logFile, FileName, isAesCodeEncUsed, codeEncId, SBU_DLLHandle, memoryDstAddr, keyFileName, nonce, cryptoType, ProjDict):
    try:
        if isAesCodeEncUsed == 1 :
             # do Aes and Hash
            if codeEncId != USE_AES_CE_ID_NONE :
                codeEncObj = CodeEncryptionData(logFile, keyFileName, memoryDstAddr, nonce, cryptoType, ProjDict)
                return codeEncObj.AESEncryptDataAndHash(FileName, SBU_DLLHandle)
            else:
               print_and_log(logFile, "ERROR: No AES key was selected!")
               sys.exit(1)
        else:
            # do only Hash
            return HashResOnSWComponent_SHA256(logFile, FileName, SBU_DLLHandle)
    except NameError:
        print_exeption()
        sys.exit(1)

    return
# End of HashResOnSWComponent

# The HashResOnSWComponent_SHA256 function reads the image file (SW component) and calculate HASH on it
def HashResOnSWComponent_SHA256(logFile, FileName, SBU_Crypto):
    try:
        image_size = c_uint()
        OutputDataIntArray = create_string_buffer(SHA_256_HASH_SIZE_IN_BYTES)

        result = SBU_Crypto.SBU_AES_CTR_EncryptFile(str.encode(FileName), None, None, 0 ,None, OutputDataIntArray, byref(image_size), 0)
        if result != 0:
            print_and_log(logFile, "Error in Hash!")
            sys.exit(1)

    except NameError:
        print_and_log(logFile, "Error in Hash !")
        sys.exit(1)

    return dict(Hash = OutputDataIntArray.raw, ImageSize = image_size.value)

def createAddrList (dataStr):
    dataList = list()

    if len(dataStr)%2 == 1: #miss a zero at the beginning
        newStr = '0'+dataStr
    else:
        newStr = dataStr

    for i in range(int(len(newStr)/2)):
        dataList.append(newStr[i*2:i*2+2])
    return dataList

########### Data Records analyzer functions End ###########

