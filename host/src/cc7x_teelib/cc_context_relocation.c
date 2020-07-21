/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_API

/*! \file cc_context_relocation.c
 * Handle relocation of crypto context in the context buffer given
 * by the user to assure it does not cross a page boundary
 */
#include "cc_context_relocation.h"
#include "cc_pal_compiler.h"
#include "cc_pal_mem.h"

/* Assume standard 4KB page size */
#define PAGE_SHIFT              calcPageShift(MEMORY_FRAGMENT_MAX_SIZE_IN_KB)
#define PAGE_SIZE               ((size_t)(1<<PAGE_SHIFT))
#define PAGE_MASK               (~(PAGE_SIZE-1))
/* "natural" 4B alignment */
#define CONTEXT_ALIGNMENT_SHIFT 2
#define CONTEXT_ALIGNMENT_SIZE  (1<<CONTEXT_ALIGNMENT_SHIFT)
#define CONTEXT_ALIGNMENT_MASK  (~((1<<CONTEXT_ALIGNMENT_SHIFT) - 1))

#define CONTEXT_ALIGN(addr) \
    (((unsigned long)(addr)+CONTEXT_ALIGNMENT_SIZE-1) & CONTEXT_ALIGNMENT_MASK)

#define IS_BUF_CROSS_PAGE(start, size) \
    (((unsigned long)(start) >> PAGE_SHIFT) < (((unsigned long)(start) + (size) - 1) >> PAGE_SHIFT))

/* Context buffer properties */
/* this data is always saved at the original start of user context buffer */
typedef struct {
    uint32_t bufSize; /* Original user buffer size in bytes */
    uint32_t ctxSize; /* Contained context actual size in bytes */
    uint32_t ctxOffset;/* Byte offset of the contained context from the beginning of this structure */
    uint8_t  buff[0]; /* the rest of the buffer, of variable size */
} CCCtxBufProps_t;

CC_PAL_COMPILER_ASSERT(sizeof(CCCtxBufProps_t) == CC_CTX_BUFF_PROPS_SIZE_BYTES, "sizeof(CCCtxBufProps_t) should be equal to CC_CTX_BUFF_PROPS_SIZE_BYTES!");

static uint32_t calcPageShift(uint32_t pageSizeInKB)
{
    static uint32_t pageShift = 0;

    if (pageShift != 0) {
        return pageShift;
    }

    for (pageShift = 0; pageShift < sizeof(uint32_t) * 8 && pageSizeInKB > 0; ++pageShift) {
        pageSizeInKB = pageSizeInKB >> 1;
    }

    pageShift += 10; /* Add KB shift. 1024 - 10 bits; */
    pageShift--;

    return pageShift;
}

/*!
 * Find a good offset in given buffer to accomodate given context size
 * without crossing a page boundary
 * Note: this function does not take into account the "bufProps" data
 *       that we locate in the buffer's start, so it should get
 *       bufferStart at the location that follows that data.
 *
 * \param bufferStart The pointer to the context buffer given by the user
 *                     (offseted to accommodate the bufProps data)
 * \param bufferSize The total size of pointed buffer
 * \param contextSize The size of a context to place in the buffer
 *
 * \return Offset of the context in the given buffer
 */
static unsigned long GetNonCrossingOffset(unsigned long bufferStart,
                                          unsigned long bufferSize,
                                          unsigned long contextSize)
{
    const unsigned long bufStartNextPage = (bufferStart + PAGE_SIZE) & PAGE_MASK;
    const unsigned long bufEndPage = (bufferStart + bufferSize - 1) & PAGE_MASK;
    unsigned long goodLocation;

    if (bufStartNextPage > bufEndPage) {
        /* Buffer does not cross a page */
        /* Just assure alignment of buffer start */
        goodLocation = CONTEXT_ALIGN(bufferStart);
    } else if (bufStartNextPage == bufEndPage) {
        /* Buffer crosses one page boundary */
        /* Return part that can accomodate context */
        goodLocation = CONTEXT_ALIGN(bufferStart);
        if ((bufStartNextPage - goodLocation) < contextSize) {
            /* First part is too small, pick the start of the second page */
            goodLocation = bufEndPage; /* Page is always aligned... */
        }
    } else {
        /* Buffer crosses two page boundaries */
        /* Pick the start of the full page in the middle */
        goodLocation = bufStartNextPage;
    }

    return goodLocation - bufferStart;
}

static void RcSetProp(CCCtxBufProps_t *pBufProps, unsigned long bufferSize, unsigned long contextSize)
{
    unsigned long contextOffset = 0;

    /* Get good location (starting from buffer_ptr + sizeof(CCCtxBufProps_t) */
    contextOffset = GetNonCrossingOffset((unsigned long) pBufProps->buff,
                                         bufferSize,
                                         contextSize);

    /* The actual offset is after the CCCtxBufProps_t structure */
    contextOffset += sizeof(CCCtxBufProps_t);

    /* Save buffer properties */
    pBufProps->bufSize = bufferSize;
    pBufProps->ctxSize = contextSize;
    pBufProps->ctxOffset = contextOffset;
}

/*!
 * Initialize the context offset for a new buffer given to INIT phase
 *
 * \param bufferStart The address of the context buffer given by the user
 * \param bufferSize The size of the user buffer in bytes
 * \param contextSize The required size (in bytes) of the context
 *
 * \return The address of the context within the buffer
 */
void *RcInitUserCtxLocation(void *bufferStart, unsigned long bufferSize, unsigned long contextSize)
{
    /* Buffer must accommodate the BufProps and 2*contextSize to
     assure at least contextSize bytes are not crossing page boundary */
    const unsigned long requested_buf_size = sizeof(CCCtxBufProps_t) + 2 * contextSize;
    void *contextStart;

    CCCtxBufProps_t *bufProps = (CCCtxBufProps_t *) bufferStart;
    /* Buffer properties are save at reserved space at buffer's start */

    /* Verify given sizes validity*/
    if ((contextSize > PAGE_SIZE) || (bufferSize < requested_buf_size)) {
        return NULL;
    }

    RcSetProp(bufProps, bufferSize, contextSize);

    contextStart = (void*) ((unsigned long) bufferStart + bufProps->ctxOffset);
    return contextStart;
}

/*!
 * Return the context address in the given buffer
 * If previous context offset is now crossing a page the context data
 * would be moved to a good location.
 *
 * \param bufferStart The address of the context buffer given by the user
 *
 * \return The address of the context within the buffer
 */
void *RcGetUserCtxLocation(void *bufferStart)
{
    /* Calculate current context location based on offset in buffer props */
    CCCtxBufProps_t *bufProps = (CCCtxBufProps_t *) bufferStart;
    void *curContextLocation = (void *) ((unsigned long) bufferStart + bufProps->ctxOffset);
    void *newContextLocation;

    /* Verify current location */
    if (!IS_BUF_CROSS_PAGE(curContextLocation, bufProps->ctxSize)) {
        /* If context does not cross page boundary - keep it where it is */
        return curContextLocation;
    }

    RcSetProp(bufProps, bufProps->bufSize, bufProps->ctxSize);

    newContextLocation = (void*) ((unsigned long) bufferStart + bufProps->ctxOffset);

    /* memmove context + private data from original location to new location */
    CC_PalMemMove(newContextLocation, curContextLocation, (bufProps->bufSize - (sizeof(CCCtxBufProps_t)))/2);

    return newContextLocation;
}

