/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm's non-OSI source license
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/dma-mapping.h>
#include <linux/mempool.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/ioctl.h>
#include <linux/fs.h> // required for various structures related to files liked fops.
#include <linux/cdev.h>
#include <asm/io.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include "cc_pal_linux_drv.h"


#define CC_PAL_FORCE_ACCESS 1
#define CC_PAL_BASE_MINOR   0
#define CC_PAL_DRV_COUNT    1

static struct class *class_device = NULL;    // The device class
static struct device *my_device = NULL;
static struct cdev cc_pal_cdev; // The character device structure
static int cc_pal_dev_major;
static dev_t cc_pal_dev;

#if 0
#define KPRINT_BUFF(str, buff, size) {\
		unsigned int ii=0;\
		printk(KERN_ALERT "%s(): printing %s size %d:" , __FUNCTION__, str, size);\
		for(ii = 0; ii < size; ii+=4) {\
			printk(KERN_ALERT "0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X ",  \
			((char *)buff)[ii], ((char *)buff)[ii+1], ((char *)buff)[ii+2], ((char *)buff)[ii+3]);\
		}\
}

#define KPRINT(format, args...) \
		printk(KERN_ALERT "%s(): " format, __FUNCTION__, ##args); printk(KERN_ALERT "\n");
#else
#define KPRINT_BUFF(str, buff, size)  do{}while(0)
#define KPRINT(format, args...)       do{}while(0)
#endif

int pal_linux_drv_mmap(struct file *f, struct vm_area_struct * vma);

const struct file_operations fops = {
    .owner = THIS_MODULE,
    .mmap = pal_linux_drv_mmap,
};

int pal_linux_drv_mmap(struct file *f, struct vm_area_struct * vma)
{

	size_t size = vma->vm_end - vma->vm_start;

	KPRINT("started size 0x%lx, vm_start 0x%lx", size, vma->vm_start);

	if (!(vma->vm_flags & VM_MAYSHARE)) {
		KPRINT("failed private_mapping_ok");
		return -ENOSYS;
	}


	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	/* Remap-pfn-range will mark the range VM_IO */
	if (remap_pfn_range(vma,
			    vma->vm_start,
			    vma->vm_pgoff,
			    size,
			    vma->vm_page_prot)) {
		KPRINT("failed remap_pfn_range");
		return -EAGAIN;
	}
	KPRINT("OK");
	return 0;
}


/**
 * @brief
 *
 * @return Returns a non-zero value in case of failure
 */

static int __init pal_linux_drv_init(void)
{
	int rc = 0;
	dev_t cc_pal_dev_num;

	//KPRINT("started");

	// creating and allocating character driver
	rc = alloc_chrdev_region(&cc_pal_dev_num,
				CC_PAL_BASE_MINOR,
				CC_PAL_DRV_COUNT,
				PAL_LINUX_DRV_NAME);
	if (rc < 0) {
		printk(KERN_INFO "alloc_chrdev_region() failed 0x%x\n", rc);
		return rc;
	}

	// creating a class to hold the char driver and following device
	class_device = class_create(THIS_MODULE, PAL_LINUX_CLASS_NAME);
	if (class_device == NULL ) {
		printk(KERN_INFO "class_create() failed 0x%x\n", rc);
		goto init_end_unrgister;
	}

	// create a device connected to the character deriver
	my_device = device_create(class_device, NULL, cc_pal_dev_num, NULL, PAL_LINUX_DRV_NAME);
	if(my_device == NULL) {
		printk(KERN_INFO "device_create() failed 0x%x\n", rc);
		goto init_end_class;
	}

	// init the driver
	cdev_init(&cc_pal_cdev, &fops);

	cc_pal_dev_major = MAJOR(cc_pal_dev_num);
	cc_pal_dev = MKDEV(cc_pal_dev_major,0);

	// adding the driver to the kernel - after that the module can be accessed by user
	rc = cdev_add(&cc_pal_cdev, cc_pal_dev, CC_PAL_DRV_COUNT);
	if (rc < 0) {
		printk(KERN_INFO "cdev_add() failed 0x%x\n", rc);
		goto init_end_error;
	}

	/* ARM-specific DMA coherency operations option */
//	set_dma_ops(my_device, &noncoherent_swiotlb_dma_ops ); //); //coherent_swiotlb_dma_ops //arm_coherent_dma_ops); // arm_dma_ops
	//KPRINT("Done");
	return rc;

init_end_error:
	cdev_del(&cc_pal_cdev);
	device_destroy(class_device, cc_pal_dev);
init_end_class:
	class_destroy(class_device);
init_end_unrgister:
	unregister_chrdev_region(cc_pal_dev_major, CC_PAL_DRV_COUNT);
	KPRINT("Done bad 0x%x", rc);
	return rc;
}


static void __exit pal_linux_drv_exit(void)
{
	//KPRINT("started");
	cdev_del(&cc_pal_cdev);
	device_destroy(class_device, cc_pal_dev);
	class_destroy(class_device);
	unregister_chrdev_region(cc_pal_dev_major, CC_PAL_DRV_COUNT);
	//KPRINT("Done");
}


module_init(pal_linux_drv_init);
module_exit(pal_linux_drv_exit);

MODULE_AUTHOR("CC-ARM");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CC linux pal Driver");

