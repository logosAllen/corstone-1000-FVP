/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * (C) Copyright 2022 ARM Limited
 * (C) Copyright 2022 Linaro
 * Rui Miguel Silva <rui.silva@linaro.org>
 * Abdellatif El Khlifi <abdellatif.elkhlifi@arm.com>
 *
 * Configuration for Corstone1000. Parts were derived from other ARM
 * configurations.
 */

#ifndef __CORSTONE1000_H
#define __CORSTONE1000_H

#include <linux/sizes.h>

/* The SE Proxy partition ID*/
#define CORSTONE1000_SEPROXY_PART_ID		(0x8002)

/* Update service ID provided by  the SE Proxy secure partition*/
#define CORSTONE1000_SEPROXY_UPDATE_SVC_ID	(0x4)

/* Notification events used with SE Proxy update service */
#define CORSTONE1000_BUFFER_READY_EVT		(0x1)
#define CORSTONE1000_UBOOT_EFI_STARTED_EVT	(0x2)

#define PREP_SEPROXY_SVC_ID_MASK	GENMASK(31, 16)
#define PREP_SEPROXY_SVC_ID(x)	 (FIELD_PREP(PREP_SEPROXY_SVC_ID_MASK, (x)))

#define PREP_SEPROXY_EVT_MASK		GENMASK(15, 0)
#define PREP_SEPROXY_EVT(x)	(FIELD_PREP(PREP_SEPROXY_EVT_MASK, (x)))

/* Size in 4KB pages of the EFI capsule buffer */
#define CORSTONE1000_CAPSULE_BUFFER_SIZE	(4096) /* 16 MB */

/* Capsule GUID */
#define EFI_CORSTONE1000_CAPSULE_ID_GUID \
	EFI_GUID(0x3a770ddc, 0x409b, 0x48b2, 0x81, 0x41, \
		 0x93, 0xb7, 0xc6, 0x0b, 0x20, 0x9e)

#define V2M_BASE		0x80000000

#define CFG_PL011_CLOCK	50000000

/* Physical Memory Map */
#define PHYS_SDRAM_1		(V2M_BASE)
#define PHYS_SDRAM_1_SIZE	0x80000000

#define CFG_SYS_SDRAM_BASE	PHYS_SDRAM_1

#define BOOT_TARGET_DEVICES(func) \
	func(USB, usb, 0) \
	func(MMC, mmc, 0) \
	func(MMC, mmc, 1)

#include <config_distro_bootcmd.h>

#define CFG_EXTRA_ENV_SETTINGS BOOTENV

#endif
