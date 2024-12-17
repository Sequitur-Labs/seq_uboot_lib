/*================================================
Copyright © 2016-2022 Sequitur Labs Inc. All rights reserved.

The information and software contained in this package is proprietary property of
Sequitur Labs Incorporated. Any reproduction, use or disclosure, in whole
or in part, of this software, including any attempt to obtain a
human-readable version of this software, without the express, prior
written consent of Sequitur Labs Inc. is forbidden.
================================================*/
#ifndef __SEQ_BOOT_H__
#define __SEQ_BOOT_H__

#define SEQ_BOOT_COMPONENT_DDR_BASE 0x60000000
#define SEQ_BOOT_VERSION_LENGTH 128

/*
 * Enable this macro to copy kernel and fdt from MMC to DDR,
 * then properly relocated once u-boot is up.
 */
#define SEQ_LOAD_KERNEL_VIA_SLIPS

typedef struct {
	char version[SEQ_BOOT_VERSION_LENGTH];
	uintptr_t nvsaddr;
	size_t nvslength;
	uintptr_t ramaddr;
	size_t ramlength;
	uint32_t status;
} SeqBootComponentInfo;

typedef struct {
	char version[SEQ_BOOT_VERSION_LENGTH];
	uint32_t partition;
	uint32_t status;
} SeqBootFilesystemInfo;

typedef struct {
	char model[SEQ_BOOT_VERSION_LENGTH];
	char build[SEQ_BOOT_VERSION_LENGTH];
	SeqBootComponentInfo atf;
	SeqBootComponentInfo coretee;
	SeqBootComponentInfo uboot;
	SeqBootComponentInfo kernel;
	SeqBootComponentInfo fdt;
	SeqBootComponentInfo coreteedtb;
	SeqBootFilesystemInfo rootfs;
	SeqBootFilesystemInfo rwfs;
	SeqBootFilesystemInfo appfs;
} SeqBootPlexInfo;

#define SEQ_BOOT_WDOG  WDOG2_BASE_ADDR
void seq_service_watchdog( void );
void seq_reset_with_watchdog( void );

/*
 * Loads the plex manifest.
 *  - If 'plexa' does not equal 0 then load the 'A' plex.
 *  - If 'plexa' equals 0 then load the 'B' plex.
 */
int seq_load_plex_manifest( uint8_t plexa );

/*
 * Returns the current plex. This can be NULL if the manifests have not been loaded yet.
 */
SeqBootPlexInfo *seq_get_current_plex( void );

/*
 * Loads the boot components for the 'current' plex and continues boot to next component.
 */
int seq_component_setup( void );

/* Where the CoreTEE boot logic starts. */
void seq_run_boot_start( void ) __attribute__ ((noreturn));

void seq_board_coretee_late_init( void );

#endif /*seq_boot_h*/
