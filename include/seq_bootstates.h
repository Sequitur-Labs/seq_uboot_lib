/*================================================
Copyright © 2016-2022 Sequitur Labs Inc. All rights reserved.

The information and software contained in this package is proprietary property of
Sequitur Labs Incorporated. Any reproduction, use or disclosure, in whole
or in part, of this software, including any attempt to obtain a
human-readable version of this software, without the express, prior
written consent of Sequitur Labs Inc. is forbidden.
================================================*/

#ifndef __seq_bootstates_h__
#define __seq_bootstates_h__

//Boot states.
#define SEQ_BLC_MAX 5
#define SEQ_BLC_MMC_OFFSET 0x06

//BLC and Error codes stored in SNVS_LPGPR
#define SEQ_BLC_MASK 		0xF 		/*Boot loop counter. 	Bits 0-3*/

#define SEQ_SPL_UPDT_SHIFT	8						/*SPL Update happening - Bits 8-11*/
#define SEQ_SPL_UPDT_MASK   (0xF << SEQ_SPL_UPDT_SHIFT)

#define SEQ_SPL_ERR_SHIFT	12
#define SEQ_CT_ERR_SHIFT	16
#define SEQ_UB_ERR_SHIFT	20
#define SEQ_LX_ERR_SHIFT	24
#define SEQ_FS_ERR_SHIFT	28
#define SEQ_SPL_ERR_MASK 	(0xF << SEQ_SPL_ERR_SHIFT)	/*SPL error				Bits 12-15*/
#define SEQ_CT_ERR_MASK  	(0xF << SEQ_CT_ERR_SHIFT)	/*CoreTEE error			Bits 16-19*/
#define SEQ_UB_ERR_MASK  	(0xF << SEQ_UB_ERR_SHIFT)	/*U-Boot error			Bits 20-23*/
#define SEQ_LX_ERR_MASK  	(0xF << SEQ_LX_ERR_SHIFT)	/*Linux Kernel error	Bits 24-27*/
#define SEQ_FS_ERR_MASK 	(0xF << SEQ_FS_ERR_SHIFT)	/*File system error		Bits 28-31*/

#define SEQ_BLC_ZERO (1 << 16);

//Boot states stored in MMC (0x05 - 1 block size (512 bytes))
#define SEQ_BOOT_STATE_MMC_OFFSET 0x05
#define SEQ_BOOT_STATE_SIZE 512
#define SEQ_BS_ACTIVATE (1<<0)
#define SEQ_BS_UPDATE (1<<1)
#define SEQ_BS_B_VALID (1<<2)
#define SEQ_BS_A_VALID (1<<3)
#define SEQ_BS_A_PRIMARY (1<<4)
#define SEQ_BS_MATURE (1<<5)

/*
 * We use the Secure Watchdog to reset the board.
 * This clears the SNVS registers, which is where we stored the value
 * of 'spl_updating'. We need to move it to NVM. The BootStates work.
 */
#define SEQ_BS_SPL_UPDATING (1<<7)
#define SEQ_PLEX_A_ID 1 /*Value of SEQ_BS_A_PRIMARY bit*/
#define SEQ_PLEX_B_ID 0

#define SEQ_CHECK_STATE(s, x) ((s & x)==x)
#define SEQ_CLEAR_STATE(s,x) (s &= ~x)
#define SEQ_SET_STATE(s,x) (s |= x);

/*
 * Sets the BLC to the maximum value
 */
void seq_set_blc_to_max( void );

/*Update the state values*/
void seq_update_boot_state(uint32_t state_val);

/*Read the state values from NVM*/
uint32_t seq_read_boot_state_values(void);

//Run the update on the plex.
/*
 * PLEX_A_ID - for plex 'A'
 * PLEX_B_ID - for plex 'B'
 */
int seq_run_update( unsigned int plexid );

/*
 * Checks if the board is in a bricked state based on Power On Reset and current state.
 */
void seq_check_bricked(unsigned int por, uint32_t state);

/*
 * Start state based boot decisions.
 */
void seq_boot_state_start( uint32_t stateval );

#endif /*seq_bootstates_h*/
