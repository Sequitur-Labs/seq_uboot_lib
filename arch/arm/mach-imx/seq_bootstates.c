#include <common.h>
#include <memalign.h>
#ifdef CONFIG_IMX_ECSPI
#include <imx_spi.h>
#endif

#include <fsl_wdog.h>
#include <asm/io.h>
#include <asm/arch-imx8m/imx8mq_pins.h>
#include <asm/mach-imx/iomux-v3.h>

#include <image.h>
#include <boot_fit.h>

#include <seq_error.h>
#include <seq_boot_manifests.h>
#include <seq_ecc_utils.h>
#include <seq_memio.h>
#include <seq_boot.h>
#include <seq_update.h>

#ifdef CONFIG_CORETEE_ENABLE_BLOB
#include <seq_blob.h>
#include <seq_keys.h>
int blob_decap(u8*,u8*,u8*,u32);
#endif

#include <seq_cipher.h>
#include <seq_bootstates.h>

static char * byteToHex( uint8_t byte )
{
	static const char * hex = "0123456789ABCDEF";
	static char hexstr[2];
	memset(hexstr, 0, 2);

	hexstr[0] = hex[(byte>>4) & 0xF];
	hexstr[1] =   hex[ byte & 0xF];
	return hexstr;
}

void seq_print_bytes( uint8_t *data, uint32_t len)
{
	static char buffer[512];
	unsigned long bx=0;
	uint32_t i=0;
	memset(buffer, 0, 512);
	for(i = 0; i < len; i++) {
		memcpy(buffer+bx*2, byteToHex(data[i]), 2);
		bx++;
		if (bx == 16) {
			printf("%s\n", buffer);
			memset(buffer, 0, 512);
			bx=0;
		}
	}
	if (bx != 0) {
		printf("%s\n", buffer);
	}
}

//SEQ_BLC = Boot Loop Counter
#if IS_ENABLED(CONFIG_CORETEE_USE_NVM_FOR_BLC) //Are we loading the BLC from NVM?
uint32_t get_lpgpr( void ) 
{
	uint8_t *buffer = NULL; 
	uint32_t lpgpr=0;

	buffer = (uint8_t*)malloc(SEQ_MMC_BLOCK_SIZE);
	if (buffer) {
		seq_mmc_read(SEQ_BLC_MMC_OFFSET, SEQ_MMC_BLOCK_SIZE, buffer);
		memcpy((void*)&lpgpr, buffer, sizeof(uint32_t));

		free(buffer);
	}

	return lpgpr;
}

uint32_t get_lpgpr_blc( void ) 
{
	uint32_t regval = get_lpgpr();
	//printf("MMC [%s] - State read: 0x%02x\n", __func__, regval&0xFF);
	return regval & 0xFF;
}

void set_lpgpr_blc( uint8_t blc ) 
{
	uint8_t *buffer = NULL; 
	uint32_t regval = get_lpgpr();

	buffer = (uint8_t*)malloc(SEQ_MMC_BLOCK_SIZE);
	if (buffer) {
		//Clear lower 8 bits
		regval &= ~(0xFF);
		regval |= (blc & 0xFF);

		memcpy(buffer, (void*)(&regval), sizeof(uint32_t));

		printf("Setting SEQ_BLC to: %d\n", blc);
		seq_mmc_write(SEQ_BLC_MMC_OFFSET, SEQ_MMC_BLOCK_SIZE, buffer);

		//Debugging, can be removed
		//memset(buffer, 0, SEQ_MMC_BLOCK_SIZE);
		//seq_mmc_read(SEQ_BLC_MMC_OFFSET, SEQ_MMC_BLOCK_SIZE, buffer);
		//memcpy((void*)&regval, buffer, sizeof(uint32_t));
		//printf("Regval: 0x%08x    SEQ_BLC: 0x%02x\n", regval, regval & 0xFF);

		free(buffer);
	}
}

void decrement_blc(void) 
{
	uint32_t blc = 0;
	//printf("[%s] - Calling get_blc\n", __func__);
	blc = get_lpgpr_blc();
	if (blc>0) { //Don't decrement below 0
		set_lpgpr_blc(blc-1);
	}
}

#else //USE_NVM_FOR_BLC

uint8_t get_lpgpr_blc( void ) 
{
	uint32_t regval = in_le32(SNVS_BASE_ADDR + SNVS_LPGPR);
	//printf("!MMC SEQ_BLC: %d\n", (regval & 0xFF));
	return regval & 0xFF;
}

uint32_t get_lpgpr( void ) 
{
	return in_le32(SNVS_BASE_ADDR + SNVS_LPGPR);
}

void set_lpgpr_blc( uint8_t blc ) 
{
	uint32_t hpcomr = (in_le32(SNVS_BASE_ADDR + SNVS_HPCOMR));
	uint32_t regval = get_lpgpr();

	printf("Regval[1] is: 0x%08x\n", regval);

	//Clear lower 8 bits
	regval &= ~(0xFF);
	regval |= (blc & 0xFF);

	printf("LPGPR: 0x%08x\n", SNVS_BASE_ADDR + SNVS_LPGPR);
	printf("Setting SEQ_BLC reg [0x%08x] to %d\n", regval, blc);

	out_le32(SNVS_BASE_ADDR + SNVS_LPGPR, regval);

	regval = in_le32(SNVS_BASE_ADDR + SNVS_LPGPR);
	printf("Reading SEQ_BLC: %d\n", regval & 0xFF);
}

void decrement_blc(void) 
{
	uint32_t regval = in_le32(SNVS_BASE_ADDR + SNVS_LPGPR);
	uint32_t blc = regval & 0xFF;
	if (blc!=0) { //Don't decrement below 0
		set_lpgpr_blc(blc-1);
	}
}

#endif //USE_MMC_FOR_BLC

void seq_set_blc_to_max( void )
{
	set_lpgpr_blc(SEQ_BLC_MAX);
}

void seq_check_bricked(unsigned int por, uint32_t state)
{
	uint32_t blc = 0;

	//printf("[%s] - Calling get_blc\n", __func__);
	blc = get_lpgpr_blc();
	if (blc == 0) {
		state |= SEQ_BLC_ZERO;
	}
	//printf("[%s] SEQ_BLC: %d\n", __func__, blc);


	/*
	 * If POR then we don't care about SEQ_BLC just the validity of the plex or possible actions.
	 * If SEQ_BLC doesn't equal zero then we can't be bricked yet.
	 * If SEQ_BLC == 0 then if we have any valid plex or any action we are not bricked.
	 */
	//printf("Check bricked. por/blc %d    state: %x    check value: %x\n", (por || blc==0), state, (SEQ_BS_ACTIVATE | SEQ_BS_UPDATE | SEQ_BS_B_VALID | SEQ_BS_A_VALID));
	if ((por || blc==0) && ((state & (SEQ_BS_ACTIVATE | SEQ_BS_UPDATE | SEQ_BS_B_VALID | SEQ_BS_A_VALID )) == 0)) {
		//Bricked!!!!!
		printf("Bricked!!!\n");

		//printf("BUT NOT HALTING!!! CONTINUE\n");
		while(1) {}
	}
}

/*
 *
 */
void update_plex( uint8_t plexid, uint32_t stateval ) 
{
	int res=0;
	uintptr_t ddr_dest;
	uint8_t *binaryparams = 0;
	int paramsize = 0;
	SEQ_CLEAR_STATE(stateval, SEQ_BS_UPDATE);

	printf("Running update against plexID: %d\n", plexid);
	res = seq_run_update( plexid );

	//If we got here we aren't about to reboot for SPL. That's handled in 'seq_run_update'
	SEQ_CLEAR_STATE(stateval, SEQ_BS_SPL_UPDATING);

	if (res) {
		//Update failed. Clear activate state
		char msg[]="Failed to run update. Clearing activate\n";
		printf(msg);
		SEQ_CLEAR_STATE(stateval, SEQ_BS_ACTIVATE);
		seq_update_boot_state(stateval);
		seq_boot_state_start( stateval );
		return;
	}

	//Save updated plex information to DDR for CoreTEE
	ddr_dest = CORETEE_TZDRAM_SEQ_MANIFEST_BASE + SEQ_MANIFEST_SIZE*SEQ_MANIFEST_COMPONENT;
	binaryparams = seq_get_binary_manifest( seq_get_manifest(SEQ_MANIFEST_COMPONENT), &paramsize);
	if (binaryparams) {
		memcpy((void*)ddr_dest, binaryparams, paramsize);
		free(binaryparams);
	}

	if (plexid == SEQ_PLEX_A_ID) {
		SEQ_SET_STATE(stateval, SEQ_BS_A_VALID);
	} else {
		SEQ_SET_STATE(stateval, SEQ_BS_B_VALID);
	}

	//If activating then we'll save the boot state after clearing the activate flag.
	//If not activating then we'll need to save the boot state with the cleared update flag.
	if (!SEQ_CHECK_STATE(stateval, SEQ_BS_ACTIVATE)) {
		//Save cleared 'update' flag back to SPI.
		seq_update_boot_state(stateval);
	}

	//Cycle through again.
	set_lpgpr_blc(SEQ_BLC_MAX);
	seq_boot_state_start( stateval );
}

/*
 *
 */
void activate_plex( uint8_t plexid, uint32_t stateval ) 
{
	SEQ_CLEAR_STATE(stateval, SEQ_BS_ACTIVATE);

	if (plexid == SEQ_PLEX_A_ID) {
		SEQ_SET_STATE(stateval, SEQ_BS_A_PRIMARY);
	} else {
		SEQ_CLEAR_STATE(stateval, SEQ_BS_A_PRIMARY);
	}

	//Save cleared 'activate' flag back to SPI.
	seq_update_boot_state(stateval);

	//Cycle through again.
	set_lpgpr_blc(SEQ_BLC_MAX);
	seq_boot_state_start( stateval );
}

void invalidate_plex( uint8_t plexa, uint32_t stateval ) 
{
	/*
	 * Invalidate the current plex (set valid to false).
	 * Switch to other plex.
	 * 'Brick' if both plexes are invalid and no actions.
	 */
	SEQ_CLEAR_STATE(stateval, (plexa ? SEQ_BS_A_VALID : SEQ_BS_B_VALID) );
	if (plexa) {
		SEQ_CLEAR_STATE(stateval, SEQ_BS_A_PRIMARY);
	} else {
		SEQ_SET_STATE(stateval, SEQ_BS_A_PRIMARY);
	}

	//Save new plex and invalid state back to SPI
	seq_update_boot_state(stateval);

	//Check to make sure at least one of the plexes is 'valid', or updateable
	seq_check_bricked(0, stateval);

	//Cycle through again on other plex. If/When SEQ_BLC hits zero then we are bricked/
	set_lpgpr_blc(SEQ_BLC_MAX);
	seq_boot_state_start(stateval);
}

void check_boot_state(uint32_t stateval) 
{
	uint32_t blc=0;
	uint8_t aisprimary;

#ifdef RUN_UPDATE
	printf("Calling update_plex\n");
	update_plex(SEQ_PLEX_B_ID, stateval);
#endif

	printf("[%s] - Stateval: 0x%02x\n", __func__, stateval & 0xFF);

	//Are we bricked?
	seq_check_bricked(0, stateval);

	//printf("[%s] - Calling get_blc\n", __func__);
	blc = get_lpgpr_blc();

	aisprimary = SEQ_CHECK_STATE(stateval, SEQ_BS_A_PRIMARY);
	/*
	 * When checking the 'states' the actions update and activate are the most important, with
	 * update being done before activate (if set).
	 *
	 * The 'bricked' state was already checked but if blc has been decremented to 0 then
	 * we need to invalidate the current plex and test the states again.
	 *
	 * If all those tests pass then we can proceed with a normal boot.
	 */

	if ( SEQ_CHECK_STATE(stateval, SEQ_BS_UPDATE) ) {
		printf("[SLI] - Update plex set. Updating non-primary plex\n");
		//Update 'other' plex
		update_plex(!aisprimary, stateval);
	} else if ( SEQ_CHECK_STATE(stateval, SEQ_BS_ACTIVATE) ) {
		printf("[SLI] - Activate plex set. Activating non-primary plex\n");
		//Activate 'other' plex
		activate_plex(!aisprimary, stateval);
	} else if (blc==0) {
		//set current plex valid to false. Check boot states again.
		printf("[SLI] - Invalidate plex: blc = %d,  a primary %d   stateval: %x\n", blc, aisprimary, stateval);
		invalidate_plex(aisprimary, stateval);
	} else {
		//continue to boot current plex
		if (seq_load_plex_manifest(aisprimary)) {
			printf("Failed  to load the plex manifest\n");

			//force reboot, which will decrement SEQ_BLC and loop again.
			seq_reset_with_watchdog();
		}

		printf("Calling component_setup\n");
		seq_component_setup();
	}
}

void seq_boot_state_start( uint32_t stateval )
{
	//Always decrement boot counter.
	decrement_blc();

	//Determine boot state
	check_boot_state(stateval);
}


/*
 * Write state_val to SPI flash at address SPI_STATE_ADDR
 */
void seq_update_boot_state( uint32_t state_val ) 
{
	int res=0;
	/*
	 * Use MMC interface to erase/write flash
	 */
	printf("Setting MMC boot state to: 0x%02x\n", (state_val & 0xFF));
	res = seq_mmc_write(SEQ_BOOT_STATE_MMC_OFFSET, sizeof(uint32_t), &state_val);
	if (res) {
		printf("Failed to save boot state!!!\n");
	}
}

uint32_t seq_read_boot_state_values( void ) 
{
	uint32_t stateval=0;
	int res=0;
	uint8_t stateblk[SEQ_MMC_BLOCK_SIZE];
	/*
	  read the value from SPI
	 */
	res = seq_mmc_read(SEQ_BOOT_STATE_MMC_OFFSET, SEQ_MMC_BLOCK_SIZE, stateblk);
	if (res) {
		printf("Failed to load bootstate\n");
	}
	memcpy((void*)(&stateval), stateblk, sizeof(uint32_t));
	return stateval;
}

