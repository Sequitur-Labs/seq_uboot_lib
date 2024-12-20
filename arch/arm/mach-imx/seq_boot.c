#include <common.h>
#include <malloc.h>
#include <memalign.h>
#include <fsl_wdog.h>
#include <asm/io.h>
#include <spl.h>
#include <mmc.h>

#include <mapmem.h>
#include <linux/arm-smccc.h>

#include <seq_error.h>
#include <seq_memio.h>
#include <seq_boot_manifests.h>
#include <seq_bootstates.h>
#include <seq_cipher.h>
#include <seq_activation.h>
#include <seq_imx8m_regs.h>
#include <seq_secmon_regs.h>

#ifdef CONFIG_CORETEE_ENABLE_BLOB
#include <seq_blob.h>
#include <seq_keys.h>
int blob_decap(u8*,u8*,u8*,u32);
#endif


#include <seq_boot.h>

#ifdef CONFIG_SPL_BUILD

#define RESET_CAUSE_UNKNOWN 0
#define RESET_CAUSE_POR 1
#define RESET_CAUSE_WDOG 2

#define GLITCH_VAL  0x41736166


static SeqBootPlexInfo boot_plex;

void seq_service_watchdog( void ) {
	struct watchdog_regs *wdog = (struct watchdog_regs *)SEQ_BOOT_WDOG;
	writew(0x5555, &wdog->wsr);
	writew(0xaaaa, &wdog->wsr);
}

void seq_reset_with_watchdog( void ){
	struct watchdog_regs *wdog = (struct watchdog_regs *)SEQ_BOOT_WDOG;

	clrsetbits_le16(&wdog->wcr, WCR_WT_MSK, WCR_WDE);

	writew(0x5555, &wdog->wsr);
	writew(0xaaaa, &wdog->wsr);	/* load minimum 1/2 second timeout */
	while (1) {
		/*
		 * spin before reset
		 */
	}
}

static void load_component( SeqManifest *layout, SeqBootComponentInfo *cinfo, const char *plex, const char *prefix ){
	char *str=NULL;
	char keyname[32];

	sprintf(keyname, "%s_%s", prefix, "source");
	cinfo->nvsaddr = seq_get_keyval_uint32(layout, plex, keyname);

	sprintf(keyname, "%s_%s", prefix, "dest");
	cinfo->ramaddr = seq_get_keyval_uint32(layout, plex, keyname);
	sprintf(keyname, "%s_%s", prefix, "size");
	cinfo->nvslength = seq_get_keyval_uint32(layout, plex, keyname);
	cinfo->ramlength = cinfo->nvslength;

	sprintf(keyname, "%s_%s", prefix, "version");
	str = seq_get_keyval_string(layout, plex, keyname);
	memset(cinfo->version, 0, SEQ_BOOT_VERSION_LENGTH);
	memcpy(cinfo->version, str, strlen(str));
}

int seq_load_plex_manifest( uint8_t plexa ){
	//If plex a load "plexa" values
	SeqManifest *layout = seq_get_manifest(SEQ_MANIFEST_COMPONENT);
	char *current_plex = (plexa ? "plex_a" : "plex_b");
	char *version = seq_get_keyval_string(layout, current_plex, "firmware_ver");

	if(!layout || !current_plex || !version){
		printf("Failed to load firmare component information. Unable to continue.\n");
		return -1;
	}

	printf("\nLoading firmware version [%s] for %s\n", version, (plexa ? "Plex A" : "Plex B"));;

	load_component(layout, &boot_plex.coretee, current_plex, "coretee");
	load_component(layout, &boot_plex.atf, current_plex, "atf");
	load_component(layout, &boot_plex.uboot, current_plex, "uboot");
	load_component(layout, &boot_plex.kernel, current_plex, "kernel");
	load_component(layout, &boot_plex.fdt, current_plex, "fdt");
	load_component(layout, &boot_plex.coreteedtb, current_plex, "coretee_dtb");

	if(version) {
		free(version);
		version = 0;
	}

	return 0;
}


SeqBootPlexInfo* seq_get_current_plex( void ){
	return &boot_plex;
}

static int atf_setup(SeqBootPlexInfo *current_plex)
{
	int res=SEQ_SUCCESS;

#ifdef CONFIG_CORETEE_ENABLE_BLOB

	//printf("Loading ATF from BLOB [0x%08lx]->[0x%08lx]\n", current_plex->atf.nvsaddr, current_plex->atf.ramaddr);
	printf("Loading ATF from GOLD BLOB\n");
	res = seq_blob_decapsulate( SEQ_BLOB_MEM_MMC, current_plex->atf.nvsaddr, current_plex->atf.ramaddr, SEQ_BLOB_KEY_OTPMK, &current_plex->atf.ramlength);

#else

	// Non blobbed CORETEE
	printf("Loading ATF MMC: 0x%08lx. Size: 0x%08lx  Loading to: 0x%08lx\n", current_plex->atf.nvsaddr, current_plex->atf.nvslength, current_plex->atf.ramaddr);
	res = seq_mmc_read( current_plex->atf.nvsaddr, current_plex->atf.nvslength, (void *)current_plex->atf.ramaddr );

#endif // CONFIG_CORETEE_ENABLE_BLOB

	if (res) {
		printf("Failed to load ATF!!\n");
		return res;
	}

	return 0;
}

static int coretee_setup( SeqBootPlexInfo *current_plex )
{
	int res = SEQ_SUCCESS;

#ifdef CONFIG_CORETEE_ENABLE_BLOB

	//printf("Loading CoreTEE from GOLD BLOB [0x%08lx]->[0x%08lx]\n", current_plex->coretee.nvsaddr, current_plex->coretee.ramaddr);
	printf("Loading CoreTEE from GOLD BLOB\n");
	res = seq_blob_decapsulate( SEQ_BLOB_MEM_MMC, current_plex->coretee.nvsaddr, current_plex->coretee.ramaddr, SEQ_BLOB_KEY_OTPMK, &current_plex->coretee.ramlength);

	printf("Loading CORETEE DTB from GOLD BLOB\n");
	res = seq_blob_decapsulate( SEQ_BLOB_MEM_MMC, current_plex->coreteedtb.nvsaddr, current_plex->coreteedtb.ramaddr, SEQ_BLOB_KEY_OTPMK, &current_plex->coreteedtb.ramlength );

#else

	// Non blobbed CORETEE
	printf("Loading CORETEE MMC: 0x%08lx. Size: 0x%08lx  Loading to: 0x%08lx\n", current_plex->coretee.nvsaddr, current_plex->coretee.nvslength, current_plex->coretee.ramaddr);
	res = seq_mmc_read( current_plex->coretee.nvsaddr, current_plex->coretee.nvslength, (void *)current_plex->coretee.ramaddr );

	printf("Loading CORETEE DTB MMC: 0x%08lx. Size: 0x%08lx  Loading to: 0x%08lx\n", current_plex->coreteedtb.nvsaddr, current_plex->coreteedtb.nvslength, current_plex->coreteedtb.ramaddr);
	res = seq_mmc_read( current_plex->coreteedtb.nvsaddr, current_plex->coreteedtb.nvslength, (void *)current_plex->coreteedtb.ramaddr );

#endif // CONFIG_CORETEE_ENABLE_BLOB


	if (res) {
		printf("[%s] - FAILED to load CORETEE\n", __func__);
	}
	return res;
}

/*
	If we need to install the kernel from SPL. Do it here.
	If the kernel is an itb image then the different components will be extracted
	   in the main u-boot code.
*/
static int kernel_setup( SeqBootPlexInfo *current_plex )
{
	int res=SEQ_SUCCESS;
	uintptr_t ddr = SEQ_BOOT_COMPONENT_DDR_BASE+(current_plex->kernel.nvsaddr*SEQ_MMC_BLOCK_SIZE);

#ifdef CONFIG_CORETEE_ENABLE_BLOB
	///printf("Loading KERNEL from GOLD BLOB: 0x%08lx blocks from 0x%08lx to 0x%08lx\n",current_plex->kernel.nvslength,current_plex->kernel.nvsaddr,current_plex->kernel.ramaddr);
	printf("Loading KERNEL from GOLD BLOB\n");
	//printf("Writing to: 0x%08lx\n", ddr);
	res = seq_blob_decapsulate( SEQ_BLOB_MEM_MMC, current_plex->kernel.nvsaddr, ddr, SEQ_BLOB_KEY_OTPMK, &current_plex->kernel.ramlength);

#else

	// Load un-encrypted kernel
	printf("Loading KERNEL image: 0x%08lx blocks from 0x%08lx to 0x%08lx\n",current_plex->kernel.nvslength,current_plex->kernel.nvsaddr,current_plex->kernel.ramaddr);
	printf("Writing to: 0x%08lx\n", ddr);
	res = seq_mmc_read(current_plex->kernel.nvsaddr,current_plex->kernel.nvslength,(void *)ddr);

#endif // CONFIG_CORETEE_ENABLE_BLOB

	if (res) {
		printf("[%s] FAILED\n", __func__);
	}
	return res;
}

/*
	If we need to install the kernel FDT from SPL. Do it here.
*/
static int fdt_setup( SeqBootPlexInfo *current_plex )
{
	int res=SEQ_SUCCESS;
	uintptr_t ddr = SEQ_BOOT_COMPONENT_DDR_BASE+(current_plex->fdt.nvsaddr*SEQ_MMC_BLOCK_SIZE);

#ifdef CONFIG_CORETEE_ENABLE_BLOB
	printf("Loading FDT from GOLD BLOB: 0x%08lx blocks from 0x%08lx to 0x%08lx\n",current_plex->kernel.nvslength,current_plex->kernel.nvsaddr,current_plex->kernel.ramaddr);
	//printf("Loading FDT from GOLD BLOB\n");
	printf("Writing to: 0x%08lx\n", ddr);
	res = seq_blob_decapsulate( SEQ_BLOB_MEM_MMC, current_plex->fdt.nvsaddr, ddr, SEQ_BLOB_KEY_OTPMK, &current_plex->fdt.ramlength);

#else

	// Load un-encrypted kernel
	printf("Loading FDT image: 0x%08lx blocks from 0x%08lx to 0x%08lx\n",current_plex->fdt.nvslength,current_plex->fdt.nvsaddr,current_plex->fdt.ramaddr);
	printf("Writing to: 0x%08lx\n", ddr);
	res = seq_mmc_read(current_plex->fdt.nvsaddr,current_plex->fdt.nvslength,(void *)ddr);

#endif // CONFIG_CORETEE_ENABLE_BLOB

	if (res) {
		printf("[%s] FAILED\n", __func__);
	}
	return res;
}

/*
  Read u-boot-dtb.bin or u-boot.itb to DRAM
  if itb:
  	  Extract u-boot-nodtb to expected destination address, make note of length
  	  Determine board and som type
  	  Extract corresponding DTB and 1) append to u-boot 2) place at expected location for Linux FDT
 */
static int uboot_setup(SeqBootPlexInfo *current_plex)
{
	int res=SEQ_SUCCESS;
	uintptr_t ddr = SEQ_BOOT_COMPONENT_DDR_BASE+(current_plex->uboot.nvsaddr*SEQ_MMC_BLOCK_SIZE);

#if IS_ENABLED(CONFIG_CORETEE_USE_UBOOT_ITB)
	uintptr_t fdt_ddr = SEQ_BOOT_COMPONENT_DDR_BASE+(current_plex->fdt.nvsaddr*SEQ_MMC_BLOCK_SIZE);
	const void *fit=NULL, *fdt_data=NULL, *uboot_data=NULL;
	int conf_node=0;
	const char *fdt_name=NULL, *firmware_name=NULL;
	//const char *dtb_name=NULL, *uboot_name=NULL;
	int images=0, fdt_node=0, fdt_len=0, d_len=0, uboot_node=0;
	size_t fdt_length=0, uboot_length=0;
#endif //CORETEE_USE_UBOOT_ITB

	//Decrypt or move .itb to temporary location.
#ifdef CONFIG_CORETEE_ENABLE_BLOB
	//printf("Loading u-boot from GOLD BLOB: 0x%08lx blocks from 0x%08lx to 0x%08lx\n",current_plex->uboot.nvslength,current_plex->uboot.nvsaddr,ddr);
	printf("Loading u-boot from GOLD BLOB\n");
	res = seq_blob_decapsulate( SEQ_BLOB_MEM_MMC, current_plex->uboot.nvsaddr, ddr, SEQ_BLOB_KEY_OTPMK, &current_plex->uboot.ramlength);
#else
	// Load un-encrypted u-boot ITB
	printf("Loading PLAIN u-boot 0x%08lx blocks from 0x%08lx to 0x%08lx\n",
			current_plex->uboot.nvslength,
			current_plex->uboot.nvsaddr,
			ddr);
	res = seq_mmc_read(current_plex->uboot.nvsaddr,
			current_plex->uboot.nvslength,
			(void *)ddr);
#endif


#if IS_ENABLED(CONFIG_CORETEE_USE_UBOOT_ITB)

	printf("    Parsing u-boot ITB...\n");
	fit = (void *)ddr;

	conf_node = fit_find_config_node(fit);
	if (conf_node < 0) {
		printf("Could not find valid configuration .... hang\n");
		asm volatile("b .\n");
	}

	images = fdt_path_offset(fit, FIT_IMAGES_PATH);

	fdt_name = fdt_getprop(fit, conf_node, FIT_FDT_PROP, &fdt_len);
	//dtb_name = fdt_getprop(fit, conf_node, "description", &d_len);

	firmware_name = fdt_getprop(fit, conf_node, FIT_FIRMWARE_PROP, &d_len);
	uboot_node = fdt_subnode_offset(fit, images, firmware_name);
	//uboot_name = fdt_getprop(fit, uboot_node, FIT_DESC_PROP, &d_len);

	//printf("Uboot info: uboot_node: %d uboot-label: %s uboot_name: %s\n", uboot_node, firmware_name, uboot_name);

	if (!fdt_name) {
		printf("Could not find description .... hang\n");
		asm volatile("b .\n");
	}

	printf("    DTB loaded from U-Boot\n");
	//printf("DTB: %s node: %s images: %d\n", dtb_name, fdt_name, images);

	fdt_node = fdt_subnode_offset(fit, images, fdt_name);
	//printf("DTB: %s node: %s images: %d fdt_node: %d\n", dtb_name, fdt_name, images, fdt_node);

	res = fit_image_get_data(fit, fdt_node, &fdt_data, &fdt_length);
	//printf("FDT data: res: %d fdt_data: 0x%p fdt_length: %ld\n", res, fdt_data, fdt_length);

	res = fit_image_get_data(fit, uboot_node, &uboot_data, &uboot_length);
	//printf("Uboot data: res: %d uboot_data: 0x%p uboot_length: %ld\n", res, uboot_data, uboot_length);

	/*
	  Uboot is at uboot_data in memory, length uboot_length
	  FDT is at fdt_data in memory, length fdt_length
	  Relocate uboot to target address, append fdt, copy fdt to expected address for linux
	 */

	/* uboot and fdt */
	/*printf("Uboot:     load: 0x%p src: 0x%p length: %d\n",
			(void *)current_plex->uboot.ramaddr,
			uboot_data,
			uboot_length);
	printf("Uboot dtb: load: 0x%p src: 0x%p length: %d\n",
			(void *)current_plex->uboot.ramaddr + uboot_length,
			fdt_data,
			fdt_length);*/

	memcpy((void *)current_plex->uboot.ramaddr, uboot_data, uboot_length);
	memcpy((void *)current_plex->uboot.ramaddr + uboot_length, fdt_data, fdt_length);

	/* linux fdt */
	/*printf("Linux dtb: load: 0x%p src: 0x%p length: %d\n",
			(void *)fdt_ddr,
			fdt_data,
			fdt_length);*/
	memcpy((void *)fdt_ddr, fdt_data, fdt_length);

#else //CORETEE_USE_UBOOT_ITB

	//Copy deblobbed data to correct RAM location
	printf("Copying u-boot binary to 0x%08x...\n", current_plex->uboot.ramaddr);
	memcpy((void *)current_plex->uboot.ramaddr, (void*)ddr, current_plex->uboot.nvslength);

#endif //CORETEE_USE_UBOOT_ITB

	if (res) {
		printf("[%s] FAILED\n", __func__);
	}
	return res;
}

int seq_component_setup( void )
{
	typedef void __noreturn (*image_entry_noargs_t)(void);
	SeqBootPlexInfo *current_plex = seq_get_current_plex( );
	image_entry_noargs_t image_entry = NULL;
	int res = SEQ_SUCCESS;

	if (!current_plex) {
		return SEQ_ERROR_ITEM_NOT_FOUND;
	}

	if ((res=kernel_setup( current_plex )) != SEQ_SUCCESS) {
		goto error;
	}

#if !IS_ENABLED(CONFIG_CORETEE_USE_UBOOT_ITB)
	if ((res=fdt_setup(current_plex)) != SEQ_SUCCESS) {
		goto error;
	}
#endif
	//Otherwise fdt is copied from uboot

	if ((res=uboot_setup(current_plex)) != SEQ_SUCCESS) {
		goto error;
	}

	if ((res=coretee_setup(current_plex)) != SEQ_SUCCESS) {
		goto error;
	}

	if ((res = atf_setup(current_plex)) != SEQ_SUCCESS) {
		goto error;
	}

#ifndef CONFIG_CORETEE_GOLD
	//Everything is in place. Update DT.
	seq_act_update_dt( current_plex );
#endif

	//Jump to ATF
	image_entry = (image_entry_noargs_t)(unsigned long)current_plex->atf.ramaddr;

	//printf("Calling into ATF: %p\n", image_entry);
	//seq_print_bytes((void*)image_entry, 32);

	printf("\n-----------------------------------------------------------------------\n");
	printf("Separating RAM into Secure and Non-Secure\n");
	printf("-----------------------------------------------------------------------\n\n");

	/*
	 * This doesn't return. ATF calls directly into u-boot
	 */
	image_entry();

error:
	printf("Error loading components. Halting boot!\n");
	while (1) {}
	return res;
}


static uint32_t seq_get_manifest_offset( int index )
{
	if (index == 0)
		return 0;

	uintptr_t address=seq_get_manifest_address_by_index(index);
	return address - CORETEE_COMPONENT_DATA_OFFSET;
}

static uint8_t* get_aes_slip_key(int index,size_t* size)
{
	uint8_t* key=0;
	SeqManifest *slip=seq_get_manifest(SEQ_MANIFEST_OEM);
	SeqParamKey *aeskey=NULL;

	if (!slip) {
		printf("OEM slip not found.\n");
		return key;
	}

	switch (index)
	{
	case SEQ_MANIFEST_CERTS:
		aeskey=seq_find_param(slip, SEQ_MANIFEST_SECTION_CRYPT, SEQ_MANIFEST_KEY_CRYPT_CERTS);
		break;
	case SEQ_MANIFEST_EMPOWER:
		aeskey=seq_find_param(slip, SEQ_MANIFEST_SECTION_CRYPT, SEQ_MANIFEST_KEY_CRYPT_EMPOWER);
		break;
#ifdef CONFIG_CORETEE_USE_KEYRING
	case SEQ_MANIFEST_KEYRING:
		aeskey=seq_find_param(slip, SEQ_MANIFEST_SECTION_CRYPT, SEQ_MANIFEST_KEY_CRYPT_KEYRING);
		break;
#endif
	default:
		break;
	}

	if (aeskey) {
		key=(uint8_t*)malloc_cache_aligned(aeskey->size);
		if(key) {
			memcpy(key,aeskey->value,aeskey->size);
			*size=aeskey->size;
		}
	}

	return key;
}

static void decrypt_manifest(SeqManifestIndex index, uintptr_t *address)
{
	uintptr_t ddr_dest=0;
	int ret=0;
	uint32_t slip_offset=seq_get_manifest_offset(index)*SEQ_MMC_BLOCK_SIZE;
	ddr_dest = CORETEE_TZDRAM_SEQ_MANIFEST_BASE + slip_offset;

	if (!address) {
		return;
	}

	//Don't touch the SEQ manifest.
	if (index == SEQ_MANIFEST_SEQ) {
		printf("Copying SEQ manifest from MMC [0x%08x] to DDR [0x%08x].", *address, ddr_dest);
		ret=seq_mmc_read(*address, SEQ_MANIFEST_SIZE, ddr_dest);
		return;
	}

	//printf("Manifest offset for index[%d] is : %d\n", index, slip_offset);

	switch (index)
	{
	case SEQ_MANIFEST_CERTS:
	case SEQ_MANIFEST_EMPOWER:
#ifdef CONFIG_CORETEE_USE_KEYRING
	case SEQ_MANIFEST_KEYRING:
#endif
	{
		uint8_t* ebuffer=NULL;
		printf("Processing encrypted manifest [%s]\n", seq_get_manifest_name(index));

		// load from mmc
		ebuffer=(uint8_t*)malloc_cache_aligned(SEQ_MANIFEST_SIZE);
		if (!ebuffer) {
			printf("Failed to allocate buffer for manifest!\n");
			*address=0; //Error condition
			return;
		}

		ret=seq_mmc_read(*address,SEQ_MANIFEST_SIZE,ebuffer);
		if (!ret) {
			// check ebuffer for aesmagic header
			SeqCryptSlip_t *cheader=(SeqCryptSlip_t*)ebuffer;
			if (!memcmp(cheader->magic,SEQ_AES_MAGIC,sizeof(SEQ_AES_MAGIC))) {
				int cryptres=0;
				size_t keysize=0;
				uint8_t* key=get_aes_slip_key(index,&keysize);
				size_t buffersize=cheader->cryptsize;

				if (key) {
					// this overwrites the header! Do not use cheader after this point
					memmove(ebuffer,ebuffer+sizeof(SeqCryptSlip_t),SEQ_MANIFEST_SIZE-sizeof(SeqCryptSlip_t));

					cryptres=seq_dec_aes_ctr(key,keysize,ebuffer,(uint8_t*)ddr_dest,buffersize,NULL);
					free(key);
					if (cryptres != 0) {
						printf("Failed to decrypt manifest buffer!\n");
						free(ebuffer);
						*address=0; //Error condition
						return;
					}

				} else {
					printf("Manifest could not be decrypted (missing key)\n");
					free(ebuffer);
					*address=0; //Error condition
					return;
				}
			} else {
				//printf("AES slip in plain\n");
				memcpy((void*)ddr_dest,ebuffer,SEQ_MANIFEST_SIZE);
			}
		} else {
			printf("FAILED to read AES blob header: %d\n",ret);
			*address=0;
			free(ebuffer);
			return;
		}

		free(ebuffer);
	}
	break;
	default:
	{
#ifdef CONFIG_CORETEE_ENABLE_BLOB
		uint8_t *ebuffer=NULL;
		uint8_t *rnd=NULL;

		ebuffer=(uint8_t *)malloc_cache_aligned(SEQ_MANIFEST_SIZE);
		if (!ebuffer) {
			printf("Failed to allocate memory for encrypted manifest!!\n");
			*address=0; //Error condition
			return;
		}

		rnd=(uint8_t *)malloc_cache_aligned(32);
		if (!rnd) {
			printf("Failed to allocate memory for encrypted manifest!!\n");
			free(ebuffer);
			*address=0; //Error condition
			return;
		}

		memset(ebuffer,0,SEQ_MANIFEST_SIZE);
		memset(rnd,0,32);

		seq_select_otpmk();
		ddr_dest = CORETEE_TZDRAM_SEQ_MANIFEST_BASE + slip_offset;

		//printf("Read blob 0x%08lx to 0x%08lx\n", *address, ddr_dest);
		printf("Processing blobbed manifest [%s]\n", seq_get_manifest_name(index));
		ret=seq_mmc_read(*address,SEQ_MANIFEST_SIZE,ebuffer);
		if (!ret) {
			SeqBlobHeaderType header;
			memcpy(&header,ebuffer,sizeof(SeqBlobHeaderType));
			//printf("totalsize: 0x%x   payloadsize: 0x%x\n",header.totalsize,header.payloadsize);
			memmove(ebuffer,ebuffer+sizeof(SeqBlobHeaderType),header.totalsize-sizeof(SeqBlobHeaderType));

			ret=blob_decap((u8*)rnd,(u8*)ebuffer,(u8*)ddr_dest,header.payloadsize);
			if (ret) {
				printf("FAILED to decrypt blob for index[%d] : %d\n",index,ret);
				*address=0;
				return;
			}
		} else {
			printf("FAILED to read blob header for index[%d] : %d\n",index,ret);
			*address=0;
			return; // ** NOTE - thie will leak a SEQ_MANIFEST_SIZE buffer!!!
		}

		free(ebuffer);
		free(rnd);
#else
		//SLI - no decrypting yet, just copy.
		ddr_dest = CORETEE_TZDRAM_SEQ_MANIFEST_BASE + slip_offset;

		/*
				Copy the entire SLIP
		 */
		printf("Copying MANIFEST from [%ld]-0x%08lx to 0x%08lx\n", *address, *address, ddr_dest);
		ret = seq_mmc_read(*address, SEQ_MANIFEST_SIZE, (void*)ddr_dest);
		if (ret) {
			printf("FAILED to load component information for index[%d] from MMC\n", index);
			printf("Error: 0x%08x\n", ret);
			*address = 0;
			return;
		}
#endif
	} // default
	} // switch


	*address = ddr_dest;
}

#define USE_LOW_POWER_GLITCH 1
static int get_reset_cause(void)
{
#ifdef USE_LOW_POWER_GLITCH
	uint32_t lpsr=0;
	lpsr = __raw_readl((void *)(SNVS_BASE_ADDR + SNVS_LPSR));

	//printf("Cause from SNVS %d (8=POR)\n", (lpsr & (1<<3)));
	if((lpsr & 1<<3)){
		return RESET_CAUSE_POR;
	} else {
		return RESET_CAUSE_WDOG;
	}
	return RESET_CAUSE_UNKNOWN;
#else
	struct src *src_regs = (struct src *)SRC_BASE_ADDR;
	u32 cause;
	cause = readl(&src_regs->srsr);
	writel(cause, &src_regs->srsr);
	printf("Cause SRC: 0x%08x    %p\n", cause, &(src_regs->srsr));


	//u16 wcr = readw(WDOG_IPB);
	//printf("WCR: 0x%08x\n", wcr);

	//wcr = readw(WDOG_IPB+0x04);
	//printf("WDOG_WRSR: 0x%08x\n", wcr);

	switch (cause) {
	case 0x00001:
	case 0x00011:
		return "POR";
	case 0x00004:
	{
		struct watchdog_regs *wdog = (struct watchdog_regs *)WDOG_IPB;

		if (wdog->wrsr & 0x02) {
			return("SECURE WATCHDOG");
		}
		return "CSU";
	}
	case 0x00008:
		return "IPP USER";
	case 0x00010:
#ifdef	CONFIG_MX7
		return "WDOG1";
#else
		return "WDOG";
#endif
	case 0x00014:
		return "WDOG2";
	case 0x00020:
		return "JTAG HIGH-Z";
	case 0x00040:
		return "JTAG SW";
	case 0x00080:
		return "WDOG3";
#ifdef CONFIG_MX7
	case 0x00100:
		return "WDOG4";
	case 0x00200:
		return "TEMPSENSE";
#elif defined(CONFIG_MX8M)
	case 0x00100:
		return "WDOG2";
	case 0x00200:
		return "TEMPSENSE";
#else
	case 0x00100:
		return "TEMPSENSE";
	case 0x10000:
		return "WARM BOOT";
#endif
	default:
		return "unknown reset";
	}
#endif //USE_LOW_POWER_GLITCH
}

static void check_startup_registers(void)
{
	char buffer[64];
	int cause = get_reset_cause();
	uint32_t state = 0;
	state = (seq_read_boot_state_values() & 0xFF);

	printf(buffer, "\nReset reason: %d\nState: 0x%02x\n", cause, state);
	if ( cause == RESET_CAUSE_POR ) {
		//This is a power on reset. Set SEQ_BLC to max.
		seq_check_bricked(1, state);
		seq_set_blc_to_max();
	}
}

/*Watchdog Section*/
#define WDT_WCR 0
#define WDT_WSR 2
#define WDT_WRSR 4
#define WDT_WICR 6
#define WDT_WMCR 8
static void lp_deglitch( uint8_t force )
{
	uint32_t lpsr;
	uint32_t hpsvsr;
	uint32_t reg;
	//uint32_t lpgpr0;

	lpsr = __raw_readl((void *)(SNVS_BASE_ADDR + SNVS_LPSR));
	hpsvsr = __raw_readl((void *)(SNVS_BASE_ADDR + SNVS_HPSVSR));

	//printf("Low power - power supply glitch detected %d\n", (lpsr & (1<<3)));
	//lpgpr0 = __raw_readl((void *)(SNVS_BASE_ADDR + SNVS_LPGPR0));
	//printf("START LPGPR0: 0x%08x\n", lpgpr0);

	/* clear errors */
	if (force || (hpsvsr & 0x3f) || (lpsr & 0x01707ff)) {
		uint32_t rst = __raw_readl((void *)(SNVS_BASE_ADDR + SNVS_HPCOMR)); /* HPCOMR */

		//printf("Running deglitch\n");

		__raw_writel(rst | 0x10, (void *)(SNVS_BASE_ADDR+SNVS_HPCOMR)); /* low power reset */
		__raw_writel(0x03f, (void *)(SNVS_BASE_ADDR+SNVS_HPSVSR)); /* clear hp errors */
		__raw_writel(GLITCH_VAL, (void *)(SNVS_BASE_ADDR+SNVS_GLITCH)); /* write deglitch */
		__raw_writel(0x01707ff, (void *)(SNVS_BASE_ADDR+SNVS_LPSR)); /* clear lp errors */
	}
	else {
		printf("%s(%d): NOPOR: LPGPR0: 0x%08x\n", __func__, __LINE__, __raw_readl((void *)(SNVS_BASE_ADDR + SNVS_LPGPR0)));
	}

	//Setting NS Access to registers
	reg = __raw_readl((void*)(SNVS_BASE_ADDR + SNVS_HPCOMR)); // read HPcomr
	reg |= 0x80000000; // enable NS access to SNVS registers (for linux)
	__raw_writel(reg, (void*)(SNVS_BASE_ADDR + SNVS_HPCOMR)); // enable NS access to SNVS
}

void secure_wdog_setup(u32 tmo_ms, u32 pre_interrupt_ms)
{
	uintptr_t snvs_hpcomr;
	uintptr_t snvs_hpsvcr;
	uintptr_t snvs_hphacivr;
	uintptr_t snvs_lpsvcr;
	uintptr_t wdog;
	uint16_t wicr, wcr;

	u16 timeout = (tmo_ms / 500) - 1;
	wcr = (((timeout << 8) & 0xFF00) | (WCR_WDZST | WCR_WDBG | WCR_WDE | WCR_WDT | WCR_SRS | WCR_WDA));
	wicr = ((pre_interrupt_ms / 500) & 0x0ff) | 0x8000; // enable WIE, set/clamp pre-interrupt timeout

	snvs_hpcomr = SNVS_BASE_ADDR + SNVS_HPCOMR;
	snvs_hpsvcr = SNVS_BASE_ADDR + SNVS_HPSVCR;
	snvs_hphacivr = SNVS_BASE_ADDR + SNVS_HPHACIVR;
	snvs_lpsvcr = SNVS_BASE_ADDR + SNVS_LPSVCR;

	wdog = SEQ_BOOT_WDOG;

	{
		writel(/* 0x80000000 |*/ (1 << 18), snvs_hpcomr); /* clear HAC */
		writel(0x01000000, snvs_hphacivr); /* high assurance counter initial value */
		writel(/* 0x80000000 |*/ (1 << 17), snvs_hpcomr); /* load HAC */
		writel(/* 0x80000000 |*/ (1 << 16) | 4, snvs_hpcomr); /* enable HAC, disable soft-fail->non-secure */

		writel(0x80000004, snvs_hpsvcr); /* enable VIO 2 -- wdog */
		writel(0x00000004, snvs_lpsvcr); /* enable VIO 2 -- wdog */
	}

	writew(wcr, wdog + WDT_WCR); /* enable wdog */
	writew(wicr, wdog + WDT_WICR);
}

__attribute__((unused))
void ct_init_sec_wdog(u32 tmo_ms, u32 pre_interrupt_ms)
{
	secure_wdog_setup(tmo_ms, pre_interrupt_ms);
}

void __noreturn seq_run_boot_start( void )
{
	uint32_t stateval=0;
	int blc = 0, rc=0;

	printf("\nThe SPL has passed verification against SRKH in fuses.\n");
	printf("\nRunning Sequitur Labs Secure Boot Steps.\n");

	rc = get_reset_cause();
	if(rc == RESET_CAUSE_POR) {
		seq_set_blc_to_max();
	}

	printf("BLC before deglitch: 0x%02x\n", blc);
	lp_deglitch( 0 ); //Deglitch if power supply gitch detected.

	//Set the watchdog
	/*
	 * NOTE
	 * For testing the fail over boot set the timeout to a shorter value
	 * and have u-boot stop at the command prompt.
	 */
#ifdef CONFIG_SPL_ENABLE_WATCHDOG
	/*
	 * This time must be enough to allow a full update cycle to happen and boot to Linux
	 */
	printf("Setting watchdog time to 60s\n");
	ct_init_sec_wdog(60000, 2000); /* 60s timeout, 2s pre-interrupt/warn */
	//hw_watchdog_init();
#else
	printf("WATCHDOG IS NOT ENABLED\n");
#endif

	printf("\n------------------------------------------------------------------------\n");
	printf("Setting Up Secure Environment\n");
	printf("Loading into Secure RAM and decrypting blobbed components\n");
	printf("------------------------------------------------------------------------\n\n");

	//Parse manifests so we can start the error logging to the correct address.
	//printf("[SLI] - calling init slips on addr: 0x%08x\n", CORETEE_COMPONENT_DATA_OFFSET);
	//asm volatile("b .\n");
	if (seq_init_manifests(CORETEE_COMPONENT_DATA_OFFSET, decrypt_manifest)) {
		printf("Failed to initialize the component information.\n");
		//reset - We've got nowhere to go.
		seq_reset_with_watchdog();
	}

#if 0
	{
		uint8_t hash=0;
		printf("Running hash test\n");
		hash=malloc_cache_aligned(32);
		if (!hash) {
			printf("Hash buffer was not allocated\n");
		} else {
			hw_sha256(0x40000000,32,hash,0);
			outputData(hash, 32);
		}
	}
#endif

	//Check power on reset
	check_startup_registers();

	stateval = (seq_read_boot_state_values() & 0xFF);
	//printf("Starting boot with state: 0x%02x\n\n", stateval);

	//Go to start of state decisions.
	seq_boot_state_start(stateval);

	//Shouldn't reach here...
	printf("End of [%s]\n", __func__);
	while(1) {
		static int count=0;
		udelay(10000);
		printf(".");
		if (count % 30 == 0)
			printf("\n");
		count++;
	};
}

#else //CONFIG_SPL BUILD

static uint32_t get_boot_state_values( void )
{
	uint32_t stateval=0;
	int res=0;
	uint8_t stateblk[SEQ_MMC_BLOCK_SIZE];
	/*
	  read the value from SPI
	*/
	res = seq_mmc_read(SEQ_BOOT_STATE_MMC_OFFSET, SEQ_MMC_BLOCK_SIZE, stateblk);
	if(res){
		printf("Failed to load bootstate\n");
	}
	memcpy((void*)(&stateval), stateblk, sizeof(uint32_t));
	return stateval;
}

void seq_board_coretee_late_init( void )
{
	char kdest[32];
	char fdest[32];
	unsigned int bootstate=0;
	struct arm_smccc_res kernelres;
	struct arm_smccc_res fdtres;

	kernelres.a0 = 0;
	fdtres.a0 = 0;

	printf("Getting component info from coretee\n");
	bootstate = get_boot_state_values();
	printf("Bootstate: %x\n", bootstate);
	printf("Calling SMC...\n");
	arm_smccc_smc(ARM_SMCCC_CORETEE_GET_KERNEL, bootstate, 0, 0, 0, 0, 0, 0, &kernelres);
	arm_smccc_smc(ARM_SMCCC_CORETEE_GET_FDT, bootstate, 0, 0, 0, 0, 0, 0, &fdtres);

	printf("kernelres: %ld    fdtres: %ld\n", kernelres.a0, fdtres.a0);

	if(kernelres.a0 == 0 && fdtres.a0 == 0){
		uintptr_t kddr = SEQ_BOOT_COMPONENT_DDR_BASE + (kernelres.a1 * SEQ_MMC_BLOCK_SIZE);
		uintptr_t fddr = SEQ_BOOT_COMPONENT_DDR_BASE + (fdtres.a1 * SEQ_MMC_BLOCK_SIZE);
		//Components should have been copied during SPL boot.
		printf("/***************************\nCopying back from DDR.\n");
		printf("Copying kernel from [0x%08lx] to [0x%08lx]  Size: 0x%08lx\n", kddr, kernelres.a3, kernelres.a2 );
		memcpy((void*)kernelres.a3, (void*)(kddr), kernelres.a2);

		printf("Copying FDT from [0x%08lx] to [0x%08lx]  Size: 0x%08lx\n", fddr, fdtres.a3, fdtres.a2 );
		memcpy((void*)fdtres.a3, (void*)fddr, fdtres.a2);
		snprintf(kdest, 32, "0x%08lx", kernelres.a3);
		snprintf(fdest, 32, "0x%08lx", fdtres.a3);

		/*
		 * Update the boot settings based on values returned from CoreTEE.
		 * These values are extracted from the plex manifest.
		 */
		env_set("loadaddr", kdest);
		env_set("fdt_addr", fdest);
		env_set("bootcmd", CORETEE_BOOT_CMD);
	} else {
		printf("FAILED to load kernel params from CoreTEE. [%ld] [%ld]\n", kernelres.a0, fdtres.a0);
	}
}

#endif //CONFIG_SPL BUILD
