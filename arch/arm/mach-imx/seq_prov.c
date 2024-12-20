#include <common.h>
#include <memalign.h>
#include <asm/arch/clock.h>
#include <fsl_sec.h>
#include <uboot_aes.h>
#include <mmc.h>
#include <fuse.h>
#include <hw_sha.h>
#include <fsl_caam.h>
#include <spi.h>
#include <spi_flash.h>
#include <linux/delay.h>
#include <fsl_wdog.h>
#include <asm/mach-imx/sys_proto.h>

#include <seq_error.h>
#include <seq_list.h>
#include <seq_manifest.h>
#include <seq_boot_manifests.h>
#include <seq_ecc_utils.h>
#include <seq_keys.h>
#include <seq_cipher.h>
#include <seq_bootstates.h>
#include <seq_boot.h>
#include <seq_blob.h>
#include <seq_memio.h>
#include <seq_prov.h>

#include "seq_prov_fuse_values.h"

#if IS_ENABLED(CONFIG_CORETEE_PROV_TESTS)
#include <seq_tests.h>
#endif //CONFIG_CORETEE_PROV_TESTS

//Scratch DDR values for decapsulating components.
#define BSRC 0x60000000
#define BDST 0x70000000
#define BRND 0x78000000

//Load provisioning slip below where CoreTEE will be.
//CoreTEE is not up during provisioning but this gives us an address to start from.
//DDR may be bigger but this is more portable to different platforms.
#define SLIPADDR (CORETEE_TZDRAM_SEQ_MANIFEST_BASE)

//Location in NVM where the provisioning manifest is located.
#define SLIPMMC CORETEE_COMPONENT_DATA_OFFSET

//#define DEBUG
#ifdef DEBUG
#define DMSG printf
#else
#define DMSG(...) {}
#endif


#if IS_ENABLED(CONFIG_CORETEE_ENABLE_BLOB)

#if IS_ENABLED(CONFIG_CORETEE_USE_KEYRING)
#define NUM_SINGLE_COMPONENTS 8
#else
#define NUM_SINGLE_COMPONENTS 7
#endif

#else //CONFIG_CORETEE_ENABLE_BLOB

#if IS_ENABLED(CONFIG_CORETEE_USE_KEYRING)
#define NUM_SINGLE_COMPONENTS 6
#else
#define NUM_SINGLE_COMPONENTS 5
#endif

#endif //CONFIG_CORETEE_ENABLE_BLOB

static char* single_component_names[NUM_SINGLE_COMPONENTS]={
	"spl",
	"pd_oem",
	"pd_seq",
	"certs",
	"empower"
#if IS_ENABLED(CONFIG_CORETEE_ENABLE_BLOB)
	, "layout", "brn"
#endif
#if IS_ENABLED(CONFIG_CORETEE_USE_KEYRING)
	, "keyring"
#endif
	};

#define NUM_PLEXES 2
static char* plex_names[NUM_PLEXES]={"plex_a", "plex_b"};

#define NUM_COMPONENTS 6
static char* plex_component_names[NUM_COMPONENTS]={"uboot", "atf", "coretee", "kernel", "fdt", "coretee_dtb"};

#define CHECK_CPU_REV
#define EXPECTED_CPU_REV 0x00182010 //IMX8MP[8]

typedef struct compdata {
	SeqManifest* manifest;
	uint32_t offset;
} SeqComponentDataType;

#define MEDIA_MMC 0
#define MEDIA_SF 1
#define MEDIA_SDCARD 2

#define P(val) (void*)(val)

struct mmc * _emmc_dev=NULL;
struct mmc * _sd_dev=NULL;
struct mmc * _prov_dev=NULL;

static uint8_t *_keymod = NULL;

#if IS_ENABLED(CONFIG_CORETEE_ENABLE_BLOB)
int blob_decap(u8*,u8*,u8*,u32,u8);
int blob_encap(u8*,u8*,u8*,u32,u8);
#endif

#if IS_ENABLED(CONFIG_CORETEE_PROV_TESTS)
void execute_cert_test( void );
#endif //CONFIG_CORETEE_PROV_TESTS

#if IS_ENABLED(CONFIG_CORETEE_ENABLE_BLOB)
static int deblob_component( void *addr, uint32_t blobsize )
{
	int res=-1;
	uint32_t size;
	uint8_t *scratch = NULL;
	SeqBlobHeaderType *header=(SeqBlobHeaderType*)addr;

	if (memcmp(header->magic, SEQ_BLOB_MAGIC, SEQ_BLOB_MAGIC_LENGTH)) {
		printf("Invalid blob!\n");
		return res;
	}

	if (blobsize < header->totalsize) {
		printf("Invalid size of blob\n");
		return res;
	}

	size = header->payloadsize;

	scratch = malloc_cache_aligned(size);
	if (!scratch) {
		printf("[%s] - Failed to allocate aligned memory!\n", __func__);
		return res;
	}

	//Force known alignment
	memcpy((void*)BDST, addr+sizeof(SeqBlobHeaderType), size);

	seq_select_zmk();
	res=blob_decap((u8*)_keymod, (u8*)BDST, (u8*)scratch, size-512, 0);
	if (!res) {
		//Copy deblobbed data back to 'addr'.
		memcpy(addr+sizeof(SeqBlobHeaderType), scratch, size);
	} else {
		printf("Deblobbing failed!\n");
	}

	free(scratch);
	return res;
}

static int reblob_component( void *addr, uint32_t componentsize )
{
	int res=-1;
	int diff=0;
	uint8_t *plainbuffer=addr;
	uint32_t plainsize=0;
	uint8_t *actualdest=NULL;
	uint8_t *aligned=NULL;
	SeqBlobHeaderType *header=NULL;
	uint8_t *srcbuffer=NULL;
	uint32_t payloadsize=0;
	uint32_t size;

	header = (SeqBlobHeaderType*)addr;

	if (!memcmp(header->magic, SEQ_BLOB_MAGIC, SEQ_BLOB_MAGIC_LENGTH)) {
		//Header is at start of buffer
		plainbuffer = addr + sizeof(SeqBlobHeaderType);
		plainsize = header->plainsize;
		payloadsize = header->payloadsize;
		size = payloadsize;
	} else {
		size = componentsize;
	}

	srcbuffer = (uint8_t*)malloc_cache_aligned(size);
	if (!srcbuffer) {
		printf("[%s] - Failed to allocate aligned memory!\n", __func__);
		return res;
	}

	//BRN isn't larger than MMC block size. It wasn't encrypted...
	diff = size > 512 ? 512 : 0;

	//Copy to aligned buffer
	memcpy(srcbuffer,plainbuffer,size);

	header=(SeqBlobHeaderType*)BDST;
	memcpy(header->magic, SEQ_BLOB_MAGIC, SEQ_BLOB_MAGIC_LENGTH);
	header->totalsize=  diff > 0 ? size : (size + 48); /*Add blob padding*/
	header->payloadsize=size-diff;
	header->plainsize = plainsize;
	actualdest=(uint8_t*)(BDST+sizeof(SeqBlobHeaderType));
	aligned=(uint8_t*)malloc_cache_aligned(header->totalsize);

	if (!aligned) {
		free(srcbuffer);
		printf("[%s] - Failed to allocate aligned memory!\n", __func__);
		return res;
	}

	memset(aligned,0,header->totalsize);

	DMSG("Encap Copying from: %p   to    %p     %d\n", (void*)srcbuffer, (void*)aligned, (size-diff));
	seq_select_otpmk();
	res=blob_encap((u8*)_keymod,(u8*)srcbuffer,(u8*)aligned,size-diff, 0);

	if (diff == 0) {
		//Make sure to save blob header
		header->totalsize = header->totalsize + sizeof(SeqBlobHeaderType);
	}

	memcpy(actualdest,aligned,size);
	memcpy(addr, (void*)BDST, header->totalsize);

	free(srcbuffer);
	free(aligned);
	return res;
}

static void load_brn(SeqManifest* manifest)
{
	SeqParamKey* brnmmc=seq_find_param(manifest,"brn","source");
	if (brnmmc) {
		uint32_t brnmmcval=seq_value_uint32_t(brnmmc);
		DMSG("loading BRN from 0x%08x\n",brnmmcval);
		seq_mmc_read_dev(_prov_dev, brnmmcval,SEQ_MMC_BLOCK_SIZE,P(BRND));
	} else {
		printf("Could not find BRN parameter\n");
	}
}

#endif

void reblob_manifest( SeqManifest *slip )
{
	size_t sizeval=0;
	int slipsize=0;
	int bres=0;
	uint8_t *parambuffer=NULL;

#ifdef CONFIG_CORETEE_ENABLE_BLOB
	SeqBlobHeaderType *header=NULL;
	uint8_t *actualdest=NULL, *aligned=NULL;
#endif //CONFIG_CORETEE_ENABLE_BLOB

	if (!slip) {
		return;
	}

	//Convert SLIP to binary blob
	parambuffer = seq_get_binary_manifest(slip, &slipsize);
	if (!parambuffer) {
		printf("Failed to load manifest!\n");
		return;
	}

#ifdef CONFIG_CORETEE_ENABLE_BLOB
	slipsize+=sizeof(SeqBlobHeaderType);

	//Align to MMC block size
	sizeval = ((slipsize/512)+1)*512;
	sizeval += 512; //Add padding

	memset(P(BSRC), 0, sizeval);
	memset(P(BDST), 0, sizeval);
	header=(SeqBlobHeaderType*)BDST;

	//Make sure to align it, best just copy to known alignment
	memcpy(P(BSRC), parambuffer, slipsize);
	free(parambuffer);

	header->totalsize=sizeval;
	header->payloadsize=sizeval-512;

	actualdest=(uint8_t*)(BDST+sizeof(SeqBlobHeaderType));
	aligned=(uint8_t*)malloc_cache_aligned(sizeval);

	if (!aligned) {
		printf("Failed to allocate aligned memory.\n");
		return;
	}
	memset(aligned,0,sizeval);

	seq_select_otpmk();
	bres=blob_encap((u8*)_keymod,(u8*)BSRC,(u8*)aligned,sizeval-512, 0);
	printf("[%s] - %s (%d)\n",__func__, (bres==0) ? "SUCCESS" : "FAILED",bres);

	memcpy(actualdest,aligned,sizeval);
	free(aligned);
#else //CONFIG_CORETEE_ENABLE_BLOB
	sizeval = slipsize;
	memcpy(P(BDST), parambuffer, sizeval);
	free(parambuffer);
#endif //CONFIG_CORETEE_ENABLE_BLOB

	//Save back to storage
	bres=seq_mmc_write_dev(_prov_dev,slip->nvm,sizeval,P(BDST));
	if (bres) {
		printf("Failed to write manifest back to NVM!\n");
	}
}

static SeqManifest* load_manifest(void)
{
	SeqManifest* res=0;
	int rres=-1;
	DMSG("Loading layout from: 0x%08x...\n", SLIPMMC);
	rres = seq_mmc_read_dev(_prov_dev, SLIPMMC, SEQ_MANIFEST_SIZE, P(SLIPADDR));
	if (rres) {
		DMSG("Load slip from NVM res: %d\n", rres);
	}
	res=seq_load_manifest(SLIPADDR);
	return res;
}

static int save_to_media( uint8_t mediaval, void *buffer, uint32_t destval, uint32_t sizeval )
{
	// write to media : destval
	int bres=-1;
#if USE_MANIFEST_MEDIA
	switch (mediaval)
	{
	case MEDIA_MMC:
		//Test device. We didn't fail during setup
		if (!_emmc_dev) {
			printf("Failed to write to eMMC. No driver\n");
			bres=-1;
			break;
		}
		//printf("  Writing to the MMC block offset: [0x%08x]    bytes[0x%08x]... ", destval, sizeval);
		bres=seq_mmc_write_dev(_emmc_dev, destval,sizeval, buffer);
		printf("   %s\n", (bres==0) ? "SUCCESS" : "FAILED");
		break;
	case MEDIA_SF:
		printf("  SF media not available\n");
		bres = -1;
		break;
	case MEDIA_SDCARD:
		if (!_sd_dev) {
			printf("Failed to write to SD card. No driver\n");
			bres=-1;
			break;
		}
		printf("  Writing to the SDCARD (0x%08x block offset): ",destval);
		bres=seq_mmc_write_dev(_sd_dev, destval,sizeval,buffer);
		printf("%s\n", (bres==0) ? "SUCCESS" : "FAILED");
		break;
	}
#else
	bres=seq_mmc_write_dev(_prov_dev, destval,sizeval, buffer);
	printf("   %s\n", (bres==0) ? "SUCCESS" : "FAILED");
#endif
	return bres;
}

#define SET_KEYNAME(p,n) if (p) { sprintf(keyname, "%s_%s", p, n); } else { strcpy(keyname, n); }

static uint32_t diversify_component(SeqManifest *manifest, const char* section, const char *prefix) {
	uint32_t res=0, done=0;
	uint32_t srcval=0, sizeval=0, dstval=0;
	uint8_t media=0;
	char keyname[32];

#ifdef CONFIG_CORETEE_ENABLE_BLOB
	SeqParamKey* blobbedkey=NULL;
	SeqParamKey* reblobkey=NULL;
	uint8_t blobbed = 0;
	uint8_t reblob = 0;
#endif /*CONFIG_CORETEE_ENABLE_BLOB*/

	memset(keyname, 0, 32);

	printf("\nHandling component %s : %s...\n",section, prefix ? prefix : "");

	SET_KEYNAME(prefix, "source");
	SeqParamKey* srckey=seq_find_param(manifest,section,keyname);
	SET_KEYNAME(prefix, "prov_dest");
	SeqParamKey* dstkey=seq_find_param(manifest,section,keyname);
	SET_KEYNAME(prefix, "size");
	SeqParamKey* sizekey=seq_find_param(manifest,section,keyname);

	SeqParamKey* mediakey=seq_find_param(manifest,section,"media");

	if (!srckey || !sizekey) {
		printf("Failed to load component: %s : %s from manifest. Halting provisioning...\n", section, prefix ? prefix : "");
		return -1;
	}

	srcval = seq_value_uint32_t(srckey);  /*Source location within eMMC*/
	sizeval = seq_value_uint32_t(sizekey);/*Size in bytes*/

	media = seq_value_uint8_t(mediakey);

	if (dstkey) { //Not a failure if this doesn't exist.
		dstval = seq_value_uint32_t(dstkey);  /*Destination within eMMC*/
	}
	if (dstval == 0) {
		dstval = srcval;
	}

	DMSG("   [%s : %s] - 0x%08x -> 0x%08x    0x%08x bytes.\n", section, prefix ? prefix : "", srcval, dstval, sizeval );

#ifdef CONFIG_CORETEE_ENABLE_BLOB
	blobbedkey=seq_find_param(manifest,section,"blobbed");
	reblobkey=seq_find_param(manifest,section,"reblob");
	blobbed = seq_value_uint8_t(blobbedkey);
	reblob = seq_value_uint8_t(reblobkey);

	// read component into BSRC
	res=seq_mmc_read_dev(_prov_dev, srcval, sizeval, P(BSRC));
	printf("  Component loading from: 0x%08x. %s\n",srcval,(res==0) ? "SUCCESS" : "FAILED");

	if (!res && blobbed) {
		printf("   Deblobbing [%d bytes]...\n", sizeval);
		res = deblob_component(P(BSRC), sizeval);
	}
	if (!res && reblob) {
		printf("   Reblobbing [%d bytes]...\n", sizeval);
		res = reblob_component(P(BSRC), sizeval);
	}
	if (!reblob) {
		printf("   Not reblobbing...\n");
		if (blobbed) {
			printf("   Removing blob header.\n");
			memmove(P(BSRC), P(BSRC+sizeof(SeqBlobHeaderType)), sizeval);
		}
	}
	done = !res;
#else //CONFIG_CORETEE_ENABLE_BLOB
	if (srcval != dstval) {
		printf("   Copying value from: 0x%08x to 0x%08x  - 0x%08x bytes...\n", srcval, dstval, sizeval);
		// read component into BSRC
		res=seq_mmc_read_dev(_prov_dev, srcval, sizeval, P(BSRC));
		printf("   Component loading from: 0x%08x. %s\n", srcval, (res==0) ? "SUCCESS" : "FAILED");
		done = !res;
	} else {
		printf("   Source and destination are the same. Nothing to do..\n");
		res = 0;
	}
#endif //CONFIG_CORETEE_ENABLE_BLOB

	if (done) {
		printf("   Saving to NVM...\n");
		save_to_media(media, P(BSRC), dstval, sizeval);
	}
	return res;
}

static uint32_t get_manifest_offset( int index )
{
	uintptr_t address=0;
	if (index == 0) {
		return 0;
	}

	address=seq_get_manifest_address_by_index(index);
	return address - CORETEE_COMPONENT_DATA_OFFSET;
}

static void decrypt_manifest(SeqManifestIndex index,uintptr_t* address)
{
	uintptr_t ddr_dest=0;
	int ret=0;
	uint32_t slip_offset=get_manifest_offset(index)*SEQ_MMC_BLOCK_SIZE;

#ifdef CONFIG_CORETEE_ENABLE_BLOB
	uint8_t* ebuffer=NULL;
#endif

	DMSG("Slip offset for index[%d] is : %d\n", index, slip_offset);

	//Don't touch the SecEdge manifest.
	if (index == SEQ_MANIFEST_SEQ) {
		*address=0;
		return;
	}

#ifdef CONFIG_CORETEE_ENABLE_BLOB
	seq_select_otpmk();
	ddr_dest = CORETEE_TZDRAM_SEQ_MANIFEST_BASE + slip_offset;

	ebuffer=(uint8_t*)malloc_cache_aligned(SEQ_MANIFEST_SIZE);
	if (!ebuffer) {
		return;
	}

	DMSG("Read blob 0x%08lx to 0x%08lx\n", *address, ddr_dest);
	ret=seq_mmc_read_dev(_prov_dev, *address, SEQ_MANIFEST_SIZE, ebuffer);
	if (!ret) {
		SeqBlobHeaderType header;
		memcpy(&header, ebuffer, sizeof(SeqBlobHeaderType));
		DMSG("totalsize: %d   payloadsize: %d\n",header.totalsize, header.payloadsize);
		memmove(ebuffer, ebuffer+sizeof(SeqBlobHeaderType), header.totalsize-sizeof(SeqBlobHeaderType));
		ret=blob_decap((u8*)_keymod, (u8*)ebuffer, (u8*)ddr_dest, header.payloadsize, 0);

		if (ret) {
			printf("FAILED to decrypt blob for index[%d] : %d\n",index,ret);
			*address=0;
			return;
		}
	} else {
		printf("FAILED to read blob header for index[%d] : %d\n",index,ret);
		*address=0;
		return;
	}

	free(ebuffer);
#else //CONFIG_CORETEE_ENABLE_BLOB
	//SLI - no decrypting, just copy.
	ddr_dest = CORETEE_TZDRAM_SEQ_MANIFEST_BASE + slip_offset;

	/*
	  Copy the entire SLIP
	 */
	printf("Copying SLIP from [%ld]-0x%08lx to 0x%08lx\n", *address, *address, ddr_dest);
	ret = seq_mmc_read_dev(_prov_dev, *address, SEQ_MANIFEST_SIZE, (void*)ddr_dest);
	if (ret) {
		printf("FAILED to load component information for index[%d] from MMC\n", index);
		printf("Error: 0x%08x\n", ret);
		*address = 0;
		return;
	}
#endif //CONFIG_CORETEE_ENABLE_BLOB

	*address = ddr_dest;

	printf("Loaded slip %s...\n", seq_get_manifest_name(index));
}

static void cleanup( void )
{
	memset(P(CORETEE_TZDRAM_SEQ_MANIFEST_BASE), 0, CORETEE_TZDRAM_SEQ_MANIFEST_SIZE);
}

static uint8_t* get_manifest_aes_key(int index,size_t* keysize)
{
	uint8_t* key=0;
	char keyname[32];
	memset(keyname, 0, 32);

	switch (index)
	{
	case SEQ_MANIFEST_CERTS:
		strcpy(keyname, SEQ_MANIFEST_KEY_CRYPT_CERTS);
		break;
	case SEQ_MANIFEST_EMPOWER:
		strcpy(keyname, SEQ_MANIFEST_KEY_CRYPT_EMPOWER);
		break;
#if IS_ENABLED(CONFIG_CORETEE_USE_KEYRING)
	case SEQ_MANIFEST_KEYRING:
		strcpy(keyname, SEQ_MANIFEST_KEY_CRYPT_KEYRING);
		break;
#endif //CONFIG_CORETEE_USE_KEYRING
	}

	if (keyname[0] != '\0') {
		SeqManifest *seqslip=seq_get_manifest(SEQ_MANIFEST_OEM);
		if (seqslip) {
			SeqParamKey* param=seq_find_param(seqslip, SEQ_MANIFEST_SECTION_CRYPT, keyname);
			if (param) {
				key=(uint8_t*)malloc_cache_aligned(param->size);
				if (key) {
					memcpy(key,param->value,param->size);
					*keysize=param->size;
				}
			}
		}
	}

	return key;
}


static void aes_encrypt_slip(int index)
{
	SeqManifest *slip = seq_get_manifest(index);
	uint32_t slipaddr=(uint32_t)seq_get_manifest_address_by_index(index);
	if (slipaddr) {
		size_t keysize=0;
		uint8_t* key=get_manifest_aes_key(index,&keysize);
		if (key) {
			int aesres=0;
			int slipbuffersize=0;
			size_t encryptedsize=0;
			size_t plainsize=0;
			uint8_t *plainbuffer=NULL;
			uint8_t* encryptedbuffer=NULL;
			uint8_t *slipbuffer=seq_get_binary_manifest(slip, &slipbuffersize);
			if (!slipbuffer) {
				free(key);
				return;
			}

			plainsize = slipbuffersize;

			if (slipbuffersize%16) {
				slipbuffersize += (16-(slipbuffersize%16));
			}

			plainbuffer=(uint8_t*)malloc_cache_aligned(slipbuffersize);
			if (!plainbuffer) {
				free(key);
				free(slipbuffer);
				return;
			}

			printf("AES Encrypting Slip %s\n", seq_get_manifest_name(index));
			memcpy(plainbuffer, slipbuffer, slipbuffersize);

			encryptedsize=slipbuffersize+sizeof(SeqCryptSlip_t);
			encryptedbuffer=(uint8_t*)malloc_cache_aligned(encryptedsize);

			if (!encryptedbuffer) {
				free(plainbuffer);
				free(slipbuffer);
				free(key);
				return;
			}

			memset(encryptedbuffer, 0, encryptedsize);

			aesres=seq_enc_aes_ctr(key, keysize, plainbuffer, encryptedbuffer, slipbuffersize, NULL);

			DMSG("%s (%d)\n",((!aesres) ? "SUCCESS" : "FAILED"),aesres);

			if (!aesres) {
				uint8_t* aesbufferstart=encryptedbuffer+sizeof(SeqCryptSlip_t);
				SeqCryptSlip_t *aesheader=(SeqCryptSlip_t*)encryptedbuffer;
				memmove(aesbufferstart,encryptedbuffer,slipbuffersize);
				memcpy(aesheader->magic,SEQ_AES_MAGIC,sizeof(SEQ_AES_MAGIC));
				aesheader->cryptsize=slipbuffersize;
				aesheader->plainsize=plainsize;

				//printf("Writing AES slip to 0x%08x (%lu bytes)\n",slipaddr,encryptedsize);
				seq_mmc_write_dev(_prov_dev, slipaddr,encryptedsize,(void*)encryptedbuffer);
				printf("Encrypted slip was saved to NVM\n");
			} else {
				printf("Could not encrypt slip [%d]\n", index);
			}

			free(key);
			free(slipbuffer);
			free(plainbuffer);
			free(encryptedbuffer);
		} else {
			printf("No key specified\n");
		}
	} else {
		printf("Could not retrieve slip address\n");
	}
}

static void generate_aes_key( SeqManifest *slip, const char* keyname )
{
	SeqParamKey *certkey = NULL;
	uint8_t *key=NULL;

	/*
	 * Generate new random AES key
	 */
	key=malloc(32);
	if (!key) {
		return;
	}

	memset(key,0,32);
	seq_random(key,32);

	seq_delete_param_by_name(slip, SEQ_MANIFEST_SECTION_CRYPT, keyname);
	certkey=seq_new_param(SEQ_MANIFEST_SECTION_CRYPT,keyname,SEQ_TYPE_BINARY);
	if (!certkey) {
		free(key);
		return;
	}

	certkey->size=32;
	certkey->value=key;

	//Pass memory handling to manifest
	seq_add_param(slip, certkey);
}

static void encrypt_slips( void )
{
	//Get the certs and device key from the existing manifests.
	SeqManifest* slip = seq_get_manifest(SEQ_MANIFEST_OEM);

	//Sanity check
	if (!slip) {
		printf("Failed to load SEQ manifest\n");
		return;
	}

	generate_aes_key( slip, SEQ_MANIFEST_KEY_CRYPT_CERTS );
	generate_aes_key( slip, SEQ_MANIFEST_KEY_CRYPT_EMPOWER );

#if IS_ENABLED(CONFIG_CORETEE_USE_KEYRING)
	generate_aes_key( slip, SEQ_MANIFEST_KEY_CRYPT_KEYRING );
#endif

	printf("\nDiversifying Slips...\n");
	aes_encrypt_slip(SEQ_MANIFEST_CERTS);
	aes_encrypt_slip(SEQ_MANIFEST_EMPOWER);
#if IS_ENABLED(CONFIG_CORETEE_USE_KEYRING)
	aes_encrypt_slip(SEQ_MANIFEST_KEYRING);
#endif

	//reblob_slip seq with AES keys added.
	reblob_manifest(slip);
}

int finish_provisioning(SeqManifest* manifest)
{
	printf("\nRunning finishing steps...\n");
	if (seq_init_manifests(CORETEE_COMPONENT_DATA_OFFSET, decrypt_manifest)) {
		printf("Failed to initialize the component information.\n");
		return -1;
	}


	/*This will save the device keys and certs to the cert slip.*/
	/*In addition it will remove the OEM private key from the cert slip*/
	printf("\nBuild OEM Device certificate...\n");
	seq_create_device_key_and_cert(0, seq_random);

	/*This will create and save the empower device keys and certs to the cert slip.*/
	/*In addition it will remove the empower private key from the cert slip*/
	printf("\nBuild EmPower Device Certificate...\n");
	seq_create_device_key_and_cert(1, seq_random);

	//Encrypt AES slips and save modified slips to NVM
	encrypt_slips();

	//Clear DDR
	cleanup();
	return 0;
}

//SEQ_BLC = Boot Loop Counter
#if IS_ENABLED(CONFIG_CORETEE_USE_NVM_FOR_BLC)
static uint32_t get_lpgpr( void )
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

static void set_lpgpr_blc( uint8_t blc )
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
		free(buffer);
	}
}

#else //USE_NVM_FOR_BLC

static uint32_t get_lpgpr( void )
{
	return in_le32(SNVS_BASE_ADDR + SNVS_LPGPR);
}

static void set_lpgpr_blc( uint8_t blc )
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

#endif //USE_MMC_FOR_BLC

#if IS_ENABLED(CONFIG_SPL_CORETEE_SET_FUSES)

//#define SEQ_LOCKDOWN_BOARD
#define LOCK_SRK_FUSE_VAL (1<<9)
#define CLOSE_HAB_FUSE_VAL (1<<25)
#define TZASC_EN_FUSE_VAL (1<<11)
static void set_fuses( void )
{
	int ret=0;
	uint32_t val=0;
	uint8_t fuseset=0;

	printf("---------------------------------------------------\n");
	printf("PROGRAMMING FUSES!\n");
	printf("---------------------------------------------------\n");

	ret = fuse_sense(6, 0, &val);
	DMSG("RET: %d\nBank 6, word 0: Value: 0x%08x\n", ret, val);
	if (!ret && val == 0) {
		//Values loaded from seq_prov_fuse_values.h. This file is copied from the 'build/cst' directory.
		DMSG("Setting SRK fuses...\n");
		fuse_prog(6, 0, SEQ_FUSE_SRKH_6_0);
		fuse_prog(6, 1, SEQ_FUSE_SRKH_6_1);
		fuse_prog(6, 2, SEQ_FUSE_SRKH_6_2);
		fuse_prog(6, 3, SEQ_FUSE_SRKH_6_3);
		fuse_prog(7, 0, SEQ_FUSE_SRKH_7_0);
		fuse_prog(7, 1, SEQ_FUSE_SRKH_7_1);
		fuse_prog(7, 2, SEQ_FUSE_SRKH_7_2);
		fuse_prog(7, 3, SEQ_FUSE_SRKH_7_3);

		fuseset=1;
	}

#ifdef CONFIG_SPL_CORETEE_SET_LOCK_FUSES
	ret = fuse_sense(0, 0, &val);
	if (!ret && ((val&LOCK_SRK_FUSE_VAL)!=LOCK_SRK_FUSE_VAL)) {
		DMSG("Setting Lock Fuses...\n");
		//Lock the SRKH fuses
		DMSG("Sensed: 0x%08x\n", val);
		val |= LOCK_SRK_FUSE_VAL;
		DMSG("Setting: 0x%08x\n", val);
		fuse_prog(0, 0, val);

		fuseset=1;
	}

	ret = fuse_sense(1,3,&val);
	if (!ret && ((val&CLOSE_HAB_FUSE_VAL)!=CLOSE_HAB_FUSE_VAL)) {
		//Boot configuration values.
		//Set addr 0x470, bits 21,22,23,25,26
		DMSG("Sensed[1,3]: 0x%08x\n", val);
		val |= CLOSE_HAB_FUSE_VAL;

		DMSG("Setting[1,3]: 0x%08x\n", val);
		fuse_prog(1,3,val);

		fuseset=1;
	}

	ret = fuse_sense(2, 0, &val);
	if (!ret && ((val&TZASC_EN_FUSE_VAL)!=TZASC_EN_FUSE_VAL)) {
		//Set addr 0x480, bits 11 and 21
		//Enable trustzone
		//Disable Serial Download
		DMSG("Sensed[2,0]: 0x%08x\n", val);
		val |= TZASC_EN_FUSE_VAL;

		DMSG("Setting[2,0]: 0x%08x\n", val);
		fuse_prog(2,0,val);

		fuseset=1;
	}

#ifdef SEQ_LOCKDOWN_BOARD
	ret = fuse_sense(1,3,&val);
	val |= 1<<21; //Disable secure JTAG
	val |= 1<<22; //22,23 Disable all DEBUG modes
	val |= 1<<23;
	val |= 1<<26; //Hab may not override JTAG.
	fuse_prog(1,3,val);

	ret = fuse_sense(2, 0, &val);
	val |= 1<<21; //Disable serial download
	fuse_prog(2,0,val);
	fuseset=1;
#else
	printf("BOARD IS ___NOT___ FULLY SECURE!\nNot suitable for production!!!\n");
#endif //SEQ_LOCKDOWN_BOARD

	if (fuseset) {
		printf("SECURITY FUSES HAVE BEEN SET.\nPlease reset the board...\n");
		while(1) {}
	}
#else
		printf("SET_LOCK_FUSES not SET.\n");
#endif //CONFIG_SPL_CORETEE_SET_LOCK_FUSES
}
#else
static void set_fuses( void ) {
	printf("CoreTEE Security Fuses are NOT being set.\n");
}
#endif /*CONFIG_SPL_CORETEE_SET_FUSES*/


#ifdef CHECK_CPU_REV
//Code taken from arch/arm/mach-imx/cpu.c, rather than enabling it to be built with SPL.
const char *get_imx_type(u32 imxtype)
{
	switch (imxtype) {
	case MXC_CPU_IMX8MP:
		return "8MP[8]";	/* Quad-core version of the imx8mp */
	case MXC_CPU_IMX8MPD:
		return "8MP Dual[3]";	/* Dual-core version of the imx8mp */
	case MXC_CPU_IMX8MPL:
		return "8MP Lite[4]";	/* Quad-core Lite version of the imx8mp */
	case MXC_CPU_IMX8MP6:
		return "8MP[6]";	/* Quad-core version of the imx8mp, NPU fused */
	case MXC_CPU_IMX8MN:
		return "8MNano Quad";/* Quad-core version of the imx8mn */
	case MXC_CPU_IMX8MND:
		return "8MNano Dual";/* Dual-core version of the imx8mn */
	case MXC_CPU_IMX8MNS:
		return "8MNano Solo";/* Single-core version of the imx8mn */
	case MXC_CPU_IMX8MNL:
		return "8MNano QuadLite";/* Quad-core Lite version of the imx8mn */
	case MXC_CPU_IMX8MNDL:
		return "8MNano DualLite";/* Dual-core Lite version of the imx8mn */
	case MXC_CPU_IMX8MNSL:
		return "8MNano SoloLite";/* Single-core Lite version of the imx8mn */
	case MXC_CPU_IMX8MM:
		return "8MMQ";	/* Quad-core version of the imx8mm */
	case MXC_CPU_IMX8MML:
		return "8MMQL";	/* Quad-core Lite version of the imx8mm */
	case MXC_CPU_IMX8MMD:
		return "8MMD";	/* Dual-core version of the imx8mm */
	case MXC_CPU_IMX8MMDL:
		return "8MMDL";	/* Dual-core Lite version of the imx8mm */
	case MXC_CPU_IMX8MMS:
		return "8MMS";	/* Single-core version of the imx8mm */
	case MXC_CPU_IMX8MMSL:
		return "8MMSL";	/* Single-core Lite version of the imx8mm */
	case MXC_CPU_IMX8MQ:
		return "8MQ";	/* Quad-core version of the imx8mq */
	case MXC_CPU_IMX8MQL:
		return "8MQLite";	/* Quad-core Lite version of the imx8mq */
	case MXC_CPU_IMX8MD:
		return "8MD";	/* Dual-core version of the imx8mq */
	case MXC_CPU_MX7S:
		return "7S";	/* Single-core version of the mx7 */
	case MXC_CPU_MX7D:
		return "7D";	/* Dual-core version of the mx7 */
	case MXC_CPU_MX6QP:
		return "6QP";	/* Quad-Plus version of the mx6 */
	case MXC_CPU_MX6DP:
		return "6DP";	/* Dual-Plus version of the mx6 */
	case MXC_CPU_MX6Q:
		return "6Q";	/* Quad-core version of the mx6 */
	case MXC_CPU_MX6D:
		return "6D";	/* Dual-core version of the mx6 */
	case MXC_CPU_MX6DL:
		return "6DL";	/* Dual Lite version of the mx6 */
	case MXC_CPU_MX6SOLO:
		return "6SOLO";	/* Solo version of the mx6 */
	case MXC_CPU_MX6SL:
		return "6SL";	/* Solo-Lite version of the mx6 */
	case MXC_CPU_MX6SLL:
		return "6SLL";	/* SLL version of the mx6 */
	case MXC_CPU_MX6SX:
		return "6SX";   /* SoloX version of the mx6 */
	case MXC_CPU_MX6UL:
		return "6UL";   /* Ultra-Lite version of the mx6 */
	case MXC_CPU_MX6ULL:
		return "6ULL";	/* ULL version of the mx6 */
	case MXC_CPU_MX6ULZ:
		return "6ULZ";	/* ULZ version of the mx6 */
	case MXC_CPU_MX51:
		return "51";
	case MXC_CPU_MX53:
		return "53";
	default:
		return "??";
	}
}

static void check_cpu_rev( void ) {
	DMSG("Checking CPU Revision...\n");
	u32 cpurev = get_cpu_rev();
	
	if (cpurev != EXPECTED_CPU_REV) {
		printf("Current CPU Revision does not match expected Revision.\n");

		printf("\tExpected (0x%08x  --  Type i.MX%s)\n", EXPECTED_CPU_REV, get_imx_type((EXPECTED_CPU_REV & 0x1FF000) >> 12));
		printf("\tCurrent (0x%08x -- Type i.MX%s)\n", cpurev, get_imx_type((cpurev & 0x1FF000) >> 12));

		printf("\tExpected Chip Revision: 0x%02x\n", EXPECTED_CPU_REV & 0xFF);
		printf("\tCurrent Chip Revision: 0x%02x\n", cpurev & 0xFF);


#if defined(CONFIG_CORETEE_ENABLE_BLOB)
		printf("\nBLOBS CANNOT BE DECAPSULATED! HALTING!!!!\n");
		for (;;) {}
#endif //CONFIG_CORETEE_ENABLE_BLOB
	} else {
		DMSG("Found CPU Rev: iMX.%s. Continuing...\n", get_imx_type((cpurev & 0x1FF000) >> 12));
	}
}
#endif


/*Watchdog Section*/
# define SNVS_BASE 0x30370000
# define _HPCOMR     0x04
# define _HPSVSR     0x018
# define _LPSVCR     0x040
# define _HPSVCR     0x010
# define _LPSR       0x04c
# define _LPPGDR     0x064
# define GLITCH_VAL  0x41736166
# define _LPGPR0     0x090

#define WDT_WCR 0
#define WDT_WSR 2
#define WDT_WRSR 4
#define WDT_WICR 6
#define WDT_WMCR 8

static void secure_wdog_setup(u32 tmo_ms, u32 pre_interrupt_ms)
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

	snvs_hpcomr = SNVS_BASE + _HPCOMR;
	snvs_hpsvcr = SNVS_BASE + 0x10;
	snvs_hphacivr = SNVS_BASE + 0x1c;
	snvs_lpsvcr = SNVS_BASE + 0x40;

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

static void lp_deglitch( uint8_t force )
{
	uint32_t lpsr;
	uint32_t hpsvsr;
	uint32_t reg;

	lpsr = __raw_readl((void *)(SNVS_BASE + _LPSR));
	hpsvsr = __raw_readl((void *)(SNVS_BASE + _HPSVSR));

	/* clear errors */
	if (force || (hpsvsr & 0x3f) || (lpsr & 0x01707ff)) {
		uint32_t rst = __raw_readl((void *)(SNVS_BASE + _HPCOMR)); /* HPCOMR */

		__raw_writel(rst | 0x10, (void *)(SNVS_BASE + _HPCOMR)); /* low power reset */
		__raw_writel(0x03f, (void *)(SNVS_BASE + _HPSVSR)); /* clear hp errors */
		__raw_writel(GLITCH_VAL, (void *)(SNVS_BASE + _LPPGDR)); /* write deglitch */
		__raw_writel(0x01707ff, (void *)(SNVS_BASE + _LPSR)); /* clear lp errors */
	}
	else {
		printf("%s(%d): NOPOR: LPGPR0: 0x%08x\n", __func__, __LINE__, __raw_readl((void *)(SNVS_BASE + _LPGPR0)));
	}

	//Setting NS Access to registers
	reg = __raw_readl((void*)(SNVS_BASE + _HPCOMR)); // read HPcomr
	reg |= 0x80000000; // enable NS access to SNVS registers (for linux)
	__raw_writel(reg, (void*)(SNVS_BASE + _HPCOMR)); // enable NS access to SNVS
}

//===============================================
void __noreturn seq_run_provisioning(void)
{
	int res=0;
	int i=0;
	int j=0;

	lp_deglitch(1);
	secure_wdog_setup(120000, 2000);

	set_fuses();

	printf("---------------------------------------------------\n");
	printf("Starting PROVISIONING\n");
	printf("---------------------------------------------------\n");

#ifdef CHECK_CPU_REV
	check_cpu_rev();
#endif //CHECK_CPU_REV

	printf("Initializing NVM device drivers...\n");
	_emmc_dev = seq_get_mmc( CORETEE_MMC_DEV, 0, 0, 0);
	_sd_dev = seq_get_mmc( CORETEE_SD_DEV, 0, 0, 0);

	DMSG("EMMC DEV(%d): %p\nSD DEV(%d):  %p\n", CORETEE_MMC_DEV, _emmc_dev, CORETEE_SD_DEV, _sd_dev);

	/*This needs to be modified to where the gold blobs are initially stored*/
	if (CORETEE_NVM_DEV == CORETEE_SD_DEV) {
		printf("Loading components from SD Card\n");
		_prov_dev = _sd_dev;
	} else {
		printf("Loading components from eMMC\n");
		_prov_dev = _emmc_dev;
	}

	_keymod=malloc_cache_aligned(32);
	if (!_keymod) {
		printf("Failed to allocate memory for key modifier!\nHalting!!!\n");
		for (;;) {}
	}
	memset(_keymod,0,32);

	/*Only test for required driver here*/
	if (!_prov_dev) {
		printf("The required driver for provisioning is not found!\nHalting!!!\n");
		for (;;) {}
	}

	// load the component layout manifest
	SeqManifest* manifest=load_manifest();
	if (!manifest) {
		printf("Failed to load provisioning manifest. Halting!\n");
		for (;;) {}
	}

	printf("Loaded provisioning manifest...\n");


	// load brn
#ifdef CONFIG_CORETEE_ENABLE_BLOB
	load_brn(manifest);
	res=seq_set_zmk(P(BRND),32);
#endif

	if (res) {
		printf("Could not set ZMK: %d\n",res);
		printf("Provisioning Failed!!!Halting...\n");
		for (;;) {}
	}

	//Diversify (deblob/reblob if necessary) the individual components.
	for(i=0; i<NUM_SINGLE_COMPONENTS && res==0; i++) {
		res = diversify_component(manifest, single_component_names[i], NULL);
		printf("\n");
	}

	//Check 'res' before continuing. Don't lose errors.
	if (res) {
		printf("Failed to diversify: %s\n", single_component_names[i-1]);
		printf("Provisioning Failed!!!Halting...\n");
		for (;;) {}
	}

	printf("-------------------------------------------------------\n");
	printf("Setting up components[%d] for two boot stacks: plex_a and plex_b\n", NUM_COMPONENTS);
	printf("-------------------------------------------------------\n");

	for(i=0; i<NUM_PLEXES && res==0; i++) {
		for(j=0; j<NUM_COMPONENTS && !res; j++) {
			res = diversify_component(manifest, plex_names[i], plex_component_names[j]);
		}
	}

	//Check 'res' before continuing. Don't lose errors.
	if (res) {
		printf("Failed to diversify: %s - %s\n", plex_names[i-1], plex_component_names[j-1]);
		printf("Provisioning Failed!!!Halting...\n");
		for (;;) {}
	}

	printf("----------------------------------------------------------------\n");
	printf("Installing personalization data manifests and\n\tunique device identification generation\n");
	printf("----------------------------------------------------------------\n");

	printf("Finishing...\n");
	res = finish_provisioning(manifest);
	if (res) {
		printf("/***********\nProvisioning Failed\n***********\\\n");
	}

#if IS_ENABLED(CONFIG_CORETEE_PROV_TESTS)
#if IS_ENABLED(CONFIG_CORETEE_CERT_TEST)

	res = seq_verify_device_cert(SEQ_CERT_TYPE_EMPOWER);
	printf("[%s] RESULT: %s\n", __func__, res==SEQ_SUCCESS ? "SUCCESS" : "FAILED");

	seq_execute_cert_test(seq_random);
#endif
#if IS_ENABLED(CONFIG_CORETEE_KEY_TEST)
	seq_execute_key_test(seq_random);
#endif

	printf("\n----------------------------------------------------------------\n");
	printf("Done testing... Halting.\n");
	while(1) {
		udelay(1000);
	}
#endif //CONFIG_CORETEE_PROV_TESTS


#ifndef CONFIG_SPL_CORETEE_SET_FUSES
	printf("NOTE!! FUSES WERE NOT SET!\n");
	udelay(10);
#elif !defined(SEQ_LOCKDOWN_BOARD)
	printf("BOARD IS ___NOT___ FULLY SECURE!\n");
	printf("Not suitable for production!!!\n");
	printf("Modify code to set SEQ_LOCKDOWN_BOARD!\n");
	udelay(10);
#endif

	set_lpgpr_blc(5); //Reset BLC value after deglitch

	printf("\n----------------------------------------------------------------\n");
	printf("PROVISIONING -- DONE\n");
	printf("The board will now reboot in SECURE BOOT mode.\n");
	printf("----------------------------------------------------------------\n");
	udelay(1);

	seq_reset_with_watchdog();
	for (;;) {}
};









