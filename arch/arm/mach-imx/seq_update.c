/*================================================
Copyright © 2016-2019 Sequitur Labs Inc. All rights reserved.

The information and software contained in this package is proprietary property of
Sequitur Labs Incorporated. Any reproduction, use or disclosure, in whole
or in part, of this software, including any attempt to obtain a
human-readable version of this software, without the express, prior
written consent of Sequitur Labs Inc. is forbidden.
================================================*/

#include <common.h>
#include <command.h>
#include <memalign.h>
#include <linux/delay.h>

#include <fsl_sec.h>

#include <seq_keys.h>
#include <seq_error.h>
#include <seq_manifest.h>
#include <seq_boot_manifests.h>
#include <seq_ecc_utils.h>
#include <seq_ecc_certificate.h>
#include <uECC.h>
#include <seq_asn1.h>

#include <seq_memio.h>
#include <seq_bootstates.h>
#include <seq_boot.h>

#define SEQ_RUN_UPDATE
#ifdef SEQ_RUN_UPDATE
#include <seq_update.h>

#if defined(CONFIG_IMX8MP)
#define SEQ_SPL_UPDATE_ADDR 64 /*Address in MMC*/
#elif defined(CONFIG_IMX8MM)
#define SEQ_SPL_UPDATE_ADDR 66
#endif

#define DDR_UPDATE_PAYLOAD_ADDR 0x60000000
#define DDR_UPDATE_CONTENT_ADDR 0x68000000
#define DDR_UPDATE_COMPONENT_ADDR 0x70000000
#define P(val) (void*)(val)

#if IS_ENABLED(CONFIG_CORETEE_ENABLE_BLOB)
extern int blob_decap(u8*,u8*,u8*,u32,u8);
extern int blob_encap(u8*,u8*,u8*,u32,u8);
extern void caam_jr_strstatus(u32 status);
#endif

extern void seq_print_bytes( uint8_t *data, uint32_t len);

//#define USE_UPDATE_MMC
#ifdef USE_UPDATE_MMC
static struct mmc * update_mmc=NULL;
#endif

#define NUM_COMPONENT_NAMES 4
static char* component_names[NUM_COMPONENT_NAMES]={
		"coretee",
		"uboot",
		"kernel",
		"atf"
};

#define NUM_KEY_NAMES 3
static char *key_names[NUM_KEY_NAMES]={
		"dest",
		"jump",
		"version"
};

static int verify_update(SeqDerNode *signode, SeqDerNode *plnode)
{
	int res=0;
	uint8_t *oempk=NULL, *plhash=NULL, *sigbuff=NULL;
	size_t siglength;
	size_t pksize = uECC_curve_public_key_size(uECC_secp256r1());

	oempk = malloc(pksize);
	plhash = malloc_cache_aligned(SEQ_SHA256LEN_BYTES);
	if(!oempk || !plhash){
		printf("Failed to allocate memory!\n");
		return -1;
	}

	if((res = seq_get_ecc_public_key(oempk, pksize, SEQ_MANIFEST_CERT_OEM_PAYLOAD)) != SEQ_SUCCESS){
		printf("Failed to load OEM Payload key. Unable to verify update package.\n");
		goto done;
	}

	//Need to hash the payload.
	//Check alignment because we don't have a lot of 'malloc' space to use.
	memcpy((void*)DDR_UPDATE_CONTENT_ADDR, plnode->content, plnode->length);
	seq_run_sha(plhash, SEQ_SHA256LEN_BYTES, (void*)DDR_UPDATE_CONTENT_ADDR, plnode->length, SEQ_SHA_256);

	if((res = seq_extract_ec_signature(&sigbuff, &siglength, signode)) != SEQ_SUCCESS) {
		printf("Failed to extract EC signature from node\n");
		goto done;
	}

	printf("Update package signature for debugging!!!!\n");
	seq_print_bytes(sigbuff, siglength);

	if((res = uECC_verify(oempk, plhash, SEQ_SHA256LEN_BYTES, sigbuff, uECC_secp256r1())) == 0){
		printf("Failed to verify update package signature\n");
		res=-1;
		goto done;
	}

	res = 0; /*Success*/
done:
	if(oempk) {
		free(oempk);
	}
	if(plhash) {
		free(plhash);
	}
	return res;
}

/*After provisioning this header sits in front of the blobs*/
typedef struct blobheader
{
	uint32_t totalsize;
	uint32_t payloadsize;
} SeqBlobHeaderType;

#define USE_BOOTSTATE_FOR_SPL
static int get_updated_spl( void ){
#ifdef USE_BOOTSTATE_FOR_SPL
	uint32_t state = seq_read_boot_state_values();
	return SEQ_CHECK_STATE(state, SEQ_BS_SPL_UPDATING);
#else
	uint32_t regval = in_le32(SNVS_BASE_ADDR + SNVS_LPGPR);
	return (regval & SEQ_SPL_UPDT_MASK) == SEQ_SPL_UPDT_MASK;
#endif
}

static void set_updated_spl( void )
{
#ifdef USE_BOOTSTATE_FOR_SPL
	uint32_t state = seq_read_boot_state_values();
	SEQ_SET_STATE(state, SEQ_BS_SPL_UPDATING);
	seq_update_boot_state(state);
#else
	uint32_t regval = in_le32(SNVS_BASE_ADDR + SNVS_LPGPR);

	//Set SPL Update MASK
	regval |= (SEQ_SPL_UPDT_MASK);
	out_le32(SNVS_BASE_ADDR + SNVS_LPGPR, regval);
#endif
}

#if IS_ENABLED(CONFIG_CORETEE_ENABLE_BLOB)
#define BRN_SIZE 32
static int set_update_zmk( void )
{
	int res=0;
	uint32_t brnaddr=0;
	uint8_t *brnblob = malloc_cache_aligned(SEQ_MMC_BLOCK_SIZE);
	uint8_t *brn = malloc_cache_aligned(BRN_SIZE);
	SeqManifest *component=NULL;

	printf("Setting the ZMK for update!\n");

	if(!brnblob || !brn){
		printf("Failed to allocate buffers for BRN\n");
		return -1;
	}

	printf("getting component\n");

	//Get the BRN from the component manifest
	component = seq_get_manifest(SEQ_MANIFEST_COMPONENT);
	if(!component) {
		printf("No component manifest found during update\n");
		res = -1;
	}

	if(!res) {
		brnaddr = seq_get_keyval_uint32(component, "brn", "source");
		if(!brnaddr){
			res = -1;
		}
	}

	if(!res) {
		SeqBlobHeaderType* header=NULL;
		uint8_t *keymod=malloc_cache_aligned(32);
		uintptr_t dataaddr = DDR_UPDATE_COMPONENT_ADDR; /*Known aligned address*/

		if(keymod) {
			printf("Setting keymod\n");
			memset(keymod,0,32);

			printf("getting brn\n");
			seq_mmc_read(brnaddr, SEQ_MMC_BLOCK_SIZE, brnblob);

			printf("Selecting otpmk\n");
			seq_select_otpmk();

			header = (SeqBlobHeaderType*)brnblob;

			printf("Copying: from %p to %p   -   %d bytes", (void*)dataaddr, (void*)(brnblob+sizeof(SeqBlobHeaderType)), header->totalsize);
			memcpy((void*)dataaddr, (void*)(brnblob+sizeof(SeqBlobHeaderType)), header->totalsize);

			if(header->payloadsize != BRN_SIZE){
				printf("Sizes are wrong. Payload: %d   BRN: %d\n", header->payloadsize, BRN_SIZE);
				res=-1;
			} else {
				printf("decap header\n");
				res = blob_decap((u8*)keymod,(u8*)dataaddr, (u8*)brn, header->payloadsize,0);
			}

			free(keymod);
			keymod=NULL;
		} else {
			res = -1;
		}
	}

	if(!res){
		printf("Resetting zmk\n");
		res=seq_set_zmk(brn, BRN_SIZE);
	} else {
		printf("BRN decapsulation failed\n");
	}

	if(brn)	{
		free(brn);
	}
	if(brnblob) {
		free(brnblob);
	}

	return res;
}

static void clear_update_zmk( void )
{
	memset((void*)DDR_UPDATE_COMPONENT_ADDR, 0, 32);
	seq_set_zmk((uint8_t*)DDR_UPDATE_COMPONENT_ADDR, 32);
}

#endif


static uintptr_t handle_update_blob(uintptr_t updateoffset, uint32_t size, int reblob)
{
	uintptr_t componentaddr = DDR_UPDATE_COMPONENT_ADDR;

#if IS_ENABLED(CONFIG_CORETEE_ENABLE_BLOB)
	
	//Move it well past the component, aligned on SEQ_MMC_BLOCK_SIZE
	uintptr_t deblobaddr = componentaddr+((size/SEQ_MMC_BLOCK_SIZE + 10)*SEQ_MMC_BLOCK_SIZE);
	int bres;
	SeqBlobHeaderType* header=NULL;
	uint8_t *rnd=NULL;

	//Check size alignment for blob decapsulation
	if(size % SEQ_MMC_BLOCK_SIZE != 0) {
		//Invalid blob based on how we create them.
		printf("Invalid blob size. Unable to deblob.\n");
		return (uintptr_t)0;
	}


	rnd = malloc_cache_aligned(32);
	if (!rnd) {
		return (uintptr_t)0;
	}

	memset(rnd,0,32);

	//Reset alignment. Alignment within the update blob is not guaranteed.
	printf("Copying: 0x%08lx to 0x%08lx   size: %x\n", updateoffset, componentaddr, size);

	memset((void*)componentaddr, 0, size);
	memset((void*)deblobaddr, 0, size);
	memcpy((void*)componentaddr, (void*)updateoffset, size);

	printf("Decapsulate Gold Update Blob\n");
	seq_select_zmk();
	bres=blob_decap((u8*)rnd,(u8*)componentaddr,(u8*)deblobaddr,(size-SEQ_MMC_BLOCK_SIZE),0);

	//printf("blob decap res: %d\n", bres);
	if (bres!=0) {
		caam_jr_strstatus(bres);
		free(rnd);
		printf("Failed to decapsulate component\n");
		return (uintptr_t)0;
	}

	//Now reblob
	if (reblob) {
		printf("Encrypting component: ");
		seq_select_otpmk();

		header = (SeqBlobHeaderType*)componentaddr;
		header->totalsize=size;
		header->payloadsize=header->totalsize-SEQ_MMC_BLOCK_SIZE;
		uint8_t* actualdest=(uint8_t*)(componentaddr+sizeof(SeqBlobHeaderType));
		uint8_t* aligned=(uint8_t*)malloc_cache_aligned(header->totalsize);
		if(aligned) {
			memset(aligned,0,header->totalsize);

			bres=blob_encap((u8*)rnd,(u8*)deblobaddr,(u8*)aligned, header->payloadsize, 0);
			printf("%s (%d)\n",(bres==0) ? "SUCCESS" : "FAILED",bres);

			memcpy(actualdest,aligned,header->totalsize);
			memset((void*)deblobaddr, 0, size);
			free(aligned);
		} else {
			printf("Failed to allocate aligned memory for reblobbing.\n");
			componentaddr=0;
		}
	} else {
		memcpy((void*)componentaddr, (void*)deblobaddr, (size-SEQ_MMC_BLOCK_SIZE));
	}

	free(rnd);

#else
	// no blobs - just copy updateoffset to componentaddr
	printf("Component is not blobbed. Copying %d bytes from: 0x%08lx   to 0x%08lx\n", size, updateoffset, componentaddr);
	memcpy((void*)componentaddr,(void*)updateoffset, size);
#endif
	
	return componentaddr;
}

int encap_and_and_save_manifest( SeqManifest *slip )
{
	int bres=0;

#ifdef CONFIG_CORETEE_ENABLE_BLOB
	size_t sizeval;
	int slipsize=0;
	SeqBlobHeaderType *header=NULL;
	uint8_t *actualdest=NULL, *aligned=NULL, *parambuffer=NULL;
	uint8_t *rnd=NULL;
	uintptr_t bsrc, bdst;

	if(!slip) {
		return -1;
	}

	rnd = malloc_cache_aligned(32);
	if(!rnd) {
		return -1;
	}

	memset(rnd,0,32);

	//Convert manifest to binary blob
	parambuffer = seq_get_binary_manifest(slip, &slipsize);
	if(!parambuffer) {
		free(rnd);
		return -1;
	}

	//printf("Slip is size: %d\n", slipsize);
	slipsize+=sizeof(SeqBlobHeaderType);

	//Align to MMC block size
	sizeval = ((slipsize/SEQ_MMC_BLOCK_SIZE)+1)*SEQ_MMC_BLOCK_SIZE;
	sizeval += SEQ_MMC_BLOCK_SIZE; //Add padding

	bsrc = DDR_UPDATE_COMPONENT_ADDR;
	bdst = DDR_UPDATE_COMPONENT_ADDR + (sizeval+4096); /*Add padding*/
	memset(P(bsrc), 0, sizeval);
	memset(P(bdst), 0, sizeval);
	header=(SeqBlobHeaderType*)bdst;

	//Make sure to align it, best just copy to known alignment
	memcpy(P(bsrc), parambuffer, slipsize);
	free(parambuffer);

	header->totalsize=sizeval;
	header->payloadsize=sizeval-SEQ_MMC_BLOCK_SIZE;

	actualdest=(uint8_t*)(bdst+sizeof(SeqBlobHeaderType));
	aligned=(uint8_t*)malloc_cache_aligned(sizeval);
	if(!aligned){
		free(rnd);
		return -1;
	}

	memset(aligned,0,sizeval);

	seq_select_otpmk();
	bres=blob_encap((u8*)rnd,(u8*)bsrc,(u8*)aligned,sizeval-SEQ_MMC_BLOCK_SIZE,0);
	printf("%s (%d)\n",(bres==0) ? "SUCCESS" : "FAILED",bres);

	memcpy(actualdest,aligned,sizeval);
	free(aligned);

	//Save back to flash
	printf("Writing to the SF...");
	bres = seq_mmc_write(slip->nvm, sizeval, P(bdst));
	if (!bres)
		printf("%zu bytes written\n",sizeval);
	else
		printf("FAILED\n");

	free(rnd);

#else
	uint8_t* parambuffer;
	// size_t sizeval;
	int slipsize=0;

	if (slip) {
		parambuffer=seq_get_binary_manifest(slip,&slipsize);
		if(!parambuffer){
			printf("Failed to get binary manifest.n");
			return -1;
		}

		bres=seq_mmc_write(slip->nvm,slipsize,parambuffer);
		if (!bres) {
			printf("%d bytes written at %p\n", slipsize, (void*)slip->nvm);
		} else {
			printf("FAILED\n");
		}
	}
	else {
		bres=-1;
	}
#endif // CONFIG_CORETEE_ENABLE_BLOB
	
	return bres;
}

//0 means the same, 1 means different.
static int is_key_different( SeqParamKey *oldkey, SeqParamKey *newkey)
{
	if(!newkey || !oldkey) {
		return 0; //Can't compare, assume the same
	}
	if(newkey->size != oldkey->size){
		return 1;
	}
	if(newkey->type != oldkey->type) {
		return 1;
	}

	if(newkey->type == SEQ_TYPE_STRING) {
		return strncmp(newkey->value, oldkey->value, newkey->size); /*Sizes are the same*/
	} else if( newkey->type == SEQ_TYPE_BINARY ) {
		return 1; //Assume different??
	} else if( newkey->type == SEQ_TYPE_UINT32 ) {
		uint32_t ok, nk;
		memcpy(&ok, oldkey->value, sizeof(uint32_t));
		memcpy(&nk, newkey->value, sizeof(uint32_t));
		return (nk!=ok);
	}

	return 0; /*Made it where we can't compare. Assume the same, skip...*/
}

static void replace_key( SeqParamKey *oldkey, SeqParamKey *newkey, const char* plex_str, const char* keyname, SeqManifest *layout )
{
	if( is_key_different(oldkey, newkey) ){
		//Need to replace key with allocated value or else the key just points to 'raw' in the SLIP
		SeqParamKey *key = seq_new_param(plex_str, keyname, newkey->type);
		key->value = malloc(newkey->size);
		key->size = newkey->size;
		if(key->value) {
			memcpy(key->value, newkey->value, newkey->size);

			//Delete the old key memory and it's place in the SLIP
			seq_delete_param_by_key(layout, oldkey);

			//This will update the value in the SLIP and will be saved back to NVM.
			seq_add_param(layout, key);
		}
	}
}

static void update_keys( SeqManifest *layout, SeqManifest *update, const char* component, const char *plex_str )
{
	int i=0;
	char keyname[32];
	uint32_t size,tsize=0;
	SeqParamKey *oldkey=NULL;
	SeqParamKey *newkey=NULL;

	/*
	 * Update size separately since the update payload specifies bytes
	 * but the component payload specifies blocks.
	 */
	sprintf(keyname, "%s_%s", component, "size");
	oldkey = seq_find_param(layout, plex_str, keyname);
	newkey = seq_find_param(update, component, "size");

	if(!oldkey || !newkey) {
		return;
	}

	memcpy(&size, newkey->value, sizeof(uint32_t));
	tsize=size;
	size = size/SEQ_MMC_BLOCK_SIZE;
	if(tsize%SEQ_MMC_BLOCK_SIZE != 0) {
		size++;
	}

	memcpy(newkey->value, &size, sizeof(uint32_t));
	replace_key(oldkey, newkey, plex_str, keyname, layout);

	for(i=0; i<NUM_KEY_NAMES; i++) {
		sprintf(keyname, "%s_%s", component, key_names[i]);
		oldkey = seq_find_param(layout, plex_str, keyname);
		newkey = seq_find_param(update, component, key_names[i]);
		replace_key(oldkey, newkey, plex_str, keyname, layout);
	}
}

static int update_component( SeqManifest *layout, SeqManifest *update, uint32_t uaddr, const char* component, const char *plex_str )
{
	int res=0, is_spl=0;
	uint32_t offset;
	uint32_t size=0;
	uintptr_t mmcdest=0;
	uintptr_t ddraddr=0;
	uintptr_t compaddr=uaddr;
	char keyname[32];

	is_spl = (strcmp(component, "spl")==0);

	//Size must be number of MMC blocks
	size = seq_get_keyval_uint32(update, component, "size");
	if(size==0) {
		//printf("Unable to find component[%s] in update manifest\n", component);
		return 0; /*No component info found*/
	}

	offset = seq_get_keyval_uint32(update, component, "update_addr");

	/*Address of component within update payload*/
	compaddr += offset;

	printf("New component[%s] at update offset 0x%08x, size: 0x%x bytes.\n", component, offset, size);

	//Verify this is the correct component.
	//Compare against update package input files.
	//outputData((uint8_t*)compaddr, 32);

	seq_service_watchdog();

	//Deblob and reblob the component.
	ddraddr = handle_update_blob(compaddr, size, !is_spl);
	if(ddraddr == 0){
		printf("Failed blob operation in update.");
		return -1;
	}

	if(is_spl) {
		//Just copy to MMC
		printf("Updating SPL - Copying to MMC address: 0x%08x\n", SEQ_SPL_UPDATE_ADDR);
		seq_mmc_write(SEQ_SPL_UPDATE_ADDR, size, (uint8_t*)ddraddr);
		set_updated_spl();
		printf("SPL is updated. Resetting... This may take a few seconds.\n");
		seq_reset_with_watchdog();
		while(1) {
			udelay(1000);
			printf(".");
		}
	} else {
		//Get destination in MMC from plex manifest
		sprintf(keyname, "%s_%s", component, "source");
		mmcdest = seq_get_keyval_uint32(layout, plex_str, keyname);

		//printf("DDR location: 0x%08lx\n", ddraddr);
		//printf("Component \'source\' from plex is: 0x%08lx\n", mmcdest);

		//Copy blob back to MMC.
		printf("Copying component to MMC from: 0x%08lx to 0x%08lx numbytes: %d\n", ddraddr, mmcdest, size);
		res = seq_mmc_write(mmcdest, size, (void*)ddraddr);
		if(res) {
			printf("FAILED TO WRITE TO MMC!!!\n");
		}

		//Update the keys
		update_keys(layout, update, component, plex_str);
	}

	return res;
}

static int update_firmware_version( SeqManifest *update, SeqManifest *layout, const char *plexstr )
{
	const char keystr[]="firmware_ver";

	SeqParamKey *oldkey = seq_find_param(layout, plexstr, keystr);
	SeqParamKey *newkey = seq_find_param(update, "firmware", "version");

	if(oldkey && newkey){
		replace_key(oldkey, newkey, plexstr, keystr, layout);
		return 0;
	}
	return -1;
}

static int update_components( SeqManifest *update, uintptr_t componentaddr, size_t length, SeqManifest *layout, const char * plex_str )
{
	int res=0;
	int i=0;

	i = get_updated_spl();
	printf("Update manifest found. Running update. SPL already: %d.\n", i);

	//First check to see if SPL needs to be updated.
	if( seq_find_param( update, "spl", "size") && !get_updated_spl()) {
		//This should set a 'updating SPL flag' and reset the board....
		update_component(layout, update, componentaddr, "spl", NULL);
	}

	for(i=0; i<NUM_COMPONENT_NAMES && res==0; i++) {
		res = update_component(layout, update, componentaddr, component_names[i], plex_str);
	}

	if(res == 0) {
		res = update_firmware_version( update, layout, plex_str );
	}

	//Save plex manifest back to MMC
	if(!res) {
		printf("Saving manifest back to NVM: 0x%08lx\n", layout->nvm);
		encap_and_and_save_manifest(layout);
	} else {
		printf("Failed to update components. Exiting Update\n");
	}

	return res;
}

static SeqManifest *get_update_manifest( uintptr_t ddr, size_t length )
{
	SeqManifest *slip = NULL;
	slip = seq_load_manifest( ddr );
	return slip;
}

static int verify_and_run_update( uintptr_t ddr_uaddr, size_t length, SeqManifest *layout, const char *plex_str )
{
	int res=0;
	SeqDerNode *parent=NULL;
	SeqDerNode *algnode=NULL, *signode=NULL, *plnode=NULL;
	SeqManifest *updateslip=NULL;

	res = seq_asn1_parse_der(&parent, (uint8_t*)ddr_uaddr, length);
	if(res || !parent) {
		printf("Failed to parse DER update package\n");
		return -1;
	}

	//Update DER consists of
	//parent_node
	//  SHA algorithm node
	//  Signature node
	//	Payload node
	algnode = seq_asn1_get_child(parent, 0);
	signode = seq_asn1_get_child(parent, 1);
	plnode = seq_asn1_get_child(parent, 2);

	if(!algnode || !signode || !plnode ) {
		printf("Failed to get child components of update payload.\n\t[%p] [%p] [%p]\n", algnode, signode, plnode);
		seq_asn1_free_tree(parent, SEQ_AP_FREENODEONLY);
		return -1;
	}

	//Verify against oem public key
	printf("Calling verify...\n");
	res = verify_update(signode, plnode);
	if(res) {
		printf("Verify failed!!!\n");
		return res;
	}

	seq_service_watchdog();

	//Verified so lets look at the update manifest.
	//Payload consists of:
#define UPDATE_MANIFEST_SIZE 4096
	//	Update Manifest - 4096 Bytes
	//	Update Components
	if((updateslip = get_update_manifest((uintptr_t)plnode->content, UPDATE_MANIFEST_SIZE)) == NULL){
		printf("Failed to parse update manifest from DDR\n");
		return -1;
	}

#if IS_ENABLED(CONFIG_CORETEE_ENABLE_BLOB)
	printf("Resetting the zmk!\n");
	res = set_update_zmk();
	if(res) {
		printf("Failed to set the ZMK in UPDATE!\n");
		return res;
	}
#endif

	printf("Updating components. Manifest: 0x%08x   plnode->content: %p\n", UPDATE_MANIFEST_SIZE, plnode->content);
	if((res = update_components( updateslip, (uintptr_t)(plnode->content)+UPDATE_MANIFEST_SIZE, plnode->length-UPDATE_MANIFEST_SIZE, layout, plex_str )) != 0) {
		printf("Failed to update components\n");
		goto done;
	}

	printf("Done update\n");
done:
	if(updateslip) {
		seq_free_manifest(updateslip);
	}

#ifdef CONFIG_CORETEE_ENABLE_BLOB
	clear_update_zmk();
#endif

	return res;
}

static int copy_update_to_ddr( uintptr_t *mmc_uaddr, size_t *plsize )
{
	SeqDerNode *parent=0;
	uint32_t offset = (uint32_t)(*mmc_uaddr);
	size_t length;
	uint8_t * update=NULL;
	int res=0;

#ifdef USE_UPDATE_MMC
	if(!update_mmc) {
		printf("Failed to create the MMC device object for UPDATE\n");
	}

	//Just get the header. 512 is the MMC block size and the minimum size to copy
	printf("Copying update from block offset 0x%08lx   to   DDR: 0x%08x\n", addr, DDR_UPDATE_PAYLOAD_ADDR);
	seq_mmc_read_dev( update_mmc, offset, SEQ_MMC_BLOCK_SIZE, (void*)DDR_UPDATE_PAYLOAD_ADDR);

	update = (uint8_t*)DDR_UPDATE_PAYLOAD_ADDR;

	parent = seq_asn1_parse_single_node(update, SEQ_MMC_BLOCK_SIZE);
	if(!parent) {
		printf("Failed to get parse update package!\n");
		return -1;
	}

	length = parent->rawlength;
	*plsize = length;

	printf("Total update size: %d  %d\n", parent->rawlength, parent->length);

	//Copy the whole update payload to DDR
	seq_mmc_read_dev( update_mmc, offset, length, (void*)DDR_UPDATE_PAYLOAD_ADDR );
#else //USE_UPDATE_MMC
	//Just get the header. 512 is the MMC block size and the minimum size to copy
	printf("Copying update header from block offset[%d] 0x%08x   to   DDR: 0x%08x\n", offset, offset, DDR_UPDATE_PAYLOAD_ADDR);
	seq_mmc_read( offset, SEQ_MMC_BLOCK_SIZE, (void*)DDR_UPDATE_PAYLOAD_ADDR);

	update = (uint8_t*)DDR_UPDATE_PAYLOAD_ADDR;

	printf("Update header...\n");
	seq_print_bytes(update, 32);

	parent = seq_asn1_parse_single_node(update, SEQ_MMC_BLOCK_SIZE);
	if(!parent) {
		printf("Failed to get parse update package!\n");
		return -1;
	}

	length = parent->rawlength;
	*plsize = length;

	printf("Total update size: %ld  %ld\n", parent->rawlength, parent->length);

	//Copy the whole update payload to DDR
	seq_mmc_read(offset, length, (void*)DDR_UPDATE_PAYLOAD_ADDR );
#endif //USE_UPDATE_MMC
	*mmc_uaddr = DDR_UPDATE_PAYLOAD_ADDR;
	return res;
}

int seq_run_update( unsigned int plexid )
{
	int res=0;
	uintptr_t uaddr=0;
#ifdef USE_UPDATE_MMC
	uint32_t update_part;
	uint32_t update_access;
	uint32_t update_ack;
#endif

	size_t plsize=0;
	SeqManifest *component=NULL;
	char *plex_str = (plexid == SEQ_PLEX_A_ID) ? "plex_a" : "plex_b";

	//Get the update manifest address from main component manifest.
	component = seq_get_manifest(SEQ_MANIFEST_COMPONENT);
	if(!component) {
		//printf("No component manifest found during update\n");
		return -1;
	}

	/*
	 * Read where the update payload is stored from the compidx manifest.
	 */
	uaddr = seq_get_keyval_uint32(component, "p13n", "update");
#ifdef USE_UPDATE_MMC
	update_part = seq_get_keyval_uint32(component, "p13n", "update_part");
	update_access = seq_get_keyval_uint32(component, "p13n", "update_access");
	update_ack = seq_get_keyval_uint32(component, "p13n", "update_ack");

	update_mmc = seq_get_mmc( update_ack, update_part, update_access );
	if(!update_mmc) {
		printf("Failed to get the MMC device for the update payload\n");
		return -1;
	}
#endif

	seq_service_watchdog();

	printf("Update at addr: 0x%08lx. Copying to DDR\n", uaddr);
	if((res = copy_update_to_ddr( &uaddr, &plsize )) != 0) {
		printf("Failed to copy the update to DDR\n");
		goto done;
	}

	seq_service_watchdog();

	printf("Calling verify_and_run_update...\n");
	if((res = verify_and_run_update( uaddr, plsize, component, plex_str )) != 0) {
		printf("Failed to run update\n");
		goto done;
	}

	seq_service_watchdog();

	//Successfully ran update
	memset((void*)uaddr, plsize, 0);
done:
	return res;
}
#else //SEQ_RUN_UPDATE
int seq_run_update(unsigned int plexid)
{
	printf("Update is not implemented yet. Returning success\n");
	return 0;
}
#endif
