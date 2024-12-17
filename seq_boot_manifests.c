/*================================================
Copyright © 2016-2019 Sequitur Labs Inc. All rights reserved.

The information and software contained in this package is proprietary property of
Sequitur Labs Incorporated. Any reproduction, use or disclosure, in whole
or in part, of this software, including any attempt to obtain a
human-readable version of this software, without the express, prior
written consent of Sequitur Labs Inc. is forbidden.
================================================*/

#include <common.h>
#include <inttypes.h>
#include <seq_boot_manifests.h>

uint8_t SEQ_AES_MAGIC[8]={'a','e','s','s','l','i','p',0x00};

struct manifestarray {
	SeqManifestIndex index;
	char *name;
};

static struct manifestarray s_manifestarray[]={
	{SEQ_MANIFEST_COMPONENT, "layout"},
	{SEQ_MANIFEST_CERTS, "certs"},
	{SEQ_MANIFEST_SEQ,"pd_seq"},
	{SEQ_MANIFEST_OEM,"pd_oem"},
	{SEQ_MANIFEST_EMPOWER, "empower"}
#if IS_ENABLED(CONFIG_CORETEE_USE_KEYRING)
	, {SEQ_MANIFEST_KEYRING, "keyring"}
#endif
};

static SeqManifest* s_manifests[SEQ_NUM_MANIFESTS]={0};

static SeqManifest *load_sub_manifest(SeqManifestIndex index, SEQ_MANIFEST_MANGLE mangle)
{
	SeqManifest* res=0;
	char* name=seq_get_manifest_name(index);
	if (name) {
		uintptr_t address=seq_get_manifest_address_by_name(name);
		//printf("Address for slip: %s is %p\n", name, (void*)address);
		printf("Loading slip - %s - from NVM\n", name);
		uintptr_t ddr = address;
		if (mangle) {
			mangle(index,&ddr);
			res = seq_load_manifest(ddr);
		} //else do nothing

		if(res) {
			res->nvm = address; /*NVM address*/
		}
		else {
			printf("Failed to load subslip: %s\n", name);
		}
	} else {
		printf("ERROR: Slip name not found for index - 0x%08x\n",index);
	}
	return res;
}

//-----------------------------------------------
// public
uintptr_t seq_get_manifest_address_by_name(const char *name)
{
	uintptr_t res=0;
	SeqParamKey* key=NULL;
	if(!name) {
		return res;
	}

	key = seq_find_param(s_manifests[SEQ_MANIFEST_COMPONENT], name, "dest");
	if (key) {
		memcpy(&res, key->value, sizeof(uint32_t));
	}
	return res;
}

uintptr_t seq_get_manifest_address_by_index(SeqManifestIndex index)
{
	char* name = seq_get_manifest_name(index);
	if(name) {
		return seq_get_manifest_address_by_name(name);
	}
	return 0;
}

char *seq_get_manifest_name(SeqManifestIndex index)
{
	char* res=0;
	struct manifestarray* ptr=s_manifestarray;
	while (ptr) {
		if (ptr->index==index) {
			res=ptr->name;
			break;
		}
		ptr++;
	}
	return res;
}

int seq_init_manifests(uintptr_t compaddr, SEQ_MANIFEST_MANGLE mangle)
{
	uintptr_t address=compaddr;
	uintptr_t ddr = address;
	int res=0;

	// decrypt component slip
	if(mangle) {
		mangle(SEQ_MANIFEST_COMPONENT, &ddr);
	} //else do nothing

	printf("Calling load manifest for %" PRIxPTR "\n", compaddr);
	s_manifests[SEQ_MANIFEST_COMPONENT] = seq_load_manifest(ddr);
	if (s_manifests[SEQ_MANIFEST_COMPONENT]) {
		s_manifests[SEQ_MANIFEST_COMPONENT]->nvm = address;
		int i=0;
		for(i=1; i<SEQ_NUM_MANIFESTS; i++){
			SeqManifest* slip=0;

			slip=load_sub_manifest(i,mangle);
			if (slip) {
				s_manifests[i]=slip;
			} else {
				printf("WARNING: MANIFEST ID [%d] not found\n", i);
			}
		}
	} else {
		puts("ERROR: Component MANIFEST not found or could not be loaded.\n");
		res=-1;
	}
	return res;
}

void seq_replace_manifest( SeqManifestIndex index, SeqManifest *newslip )
{
	if(s_manifests[index]) {
		seq_free_manifest(s_manifests[index]);
	}
	s_manifests[index] = newslip;
}

SeqManifest* seq_get_manifest(SeqManifestIndex index)
{
	return s_manifests[index];
}

