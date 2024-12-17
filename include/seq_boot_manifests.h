/*================================================
Copyright © 2016-2019 Sequitur Labs Inc. All rights reserved.

The information and software contained in this package is proprietary property of
Sequitur Labs Incorporated. Any reproduction, use or disclosure, in whole
or in part, of this software, including any attempt to obtain a
human-readable version of this software, without the express, prior
written consent of Sequitur Labs Inc. is forbidden.
================================================*/
#ifndef _SEQ_MANIFEST_HELPER_H_
#define _SEQ_MANIFEST_HELPER_H_

#include <seq_manifest.h>

//Size of all manifests in NVM
#define SEQ_MANIFEST_SIZE 0x10000

//Index values for the different manifests.
typedef enum {
	SEQ_MANIFEST_COMPONENT,
	SEQ_MANIFEST_SEQ,
	SEQ_MANIFEST_OEM,
	SEQ_MANIFEST_CERTS,
	SEQ_MANIFEST_EMPOWER,
#if IS_ENABLED(CONFIG_CORETEE_USE_KEYRING)
	SEQ_MANIFEST_KEYRING,
#endif
	SEQ_NUM_MANIFESTS
} SeqManifestIndex;

extern uint8_t SEQ_AES_MAGIC[8];


#define SEQ_MANIFEST_SECTION_PERSONALIZATION "p13n"
#define SEQ_MANIFEST_SECTION_SYSTEM "system"
#define SEQ_MANIFEST_SECTION_SPL "spl"
#define SEQ_MANIFEST_SECTION_BOOT "boot"
#define SEQ_MANIFEST_SECTION_PLEX_A "plex_a"
#define SEQ_MANIFEST_SECTION_PLEX_B "plex_b"

#define SEQ_MANIFEST_SECTION_PRIVATE "prv"
#define SEQ_MANIFEST_SECTION_PUBLIC "pub"
#define SEQ_MANIFEST_SECTION_OEM	"oem"
#define SEQ_MANIFEST_SECTION_EMPOWER "empower"
#define SEQ_MANIFEST_SECTION_SEQLABS "seqlabs"
#define SEQ_MANIFEST_SECTION_KEYS "keys"
#define SEQ_MANIFEST_SECTION_CRYPT "crypt"
#define SEQ_MANIFEST_SECTION_FTPM "ftpm"

#define SEQ_MANIFEST_CERT_OEM_ROOT	  "oem.root.cert"
#define SEQ_MANIFEST_CERT_OEM_PAYLOAD "oem.payload.cert"
#define SEQ_MANIFEST_CERT_OEM_COMMAND "oem.command.cert"
#define SEQ_MANIFEST_CERT_OEM_CLOUD "oem.cloud.cert"
#define SEQ_MANIFEST_CERT_OEM_DEVICE "oem.device.cert"
#define SEQ_MANIFEST_CERT_EMPOWER_ROOT "emp.root.cert"
#define SEQ_MANIFEST_CERT_EMPOWER_DEVICE "emp.device.cert"
#define SEQ_MANIFEST_CERT_EMPOWER_CLOUD "emp.cloud.cert"

#define SEQ_MANIFEST_CSR_EMPOWER_DEVICE "emp.device.csr"
#define SEQ_MANIFEST_CSR_OEM_DEVICE "oem.device.csr"

#define SEQ_MANIFEST_KEY_EMPOWER_DEVICE "emp.device.key"
#define SEQ_MANIFEST_KEY_EMPOWER_PRIVATE "emp.private.key"
#define SEQ_MANIFEST_KEY_OEM_DEVICE "oem.device.key"
#define SEQ_MANIFEST_KEY_OEM_PRIVATE "oem.private.key"

#define SEQ_MANIFEST_KEY_TA_ENCRYPTION "seq.ta_encryption.key"
#define SEQ_MANIFEST_KEY_CORETEE "seq.coretee.key"

#define SEQ_MANIFEST_KEY_USER_1 "seq.userkey.1"
#define SEQ_MANIFEST_KEY_USER_2 "seq.userkey.2"
#define SEQ_MANIFEST_KEY_USER_3 "seq.userkey.3"
#define SEQ_MANIFEST_KEY_USER_4 "seq.userkey.4"

#define SEQ_MANIFEST_KEY_CRYPT_CERTS "certkey"
#define SEQ_MANIFEST_KEY_CRYPT_EMPOWER "empkey"
#define SEQ_MANIFEST_KEY_CRYPT_KEYRING "keyringkey"

#define SEQ_MANIFEST_FTPM_SN "seq.ftpm.device_sn"
#define SEQ_MANIFEST_FTPM_VAULT_KEY "seq.ftpm.vault_key"

/*
 * Individual components contained within a plex
 */
typedef enum seq_component_id_t {
	SPL_COMPONENT_ID = 0,
	CORETEE_COMPONENT_ID = 1,
	UBOOT_COMPONENT_ID = 2,
	LINUX_COMPONENT_ID = 3,
	FILESYSTEM_COMPONENT_ID = 4,
	FDT_COMPONENT_ID = 5,
	ATF_COMPONENT_ID = 6,
	NUM_COMPONENTS
} SeqComponentId;


//Must line up with crypt_blob tool used in manifest encryption.
typedef struct SeqCryptSlip {
	uint8_t magic[8];
	uint32_t plainsize;
	uint32_t cryptsize;
} SeqCryptSlip_t;

typedef void (*SEQ_MANIFEST_MANGLE)(SeqManifestIndex index, uintptr_t *address);

int seq_init_manifests(uintptr_t compaddr, SEQ_MANIFEST_MANGLE mangle);
SeqManifest *seq_get_manifest(SeqManifestIndex index);
void seq_replace_manifest(SeqManifestIndex index, SeqManifest *manifest);

void seq_free_manifest(SeqManifest* manifest);


char* seq_get_manifest_name(SeqManifestIndex index);
uintptr_t seq_get_manifest_address_by_index(SeqManifestIndex index);
uintptr_t seq_get_manifest_address_by_name(const char *name);


#endif /*SEQ_MANIFEST_HELPER_H*/
