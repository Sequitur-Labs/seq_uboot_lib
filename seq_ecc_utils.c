#include <common.h>
#include <hw_sha.h>
#include <memalign.h>
#include <fsl_sec.h>

#include <seq_manifest.h>
#include <seq_asn1.h>
#include <seq_boot_manifests.h>
#include <seq_error.h>
#include <seq_rng.h>
#include <uECC.h>
#include <seq_ecc_certificate.h>
#include <seq_ecc_utils.h>

extern void seq_print_bytes( uint8_t *data, uint32_t len);

///This is ONLY for 32bit ECC curves. Hardcoded lengths.
static unsigned char uECC_secp256r1_oid[]={0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07};
static int write_UECC_to_der( unsigned char *pvt, unsigned char *pub, unsigned char* outbuffer)
{
  int index=0, fullsize=0;
  int i;
  unsigned char oid_size = sizeof(uECC_secp256r1_oid);

  outbuffer[index++]=0x30; /*sequence*/
  outbuffer[index++]=0x77; /*sequence length - HARDCODED at 119*/
  outbuffer[index++]=0x02; /*integer*/
  outbuffer[index++]=0x01; /*length*/
  outbuffer[index++]=0x01; /*version - 1*/

  //Private key
  outbuffer[index++]=0x04; /*octet string*/
  outbuffer[index++]=0x20; /*32 bytes*/

  for(i=0;i<32;i++) {
	  outbuffer[index++]=pvt[i];
  }

  //Now optional parameters and public key
  outbuffer[index++] = 0xA0; /*First optional*/
  outbuffer[index++] = 0x0A; /*Length of optional*/
  outbuffer[index++] = 0x06; /*OID*/
  outbuffer[index++] = oid_size;

  for(i=0;i<oid_size;i++) {
	  outbuffer[index++]=uECC_secp256r1_oid[i];
  }

  //Now public key
  outbuffer[index++] = 0xA1; /*Second optional*/
  outbuffer[index++] = 0x44; /*Length of optional*/
  outbuffer[index++] = 0x03; /*Bit string*/
  outbuffer[index++] = 0x42; /*length of bit string*/
  outbuffer[index++] = 0x00; /*0x0004 shows uncompressed*/
  outbuffer[index++] = 0x04;

  for(i=0;i<64;i++) {
	  outbuffer[index++]=pub[i];
  }
  fullsize = index;

  return fullsize;
}

__attribute__((unused))
static void delete_root_key(SeqCertType cert)
{
	SeqManifest *manifest = seq_get_manifest(SEQ_MANIFEST_CERTS);
	if (!manifest)
		return;
	seq_delete_param_by_name(manifest, SEQ_MANIFEST_SECTION_PRIVATE, cert == SEQ_CERT_TYPE_EMPOWER ? SEQ_MANIFEST_KEY_EMPOWER_PRIVATE : SEQ_MANIFEST_KEY_OEM_PRIVATE);
};

int seq_save_binary_to_cert_manifest(uint8_t *key, size_t length, const char *section, const char *keyname)
{
	int res=SEQ_SUCCESS;
	SeqParamKey *skey=0;
	SeqManifest *manifest = seq_get_manifest(SEQ_MANIFEST_CERTS);

	if (!manifest) {
		res = SEQ_ERROR_ITEM_NOT_FOUND;
		SEQ_ERRMSG( res );
		return res;
	}

	//If it already exists, delete it.
	seq_delete_param_by_name(manifest, section, keyname);

	skey = seq_new_param(section, keyname, SEQ_TYPE_BINARY );
	if (!skey) {
		res = SEQ_ERROR_MEMORY;
		SEQ_ERRMSG( res );
		return res;
	}

	skey->value = malloc(length);
	if (skey->value) {
		memset(skey->value, 0, length);
		memcpy(skey->value, key, length);
		skey->size = length;
		skey->flags |= SEQ_FLAG_VALUE_DYNAMIC;
		seq_add_param(manifest, skey);
	} else {
		res = SEQ_ERROR_MEMORY;
		SEQ_ERRMSG( res );
		return res;
	}

	return res;
}

int seq_create_device_key( SeqCertType empower, uECC_RNG_Function random, uint8_t** privatekey, uint8_t **publickey ) {
	int res=SEQ_SUCCESS;
	uint8_t *privkey = NULL;
	uint8_t *pubkey = NULL;
	uint8_t *der = NULL;
	int derlength=0;
	const char *keyname = (empower == SEQ_CERT_TYPE_EMPOWER) ? SEQ_MANIFEST_KEY_EMPOWER_DEVICE : SEQ_MANIFEST_KEY_OEM_DEVICE;

	der = SEQ_ASN1_CALLOC(SEQ_KEY_DER_SIZE, sizeof(uint8_t));
	*publickey = SEQ_ASN1_CALLOC(SEQ_CURVE_KEY_SIZE * 2, sizeof(uint8_t) );
	*privatekey = SEQ_ASN1_CALLOC(SEQ_CURVE_KEY_SIZE, sizeof( uint8_t ));

	pubkey = *publickey;
	privkey = *privatekey;

	if (!der || !pubkey || !privkey) {
		res = SEQ_ERROR_MEMORY;
		SEQ_ERRMSG( res );
		return res;
	}

	uECC_set_rng(random);

	printf("Calling uECC_make_key...\n");
	if ((res = uECC_make_key(pubkey, privkey, uECC_secp256r1())) != 1) {
		res = SEQ_ERROR_CRYPTO;
		SEQ_ERRMSG( res );
		goto done;
	}

	res=SEQ_SUCCESS; //reset

	derlength=write_UECC_to_der(privkey, pubkey, der);

	printf("Device Private Key - %s\n", keyname);
	//seq_print_bytes(der, derlength);
	if (seq_save_binary_to_cert_manifest(der, derlength, SEQ_MANIFEST_SECTION_PRIVATE, keyname) != SEQ_SUCCESS) {
		res = SEQ_ERROR_PROGRAMMER;
		SEQ_ERRMSG( res );
	}

done:
	if (der) {
		free(der);
	}

	return res;
}

int seq_create_device_key_and_cert( SeqCertType empower, uECC_RNG_Function random)
{
	int res=SEQ_SUCCESS;
	uint8_t *privatekey = NULL;
	uint8_t *publickey = NULL;
	SeqManifest *manifest = seq_get_manifest(SEQ_MANIFEST_CERTS);
	SeqParamKey *key=NULL;
	uint32_t flags = (empower == SEQ_CERT_TYPE_EMPOWER) ? SEQ_CERT_CREATE_FLAGS_EMPOWER : 0;
	const char *keyname = (empower == SEQ_CERT_TYPE_EMPOWER) ? SEQ_MANIFEST_KEY_EMPOWER_DEVICE : SEQ_MANIFEST_KEY_OEM_DEVICE;

	if (!manifest) {
		res = SEQ_ERROR_ITEM_NOT_FOUND;
		SEQ_ERRMSG( res );
		return res;
	}

	key=seq_find_param(manifest, SEQ_MANIFEST_SECTION_PRIVATE, keyname);
	if (key) {
#if !IS_ENABLED(CONFIG_CORETEE_CERT_TEST)
		printf("[%s] key already exists\n", keyname);
		return SEQ_SUCCESS; //Is this an error or not...?
#endif //else continue
	}

	printf("Calling create_device_key\n");
	res = seq_create_device_key( empower, random, &privatekey, &publickey);
	if (res != SEQ_SUCCESS || !privatekey || !publickey) {
		SEQ_ERRMSG( res );
		goto done;
	}

	// ****** create device certificate after private device key has been created ***** //
	printf("    Generate signed cert...\n");
	if (seq_create_full_der_certificate(privatekey, publickey, SEQ_CURVE_KEY_SIZE, flags)) {
		puts("ERROR: Could not sign device cert!\n");
		puts("The CSR must be signed and passed in from the client command line!\n");
	}

	printf("    Done creating cert\n    Creating CSR...\n");
	seq_create_full_der_certificate(privatekey, publickey, SEQ_CURVE_KEY_SIZE, flags | SEQ_CERT_CREATE_FLAG_CSR);
	printf("    Done creating CSR\n");

	//Delete the root private key. We don't need it anymore.
	//The public key can be retrieved from the oem cert.
	//printf("Delete root key...\n");
#if !IS_ENABLED(CONFIG_CORETEE_CERT_TEST) //We'll need these keys for testing.
	delete_root_key( empower );
#endif

	//Zero out private key memory
	//printf("Zero private key...\n");
	memset(privatekey,0,SEQ_CURVE_KEY_SIZE);

done:
	puts("    Done create device key/cert\n");
	if (privatekey) {
		SEQ_ASN1_FREE(privatekey);
	}
	if (publickey) {
		SEQ_ASN1_FREE(publickey);
	}
	return res;
}

int seq_get_ecc_public_key(uint8_t *oempk, size_t pksize, const char *certname)
{
	int res=0;
	int index=6;
	SeqDerNode *parent=NULL, *cert=NULL, *version=NULL, *eccsig, *ecpoint;
	uint8_t *pointbuffer=NULL;
	SeqParamKey *key=NULL;

	key = seq_find_param(seq_get_manifest(SEQ_MANIFEST_CERTS), SEQ_MANIFEST_SECTION_PUBLIC, certname);
	if (!key || key->size == 0) {
		res = SEQ_ERROR_ITEM_NOT_FOUND;
		SEQ_ERRMSG( res );
		return res;
	}

	if (pksize < SEQ_CURVE_KEY_SIZE*2) {
		res = SEQ_ERROR_BAD_PARAMS;
		SEQ_ERRMSG( res );
		return res;
	}

	//printf("Certname: %s\n", certname);
	//seq_print_bytes(key->value, key->size);

	res = seq_asn1_parse_der(&parent, key->value, key->size);
	if (res) {
		res = SEQ_ERROR_PARSE;
		SEQ_ERRMSG( res );
		return res;
	}

	cert = seq_asn1_get_child(parent, 0);

	//printf("TBS Cert...\n");
	//seq_print_bytes(cert->raw, cert->rawlength);

	version = seq_asn1_get_child(cert, 0);

	//printf("Version: Cls: 0x%08x   Tag 0x%08x\n", version->cls, version->tag);
	if (version->cls == SEQ_ASN1_CLS_CONTEXT && version->tag==SEQ_ASN1_CONTEXT_EXPLICIT(0)) {
		index = 6;
	} else  {
		index = 5;
	}

	eccsig = seq_asn1_get_child(cert, index);
	if (!eccsig) {
		res = SEQ_ERROR_ITEM_NOT_FOUND;
		SEQ_ERRMSG( res );
		goto done;
	}

	//ECC public key
	//Key should be
	//Sequence
	//	Sequence
	//	  ecPublicKey OID
	//	  ecCurveID
	//	BitString
	ecpoint=seq_asn1_get_child(eccsig,1);
	if (!ecpoint) {
		res = SEQ_ERROR_ITEM_NOT_FOUND;
		SEQ_ERRMSG( res );
		goto done;
	}

	if (ecpoint->tag!=SEQ_ASN1_BITSTRING) {
		res = SEQ_ERROR_PROGRAMMER;
		SEQ_ERRMSG( res );
		goto done;
	}

	pointbuffer=(uint8_t*)ecpoint->content;

	// we only handle regular packing, not compressed or hybrid
	if (!pointbuffer || pointbuffer[1]!=0x04) {
		res = SEQ_ERROR_ITEM_NOT_FOUND;
		SEQ_ERRMSG( res );
		goto done;
	}

	memcpy(oempk,&pointbuffer[2],SEQ_CURVE_KEY_SIZE);
	memcpy(oempk+SEQ_CURVE_KEY_SIZE,&pointbuffer[2+SEQ_CURVE_KEY_SIZE],SEQ_CURVE_KEY_SIZE);

done:
	if (parent) {
		seq_asn1_free_tree(parent, SEQ_AP_FREENODEONLY);
	}
	return res;
}


uint32_t seq_extract_ec_signature(uint8_t **sigbuffer, size_t *sigbuffersize, SeqDerNode *signode)
{
	uint32_t res=-1;
	SeqDerNode *rnode=NULL, *snode=NULL;
	if (!signode ||  seq_asn1_get_child_count(signode) != 2) {
		res = SEQ_ERROR_PROGRAMMER; //Bad sequence
		SEQ_ERRMSG( res );
		return res;
	}

	// ec signature = sequence with two ints
	rnode=seq_asn1_get_child(signode,0);
	snode=seq_asn1_get_child(signode,1);

	if (rnode && snode) {
		uint8_t* rint=rnode->content;
		size_t rintsize=rnode->length;
		size_t roffset=0;

		uint8_t* sint=snode->content;
		size_t sintsize=snode->length;
		size_t soffset=0;

		if (rint[0]==0x0) {
			rint+=1;
			rintsize-=1;
		}

		if (sint[0]==0x0) {
			sint+=1;
			sintsize-=1;
		}

		if (sintsize<=SEQ_CURVE_KEY_SIZE && rintsize<=SEQ_CURVE_KEY_SIZE) {
			roffset=SEQ_CURVE_KEY_SIZE-rintsize;
			soffset=SEQ_CURVE_KEY_SIZE-sintsize;

			//*sigbuffersize=rintsize+sintsize;
			*sigbuffersize=SEQ_CURVE_KEY_SIZE*2;
			*sigbuffer=(uint8_t*)calloc(1,*sigbuffersize);

			memcpy(*sigbuffer+roffset,rint,rintsize);
			memcpy(*sigbuffer+SEQ_CURVE_KEY_SIZE+soffset,sint,sintsize);
			res=0;
		} else {
			res = SEQ_ERROR_BAD_PARAMS; //Bad format
			SEQ_ERRMSG( res );
			return res;
		}
	} else {
		res = SEQ_ERROR_ITEM_NOT_FOUND; //Bad sequence
		SEQ_ERRMSG( res );
		return res;
	}

	return res;
}

void seq_run_sha(uint8_t *hashvalue, uint32_t hashlen, void *data, uint32_t size, SeqShaType sha)
{
#if defined(CONFIG_SPL_CRYPTO_SUPPORT) && defined(CONFIG_FSL_CAAM)
	uint8_t* dataaligned=NULL;
	uint8_t* localhash=NULL;
	int shalen = sha == SEQ_SHA_256 ? SEQ_SHA256LEN_BYTES : SEQ_SHA1LEN_BYTES;

	if (!hashvalue || !data) {
		SEQ_ERRMSG( SEQ_ERROR_BAD_PARAMS);
		return;
	}

	if (hashlen < shalen) {
		SEQ_ERRMSG( SEQ_ERROR_BAD_PARAMS);
		return;
	}
	
	//Align data before calling CAAM
	dataaligned=malloc_cache_aligned(size);
	localhash=malloc_cache_aligned( shalen );

	if (!dataaligned || !localhash) {
		SEQ_ERRMSG( SEQ_ERROR_MEMORY);
		memset(hashvalue, 0, shalen);
		return;
	}

	memcpy(dataaligned,data,size);
	//printf("Calling hardware sha. Size: %d\n", size);
	if (sha == SEQ_SHA_256) {
		hw_sha256(dataaligned,size,localhash,0);
	} else {
		hw_sha1(dataaligned,size,localhash,0);
	}

	//printf("After hw, copy local\n");
	memcpy(hashvalue,localhash,shalen);

	free(dataaligned);
	free(localhash);
#else //SPL_CRYPTO && FSL_CAAM

#ifdef CONFIG_SPL_HASH_SUPPORT
	printf("Using hash_block");
	int shalen=(sha==SEQ_SHA_256) ? SEQ_SHA256LEN : SEQ_SHA1LEN;
	hash_block((sha==SEQ_SHA_256) ? "sha256" : "sha1",data,size,hashvalue,&shalen);
	
#else // CONFIG_SPL_HASH_SUPPORT

#error NO HASH CODE

#endif 

#endif //SPL_CRYPTO && FSL_CAAM
}

/*
 * Function prototype to match what uECC needs.
 */
int seq_random(unsigned char* out, uint32_t len)
{
	uint32_t res=-1;
	uint8_t* ranalign=NULL;

	ranalign = malloc_cache_aligned(len);
	if (!ranalign) {
		return res;
	}

	memset(ranalign,0,len);
	res=seq_rng(ranalign,len);
	memcpy(out,ranalign,len);
	free(ranalign);

	return (res == 0); /*uECC needs 1 on success*/
}

void seq_set_uecc_rng( void )
{
	uECC_set_rng(seq_random);
}
