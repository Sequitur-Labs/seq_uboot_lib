#include <common.h>
#include <hw_sha.h>
#include <memalign.h>
#include <fsl_sec.h>

#include <seq_asn1.h>
#include <seq_manifest.h>

#include <seq_boot_manifests.h>
#include <seq_error.h>
#include <uECC.h>
#include <seq_ecc_certificate.h>
#include <seq_ecc_utils.h>
#include <seq_tests.h>

#if IS_ENABLED(CONFIG_CORETEE_PROV_TESTS)
extern void seq_print_bytes( uint8_t *data, uint32_t len);

#if IS_ENABLED(CONFIG_CORETEE_CERT_TEST)

/*
 * Verifies the created device cert using the root cert of the accompanying type
 */
int seq_verify_device_cert(SeqCertType certtype) {
	int res=-1;
	SeqDerNode *devparent=NULL, *devtbs=NULL, *devbits=NULL, *devsig=NULL, *tmpnode=NULL;
	SeqManifest *manifest = seq_get_manifest(SEQ_MANIFEST_CERTS);
	SeqParamKey *certkey=NULL;
	const char *certname = (certtype == SEQ_CERT_TYPE_EMPOWER) ? SEQ_MANIFEST_CERT_EMPOWER_DEVICE : SEQ_MANIFEST_CERT_OEM_DEVICE;
	const char *rootcertname = (certtype == SEQ_CERT_TYPE_EMPOWER) ? SEQ_MANIFEST_CERT_EMPOWER_ROOT : SEQ_MANIFEST_CERT_OEM_ROOT;
	uint8_t *tmpbytes=NULL;
	uint8_t *rootpublic=NULL, *sigbytes=NULL, *hashbytes=NULL, *derbytes=NULL;
	size_t rootpubliclen=0, siglen=0, hashlen=0, derlen=0;

	printf("Running: %s...\n", __func__);
	if(!manifest) {
		res = SEQ_ERROR_ITEM_NOT_FOUND;
		SEQ_ERRMSG( res);
		return res;
	}

	rootpublic = malloc(SEQ_CURVE_KEY_SIZE*2);
	rootpubliclen = SEQ_CURVE_KEY_SIZE*2;
	if(!rootpublic) {
		res = SEQ_ERROR_MEMORY;
		SEQ_ERRMSG( res);
		return res;
	}

	res = seq_get_ecc_public_key(rootpublic, rootpubliclen, rootcertname);
	if(res) {
		res = SEQ_ERROR_ITEM_NOT_FOUND;
		SEQ_ERRMSG( res);
		goto done;
	}

	//printf("Public key bytes are: \n");
	//seq_print_bytes(rootpublic, rootpubliclen);

	printf("Loading cert name: %s\n", certname);
	certkey = seq_find_param(manifest, SEQ_MANIFEST_SECTION_PUBLIC, certname);
	if(!certkey) {
		res = SEQ_ERROR_ITEM_NOT_FOUND;
		SEQ_ERRMSG( res);
		goto done;
	}

	//printf("Device certificate is: \n");
	//seq_print_bytes(certkey->value, certkey->size);

	res = seq_asn1_parse_der(&devparent, certkey->value, certkey->size);
	if(!devparent || res != 0){
		res = SEQ_ERROR_PARSE;
		SEQ_ERRMSG( res);
		goto done;
	}

	//Get TBS cert
	devtbs = seq_asn1_get_child(devparent, 0);
	if(!devtbs || devtbs->tag != SEQ_ASN1_SEQUENCE) {
		res = SEQ_ERROR_PROGRAMMER; //Bad sequence
		SEQ_ERRMSG( res);
		goto done;
	}

	//We only generate ECC256 certs so skip signature algorithm and just get signature.
	devbits = seq_asn1_get_child(devparent, 2);
	if(!devbits || devbits->tag != SEQ_ASN1_BITSTRING) {
		res = SEQ_ERROR_PROGRAMMER; //Bad sequence
		SEQ_ERRMSG( res);
		goto done;
	}

	tmpbytes = devbits->content;
	tmpbytes++; //Skip 0x00 for uncompressed bitstring.
	res = seq_asn1_parse_der(&devsig, tmpbytes, devbits->length-1);
	if(!devsig || res != 0) {
		res = SEQ_ERROR_PARSE;
		SEQ_ERRMSG( res);
		goto done;
	}

	res = seq_extract_ec_signature(&sigbytes, &siglen, devsig);
	if(res) {
		res = SEQ_ERROR_PROGRAMMER; //Bad sequence
		SEQ_ERRMSG( res);
		goto done;
	}
	//printf("Signature bytes are: \n");
	//seq_print_bytes(sigbytes, siglen);

	//Verify existing signature of tbs part.
	derlen = seq_asn1_get_size(devtbs);
	derbytes = SEQ_ASN1_MALLOC(derlen);
	if(!derbytes) {
		res = SEQ_ERROR_MEMORY;
		SEQ_ERRMSG( res);
		goto done;
	}

	tmpnode = devtbs->next;
	devtbs->next = NULL;
	derlen = seq_asn1_encode(derbytes, devtbs);
	if(derlen == 0) {
		res = SEQ_ERROR_PROGRAMMER; //Bad sequence
		SEQ_ERRMSG( res);
		goto done;
	}

	//printf("TBS bytes are (%d): \n", derlen);
	//seq_print_bytes(derbytes, derlen);

	devtbs->next = tmpnode;
	tmpnode = NULL;

	hashlen=SEQ_SHA256LEN_BYTES;
	hashbytes = malloc(hashlen);
	if(!hashbytes) {
		res = SEQ_ERROR_MEMORY;
		SEQ_ERRMSG( res);
		goto done;
	}
	seq_run_sha(hashbytes, hashlen, derbytes, derlen, SEQ_SHA_256);

	//printf("Hash is:\n");
	//seq_print_bytes(hashbytes, hashlen);


	if((res = uECC_verify(rootpublic, hashbytes, hashlen, sigbytes, uECC_secp256r1())) == 0){
		res = SEQ_ERROR_CRYPTO;
		SEQ_ERRMSG( res);
		goto done;
	}

	res = SEQ_SUCCESS;
	printf("Device Certificate has been VERIFIED!\n");

done:
	if(res != SEQ_SUCCESS){
		if(rootpublic) {
			printf("OEM Public Key: \n");
			seq_print_bytes(rootpublic, rootpubliclen);
		}
		if(sigbytes){
			printf("Extracted signature: \n");
			seq_print_bytes(sigbytes, siglen);
		}
		if(derbytes){
			printf("Device TBS Cert: \n");
			seq_print_bytes(derbytes, derlen);
		}
	}

	if(rootpublic) {
		free(rootpublic);
	}

	if(hashbytes) {
		free(hashbytes);
	}

	if(sigbytes) {
		free(sigbytes);
	}

	if(derbytes) {
		free(derbytes);
	}

	if(devsig) {
		seq_asn1_free_tree(devsig, SEQ_AP_FREENODEONLY);
	}

	if(devparent) {
		seq_asn1_free_tree(devparent, SEQ_AP_FREENODEONLY);
	}

	return res;
}

void seq_execute_cert_test( uECC_RNG_Function random )
{
	//Generate and verify the oem device cert.
	int res=SEQ_SUCCESS;
	int i=0;
	int numtests=1000;
	for(i=0; i<numtests && res==SEQ_SUCCESS; i++){
		printf("\nRunning test num: %d\n", i);
		res = seq_create_device_key_and_cert( SEQ_CERT_TYPE_OEM, random );
		if(res == SEQ_SUCCESS) {
			res = seq_verify_device_cert( SEQ_CERT_TYPE_OEM );
		}
#if IS_ENABLED(CONFIG_UNIT_TEST)
		malloc_stats();
#endif
	}

	printf("[%s] RESULT: %s\n", __func__, res==SEQ_SUCCESS ? "SUCCESS" : "FAILED");
}
#else //CONFIG_CORETEE_CERT_TEST
void seq_execute_cert_test( uECC_RNG_Function random )
{
	(void)random;
	return;
}
#endif

#if IS_ENABLED(CONFIG_CORETEE_KEY_TEST)

static int seq_create_test_key( SeqCertType certtype, uECC_RNG_Function random)
{
	int res = SEQ_SUCCESS;
	uint8_t *privatekey=NULL;
	uint8_t *publickey=NULL;

	res = seq_create_device_key( certtype, random, &privatekey, &publickey );
	if(privatekey) {
		free(privatekey);
	}
	if(publickey) {
		free(publickey);
	}

	return res;
}

/*
 * ECPrivateKey ::= SEQUENCE {
     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     privateKey     OCTET STRING,
     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
     publicKey  [1] BIT STRING OPTIONAL
   }
 */
typedef struct {
	uint8_t *pvt_key; /*length*/
	uint8_t *pub_key; /*length * 2*/
	size_t length;
} SeqEccKey;

static int load_device_key( SeqCertType certtype, SeqEccKey *devicekey )
{
	SeqDerNode *top=NULL, *pvt=NULL, *pub=NULL, *oidnode=NULL, *option=NULL;
	uint32_t temp[2];
	//int i;
	uint8_t *derbuffer=NULL;
	size_t dersize=0;
	int res=0;
	SeqParamKey *keyparam=NULL;
	SeqManifest *manifest = seq_get_manifest(SEQ_MANIFEST_CERTS);
	const char *keyname = (certtype == SEQ_CERT_TYPE_EMPOWER) ? SEQ_MANIFEST_KEY_EMPOWER_DEVICE : SEQ_MANIFEST_KEY_OEM_DEVICE;

	memset(devicekey, 0, sizeof(SeqEccKey));

	keyparam = seq_find_param(manifest, SEQ_MANIFEST_SECTION_PRIVATE, keyname);
	if(!keyparam){
		res = SEQ_ERROR_ITEM_NOT_FOUND;
		SEQ_ERRMSG(res);
		return res;
	}

	//This is not allocated but still held by the manifest.
	derbuffer = keyparam->value;
	dersize = keyparam->size;

	if(!derbuffer) {
		res = SEQ_ERROR_ITEM_NOT_FOUND;
		SEQ_ERRMSG(res);
		return res;
	}

	seq_asn1_parse_der(&top, derbuffer, dersize);
	if(!top) {
		res = SEQ_ERROR_PARSE;
		SEQ_ASN1_FREE(derbuffer);
		SEQ_ERRMSG(res);
		return res;
	}

	pvt = seq_asn1_get_child(top, 1);
	devicekey->length = pvt->length;
	devicekey->pvt_key = (uint8_t*)SEQ_ASN1_MALLOC(pvt->length);
	if(!devicekey->pvt_key){
		res = SEQ_ERROR_MEMORY;
		SEQ_ERRMSG(res);
		goto done;
	}
	memcpy(devicekey->pvt_key, pvt->content, pvt->length);

	option = seq_asn1_get_child(top, 2);
	if(option->cls == SEQ_ASN1_CLS_CONTEXT && option->tag == SEQ_ASN1_CONTEXT_EXPLICIT(0)) {
		seq_asn1_parse_der(&oidnode, option->content, option->length);
		//TODO - Make sure the curve matches the key lengths!
		seq_asn1_free_tree(oidnode, SEQ_AP_FREENODEONLY);
		option = seq_asn1_get_child(top, 3);
	}

	if(option->cls == SEQ_ASN1_CLS_CONTEXT && option->tag == SEQ_ASN1_CONTEXT_EXPLICIT(1)) {
		seq_asn1_parse_der(&pub, option->content, option->length);
		//outputData(pub->content, pub->length);
		devicekey->pub_key = (uint8_t*)SEQ_ASN1_MALLOC(pub->length - 2);
		if(devicekey->pub_key){
			memcpy(devicekey->pub_key, pub->content+2, pub->length-2); /*ignore 0x00 0x04 to start*/
		}
		seq_asn1_free_tree(pub, SEQ_AP_FREENODEONLY);
	} else {
		printf("Not copying public key bytes!\n");
	}

done:
	seq_asn1_free_tree(top, SEQ_AP_FREENODEONLY);
	memset(temp,0,2);
	return res;
}

static int seq_verify_device_key( SeqCertType certtype )
{
	int res = SEQ_SUCCESS;
	SeqEccKey devicekey;
	static const char testbuffer[SEQ_CURVE_KEY_SIZE] = "01234567890123456789012345678901";
	uint8_t *sigbuffer=NULL;
	size_t siglen=0;

	memset(&devicekey, 0, sizeof(SeqEccKey));

	res=load_device_key( certtype, &devicekey );

	if(res != SEQ_SUCCESS){
		SEQ_ERRMSG(res);
		goto done;
	}

	siglen = SEQ_CURVE_KEY_SIZE*2;
	sigbuffer = malloc(siglen);
	if(!sigbuffer){
		res = SEQ_ERROR_MEMORY;
		SEQ_ERRMSG(res);
		goto done;
	}

	res = uECC_sign(devicekey.pvt_key, testbuffer, SEQ_CURVE_KEY_SIZE, sigbuffer, uECC_secp256r1());
	if(res != 1) { //uECC Success is '1'
		res = SEQ_ERROR_CRYPTO;
		SEQ_ERRMSG( res);
		goto done;
	}

	if((res = uECC_verify(devicekey.pub_key, testbuffer, SEQ_CURVE_KEY_SIZE, sigbuffer, uECC_secp256r1())) != 1){
		res = SEQ_ERROR_CRYPTO;
		SEQ_ERRMSG(res);
		goto done;
	}

	res = SEQ_SUCCESS;
	printf("Device key has been verified!\n");

done:
	if(res != SEQ_SUCCESS){
		if(devicekey.pub_key) {
			printf("Device Public Key: \n");
			seq_print_bytes(devicekey.pub_key, SEQ_CURVE_KEY_SIZE*2);
		}
		if(devicekey.pvt_key) {
			printf("Device Private Key: \n");
			seq_print_bytes(devicekey.pvt_key, SEQ_CURVE_KEY_SIZE);
		}
		if(sigbuffer){
			printf("Extracted signature: \n");
			seq_print_bytes(sigbuffer, siglen);
		}
	}

	if(devicekey.pvt_key){
		free(devicekey.pvt_key);
	}
	if(devicekey.pub_key){
		free(devicekey.pub_key);
	}
	if(sigbuffer) {
		free(sigbuffer);
	}
	return res;
}

void seq_execute_key_test( uECC_RNG_Function random )
{
	//Generate and verify the oem device cert.
	int res=SEQ_SUCCESS;
	int i=0;
	int numtests=1000;
	for(i=0; i<numtests && res==SEQ_SUCCESS; i++) {
		printf("\nRunning test num: %d\n", i);
		res = seq_create_test_key( SEQ_CERT_TYPE_OEM, random );
		if(res == SEQ_SUCCESS) {
			res = seq_verify_device_key( SEQ_CERT_TYPE_OEM );
		}
#if IS_ENABLED(CONFIG_UNIT_TEST)
		malloc_stats();
#endif
	}

	printf("[%s] RESULT: %s\n", __func__, res==SEQ_SUCCESS ? "SUCCESS" : "FAILED");
}
#else //CONFIG_CORETEE_CERT_TEST
void seq_execute_key_test( uECC_RNG_Function random )
{
	return;
}

#endif

#endif //CONFIG_CORETEE_PROV_TESTS

