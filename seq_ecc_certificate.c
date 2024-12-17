 /*
 * Copyright © 2016-2017 Sequitur Labs Inc. All rights reserved.
 *
 * The information and software contained in this package is proprietary property of
 * Sequitur Labs Incorporated, except as noted by individual copyright in files.
 * Any reproduction, use or disclosure, in whole or in part, of this software
 * including, but not limited to, any attempt to obtain a human-readable version of this
 * software, without the express, prior written consent of Sequitur Labs Inc. is forbidden.
 */
#include <common.h>
#include <asm/io.h>
#include <malloc.h>

#include <seq_imx8m_regs.h>

#include <seq_error.h>
#include <seq_manifest.h>
#include <seq_boot_manifests.h>
#include <seq_ecc_utils.h>
#include <seq_asn1.h>
#include <uECC.h>
#include <uECC_types.h>
#include <seq_ecc_certificate.h>

typedef struct {
	uint8_t *pvt_key; /*length*/
	uint8_t *pub_key; /*length * 2*/
	size_t length;
} SeqEccKey;

typedef struct {
	uint8_t oid[16];
	size_t length;
} SeqEncodedOID;

typedef struct cert_options_t {
	char *name;
	char *value;
	struct cert_options_t *next;
} SeqCertOptions;

/*******************NAME Options**********************/
/*
 * These must sync up with the ObjectID values in OptionOID list and
 * char * name value in OptionName list.
 */
typedef enum {
	OT_COUNTRY,
	OT_STATE,
	OT_LOCALITY,
	OT_ORGANIZATION,
	OT_ORG_UNIT,
	OT_COMMON_NAME, //Maximum value for OptionOID list
	OT_START_DATE,
	OT_END_DATE
} SeqOptionType;


extern void seq_print_bytes( uint8_t *data, uint32_t len);

static uint32_t s_create_flags=0;
static SeqEccKey s_root_key;
static SeqEccKey s_device_key;

/*
 * *_pd means personalization data.
 */
static int get_root_key(uint8_t **buffer, size_t *size )
{
	SeqManifest* manifest=0;
	SeqParamKey *skey=0;
	manifest=seq_get_manifest(SEQ_MANIFEST_CERTS);
	const char* keyname = ((s_create_flags & SEQ_CERT_CREATE_FLAGS_EMPOWER) == SEQ_CERT_CREATE_FLAGS_EMPOWER) ?
			SEQ_MANIFEST_KEY_EMPOWER_PRIVATE :
			SEQ_MANIFEST_KEY_OEM_PRIVATE;

	if(!manifest) {
		return SEQ_ERROR_ITEM_NOT_FOUND;
	}

	skey =  seq_find_param(manifest,SEQ_MANIFEST_SECTION_PRIVATE, keyname);
	if(!skey) {
		return SEQ_ERROR_ITEM_NOT_FOUND;
	}

	*buffer = seq_value_binary(skey);
	*size = skey->size;
	return SEQ_SUCCESS;
}

static int load_root_cert(uint8_t **buffer, size_t *size)
{
	SeqManifest* manifest=0;
	SeqParamKey *skey=0;
	manifest=seq_get_manifest(SEQ_MANIFEST_CERTS);
	const char* certname = ((s_create_flags & SEQ_CERT_CREATE_FLAGS_EMPOWER) == SEQ_CERT_CREATE_FLAGS_EMPOWER) ?
			SEQ_MANIFEST_CERT_EMPOWER_ROOT :
			SEQ_MANIFEST_CERT_OEM_ROOT;

	if(!manifest) {
		return SEQ_ERROR_ITEM_NOT_FOUND;
	}

	skey =  seq_find_param(manifest, SEQ_MANIFEST_SECTION_PUBLIC, certname);
	if(!skey) {
		return SEQ_ERROR_ITEM_NOT_FOUND;
	}

	*buffer = seq_value_binary(skey);
	*size = skey->size;
	return 0;
}

static int seq_ecc_sign(uint8_t *key, uint8_t *buff, size_t shalength, uint8_t *ecsig, size_t *ecsiglength)
{
	int res=0;
	if(!ecsig || *ecsiglength<64) {
		*ecsiglength=64;
		return 0;
	}

	res = uECC_sign(key, buff, shalength, ecsig, uECC_secp256r1());
	return (res==0);
}

static void free_ecc_key( SeqEccKey *key )
{
	if(!key) {
		return;
	}

	SEQ_ASN1_FREE(key->pub_key);
	SEQ_ASN1_FREE(key->pvt_key);
	key->pub_key=0;
	key->pvt_key=0;
}

/*
 * ECPrivateKey ::= SEQUENCE {
     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     privateKey     OCTET STRING,
     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
     publicKey  [1] BIT STRING OPTIONAL
   }
 */
static int load_root_key( void ) {
	SeqDerNode *top=NULL, *pvt=NULL, *pub=NULL, *oidnode=NULL, *option;
	uint32_t temp[2];
	//int i;
	uint8_t *derbuffer=NULL;
	size_t dersize=0;
	int res=0;

	memset(&s_root_key, 0, sizeof(SeqEccKey));

	res = get_root_key(&derbuffer, &dersize);
	if(res!=0 || !derbuffer) {
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
	s_root_key.length = pvt->length;
	s_root_key.pvt_key = (uint8_t*)SEQ_ASN1_MALLOC(pvt->length);
	if(!s_root_key.pvt_key){
		res = SEQ_ERROR_MEMORY;
		SEQ_ERRMSG(res);
		goto done;
	}
	memcpy(s_root_key.pvt_key, pvt->content, pvt->length);

	option = seq_asn1_get_child(top, 2);
	if(option->cls == SEQ_ASN1_CLS_CONTEXT && option->tag==SEQ_ASN1_CONTEXT_EXPLICIT(0)) {
		seq_asn1_parse_der(&oidnode, option->content, option->length);
		//TODO - Make sure the curve matches the key lengths!
		seq_asn1_free_tree(oidnode, SEQ_AP_FREENODEONLY);
		option = seq_asn1_get_child(top, 3);
	}

	if(option->cls == SEQ_ASN1_CLS_CONTEXT && option->tag == SEQ_ASN1_CONTEXT_EXPLICIT(1)) {
		seq_asn1_parse_der(&pub, option->content, option->length);
		//outputData(pub->content, pub->length);
		s_root_key.pub_key = (uint8_t*)SEQ_ASN1_MALLOC(pub->length - 2);
		if(s_root_key.pub_key){
			memcpy(s_root_key.pub_key, pub->content+2, pub->length-2); /*ignore 0x00 0x04 to start*/
		} else {
			res = SEQ_ERROR_MEMORY;
			SEQ_ERRMSG(res);
			goto done;
		}
		seq_asn1_free_tree(pub, SEQ_AP_FREENODEONLY);
	}

done:
	seq_asn1_free_tree(top, SEQ_AP_FREENODEONLY);
	memset(temp,0,2);

	if(derbuffer) {
		SEQ_ASN1_FREE(derbuffer);
	}
	return res;
}

int get_ecdsa_signature(uint8_t *shabuffer, size_t shalength, uint8_t **sigbuffer, size_t *siglength, uint8_t csr) {
	int res=0;
	SeqDerNode *seq = NULL;
	SeqDerNode *keyx = NULL;
	SeqDerNode *keyy = NULL;
	uint8_t *signkey = s_device_key.pvt_key;
	SeqEccKey *key = &s_device_key;

	if(!csr) {
		signkey = s_root_key.pvt_key;
		key = &s_root_key;
	}

	uint8_t *ecsig = SEQ_ASN1_CALLOC(2 * key->length, sizeof(uint8_t));
	if(!ecsig){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return SEQ_ERROR_MEMORY;
	}

	size_t ecsiglength=2*key->length;

	if((res = seq_ecc_sign(signkey, shabuffer, shalength, ecsig, &ecsiglength)) != 0) {
		res = SEQ_ERROR_CRYPTO;
		SEQ_ERRMSG(res);
		SEQ_ASN1_FREE(ecsig);
		return res;
	}

	seq = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	keyx = seq_asn1_new_node(SEQ_ASN1_INTEGER);
	keyy = seq_asn1_new_node(SEQ_ASN1_INTEGER);

	if(!seq || !keyx || !keyy ){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		res = SEQ_ERROR_MEMORY;
		goto done;
	}

	//Memory is alloc'd in these calls
	seq_asn1_set_big_int(keyx, ecsig, key->length);
	seq_asn1_set_big_int(keyy, ecsig+key->length, key->length);

	seq_asn1_add_child(seq, keyx);
	seq_asn1_add_child(seq, keyy);

	//Allocate proper size for DER encoded signature
	*siglength = seq_asn1_get_size(seq);
	*sigbuffer = (uint8_t*)SEQ_ASN1_MALLOC(*siglength);
	if(*sigbuffer){
		memset(*sigbuffer, 0, *siglength);
		seq_asn1_encode(*sigbuffer, seq);
		res = SEQ_SUCCESS;
	} else {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		res = SEQ_ERROR_MEMORY;
		goto done;
	}

	//Free the content buffers allocated with CALLOC
done:
	if(seq) {
		seq_asn1_free_tree(seq, SEQ_AP_FREECONTENT);
	}

	if(ecsig) {
		SEQ_ASN1_FREE(ecsig);
	}
	return res;
}

//All public keys need a '04'
static void get_ecc_public_key_bytes( SeqEccKey *eckey, uint8_t **bytes, size_t *length )
{
	uint8_t *p=NULL;
	*length = eckey->length*2 + 1; /*0x04*/

	p = SEQ_ASN1_CALLOC(1, *length);
	if(!p){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return; //failed to allocate
	}

	p[0] = 0x04; /*All ECC Pubkey bit strings start 00,04*/
	memcpy(p+1, eckey->pub_key, *length-1);

	*bytes = p;
}

static void get_device_key_public_bytes( uint8_t **bytes, size_t *length )
{
	get_ecc_public_key_bytes(&s_device_key, bytes, length);
}

static void get_root_key_public_bytes( uint8_t **bytes, size_t *length )
{
	get_ecc_public_key_bytes(&s_root_key, bytes, length);
}

//This function loads the root certificate file which must be DER encoded.
static SeqDerNode* get_root_cert_subject(void)
{
	SeqDerNode *top = NULL;
	SeqDerNode *cert = NULL;
	SeqDerNode *version = NULL;
	SeqDerNode *subject = NULL;
	SeqDerNode *ret = NULL;
	int res=0;
	int subjectindex=5;
	size_t buffersize=0;
	uint8_t *buffer = NULL;

	// the second word of the header contains the byte size of the file
	res = load_root_cert(&buffer, &buffersize);
	if( res != 0 || !buffer ) {
		return NULL;
	}

	res = seq_asn1_parse_der(&top, buffer, buffersize);;
	if(!top || res != 0){
		res = SEQ_ERROR_PARSE;
		goto done;
	}

	//Get TBS cert
	cert = seq_asn1_get_child(top, 0);
	if(!cert || cert->tag != SEQ_ASN1_SEQUENCE) {
		goto done;
	}

	version = seq_asn1_get_child(cert, 0);
	if(!version || (version->cls != SEQ_ASN1_CLS_CONTEXT)) {
		subjectindex = 4;
	}
	subject = seq_asn1_get_child(cert, subjectindex);

	if(!subject || subject->tag != SEQ_ASN1_SEQUENCE) {
		res = SEQ_ERROR_PARSE;
		subject = NULL;
		goto done;
	}

	//Need to copy the memory so we can release the full buffer
	ret = seq_asn1_copy_node(subject, 0);
	if(!ret) {
		res = SEQ_ERROR_PROGRAMMER;
	}

done:
	if(top) {
		seq_asn1_free_tree(top, SEQ_AP_FREENODEONLY); /*data values are in 'buffer'*/
	}
	if(buffer) {
		SEQ_ASN1_FREE(buffer);
	}
	return ret;
}

/*
 * This defines the structure of an X509 v3 certificate
   https://datatracker.ietf.org/doc/html/rfc5280
   Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }

   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

   CertificateSerialNumber  ::=  INTEGER

   Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }
	   Time ::= CHOICE {
			utcTime        UTCTime,
			generalTime    GeneralizedTime }

   UniqueIdentifier  ::=  BIT STRING

   SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }

   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

   Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING
                    -- contains the DER encoding of an ASN.1 value
                    -- corresponding to the extension type identified
                    -- by extnID
        }

	AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }

   Name ::= CHOICE { -- only one possibility for now --
     rdnSequence  RDNSequence }

   RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

   RelativeDistinguishedName ::=
     SET SIZE (1..MAX) OF AttributeTypeAndValue

   AttributeTypeAndValue ::= SEQUENCE {
     type     AttributeType,
     value    AttributeValue }

   AttributeType ::= OBJECT IDENTIFIER

   AttributeValue ::= ANY -- DEFINED BY AttributeType

   DirectoryString ::= CHOICE {
         teletexString           TeletexString (SIZE (1..MAX)),
         printableString         PrintableString (SIZE (1..MAX)),
         universalString         UniversalString (SIZE (1..MAX)),
         utf8String              UTF8String (SIZE (1..MAX)),
         bmpString               BMPString (SIZE (1..MAX)) }
      * country,
      * state or province name,
      * locality
      * organization,
      * organizational unit,
      * distinguished name qualifier,
      * common name (e.g., "Susan Housley"), and
      * ALL PRINTABLE STRING
    - id-at OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 }
    - id-at-countryName       AttributeType ::= { id-at 6 } SIZE(2)
    - id-at-stateOrProvinceName AttributeType ::= { id-at 8 }
    - id-at-localityName      AttributeType ::= { id-at 7 }
    - id-at-organizationName  AttributeType ::= { id-at 10 }
    - id-at-organizationalUnitName AttributeType ::= { id-at 11 }
    - id-at-commonName        AttributeType ::= { id-at 3 }
    - id-at-serialNumber      AttributeType ::= { id-at 5 } (???)


   Conforming CAs MUST support key identifiers (Sections 4.2.1.1 and
   4.2.1.2), basic constraints (Section 4.2.1.9), key usage (Section
   4.2.1.3), and certificate policies (Section 4.2.1.4) extensions.
    - id-ce   OBJECT IDENTIFIER ::=  { joint-iso-ccitt(2) ds(5) 29 }
    - id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
    	 AuthorityKeyIdentifier ::= SEQUENCE {
			  keyIdentifier             [0] KeyIdentifier           OPTIONAL,
			  authorityCertIssuer       [1] GeneralNames            OPTIONAL,
			  authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }

	     KeyIdentifier ::= OCTET STRING
	     The keyIdentifier is composed of the 160-bit SHA-1 hash of the
           value of the BIT STRING subjectPublicKey (excluding the tag,
           length, and number of unused bits).
	- id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 }
   	   SubjectKeyIdentifier ::= KeyIdentifier
   	- id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
      KeyUsage ::= BIT STRING {
           digitalSignature        (0),
           nonRepudiation          (1), -- recent editions of X.509 have
                                -- renamed this bit to contentCommitment
           keyEncipherment         (2),
           dataEncipherment        (3),
           keyAgreement            (4),
           keyCertSign             (5),
           cRLSign                 (6),
           encipherOnly            (7),
           decipherOnly            (8) }

	- id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
	   BasicConstraints ::= SEQUENCE {
			cA                      BOOLEAN DEFAULT FALSE,
			pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 */
/************UTILITY_FUNCTIONS***************/


/*
void debug_node(SeqDerNode *root, const char *msg)
{
	uint8_t *buffer;
	size_t length;

	length = seq_asn1_get_size(root);
	buffer = SEQ_ASN1_MALLOC(length);
	length = seq_asn1_encode(buffer, root);

	printf("%s\n", msg);
	seq_output_data(buffer, length);
	SEQ_ASN1_FREE(buffer);
}
*/

/*************Object Identifier Values*************************/
static const SeqEncodedOID OptionOIDs[]={
		{{0x55,0x04,0x06},3}, //Country
		{{0x55,0x04,0x08},3}, //State
		{{0x55,0x04,0x07},3}, //locality
		{{0x55,0x04,0x0A},3}, //Organization
		{{0x55,0x04,0x0B},3}, //Organization Unit
		{{0x55,0x04,0x03},3}  //Common Name
};

//Signature Algorithm OID
static const SeqEncodedOID ecdsaSha256_oid = {
	{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02},
	8
};

//Public Key OID
static const SeqEncodedOID ecPubKey_oid = {
	{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01},
	7
};

//ECC Curve IDs
static const SeqEncodedOID ecCurvePrime256_oid = {
	{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07},
	8
};

//Subject Key ID OID
static const SeqEncodedOID subKeyId_oid = {
	{0x55,0x1D,0x0E},
	3
};

//Authority Key ID OID
static const SeqEncodedOID authKeyId_oid = {
	{0x55,0x1D,0x23},
	3
};

//Basic Constraints
static const SeqEncodedOID basicConstraints_oid = {
	{0x55,0x1D,0x13},
	3
};

#ifdef USE_KEY_USAGE
//Key Usage
static const SeqEncodedOID keyUsage_oid = {
	{0x55,0x1D,0x0F},
	3
};
#endif

#define AUTH_KEY_ID_TYPE 0
#define SUBJ_KEY_ID_TYPE 1

static void copy_oid( SeqDerNode *node, const SeqEncodedOID *oid ){
	node->content = SEQ_ASN1_MALLOC(oid->length);
	if(node->content) {
		memcpy(node->content, oid->oid, oid->length);
		node->length = oid->length;
	}
}

/*******************NAME Options**********************/
#define OPTION_LENGTH 8
static const char* OptionName[]={
	"country",
	"state",
	"locality",
	"organization",
	"org_unit",
	"common_name",
	"start_date",
	"end_date"
};


static SeqCertOptions *s_coptions = NULL;

static void free_cert_options( SeqCertOptions *options ){
	SeqCertOptions *tmp=options;
	while(options){
		tmp = options;
		options = options->next;
		SEQ_ASN1_FREE(tmp->name);
		SEQ_ASN1_FREE(tmp->value);
		SEQ_ASN1_FREE(tmp);
	}
}

/*
 * Strip '\"'
 */
static void copy_option( SeqCertOptions *option, const char *name, const char *value )
{
	if(!option || !name || !value) {
		return;
	}

	int nlen = strlen(name);
	int vlen = strlen(value);
	char *v = (char*)value;

	option->name = SEQ_ASN1_MALLOC(nlen+1);
	if(!option->name){
		return; //Failed to allocate
	}
	memcpy(option->name, name, nlen+1);

	if(v[0] == '\"') {
		v++;
		vlen--;
	}
	if(v[vlen-1] == '\"') {
		vlen--;
	}
	option->value = SEQ_ASN1_MALLOC(vlen+1);
	if(option->value) {
		memset(option->value, 0, vlen+1);
		memcpy(option->value, v, vlen);
	}
}

void load_option_from_manifest( SeqManifest *manifest, SeqCertOptions *option, const char *name )
{
	const char *section_name = ((s_create_flags&SEQ_CERT_CREATE_FLAGS_EMPOWER)==SEQ_CERT_CREATE_FLAGS_EMPOWER) ?
			SEQ_MANIFEST_SECTION_EMPOWER : SEQ_MANIFEST_SECTION_OEM;

	char *value = seq_get_keyval_string(manifest, section_name, name);
	if(!value) {
		printf("Failed to retrieve %s - %s from SLIP\n", section_name, name);
		return;
	}

	copy_option( option, name, value );

	free(value);
}

static void load_cert_options(void)
{
	int i=0;
	SeqManifest *manifest = seq_get_manifest(SEQ_MANIFEST_CERTS);

	if(s_coptions) {
		free_cert_options(s_coptions);
		s_coptions = NULL;
	}
	s_coptions = (SeqCertOptions*)SEQ_ASN1_MALLOC(sizeof(SeqCertOptions));
	SeqCertOptions *option = s_coptions;

	if(!option) {
		return; //Failed to allocate
	}
	memset(option, 0, sizeof(SeqCertOptions));

	for(i=0; i < OPTION_LENGTH; i++) {
		load_option_from_manifest(manifest, option, OptionName[i]);

		if(i < (OPTION_LENGTH)){
			option->next = (SeqCertOptions*)SEQ_ASN1_MALLOC(sizeof(SeqCertOptions));
			if(option->next) {
				memset(option->next, 0, sizeof(SeqCertOptions));
				option = option->next;
			} else {
				//Failed to allocate.
				printf("ERROR - Failed to allocate option!\n");
				return;
			}
		} else {
			option->next = NULL;
		}
	}
}

static char *get_option_value(SeqCertOptions *list, SeqOptionType ot)
{
	SeqCertOptions *curr=list;
	while(curr) {
		if(!strcmp(curr->name, OptionName[ot])) {
			return curr->value;
			break;
		}
		curr = curr->next;
	}

	return (char*)NULL;
}

static SeqDerNode *get_option(SeqCertOptions *list, SeqOptionType ot )
{
	SeqDerNode *option = NULL, *sequence=NULL, *oidnode=NULL, *valuenode=NULL;
	char *value=NULL;
	int len=0;
	const SeqEncodedOID *eoid=NULL;

	if(ot > OT_COMMON_NAME) {
		return NULL; /*There won't be a valid OptionID for SeqOptionType*/
	}

	value = get_option_value(list, ot);
	if(!value) {
		return NULL;
	}

	eoid = &(OptionOIDs[ot]);
	if(!eoid) {
		return NULL;
	}

	len = strlen(value);

/*
 * Each option is...
   Name ::= CHOICE { -- only one possibility for now --
     rdnSequence  RDNSequence }

   RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

   RelativeDistinguishedName ::=
     SET SIZE (1..MAX) OF AttributeTypeAndValue

   AttributeTypeAndValue ::= SEQUENCE {
     type     AttributeType,
     value    AttributeValue }

   AttributeType ::= OBJECT IDENTIFIER

   AttributeValue ::= ANY -- DEFINED BY AttributeType
 */
	option = seq_asn1_new_node(SEQ_ASN1_SET);
	sequence = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);

	//Set Object Identifier
	oidnode = seq_asn1_new_node(SEQ_ASN1_OBJECTID);

	//Value
	valuenode = seq_asn1_new_node(SEQ_ASN1_PRINTABLESTRING);

	if(!option || !sequence || !oidnode || !valuenode) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	//Set value
	valuenode->content = SEQ_ASN1_MALLOC(len);
	if(valuenode->content) {
		memcpy(valuenode->content, value, len);
		valuenode->length = len;
	}

	copy_oid(oidnode, eoid);

	seq_asn1_add_child(option, sequence);
	seq_asn1_add_child(sequence, oidnode);
	seq_asn1_add_child(sequence, valuenode);
	return option;
}

static SeqDerNode *get_subject(void)
{
	SeqDerNode *subject = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	if(!subject) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	SeqDerNode *country = get_option(s_coptions, OT_COUNTRY);
    SeqDerNode *state = get_option(s_coptions, OT_STATE);
    SeqDerNode *locality = get_option(s_coptions, OT_LOCALITY);
	SeqDerNode *organization = get_option(s_coptions, OT_ORGANIZATION);
    SeqDerNode *org_unit = get_option(s_coptions, OT_ORG_UNIT);
    SeqDerNode *common_name = get_option(s_coptions, OT_COMMON_NAME);

    seq_asn1_add_sibling(country, state);
    seq_asn1_add_sibling(country, locality);
    seq_asn1_add_sibling(country, organization);
    seq_asn1_add_sibling(country, org_unit);
    seq_asn1_add_sibling(country, common_name);
    seq_asn1_add_child(subject, country);

    return subject;
}

/*Issuer must match subject of signing certificate.*/
static SeqDerNode *get_issuer(void)
{
	return get_root_cert_subject();
}

static SeqDerNode *get_version(uint8_t csr)
{
	uint8_t num = csr ? 0 : 2;
	SeqDerNode *node = NULL;
	SeqDerNode *version = seq_asn1_new_node(SEQ_ASN1_INTEGER);
	if(!version){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	version->content = SEQ_ASN1_MALLOC(sizeof(uint8_t));
	version->length = sizeof(uint8_t);
	if(!version->content){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	memcpy(version->content, &num, sizeof(uint8_t));

	if(csr){
		return version;
	} else {
		node = seq_asn1_new_node(SEQ_ASN1_CONTEXT_EXPLICIT(0));
		if(!node) {
			SEQ_ERRMSG(SEQ_ERROR_MEMORY);
			return NULL;
		}
		node->composition=SEQ_ASN1_CTYPE_CONSTRUCTED;
		node->cls = SEQ_ASN1_CLS_CONTEXT;
		seq_asn1_add_child(node, version);
		return node;
	}
}


/*
 * Read unique ID from fuses.
 *
 0x410[31:0]   UNIQUE_ID[31:0])
 0x420[31:0]   UNIQUE_ID[63:32])
 */
#define ID_BASE 0x30350000
#define ID1_OFFSET 0x410
#define ID2_OFFSET 0x420
static SeqDerNode *get_serial_number(void)
{
	uint32_t chipid[2];
	uint8_t *serial;
	SeqDerNode *node = seq_asn1_new_node(SEQ_ASN1_INTEGER);
	if(!node) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	//Set glitch address
	out_le32(SNVS_BASE_ADDR + SNVS_GLITCH, 0x41736166);
	chipid[0] = in_le32(ID_BASE+ID1_OFFSET);
	chipid[1] = in_le32(ID_BASE+ID2_OFFSET);

	//printf("Unique ID: 0x%08x  0x%08x\n", chipid[0], chipid[1]);

	serial = SEQ_ASN1_CALLOC(SEQ_SHA1LEN_BYTES, sizeof(uint8_t));
	if(!serial) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	seq_run_sha(serial, SEQ_SHA1LEN_BYTES, (uint8_t*)(&chipid), sizeof(uint32_t)*2, SEQ_SHA_1);
	serial[0] = serial[0]&0x7F;

	node->content = serial; /*pass memory handling to node*/
	node->length = SEQ_SHA1LEN_BYTES;

	return node;
}

static SeqDerNode *get_algorithm_id(void)
{
	SeqDerNode *seq=seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	SeqDerNode *oid=seq_asn1_new_node(SEQ_ASN1_OBJECTID);

	if(!seq || !oid){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	copy_oid(oid, &ecdsaSha256_oid);

	seq_asn1_add_child(seq, oid);
	return seq;
}

static SeqDerNode *get_validity(void)
{
	SeqDerNode *seq = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	SeqDerNode *start = seq_asn1_new_node(SEQ_ASN1_UTCTIME);
	SeqDerNode *end = seq_asn1_new_node(SEQ_ASN1_UTCTIME);
	char *value = NULL;
	int len=0;
	int offset=0;

	if(!seq || !start || !end){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	value = get_option_value( s_coptions, OT_START_DATE );
	if(value){
		len = strlen(value);
		if(value[0]=='\"') {
			len-=2;
			offset=1;
		}
		start->content = SEQ_ASN1_MALLOC(len);
		if(start->content) {
			memcpy(start->content, value+offset, len);
			start->length = len;
		}
	} else {
		printf("[ERROR] - Invalid start date.\n");
	}

	offset=0;
	value = get_option_value( s_coptions, OT_END_DATE );
	if(value){
		len = strlen(value);
		if(value[0]=='\"') {
			len-=2;
			offset=1;
		}
		end->content = SEQ_ASN1_MALLOC(len);
		if(end->content){
			memcpy(end->content, value+offset, len);
			end->length = len;
		}
	} else {
		printf("[ERROR] - Invalid end date.\n");
	}

	seq_asn1_add_child(seq, start);
	seq_asn1_add_child(seq, end);

	return seq;
}

/*
 * From openssl generated ECC
 30 59
  30 13
   06 07 2A 86 48 CE 3D 02 01
   06 08 2A 86 48 CE 3D 03 01 07
   03 42 00 04 22 71 F1 AC 06 4E 4A CA 13 6B B1 4A D2 DE F3 D2 53 2B 5A 5D
   29 C0 F5 96 23 A7 4C 9E 8A E7 8B 17 9A 13 FF AE DD F5 B7 37 AA 0C 9C 4F
   F7 0B 3A 16 7E 09 D7 AA E7 45 0E 90 A0 30 9A 2D 2B 67 51 B3
 */
/*
 * From this
 30 59
  30 13
    06 07 2A 86 48 CE 3D 02 01
    06 08 2A 86 48 CE 3D 03 01 07
  03 42 00 04
     764D379CCE74BD3D08E94ACCD592A3307F4F5C7585D806CF27862F3BDCD310FE
     C227E1C46DA19DA8E5F264C81EE2206965EBF8BDB2E97A93BF37FC59D2F215F8
 */
static SeqDerNode *get_public_key(void)
{
	SeqDerNode *seq = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	SeqDerNode *ecc_root = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	SeqDerNode *ecc_pkid = seq_asn1_new_node(SEQ_ASN1_OBJECTID);
	SeqDerNode *ecc_pkcv = seq_asn1_new_node(SEQ_ASN1_OBJECTID);
	SeqDerNode *ecc_pk = seq_asn1_new_node(SEQ_ASN1_BITSTRING);
	uint8_t *pk_bytes = NULL;
	size_t pk_length=0;

	get_device_key_public_bytes(&pk_bytes, &pk_length);

	if(!seq || !ecc_root || !ecc_pkid || !ecc_pkcv || !ecc_pk || !pk_bytes){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	copy_oid(ecc_pkid, &ecPubKey_oid);
	copy_oid(ecc_pkcv, &ecCurvePrime256_oid);

	ecc_pk->content = SEQ_ASN1_MALLOC(pk_length+1); /*Need to add 00*/
	if(ecc_pk->content) {
		((uint8_t*)(ecc_pk->content))[0] = 0x00;
		memcpy(ecc_pk->content +1, pk_bytes, pk_length);
		ecc_pk->length = pk_length+1;
	}

	SEQ_ASN1_FREE(pk_bytes); /*Now copied to new memory in ecc_pk->content*/

	seq_asn1_add_child(seq, ecc_root);
	seq_asn1_add_child(ecc_root, ecc_pkid);
	seq_asn1_add_child(ecc_root, ecc_pkcv);
	seq_asn1_add_child(seq, ecc_pk);

	return seq;
}

//So goofy...
/*
 * Subject is an OctetString with an internal OctetString. Need to encode it here
 */
static SeqDerNode *get_subj_key_id_value_node(void)
{
	uint8_t *shabuffer=NULL;
	uint8_t *derbuffer=NULL;
	size_t derlength=0;
	uint8_t *pk_bytes=NULL;
	size_t pk_length=0;
	SeqDerNode *node=NULL;
	SeqDerNode *internal=NULL;

	shabuffer = SEQ_ASN1_CALLOC(SEQ_SHA1LEN_BYTES, sizeof(uint8_t));
	if(!shabuffer) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	node = seq_asn1_new_node(SEQ_ASN1_OCTETSTRING);
	internal = seq_asn1_new_node(SEQ_ASN1_OCTETSTRING);

	if(!node || !internal) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		goto error;
	}

	get_device_key_public_bytes(&pk_bytes, &pk_length);
	if(!pk_bytes || pk_length == 0){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		goto error;
	}

	seq_run_sha(shabuffer, SEQ_SHA1LEN_BYTES, pk_bytes, pk_length, SEQ_SHA_1);

	internal->content=shabuffer;
	internal->length = SEQ_SHA1LEN_BYTES;

	//Now encode and store
	derlength = seq_asn1_get_size(internal);
	derbuffer = SEQ_ASN1_MALLOC(derlength);
	if(!derbuffer) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		goto error;
	}

	derlength = seq_asn1_encode(derbuffer, internal);
	if(derlength == 0){
		printf("Failed encode\n");
		goto error;
	}

	node->content=derbuffer;
	node->length =derlength;

	//It's no longer in the tree. This frees the 'shabuffer'.
	seq_asn1_free_tree(internal, SEQ_AP_FREECONTENT);
	if(pk_bytes){
		SEQ_ASN1_FREE(pk_bytes);
	}

	return node;

error:
	if(pk_bytes) {
		SEQ_ASN1_FREE(pk_bytes);
	}
	if(shabuffer) {
		SEQ_ASN1_FREE(shabuffer);
	}
	seq_asn1_free_tree(internal, SEQ_AP_FREENODEONLY);
	seq_asn1_free_tree(node, SEQ_AP_FREENODEONLY);
	if(derbuffer) {
		SEQ_ASN1_FREE(derbuffer);
	}
	return NULL;
}

/*
 * Authority Key is an OctetString with internal Sequence that contains Optional values...
 */
static SeqDerNode *get_auth_key_id_value_node(void)
{
	uint8_t *shabuffer=NULL;
	uint8_t *derbuffer=NULL;
	size_t derlength=0;
	uint8_t *pk_bytes=NULL;
	size_t pk_length=0;

	get_root_key_public_bytes(&pk_bytes, &pk_length);

	if(!pk_bytes || pk_length==0) {
		printf("Failed to load root key public bytes\n");
		return NULL;
	}

	shabuffer=SEQ_ASN1_CALLOC(SEQ_SHA1LEN_BYTES, sizeof(uint8_t));
	if(!shabuffer) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}
	seq_run_sha(shabuffer, SEQ_SHA1LEN_BYTES, pk_bytes, pk_length, SEQ_SHA_1);

	SeqDerNode *node = seq_asn1_new_node(SEQ_ASN1_OCTETSTRING);
	SeqDerNode *seq = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	SeqDerNode *opt = seq_asn1_new_node(SEQ_ASN1_CONTEXT_EXPLICIT(0));
	if(!node || !seq || !opt) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}
	opt->composition=SEQ_ASN1_CTYPE_PRIMITIVE;
	opt->cls = SEQ_ASN1_CLS_CONTEXT;

	opt->content=shabuffer;
	opt->length=SEQ_SHA1LEN_BYTES;

	seq_asn1_add_child(seq, opt);

	//Now encode and store
	derlength = seq_asn1_get_size(seq);
	derbuffer = SEQ_ASN1_MALLOC(derlength);
	if(!derbuffer) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	derlength = seq_asn1_encode(derbuffer, seq);
	if(derlength == 0) {
		printf("Derlength is 0\n");
		return NULL;
	}

	node->content=derbuffer;
	node->length =derlength;

	//It's no longer in the tree
	seq_asn1_free_tree(seq, SEQ_AP_FREENODEONLY);
	if(pk_bytes) {
		SEQ_ASN1_FREE(pk_bytes);
	}
	if(shabuffer) {
		SEQ_ASN1_FREE(shabuffer);
	}
	return node;
}

/*
  The keyIdentifier is composed of the 160-bit SHA-1 hash of the
  value of the BIT STRING subjectPublicKey (excluding the tag,
  length, and number of unused bits).
 */
static SeqDerNode *get_key_identifier( uint8_t extid )
{
	SeqDerNode *seq=NULL, *oidnode=NULL, *valuenode=NULL;
	const SeqEncodedOID *eoid=NULL;

	//HACK
	switch(extid){
	case SUBJ_KEY_ID_TYPE:
		eoid = &(subKeyId_oid);
		valuenode = get_subj_key_id_value_node();
		break;
	case AUTH_KEY_ID_TYPE:
		valuenode = get_auth_key_id_value_node();
		eoid = &(authKeyId_oid);
		break;
	}

	oidnode = seq_asn1_new_node(SEQ_ASN1_OBJECTID);
	if(!oidnode) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}
	copy_oid(oidnode, eoid);

	seq = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	if(!seq) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	seq_asn1_add_child(seq, oidnode);
	seq_asn1_add_child(seq, valuenode);
	return seq;
}

#ifdef USE_KEY_USAGE
/*30  0B 06 03 55 1D 0F 04 04
03 02 05 A0 */
static SeqDerNode* get_key_usage(void)
{
	SeqDerNode *usage= seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	SeqDerNode *oid  = seq_asn1_new_node(SEQ_ASN1_OBJECTID);
	SeqDerNode *node = seq_asn1_new_node(SEQ_ASN1_OCTETSTRING);
	SeqDerNode *bits = seq_asn1_new_node(SEQ_ASN1_BITSTRING);
	uint8_t *derbuffer=NULL;
	size_t derlength=0;

	if(!usage || !oid || !node || !bits){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	copy_oid(oid, &keyUsage_oid);
	bits->content = SEQ_ASN1_MALLOC(2);
	bits->length = 2;
	((uint8_t*)(bits->content))[0] = 0x05;
	((uint8_t*)(bits->content))[1] = 0xA0;

	//Now encode and store
	derlength = seq_asn1_get_size(bits);
	derbuffer = SEQ_ASN1_MALLOC(derlength);
	if(!derbuffer) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	derlength = seq_asn1_encode(derbuffer, bits);
	if(derlength == 0) {
		SEQ_ERRMSG(SEQ_ERROR_PROGRAMMER);
		return NULL;
	}

	node->content=derbuffer;
	node->length =derlength;

	seq_asn1_add_child(usage, oid);
	seq_asn1_add_child(usage, node);

	//It's no longer in the tree
	seq_asn1_free_tree(bits, SEQ_AP_FREENODEONLY);

	return usage;
}
#endif

/*30 0C 06 03
55 1D 13 01 01 FF 04 02  30 00*/
static SeqDerNode* get_basic_constraints(void)
{
	SeqDerNode *basic = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	SeqDerNode *oid = seq_asn1_new_node(SEQ_ASN1_OBJECTID);
	SeqDerNode *node = seq_asn1_new_node(SEQ_ASN1_OCTETSTRING);
	SeqDerNode *seq  = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	SeqDerNode *boolean = seq_asn1_new_node(SEQ_ASN1_BOOLEAN);
	uint8_t *derbuffer=NULL;
	size_t derlength=0;

	if(!basic || !oid || !node || !seq || !boolean){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	copy_oid(oid, &basicConstraints_oid);

	boolean->content=SEQ_ASN1_MALLOC(1);
	if(!boolean->content){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}
	boolean->length=1;
	((uint8_t*)(boolean->content))[0] = 0x00;
	seq_asn1_add_child(seq, boolean);


	//Now encode and store
	derlength = seq_asn1_get_size(seq);
	//printf("Size of seq: %d\n", derlength);
	derbuffer = SEQ_ASN1_MALLOC(derlength);
	if(!derbuffer) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	derlength = seq_asn1_encode(derbuffer, seq);
	if(derlength == 0) {
		SEQ_ERRMSG(SEQ_ERROR_PROGRAMMER);
		return NULL;
	}

	node->content=derbuffer;
	node->length =derlength;

	seq_asn1_add_child(basic, oid);
	seq_asn1_add_child(basic, node);

	//It's no longer in the tree
	free(boolean->content);
	seq_asn1_free_tree(seq, SEQ_AP_FREENODEONLY);
	return basic;
}

static SeqDerNode *get_extensions(void)
{
	SeqDerNode *option = seq_asn1_new_node(SEQ_ASN1_CONTEXT_EXPLICIT(3));
	option->composition=SEQ_ASN1_CTYPE_CONSTRUCTED;
	option->cls = SEQ_ASN1_CLS_CONTEXT;

	SeqDerNode *seq = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	if(!seq){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	seq_asn1_add_child(seq, get_key_identifier(SUBJ_KEY_ID_TYPE));
	seq_asn1_add_child(seq, get_key_identifier(AUTH_KEY_ID_TYPE));
	seq_asn1_add_child(seq, get_basic_constraints());

#ifdef USE_KEY_USAGE
	seq_asn1_add_child(seq, getKeyUsage());
#endif
	seq_asn1_add_child(option, seq);
	return option;
}

/*
 TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }
 */
static SeqDerNode *get_tbs_cert_node(void )
{
	SeqDerNode *tbsparent;

	tbsparent = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	if(!tbsparent){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	load_cert_options();

	//Add Version
	seq_asn1_add_child(tbsparent, get_version(0));
	//Add Serial Number
	seq_asn1_add_child(tbsparent, get_serial_number());
	//Add signature algorithm ID
	seq_asn1_add_child(tbsparent, get_algorithm_id());
	//Add Issuer
	seq_asn1_add_child(tbsparent, get_issuer());
	seq_asn1_add_child(tbsparent, get_validity());
	seq_asn1_add_child(tbsparent, get_subject());
	seq_asn1_add_child(tbsparent, get_public_key());
	seq_asn1_add_child(tbsparent, get_extensions());

	free_cert_options(s_coptions);
	s_coptions = NULL;

	return tbsparent;
}

static SeqDerNode *get_tbs_csr_node(void ){
	SeqDerNode *tbsparent;

	tbsparent = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	if(!tbsparent) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	load_cert_options();

	//Add Version
	seq_asn1_add_child(tbsparent, get_version(1));
	seq_asn1_add_child(tbsparent, get_subject());
	seq_asn1_add_child(tbsparent, get_public_key());

	//Freeing options
	free_cert_options(s_coptions);
	s_coptions = NULL;

	return tbsparent;
}

/*
 AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
static SeqDerNode * get_ecdsa_sig_alg_node(void){
	SeqDerNode *seq = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);
	SeqDerNode *oid = seq_asn1_new_node(SEQ_ASN1_OBJECTID);
	if(!seq || !oid) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}

	copy_oid(oid, &ecdsaSha256_oid);
	seq_asn1_add_child(seq, oid);
	return seq;
}

SeqDerNode * get_sig_node(uint8_t *sigbuffer, size_t siglength){
	//For ECDSA the signature is DER encoded but a byte of 0x00 must precede it.
	SeqDerNode *node = seq_asn1_new_node(SEQ_ASN1_BITSTRING);
	if(!node){
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return NULL;
	}
	node->content = SEQ_ASN1_MALLOC(siglength+1);
	if(node->content) {
		node->length = siglength+1;
		memset(node->content, 0, node->length);
		memcpy(node->content+1, sigbuffer, siglength);
	}
	return node;
}


#define CSR_CERT    0x81000000

int seq_create_full_der_certificate(void *private_key, void *public_key, int length, uint32_t createflags ){
	int res = -1;
	uint8_t *derbuffer = NULL;
	size_t derlength = 0;
	uint8_t *sigbuffer = NULL;
	size_t siglength =0;
	uint8_t *shabuffer=NULL;
	uint32_t csr = ((createflags & SEQ_CERT_CREATE_FLAG_CSR) == SEQ_CERT_CREATE_FLAG_CSR);
	char *keyname = NULL;

	if((createflags & SEQ_CERT_CREATE_FLAGS_EMPOWER) == SEQ_CERT_CREATE_FLAGS_EMPOWER) {
		//Empower
		keyname = csr ? SEQ_MANIFEST_CSR_EMPOWER_DEVICE : SEQ_MANIFEST_CERT_EMPOWER_DEVICE;
	} else {
		keyname = csr ? SEQ_MANIFEST_CSR_OEM_DEVICE : SEQ_MANIFEST_CERT_OEM_DEVICE;
	}


	s_create_flags = createflags;

	/*The top level of an x509 cert*/
    /*Certificate  ::=  SEQUENCE  {
		tbsCertificate       TBSCertificate,
		signatureAlgorithm   AlgorithmIdentifier,
		signatureValue       BIT STRING  }*/
	SeqDerNode *parent=NULL;
	SeqDerNode *tbscert = NULL;

	if(length<=0) {
		return SEQ_ERROR_BAD_PARAMS;
	}

	//Root of entire certificate
	parent = seq_asn1_new_node(SEQ_ASN1_SEQUENCE);

	//Step 0) Get root values.
	if(!csr && load_root_key( )) {
		//Failed to load root key. Cert cannot be created or signed.
		return SEQ_ERROR_PROGRAMMER;
	}

	//Step 1) Populate ECDSA 256 Full Key
	s_device_key.length = length;
	s_device_key.pvt_key = private_key;
	s_device_key.pub_key = public_key;

	//Step 2) Get the TBS Certificate
	if(csr) {
		tbscert = get_tbs_csr_node();
	} else {
		tbscert = get_tbs_cert_node();
	}

	//Step 3) Create a DER encoding of just the TBS Certificate
	//This will include the public key bits from the key generated above
	//printf("Got TBS\n");
	derlength = seq_asn1_get_size(tbscert);
	derbuffer = SEQ_ASN1_MALLOC(derlength);

	if(!derbuffer) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		seq_asn1_free_tree(tbscert, SEQ_AP_FREECONTENT);
		return SEQ_ERROR_MEMORY;
	}

	derlength = seq_asn1_encode(derbuffer, tbscert);

	//printf("tbscert derbuffer length: %d\n", derlength);
	//seq_print_bytes(derbuffer, derlength);

	//Step 4) Using the key generated above, sign the SHA256 hash of the
	//fully encoded DER certificate.
	shabuffer = SEQ_ASN1_CALLOC(SEQ_SHA256LEN_BYTES, sizeof(uint8_t));
	if(!shabuffer) {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		seq_asn1_free_tree(tbscert, SEQ_AP_FREECONTENT);
		SEQ_ASN1_FREE(derbuffer);
		return SEQ_ERROR_MEMORY;
	}
	seq_run_sha(shabuffer, SEQ_SHA256LEN_BYTES, derbuffer, derlength, SEQ_SHA_256);



	//printf("%s: Getting signature of certificate buffer\n", __func__);
	if(get_ecdsa_signature(shabuffer, SEQ_SHA256LEN_BYTES, &sigbuffer, &siglength, csr)) {
		seq_asn1_free_tree(tbscert, SEQ_AP_FREECONTENT);
		SEQ_ASN1_FREE(derbuffer);
		SEQ_ASN1_FREE(shabuffer);
		return SEQ_ERROR_CRYPTO;
	}

	// Print signed cert to output
	//printf("Signature length : %d\n", siglength);
	//outputData(sigbuffer, siglength);

	//Step 5) Add the signature algorithm and signature to create the full certificate
	seq_asn1_add_child(parent, tbscert);
	seq_asn1_add_child(parent, get_ecdsa_sig_alg_node());
	seq_asn1_add_child(parent, get_sig_node(sigbuffer, siglength));

	SEQ_ASN1_FREE(derbuffer);
	derbuffer=NULL;

	derlength = seq_asn1_get_size(parent);
	derbuffer = SEQ_ASN1_MALLOC(derlength);

	if(derbuffer) {
		derlength = seq_asn1_encode(derbuffer, parent);
		//printf("Created: %s\n", keyname);
		//seq_print_bytes(derbuffer, derlength);
		res = seq_save_binary_to_cert_manifest(derbuffer, derlength, SEQ_MANIFEST_SECTION_PUBLIC, keyname);
	} else {
		SEQ_ERRMSG(SEQ_ERROR_MEMORY);
		return SEQ_ERROR_MEMORY;
	}

	//Cleanup
	//printf("    Cleanup...\n");
	memset(&s_device_key,0,sizeof(SeqEccKey));
	if(sigbuffer) {
		SEQ_ASN1_FREE(sigbuffer);
	}
	if(derbuffer) {
		SEQ_ASN1_FREE(derbuffer);
	}
	if(shabuffer) {
		SEQ_ASN1_FREE(shabuffer);
	}
	seq_asn1_free_tree(parent, SEQ_AP_FREECONTENT);

	free_ecc_key(&s_root_key);

	return res;
}
