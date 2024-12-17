#ifndef __seq_ecc_utils_h__
#define __seq_ecc_utils_h__

/*
 * Define this type here for pointer usage.
 */
typedef struct dernode SeqDerNode;

#define SEQ_SHA1LEN_BYTES 20
#define SEQ_SHA256LEN_BYTES 32

typedef enum {
	SEQ_SHA_1,
	SEQ_SHA_256
} SeqShaType;

typedef enum {
	SEQ_CERT_TYPE_OEM,
	SEQ_CERT_TYPE_EMPOWER
} SeqCertType;

/*
 * Used by uECC
 * Must return '1' for success, '0' for failure.
 */
typedef int (*uECC_RNG_Function)(unsigned char *dest, unsigned size);

/*
 * Save the binary to 'section'_'keyname'
 */
int seq_save_binary_to_cert_manifest(uint8_t *bin, size_t length, const char *section, const char *keyname);

/*
 *
 */
int seq_create_device_key( SeqCertType empower, uECC_RNG_Function random, uint8_t** privatekey, uint8_t **publickey );

/*
 * Create the device ECC key, certificate and CSR.
 *
 * 'empower' - If SEQ_CERT_TYPE_OEM then build the OEM device components.
 *           - If SEQ_CERT_TYPE_EMPOWER then build the EmPOWER device components.
 */
int seq_create_device_key_and_cert(SeqCertType cert, uECC_RNG_Function random);

/*
 * This gets the signature bytes from a DER encoded EC signature.
 */
uint32_t seq_extract_ec_signature(uint8_t **sigbuffer,size_t *sigbuffersize, SeqDerNode *signode);

/*
 * Gets the public key values from the named certificate.
 */
int seq_get_ecc_public_key(uint8_t *oempk, size_t pksize, const char *certname);

/*
 * hashvalue - where the hash is stored. Must be at least SHA*LEN in size
 * hashlen - length of hashvalue buffer in bytes.
 * data - data buffer to be hashed
 * size - length of data buffer
 */
void seq_run_sha(uint8_t *hashvalue, uint32_t hashlen, void *data, uint32_t size, SeqShaType sha);

int seq_random(unsigned char* out, uint32_t len);

//Set Random for uECC
void seq_set_uecc_rng( void );

#endif /*seq_ecc_utils_h*/
