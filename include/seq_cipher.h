#ifndef _SEQ_CIPHER_H
#define _SEQ_CIPHER_H

#include <common.h>

/*
 *  * Encrypt/Decrypt with cipher in a single step.
 *   */
int seq_enc_aes_ctr(const uint8_t *key, size_t keyLen,
              const uint8_t *in, uint8_t *out, size_t len,
			  const uint8_t *iv);
int seq_dec_aes_ctr(const uint8_t *key, size_t keyLen,
              const uint8_t *in, uint8_t *out, size_t len,
			  const uint8_t *iv);

int seq_enc_aes_ecb(uint8_t *key, size_t keylen,
			  uint8_t *in, uint8_t *out, size_t len);

int seq_dec_aes_ecb(uint8_t *key, size_t keylen,
			  uint8_t *in, uint8_t *out, size_t len);

int seq_enc_aes_cbc(uint8_t *key, size_t keylen,
			  uint8_t *in, uint8_t *out, size_t len, const uint8_t *iv);

int seq_dec_aes_cbc(uint8_t *key, size_t keylen,
			  uint8_t *in, uint8_t *out, size_t len, const uint8_t *iv);

#endif /*_SEQ_CIPHER_H */
