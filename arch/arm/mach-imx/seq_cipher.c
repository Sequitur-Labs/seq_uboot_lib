#include <common.h>
#include <malloc.h>
#include <memalign.h>
#include <fsl_sec.h>
#include <linux/errno.h>
#include <desc_constr.h>
#include <jobdesc.h>
#include <desc.h>
#include <jr.h>
#include <cpu_func.h>
#include <seq_cipher.h> 

#define OP_ALG_AAI_AES_CTR          (0x00 << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_AES_CBC          (0x10 << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_AES_ECB          (0x20 << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_AES_CFB          (0x30 << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_AES_OFB          (0x40 << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_AES_XTS          (0x50 << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_AES_CMAC         (0x60 << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_AES_XCBC_MAC     (0x70 << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_AES_CCM          (0x80 << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_AES_GCM          (0x90 << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_AES_CBC_XCBC_MAC (0xA0 << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_AES_CTR_XCBC_MAC (0xB0 << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_AES_CBC_CMAC     (0xC0 << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_AES_CTR_CMAC_LTE (0xD0 << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_AES_CTR_CMAC     (0xE0 << OP_ALG_AAI_SHIFT)

static void inline_cnstr_jobdesc_cipher(uint32_t *desc,
             const uint8_t *key, uint32_t key_sz,
             const uint8_t *iv, uint32_t iv_sz,
             const uint8_t *in, uint8_t *out, uint32_t sz,
             u32 alg, int encrypt) {
	/* *alg* should combine OP_ALG_ALGSEL* and OP_ALG_AAI* values.
	 * Sizes should be checked upstream before calling this function. */
	u32 dma_addr_key, dma_addr_in, dma_addr_out, dma_addr_iv;
	u32 options;

	dma_addr_key = virt_to_phys((void *)key);
	dma_addr_in	= virt_to_phys((void *)in);
	dma_addr_out	= virt_to_phys((void *)out);
	if (iv) dma_addr_iv	= virt_to_phys((void *)iv);

	init_job_desc(desc, 0);

	append_key(desc, dma_addr_key, key_sz, KEY_DEST_CLASS_REG | CLASS_1);

	if (iv) {
		options = LDST_SRCDST_BYTE_CONTEXT | CLASS_1;
		if(alg == (OP_ALG_ALGSEL_AES | OP_ALG_AAI_AES_CTR)) {
			options |= (16 << LDST_OFFSET_SHIFT);
		}
		append_load(desc, dma_addr_iv, iv_sz, options);
	}

	options = OP_TYPE_CLASS1_ALG | OP_ALG_AS_INITFINAL | alg;
	options |= (encrypt) ? OP_ALG_ENCRYPT : OP_ALG_DECRYPT;
	append_operation(desc, options);

	if (sz > 0xffff) {
		append_fifo_store(desc, dma_addr_out, 0, FIFOST_TYPE_MESSAGE_DATA | FIFOLDST_EXT);
		append_cmd(desc, sz);
		append_fifo_load(desc, dma_addr_in, 0, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_LAST1 | FIFOLD_TYPE_MSG | FIFOLDST_EXT);
		append_cmd(desc, sz);
	} else {
		append_fifo_store(desc, dma_addr_out, sz, FIFOST_TYPE_MESSAGE_DATA);
		append_fifo_load(desc, dma_addr_in, sz, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_LAST1 | FIFOLD_TYPE_MSG);
	}
}

static int seq_cipher(const u8 *key, size_t keylen,
                      const u8 *src, u8 *dst, size_t len,
					  const u8 *iv, //blocksize
                      u32 alg_sel, u32 alg_aai, int stream, int encrypt) 
{
	int ret, size, i = 0, use_iv=0, iv_alloc=0;
	u32 *desc = NULL, blocksize;

	if (alg_sel == OP_ALG_ALGSEL_AES) {
		blocksize = 16;
	} else if ((alg_sel == OP_ALG_ALGSEL_DES) || (alg_sel == OP_ALG_ALGSEL_3DES)) {
		blocksize = 8;
	} else {
		return -EINVAL;
	}

	if (!stream && (len & (blocksize-1))) {
		return -EINVAL;
	}

	if (!IS_ALIGNED((uintptr_t)key, ARCH_DMA_MINALIGN)) {
		printf("Error: seq_cipher: Key is not aligned.\n");
		return -EINVAL;
	}
	if (!IS_ALIGNED((uintptr_t)src, ARCH_DMA_MINALIGN)) {
		printf("Error: seq_cipher: Src is not aligned.\n");
		return -EINVAL;
	}
	if (!IS_ALIGNED((uintptr_t)dst, ARCH_DMA_MINALIGN)) {
		printf("Error: seq_cipher: Dst is not aligned.\n");
		return -EINVAL;
	}
	if (iv && !IS_ALIGNED((uintptr_t)iv, ARCH_DMA_MINALIGN)) {
		printf("Error: seq_cipher: IV is not aligned.\n");
		return -EINVAL;
	}

	desc = malloc_cache_aligned(sizeof(int) * MAX_CAAM_DESCSIZE);
	if (!desc) {
		debug("Not enough memory for descriptor allocation\n");
		return -ENOMEM;
	}

	/* The following works for AES and DES */
	use_iv = (alg_aai != OP_ALG_AAI_AES_ECB);
	if (use_iv && !iv) {
		iv = malloc_cache_aligned(blocksize);
		if (!iv) {
			debug("Not enough memory for IV allocation\n");
			ret = -ENOMEM;
			goto done;
		}
		iv_alloc=1;
		memset(iv, 0, blocksize);
		size = ALIGN(blocksize, ARCH_DMA_MINALIGN);
		flush_dcache_range((unsigned long)iv,
				   (unsigned long)iv + size);
	}

	size = ALIGN(keylen, ARCH_DMA_MINALIGN);
	flush_dcache_range((unsigned long)key,
			   (unsigned long)key + size);

	size = ALIGN(len, ARCH_DMA_MINALIGN);
	flush_dcache_range((unsigned long)src,
			   (unsigned long)src + size);

	inline_cnstr_jobdesc_cipher(desc, key, (uint32_t)keylen, iv, blocksize,
	                            src, dst, (uint32_t)len, alg_sel|alg_aai, encrypt);

	debug("Descriptor dump:\n");
	for (i = 0; i < 14; i++) {
		debug("Word[%d]: %08x\n", i, *(desc + i));
	}

	size = ALIGN(sizeof(int) * MAX_CAAM_DESCSIZE, ARCH_DMA_MINALIGN);
	flush_dcache_range((unsigned long)desc,
			   (unsigned long)desc + size);

	ret = run_descriptor_jr(desc);

	if (ret) {
		printf("Error in cipher operation: %d\n", ret);
	} else {
		size = ALIGN(len, ARCH_DMA_MINALIGN);
		invalidate_dcache_range((unsigned long)dst,
					(unsigned long)dst + size);

	}

done:
	if (iv && iv_alloc) {
		free(iv);
	}
	if (desc) {
		free(desc);
	}
	return ret;
}

/**
 * seq_enc_aes_ctr() - Encrypts using AES CTR algorithm.
 * @key:    - Key address
 * @keylen: - Key length (bytes)
 * @in:     - Source address (plaintext)
 * @out:    - Destination address (cipher output)
 * @len:    - Size of data
 *
 * Note: Start and end of the key, in and out buffers have to be aligned to
 * the cache line size (ARCH_DMA_MINALIGN) for the CAAM operation to succeed.
 *
 * Returns zero on success, negative on error.
 */

int seq_enc_aes_ctr(const uint8_t *key, size_t keylen,
              const uint8_t *in, uint8_t *out, size_t len, const uint8_t *iv)
{
	if ((keylen != 16) && (keylen != 24) && (keylen != 32)) {
		return -EINVAL;
	}

	return seq_cipher(key, keylen, in, out, len, iv, OP_ALG_ALGSEL_AES,
	                  OP_ALG_AAI_AES_CTR, 1, 1);
}

/**
 * seq_dec_aes_ctr - Decrypts using AES CTR algorithm.
 * @key:    - Key address
 * @keylen: - Key length (bytes)
 * @in:     - Source address (cipher input)
 * @out:    - Destination address (plaintext)
 * @len:    - Size of data
 *
 * Note: Start and end of the key, in and out buffers have to be aligned to
 * the cache line size (ARCH_DMA_MINALIGN) for the CAAM operation to succeed.
 *
 * Returns zero on success, negative on error.
 */

int seq_dec_aes_ctr (const uint8_t *key, size_t keylen,
              const uint8_t *in, uint8_t *out, size_t len, const uint8_t *iv)
{
	if ((keylen != 16) && (keylen != 24) && (keylen != 32)) {
		return -EINVAL;
	}

	return seq_cipher(key, keylen, in, out, len, iv, OP_ALG_ALGSEL_AES,
	                  OP_ALG_AAI_AES_CTR, 1, 0);
}

int seq_enc_aes_ecb(uint8_t *key, size_t keylen,
			  uint8_t *in, uint8_t *out, size_t len)
{
	if ((keylen != 16) && (keylen != 24) && (keylen != 32)) {
		return -EINVAL;
	}

	return seq_cipher(key, keylen, in, out, len, NULL, OP_ALG_ALGSEL_AES,
		                  OP_ALG_AAI_AES_ECB, 0, 1);
}

int seq_dec_aes_ecb(uint8_t *key, size_t keylen,
			  uint8_t *in, uint8_t *out, size_t len)
{
	if ((keylen != 16) && (keylen != 24) && (keylen != 32)) {
		return -EINVAL;
	}

	return seq_cipher(key, keylen, in, out, len, NULL, OP_ALG_ALGSEL_AES,
		                  OP_ALG_AAI_AES_ECB, 0, 0);
}


int seq_enc_aes_cbc(uint8_t *key, size_t keylen,
			  uint8_t *in, uint8_t *out, size_t len, const uint8_t *iv)
{
	if ((keylen != 16) && (keylen != 24) && (keylen != 32)) {
		return -EINVAL;
	}

	return seq_cipher(key, keylen, in, out, len, iv, OP_ALG_ALGSEL_AES,
					OP_ALG_AAI_AES_CBC, 0, 1);
}

int seq_dec_aes_cbc(uint8_t *key, size_t keylen,
			  uint8_t *in, uint8_t *out, size_t len, const uint8_t *iv)
{
	if ((keylen != 16) && (keylen != 24) && (keylen != 32)) {
		return -EINVAL;
	}

	return seq_cipher(key, keylen, in, out, len, iv, OP_ALG_ALGSEL_AES,
					OP_ALG_AAI_AES_CBC, 0, 0);
}
