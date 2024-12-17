#include <common.h>
#include <cpu_func.h>
#include <malloc.h>
#include <memalign.h>
#include "fsl_sec.h"
#include "jr.h"
#include "jobdesc.h"
#include "desc_constr.h"

#include <seq_rng.h>

int seq_rng(u8 *output_ptr, int output_len)
{
	u32 ret = 0;
	u32 *hwrng_desc = NULL;
	u32 size;
	u8 *dst = NULL;
	/* Buffer to hold the resulting output*/
	u8 *output = NULL;

	size = roundup(sizeof(int) * MAX_CAAM_DESCSIZE, ARCH_DMA_MINALIGN);
	hwrng_desc = malloc_cache_aligned(size);

	if (!hwrng_desc) {
		debug("Not enough memory for descriptor allocation\n");
		return -ENOMEM;
	}
	memset(hwrng_desc, 0, size);

    size = roundup(output_len, ARCH_DMA_MINALIGN);
    dst = malloc_cache_aligned(size);
    if (!dst) {
	  debug("Not enough memory for descriptor allocation\n");
	  return -ENOMEM;
	}

    output = (u8 *)dst;
	/* initialize the output array */
	memset(output, 0, output_len);
    memset(output_ptr, 0, output_len);

	flush_dcache_range((unsigned long)dst,
			   (unsigned long)dst + size);

	/* prepare job descriptor */
	init_job_desc(hwrng_desc, 0);
	append_operation(hwrng_desc, OP_ALG_ALGSEL_RNG | OP_TYPE_CLASS1_ALG);
#define PTR2CAAMDMA(x)  (u32)((uintptr_t)(x) & 0xffffffff)
	append_fifo_store(hwrng_desc, PTR2CAAMDMA(output),
			  output_len, FIFOST_TYPE_RNGSTORE);

	size = ALIGN(sizeof(int) * MAX_CAAM_DESCSIZE, ARCH_DMA_MINALIGN);
	flush_dcache_range((unsigned long)hwrng_desc,
			   (unsigned long)hwrng_desc + size);

	ret = run_descriptor_jr(hwrng_desc);

    size = roundup(output_len, ARCH_DMA_MINALIGN);
	invalidate_dcache_range((unsigned long)dst,
				(unsigned long)dst + size);

	if (ret) {
	  printf("Error: RNG generate failed 0x%x\n", ret);
	}

    memcpy(output_ptr, dst, output_len);

	/*
	  no residue.
	*/
    memset(dst, 0, output_len);
	flush_dcache_range((unsigned long)dst,
			   (unsigned long)dst + size);

    free(dst);
	free(hwrng_desc);

	return ret;
}
