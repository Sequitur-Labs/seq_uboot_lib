#include <memalign.h>
#include <hw_sha.h>

#include "fsl_sec.h"
#include "desc.h"
#include "desc_constr.h"
#include "jr.h"
#include <seq_imx8m_regs.h>
#include "seq_secmon_regs.h"
#include <seq_keys.h>


/* These are the sizes of the various buffers used in the ZMK calculation. */
#define MAXPUBKEYLEN 132
#define ZMKLEN 32
#define SHA256LEN 32
#define SBUFLEN 256

#define IRAM_BASE_ADDR 0

/* This should work for iMX6 and iMX7 devices */
#if defined IRAM_BASE_ADDR
#define TRUSTZONE_OCRAM_START IRAM_BASE_ADDR
#else
#error OCRAM base address undefined
#endif

#define seq_sec_out32(x,y) __raw_writel((y),(x))
#define seq_sec_in32(x) __raw_readl((x))

#define alloc(size) malloc_cache_aligned((size))


static void select_key(uint8_t key)
{
	volatile SECMON_LPMKCR lpmkcr;
	lpmkcr.val = seq_sec_in32(SECMON_LPMKCR_ADDR);
	lpmkcr.bits.MASTER_KEY_SEL = key;
	seq_sec_out32(SECMON_LPMKCR_ADDR, lpmkcr.val);
}

static size_t load_srkh(uint8_t *srkh)
{
  uint32_t srkh_val;

  srkh_val = seq_sec_in32(SRKH_BASE_ADDR);
  memcpy(&srkh[0], &srkh_val, 4);

  srkh_val = seq_sec_in32(SRKH_BASE_ADDR+16);
  memcpy(&srkh[4], &srkh_val, 4);

  srkh_val = seq_sec_in32(SRKH_BASE_ADDR+32);
  memcpy(&srkh[8], &srkh_val, 4);

  srkh_val = seq_sec_in32(SRKH_BASE_ADDR+48);
  memcpy(&srkh[12], &srkh_val, 4);

  srkh_val = seq_sec_in32(SRKH_BASE_ADDR+64);
  memcpy(&srkh[16], &srkh_val, 4);

  srkh_val = seq_sec_in32(SRKH_BASE_ADDR+80);
  memcpy(&srkh[20], &srkh_val, 4);

  srkh_val = seq_sec_in32(SRKH_BASE_ADDR+96);
  memcpy(&srkh[24], &srkh_val, 4);

  srkh_val = seq_sec_in32(SRKH_BASE_ADDR+112);
  memcpy(&srkh[28], &srkh_val, 4);

  return 32;	/* # bytes copied */
}


static void init_mp_pubkey_desc(u32 *desc, uint8_t **pubkey, uint32_t csel) {
  *pubkey = malloc_cache_aligned(64);
	memset(*pubkey,0,64);
  desc[0] = 0xb0840005;
  desc[1] = csel;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
  desc[2] = (uint32_t)*pubkey;
#pragma GCC diagnostic pop
  desc[3] = 0x40;
  desc[4] = 0x86140000;
}

static int get_mppub(uint8_t *pubkey, size_t *pubkeyLen) {
	/* N.B.  No cache maintenance on pubkey is done here.  It must have been
	 * done upstream if necessary. */
	int res = 0, size;
	uint32_t curve;
	volatile SecSCfgrType scfgr;
	uint8_t *_pubkey;

	scfgr.val = seq_sec_in32(SEC_SCFGR_ADDR);
	curve = scfgr.bits.MPCURVE;

	if ((curve >= 0x3) && (curve <= 0x5)) {
		u32 *desc;
		unsigned int N = (curve == 0x3) ? 32 :
		                 (curve == 0x4) ? 48 :
		                                  66 ;
		if (*pubkeyLen < 2*N) {
			*pubkeyLen = 2*N;
			res = CRYPT_BUFFER_OVERFLOW;
			goto done;
		}

		if ((desc = malloc_cache_aligned(sizeof(int) * MAX_CAAM_DESCSIZE))) {
		  init_mp_pubkey_desc(desc, &_pubkey, curve << PDB_MP_CSEL_SHIFT);
			size = ALIGN(sizeof(int) * MAX_CAAM_DESCSIZE, ARCH_DMA_MINALIGN);
			flush_dcache_range((unsigned long)desc, (unsigned long)desc + size);
			res = run_descriptor_jr(desc);
			if (!res) {
				*pubkeyLen = 2*N;
			}
			free(desc);
			invalidate_dcache_range((unsigned long)_pubkey, (unsigned long)_pubkey+0x40);
			memcpy(pubkey, _pubkey, 0x40);
			memset(_pubkey, 0, 0x40);
			free(_pubkey);
		} else
			res = CRYPT_MEM;
	} else
		res = CRYPT_ERR;
done:
	return res;
}

//#define DEBUG_BUILD 1
//#define SEQ_KEYS_DEBUG
int seq_set_zmk(uint8_t *_in, size_t inLen) {
	/* This sets the ZMK register for use with provisioning blobs.
	 * For devices with Manufacturing Protection support, the ZMK is set
	 * to the SHA256 hash of the MP public key concatenated with the
	 * input data.  If the device does not have MP support, the SRKH
	 * is used in place of the MP public key. */
        //int err = 0;
	int res = 0, i;
	// uint32_t scratch;
	uint32_t *p, *zmk_reg;
	uint32_t *sbuf=0; /* Contains ZMK, pubkey, and copy of input message */
	uint8_t *zmk;
	uint8_t* pubkey=0;
	uint8_t* in;
	size_t pubkeyLen = MAXPUBKEYLEN;
	volatile SecCtprLsType ctpr_ls;
#if (DEBUG_BUILD)
	volatile SECMON_HPSR hpsr;
#endif
	volatile SECMON_HPCOMR hpcomr;
	volatile SECMON_LPMKCR lpmkcr;
	volatile SECMON_HPLR hplr;
	volatile SECMON_LPLR lplr;

	/* First, check to see that the ZMK isn't locked. */
	lpmkcr.val = seq_sec_in32(SECMON_LPMKCR_ADDR);
	hplr.val = seq_sec_in32(SECMON_HPLR_ADDR);
	lplr.val = seq_sec_in32(SECMON_LPLR_ADDR);
	if ((lpmkcr.bits.ZMK_HWP) ||
	    (hplr.bits.MKS_SL) || (hplr.bits.ZMK_WSL) || (hplr.bits.ZMK_RSL) ||
	    (lplr.bits.MKS_HL) || (lplr.bits.ZMK_WHL)/* || (lplr.bits.ZMK_RHL) */) {
	  //	  asm volatile("b .\n");
		res = CRYPT_ERR;
		printf("ZMK is locked\n");
		goto done;
	}

#define SNVS_BASE 0x30370000
# define _HPCOMR     0x04
# define _HPSVSR     0x018
# define _LPSVCR     0x040
# define _HPSVCR     0x010
# define _LPSR       0x04c
# define _LPPGDR     0x064
# define GLITCH_VAL  0x41736166
	// DEGLITCH
	{
		uint32_t status = seq_sec_in32((void*)SNVS_BASE+_LPSR);
		if((status & (1<<3)) == (1<<3)){
			uint32_t rst = seq_sec_in32((void *)(SNVS_BASE + 0x4)); /* HPCOMR */
			__raw_writel(rst | 0x10, (void *)(SNVS_BASE + _HPCOMR)); /* low power reset */
			__raw_writel(0x03f, (void *)(SNVS_BASE + _HPSVSR)); /* clear hp errors */
			__raw_writel(GLITCH_VAL, (void *)(SNVS_BASE + _LPPGDR)); /* write deglitch */
			__raw_writel(0x01707ff, (void *)(SNVS_BASE + _LPSR)); /* clear lp errors */
		}
	}
	

	/* Turn off ECC checking of the ZMK so we can set it (change it) */
	lpmkcr.val = seq_sec_in32(SECMON_LPMKCR_ADDR);
	lpmkcr.bits.ZMK_ECC_EN = 0;
	seq_sec_out32(SECMON_LPMKCR_ADDR, lpmkcr.val);

	/* Set up the pointers into the sbuf[] buffer in OCRAM.  We don't need
	 * to do cache maintenance then for use with the CAAM. */
	//sbuf = (uint32_t*)phys_to_virt(TRUSTZONE_OCRAM_START);
	sbuf=alloc(SBUFLEN);
	
	zmk = (uint8_t*)sbuf;
	pubkey = alloc(pubkeyLen+inLen);
	/* Set *in later when pubkeyLen is known. */
	memset(sbuf, 0, SBUFLEN);
	memset(pubkey,0,pubkeyLen+inLen);

	ctpr_ls.val = seq_sec_in32(SEC_CTPR_LS_ADDR);
	if (ctpr_ls.bits.MAN_PROT) {
		/* Have MP support, so use the MP public key */
#ifdef SEQ_KEYS_DEBUG
		printf("SoC claims to support MP\n");
#endif
		if ((res = get_mppub(pubkey, &pubkeyLen)) != CRYPT_OK){
			printf("Failed to get MPPUB Key\n");
			goto done;
		}
	} else {
		/* No MP support, so use the SRKH in place of the public key */
#ifdef SEQ_KEYS_DEBUG
		printf("SoC DOESN'T support MP\n");
#endif
		pubkeyLen = load_srkh(pubkey);
	}

	/* Hash the pubkey and input message to produce the ZMK. */
	if (inLen > (SBUFLEN-ZMKLEN-pubkeyLen)) {
		res = CRYPT_MEM;
		printf("Buffer length is incorrect\n");
		goto done;
	}
	in = pubkey + pubkeyLen;
	memcpy(in, _in, inLen);
	//if ((res = sha256(pubkey, pubkeyLen+inLen, zmk)) != CRYPT_OK)
	//	goto done;

#ifdef SEQ_KEYS_DEBUG
	printf("pubkey contents\n");
	printBuffer(pubkey,pubkeyLen+inLen);
#endif

	hw_sha256(pubkey, pubkeyLen+inLen, zmk, 0);

	/*
	 Write ZMK to ZMK.
	 */
	p = sbuf;	/* Point to zmk */
	zmk_reg = (uint32_t*)SECMON_LPZMKR0_ADDR;
	for (i = 0; i < 8; i++) {
	  seq_sec_out32(zmk_reg+i, *(p+i));
	}

#if (DEBUG_BUILD)
	hpsr.val = seq_sec_in32(SECMON_HPSR_ADDR);
	if (hpsr.bits.ZMK_ZERO) {
		debug("\nZMK zero is set\n");
	} else {
		debug("\nZMK zero is clear\n");
	}
	if (hpsr.bits.OTPMK_ZERO) {
		debug("\nOTPMK zero is set\n");
	} else {
		debug("\nOTPMK zero is clear\n");
	}
#endif
	
# ifdef SEQ_KEYS_DEBUG // cannot compare if no-read/RAZ
	printf("Input to set_zmk\n");
	for (i=0; i < inLen; i++ ){
		printf("0x%02x ", _in[i]);
	}
	printf("\nZMK: \n");

	//Test mirror register contents against zmk buffer. 
	for (i = 0; i < 8; i++) {
	  uint32_t scratch;
	  scratch = seq_sec_in32(zmk_reg+i);
	  if (sbuf[i] != scratch) {
	    res = CRYPT_ERR;
			printf("%d: 0x%08x  0x%08x\n", i, scratch,sbuf[i]);
	    printf("ZMK buffer and mirror registers differ\n");
	    //asm volatile("b .\n");
	    //goto done;
	  }
	  else {
	    printf("%d: 0x%08x\n", i, scratch);
	  }
	}
	printf("\n");
# endif

	/*
	 Select ZMK as MK
	 */
	/* Enable master key selection. */
	hpcomr.val = seq_sec_in32(SECMON_HPCOMR_ADDR);
	hpcomr.bits.MKS_EN = 1;
	seq_sec_out32(SECMON_HPCOMR_ADDR, hpcomr.val);

	/* Get current value */
	lpmkcr.val = seq_sec_in32(SECMON_LPMKCR_ADDR);

	/* Set ZMK as valid. */
	lpmkcr.bits.ZMK_VAL = 1;

	/* Enable ECC check of ZMK (so that it isn't changed) */
#ifdef SEQ_KEYS_DEBUG
	printf("CURRENTLY NOT ENABLING ECC CHECK FOR ZMK!!!!\n");
#endif
	lpmkcr.bits.ZMK_ECC_EN = 0;
	seq_sec_out32(SECMON_LPMKCR_ADDR, lpmkcr.val);

	
# if 0
	/* Disable read access to ZMK. */

	hplr.val = 0;
	hplr.bits.ZMK_RSL = 1;
	seq_sec_out32(SECMON_HPLR_ADDR, hplr.val);
	lplr.val = 0;
	lplr.bits.ZMK_RHL = 1;
	seq_sec_out32(SECMON_LPLR_ADDR, lplr.val);
# endif
	/* We don't block write access to the ZMK until we clear it later. */

	/* We don't lock the MASTER_KEY_SEL bit because we may need to change
	 * it to use OTMPK later. */

	/* XXXXX Test writing to the ZMK and triggering the ECC error. */
done:
	if (sbuf)
		free(sbuf);

	if (pubkey)
		free(pubkey);

	return res;
}

void seq_select_zmk(void)
{
	select_key(LPMKCR_MASTER_KEY_SEL_ZMK);
}

void seq_select_otpmk(void)
{
	select_key(LPMKCR_MASTER_KEY_SEL_OTPMK);
}


void seq_set_priblob(unsigned int priblob)
{
	volatile SecSCfgrType scfgr = {0};
	scfgr.bits.PRIBLOB=priblob;
	seq_sec_out32(SEC_SCFGR_ADDR,scfgr.val);
}

uint32_t seq_get_scfgr(void)
{
	uint32_t res=seq_sec_in32(SEC_SCFGR_ADDR);
	return res;
}

void seq_unset_zmk(void)
{
  uint32_t rst = seq_sec_in32(SECMON_HPCOMR_ADDR);

  //# define DUMP_ZMK
# ifdef DUMP_ZMK // enable for dump
  {
    uint32_t *zmk_reg = (uint32_t*)SECMON_LPZMKR0_ADDR;
    int i;

    rst = seq_sec_in32(SECMON_HPSR_ADDR);
    printf("Pre:  HPSR:   0x%08x\n", rst);
    rst = seq_sec_in32(SECMON_HPCOMR_ADDR);
    printf("Pre:  HPCOMR: 0x%08x\n", rst);

    for (i = 0; i < 8; i++) {
      uint32_t scratch;
      scratch = seq_sec_in32(zmk_reg+i);
      printf("zmk[%d]: 0x%08x\n", i, scratch);
    }
  }
# endif

  seq_select_otpmk();
  rst = rst & ~(1 << 13); /* sticky bit, can't be changed until next reset */
  seq_sec_out32(SECMON_HPCOMR_ADDR, rst | 0x10); /* lp reset */
  seq_sec_out32(SECMON_HPCOMR_ADDR, rst | 0x20); /* disable further LP resets */

# ifdef DUMP_ZMK // enable for dump
  {
    uint32_t *zmk_reg = (uint32_t*)SECMON_LPZMKR0_ADDR;
    int i;

    rst = seq_sec_in32(SECMON_HPSR_ADDR);
    printf("Post: HPSR:   0x%08x\n", rst);
    rst = seq_sec_in32(SECMON_HPCOMR_ADDR);
    printf("Post: HPCOMR: 0x%08x\n", rst);
    for (i = 0; i < 8; i++) {
      uint32_t scratch;
      scratch = seq_sec_in32(zmk_reg+i);
      printf("zmk[%d]: 0x%08x\n", i, scratch);
    }
  }
# endif
}
