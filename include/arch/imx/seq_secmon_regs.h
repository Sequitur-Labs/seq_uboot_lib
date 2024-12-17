#ifndef __sli_secmon_regs__
#define __sli_secmon_regs__

#include <common.h>
//#include <asm/arch-imx8/imx-regs.h>


#ifdef CONFIG_IMX8M
#define SECMON_BASE_ADDR SNVS_BASE_ADDR
/*Shadow 0x30350580*/
#define SRKH_BASE_ADDR   0x30350580
# else
#define SECMON_BASE_ADDR 0x01e90000
# endif

/* N.B.  'S' in the comment means the bit is sticky. */

#define SECMON_HPLR_ADDR (SECMON_BASE_ADDR + 0x0)
typedef union {
	uint32_t val;
	struct {
		uint32_t ZMK_WSL      :1;	/* S Locks writes to ZMK registers, LPMKCR[ZMK_HWP], LPMKCR[ZMK_VAL] and LPMKCR[ZMK_ECC_EN] */
		uint32_t ZMK_RSL      :1;	/* S Locks reads from ZMK registers and LPMKCR[ZMK_ECC_VALUE] */
		uint32_t SRTC_SL      :1;	/* S Locks SRTC registers, LPCR[SRTC_ENV] and LPCR[SRTC_INV_EN]*/
		uint32_t LPCALB_SL    :1;	/* S Locks LPCR[LPCALB_VAL] and LPCR[LPCALB_EN] */
		uint32_t MC_SL        :1;	/* S Locks MC registers and LPCR[MC_ENV] */
		uint32_t GPR_SL       :1;	/* S Locks GPR */
		uint32_t LPSVCR_SL    :1;	/* S Locks LPSVCR */
		uint32_t res0         :1;
		uint32_t LPTDCR_SL    :1;	/* S Locks LPTDCR */
		uint32_t MKS_SL       :1;	/* S Locks LPMKCR[MASTER_KEY_SEL] */
		uint32_t res1         :6;
		uint32_t HPSVCR_L     :1;	/* S Locks HPSCVR */
		uint32_t HPSICR_L     :1;	/* S Locks HPSICR */
		uint32_t HAC_L        :1;	/* S Locks HPACIVR, HPHACR, HPCOMR[HAC_EN] */
		uint32_t res2         :13;
	} bits;
} SECMON_HPLR;

#define SECMON_HPCOMR_ADDR (SECMON_BASE_ADDR + 0x4)
typedef union {
	uint32_t val;
	struct {
		uint32_t SSM_ST       :1;
		uint32_t SSM_ST_DIS   :1;	/* S Disables transitions from secure to trusted state */
		uint32_t SSM_SFNS_DIS :1;	/* S Disables soft fail to Non-Secure state */
		uint32_t res0         :1;
		uint32_t LP_SWR       :1;
		uint32_t LP_SWR_DIS   :1;	/* S Disables LP_SWR bit */
		uint32_t res1         :2;
		uint32_t SW_SV        :1;
		uint32_t SW_FSV       :1;
		uint32_t SW_LPSV      :1;
		uint32_t res2         :1;
		uint32_t PROG_ZMK     :1;
		uint32_t MKS_EN       :1;	/* S Enables the LPMKCR[MASTER_KEY_SEL] bit */
		uint32_t res3         :2;
		uint32_t HAC_EN       :1;
		uint32_t HAC_LOAD     :1;
		uint32_t HAC_CLEAR    :1;
		uint32_t HAC_STOP     :1;
		uint32_t res4         :11;
		uint32_t NPSWA_EN     :1;
	} bits;
} SECMON_HPCOMR;

#define SECMON_HPCR_ADDR (SECMON_BASE_ADDR + 0x8)
typedef union {
	uint32_t val;
	struct {
		uint32_t RTC_EN       :1;
		uint32_t HPTA_EN      :1;
		uint32_t res0         :1;
		uint32_t PI_EN        :1;
		uint32_t PI_FREQ      :4;
		uint32_t HPCALB_EN    :1;
		uint32_t res1         :1;
		uint32_t HPCALB_VAL   :5;
		uint32_t res2         :1;
		uint32_t HP_TS        :1;
		uint32_t res3         :15;
	} bits;
} SECMON_HPCR;

#define SECMON_HPSICR_ADDR (SECMON_BASE_ADDR + 0xC)
typedef union {
	uint32_t val;
	struct {
		uint32_t SV0_EN       :1;
		uint32_t SV1_EN       :1;
		uint32_t SV2_EN       :1;
		uint32_t SV3_EN       :1;
		uint32_t SV4_EN       :1;
		uint32_t SV5_EN       :1;
		uint32_t res0         :25;
		uint32_t LPSVI_EN     :1;
	} bits;
} SECMON_HPSICR;

#define SECMON_HPSVCR_ADDR (SECMON_BASE_ADDR + 0x10)
typedef union {
	uint32_t val;
	struct {
		uint32_t SV0_CFG      :1;
		uint32_t SV1_CFG      :1;
		uint32_t SV2_CFG      :1;
		uint32_t SV3_CFG      :1;
		uint32_t SV4_CFG      :1;
		uint32_t SV5_CFG      :1;
		uint32_t res0         :1;
		uint32_t LPSV_CFG     :1;
	} bits;
} SECMON_HPSVCR;

#define SECMON_HPSR_ADDR (SECMON_BASE_ADDR + 0x14)
typedef union {
	uint32_t val;
	struct {
		uint32_t HPTA         :1;
		uint32_t PI           :1;
		uint32_t res0         :6;
		uint32_t SSM_STATE    :4;
		uint32_t res1         :15;
		uint32_t OTPMK_ZERO   :1;
		uint32_t res2         :3;
		uint32_t ZMK_ZERO     :1;
	} bits;
} SECMON_HPSR;

#define HPSR_SSM_STATE_INIT      0x0
#define HPSR_SSM_STATE_HARD_FAIL 0x1
#define HPSR_SSM_STATE_SOFT_FAIL 0x3
#define HPSR_SSM_STATE_INIT_INT  0x8
#define HPSR_SSM_STATE_CHECK     0x9
#define HPSR_SSM_STATE_NONSECURE 0xB
#define HPSR_SSM_STATE_TRUSTED   0xD
#define HPSR_SSM_STATE_SECURE    0xF

#define SECMON_HPSVSR_ADDR (SECMON_BASE_ADDR + 0x18)
typedef union {
	uint32_t val;
	struct {
		uint32_t SV0          :1;
		uint32_t SV1          :1;
		uint32_t SV2          :1;
		uint32_t SV3          :1;
		uint32_t SV4          :1;
		uint32_t SV5          :1;
		uint32_t res0         :10;
		uint32_t ZMK_SYNDROME :9;
		uint32_t res1         :2;
		uint32_t ZMK_ECC_FAIL :1;
		uint32_t res2         :4;
	} bits;
} SECMON_HPSVSR;

#define SECMON_HPHACIVR_ADDR (SECMON_BASE_ADDR + 0x1C)
typedef union {
	uint32_t val;
	struct {
		uint32_t HAC_COUNTER_IV :32;	/* Locked by HPLR[HAC_L] */
	} bits;
} SECMON_HPHACIVR;

#define SECMON_HPHACR_ADDR (SECMON_BASE_ADDR + 0x20)
typedef union {
	uint32_t val;
	struct {
		uint32_t HAC_COUNTER  :32;
	} bits;
} SECMON_HPHACR;

#define SECMON_HPRTCMR_ADDR (SECMON_BASE_ADDR + 0x24)
typedef union {
	uint32_t val;
	struct {
		uint32_t RTC          :15;
		uint32_t res0         :17;
	} bits;
} SECMON_HPRTCMRR;

#define SECMON_HPRTCLR_ADDR (SECMON_BASE_ADDR + 0x28)
typedef union {
	uint32_t val;
	struct {
		uint32_t RTC          :32;
	} bits;
} SECMON_HPRTCLR;

#define SECMON_HPTAMR_ADDR (SECMON_BASE_ADDR + 0x2c)
typedef union {
	uint32_t val;
	struct {
		uint32_t HPTA_MS      :15;
		uint32_t res0         :17;
	} bits;
} SECMON_HPTAMR;

#define SECMON_HPTALR_ADDR (SECMON_BASE_ADDR + 0x30)
typedef union {
	uint32_t val;
	struct {
		uint32_t HPTA_LS      :32;
	} bits;
} SECMON_HPTALR;

#define SECMON_LPLR_ADDR (SECMON_BASE_ADDR + 0x34)
typedef union {
	uint32_t val;
	struct {
		uint32_t ZMK_WHL      :1;	/* S Locks writes to ZMK registers, LPMKCR[ZMK_HWP], LPMKCR[ZMK_VAL], and LPMKCR[ZMK_ECC_EN] */
		uint32_t ZMK_RHL      :1;	/* S Locks reads from ZMK registers and LPMKCR[ZM_ECC_VALUE] */
		uint32_t SRTC_HL      :1;	/* S Locks SRTC registers, LPCR[SRTC_ENV] and LPCR[SRTC_INV_EN] */
		uint32_t LPCALB_HL    :1;	/* S Locks LPCR[LPCALB_VAL] and LPCR[LPCALB_EN] */
		uint32_t MC_HL        :1;	/* S Locks MC registers and LPCR[MC_ENV] */
		uint32_t GPR_HL       :1;	/* S Locks GPR */
		uint32_t LPSVCR_HL    :1;	/* S Locks LPSVCR */
		uint32_t res0         :1;
		uint32_t LPTDCR_HL    :1;	/* S Locks LPTDCR */
		uint32_t MKS_HL       :1;	/* S Locks LPMKCR[MASTER_KEY_SEL] */
		uint32_t res1         :22;
	} bits;
} SECMON_LPLR;

#define SECMON_LPCR_ADDR (SECMON_BASE_ADDR + 0x38)
typedef union {
	uint32_t val;
	struct {
		uint32_t SRTC_ENV     :1;
		uint32_t LPTA_EN      :1;
		uint32_t MC_ENV       :1;
		uint32_t res0         :3;
		uint32_t SRTC_INV_EN  :1;
		uint32_t res1         :1;
		uint32_t LPCALB_EN    :1;
		uint32_t res2         :1;
		uint32_t LPCALB_VAL   :5;
		uint32_t res3         :17;
	} bits;
} SECMON_LPCR;

#define SECMON_LPMKCR_ADDR (SECMON_BASE_ADDR + 0x3C)
typedef union {
	uint32_t val;
	struct {
		uint32_t MASTER_KEY_SEL :2;	/* Enabled by HPCOMR[MKS_EN] */
		uint32_t ZMK_HWP        :1;	/* Locked by HPLR[ZMK_WSL] or LPLR[ZMK_WHL] */
		uint32_t ZMK_VAL        :1;	/* Locked by HPLR[ZMK_WSL] or LPLR[ZMK_WHL] */
		uint32_t ZMK_ECC_EN     :1;	/* Locked by HPLR[ZMK_WSL] or LPLR[ZMK_WHL] */
		uint32_t res0           :2;
		uint32_t ZMK_ECC_VALUE  :9;
		uint32_t res1           :16;
	} bits;
} SECMON_LPMKCR;

#define LPMKCR_MASTER_KEY_SEL_OTPMK     0x0
#define LPMKCR_MASTER_KEY_SEL_ZMK       0x2
#define LPMKCR_MASTER_KEY_SEL_COMBINED  0x3

#define SECMON_LPSVCR_ADDR (SECMON_BASE_ADDR + 0x40)
typedef union {
	uint32_t val;
	struct {
		uint32_t SV0_EN       :1;
		uint32_t SV1_EN       :1;
		uint32_t SV2_EN       :1;
		uint32_t SV3_EN       :1;
		uint32_t SV4_EN       :1;
		uint32_t SV5_EN       :1;
		uint32_t res0         :26;
	} bits;
} SECMON_LPSVCR;

#define SECMON_LPTDCR_ADDR (SECMON_BASE_ADDR + 0x48)
typedef union {
	uint32_t val;
	struct {
		uint32_t res0         :1;
		uint32_t SRTCR_EN     :1;
		uint32_t MCR_EN       :1;
		uint32_t res1         :6;
		uint32_t ET1_EN       :1;
		uint32_t res2         :4;
		uint32_t PFD_OBSERV   :1;
		uint32_t POR_OBSERV   :1;
		uint32_t res3         :12;
		uint32_t OSCB         :1;
		uint32_t res4         :3;
	} bits;
} SECMON_LPTDCR;

#define SECMON_LPSR_ADDR (SECMON_BASE_ADDR + 0x4C)
typedef union {
	uint32_t val;
	struct {
		uint32_t LPTA         :1;
		uint32_t SRTCR        :1;
		uint32_t MCR          :1;
		uint32_t PGD          :1;
		uint32_t res0         :5;
		uint32_t ET1D         :1;
		uint32_t res1         :6;
		uint32_t ESVD         :1;
		uint32_t res2         :13;
		uint32_t LPNS         :1;
		uint32_t LPS          :1;
	} bits;
} SECMON_LPSR;

#define SECMON_LPSRTCMR_ADDR (SECMON_BASE_ADDR + 0x50)
typedef union {
	uint32_t val;
	struct {
		uint32_t SRTC         :15;
		uint32_t res0         :17;
	} bits;
} SECMON_LPSRCTMR;

#define SECMON_LPSRTCLR_ADDR (SECMON_BASE_ADDR + 0x54)
typedef union {
	uint32_t val;
	struct {
		uint32_t SRTC         :32;
	} bits;
} SECMON_LPSRTCLR;

#define SECMON_LPTAR_ADDR (SECMON_BASE_ADDR + 0x58)
typedef union {
	uint32_t val;
	struct {
		uint32_t LPTA         :32;
	} bits;
} SECMON_LPTAR;

#define SECMON_LPSMCMR_ADDR (SECMON_BASE_ADDR + 0x5C)
typedef union {
	uint32_t val;
	struct {
		uint32_t MON_COUNTER  :16;
		uint32_t MC_ERA_BITS  :16;
	} bits;
} SECMON_LPSMCMR;

#define SECMON_LPSMCLR_ADDR (SECMON_BASE_ADDR + 0x60)
typedef union {
	uint32_t val;
	struct {
		uint32_t MON_COUNTER  :32;
	} bits;
} SECMON_LPSMCLR;

#define SECMON_LPPGDR_ADDR (SECMON_BASE_ADDR + 0x64)
typedef union {
	uint32_t val;
	struct {
		uint32_t PGD          :32;
	} bits;
} SECMON_LPPGDR;

#define SECMON_LPGPR_ADDR (SECMON_BASE_ADDR + 0x68)
typedef union {
	uint32_t val;
	struct {
		uint32_t GPR          :32;
	} bits;
} SECMON_LPGPR;

#define SECMON_LPZMKR0_ADDR (SECMON_BASE_ADDR + 0x6C)
typedef union {
	uint32_t val;
	struct {
		uint32_t ZMK          :32;
	} bits;
} SECMON_LPZMKR0;

#define SECMON_HPVIDR1_ADDR (SECMON_BASE_ADDR + 0xBF8)
typedef union {
	uint32_t val;
	struct {
		uint32_t MINOR_REV    :8;
		uint32_t MAJOR_REV    :8;
		uint32_t IP_ID        :16;
	} bits;
} SECMON_HPVIDR1;

#define SECMON_HPVIDR2_ADDR (SECMON_BASE_ADDR + 0xBFC)
typedef union {
	uint32_t val;
	struct {
		uint32_t CONFIG_OPT   :8;
		uint32_t ECO_REV      :8;
		uint32_t INTG_OPT     :8;
		uint32_t IP_ERA       :8;
	} bits;
} SECMON_HPVIDR2;

void init_secmon(void);
void transition_security_state(void);

#endif /*__sli_secmon_regs__ */
