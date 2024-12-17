#ifndef _SEQ_KEYS_H
#define _SEQ_KEYS_H

#include <common.h>

typedef union {
	uint32_t val;
	struct {
		uint32_t res0 :17;
		uint32_t Csel :4;
		uint32_t res1 :10;
		uint32_t SGF :1;
	} bits;
} SecPdbMpKeygenType; /* Used by both private and public key generation. */

typedef union {
	uint32_t val;
	struct {
		uint32_t res0 :17;
		uint32_t Csel :4;
		uint32_t res1 :7;
		uint32_t SGF_d :1;
		uint32_t SGF_c :1;
		uint32_t SGF_mrep :1;
		uint32_t SGF_m :1;
	} bits;
} SecPdbMpSignType;

typedef union {
	uint16_t val;
	struct {
		uint16_t F2M_FP :1;
		uint16_t ECC_DL :1;
		uint16_t ENC_PRI :1;
		uint16_t KPG_NO_TEQ :1;
		uint16_t EXT_PRI :1;
		uint16_t ENC_Z :1;
		uint16_t EKT_Z :1;
		uint16_t KPG_IETF_DH :1;
		uint16_t res0 :8;
	} bits;
} SecProtinfoKeyGenType;

/*
 * Manufacturing-protection curve IDs
 */

#define SEC_MP_CURVE_P256 3
#define SEC_MP_CURVE_P384 4
#define SEC_MP_CURVE_P521 5

/*
 * These are for ordinary ECC operations (i.e. non-MP)
 */

typedef union {
	uint32_t val;
	struct {
		uint32_t res0         :7;
		uint32_t ECDSEL       :7;
		uint32_t res1         :11;
		uint32_t PD           :1;
		uint32_t res2         :1;
		uint32_t SGF_w        :1;
		uint32_t SGF_s        :1;
		uint32_t res3         :3;
	} bits;
} SecPdbKeyGenPd1Type;

typedef union {
	uint32_t val;
	struct {
		uint32_t res0         :7;
		uint32_t ECDSEL       :7;
		uint32_t res1         :8;
		uint32_t PD           :1;
		uint32_t SGF_u        :1; /* res in verify mode */
		uint32_t res2         :1; /* tmp in verify mode */
		uint32_t SGF_d        :1;
		uint32_t SGF_c        :1;
		uint32_t SGF_f        :1;
		uint32_t SGF_s        :1;
		uint32_t res3         :3;
	} bits;
} SecPdbDsaPd1Type;

#define SEC_ECC_CURVE_P256 2
#define SEC_ECC_CURVE_P384 3
#define SEC_ECC_CURVE_P521 4

# define CRYPT_OK              0
# define CRYPT_INVALID_ARG     1
# define CRYPT_MEM             2
# define CRYPT_BUFFER_OVERFLOW 3
# define CRYPT_ERR             4

#define SEC_BASE_ADDR           CAAM_IPS_BASE_ADDR

#define SEC_MPKR_ADDR (SEC_BASE_ADDR + 0x0300)
#define SEC_MPMR_ADDR (SEC_BASE_ADDR + 0x0380)

#define SEC_MCFGR_ADDR (SEC_BASE_ADDR + 0x4)
typedef union {
	uint32_t val;
	struct {
		uint32_t NORMAL_BURST :1;
		uint32_t res0 :1;
		uint32_t LARGE_BURST :1;
		uint32_t AXIPRI :1;
		uint32_t AXIPIPE :4;
		uint32_t AWCACHE :4;
		uint32_t ARCACHE :4;
		uint32_t PS :1;
		uint32_t res1 :2;
		uint32_t DWT :1;
		uint32_t DBPC :1;
		uint32_t DJPC :1;
		uint32_t res2 :5;
		uint32_t WRHD :1;
		uint32_t DMA_RST :1;
		uint32_t WDF :1;
		uint32_t WDE :1;
		uint32_t SWRST :1;
	} bits;
} SecMcfgrType;

#define SEC_SCFGR_ADDR (SEC_BASE_ADDR + 0xC)
typedef union {
	uint32_t val;
	struct {
		uint32_t PRIBLOB      :2;
		uint32_t res0         :6;
		uint32_t RANDDPAR     :1;
		uint32_t RNGSH0       :1;
		uint32_t RDB          :1;
		uint32_t LCK_TRNG     :1;
		uint32_t res1         :3;
		uint32_t VIRT_EN      :1;
		uint32_t res2         :10;
		uint32_t MPMRL        :1;
		uint32_t MPPKRC       :1;
		uint32_t MPCURVE      :4;
	} bits;
} SecSCfgrType;

#define SEC_CTPR_MS_ADDR (SEC_BASE_ADDR + 0x0FA8)
typedef union {
	uint32_t val;
	struct {
		uint32_t VIRT_EN_INCL :1;
		uint32_t VIRT_EN_POR :1;
		uint32_t res0 :2;
		uint32_t REG_PG_SIZE :1;
		uint32_t res1 :3;
		uint32_t RNG_I :3;
		uint32_t AI_INCL :1;
		uint32_t res2 :1;
		uint32_t DPAA2 :1;
		uint32_t IP_CLK :1;
		uint32_t res3 :1;
		uint32_t MCFG_BURST :1;
		uint32_t MCFG_PS :1;
		uint32_t SG8 :1;
		uint32_t PM_EVT_BUS :1;
		uint32_t DECO_WD :1;
		uint32_t PC :1;
		uint32_t res4 :1;
		uint32_t C1C2 :1;
		uint32_t ACC_CTL :1;
		uint32_t QI :1;
		uint32_t AXI_PRI :1;
		uint32_t AXI_LIODN :1;
		uint32_t AXI_PIPE_DEPTH :4;
	} bits;
} SecCtprMsType;

#define SEC_CTPR_LS_ADDR (SEC_BASE_ADDR + 0x0FAC)
typedef union {
	uint32_t val;
	struct {
		uint32_t KGDS         :1;
		uint32_t BLOB         :1;
		uint32_t WIFI         :1;
		uint32_t WIMAX        :1;
		uint32_t SRTP         :1;
		uint32_t IPSEC        :1;
		uint32_t IKE          :1;
		uint32_t SSL_TLS      :1;
		uint32_t TLS_PRF      :1;
		uint32_t MACSEC       :1;
		uint32_t RSA          :1;
		uint32_t P3G_LTE      :1;
		uint32_t DBL_CRC      :1;
		uint32_t MAN_PROT     :1;
		uint32_t SPLIT_KEY    :1;
		uint32_t res0         :17;
	} bits;
} SecCtprLsType;

#define SEC_SSTA_ADDR (SEC_BASE_ADDR + 0x0FD4)
typedef union {
	uint32_t val;
	struct {
		uint32_t BUSY         :1;
		uint32_t IDLE         :1;
		uint32_t TRNG_IDLE    :1;
		uint32_t res0         :5;
		uint32_t MOO          :2;
		uint32_t PLEND        :1;
		uint32_t res1         :21;
	} bits;
} SecSstaType;

/* The PROTOCOL command uses SEC_OPERATION_CTYPE, and one of
 * SEC_UNIDIRECTIONAL_PROTOCOL_OPTYPE, SEC_ENCAPSULATION_PROTOCOL_OPTYPE
 * or SEC_DECAPSULATION_PROTOCOL_OPTYPE */
typedef union {
	uint32_t val;
	struct {
		uint32_t PROTINFO :16;
		uint32_t PROTID :8;
		uint32_t OPTYPE :3;
		uint32_t CTYPE :5;
	} bits;
} SecProtocolCmdType;

/* These are the OPTYPE values */
#define SEC_UNIDIRECTIONAL_PROTOCOL_OPTYPE 0x0
#define SEC_PKHA_OPTYPE 0x1
#define SEC_CLASS_1_ALGORITHM_OPTYPE 0x2
#define SEC_CLASS_2_ALGORITHM_OPTYPE 0x4
#define SEC_DECAPSULATION_PROTOCOL_OPTYPE 0x6
#define SEC_ENCAPSULATION_PROTOCOL_OPTYPE 0x7

/* Protocol IDs */
#define SEC_PROTID_BLOB          0x0D
#define SEC_PROTID_VERIFY_PRV    0x12
#define SEC_PROTID_KEY_GEN       0x14
#define SEC_PROTID_SIGN          0x15
#define SEC_PROTID_VERIFY        0x16
#define SEC_PROTID_DH            0x17
#define SEC_PROTID_RSA_ENC       0x18
#define SEC_PROTID_RSA_DEC       0x19
#define SEC_PROTID_KEY_FIN       0x1A
#define SEC_PROTID_EC_PUBKEY_VAL 0x1E

#define SEC_OPERATION_CTYPE 0x10  //10000b
typedef union {
	uint32_t val;
	struct {
		uint32_t ENC :1;
		uint32_t ICV :1;
		uint32_t AS :2;
		uint32_t AAI :9;
		uint32_t C2K :1;
		uint32_t res0 :2;
		uint32_t ALG :8;
		uint32_t OPTYPE :3;
		uint32_t CTYPE :5;
	} bits;
} SecAlgorithmCmdType;

/* The following are for SHA calculations. */
#define SEC_ALG_SHA1       		  0x41
#define SEC_ALG_SHA256            0x43
#define SEC_ALG_AS_INIT_FINAL     0x03
#define SEC_ALG_AAI_HASH          0x00

/* The following are for CCM calculations. */
#define SEC_AE_MAX_CTX_SIZE 64
#define SEC_ALG_AES 0x10
#define SEC_ALG_AAI_AES_CCM 0x80

/* Enable timing equalization by default. */
#ifndef SEC_NO_TEQ
#define SEC_NO_TEQ 0
#endif

/*
 * Descriptor commands
 */

#define SEC_JD_HEADER_CTYPE 0x16  //10110b
typedef union {
	uint32_t val;
	struct {
		uint32_t DESCLEN :7;
		uint32_t res0 :1;
		uint32_t SHARE :3;
		uint32_t REO :1;
		uint32_t SHR :1;
		uint32_t TDES :2;
		uint32_t ZRO :1;
		uint32_t START_INDEX :6; /* This is also SHR_DESC_LENGTH */
		uint32_t res1 :1;
		uint32_t ONE :1;
		uint32_t DNR :1;
		uint32_t RSI :1;
		uint32_t EXT :1;
		uint32_t CTYPE :5;
	} bits;
} SecJdHeaderCmdType;

#define SEC_LOAD_CTYPE 0x02  //00010b
typedef union {
	uint32_t val;
	struct {
		uint32_t LENGTH       :8;
		uint32_t OFFSET       :8;
		uint32_t DST          :7;
		uint32_t IMM          :1;
		uint32_t SGF          :1;
		uint32_t CLASS        :2;
		uint32_t CTYPE        :5;
	} bits;
} SecLoadCmdType;

/* These are values for the DST part of the LOAD command */
#define SEC_LOAD_DST_CTX  0x20

typedef union {
	uint32_t val;
	struct {
		uint32_t quadrant     :4;
		uint32_t type         :2;
		uint32_t res0         :26;
		} pkha_bits;
	struct {
		uint32_t FC1          :1;
		uint32_t LC1          :1;
		uint32_t LC2          :1;
		uint32_t type         :3;
		uint32_t res0         :26;
	} bits;
} SecFifoInputDataType;

#define SEC_IDT_MSG           0x2
#define SEC_IDT_MSG_BIT       0x5
#define SEC_IDT_AAD           0x6
#define SEC_IDT_ICV           0x7

#define SEC_FIFO_LOAD_CTYPE 0x04  //00100b
typedef union {
	uint32_t val;
	struct {
		uint32_t LENGTH       :16;
		uint32_t INPUT_DATA_TYPE :6;
		uint32_t EXT          :1;
		uint32_t IMM          :1;
		uint32_t SGF          :1;
		uint32_t CLASS        :2;
		uint32_t CTYPE        :5;
	} bits;
} SecFifoLoadCmdType;

#define SEC_STORE_CTYPE 0x0a  //01010b
typedef union {
	uint32_t val;
	struct {
		uint32_t LENGTH       :8;
		uint32_t OFFSET       :8;
		uint32_t SRC          :7;
		uint32_t IMM          :1;
		uint32_t SGF          :1;
		uint32_t CLASS        :2;
		uint32_t CTYPE        :5;
	} bits;
} SecStoreCmdType;

/* These are values for the SRC part of the STORE command */
#define SEC_STORE_SRC_CTX 0x20

#define SEC_FIFO_STORE_CTYPE 0x0c  //01100b
typedef union {
	uint32_t val;
	struct {
		uint32_t LENGTH       :16;
		uint32_t OUTPUT_DATA_TYPE :6;
		uint32_t EXT          :1;
		uint32_t CONT         :1;
		uint32_t SGF          :1;
		uint32_t AUX          :2;
		uint32_t CTYPE        :5;
	} bits;
} SecFifoStoreCmdType;

/* These are output data types */
#define SEC_ODT_MSG 0x30

#define SEC_PROTINFO_ECC_TYPE 0x1
#define SEC_PROTINFO_FP_TYPE  0x0
typedef union {
	uint16_t val;
	struct {
		uint16_t F2M_FP :1;
		uint16_t ECC_DL :1;
		uint16_t ENC_PRI :1;
		uint16_t TEST :1;
		uint16_t EXT_PRI :1;
		uint16_t SIGN_1ST_HALF :1;
		uint16_t SIGN_2ND_HALF :1;
		uint16_t HASH :3;
		uint16_t MES_REP :2;
		uint16_t SIGN_NO_TEQ :1;
		uint16_t res0 :3;
	} bits;
} SecProtinfoSignType;

#define SEC_KEY_CTYPE 0x0  //00000b
typedef union {
	uint32_t val;
	struct {
		uint32_t LENGTH       :10;
		uint32_t res0         :4;
		uint32_t PTS          :1;
		uint32_t TK           :1;
		uint32_t KDEST        :2;
		uint32_t res1         :2;
		uint32_t EKT          :1;
		uint32_t NWB          :1;
		uint32_t ENC          :1;
		uint32_t IMM          :1;
		uint32_t SGF          :1;
		uint32_t CLASS        :2;
		uint32_t CTYPE        :5;
	} bits;
} SecKeyCmdType;

/* Key destination values */
#define SEC_KEY_KDEST_KEY_REGISTER   0x0  /* CLASS 1 or 2 */

/*
 * General defines
 */
#define SEC_CLASS_NONE  0x0
#define SEC_CLASS_1     0x1
#define SEC_CLASS_2     0x2
#define SEC_CLASS_BOTH  0x3

int seq_set_zmk(uint8_t *in, size_t inLen);
void seq_unset_zmk(void);

void seq_select_zmk(void);
void seq_select_otpmk(void);

#define SCFGR_PRIBLOB_SECBOOT  0x0
#define SCFGR_PRIBLOB_PROV_1   0x1
#define SCFGR_PRIBLOB_PROV_2   0x2
#define SCFGR_PRIBLOB_NORMAL   0x3
void seq_set_priblob(unsigned int priblob);

uint32_t seq_get_scfgr(void);

#endif /*_SEQ_KEYS_H*/
