#ifndef _SEQ_IMX8M_REGS_H_
#define _SEQ_IMX8M_REGS_H_
#define CONFIG_SYS_FSL_MAX_NUM_OF_JR    3

#define SNVS_BASE_ADDR		SNVS_HP_BASE_ADDR
#define SNVS_HPCOMR 	0x04
#define SNVS_HPSVCR 	0x10
#define SNVS_HPSVSR		0x18
#define SNVS_HPHACIVR 	0x1C
#define SNVS_LPSVCR     0x40
#define SNVS_LPSR		0x4C
#define SNVS_GLITCH 	0x64 //LPPGDR
#define SNVS_LPGPR		0x68

#if defined(CONFIG_IMX8MP)
#define SNVS_LPGPR0     0x90
#endif

#endif //_SEQ_IMX8M_REGS_H_
