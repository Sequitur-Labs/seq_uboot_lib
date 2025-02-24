#include <common.h>
#include <mmc.h>
#ifdef CONFIG_IMX_ECSPI
#include <imx_spi.h>
#endif
#include <spi.h>
#include <spi_flash.h>
#include <asm/io.h>
#include <dm/device-internal.h>
#include <dm/uclass.h>
#include <spl.h>
#include <asm/spl.h>
#include <linux/delay.h>
#include <seq_error.h>
#include <seq_memio.h>

typedef enum {
	SEQ_NVM_TYPE_UNKNOWN,
	SEQ_NVM_TYPE_MMC,
	SEQ_NVM_TYPE_SPI
} SEQ_NVM_TYPE;


int seq_mmc_dev_id=-1; //eMMC dev ID for use with MMC drivers.
int seq_sd_dev_id=-1;
int seq_nvm_dev=-1;

static struct mmc *seq_memio_mmc = NULL;

static uint8_t seq_mmc_part_num = 0;
static uint8_t seq_mmc_ack = 0;
static uint8_t seq_mmc_access = 0;

static SEQ_NVM_TYPE seq_nvm_type = SEQ_NVM_TYPE_UNKNOWN;

void seq_init_nvm_dev(const void *fdt)
{
	struct udevice *dev=NULL;
	int sd=0, mmc=0, spi=0;
	const char *nvmtype = fdtdec_get_chosen_prop(fdt, "secedge-nvm");
	if(!nvmtype) {
		printf("No secedge-nvm found in 'chosen'\n");
		return;
	}

	debug("secedge-nvm from DTS: %s\n", nvmtype);

	sd = !strcmp(nvmtype, "SD");
	mmc = !strcmp(nvmtype, "eMMC");
	spi = !strcmp(nvmtype, "SPI");

	debug("SD: %d   eMMC: %d   SPI: %d\n", sd, mmc, spi);

	if (sd || mmc) {
		mmc_initialize(NULL);
		for (uclass_first_device(UCLASS_MMC, &dev); dev; uclass_next_device(&dev)) {
			struct mmc *m = mmc_get_mmc_dev(dev);
			if (!m) {
				continue;
			} else {
				debug("NAME: %s. Devnum: %d\n", m->cfg->name, mmc_get_blk_desc(m)->devnum);
				debug("Has init: %d   IS_SD: %d\n", m->has_init, IS_SD(m));
			}

			if (m->has_init) {
				if (sd && IS_SD(m) && seq_sd_dev_id < 0) {
					seq_sd_dev_id = mmc_get_blk_desc(m)->devnum;
				} else if (mmc && !IS_SD(m) && seq_mmc_dev_id < 0) {
					seq_mmc_dev_id = mmc_get_blk_desc(m)->devnum;
				}
			} else {
				debug("host_caps: 0x%08x\n", m->cfg->host_caps);
				if ((m->cfg->host_caps & MMC_CAP(UHS_SDR12)) ||
					(m->cfg->host_caps & MMC_CAP(UHS_SDR25)) ||
					(m->cfg->host_caps & MMC_CAP(UHS_SDR50)) ||
					(m->cfg->host_caps & MMC_CAP(UHS_SDR104)) ||
					(m->cfg->host_caps & MMC_CAP(UHS_DDR50))) {
					if (seq_sd_dev_id<0) {
						debug("Got SD capabilities. %d\n", mmc_get_blk_desc(m)->devnum);
						seq_sd_dev_id = mmc_get_blk_desc(m)->devnum;
					}
				} else if (seq_mmc_dev_id<0) {
					debug("Setting mmc dev id: %d\n", mmc_get_blk_desc(m)->devnum);
					seq_mmc_dev_id = mmc_get_blk_desc(m)->devnum;
				}
			}
		}

		if (sd && seq_sd_dev_id>=0) {
			seq_nvm_dev = seq_sd_dev_id;
			seq_nvm_type = SEQ_NVM_TYPE_MMC;
		} else if (mmc && seq_mmc_dev_id>=0) {
			seq_nvm_dev = seq_mmc_dev_id;
			seq_nvm_type = SEQ_NVM_TYPE_MMC;
		}
	} else if (spi) {
		printf("Got SPI SecEdge NVM Type.\n");
		seq_nvm_type = SEQ_NVM_TYPE_SPI;
	} else {
		seq_nvm_type = SEQ_NVM_TYPE_UNKNOWN;
		printf("Invalid DTS entry for secedge-nvm: %s", nvmtype);
	}

	if (seq_nvm_type == SEQ_NVM_TYPE_UNKNOWN) {
		printf("No SecEdge NVM device found\n");
	}
}

int seq_mem_read(uint32_t offset, uint32_t numbytes, void *dest)
{
	int res=SEQ_ERROR_UNKNOWN;

	if (!dest) {
		return SEQ_ERROR_BAD_PARAMS;
	}

	switch(seq_nvm_type) {
	case SEQ_NVM_TYPE_UNKNOWN:
		return SEQ_ERROR_UNKNOWN;
		break;
	case SEQ_NVM_TYPE_MMC:
		return seq_mmc_read( offset, numbytes, dest );
		break;
	case SEQ_NVM_TYPE_SPI:
		return seq_spi_read( offset, numbytes, dest );
		break;
	default:
		break;
	};

	return res;
}

int seq_mem_write(uint32_t offset, uint32_t numbytes, void *dest)
{
	int res=SEQ_ERROR_UNKNOWN;

	if (!dest) {
		return SEQ_ERROR_BAD_PARAMS;
	}

	switch(seq_nvm_type) {
	case SEQ_NVM_TYPE_UNKNOWN:
		return SEQ_ERROR_UNKNOWN;
		break;
	case SEQ_NVM_TYPE_MMC:
		return seq_mmc_write( offset, numbytes, dest );
		break;
	case SEQ_NVM_TYPE_SPI:
		return seq_spi_write( 1, offset, numbytes, dest );
		break;
	default:
		break;
	};

	return res;
}

//#define SEQ_MMC_ZERO_SUCCESS
static struct mmc *seq_init_mmc_device(int dev, uint8_t force_init)
{
	struct mmc *mmc;

	//printf("Calling find_mmc_device for dev: %d\n", dev);
	mmc_initialize(NULL);
	mmc = find_mmc_device(dev);
	if (!mmc) {
		printf("no mmc device at slot %x\n", dev);
		return NULL;
	}

	if (force_init) {
		mmc->has_init = 0;
	}
	//printf("Calling mmc_init\n");
	if (mmc_init(mmc)) {
		printf("Failed on call to mmc_init\n");
		return NULL;
	}
	return mmc;
}

int seq_init_mmc( void )
{
	if(seq_memio_mmc) {
		return SEQ_SUCCESS; //Already initialized
	}

	seq_memio_mmc = seq_init_mmc_device(seq_nvm_dev, false);
	if(!seq_memio_mmc) {
		printf("Failed to init MMC Device\n");
		return SEQ_ERROR_UNKNOWN;
	}

	if (IS_SD(seq_memio_mmc)) {
		//Don't set part conf
		return SEQ_SUCCESS;
	}

	//printf("Set part conf: %d: %d: %d: %d\n", seq_nvm_dev, seq_mmc_ack, seq_mmc_part_num, seq_mmc_access);
	mmc_set_part_conf(seq_memio_mmc, seq_mmc_ack, seq_mmc_part_num, seq_mmc_access);
	return SEQ_SUCCESS;
}

int seq_mmc_read( uint32_t blockoffset, uint32_t numbytes, void *addr )
{
	uint32_t copy;
	int count=0;
	if(seq_init_mmc()) {
		return SEQ_ERROR_UNKNOWN;
	}

	copy = numbytes/SEQ_MMC_BLOCK_SIZE;
	if(numbytes%SEQ_MMC_BLOCK_SIZE) {
		copy+=1;
	}

	count = blk_dread(mmc_get_blk_desc(seq_memio_mmc), blockoffset, copy, addr);
	udelay(1000);

	//printf("[%s] - blk_dread res: %d\n", __func__, count);
	return !(count==copy);
}

int seq_mmc_write( uint32_t blockoffset, uint32_t numbytes, void *addr )
{
	uint32_t copy;
	uint8_t *tmp=NULL;
	int count=0;
	if (seq_init_mmc()) {
		printf("Failed to initialize MMC device\n");
		return SEQ_ERROR_UNKNOWN;
	}

	copy = numbytes/SEQ_MMC_BLOCK_SIZE;
	if (numbytes%SEQ_MMC_BLOCK_SIZE)	{
		//printf("[%s] - Making a copy\n", __func__);
		copy+=1;
		tmp = malloc(copy*SEQ_MMC_BLOCK_SIZE);
		if (!tmp) {
			printf("FAILED TO ALLOCATE TMP\n");
			return SEQ_ERROR_MEMORY;
		}
		memcpy(tmp, addr, numbytes);
	} else {
		tmp = addr;
	}

	count = blk_dwrite(mmc_get_blk_desc(seq_memio_mmc), blockoffset, copy, tmp);
	udelay(1000);

	//printf("Wrote: %d blocks. Asked for: %d blocks\n", count, copy);

	if (tmp != addr) {
		//printf("[%s] - Freeing copy\n", __func__);
		free(tmp);
		tmp=0;
	}

	return !(count==copy);
}

struct mmc *seq_get_mmc( uint32_t dev, uint32_t ack, uint32_t part_num, uint32_t access )
{
	struct mmc *retmmc = seq_init_mmc_device( dev, true );
	if(!retmmc) {
		printf("Failed to initialize device for ID: %d\n", dev);
		return NULL;
	}

	if (IS_SD(retmmc)) {
		//Don't set partconf for SD card
		return retmmc;
	}
	mmc_set_part_conf( retmmc, ack, part_num, access );
	return retmmc;
}

int seq_mmc_read_dev( struct mmc *mmc, uint32_t blockoffset, uint32_t numbytes, void* addr )
{
	uint32_t copy;
	int count=0;
	if(!mmc) {
		return SEQ_ERROR_BAD_PARAMS;
	}

	copy = numbytes/SEQ_MMC_BLOCK_SIZE;
	if(numbytes%SEQ_MMC_BLOCK_SIZE) {
		copy+=1;
	}

	count = blk_dread(mmc_get_blk_desc(mmc), blockoffset, copy, addr);
	udelay(1000);
	return !(count==copy);
}

int seq_mmc_write_dev(struct mmc *mmc, uint32_t blockoffset, uint32_t numbytes, void *addr )
{
	uint32_t copy;
	int count=0;
	if(!mmc) {
		return SEQ_ERROR_BAD_PARAMS;
	}

	copy = numbytes/SEQ_MMC_BLOCK_SIZE;
	if(numbytes%SEQ_MMC_BLOCK_SIZE) {
		copy+=1;
	}

	count = blk_dwrite(mmc_get_blk_desc(mmc), blockoffset, copy, addr);
	printf("blk_dwrite res: %d\n", count);
	return !(count==copy);
}

int seq_spi_erase( uint32_t spidaddr, uint32_t numbytes )
{
	return SEQ_ERROR_UNKNOWN;
}

/*
 * Read 'numbytes' from 'spiaddr' to 'addr'.
 */
int seq_spi_read( uint32_t spiaddr, uint32_t numbytes, void *addr )
{
	return SEQ_ERROR_UNKNOWN;
}

/*
 * Write to 'spiaddr', 'numbytes' from 'addr'.
 * If erase != 0 then the region will be erased first. The erased region will be
 * rounded up to a multiple of SEQ_SPI_ERASE_SIZE
 */
int seq_spi_write( int erase, uint32_t spiaddr, uint32_t numbytes, void *addr )
{
	return SEQ_ERROR_UNKNOWN;
}
