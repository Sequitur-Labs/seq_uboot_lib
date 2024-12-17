#include <common.h>
#include <mmc.h>
#ifdef CONFIG_IMX_ECSPI
#include <imx_spi.h>
#endif
#include <spi.h>
#include <spi_flash.h>
#include <asm/io.h>
#include <dm/device-internal.h>
#include <spl.h>
#include <asm/spl.h>
#include <linux/delay.h>
#include <seq_memio.h>

static struct mmc *seq_memio_mmc = NULL;

#define SEQ_MMC_DEV CORETEE_NVM_DEV

static uint8_t SEQ_MMC_PART_NUM = 0;
static uint8_t SEQ_MMC_ACK = 0;
static uint8_t SEQ_MMC_ACCESS = 0;

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
		return 0;
	}

	seq_memio_mmc = seq_init_mmc_device(SEQ_MMC_DEV, false);
	if(!seq_memio_mmc) {
		printf("Failed to init MMC Device\n");
		return -1;
	}

	if (IS_SD(seq_memio_mmc)) {
		//Don't set part conf
		return 0;
	}

	//printf("Set part conf: %d: %d: %d: %d\n", SEQ_MMC_DEV, SEQ_MMC_ACK, SEQ_MMC_PART_NUM, SEQ_MMC_ACCESS);
	mmc_set_part_conf(seq_memio_mmc, SEQ_MMC_ACK, SEQ_MMC_PART_NUM, SEQ_MMC_ACCESS);
	return 0;
}

int seq_mmc_read( uint32_t blockoffset, uint32_t numbytes, void *addr )
{
	uint32_t copy;
	int count=0;
	if(seq_init_mmc()) {
		return -1;
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
	if(seq_init_mmc()) {
		printf("Failed to initialize MMC device\n");
		return -1;
	}

	copy = numbytes/SEQ_MMC_BLOCK_SIZE;
	if(numbytes%SEQ_MMC_BLOCK_SIZE)
	{
		//printf("[%s] - Making a copy\n", __func__);
		copy+=1;
		tmp = malloc(copy*SEQ_MMC_BLOCK_SIZE);
		if(!tmp) {
			printf("FAILED TO ALLOCATE TMP\n");
			return -1;
		}
		memcpy(tmp, addr, numbytes);
	} else {
		tmp = addr;
	}

	count = blk_dwrite(mmc_get_blk_desc(seq_memio_mmc), blockoffset, copy, tmp);
	udelay(1000);

	//printf("Wrote: %d blocks. Asked for: %d blocks\n", count, copy);

	if(tmp != addr) {
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
		return -1;
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
		return -1;
	}

	copy = numbytes/SEQ_MMC_BLOCK_SIZE;
	if(numbytes%SEQ_MMC_BLOCK_SIZE) {
		copy+=1;
	}

	count = blk_dwrite(mmc_get_blk_desc(mmc), blockoffset, copy, addr);
	return !(count==copy);
}

int seq_spi_erase( uint32_t spidaddr, uint32_t numbytes ){
	return -1;
}

/*
 * Read 'numbytes' from 'spiaddr' to 'addr'.
 */
int seq_spi_read( uint32_t spiaddr, uint32_t numbytes, void *addr ){
	return -1;
}

/*
 * Write to 'spiaddr', 'numbytes' from 'addr'.
 * If erase != 0 then the region will be erased first. The erased region will be
 * rounded up to a multiple of SEQ_SPI_ERASE_SIZE
 */
int seq_spi_write( int erase, uint32_t spiaddr, uint32_t numbytes, void *addr ){
	return -1;
}
