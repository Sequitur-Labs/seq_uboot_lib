#ifndef __seq_memio_h__
#define __seq_memio_h__

#define SEQ_MMC_BLOCK_SIZE 512

//Retrieve the mmc device based on the values passed in.
struct mmc *seq_get_mmc(uint32_t dev, uint32_t ack, uint32_t part_num, uint32_t access);
int seq_mmc_read_dev(struct mmc *seq_memio_mmc, uint32_t blockoffset, uint32_t numbytes, void *addr);
int seq_mmc_write_dev(struct mmc *seq_memio_mmc, uint32_t blockoffset, uint32_t numbytes, void *addr);

/*
 * Read 'nummbytes' from 'blockoffset' to 'addr'.
 * Note - the number of mmc blocks copied will be rounded up from 'numbytes'.
 */
int seq_mmc_read(uint32_t blockoffset, uint32_t numbytes, void *addr);

/*
 * Write 'numbytes' to 'blockoffset' from 'addr'
 * Note - the number of mmc blocks written to will be rounded up from 'numbytes'.
 */
int seq_mmc_write(uint32_t blockoffset, uint32_t numbytes, void *addr);


#define SEQ_SPI_ERASE_SIZE 0x10000

int seq_spi_erase(uint32_t spidaddr, uint32_t numbytes);

/*
 * Read 'numbytes' from 'spiaddr' to 'addr'.
 */
int seq_spi_read(uint32_t spiaddr, uint32_t numbytes, void *addr);

/*
 * Write to 'spiaddr', 'numbytes' from 'addr'.
 * If erase != 0 then the region will be erased first. The erased region will be
 * rounded up to a multiple of SEQ_SPI_ERASE_SIZE
 */
int seq_spi_write(int erase, uint32_t spiaddr, uint32_t numbytes, void *addr);

#endif /*seq_memio_h*/
