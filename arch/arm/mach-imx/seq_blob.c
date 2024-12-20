#include <common.h>
#include <memalign.h>

#include <seq_memio.h>
#include <seq_blob.h>
#include <seq_keys.h>

extern int blob_decap(u8*,u8*,u8*,u32,u8);

const uint8_t SEQ_BLOB_MAGIC[SEQ_BLOB_MAGIC_LENGTH]={'s','e','q','b','l','o','b',0x00};

int seq_blob_decapsulate( SeqBlobMemType source, uintptr_t blobaddr, uintptr_t destaddr, SeqBlobKeyType key, size_t *plainlength )
{
	int res=1; //0 is success.
	uint8_t* blob=NULL;
	uint8_t headerbuffer[SEQ_MMC_BLOCK_SIZE];
	SeqBlobHeaderType* header=(SeqBlobHeaderType*)headerbuffer;
	uint8_t* rnd=(uint8_t*)malloc_cache_aligned(32);

	if(!rnd) {
		//Failed to allocate
		printf("[%s] - Failed to allocate aligned memory\n", __func__);
		return res;
	}

	memset(headerbuffer, 0, SEQ_MMC_BLOCK_SIZE);
	memset(rnd, 0, 32);

	if(key == SEQ_BLOB_KEY_ZMK) {
		seq_select_zmk();
	} else {
		seq_select_otpmk();
	}

	if( source == SEQ_BLOB_MEM_MMC ) {
		//printf("Loading BLOB from MMC: 0x%08lx. Loading to: 0x%08lx\n", blobaddr, destaddr);
		res = seq_mmc_read(blobaddr, SEQ_MMC_BLOCK_SIZE, headerbuffer);
		if(res) {
			printf("[%s] Failed to read from mmc 0x%08lx\n", __func__, blobaddr);
			free(rnd);
			return res;
		}

		if (memcmp(header->magic, SEQ_BLOB_MAGIC, SEQ_BLOB_MAGIC_LENGTH)) {
			printf("Invalid blob\n");
			free(rnd);
			return res;
		}

		//printf("Allocating aligned: 0x%08lx bytes\n",header->totalsize+sizeof(SeqBlobHeaderType));
		blob=(uint8_t*)malloc_cache_aligned(header->totalsize);
		if(blob) {
			res = seq_mmc_read(blobaddr, header->totalsize, blob);
			if(res){
				printf("[%s] Failed to read from mmc 0x%08lx\n", __func__, blobaddr);
				free(blob);
				free(rnd);
				return res;
			}
			memmove(blob,blob+sizeof(SeqBlobHeaderType),header->totalsize-sizeof(SeqBlobHeaderType));
		} //'else' checked below
	} else {
		//printf("Loading BLOB from SPI: 0x%08lx. Loading to: 0x%08lx\n", blobaddr, destaddr);
		res = seq_spi_read(blobaddr, SEQ_MMC_BLOCK_SIZE, headerbuffer);
		if(res){
			printf("[%s] Failed to read from spi 0x%08lx\n", __func__, blobaddr);
			return res;
		}

		if (memcmp(header->magic, SEQ_BLOB_MAGIC, SEQ_BLOB_MAGIC_LENGTH)) {
			printf("Invalid blob\n");
			free(rnd);
			return res;
		}

		blob=(uint8_t*)malloc_cache_aligned(header->totalsize+sizeof(SeqBlobHeaderType));
		if(blob) {
			res = seq_spi_read(blobaddr, header->totalsize, blob);
			if(res){
				printf("[%s] Failed to read from spi 0x%08lx\n", __func__, blobaddr);
				free(blob);
				return res;
			}
			memmove(blob,blob+sizeof(SeqBlobHeaderType),header->totalsize-sizeof(SeqBlobHeaderType));
		} //'else' checked below
	}

	if (blob) {
		//printf("Deblobbing to 0x%08lx     size: 0x%08x bytes\n", destaddr, header->payloadsize);
		*plainlength = header->plainsize;
		res = blob_decap( (u8*)rnd, (u8*)blob, (u8*)destaddr, header->payloadsize, 0);
		free(blob);
	} else {
		printf("[%s] Failed to allocate aligned buffer.\n", __func__);
		res = -1;
	}

	if (res) {
		printf("[%s] FAILED to decrypt blob\n", __func__);
	}

	return res;
}
