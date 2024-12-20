#ifndef __seq_blob_h__
#define __seq_blob_h__

/*
 * This holds the information about a blob in memory.
 */
#define SEQ_BLOB_MAGIC_LENGTH 8
extern const uint8_t SEQ_BLOB_MAGIC[SEQ_BLOB_MAGIC_LENGTH];
typedef struct {
	uint8_t magic[8];
	uint32_t totalsize;   //Header + payload
	uint32_t payloadsize; //Padded binary size
	uint32_t plainsize;   //original binary size
} SeqBlobHeaderType;

typedef enum {
	SEQ_BLOB_MEM_MMC,
	SEQ_BLOB_MEM_SPI
} SeqBlobMemType;

typedef enum {
	SEQ_BLOB_KEY_ZMK,
	SEQ_BLOB_KEY_OTPMK
} SeqBlobKeyType;


/*
 * Run the decapsulation function on the blob at 'blobaddr'.
 * Result is moved to 'destaddr'
 *
 * Note: The blob at blobaddr is required to have a SeqBlobHeader struct at the start for the size.
 *
 * source 	- If 'SEQ_BLOB_MEM_MMC' then the blob is copied from MMC to RAM before blobbing.
 *    		- If 'SEQ_BLOB_MEM_SPI' then the blob is copied from SPI to RAM before blobbing.
 *
 * key	- If 'SEQ_BLOB_KEY_ZMK' then the ZMK is selected before the operation is run.
 *    	- If 'SEQ_BLOB_KEY_OTPMK' then the OTPMK is selected before the operation is run.
 */
int seq_blob_decapsulate( SeqBlobMemType source, uintptr_t blobaddr, uintptr_t destaddr, SeqBlobKeyType key, size_t *plainlength );

#endif /*seq_blob_h*/
