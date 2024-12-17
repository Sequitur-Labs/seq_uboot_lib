#ifndef __seq_blob_h__
#define __seq_blob_h__

/*
 * This holds the information about a blob in memory.
 */
typedef struct {
	uint32_t totalsize;
	uint32_t payloadsize;
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
int seq_blob_decapsulate( SeqBlobMemType source, uintptr_t blobaddr, uintptr_t destaddr, SeqBlobKeyType key );

#endif /*seq_blob_h*/
