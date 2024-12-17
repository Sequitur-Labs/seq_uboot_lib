#ifndef _SEQ_ERROR_H_
#define _SEQ_ERROR_H_

#define SEQ_ERROR_BASE	0xFAFA0000

#define SEQ_SUCCESS 		0
#define SEQ_ERROR_MEMORY	(SEQ_ERROR_BASE + 1)
#define SEQ_ERROR_BAD_PARAMS	(SEQ_ERROR_BASE + 2)
#define SEQ_ERROR_PARSE		(SEQ_ERROR_BASE+3)
#define SEQ_ERROR_CRYPTO	(SEQ_ERROR_BASE+4)
#define SEQ_ERROR_PROGRAMMER (SEQ_ERROR_BASE+5)
#define SEQ_ERROR_ITEM_NOT_FOUND (SEQ_ERROR_BASE+6)

void seq_output_error_string( uint32_t errorid, const char  *function, const int line );

#define SEQ_ERRMSG(errid) seq_output_error_string(errid, __func__, __LINE__)

#endif
