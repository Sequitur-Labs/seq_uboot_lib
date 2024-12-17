#include <common.h>
#include <seq_error.h>

/*
 * This will output a generic error message but will help identify the location to
 * focus debug efforts on.
 */
void seq_output_error_string( uint32_t errorid, const char  *function, const int line )
{
	switch(errorid){
	case SEQ_ERROR_MEMORY:
		printf("[%s][%d] - Failed to allocate memory.\n", function, line);
		break;
	case SEQ_ERROR_BAD_PARAMS:
		printf("[%s][%d] - Bad parameters.\n", function, line);
		break;
	case SEQ_ERROR_PARSE:
		printf("[%s][%d] - Unable to parse argument.\n", function, line);
		break;
	case SEQ_ERROR_CRYPTO:
		printf("[%s][%d] - Crypto error.\n", function, line);
		break;
	case SEQ_ERROR_PROGRAMMER:
		printf("[%s][%d] - Programming error.\n", function, line);
		break;
	case SEQ_ERROR_ITEM_NOT_FOUND:
		printf("[%s][%d] - Item not found.\n", function, line);
		break;
	default:
		printf("[%s][%d] - Unknown error id: %d\n", function, line, errorid);
		break;
	}
}
