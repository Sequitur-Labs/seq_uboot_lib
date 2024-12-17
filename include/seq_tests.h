#ifndef __seq_tests_h__
#define __seq_tests_h__

/*
 * Used by uECC
 * Must return '1' for success, '0' for failure.
 */
typedef int (*uECC_RNG_Function)(unsigned char *dest, unsigned size);

void seq_execute_cert_test( uECC_RNG_Function random );
void seq_execute_key_test( uECC_RNG_Function random );


int seq_verify_device_cert(SeqCertType certtype);

#endif //__seq_tests_h__
