 /*
 * Copyright © 2016-2017 Sequitur Labs Inc. All rights reserved.
 *
 * The information and software contained in this package is proprietary property of
 * Sequitur Labs Incorporated, except as noted by individual copyright in files.
 * Any reproduction, use or disclosure, in whole or in part, of this software
 * including, but not limited to, any attempt to obtain a human-readable version of this
 * software, without the express, prior written consent of Sequitur Labs Inc. is forbidden.
 */
#ifndef INCLUDE_ECC_CERTIFICATE_H_
#define INCLUDE_ECC_CERTIFICATE_H_

#define SEQ_CURVE_KEY_SIZE 32
#define SEQ_KEY_DER_SIZE 130 //121 +8 byte header is size of sequence+length of sequence

#define SEQ_CERT_CREATE_FLAG_CSR (1<<0)
#define SEQ_CERT_CREATE_FLAGS_EMPOWER (1<<1)

int seq_create_full_der_certificate(void *private_key, void *public_key, int length, uint32_t createflags);

#endif /* INCLUDE_EEC_CERTIFICATE_H_ */
