/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#define TOKEN_FILENAME   "enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"
#define SEAL_TOKEN_FILENAME   "seal.token"
#define SEAL_FILENAME "Seal.signed.so"
#define SEALED_KEY_FILE_NAME "sealed_key.bin"

extern sgx_enclave_id_t global_eid;    /* global enclave id */

#if defined(__cplusplus)
extern "C" {
#endif

void edger8r_array_attributes(void);
void edger8r_type_attributes(void);
void edger8r_pointer_attributes(void);
void edger8r_function_attributes(void);

void ecall_libc_functions(void);
void ecall_libcxx_functions(void);
void ecall_thread_functions(void);

#if defined(__cplusplus)
}
#endif

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

// /* Error code returned by sgx_create_enclave */
// static sgx_errlist_t sgx_errlist[] = {
//     {
//         SGX_ERROR_UNEXPECTED,
//         "Unexpected error occurred.",
//         NULL
//     },
//     {
//         SGX_ERROR_INVALID_PARAMETER,
//         "Invalid parameter.",
//         NULL
//     },
//     {
//         SGX_ERROR_OUT_OF_MEMORY,
//         "Out of memory.",
//         NULL
//     },
//     {
//         SGX_ERROR_ENCLAVE_LOST,
//         "Power transition occurred.",
//         "Please refer to the sample \"PowerTransition\" for details."
//     },
//     {
//         SGX_ERROR_INVALID_ENCLAVE,
//         "Invalid enclave image.",
//         NULL
//     },
//     {
//         SGX_ERROR_INVALID_ENCLAVE_ID,
//         "Invalid enclave identification.",
//         NULL
//     },
//     {
//         SGX_ERROR_INVALID_SIGNATURE,
//         "Invalid enclave signature.",
//         NULL
//     },
//     {
//         SGX_ERROR_OUT_OF_EPC,
//         "Out of EPC memory.",
//         NULL
//     },
//     {
//         SGX_ERROR_NO_DEVICE,
//         "Invalid Intel(R) SGX device.",
//         "Please make sure Intel(R) SGX module is enabled in the BIOS, and install Intel(R) SGX driver afterwards."
//     },
//     {
//         SGX_ERROR_MEMORY_MAP_CONFLICT,
//         "Memory map conflicted.",
//         NULL
//     },
//     {
//         SGX_ERROR_INVALID_METADATA,
//         "Invalid enclave metadata.",
//         NULL
//     },
//     {
//         SGX_ERROR_DEVICE_BUSY,
//         "Intel(R) SGX device was busy.",
//         NULL
//     },
//     {
//         SGX_ERROR_INVALID_VERSION,
//         "Enclave version was invalid.",
//         NULL
//     },
//     {
//         SGX_ERROR_INVALID_ATTRIBUTE,
//         "Enclave was not authorized.",
//         NULL
//     },
//     {
//         SGX_ERROR_ENCLAVE_FILE_ACCESS,
//         "Can't open enclave file.",
//         NULL
//     },
//     {
//         SGX_ERROR_PCL_ENCRYPTED,
//         "sgx_create_enclave can't open encrypted enclave.",
//         NULL
//     },
//     {
//         SGX_ERROR_PCL_NOT_ENCRYPTED,
//         "sgx_create_encrypted_enclave can't open not-encrypted enclave.",
//         NULL
//     },
//     {
//         SGX_ERROR_PCL_MAC_MISMATCH,
//         "PCL detected invalid section in encrypted enclave.",
//         NULL
//     },
//     {
//         SGX_ERROR_PCL_SHA_MISMATCH,
//         "PCL sealed key SHA mismatch.",
//         NULL
//     },
//     {
//         SGX_ERROR_PCL_GUID_MISMATCH,
//         "PCL sealed key GUID mismatch.",
//         NULL
//     },
// };

// /* Check error conditions for loading enclave */
// void print_error_message(sgx_status_t ret)
// {
//     size_t idx = 0;
//     size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

//     for (idx = 0; idx < ttl; idx++) {
//         if(ret == sgx_errlist[idx].err) {
//             if(NULL != sgx_errlist[idx].sug)
//                 printf("Info: %s\n", sgx_errlist[idx].sug);
//             printf("Error: %s\n", sgx_errlist[idx].msg);
//             break;
//         }
//     }
    
//     if (idx == ttl)
//         printf("Error: Unexpected error occurred.\n");
// }

typedef struct config_struct {
    char mode;
    uint32_t flags;
    sgx_spid_t spid;
    sgx_ec256_public_t pubkey;
    sgx_quote_nonce_t nonce;
    char *server;
    char *port;
} config_t;
#endif /* !_APP_H_ */
