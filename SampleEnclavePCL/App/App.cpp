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

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "Seal_u.h"

#include "sgx_stub.h"

#define SEAL_FILENAME             "Seal.signed.so"
#define SEALED_KEY_FILE_NAME     "sealed_key.bin"
#define TOKEN_FILENAME            "enclave.token"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;



/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
sgx_status_t  initialize_enclave ( const char *file_name, sgx_enclave_id_t* eid )
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    size_t read_num = 0;
    
    bool open_seal_enclave = true;
    uint8_t* sealed_blob = NULL;
    FILE *fsealp = fopen(SEALED_KEY_FILE_NAME, "rb");
    size_t sealed_blob_size = 0;

    // This is used by the sealed data. If the key is already sealed, 
    // it will be loaded from the sealed data and not from the original key file.
    // if(NULL != fsealp)
    // {   
    //     // Read file size:
    //     fseek(fsealp, 0L, SEEK_END);
    //     sealed_blob_size = ftell(fsealp);
    //     fseek(fsealp, 0L, SEEK_SET);
    //     // Read file into buffer:
    //     sealed_blob = new uint8_t[sealed_blob_size];
    //     read_num = fread(sealed_blob, 1, sealed_blob_size, fsealp);
    //     if ( read_num != sealed_blob_size )
    //     {
    //         printf ( "Warning: Failed to read sealed blob.\n" );
    //     }
    //     else
    //     {
    //         open_seal_enclave = false;
    //     }
    //     fclose(fsealp);
    // }
    // if (true == open_seal_enclave)
    // {
        // This is creating the Sealing enclave.

        // printf ("Open Seal Enclave: %s\n", SEAL_FILENAME );
        sgx_enclave_id_t seal_eid = 0;
        ret = sgx_create_enclave(
            SEAL_FILENAME, 
            SGX_DEBUG_FLAG, 
            NULL, 
            NULL, 
            &seal_eid, 
            NULL);

        if (SGX_SUCCESS != ret) 
        {

            std::cerr<<"Opening of the sealed enclave filed failed."<<std::endl;
            // print_error_message(ret);
            return ret;
        }        

        // Get the size of the sealed key in terms of bytes.
        // This call is made just to get the size of the sealed data.
        ret = ecall_get_sealed_blob_size(seal_eid, &sealed_blob_size);
        if (ret != SGX_SUCCESS || UINT32_MAX == sealed_blob_size)
        {
            printf("ecall_get_sealed_blob_size: ret = %d, sealed_blob_size = %ld\n", ret, sealed_blob_size);
            sgx_destroy_enclave(seal_eid);
            return ret;
        }

        //printf("ecall_get_sealed_blob_size: ret = %d, sealed_blob_size = %ld\n", ret, sealed_blob_size);

        sealed_blob = new uint8_t[sealed_blob_size];
        sgx_status_t gret = SGX_ERROR_UNEXPECTED;

        // If this call is successful, then the sealed_blob contains the final sealed blob.
        ret = ecall_generate_sealed_blob(seal_eid, &gret, sealed_blob, sealed_blob_size);
        if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != gret)) 
        {
            printf("ecall_generate_sealed_blob: ret = %d, gret = 0x%x\n", ret, gret);
            sgx_destroy_enclave(seal_eid);
            delete sealed_blob;
            return ret;
        }
        sgx_destroy_enclave(seal_eid);
        fsealp = fopen(SEALED_KEY_FILE_NAME, "wb");
        if(NULL != fsealp)
        {
            fwrite(sealed_blob, 1, sealed_blob_size, fsealp);
            fclose(fsealp);
        }
    // }
    // Load the PCL protected Enclave:
    ret = sgx_create_encrypted_enclave(file_name, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL, sealed_blob);
    delete sealed_blob;

    if (ret != SGX_SUCCESS) {
        std::cerr<<"Loading of the encrypted enclave failed."<<std::endl;
        std::cout<<file_name<<std::endl;
        std::cout<<eid<<std::endl;
        std::cout<<sealed_blob<<std::endl;
        // print_error_message(ret);
        return ret;
    }

    return SGX_SUCCESS;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    printf("%s", str);
}

int do_attestation(sgx_enclave_id_t eid, config_t *config);

void set_config(config_t *config){
    static struct option long_opt[] =
    {
        {"debug",       no_argument,        0, 'd'},
        {"rand-nonce",  no_argument,        0, 'r'},
        {"spid",        required_argument,  0, 's'},
        {"verbose",     no_argument,        0, 'v'},
        { 0, 0, 0, 0 }
    };

    /* Parse our options */

    while (1) {
        int c;
        int opt_index= 0;
        unsigned char keyin[64];

        c= getopt_long(argc, argv, "N:P:S:dehlmn:p:qrs:vz", long_opt,
            &opt_index);
        if ( c == -1 ) break;

        switch(c) {
        case 0:
            break;
        case 'r':
            for(i= 0; i< 2; ++i) {
                int retry= 10;
                unsigned char ok= 0;
                uint64_t *np= (uint64_t *) &config.nonce;

                while ( !ok && retry ) ok= _rdrand64_step(&np[i]);
                if ( ok == 0 ) {
                    fprintf(stderr, "nonce: RDRAND underflow\n");
                    exit(1);
                }
            }
            SET_OPT(config.flags, OPT_NONCE);
            break;
        case 's':
            if ( strlen(optarg) < 32 ) {
                fprintf(stderr, "SPID must be 32-byte hex string\n");
                exit(1);
            }
            if ( ! from_hexstring((unsigned char *) &config.spid,
                    (unsigned char *) optarg, 16) ) {

                fprintf(stderr, "SPID must be 32-byte hex string\n");
                exit(1);
            }
            ++have_spid;
            break;
        case 'v':
            verbose= 1;
            break;
        default:
            usage();
        }
    }
}
/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    config_t config;
    memset(&config, 0, sizeof(config));
    /* Initialize the enclave */
    if ( initialize_enclave ( ENCLAVE_FILENAME, &global_eid ) < 0 ){
        return -1; 
    }
 
    /* Utilize edger8r attributes */
    edger8r_array_attributes();
    edger8r_pointer_attributes();
    edger8r_type_attributes();
    edger8r_function_attributes();
    
    /* Utilize trusted libraries */
    ecall_libc_functions();
    ecall_libcxx_functions();
    ecall_thread_functions();

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclavePCL successfully returned.\n");

    return 0;
}

