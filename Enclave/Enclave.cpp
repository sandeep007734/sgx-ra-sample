/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#include "../config.h"
#include "Enclave_t.h"

#include <stdarg.h>
#include <stdio.h>   

#include <sgx_tseal.h>
// #include <memory>
#include <sgx_pcl_guid.h>

#include <string.h>
#include <sgx_utils.h>
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>

// #define SGX_AESGCM_KEY_SIZE 128
static const sgx_ec256_public_t def_service_public_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

#define PSE_RETRIES	5	/* Arbitrary. Not too long, not too short. */

/*----------------------------------------------------------------------
 * WARNING
 *----------------------------------------------------------------------
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation:
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 * These functions short-circuits the RA process in order
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 *----------------------------------------------------------------------
 */

/*
 * This doesn't really need to be a C++ source file, but a bug in 
 * 2.1.3 and earlier implementations of the SGX SDK left a stray
 * C++ symbol in libsgx_tkey_exchange.so so it won't link without
 * a C++ compiler. Just making the source C++ was the easiest way
 * to deal with that.
 */

sgx_status_t get_report(sgx_report_t *report, sgx_target_info_t *target_info)
{
// #ifdef SGX_HW_SIM
// 	return sgx_create_report(NULL, NULL, report);
// #else
	return sgx_create_report(target_info, NULL, report);
// #endif
}

size_t get_pse_manifest_size ()
{
	return sizeof(sgx_ps_sec_prop_desc_t);
}

sgx_status_t get_pse_manifest(char *buf, size_t sz)
{
	sgx_ps_sec_prop_desc_t ps_sec_prop_desc;
	sgx_status_t status= SGX_ERROR_SERVICE_UNAVAILABLE;
	int retries= PSE_RETRIES;

	do {
		status= sgx_create_pse_session();
		if ( status != SGX_SUCCESS ) return status;
	} while (status == SGX_ERROR_BUSY && retries--);
	if ( status != SGX_SUCCESS ) return status;

	status= sgx_get_ps_sec_prop(&ps_sec_prop_desc);
	if ( status != SGX_SUCCESS ) return status;

	memcpy(buf, &ps_sec_prop_desc, sizeof(ps_sec_prop_desc));

	sgx_close_pse_session();

	return status;
}

sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse,
	sgx_ra_context_t *ctx, sgx_status_t *pse_status)
{
	sgx_status_t ra_status;

	/*
	 * If we want platform services, we must create a PSE session 
	 * before calling sgx_ra_init()
	 */

	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_create_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}

	ra_status= sgx_ra_init(&key, b_pse, ctx);

	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_create_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}

	return ra_status;
}

sgx_status_t enclave_ra_init_def(int b_pse, sgx_ra_context_t *ctx,
	sgx_status_t *pse_status)
{
	return enclave_ra_init(def_service_public_key, b_pse, ctx, pse_status);
}

/*
 * Return a SHA256 hash of the requested key. KEYS SHOULD NEVER BE
 * SENT OUTSIDE THE ENCLAVE IN PLAIN TEXT. This function let's us
 * get proof of possession of the key without exposing it to untrusted
 * memory.
 */

sgx_status_t enclave_ra_get_key_hash(sgx_status_t *get_keys_ret,
	sgx_ra_context_t ctx, sgx_ra_key_type_t type, sgx_sha256_hash_t *hash)
{
	sgx_status_t sha_ret;
	sgx_ra_key_128_t k;

	// First get the requested key which is one of:
	//  * SGX_RA_KEY_MK 
	//  * SGX_RA_KEY_SK
	// per sgx_ra_get_keys().

	*get_keys_ret= sgx_ra_get_keys(ctx, type, &k);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	/* Now generate a SHA hash */

	sha_ret= sgx_sha256_msg((const uint8_t *) &k, sizeof(k), 
		(sgx_sha256_hash_t *) hash); // Sigh.

	/* Let's be thorough */
	//clear the keys
	memset(k, 0, sizeof(k));

	return sha_ret;
}

sgx_status_t enclave_ra_close(sgx_ra_context_t ctx)
{
        sgx_status_t ret;
        ret = sgx_ra_close(ctx);
        return ret;
}

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}


//----------------------
sgx_status_t provision_key_mock (uint8_t* key_ptr, uint32_t key_len,sgx_ra_context_t ctx )
{

	sgx_status_t sha_ret;
	sgx_ra_key_128_t k;

	// First get the requested key which is one of:
	//  * SGX_RA_KEY_MK 
	//  * SGX_RA_KEY_SK
	// per sgx_ra_get_keys().
	sgx_ra_key_type_t type = SGX_RA_KEY_SK;
	sgx_status_t get_keys_ret;
	get_keys_ret= sgx_ra_get_keys(ctx, type, &k);
	if ( get_keys_ret != SGX_SUCCESS ) return get_keys_ret;


    // if ( (NULL == key_ptr) || (SGX_AESGCM_KEY_SIZE != key_len))
    // {
    //     return SGX_ERROR_INVALID_PARAMETER;
    // }
    // const uint8_t key[SGX_AESGCM_KEY_SIZE] = 
        // { 0x21, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0x99, 0x99 };
      printf("Main key: 0x%x\n",k );
      // printf("Fake key%x\n",key );
    
    memcpy (key_ptr, k, SGX_AESGCM_KEY_SIZE);
    return SGX_SUCCESS;
}

sgx_status_t provision_key( uint8_t* key_ptr, uint32_t key_len,sgx_ra_context_t ctx )
{
    /* 
     * ISV must replace call to provision_key_mock with an alternative ISV's secured key provisioning scheme, e.g. using remote attestation & TLS.
     * For more details, see 'Intel(R) SGX PCL Linux User Guide.pdf', chapter 'Integration with PCL', sub chapter 'Sealing Enclave'.
     */
    return provision_key_mock(key_ptr, key_len, ctx);
}

extern "C" 
{

/*
 * @func ecall_get_sealed_blob_size returns the PCL sealed blob size
 * @return size_t, size of PCL sealed blob size in bytes
 */
size_t ecall_get_sealed_blob_size()
{
    return (size_t)sgx_calc_sealed_data_size ( SGX_PCL_GUID_SIZE, SGX_AESGCM_KEY_SIZE );
}

/*
 * @func ecall_generate_sealed_blob generates the sealed blob
 * @param uint8_t* sealed_blob is the resulting sealed blob
 * @param uint32_t sealed_blob_size is sealed blob size in bytes
 * @return sgx_status_t
 * SGX_ERROR_INVALID_PARAMETER if sealed_blob is NULL or if sealed_blob_size does not match PCL sealed blob size
 * The respective error in case provision_key  or sgx_seal_data fail
 * SGX_SUCCESS if function passes
 */
sgx_status_t ecall_generate_sealed_blob(uint8_t* sealed_blob, size_t sealed_blob_size, sgx_ra_context_t ctx)
{
    if ((NULL == sealed_blob) || (ecall_get_sealed_blob_size() != sealed_blob_size))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    sgx_status_t retstatus = SGX_ERROR_UNEXPECTED;
    uint8_t key[SGX_AESGCM_KEY_SIZE] = { 0 };
    	
    retstatus = provision_key(key, SGX_AESGCM_KEY_SIZE,ctx);
    if (retstatus != SGX_SUCCESS )
    {
        return retstatus;
    }
    
    retstatus = sgx_seal_data (
        SGX_PCL_GUID_SIZE,                 // AAD size
        g_pcl_guid,                        // AAD
        SGX_AESGCM_KEY_SIZE,               // Key len
        key,                               // Key
        (uint32_t)sealed_blob_size,                  // Resulting blob size
        (sgx_sealed_data_t*)sealed_blob ); // Resulting blob

    memset(key, 0,SGX_AESGCM_KEY_SIZE); 
    return retstatus;
}

}; 