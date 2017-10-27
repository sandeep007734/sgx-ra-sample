/*

Copyright 2017 Intel Corporation

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "EnclaveQuote_t.h"
#include <string.h>
#include <sgx_utils.h>
#include <sgx_tae_service.h>

sgx_status_t get_report(sgx_report_t *report, sgx_target_info_t *target_info)
{
	return sgx_create_report(target_info, NULL, report);
}

/* Platform services are not supported on Linux */

sgx_status_t get_ps_sec_prop(sgx_ps_sec_prop_desc_t *prop)
{
	sgx_status_t status= SGX_ERROR_SERVICE_UNAVAILABLE;

#ifdef _WIN32
	sgx_ps_sec_prop_desc_t ps_sec_prop_desc;
	int retries= 5;

	do {
		status= sgx_create_pse_session();
		if ( status != SGX_SUCCESS ) return status;
	} while (status == SGX_ERROR_BUSY && retries--);
	if ( status != SGX_SUCCESS ) return status;

	status= sgx_get_ps_sec_prop(&ps_sec_prop_desc);
	if ( status != SGX_SUCCESS ) return status;

	*prop= ps_sec_prop_desc;

	sgx_close_pse_session();
#endif
	return status;
}

