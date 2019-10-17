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


using namespace std;

#include <iostream>
#include "config.h"



# include "Enclave_u.h"

#include "sgx_stub.h"
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <sgx_urts.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <getopt.h>
#include <unistd.h>

#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <string>
#include "common.h"
#include "protocol.h"
#include "sgx_detect.h"
#include "hexutil.h"
#include "fileio.h"
#include "base64.h"
#include "crypto.h"
#include "msgio.h"
#include "logfile.h"
#include "quote_size.h"

#define MAX_LEN 80
#define SEALED_KEY_FILE_NAME     "sealed_key.bin"

# define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })


#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

typedef struct config_struct {
	char mode;
	uint32_t flags;
	sgx_spid_t spid;
	sgx_ec256_public_t pubkey;
	sgx_quote_nonce_t nonce;
	char *server;
	char *port;
} config_t;

int file_in_searchpath (const char *file, const char *search, char *fullpath,
	size_t len);

sgx_status_t sgx_create_enclave_search (
	const char *filename,
	const int edebug,
	sgx_launch_token_t *token,
	int *updated,
	sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr
);

void usage();
int do_quote(sgx_enclave_id_t eid, config_t *config);
int do_attestation(sgx_enclave_id_t eid, config_t *config);

char debug= 0;
char verbose= 0;

#define MODE_ATTEST 0x0
#define MODE_EPID 	0x1
#define MODE_QUOTE	0x2

#define OPT_PSE		0x01
#define OPT_NONCE	0x02
#define OPT_LINK	0x04
#define OPT_PUBKEY	0x08

/* Macros to set, clear, and get the mode and options */

#define SET_OPT(x,y)	x|=y
#define CLEAR_OPT(x,y)	x=x&~y
#define OPT_ISSET(x,y)	x&y


# define ENCLAVE_NAME "Enclave.signed.so"


int main (int argc, char *argv[])
{
	config_t config;
	sgx_launch_token_t token= { 0 };
	sgx_status_t status;
	sgx_enclave_id_t eid= 0;
	int updated= 0;
	int sgx_support;
	uint32_t i;
	EVP_PKEY *service_public_key= NULL;
	char have_spid= 0;
	char flag_stdio= 0;





	memset(&config, 0, sizeof(config));
	config.mode= MODE_ATTEST;

	static struct option long_opt[] =
	{
		{"debug",		no_argument,		0, 'd'},
		{"rand-nonce",	no_argument,		0, 'r'},
		{"spid",		required_argument,	0, 's'},
		{"verbose",		no_argument,		0, 'v'},
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

	argc-= optind;
	if ( argc > 1 ) usage();

	/* Remaining argument is host[:port] */

	// if ( flag_stdio && argc ) usage();
	// else if ( !flag_stdio && ! argc ) {
	// 	// Default to localhost
	// 	config.server= strdup("localhost");
	// 	if ( config.server == NULL ) {
	// 		perror("malloc");
	// 		return 1;
	// 	}
	// } else if ( argc ) {
		char *cp;

		config.server= strdup(argv[optind]);
		if ( config.server == NULL ) {
			perror("malloc");
			return 1;
		}
		
		/* If there's a : then we have a port, too */
		cp= strchr(config.server, ':');
		if ( cp != NULL ) {
			*cp++= '\0';
			config.port= cp;
		}
	// }

	if ( ! have_spid && config.mode != MODE_EPID ) {
		fprintf(stderr, "SPID required. Use one of --spid or --spid-file \n");
		return 1;
	}

	/* Can we run SGX? */

#ifndef SGX_HW_SIM
	sgx_support = get_sgx_support();
	if(sgx_support!=3){
		std::cerr<<"There is somethinig wrong with the SGX config"<<std::endl;
		return 1;
	}
#else
	std::cout<<	"We are running in SIMULATION mode"<<std::endl;
#endif

	/* Launch the enclave */
	cout<<"Launging the enclave"<<endl;
	status = sgx_create_enclave_search(ENCLAVE_NAME,
		SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_enclave: %s: %08x\n",
			ENCLAVE_NAME, status);
		if ( status == SGX_ERROR_ENCLAVE_FILE_ACCESS ) 
			fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
		return 1;
	}


	sgx_ra_context_t ra_ctx = do_attestation(eid, &config);
	int enclaveTrusted = Trusted;
	// valid after attestation
	// sgx_status_t status, sgxrv, pse_status;
	// sgx_ra_context_t ra_ctx= 0xaabcde;
	if ( enclaveTrusted == Trusted || enclaveTrusted == Trusted_ItsComplicated) {
		sgx_status_t key_status, sha_status;
		sgx_sha256_hash_t mkhash, skhash;

		status= enclave_ra_get_key_hash(eid, &sha_status, &key_status, ra_ctx,
			SGX_RA_KEY_MK, &mkhash);
		status= enclave_ra_get_key_hash(eid, &sha_status, &key_status, ra_ctx,
			SGX_RA_KEY_SK, &skhash);

			eprintf("SHA256(MK) = ");
			print_hexstring(stderr, mkhash, sizeof(mkhash));
			eprintf("\n");
			eprintf("SHA256(SK) = ");
			print_hexstring(stderr, skhash, sizeof(skhash));
			eprintf("\n");

 		size_t sealed_blob_size = 0;
		status = ecall_get_sealed_blob_size(eid, &sealed_blob_size);
        if (status != SGX_SUCCESS || UINT32_MAX == sealed_blob_size)
        {
            printf("ecall_get_sealed_blob_size: ret = %d, sealed_blob_size = %ld\n", status, sealed_blob_size);
            sgx_destroy_enclave(eid);
            return status;
        }
        cout<<"Size is: "<<sealed_blob_size<<endl;

 		uint8_t* sealed_blob = NULL;
        sealed_blob = new uint8_t[sealed_blob_size];
        sgx_status_t gret = SGX_ERROR_UNEXPECTED;

        // If this call is successful, then the sealed_blob contains the final sealed blob.
        status = ecall_generate_sealed_blob(eid, &gret, sealed_blob, sealed_blob_size, ra_ctx);
        if ((SGX_SUCCESS != status) || (SGX_SUCCESS != gret)) 
        {
            printf("ecall_generate_sealed_blob: ret = %d, gret = 0x%x\n", status, gret);
            sgx_destroy_enclave(eid);
            delete sealed_blob;
            return status;
        }

        // close when youa re done
		enclave_ra_close(eid, &status, ra_ctx);
		FILE *fsealp = fopen(SEALED_KEY_FILE_NAME, "rb");
		fsealp = fopen(SEALED_KEY_FILE_NAME, "wb");
        if(NULL != fsealp)
        {
            fwrite(sealed_blob, 1, sealed_blob_size, fsealp);
            fclose(fsealp);
        }

     }else{ 	
		cout<<"Enclave is NOT trusted."<<endl;
		// close when youa re done
	enclave_ra_close(eid, &status, ra_ctx);
	}

	
     
	return 0;
}

// skdon. This is the main part of the remote attestation.
int do_attestation (sgx_enclave_id_t eid, config_t *config)
{
	sgx_status_t status, sgxrv, pse_status;
	sgx_ra_msg1_t msg1;
	sgx_ra_msg2_t *msg2 = NULL;
	sgx_ra_msg3_t *msg3 = NULL;
	ra_msg4_t *msg4 = NULL;	

	uint32_t msg0_extended_epid_group_id = 0;
	uint32_t msg3_sz;

	uint32_t flags= config->flags;
	sgx_ra_context_t ra_ctx= 0xaabcde;
	int rv;
	MsgIO *msgio;
	size_t msg4sz = 0;
	int enclaveTrusted = NotTrusted; // Not Trusted
	int b_pse= OPT_ISSET(flags, OPT_PSE);

		try {
			msgio = new MsgIO(config->server, (config->port == NULL) ?
				DEFAULT_PORT : config->port);
		}
		catch(...) {
			exit(1);
		}

	/*
	 * WARNING! Normally, the public key would be hardcoded into the
	 * enclave, not passed in as a parameter. Hardcoding prevents
	 * the enclave using an unauthorized key.
	 *
	 * This is diagnostic/test application, however, so we have
	 * the flexibility of a dynamically assigned key.
	 */

	/* Executes an ECALL that runs sgx_ra_init() */

	if ( OPT_ISSET(flags, OPT_PUBKEY) ) {
		if ( debug ) fprintf(stderr, "+++ using supplied public key\n");
		status= enclave_ra_init(eid, &sgxrv, config->pubkey, b_pse,
			&ra_ctx, &pse_status);
	} else {
		if ( debug ) fprintf(stderr, "+++ using default public key\n");
		status= enclave_ra_init_def(eid, &sgxrv, b_pse, &ra_ctx,
			&pse_status);
	}

	/* Did the ECALL succeed? */
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "enclave_ra_init: %08x\n", status);
		delete msgio;
		return 1;
	}

	/* Did sgx_ra_init() succeed? */
	if ( sgxrv != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_ra_init: %08x\n", sgxrv);
		delete msgio;
		return 1;
	}

	/* Generate msg0 */

	status = sgx_get_extended_epid_group_id(&msg0_extended_epid_group_id);
	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx); 
		fprintf(stderr, "sgx_get_extended_epid_group_id: %08x\n", status);
		delete msgio;
		return 1;
	}
	
 
	/* Generate msg1 */

	status= sgx_ra_get_msg1(ra_ctx, eid, sgx_ra_get_ga, &msg1);
	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_ra_get_msg1: %08x\n", status);
		fprintf(fplog, "sgx_ra_get_msg1: %08x\n", status);
		delete msgio;
		return 1;
	}

	

	/*
	 * Send msg0 and msg1 concatenated together (msg0||msg1). We do
	 * this for efficiency, to eliminate an additional round-trip
	 * between client and server. The assumption here is that most
	 * clients have the correct extended_epid_group_id so it's
	 * a waste to send msg0 separately when the probability of a
	 * rejection is astronomically small.
	 *
	 * If it /is/ rejected, then the client has only wasted a tiny
	 * amount of time generating keys that won't be used.
	 */


	// dividerWithText(stderr, "Copy/Paste Msg0||Msg1 Below to SP");
	 msgio->send_partial(&msg0_extended_epid_group_id,
		sizeof(msg0_extended_epid_group_id));
	msgio->send(&msg1, sizeof(msg1));
	// divider(stderr);

	fprintf(stderr, "Waiting for msg2\n");

	/* Read msg2 
	 *
	 * msg2 is variable length b/c it includes the revocation list at
	 * the end. msg2 is malloc'd in readZ_msg do free it when done.
	 */

	rv= msgio->read((void **) &msg2, NULL);
	if ( rv == 0 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "protocol error reading msg2\n");
		delete msgio;
		exit(1);
	} else if ( rv == -1 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "system error occurred while reading msg2\n");
		delete msgio;
		exit(1);
	}

	

	/* Process Msg2, Get Msg3  */
	/* object msg3 is malloc'd by SGX SDK, so remember to free when finished */

	msg3 = NULL;

	status = sgx_ra_proc_msg2(ra_ctx, eid,
		sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2, 
		sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size,
	    &msg3, &msg3_sz);

	free(msg2);

	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_ra_proc_msg2: %08x\n", status);

		delete msgio;
		return 1;
	} 


	msgio->send(msg3, msg3_sz);
	if ( msg3 ) {
		free(msg3);
		msg3 = NULL;
	}
 
	/* Read Msg4 provided by Service Provider, then process */
        
	rv= msgio->read((void **)&msg4, &msg4sz);
	if ( rv == 0 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "protocol error reading msg4\n");
		delete msgio;
		exit(1);
	} else if ( rv == -1 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "system error occurred while reading msg4\n");
		delete msgio;
		exit(1);
	}

	edividerWithText("Enclave Trust Status from Service Provider");

	enclaveTrusted= msg4->status;
	if ( enclaveTrusted == Trusted ) {
		eprintf("Enclave TRUSTED\n");
	}
	else if ( enclaveTrusted == NotTrusted ) {
		eprintf("Enclave NOT TRUSTED\n");
	}
	else if ( enclaveTrusted == Trusted_ItsComplicated ) {
		// Trusted, but client may be untrusted in the future unless it
		// takes action.

		eprintf("Enclave Trust is TRUSTED and COMPLICATED. The client is out of date and\nmay not be trusted in the future depending on the service provider's  policy.\n");
	} else {
		// Not Trusted, but client may be able to take action to become
		// trusted.

		eprintf("Enclave Trust is NOT TRUSTED and COMPLICATED. The client is out of date.\n");
	}

	
	/*
	 * If the enclave is trusted, fetch a hash of the the MK and SK from
	 * the enclave to show proof of a shared secret with the service 
	 * provider.
	 */

	

	free (msg4);
	// enclave_ra_close(eid, &sgxrv, ra_ctx);
	delete msgio;

	return ra_ctx;
}



/*
 * Search for the enclave file and then try and load it.
 */

sgx_status_t sgx_create_enclave_search (const char *filename, const int edebug,
	sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr)
{
	struct stat sb;
	char epath[PATH_MAX];	/* includes NULL */

	/* Is filename an absolute path? */

	if ( filename[0] == '/' ) 
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

	/* Is the enclave in the current working directory? */

	if ( stat(filename, &sb) == 0 )
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

	return SGX_ERROR_UNEXPECTED;
}

int file_in_searchpath (const char *file, const char *search, char *fullpath, 
	size_t len)
{
	char *p, *str;
	size_t rem;
	struct stat sb;

	if ( search == NULL ) return 0;
	if ( strlen(search) == 0 ) return 0;

	str= strdup(search);
	if ( str == NULL ) return 0;

	p= strtok(str, ":");
	while ( p != NULL) {
		size_t lp= strlen(p);

		if ( lp ) {

			strncpy(fullpath, p, len-1);
			rem= (len-1)-lp-1;
			fullpath[len-1]= 0;

			strncat(fullpath, "/", rem);
			--rem;

			strncat(fullpath, file, rem);

			if ( stat(fullpath, &sb) == 0 ) {
				free(str);
				return 1;
			}
		}

		p= strtok(NULL, ":");
	}

	free(str);

	return 0;
}



void usage () 
{
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


