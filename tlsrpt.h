/*
    Copyright (C) 2024 sys4 AG
    Author Boris Lohner bl@sys4.de

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this program.
    If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _TLSRPT_H
#define _TLSRPT_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdlib.h>
  
#define TLSRPT_MAXDOMAINNAMELEN 256

typedef enum {
  TLSRPT_POLICY_TLSA = 1,
  TLSRPT_POLICY_STS = 2,
  TLSRPT_NO_POLICY_FOUND = 9
} tlsrpt_policy_type_t;

typedef enum {
  TLSRPT_FINAL_SUCCESS = 0,
  TLSRPT_FINAL_FAILURE = 1
} tlsrpt_final_result_t;

typedef enum {
  /* TLS negotiation failures */
  TLSRPT_STARTTLS_NOT_SUPPORTED = 201,
  TLSRPT_CERTIFICATE_HOST_MISMATCH = 202,
  TLSRPT_CERTIFICATE_NOT_TRUSTED = 203,
  TLSRPT_CERTIFICATE_EXPIRED = 204,
  TLSRPT_VALIDATION_FAILURE = 205,

  /* MTA-STS related failures */
  TLSRPT_STS_POLICY_FETCH_ERROR = 301,
  TLSRPT_STS_POLICY_INVALID = 302,
  TLSRPT_STS_WEBPKI_INVALID = 303,

  /* DNS related failures */
  TLSRPT_TLSA_INVALID = 304,
  TLSRPT_DNSSEC_INVALID = 305,
  TLSRPT_DANE_REQUIRED = 306,

  /* Internal library errors, only used within the library */
  TLSRPT_UNFINISHED_POLICY = 901

} tlsrpt_failure_t;


struct tlsrpt_connection_t;
struct tlsrpt_dr_t;

/* Handling of the connection */
int tlsrpt_open(struct tlsrpt_connection_t** pcon, const char* socketname);
int tlsrpt_close(struct tlsrpt_connection_t** pcon);

/* Handling of a single delivery request, an open connection is required */
  int tlsrpt_init_delivery_request(struct tlsrpt_dr_t** pdr, struct tlsrpt_connection_t* con, const char* domainname, const char* policyrecord);
int tlsrpt_cancel_delivery_request(struct tlsrpt_dr_t** pdr);
int tlsrpt_finish_delivery_request(struct tlsrpt_dr_t** pdr);

/* Handling of a policy within a delivery request, an initialized delivery request object is required */
int tlsrpt_init_policy(struct tlsrpt_dr_t* dr, tlsrpt_policy_type_t policy_type, const char* policydomainname);
int tlsrpt_finish_policy(struct tlsrpt_dr_t* dr, tlsrpt_final_result_t final_result);

/* Defining the policy details, an initialized delivery request object with an initialized policy is required */
int tlsrpt_add_policy_string(struct tlsrpt_dr_t* dr, const char* policy_string);
int tlsrpt_add_mx_host_pattern(struct tlsrpt_dr_t* dr, const char* mx_host_pattern);

/* Reporting a failure during a delivery request, an initialized delivery request object with an initialized policy is required */
int tlsrpt_add_delivery_request_failure(struct tlsrpt_dr_t* dr, tlsrpt_failure_t failure_code, const char* sending_mta_ip,
 const char* receiving_mx_hostname,
 const char* receiving_mx_helo,
 const char* receiving_ip,
 const char* additional_information,
 const char* failure_reason_code);


/* Error handling */

/*
All TLSRPT functions return 0 on success or an individual error code:
- errors detected within the TLSRPT c library are returned within the TLSRPT_ERR_TLSRPT number block listed below
- errors from standard c library functions are returned as the errno encountered plus one of these constants to identify the syscall that yielded the error and the tlsrpt library function where it occured:
*/
#define TLSRPT_ERR_SOCKET 11000
#define TLSRPT_ERR_CLOSE 12000
#define TLSRPT_ERR_SENDTO 13000
#define TLSRPT_ERR_OPEN_MEMSTREAM_INITDR 21000
#define TLSRPT_ERR_OPEN_MEMSTREAM_INITPOLICY 22000
#define TLSRPT_ERR_FCLOSE_FINISHPOLICY 28000
#define TLSRPT_ERR_FCLOSE_FINISHDR 29000
#define TLSRPT_ERR_FPRINTF_INITDR 31000
#define TLSRPT_ERR_FPRINTF_INITPOLICY 32000
#define TLSRPT_ERR_FPRINTF_ADDPOLICYSTRING 33000
#define TLSRPT_ERR_FPRINTF_ADDMXHOSTPATTERN 34000
#define TLSRPT_ERR_FPRINTF_FINISHPOLICY 35000
#define TLSRPT_ERR_FPRINTF_ADDFAILURE 36000
#define TLSRPT_ERR_FPRINTF_FINISHDR 37000
#define TLSRPT_ERR_MALLOC_OPENCON 41000
#define TLSRPT_ERR_MALLOC_OPENDR 42000


/*
Error codes from the TLSRPT number block:
The error codes are usually BLOCKNR+errno, but because these internal library errors are not forwarding an errno value from a std clib call we use intentional high numbers so that strerror(errorcode % 1000) does not give misleading results as would be the case for low-range numbers. This is less an issue when using the proper functions to analyze the error code, but still useful when reading the error codes.
*/
#define TLSRPT_ERR_TLSRPT 10000 // the designator for the number block used for internal errors, never returned as a result
#define TLSRPT_ERR_TLSRPT_CANCELLED 10703 // The request was cancelled via tlsrpt_cancel_delivery_request
#define TLSRPT_ERR_TLSRPT_SOCKETNAMETOOLONG 10711 // The name of the unix domain socket was too long
#define TLSRPT_ERR_TLSRPT_UNFINISHEDPOLICY 10712 // Call to tlsrpt_init_policy was not properly paired with tlsrpt_finish_policy
#define TLSRPT_ERR_TLSRPT_NOCONNECTION 10713 // Connection pointer is NULL
#define TLSRPT_ERR_TLSRPT_MEMSTREAM_NOT_INITIALIZED 10721 // an internal memstream was not initialized
#define TLSRPT_ERR_TLSRPT_MEMSTREAMPS_NOT_INITIALIZED 10722 // an internal memstream was not initialized
#define TLSRPT_ERR_TLSRPT_MEMSTREAMMX_NOT_INITIALIZED 10723 // an internal memstream was not initialized
#define TLSRPT_ERR_TLSRPT_MEMSTREAMFD_NOT_INITIALIZED 10724 // an internal memstream was not initialized
#define TLSRPT_ERR_TLSRPT_NESTEDPOLICY 10731 // Two calls to tlsrpt_init_policy without properly calling tlsrpt_finish_policy on the first one
#define TLSRPT_ERR_TLSRPT_NOPOLICIES 10732 // No policies were added

int tlsrpt_errno_from_error_code(int errorcode);
int tlsrpt_error_code_is_internal(int errorcode);
const char* tlsrpt_strerror(int errorcode);


/* Debug and development tools */
void tlsrpt_set_blocking();
void tlsrpt_set_nonblocking();
int tlsrpt_get_socket(struct tlsrpt_connection_t* con);

/* Chosing a different malloc implementation */
void tlsrpt_set_malloc_and_free(void* (*malloc_function)(size_t size), void (*free_function)(void *ptr));

#ifdef __cplusplus
}
#endif

#endif /* _TLSRPT_H */
