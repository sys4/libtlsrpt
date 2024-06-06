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

#include "tlsrpt.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct tlsrpt_connection_t {
  struct sockaddr_un addr;
  int sock_fd; /* file descriptor of socket */
} tlsrpt_connection_t;

typedef struct tlsrpt_dr_t {
  struct tlsrpt_connection_t *con;
  int status;
  int failure_count;
  int policy_count;

  /* main memstream */
  FILE *memstream;
  char *memstreambuffer;
  size_t memstreamsize;

  /* sub-memstream for policy strings */
  FILE *memstreamps;
  char *memstreambufferps;
  size_t memstreamsizeps;
  const char* separatorps;

  /* sub-memstream for mx host patterns */
  FILE *memstreammx;
  char *memstreambuffermx;
  size_t memstreamsizemx;
  const char* separatormx;

  /* sub-memstream for failure details */
  FILE *memstreamfd;
  char *memstreambufferfd;
  size_t memstreamsizefd;
  const char* separatorfd;

  tlsrpt_policy_type_t policy_type;
} tlsrpt_dr_t;


extern const char *tlsrpt_json_escape_values[256];

#define BUFFER_SIZE 65000

#define DEBUG if(0)

/*
All TLSRPT function return 0 on success or an individual error code:
- errors detected within the TLSRPT c library are returned within the ERR_TLSRPT number block listed below
- errors from standard c library functions are returned as the errno encountered plus one of these constants to identify the syscall that yielded the error and the tlsrpt library function where it occured:
*/
#define ERR_SOCKET 11000
#define ERR_CLOSE 12000
#define ERR_SENDTO 13000
#define ERR_OPEN_MEMSTREAM_INITDR 21000
#define ERR_OPEN_MEMSTREAM_INITPOLICY 22000
#define ERR_FCLOSE_FINISHPOLICY 28000
#define ERR_FCLOSE_FINISHDR 29000
#define ERR_FPRINTF_INITDR 31000
#define ERR_FPRINTF_INITPOLICY 32000
#define ERR_FPRINTF_ADDPOLICYSTRING 33000
#define ERR_FPRINTF_ADDMXHOSTPATTERN 34000
#define ERR_FPRINTF_FINISHPOLICY 35000
#define ERR_FPRINTF_ADDFAILURE 36000
#define ERR_FPRINTF_FINISHDR 37000


/* 
Error codes from the TLSRPT number block:
We return BLOCKNR+errno, but these errors are not forwarding an errno valu from a std clib call we use intentional high numbers so that strerror(errorcode % 1000) does not give misleading results as would be the case for low-range numbers.
*/
#define ERR_TLSRPT 10000 // the designator for the number block, unused within the library because there are no "ERR_TLSRPT+errno" errors, but can be used along with the other block designators to classify an error
#define ERR_TLSRPT_ALREADYSENT 10701 // The datagram was already sent, tlsrpt_finish_delivery_request called twice?
#define ERR_TLSRPT_ALREADYFAILED 10702 // There were previous errors, the first error is in the status field of the request
#define ERR_TLSRPT_CANCELLED 10703 // The request was cancelled via tlsrpt_cancel_delivery_request
#define ERR_TLSRPT_SOCKETNAMETOOLONG 10711 // The name of the unix domain socket was too long
#define ERR_TLSRPT_UNFINISHEDPOLICY 10712 // Call to tlsrpt_init_policy was not properly paired with tlsrpt_finish_policy
#define ERR_TLSRPT_NOCONNECTION 10713 // Connection pointer is NULL
#define ERR_TLSRPT_MEMSTREAM_NOT_INITIALIZED 10721 // an internal memstream was not initialized
#define ERR_TLSRPT_MEMSTREAMPS_NOT_INITIALIZED 10722 // an internal memstream was not initialized
#define ERR_TLSRPT_MEMSTREAMMX_NOT_INITIALIZED 10723 // an internal memstream was not initialized
#define ERR_TLSRPT_MEMSTREAMFD_NOT_INITIALIZED 10724 // an internal memstream was not initialized
#define ERR_TLSRPT_NESTEDPOLICY 10731 // Two calls to tlsrpt_init_policy without properly calling tlsrpt_finish_policy on the first one
#define ERR_TLSRPT_NOPOLICIES 10732 // No policies were added

/* return the error code for the given situation and flag the current delivery request as failed
or just return ERR_TLSRPT_ALREADYFAILED if another error already has occured */
static int errorcode(tlsrpt_dr_t *dr, int errcode) {
  if(dr->status != 0) return ERR_TLSRPT_ALREADYFAILED;
  dr->status=errcode;
  return errcode;
}

int tlsrpt_errno_from_error_code(int errorcode) {
  return errorcode % 1000;
}

#define RETURN_ON_EXISTING_ERRORS  if(dr->status != 0) return ERR_TLSRPT_ALREADYFAILED;

static void __attribute__ ((unused)) die(const char* msg) {
  fprintf(stderr,"ERROR: %s\n",msg);
  exit(2);
}


/* allow for a different malloc implementation */
void* (*tlsrpt_malloc)(size_t size) = malloc;
void (*tlsrpt_free)(void *ptr) = free;

void tlsrpt_set_malloc_and_free(void* (*malloc_function)(size_t size), void (*free_function)(void *ptr)) {
  tlsrpt_malloc=malloc_function;
  tlsrpt_free=free_function;
}


static int json_escape(FILE* file, const char* s) {
  for(const unsigned char *c=(unsigned char*)s; *c!=0; ++c) {
    // DEBUG if((json_escape_values[*c][0])==*c) fprintf(stderr, "_%d ",(int)(*c)); else fprintf(stderr, ">%d ",(int)(*c));
    if(fprintf(file,"%s",tlsrpt_json_escape_values[*c])<0) return -1;
  }
  // DEBUG fprintf(stderr, "EOL\n");
  return 0;
}

static int write_failure_code(FILE *file, const char* name, tlsrpt_failure_t failure_code) {
  if(fprintf(file, "\"%s\":%d", name, failure_code)<0) return -1;
  return 0;
}

/* Writes the first attribute of a JSON list without a leading "," separator */
static int write_first_attribute(FILE *file, const char* name, const char* value) {
  if(fprintf(file, "\"%s\": \"", name)<0) return -1;
  if(json_escape(file, value)<0) return -1;
  if(fprintf(file, "\"")<0) return -1;
  return 0;
}

/* Writes an additional attribute of a JSON list prepended by a "," separator */
static int write_attribute(FILE *file, const char* name, const char* value) {
  if(fprintf(file,",")<0) return -1;
  return write_first_attribute(file, name, value);
}

/* Writes an additional attribute of a JSON list prepended by a "," separator only if value is not NULL */
static int write_attribute_if_not_null(FILE *file, const char* name, const char* value) {
  if(value==NULL) return 0;
  return write_attribute(file, name, value);
}

static int _tlsrpt_open(struct tlsrpt_connection_t* con, const char* socketname) {
  /*  no calls to errorcode from this function because we have no tlsrpt_dr struct yet to record the error */

  /* Clear the whole structure */
  memset(&con->addr, 0, sizeof(struct sockaddr_un));

  /* Create local socket */
  con->sock_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (con->sock_fd == -1) {
    return ERR_SOCKET+errno;
  }

  /* Set destination address */
  con->addr.sun_family = AF_UNIX;
  strncpy(con->addr.sun_path, socketname, sizeof(con->addr.sun_path) - 1);
  if(strlen(socketname)>sizeof(con->addr.sun_path) - 1) return ERR_TLSRPT_SOCKETNAMETOOLONG;

  return 0;
}

static int _tlsrpt_close(struct tlsrpt_connection_t* con) {
  /*  no calls to errorcode from this function because we have no tlsrpt_dr struct to record the error */
  int res = 0;
  memset(&con->addr, 0, sizeof(struct sockaddr_un));
  if(con->sock_fd!=-1) {
    res = close(con->sock_fd);
    con->sock_fd=-1;
    if(res != 0) return ERR_CLOSE+errno;
  }
  return 0;
}

struct tlsrpt_connection_t* tlsrpt_open(const char* socketname) {
  struct tlsrpt_connection_t* ptr=(struct tlsrpt_connection_t*)tlsrpt_malloc(sizeof(struct tlsrpt_connection_t));
  int res=_tlsrpt_open(ptr, socketname);
  if(res==0) return ptr;
  // clean up
  tlsrpt_close(ptr);
  return NULL;
}

void tlsrpt_close(struct tlsrpt_connection_t* con) {
  _tlsrpt_close(con);
  tlsrpt_free(con);
}

/* Index of json keys

a : failure_details.additional_information
c : failure_details.failure_code
f : failure_details.failure_reason_code
h : failure_details.receiving_mx_helo
n : failure_details.receiving_mx_hostname
r : failure_details.receiving_ip
s : failure_details.sending_mta_ip
*/

static void reset_sub_memstreams(tlsrpt_dr_t *dr) {
  /* sub-memstream for policy strings */
  dr->separatorps="";
  dr->memstreamps=NULL;
  dr->memstreambufferps=NULL;
  dr->memstreamsizeps=0;

  /* sub-memstream for mx host patterns */
  dr->separatormx="";
  dr->memstreammx=NULL;
  dr->memstreambuffermx=NULL;
  dr->memstreamsizemx=0;

  /* sub-memstream for failure details */
  dr->separatorfd="";
  dr->memstreamfd=NULL;
  dr->memstreambufferfd=NULL;
  dr->memstreamsizefd=0;
}

static int _tlsrpt_init_delivery_request(tlsrpt_dr_t *dr, tlsrpt_connection_t* con, const char* domainname) {
  int res=0;
  dr->status=0;
  dr->con=con;
  dr->failure_count=0;
  dr->policy_count=0;

  reset_sub_memstreams(dr);

  /* main memstream */
  dr->memstreambuffer=NULL;
  dr->memstreamsize=0;
  dr->memstream=open_memstream(&dr->memstreambuffer, &dr->memstreamsize);
  if(dr->memstream==NULL) return errorcode(dr, ERR_OPEN_MEMSTREAM_INITDR+errno);
  res=fprintf(dr->memstream, "{");
  if(res<0) return errorcode(dr, ERR_FPRINTF_INITDR+errno);
  res=write_first_attribute(dr->memstream, "d", domainname);
  if(res<0) return errorcode(dr, ERR_FPRINTF_INITDR+errno);

  if(dr->con==NULL) return errorcode(dr,ERR_TLSRPT_NOCONNECTION);

  return 0;
}

int tlsrpt_init_policy(struct tlsrpt_dr_t* dr, tlsrpt_policy_type_t policy_type, const char* policydomainname) {
  int res=0;

  RETURN_ON_EXISTING_ERRORS;
  
  reset_sub_memstreams(dr);

  /* Check if we are already within a policy! */
  if(dr->memstreamps!=NULL) return errorcode(dr, ERR_TLSRPT_NESTEDPOLICY);

  /* sub-memstream for policy strings */
  dr->memstreamps=open_memstream(&dr->memstreambufferps, &dr->memstreamsizeps);
  if(dr->memstreamps==NULL) return errorcode(dr, ERR_OPEN_MEMSTREAM_INITPOLICY+errno);
  /* sub-memstream for mx host patterns */
  dr->memstreammx=open_memstream(&dr->memstreambuffermx, &dr->memstreamsizemx);
  if(dr->memstreammx==NULL) return errorcode(dr, ERR_OPEN_MEMSTREAM_INITPOLICY+errno);
  /* sub-memstream for failure details */
  dr->memstreamfd=open_memstream(&dr->memstreambufferfd, &dr->memstreamsizefd);
  if(dr->memstreamfd==NULL) return errorcode(dr, ERR_OPEN_MEMSTREAM_INITPOLICY+errno);

  dr->policy_type=policy_type;

  if(dr->policy_count==0) {
    res = fprintf(dr->memstream, "\n,\"policies\":[{");
  } else {
    res = fprintf(dr->memstream, "\n,{");
  }
  if(res<0) return errorcode(dr, ERR_FPRINTF_INITPOLICY+errno);

  res = fprintf(dr->memstream, "\"policy-type\":%d", dr->policy_type);
  if(res<0) return errorcode(dr, ERR_FPRINTF_INITPOLICY+errno);
  res=write_attribute_if_not_null(dr->memstream, "policy-domain", policydomainname);
  if(res<0) return errorcode(dr, ERR_FPRINTF_INITPOLICY+errno);
  ++dr->policy_count;

  return 0;
}

int tlsrpt_add_policy_string(struct tlsrpt_dr_t* dr, const char* policy_string) {
  int res=0;

  RETURN_ON_EXISTING_ERRORS;

  res=fprintf(dr->memstreamps,"%s\"",dr->separatorps);
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDPOLICYSTRING+errno);

  res=json_escape(dr->memstreamps,policy_string);
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDPOLICYSTRING+errno);

  res=fprintf(dr->memstreamps,"\"");
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDPOLICYSTRING+errno);

  dr->separatorps=",";
  return 0;
}

int tlsrpt_add_mx_host_pattern(struct tlsrpt_dr_t* dr, const char* mx_host_pattern) {
  int res=0;

  RETURN_ON_EXISTING_ERRORS;

  res=fprintf(dr->memstreammx,"%s\"",dr->separatormx);
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDMXHOSTPATTERN+errno);

  res=json_escape(dr->memstreammx,mx_host_pattern);
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDMXHOSTPATTERN+errno);

  res=fprintf(dr->memstreammx,"\"");
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDMXHOSTPATTERN+errno);

  dr->separatormx=",";
  return 0;
}

int tlsrpt_finish_policy(struct tlsrpt_dr_t* dr, tlsrpt_final_result_t final_result) {
  int res=0;
  /*
Throughout this function the errorcode is never returned prematurely!
We need to go through all steps of cleaning up!
Calls to errorcode will record the errorcode in the tlsrpt_dr_t structure.
   */
  if(dr->memstreamps!=NULL) {
    res=fclose(dr->memstreamps);
    if(res!=0) errorcode(dr, ERR_FCLOSE_FINISHPOLICY+errno);
  } else {
    errorcode(dr,ERR_TLSRPT_MEMSTREAMPS_NOT_INITIALIZED);
  }
  if(dr->memstreammx!=NULL) {
    res=fclose(dr->memstreammx);
    if(res!=0) errorcode(dr, ERR_FCLOSE_FINISHPOLICY+errno);
  } else {
    errorcode(dr,ERR_TLSRPT_MEMSTREAMMX_NOT_INITIALIZED);
  }
  if(dr->memstreamfd!=NULL) {
    res=fclose(dr->memstreamfd);
    if(res!=0) errorcode(dr, ERR_FCLOSE_FINISHPOLICY+errno);
  } else {
    errorcode(dr,ERR_TLSRPT_MEMSTREAMFD_NOT_INITIALIZED);
  }

  if(dr->memstream!=NULL) {
    if(dr->memstreamsizeps>0) res = fprintf(dr->memstream, ",\"policy-string\":[%s]", dr->memstreambufferps);
    if(res<0) return errorcode(dr, ERR_FPRINTF_FINISHPOLICY+errno);
    if(dr->memstreamsizemx>0) res = fprintf(dr->memstream, ",\"mx-host\":[%s]", dr->memstreambuffermx);
    if(res<0) return errorcode(dr, ERR_FPRINTF_FINISHPOLICY+errno);
    if(dr->memstreamsizefd>0) res = fprintf(dr->memstream, ",\"failure-details\":[%s]", dr->memstreambufferfd);
    if(res<0) return errorcode(dr, ERR_FPRINTF_FINISHPOLICY+errno);

    res=fprintf(dr->memstream, ",\"t\":%d,\"f\":%d}", dr->failure_count, final_result);
    if(res<0) return errorcode(dr, ERR_FPRINTF_FINISHPOLICY+errno);
  } else {
    errorcode(dr,ERR_TLSRPT_MEMSTREAM_NOT_INITIALIZED);
  }

  free(dr->memstreambufferps);
  free(dr->memstreambuffermx);
  free(dr->memstreambufferfd);
  reset_sub_memstreams(dr);
  return dr->status; /* errorcode of first error that has occured or zero when no error hapened */
}


int tlsrpt_add_delivery_request_failure(struct tlsrpt_dr_t* dr, tlsrpt_failure_t failure_code,
 const char* sending_mta_ip,
 const char* receiving_mx_hostname,
 const char* receiving_mx_helo,
 const char* receiving_ip,
 const char* additional_information,
 const char* failure_reason_code) {
  int res=0;

  RETURN_ON_EXISTING_ERRORS;

  dr->failure_count+=1;

  res=fprintf(dr->memstreamfd,"%s",dr->separatorfd);
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDFAILURE+errno);
  res=fprintf(dr->memstreamfd,"{");
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDFAILURE+errno);
  res=write_failure_code(dr->memstreamfd, "c", failure_code);
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDFAILURE+errno);

  res=write_attribute_if_not_null(dr->memstreamfd, "s", sending_mta_ip);
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDFAILURE+errno);
  res=write_attribute_if_not_null(dr->memstreamfd, "n", receiving_mx_hostname);
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDFAILURE+errno);
  res=write_attribute_if_not_null(dr->memstreamfd, "h", receiving_mx_helo);
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDFAILURE+errno);
  res=write_attribute_if_not_null(dr->memstreamfd, "r", receiving_ip);
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDFAILURE+errno);
  res=write_attribute_if_not_null(dr->memstreamfd, "a", additional_information);
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDFAILURE+errno);
  res=write_attribute_if_not_null(dr->memstreamfd, "f", failure_reason_code);
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDFAILURE+errno);

  res=fprintf(dr->memstreamfd,"}");
  if(res<0) return errorcode(dr, ERR_FPRINTF_ADDFAILURE+errno);
  dr->separatorfd=",";
  return 0;
}

/*
 The sending datagram socket is set to non-blocking in normal operation.
But for debugging and benchmarking purposes it might be useful to set it to blocking.
These two functiosn allow switching the blocking configuration.
*/

static int tlsrpt_sendto_flags=MSG_DONTWAIT;

void tlsrpt_set_blocking() {
  tlsrpt_sendto_flags&=~MSG_DONTWAIT;
}

void tlsrpt_set_nonblocking() {
  tlsrpt_sendto_flags|=MSG_DONTWAIT;
}

/* BEGIN DEBUG tools */
int totalsenderr=0;
int dbgnumber=999;

void debugdumpdatagram(const char* fn, const char* dgram) {
  FILE *dbg=fopen(fn,"w");
  fprintf(dbg,"%s",dgram);
  fclose(dbg);
}

void debug_datagram_hook(void* data) {
  char dbgname[1024];
  snprintf(dbgname,1023,"/tmp/datagram-%02d",dbgnumber);
  debugdumpdatagram(dbgname,data);
  debugdumpdatagram("/tmp/datagram",data);
}
/* END DEBUG TOOLS */

/* Set this request to cancelled and clean up everything by calling tlsrpt_finish_delivery_request. */
static void _tlsrpt_cancel_delivery_request(struct tlsrpt_dr_t* dr) {
  errorcode(dr, ERR_TLSRPT_CANCELLED);
  tlsrpt_finish_delivery_request(dr);
}

/* Finish a delivery request. Cleans up everything and only sends out the datagram if no errors were encountered. */
static int _tlsrpt_finish_delivery_request(tlsrpt_dr_t *dr) {
  /*
Throughout this function the errorcode is never returned prematurely!
We need to go through all steps of cleaning up.
Calls to errorcode will record the errorcode in the tlsrpt_dr_t structure, but there is no "return errorcode(...)" statement.
   */
  int res=0;

  if(dr->con==NULL) {
    errorcode(dr,ERR_TLSRPT_NOCONNECTION);
  }

  /* Check if finish_policy was called properly and clean up left-overs otherwise */
  if(dr->memstreamps != NULL) {
    errorcode(dr, ERR_TLSRPT_UNFINISHEDPOLICY);
    tlsrpt_finish_policy(dr,TLSRPT_UNFINISHED_POLICY);
  }

  if(dr->policy_count>0) {
    res=fprintf(dr->memstream, "]");
    if(res<0) errorcode(dr,ERR_FPRINTF_FINISHDR+errno);
  } else {
    errorcode(dr, ERR_TLSRPT_NOPOLICIES);
  }

  res=fprintf(dr->memstream, "}");
  if(res<0) errorcode(dr,ERR_FPRINTF_FINISHDR+errno);

  res=fclose(dr->memstream);
  if(res!=0) errorcode(dr,ERR_FCLOSE_FINISHDR+errno);

  if(dr->status == 0) { // everything looks fine, we can send the datagram
    res = sendto(dr->con->sock_fd, dr->memstreambuffer, dr->memstreamsize,
		 tlsrpt_sendto_flags, (const struct sockaddr *) &dr->con->addr,
		 sizeof(struct sockaddr_un));
    if(res<0) errorcode(dr,ERR_SENDTO+errno);
  }

  DEBUG debug_datagram_hook(dr->memstreambuffer);

  free(dr->memstreambuffer);
  int finalresult=dr->status;
  errorcode(dr,ERR_TLSRPT_ALREADYSENT);
  return finalresult;
}


struct tlsrpt_dr_t* tlsrpt_init_delivery_request(struct tlsrpt_connection_t* con, const char* domainname) {
  struct tlsrpt_dr_t* ptr=(struct tlsrpt_dr_t*)tlsrpt_malloc(sizeof(struct tlsrpt_dr_t));
  int res=_tlsrpt_init_delivery_request(ptr, con, domainname);
  if(res==0) return ptr;
  // clean up
  tlsrpt_cancel_delivery_request(ptr);
  return NULL;
}

void tlsrpt_cancel_delivery_request(struct tlsrpt_dr_t* dr) {
  _tlsrpt_cancel_delivery_request(dr);
  tlsrpt_free(dr);
}

int tlsrpt_finish_delivery_request(struct tlsrpt_dr_t* dr) {
  int res=_tlsrpt_finish_delivery_request(dr);
  tlsrpt_free(dr);
  return res;
}

