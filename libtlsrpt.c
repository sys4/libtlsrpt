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


/* flag the current delivery request as failed if it wasn´t failed already and return the old or new error code */
static int errorcode(tlsrpt_dr_t *dr, int errcode) {
  if(dr->status == 0) dr->status=errcode;
  return errcode;
}

/* Extracts the errno part from an error code */
int tlsrpt_errno_from_error_code(int errorcode) {
  return errorcode % 1000;
}

/* Returns 1 if the error code is an internal tlsrpt library error or 0 if the errno part is a errno value from libc */
int tlsrpt_error_code_is_internal(int errorcode) {
  return ((errorcode-tlsrpt_errno_from_error_code(errorcode))==TLSRPT_ERR_TLSRPT)?1:0;
}

#define INTERNAL_ERROR_STRERROR_PREFIX "TLSRPT internal library error: "
/* Returns a string describing the internal error or the context of a libc error: the libc function call and from which TLSRPT function it was called if there is more than one call */
const char* tlsrpt_strerror(int errorcode) {
  if(!tlsrpt_error_code_is_internal(errorcode)) { // reduce libc errors to their number block
    errorcode = errorcode - tlsrpt_errno_from_error_code(errorcode);
  }
  
  switch(errorcode) {
    // internal errors
    // TLSRPT_ERR_TLSRPT is the internal library error block begin, this code is not returned by any function
  case TLSRPT_ERR_TLSRPT_CANCELLED: return INTERNAL_ERROR_STRERROR_PREFIX "The request was cancelled via tlsrpt_cancel_delivery_request";
  case TLSRPT_ERR_TLSRPT_SOCKETNAMETOOLONG: return INTERNAL_ERROR_STRERROR_PREFIX "The name of the unix domain socket was too long";
  case TLSRPT_ERR_TLSRPT_UNFINISHEDPOLICY: return INTERNAL_ERROR_STRERROR_PREFIX "Call to tlsrpt_init_policy was not properly paired with tlsrpt_finish_policy";
  case TLSRPT_ERR_TLSRPT_NOCONNECTION: return INTERNAL_ERROR_STRERROR_PREFIX "Connection pointer is NULL";
  case TLSRPT_ERR_TLSRPT_MEMSTREAM_NOT_INITIALIZED: return INTERNAL_ERROR_STRERROR_PREFIX "The internal main memstream was not initialized";
  case TLSRPT_ERR_TLSRPT_MEMSTREAMPS_NOT_INITIALIZED: return INTERNAL_ERROR_STRERROR_PREFIX "The internal ps memstream was not initialized";
  case TLSRPT_ERR_TLSRPT_MEMSTREAMMX_NOT_INITIALIZED: return INTERNAL_ERROR_STRERROR_PREFIX "The internal mx memstream was not initialized";
  case TLSRPT_ERR_TLSRPT_MEMSTREAMFD_NOT_INITIALIZED: return INTERNAL_ERROR_STRERROR_PREFIX "The internal fd memstream was not initialized";
  case TLSRPT_ERR_TLSRPT_NESTEDPOLICY: return INTERNAL_ERROR_STRERROR_PREFIX "Two calls to tlsrpt_init_policy without properly calling tlsrpt_finish_policy on the first one";
  case TLSRPT_ERR_TLSRPT_NOPOLICIES: return INTERNAL_ERROR_STRERROR_PREFIX "No policies were added";
    // errors from the C-library
  case TLSRPT_ERR_SOCKET: return "TLSRPT error in call to socket in tlsrpt_open";
  case TLSRPT_ERR_CLOSE: return "TLSRPT error in call to close in tlsrpt_close";
  case TLSRPT_ERR_SENDTO: return "TLSRPT error in call to sendto in finishdr";
  case TLSRPT_ERR_OPEN_MEMSTREAM_INITDR: return "TLSRPT error in call to open_memstream in initdr";
  case TLSRPT_ERR_OPEN_MEMSTREAM_INITPOLICY: return "TLSRPT error in call to open_memstream in initpolicy";
  case TLSRPT_ERR_FCLOSE_FINISHPOLICY: return "TLSRPT error in call to fclose in finishpolicy";
  case TLSRPT_ERR_FCLOSE_FINISHDR: return "TLSRPT error in call to fclose in finishdr";
  case TLSRPT_ERR_FPRINTF_INITDR: return "TLSRPT error in call to fprintf in initdr";
  case TLSRPT_ERR_FPRINTF_INITPOLICY: return "TLSRPT error in call to fprintf in initpolicy";
  case TLSRPT_ERR_FPRINTF_ADDPOLICYSTRING: return "TLSRPT error in call to fprintf in addpolicystring";
  case TLSRPT_ERR_FPRINTF_ADDMXHOSTPATTERN: return "TLSRPT error in call to fprintf in addmxhostpattern";
  case TLSRPT_ERR_FPRINTF_FINISHPOLICY: return "TLSRPT error in call to fprintf in finishpolicy";
  case TLSRPT_ERR_FPRINTF_ADDFAILURE: return "TLSRPT error in call to fprintf in addfailure";
  case TLSRPT_ERR_FPRINTF_FINISHDR: return "TLSRPT error in call to fprintf in finishdr";
  case TLSRPT_ERR_MALLOC_OPENCON: return "TLSRPT error in call to malloc in opencon";
  case TLSRPT_ERR_MALLOC_OPENDR: return "TLSRPT error in call to malloc in opendr";
  default:
    return "UNKNOWN TLSRPT ERROR CODE";
  }
}


#define RETURN_ON_EXISTING_ERRORS  if(dr->status != 0) return dr->status;


/* allow for a different malloc implementation */
void* (*tlsrpt_malloc)(size_t size) = malloc;
void (*tlsrpt_free)(void *ptr) = free;

void tlsrpt_set_malloc_and_free(void* (*malloc_function)(size_t size), void (*free_function)(void *ptr)) {
  tlsrpt_malloc=malloc_function;
  tlsrpt_free=free_function;
}


/* Write a JSON-escaped value to a file */
static int json_escape(FILE* file, const char* s) {
  for(const unsigned char *c=(unsigned char*)s; *c!=0; ++c) {
    if(fprintf(file,"%s",tlsrpt_json_escape_values[*c])<0) return -1;
  }
  return 0;
}

/* write a key/value pair with a numeric failure code value to a file */
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

static int tlsrpt_open_prepare_struct(struct tlsrpt_connection_t* con, const char* socketname) {
  /*  no calls to errorcode from this function because we have no tlsrpt_dr struct yet to record the error */

  /* Clear the socket address structure */
  memset(&con->addr, 0, sizeof(struct sockaddr_un));
  con->sock_fd = -1;

  /* Set destination address */
  if(strlen(socketname)>sizeof(con->addr.sun_path) - 1) return TLSRPT_ERR_TLSRPT_SOCKETNAMETOOLONG;
  con->addr.sun_family = AF_UNIX;
  strncpy(con->addr.sun_path, socketname, sizeof(con->addr.sun_path) - 1);

  /* Create local socket */
  con->sock_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (con->sock_fd == -1) {
    return TLSRPT_ERR_SOCKET+errno;
  }

  return 0;
}

int tlsrpt_close(struct tlsrpt_connection_t** pcon) {
  /*  no calls to errorcode from this function because we have no tlsrpt_dr struct to record the error */
  int res = 0;
  struct tlsrpt_connection_t* con=*pcon;
  memset(&con->addr, 0, sizeof(struct sockaddr_un));
  if(con->sock_fd!=-1) {
    res = close(con->sock_fd);
    con->sock_fd=-1;
    if(res != 0) res=TLSRPT_ERR_CLOSE+errno;
  }
  tlsrpt_free(con);
  *pcon=NULL;
  return res;
}

int tlsrpt_open(struct tlsrpt_connection_t** pcon, const char* socketname) {
  *pcon=NULL;
  struct tlsrpt_connection_t* ptr=(struct tlsrpt_connection_t*)tlsrpt_malloc(sizeof(struct tlsrpt_connection_t));
  if(ptr==NULL) return TLSRPT_ERR_MALLOC_OPENCON+errno;

  int res=tlsrpt_open_prepare_struct(ptr, socketname);
  if(res==0) {
    *pcon=ptr;
    return 0;
  }
  // clean up
  tlsrpt_close(&ptr);
  return res;
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
  /* sub_memstreams are resetted for a new policy, therefore also reset failure_count */
  dr->failure_count=0;

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

static int tlsrpt_init_delivery_request_prepare_struct(tlsrpt_dr_t *dr, tlsrpt_connection_t* con, const char* domainname, const char* policyrecord) {
  int res=0;
  dr->status=0;
  dr->con=con;
  dr->policy_count=0;

  reset_sub_memstreams(dr);

  /* main memstream */
  dr->memstreambuffer=NULL;
  dr->memstreamsize=0;
  dr->memstream=open_memstream(&dr->memstreambuffer, &dr->memstreamsize);
  if(dr->memstream==NULL) return errorcode(dr, TLSRPT_ERR_OPEN_MEMSTREAM_INITDR+errno);
  res=fprintf(dr->memstream, "{");
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_INITDR+errno);
  res=write_first_attribute(dr->memstream, "d", domainname);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_INITDR+errno);
  res=write_attribute(dr->memstream, "pr", policyrecord);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_INITDR+errno);

  if(dr->con==NULL) return errorcode(dr,TLSRPT_ERR_TLSRPT_NOCONNECTION);

  return 0;
}

int tlsrpt_init_policy(struct tlsrpt_dr_t* dr, tlsrpt_policy_type_t policy_type, const char* policydomainname) {
  int res=0;

  RETURN_ON_EXISTING_ERRORS;

  /* Check if we are already within a policy before resetting the memstreams! */
  if(dr->memstreamps!=NULL) return errorcode(dr, TLSRPT_ERR_TLSRPT_NESTEDPOLICY);

  reset_sub_memstreams(dr);

  /* sub-memstream for policy strings */
  dr->memstreamps=open_memstream(&dr->memstreambufferps, &dr->memstreamsizeps);
  if(dr->memstreamps==NULL) return errorcode(dr, TLSRPT_ERR_OPEN_MEMSTREAM_INITPOLICY+errno);
  /* sub-memstream for mx host patterns */
  dr->memstreammx=open_memstream(&dr->memstreambuffermx, &dr->memstreamsizemx);
  if(dr->memstreammx==NULL) return errorcode(dr, TLSRPT_ERR_OPEN_MEMSTREAM_INITPOLICY+errno);
  /* sub-memstream for failure details */
  dr->memstreamfd=open_memstream(&dr->memstreambufferfd, &dr->memstreamsizefd);
  if(dr->memstreamfd==NULL) return errorcode(dr, TLSRPT_ERR_OPEN_MEMSTREAM_INITPOLICY+errno);

  dr->policy_type=policy_type;

  if(dr->policy_count==0) {
    res = fprintf(dr->memstream, ",\"policies\":[{");
  } else {
    res = fprintf(dr->memstream, ",{");
  }
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_INITPOLICY+errno);

  res = fprintf(dr->memstream, "\"policy-type\":%d", dr->policy_type);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_INITPOLICY+errno);
  res=write_attribute_if_not_null(dr->memstream, "policy-domain", policydomainname);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_INITPOLICY+errno);
  ++dr->policy_count;

  return 0;
}

int tlsrpt_add_policy_string(struct tlsrpt_dr_t* dr, const char* policy_string) {
  int res=0;

  RETURN_ON_EXISTING_ERRORS;

  res=fprintf(dr->memstreamps,"%s\"",dr->separatorps);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDPOLICYSTRING+errno);

  res=json_escape(dr->memstreamps,policy_string);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDPOLICYSTRING+errno);

  res=fprintf(dr->memstreamps,"\"");
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDPOLICYSTRING+errno);

  dr->separatorps=",";
  return 0;
}

int tlsrpt_add_mx_host_pattern(struct tlsrpt_dr_t* dr, const char* mx_host_pattern) {
  int res=0;

  RETURN_ON_EXISTING_ERRORS;

  res=fprintf(dr->memstreammx,"%s\"",dr->separatormx);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDMXHOSTPATTERN+errno);

  res=json_escape(dr->memstreammx,mx_host_pattern);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDMXHOSTPATTERN+errno);

  res=fprintf(dr->memstreammx,"\"");
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDMXHOSTPATTERN+errno);

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
    if(res!=0) errorcode(dr, TLSRPT_ERR_FCLOSE_FINISHPOLICY+errno);
  } else {
    errorcode(dr,TLSRPT_ERR_TLSRPT_MEMSTREAMPS_NOT_INITIALIZED);
  }
  if(dr->memstreammx!=NULL) {
    res=fclose(dr->memstreammx);
    if(res!=0) errorcode(dr, TLSRPT_ERR_FCLOSE_FINISHPOLICY+errno);
  } else {
    errorcode(dr,TLSRPT_ERR_TLSRPT_MEMSTREAMMX_NOT_INITIALIZED);
  }
  if(dr->memstreamfd!=NULL) {
    res=fclose(dr->memstreamfd);
    if(res!=0) errorcode(dr, TLSRPT_ERR_FCLOSE_FINISHPOLICY+errno);
  } else {
    errorcode(dr,TLSRPT_ERR_TLSRPT_MEMSTREAMFD_NOT_INITIALIZED);
  }

  if(dr->memstream!=NULL) {
    if(dr->memstreamsizeps>0) res = fprintf(dr->memstream, ",\"policy-string\":[%s]", dr->memstreambufferps);
    if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_FINISHPOLICY+errno);
    if(dr->memstreamsizemx>0) res = fprintf(dr->memstream, ",\"mx-host\":[%s]", dr->memstreambuffermx);
    if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_FINISHPOLICY+errno);
    if(dr->memstreamsizefd>0) res = fprintf(dr->memstream, ",\"failure-details\":[%s]", dr->memstreambufferfd);
    if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_FINISHPOLICY+errno);

    res=fprintf(dr->memstream, ",\"t\":%d,\"f\":%d}", dr->failure_count, final_result);
    if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_FINISHPOLICY+errno);
  } else {
    errorcode(dr,TLSRPT_ERR_TLSRPT_MEMSTREAM_NOT_INITIALIZED);
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
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDFAILURE+errno);
  res=fprintf(dr->memstreamfd,"{");
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDFAILURE+errno);
  res=write_failure_code(dr->memstreamfd, "c", failure_code);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDFAILURE+errno);

  res=write_attribute_if_not_null(dr->memstreamfd, "s", sending_mta_ip);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDFAILURE+errno);
  res=write_attribute_if_not_null(dr->memstreamfd, "n", receiving_mx_hostname);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDFAILURE+errno);
  res=write_attribute_if_not_null(dr->memstreamfd, "h", receiving_mx_helo);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDFAILURE+errno);
  res=write_attribute_if_not_null(dr->memstreamfd, "r", receiving_ip);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDFAILURE+errno);
  res=write_attribute_if_not_null(dr->memstreamfd, "a", additional_information);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDFAILURE+errno);
  res=write_attribute_if_not_null(dr->memstreamfd, "f", failure_reason_code);
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDFAILURE+errno);

  res=fprintf(dr->memstreamfd,"}");
  if(res<0) return errorcode(dr, TLSRPT_ERR_FPRINTF_ADDFAILURE+errno);
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

int tlsrpt_get_socket(tlsrpt_connection_t* con) {
  return con->sock_fd;
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
int tlsrpt_cancel_delivery_request(struct tlsrpt_dr_t** pdr) {
  struct tlsrpt_dr_t *dr=*pdr;
  int finalresult=dr->status;
  errorcode(dr, TLSRPT_ERR_TLSRPT_CANCELLED);
  tlsrpt_finish_delivery_request(pdr);
  return finalresult;
}

/* Finish a delivery request. Cleans up everything and only sends out the datagram if no errors were encountered. */
int tlsrpt_finish_delivery_request(struct tlsrpt_dr_t **pdr) {
  /*
Throughout this function the errorcode is never returned prematurely!
We need to go through all steps of cleaning up.
Calls to errorcode will record the errorcode in the tlsrpt_dr_t structure, but there is no "return errorcode(...)" statement.
   */
  int res=0;
  struct tlsrpt_dr_t *dr=*pdr;

  if(dr->con==NULL) {
    errorcode(dr,TLSRPT_ERR_TLSRPT_NOCONNECTION);
  }

  /* Check if finish_policy was called properly and clean up left-overs otherwise */
  if(dr->memstreamps != NULL) {
    errorcode(dr, TLSRPT_ERR_TLSRPT_UNFINISHEDPOLICY);
    tlsrpt_finish_policy(dr,TLSRPT_UNFINISHED_POLICY);
  }

  if(dr->policy_count>0) {
    res=fprintf(dr->memstream, "]");
    if(res<0) errorcode(dr,TLSRPT_ERR_FPRINTF_FINISHDR+errno);
  } else {
    errorcode(dr, TLSRPT_ERR_TLSRPT_NOPOLICIES);
  }

  res=fprintf(dr->memstream, "}");
  if(res<0) errorcode(dr,TLSRPT_ERR_FPRINTF_FINISHDR+errno);

  res=fclose(dr->memstream);
  if(res!=0) errorcode(dr,TLSRPT_ERR_FCLOSE_FINISHDR+errno);

  if(dr->status == 0) { // everything looks fine, we can send the datagram
    res = sendto(dr->con->sock_fd, dr->memstreambuffer, dr->memstreamsize,
		 tlsrpt_sendto_flags, (const struct sockaddr *) &dr->con->addr,
		 sizeof(struct sockaddr_un));
    if(res<0) errorcode(dr,TLSRPT_ERR_SENDTO+errno);
  }

  DEBUG debug_datagram_hook(dr->memstreambuffer);

  free(dr->memstreambuffer);
  int finalresult=dr->status;

  tlsrpt_free(dr);
  *pdr=NULL;
  return finalresult;
}

/* Initialize a delivery request */
int tlsrpt_init_delivery_request(struct tlsrpt_dr_t** pdr, struct tlsrpt_connection_t* con, const char* domainname, const char* policyrecord) {
  *pdr=NULL;
  struct tlsrpt_dr_t* ptr=(struct tlsrpt_dr_t*)tlsrpt_malloc(sizeof(struct tlsrpt_dr_t));
  if(ptr==NULL) return TLSRPT_ERR_MALLOC_OPENDR+errno;

  int res=tlsrpt_init_delivery_request_prepare_struct(ptr, con, domainname, policyrecord);
  if(res==0) {
    *pdr=ptr;
    return 0;
  }
  // clean up
  tlsrpt_cancel_delivery_request(&ptr);
  return res;
}

