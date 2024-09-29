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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "tlsrpt.h"

#define SOCKET_NAME "/tmp/tlsrpt-receiver.socket"

void* specialmalloc(size_t size) {
  fprintf(stderr,"specialmalloc(%ld)\n",size);
  return malloc(size);
}

void specialfree(void* p) {
  fprintf(stderr,"specialfree()\n");
  free(p);
}

void testrun() {
  int res=0;

  struct tlsrpt_connection_t *con=NULL;
  tlsrpt_open(&con, SOCKET_NAME);

  const char* domain="example.com";

  struct tlsrpt_dr_t *dr=NULL;
  tlsrpt_init_delivery_request(&dr, con, domain, "v=TLSRPTv1;rua=mailto:reports@example.com");
  tlsrpt_init_policy(dr, TLSRPT_POLICY_STS , "company-y.example");
  tlsrpt_add_policy_string(dr,"version: STSv1");
  tlsrpt_add_policy_string(dr,"mode: testing");
  tlsrpt_add_policy_string(dr,"mx: *.mail.company-y.example");
  tlsrpt_add_policy_string(dr,"max_age: 86400");
  tlsrpt_add_mx_host_pattern(dr,"*.mail.company-y.example");
  tlsrpt_add_delivery_request_failure(dr, TLSRPT_STS_POLICY_INVALID, "1.2.3.4", "mailin.example.com", "test-ehlo.example.com", "11.22.33.44", "This is additional information", "999 TEST REASON CODE");
  tlsrpt_add_delivery_request_failure(dr, TLSRPT_STS_WEBPKI_INVALID, "1.2.3.5", "mailin.example.com", "test-ehlo.example.com", "11.22.33.55", "This is additional information", "123 ANOTHER TEST REASON CODE");
  tlsrpt_finish_policy(dr, TLSRPT_FINAL_FAILURE);
  res = tlsrpt_finish_delivery_request(&dr);

  printf("Result code is %d\n", res);
  if(tlsrpt_error_code_is_internal(res)) {
    printf("Internal library error :  %s\n", tlsrpt_strerror(res));
  } else {
    int e = tlsrpt_errno_from_error_code(res);
    printf("%s : errno=%d : %s\n", tlsrpt_strerror(res), e, strerror(e));
  }

  
  tlsrpt_close(&con);

}

int main(int argc, char *argv[])
{
  fprintf(stderr,"\nNormal test\n");  
  testrun();

  /* tlsrpt_set_malloc_and_free(testmalloc, testfree must usually be called before any other tlsrpt function!
     Here we call it in the middle of the program to show its effect only because we are sure there are no objects left that were allocated by a different malloc implementation */
  tlsrpt_set_malloc_and_free(specialmalloc, specialfree); 
  fprintf(stderr,"\nTest with special malloc implementation\n");
  testrun();

  tlsrpt_set_malloc_and_free(malloc, free);
  fprintf(stderr,"\nNormal test again\n");
  testrun();

  return 0;
}
