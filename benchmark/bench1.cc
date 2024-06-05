#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "tlsrpt.h"
#include "duration.h"

#define log(...) fprintf(stderr, __VA_ARGS__)

#define SOCKET_NAME "/tmp/tlsrpt-receiver.socket"

tlsrpt_connection_t* con;

//compare global socket vs individual sockets
#ifdef INDVIDUALSOCKETS
#define SOCKOPENINNER tlsrpt_open(&con, SOCKET_NAME);
#define SOCKCLOSEINNER res=tlsrpt_close(&con);
#else
#define SOCKOPENINNER
#define SOCKCLOSEINNER
#endif

#define CHECK if(res!=0) fprintf(stderr, "RESULT AT %d IS %d : %s\n" ,__LINE__, res, strerror(res%1000));
//#define CHECK 

extern int dbgnumber;

int main(int argc, char *argv[])
{
  if(argc<2) {
    fprintf(stderr,"Usage: %s number_of_runs [force_policy]\n",argv[0]);
    exit(1);
  }
  Rate rate;
  int res=-1;
  con=tlsrpt_open(SOCKET_NAME);
  tlsrpt_set_blocking();
  int i=0;
  int runs=atoi(argv[1]);
  int forcepol=argc>=3?atoi(argv[2]):-1;
  int donetotal=0;
  int donepart=0;
  int parts=0;
  int domains=1000;

  rate.start();
  while(runs==0 || i<runs) {
    dbgnumber=i%16;
    char domain[1024];
    snprintf(domain,1023,"test-%d.example.com",i%domains);
    const char* _reason="Test with unusual characters: °!\"§$%&/()=?`'´\\<|>äöüÄÖÜß";
#define DEBUGSIZE 1024
    char reason[DEBUGSIZE];
    //const char* reason="Test with normal characters: abcdefghijklmnop";
    memset(reason,0,DEBUGSIZE);
    strncpy(reason, _reason, i % (DEBUGSIZE-1));

    tlsrpt_final_result_t polresult=tlsrpt_final_result_t((i/16)%2);

    struct tlsrpt_dr_t *dr;
    SOCKOPENINNER
    dr = tlsrpt_init_delivery_request(con, domain);
    CHECK;

    int pol=forcepol>=0?forcepol:i;

    // first policy
    if(pol & 1) {
      res = tlsrpt_init_policy(dr, TLSRPT_POLICY_STS , "company-y.example");
      CHECK;
      res = tlsrpt_add_policy_string(dr,"version: STSv1");
      res = tlsrpt_add_policy_string(dr,"mode: testing");
      res = tlsrpt_add_policy_string(dr,"mx: *.mail.company-y.example");
      res = tlsrpt_add_policy_string(dr,"max_age: 86400");
      CHECK;
      res = tlsrpt_add_mx_host_pattern(dr,"*.mail.company-y.example");
      CHECK;
      res = tlsrpt_add_delivery_request_failure(dr, TLSRPT_STS_POLICY_INVALID, "1.2.3.4", "mailin.example.com", "test-ehlo.example.com", "11.22.33.44", "This is additional information", "999 TEST ERROR");
      CHECK;
      res = tlsrpt_add_delivery_request_failure(dr, TLSRPT_STS_WEBPKI_INVALID, "1.2.3.5", "mailin.example.com", "test-ehlo.example.com", "11.22.33.55", "This is additional information", "999 TEST ERROR");
      CHECK;
      res = tlsrpt_finish_policy(dr,polresult);
      CHECK;
    }

    // second policy
    if(pol & 2) {
      res = tlsrpt_init_policy(dr, TLSRPT_POLICY_TLSA , "company-y.example");
      CHECK;
      res = tlsrpt_add_policy_string(dr,"3 0 1 1F850A337E6DB9C609C522D136A475638CC43E1ED424F8EEC8513D747D1D085D");
      res = tlsrpt_add_policy_string(dr,"3 0 1 12350A337E6DB9C6123522D136A475638CC43E1ED424F8EEC8513D747D1D1234");
      CHECK;
      res = tlsrpt_add_delivery_request_failure(dr, TLSRPT_CERTIFICATE_EXPIRED, "1.2.3.4", "mailin.example.com", "tes-ehlo.example.com", "11.22.33.55", "This is additional information", "999 TEST ERROR");
      CHECK;
      res = tlsrpt_finish_policy(dr,polresult);
    }

    // third policy
    if(pol & 4) {
      res = tlsrpt_init_policy(dr, TLSRPT_NO_POLICY_FOUND , NULL);
      CHECK;
      res = tlsrpt_add_delivery_request_failure(dr, TLSRPT_VALIDATION_FAILURE, "192.168.25.25", NULL, NULL, "11.22.33.55", "Something unexpected happened", "http://www.google.com/");
      CHECK;
      res = tlsrpt_finish_policy(dr,polresult);
    }

    // a policy without failures
    if(pol & 8) {
      res = tlsrpt_init_policy(dr, TLSRPT_POLICY_STS , "company-y.example");
      CHECK;
      res = tlsrpt_add_policy_string(dr,"version: STSv1");
      res = tlsrpt_add_policy_string(dr,"mode: testing and will contain  no failures");
      res = tlsrpt_add_policy_string(dr,"mx: *.mail.company-y.example");
      res = tlsrpt_add_policy_string(dr,"max_age: 86400");
      CHECK;
      res = tlsrpt_add_mx_host_pattern(dr,"*.mail.company-y.example");
      CHECK;
      // intentionally no failures are added here
      res = tlsrpt_finish_policy(dr,polresult);
      CHECK;
    }

    res = tlsrpt_finish_delivery_request(dr);
    CHECK;
    if(res==0) {
      ++donetotal;
      ++donepart;
    } else {
      ++parts;
      /*
	clock_gettime(clk,&ts_cur);
	log("t: %5.2f p: %5.2f s: %ld run: %d dur: %f\n",donetotal/duration(&ts_start,&ts_cur), donepart/duration(&ts_lap,&ts_cur),ts_sleep.tv_nsec, parts,duration(&ts_lap,&ts_cur));
	ts_lap.tv_sec=ts_cur.tv_sec;
	ts_lap.tv_nsec=ts_cur.tv_nsec;
	nanosleep(&ts_sleep, NULL);
	ts_sleep.tv_nsec+=1000000;
	ts_sleep.tv_sec+=ts_sleep.tv_nsec/1000000000;
	ts_sleep.tv_nsec=ts_sleep.tv_nsec%1000000000;
	donepart=0;
      */
    }
    SOCKCLOSEINNER

    if(i%1000==0) {
      rate.stop();
      cout<<rate<<endl;
    }
    rate.add();
    ++i;    
  }

  tlsrpt_close(con);
  rate.stop();
  cout<<endl<<rate<<endl;
  return 0;
}

/*
  if (ret == -1) {
  fprintf(stderr,"In iteration %d, previous ret was %d or %d k ",i, lastret, lastret/1024);
  perror("write");
  break;
  }

*/
