#ifndef _CONSTANTS_H_
#define _CONSTANTS_H_

#include <stdio.h>

void readconfig();

extern int verbose;
extern char mysql_service[10];
extern int socket_timeout;
extern char mysql_keytab[200];
extern char * prog_name;

#define START_CLIENT     "1111"
// Reserved for future use
#define SOCKET_PROBLEM   "8888"
#define ACCESS_DENIED    "9999"

#endif
