#ifndef GSS_KERBEROS_AUTH_H_
#define GSS_KERBEROS_AUTH_H_

#include <mysql.h>
//int server_authentication (u_short port, MYSQL_PLUGIN_VIO *vio);
//int client_authentication (u_short port, char *server_host, MYSQL_PLUGIN_VIO *vio);

int server_authentication (char * mysql_user, MYSQL_PLUGIN_VIO *vio);
int client_authentication (char *server_host, MYSQL_PLUGIN_VIO *vio);
#endif
