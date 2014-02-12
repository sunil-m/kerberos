/*
 * $Header: $
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <mysql.h>
#include <mysql/plugin_auth.h>
#include <mysql/client_plugin.h>
#include <mysql_version.h>
#include <pwd.h>
#include "constants.h"
#include "kerberos_auth.h"

static int auth_verify(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info) {

    unsigned char * username;

    readconfig();

    if(verbose) {
        fprintf(stderr, "Server: Initiated\n");
        fprintf(stderr, "Username = %s\n", info->user_name);
    }

    if(server_authentication(info->user_name, vio) < 0)
        return CR_ERROR;

    return CR_OK;
}


static struct st_mysql_auth auth_handler=
{
    MYSQL_AUTHENTICATION_INTERFACE_VERSION,
    "mysql_kerb",
    auth_verify
};

mysql_declare_plugin(auth_test)
{
    MYSQL_AUTHENTICATION_PLUGIN,
    &auth_handler,
    "mysql_kerb_server",
    "Sunil Mellimi",
    "Test server plugin. Example 1",
    PLUGIN_LICENSE_GPL,
    NULL,
    NULL,
    0x100,
    NULL,
    NULL,
    NULL,
}
mysql_declare_plugin_end;


static int auth_client(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql)
{
    unsigned char * username;
    unsigned char * token;
    int pkt_len;

    readconfig();

    if(verbose) 
        fprintf(stderr, "Client: Initiated\n");

    /* Receive token (protocol) from server */
    if((pkt_len = vio->read_packet(vio, &token)) < 0) {
        fprintf(stderr, "ERROR: Reading token from server\n");
        return CR_ERROR;
    }
    if(verbose)
        fprintf(stderr, "Token = %s\n", token);

    /* 
     * If logged in username and mysql username are different 
     * Returning CR_OK as the error message will be handled by server 
     */
//    if(strcmp((const char *)token, (const char *)ACCESS_DENIED) == 0) {
//        fprintf(stderr, "Access denied by server plugin\n");
//        return CR_OK;
//    }

    /* If unable to create a socket */
//    if(strcmp((const char *)token, (const char *)SOCKET_PROBLEM) == 0) {
//        fprintf(stderr, "\tUnable to create a socket \n\tPlease Reconnect...\n");
//        return CR_ERROR;
//    }

    if(strcmp((const char *) token, (const char *) START_CLIENT) != 0) {
        printf("Invalid token (%s) received from server\n", token);
        return CR_ERROR;
    }

    if(client_authentication(mysql->host, vio) < 0) { 
        return CR_ERROR;
    }

    return CR_OK;
}


mysql_declare_client_plugin(AUTHENTICATION)
    "mysql_kerb",
    "Sunil Mellimi",
    "Test Client plugin. Example 1",
    {0, 1, 0},
    "GPL",
    NULL,
    NULL,
    NULL,
    NULL,
    auth_client
mysql_end_client_plugin;


