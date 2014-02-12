#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "constants.h"
#define LINE_SIZE 1024

/*
 * Defaults
 */
int verbose = 1;
char mysql_service[10] = "mysql";
int socket_timeout = 5;
char mysql_keytab[200] = "/etc/krb5.keytab";
char * prog_name = "mysql_kerb_plugin";
// For now using a temporary location.  Will update this in production
char * config_file = "/var/tmp/mysql_kerb.conf";

void readconfig()
{
    char line[LINE_SIZE];
    char key[30], value[200];
    FILE *fp = fopen(config_file, "r");
    if(fp != NULL) {
        while(fgets(line, LINE_SIZE, fp)) {
            sscanf(line, "%[^ =\n]%*[= ]%[^\n]", key, value);
            if(strcmp(key, "verbose") == 0)
                verbose = atoi(value);
            else if(strcmp(key, "service") == 0)
                strcpy(mysql_service, value);
            else if(strcmp(key, "timeout") == 0)
                socket_timeout = atoi(value);
            else if(strcmp(key, "keytab") == 0)
                strcpy(mysql_keytab, value);
            else {}
            key[0] = '\0'; value[0] = '\0';
        }
        fclose(fp);
    }
}

/*
int main()
{
    readconfig();
    printf("Verbose = %d\n", verbose);
    printf("Service = %s, Length = %d\n", mysql_service, strlen(mysql_service));
    printf("Timeout = %d\n", socket_timeout);
    printf("Keytab = %s, Length = %d\n", mysql_keytab, strlen(mysql_keytab));
}
*/
