#include <stdio.h>
#include "constants.h"
#include <mysql.h>
#include <mysql/plugin_auth.h>
#include <unistd.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5/krb5.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <com_err.h>

/*
 * Routine to print the token information
 */ 
void print_token(gss_buffer_t tok)
{
    int i;
    unsigned char *p = (unsigned char *)tok->value;

    for (i=0; i < tok->length; i++, p++) {
        fprintf(stderr, "%02x ", *p);
        if ((i % 16) == 15) {
            fprintf(stderr, "\n");
        }
    }
    fprintf(stderr, "\n");
}


/*
 * Routine to receive tokens via mysql vio
 */
int mysql_recv_token(MYSQL_PLUGIN_VIO *vio, gss_buffer_t tok)
{
    unsigned char *pkt;

    if((tok->length = vio->read_packet(vio, &pkt)) < 0)
        return -1;

    tok->value = (char *) malloc (tok->length);

    int i;
    unsigned char *p = (unsigned char *) tok->value;

    for(i=0; i < tok->length ; i++, p++, pkt++) {
       *p = *pkt; 
    }

    return 0;
}


/*
 * Routine to send tokens via mysql vio
 */
int mysql_send_token(MYSQL_PLUGIN_VIO *vio, gss_buffer_t tok)
{

    if(vio->write_packet(vio, (const unsigned char *) tok->value, tok->length))
        return -1;

    return 0;
}

/*
 * Routine to display gssapi specific messages
 */
static void display_status_1(char *m, OM_uint32 code, int type)
{
     OM_uint32 maj_stat, min_stat;
     gss_buffer_desc msg;
     OM_uint32 msg_ctx;

     msg_ctx = 0;
     while (1) {
          maj_stat = gss_display_status(&min_stat, code,
                                       type, GSS_C_NULL_OID,
                                       &msg_ctx, &msg);
            fprintf(stderr, "GSS-API error (%s): %s\n", m,
             (char *)msg.value);
          (void) gss_release_buffer(&min_stat, &msg);

          if (!msg_ctx)
               break;
     }
}

void display_status(char *msg, OM_uint32 maj_stat, OM_uint32 min_stat)
{
     display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
     display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

/*
 * Routine to read the keytab get gssapi context
 */
static int server_acquire_creds(char * service_name, gss_cred_id_t *server_creds)
{
    gss_buffer_desc name_buf;
    gss_name_t server_name;
    OM_uint32 maj_stat, min_stat;

    if(verbose) {
        fprintf(stderr, "Keytab = %s\n", mysql_keytab);
        fprintf(stderr, "Service Name = %s\n", service_name);
    }

    // Use an alternate keytab as /etc/krb5.keytab does not permit
    if (krb5_gss_register_acceptor_identity(mysql_keytab)) {
        fprintf(stderr, "Unable to use %s keytab\n", mysql_keytab);
        return -1;
    }

    name_buf.value = service_name;
    name_buf.length = strlen((const char *)name_buf.value) + 1;
    maj_stat = gss_import_name(&min_stat, &name_buf,
                               (gss_OID) gss_nt_service_name, &server_name);

    if (maj_stat != GSS_S_COMPLETE) {
        fprintf(stderr, "Unable to import name\n");
        display_status("importing name", maj_stat, min_stat);
        return -1;
    }

    maj_stat = gss_acquire_cred(&min_stat, server_name, 0,
                                GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
                                server_creds, NULL, NULL);
    if (maj_stat != GSS_S_COMPLETE) {
        fprintf(stderr, "Unable to acquire credentials\n");
        display_status("acquiring credentials", maj_stat, min_stat);
        return -1;
    }

    if(verbose)
        display_status("acquiring credentials", maj_stat, min_stat);

    (void) gss_release_name(&min_stat, &server_name);

    return 0;
}


/*
 * Negotiate with the client 
 */
static int server_establish_context(MYSQL_PLUGIN_VIO *vio, gss_cred_id_t server_creds, gss_ctx_id_t *context, gss_buffer_t client_name,
                                    OM_uint32 *ret_flags)
{
    gss_buffer_desc send_tok, recv_tok;
    gss_name_t client;
    gss_OID doid;
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc    oid_name;
    int token_flags;

    *context = GSS_C_NO_CONTEXT;


    do {
        if (mysql_recv_token(vio, &recv_tok) < 0) {
            fprintf(stderr, "Unable to receive token\n");
            return -1;
        }

        if (verbose) {
            fprintf(stderr, "Received token (size=%d): \n", (int) recv_tok.length);
            print_token(&recv_tok);
        }

        maj_stat =
                gss_accept_sec_context(&min_stat,
                                       context,
                                       server_creds,
                                       &recv_tok,
                                       GSS_C_NO_CHANNEL_BINDINGS,
                                       &client,
                                       &doid,
                                       &send_tok,
                                       ret_flags,
                                       NULL,         /* ignore time_rec */
                                       NULL);        /* ignore del_cred_handle */

        if (maj_stat!=GSS_S_COMPLETE && maj_stat!=GSS_S_CONTINUE_NEEDED) {
            display_status("accepting context", maj_stat,
                                                   min_stat);
            (void) gss_release_buffer(&min_stat, &recv_tok);
            return -1;
        }

        (void) gss_release_buffer(&min_stat, &recv_tok);

        if(send_tok.length != 0)
        {
           if(mysql_send_token(vio, &send_tok) < 0) {
               fprintf(stderr, "Unable to send token\n");
               return -1;
           }
           (void) gss_release_buffer(&min_stat, &recv_tok);
        }

        if (verbose) {
            if (maj_stat == GSS_S_CONTINUE_NEEDED)
                fprintf(stderr, "continue needed...\n");
            else
                fprintf(stderr, "\n");
        }
    } while (maj_stat == GSS_S_CONTINUE_NEEDED);

    maj_stat = gss_display_name(&min_stat, client, client_name, &doid);
    if (maj_stat != GSS_S_COMPLETE) {
        display_status("displaying name", maj_stat, min_stat);
        return -1;
    }

    maj_stat = gss_release_name(&min_stat, &client);
    if (maj_stat != GSS_S_COMPLETE) {
        display_status("releasing name", maj_stat, min_stat);
        return -1;
    }

    return 0;
}


int server_authentication (char * mysql_user, MYSQL_PLUGIN_VIO *vio)
{
    char *service_name = mysql_service;
    gss_cred_id_t server_creds;
    gss_ctx_id_t context;
    gss_buffer_desc client_name, uname;
    gss_name_t principal;
    OM_uint32 min_stat, maj_stat;
    int ret_flags;

    // Kerberos specific
    krb5_context kcontext;
    krb5_error_code return_val = 0;    
    krb5_principal krb5_client = NULL;

    // Acquire server credentials by reading the supplied keytab
    if(server_acquire_creds(service_name, &server_creds) < 0)
    {
        fprintf(stderr, "UNABLE TO ACQUIRE SERVER CREDENTIALS\n");
        return -1;
    }    

    /* SEND a start token to client.  This will indicate the client to start its authentication mechanism */
    if(vio->write_packet(vio, (const unsigned char *) START_CLIENT, strlen(START_CLIENT) + 1) < 0) {
        fprintf(stderr, "ERROR: Sending token\n");
        return -1;
    }

    // try to establish context with the client
    if(server_establish_context(vio, server_creds, &context, &client_name, (OM_uint32 *) &ret_flags) < 0)
    {
        fprintf(stderr, "Unable to establish context with the client\n");
        return -1;
    }

    fprintf(stderr, "Connection request using principal : \"%.*s\"\n",
                          (int) client_name.length, (char *) client_name.value);

    // Convert principle to localname
    return_val = krb5_init_secure_context(&kcontext);
    if(return_val) {
        fprintf(stderr, "Unable to initialize krb5 security context\n");
        com_err(prog_name, return_val, "while initializing krb5");
        return -1;
    }

    // Convert principle (string) to kerberos internal principle representation
    if ((return_val = krb5_parse_name(kcontext,(const char *)  client_name.value, &krb5_client))){
        krb5_free_context(kcontext);
        com_err(prog_name, return_val, "when parsing name %s", client_name.value);
        return -1;
    }

    char *local_user = (char *) malloc(client_name.length);
    // Convert the principle to localname (unix username)
    if((return_val = krb5_aname_to_localname(kcontext, krb5_client, client_name.length, local_user))) {
        krb5_free_principal(kcontext, krb5_client);
        krb5_free_context(kcontext);
        com_err(prog_name, return_val, "while converting principle %s to localname", client_name.value);
        return -1;  
    }

    krb5_free_principal(kcontext, krb5_client);
    krb5_free_context(kcontext);

    if(verbose)
        fprintf(stderr, "Local name = %s\n", local_user);

    if(strcmp((const char *) mysql_user, (const char *) local_user) != 0) {
        fprintf(stderr, "ACCESS DENIED for %s as %s\n", mysql_user, local_user);
        return -1;
    }

/*  
    // Read principal of service_name (nfs/mysql in this case) here 
    maj_stat = gss_inquire_cred(&min_stat, server_creds, &principal, NULL, NULL, NULL);
    gss_display_name(&min_stat, principal, &uname, NULL);
    fprintf(stderr, "Name = %s\n", uname.value);
    (void) gss_release_name(&min_stat, &principal);
    (void) gss_release_buffer(&min_stat, &uname);
*/
    (void) gss_release_buffer(&min_stat, &client_name);

    free(local_user);
    return 1;
}

static int client_establish_context(MYSQL_PLUGIN_VIO *vio, char *host, OM_uint32 gss_flags, gss_OID oid,
                                    gss_ctx_id_t *gss_context, OM_uint32 *ret_flags)
{
    gss_buffer_desc send_tok, recv_tok, *token_ptr;
    gss_name_t target_name;
    gss_cred_id_t user_creds;
    OM_uint32 maj_stat, min_stat;
    int token_flags;
    char * principal;

    /*
     * Import the name into target_name.  Use send_tok to save
     * local variable space.
     * Request a ticket for <service>@<target_host>
     */
    char * at = "@";
    principal = (char *)malloc(strlen(host) + strlen(mysql_service) + strlen(at) + 1);
    strcpy(principal, mysql_service);
    strcat(principal, at);
    strcat(principal, host);
    if(verbose)
        fprintf(stderr, "Principal = %s\n", principal);

    send_tok.value = principal;
    send_tok.length = strlen(principal);

    maj_stat = gss_import_name(&min_stat, &send_tok,
                                   (gss_OID) gss_nt_service_name, &target_name);
    if (maj_stat != GSS_S_COMPLETE) {
        display_status("parsing name", maj_stat, min_stat);
        return -1;
    }


    token_ptr = GSS_C_NO_BUFFER;
    *gss_context = GSS_C_NO_CONTEXT;

    do {
        maj_stat =
            gss_init_sec_context(&min_stat,
                                 GSS_C_NO_CREDENTIAL,
                                 gss_context,
                                 target_name,
                                 oid,
                                 gss_flags,
                                 0,
                                 NULL,   /* no channel bindings */
                                 token_ptr,
                                 NULL,   /* ignore mech type */
                                 &send_tok,
                                 ret_flags,
                                 NULL);  /* ignore time_rec */

        if(gss_context == NULL)
        {
            printf("Unable to create context\n");
            return GSS_S_NO_CONTEXT;
        }

        if (token_ptr != GSS_C_NO_BUFFER)
            (void) gss_release_buffer(&min_stat, &recv_tok);
        if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED)
        {
            display_status("initializing context", maj_stat, min_stat);
            (void) gss_release_name(&min_stat, &target_name);
            return -1;
        }

        if(send_tok.length != 0)
        { 
            if(verbose) {
                printf("Sending init_sec_context token (size=%ld)...", send_tok.length);
                printf("Sent token = %x\n", send_tok.value);
                print_token(&send_tok);
            }
            if(mysql_send_token(vio, &send_tok) < 0)
            {
                printf("Unable to send token \n");
                (void) gss_release_buffer(&min_stat, &send_tok);
                (void) gss_release_name(&min_stat, &target_name);
                return -1;
            }
        }   
        (void) gss_release_buffer(&min_stat, &send_tok);

        if(maj_stat == GSS_S_CONTINUE_NEEDED)
        {
            if(verbose)
                printf("\ncontinue needed...");

            if(mysql_recv_token(vio, &recv_tok) < 0)
            {
                printf("Unable to receive token\n");
                (void) gss_release_name(&min_stat, &target_name);
                return -1;
            }
            token_ptr = &recv_tok;
       }
    } while(maj_stat == GSS_S_CONTINUE_NEEDED);

    (void) gss_release_name(&min_stat, &target_name);
    free(principal);
    return 0;
}

int client_authentication (char *server_host, MYSQL_PLUGIN_VIO *vio)
{
    gss_ctx_id_t context;
    OM_uint32 gss_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;
    gss_OID oid = GSS_C_NULL_OID;
    OM_uint32 ret_flags;

    if(client_establish_context(vio, server_host, gss_flags, oid, &context, &ret_flags) < 0)
    {
        printf("Unable to establish context\n");
        return -1;
    }

    return 1;
}


