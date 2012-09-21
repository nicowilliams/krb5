/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* slave/kpropd.c */
/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * Copyright 1990,1991,2007 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/*
 * XXX We need to modify the protocol so that an acknowledge is set
 * after each block, instead after the entire series is sent over.
 * The reason for this is so that error packets can get interpreted
 * right away.  If you don't do this, the sender may never get the
 * error packet, because it will die an EPIPE trying to complete the
 * write...
 */


#include <locale.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/file.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <netdb.h>
#include <syslog.h>

#include "k5-int.h"
#include "com_err.h"
#include "fake-addrinfo.h"
#include <errno.h>

#include "kprop.h"
#include <iprop_hdr.h>
#include "iprop.h"
#include <kadm5/admin.h>
#include <kdb_log.h>

#ifndef GETSOCKNAME_ARG3_TYPE
#define GETSOCKNAME_ARG3_TYPE unsigned int
#endif
#ifndef GETPEERNAME_ARG3_TYPE
#define GETPEERNAME_ARG3_TYPE unsigned int
#endif

#if defined(NEED_DAEMON_PROTO)
extern int daemon(int, int);
#endif

#define SYSLOG_CLASS LOG_DAEMON


char *def_realm = NULL;
int runonce = 0;

/*
 * This struct simulates the use of _kadm5_server_handle_t
 *
 * This is a COPY of kadm5_server_handle_t from
 * lib/kadm5/clnt/client_internal.h!
 */
typedef struct _kadm5_iprop_handle_t {
    krb5_ui_4       magic_number;
    krb5_ui_4       struct_version;
    krb5_ui_4       api_version;
    char            *cache_name;
    int             destroy_cache;
    CLIENT          *clnt;
    krb5_context    context;
    kadm5_config_params params;
    struct _kadm5_iprop_handle_t *lhandle;
} *kadm5_iprop_handle_t;


static char *kprop_version = KPROP_PROT_VERSION;

static kadm5_config_params params;

char    *progname;
int     debug = 0;
int     nodaemon = 0;
char    *srvtab = 0;
int     standalone = 0;

pid_t fullprop_child = (pid_t)-1;

krb5_principal  server;         /* This is our server principal name */
krb5_principal  client;         /* This is who we're talking to */
krb5_context kpropd_context;
krb5_auth_context auth_context;
char    *realm = NULL;          /* Our realm */
char    *file = KPROPD_DEFAULT_FILE;
char    *temp_file_name;
char    *kdb5_util = KPROPD_DEFAULT_KDB5_UTIL;
char    *kerb_database = NULL;
char    *acl_file_name = KPROPD_ACL_FILE;

krb5_address    *sender_addr;
krb5_address    *receiver_addr;
const char      *port = KPROP_SERVICE;

char **db_args = NULL;
int db_args_size = 0;

void    PRS(char**);
static void     do_standalone();
void    doit(int);
static krb5_error_code do_iprop(kdb_log_context *log_ctx);
void    kerberos_authenticate(krb5_context, int, krb5_principal *,
                              krb5_enctype *, struct sockaddr_storage *);
krb5_boolean authorized_principal(krb5_context, krb5_principal, krb5_enctype);
void    recv_database(krb5_context, int, int, krb5_data *);
void    load_database(krb5_context, char *, char *);
void    send_error(krb5_context, int, krb5_error_code, char *);
void    recv_error(krb5_context, krb5_data *);
unsigned int backoff_from_master(int *);

static kadm5_ret_t
kadm5_get_kiprop_host_srv_name(krb5_context context,
                               const char *realm_name,
                               char **host_service_name);

static void usage()
{
    fprintf(stderr,
            _("\nUsage: %s [-r realm] [-s srvtab] [-dS] [-f slave_file]\n"),
            progname);
    fprintf(stderr, _("\t[-F kerberos_db_file ] [-p kdb5_util_pathname]\n"));
    fprintf(stderr, _("\t[-x db_args]* [-P port] [-a acl_file]\n"));
    exit(1);
}

typedef void (*sig_handler_ft)(int sig);

static void
signal_wrapper(int sig, sig_handler_ft handler)
{
#ifdef POSIX_SIGNALS
    struct sigaction s_action;
    memset(&s_action, 0, sizeof(s_action));
    sigemptyset(&s_action.sa_mask);
    s_action.sa_handler = handler;
    sigaction(sig, &s_action, NULL);
#else
    signal(sig, handler);
#endif
}

static void
alarm_handler(int sig)
{
    static char *timeout_msg = "Full propagation timed out\n";
    write(STDERR_FILENO, timeout_msg, strlen(timeout_msg));
    exit(1);
}

static void
kill_do_standalone(int sig)
{
    if (fullprop_child > 0) {
        if (debug) {
            fprintf(stderr, _("Killing fullprop child (%d)\n"),
                    (int)fullprop_child);
        }
        kill(fullprop_child, sig);
    }
    /* Make sure our exit status code reflects our having been signaled */
    signal_wrapper(sig, SIG_DFL);
    kill(getpid(), sig);
}

static void
atexit_kill_do_standalone(void)
{
    if (fullprop_child > 0)
        kill(fullprop_child, SIGHUP);
}

int
main(argc, argv)
    int     argc;
    char    **argv;
{
    krb5_error_code retval;
    kdb_log_context *log_ctx;
    struct stat st;

    setlocale(LC_ALL, "");
    PRS(argv);

    if (fstat(0, &st) == -1) {
        com_err(progname, errno,
                _("while checking if stdin is a socket"));
        exit(1);
    }
    if (S_ISSOCK(st.st_mode)) {
        /* We can't be standalong if stdin is a socket, not really */
        standalone = 0;
    } else {
        /* Corollary: if stdin is not a socket, then we're standalone */
        standalone = 1;
    }

    log_ctx = kpropd_context->kdblog_context;

    signal_wrapper(SIGPIPE, SIG_IGN);

    /* "ready" is a sentinel for the test framework. */
    printf(_("ready\n"));
    fflush(stdout);
    if (!debug && !nodaemon)
        daemon(0, 0);

    if (!standalone) {
        int devnull;

        /* We're an inetd nowait service. */
        devnull = open("/dev/null", O_RDWR);
        if (devnull != -1) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        doit(0);
        exit(0);
    }

    if (log_ctx == NULL || log_ctx->iproprole != IPROP_SLAVE) {
        do_standalone();
        /* do_standalone() should never return */
        /* NOTREACHED */
        exit(1);
    }

    /*
     * This is the iprop case.  We'll fork a child to run do_standalone().
     * The parent will run do_iprop().  We try to kill the child if we
     * get killed.
     *
     * The rest of this could be a loop so we can restart when the child
     * process dies.  But that might be pointless where there are good
     * restarters.
     */
    signal_wrapper(SIGHUP, kill_do_standalone);
    signal_wrapper(SIGINT, kill_do_standalone);
    signal_wrapper(SIGQUIT, kill_do_standalone);
    signal_wrapper(SIGTERM, kill_do_standalone);
    signal_wrapper(SIGSEGV, kill_do_standalone);
    atexit(atexit_kill_do_standalone);
    fullprop_child = fork();
    switch (fullprop_child) {
    case -1:
        com_err(progname, errno, _("do_iprop failed.\n"));
        break;
    case 0:
        do_standalone();
        /* do_standalone() should never return */
        /* NOTREACHED */
        break;
    default:
        retval = do_iprop(log_ctx);
        kill(fullprop_child, SIGHUP);
        wait(NULL);
        if (retval)
            com_err(progname, retval, _("do_iprop failed.\n"));
        else
            exit(0);
        /* do_iprop() can return due to failures and runonce. */
    }

    exit(1);
}

/* Use getaddrinfo to determine a wildcard listener address, preferring
 * IPv6 if available. */
static int
get_wildcard_addr(struct addrinfo **res)
{
    struct addrinfo hints;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    hints.ai_family = AF_INET6;
    error = getaddrinfo(NULL, port, &hints, res);
    if (error == 0)
        return 0;
    hints.ai_family = AF_INET;
    return getaddrinfo(NULL, port, &hints, res);
}

static void
do_standalone()
{
    struct  sockaddr_in     frominet;
    struct addrinfo *res;
    int     finet, s;
    GETPEERNAME_ARG3_TYPE fromlen;
    int ret, error, val, status;
    pid_t child_pid;
    pid_t wait_pid;

    error = get_wildcard_addr(&res);
    if (error != 0) {
        (void) fprintf(stderr, _("getaddrinfo: %s\n"), gai_strerror(error));
        exit(1);
    }

    finet = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (finet < 0) {
        com_err(progname, errno, _("while obtaining socket"));
        exit(1);
    }

    val = 1;
    if (setsockopt(finet, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
        com_err(progname, errno, _("while setting SO_REUSEADDR option"));

#if defined(IPV6_V6ONLY)
    /* Make sure dual-stack support is enabled on IPv6 listener sockets if
     * possible. */
    val = 0;
    if (res->ai_family == AF_INET6 &&
        setsockopt(finet, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) < 0)
        com_err(progname, errno, _("while unsetting IPV6_V6ONLY option"));
#endif

    if ((ret = bind(finet, res->ai_addr, res->ai_addrlen)) < 0) {
        com_err(progname, errno, _("while binding listener socket"));
        exit(1);
    }
    if (listen(finet, 5) < 0) {
        com_err(progname, errno, "in listen call");
        exit(1);
    }
    while (1) {
        memset(&frominet, 0, sizeof(frominet));
        fromlen = sizeof(frominet);
        if (debug)
            fprintf(stderr, _("waiting for a kprop connection\n"));
        s = accept(finet, (struct sockaddr *) &frominet, &fromlen);

        if (s < 0) {
            int e = errno;
            if (e != EINTR) {
                com_err(progname, e,
                        _("while accepting connection"));
            }
        }
        child_pid = fork();
        switch (child_pid) {
        case -1:
            com_err(progname, errno, _("while forking"));
            exit(1);
        case 0:
            (void) close(finet);

            doit(s);
            close(s);
            _exit(0);
        default:
            do {
                wait_pid = waitpid(child_pid, &status, 0);
            } while (wait_pid == -1 && errno == EINTR);
            if (wait_pid == -1) {
                /* Something bad happened; panic. */
                if (debug) {
                    fprintf(stderr, _("waitpid() failed to wait for doit() "
                                      "(%d %s)\n"), errno, strerror(errno));
                }
                com_err(progname, errno,
                        _("while waiting to receive database"));
                exit(1);
            }
            if (debug) {
                fprintf(stderr, _("Database load process for full propagation "
                                  "completed.\n"));
            }

            close(s);

            if (runonce)
                break;
        }
    }
    exit(0);
}

void doit(int fd)
{
    struct sockaddr_storage from;
    int on = 1;
    GETPEERNAME_ARG3_TYPE fromlen;
    krb5_error_code retval;
    krb5_data confmsg;
    int lock_fd;
    mode_t omask;
    krb5_enctype etype;
    int database_fd;
    char host[INET6_ADDRSTRLEN+1];

    signal_wrapper(SIGALRM, alarm_handler);
    alarm(params.iprop_resync_timeout);
    fromlen = sizeof (from);
    if (getpeername(fd, (struct sockaddr *) &from, &fromlen) < 0) {
#ifdef ENOTSOCK
        if (errno == ENOTSOCK && fd == 0 && !standalone) {
            fprintf(stderr,
                    _("%s: Standard input does not appear to be a network "
                      "socket.\n"
                      "\t(Not run from inetd, and missing the -S option?)\n"),
                    progname);
            exit(1);
        }
#endif
        fprintf(stderr, "%s: ", progname);
        perror("getpeername");
        exit(1);
    }
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (caddr_t) &on,
                   sizeof (on)) < 0) {
        com_err(progname, errno,
                _("while attempting setsockopt (SO_KEEPALIVE)"));
    }

    if (getnameinfo((const struct sockaddr *) &from, fromlen,
                    host, sizeof(host), NULL, 0, 0) == 0) {
        syslog(LOG_INFO, _("Connection from %s"), host);
        if (debug)
            printf("Connection from %s\n", host);
    }

    /*
     * Now do the authentication
     */
    kerberos_authenticate(kpropd_context, fd, &client, &etype, &from);

    if (!authorized_principal(kpropd_context, client, etype)) {
        char    *name;

        retval = krb5_unparse_name(kpropd_context, client, &name);
        if (retval) {
            com_err(progname, retval,
                    "While unparsing client name");
            exit(1);
        }
        if (debug) {
            fprintf(stderr,
                    _("Rejected connection from unauthorized principal %s\n"),
                    name);
        }
        syslog(LOG_WARNING,
               _("Rejected connection from unauthorized principal %s"),
               name);
        free(name);
        exit(1);
    }
    omask = umask(077);
    lock_fd = open(temp_file_name, O_RDWR|O_CREAT, 0600);
    (void) umask(omask);
    retval = krb5_lock_file(kpropd_context, lock_fd,
                            KRB5_LOCKMODE_EXCLUSIVE|KRB5_LOCKMODE_DONTBLOCK);
    if (retval) {
        com_err(progname, retval, _("while trying to lock '%s'"),
                temp_file_name);
        exit(1);
    }
    if ((database_fd = open(temp_file_name,
                            O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0) {
        com_err(progname, errno, _("while opening database file, '%s'"),
                temp_file_name);
        exit(1);
    }
    recv_database(kpropd_context, fd, database_fd, &confmsg);
    if (rename(temp_file_name, file)) {
        com_err(progname, errno, _("while renaming %s to %s"),
                temp_file_name, file);
        exit(1);
    }
    retval = krb5_lock_file(kpropd_context, lock_fd, KRB5_LOCKMODE_SHARED);
    if (retval) {
        com_err(progname, retval, _("while downgrading lock on '%s'"),
                temp_file_name);
        exit(1);
    }
    load_database(kpropd_context, kdb5_util, file);
    retval = krb5_lock_file(kpropd_context, lock_fd, KRB5_LOCKMODE_UNLOCK);
    if (retval) {
        com_err(progname, retval, _("while unlocking '%s'"), temp_file_name);
        exit(1);
    }
    (void)close(lock_fd);

    /*
     * Send the acknowledgement message generated in
     * recv_database, then close the socket.
     */
    retval = krb5_write_message(kpropd_context, (void *) &fd, &confmsg);
    if (retval) {
        krb5_free_data_contents(kpropd_context, &confmsg);
        com_err(progname, retval, _("while sending # of received bytes"));
        exit(1);
    }
    krb5_free_data_contents(kpropd_context, &confmsg);
    if (close(fd) < 0) {
        com_err(progname, errno,
                _("while trying to close database file"));
        exit(1);
    }

    exit(0);
}

/* Default timeout can be changed using clnt_control() */
static struct timeval full_resync_timeout = { 25, 0 };

static kdb_fullresync_result_t *
full_resync(CLIENT *clnt)
{
    static kdb_fullresync_result_t clnt_res;
    uint32_t vers = IPROPX_VERSION_1; /* max version we support */
    enum clnt_stat status;

    memset(&clnt_res, 0, sizeof(clnt_res));

    status = clnt_call (clnt, IPROP_FULL_RESYNC_EXT,
                        (xdrproc_t) xdr_u_int32,
                        (caddr_t) &vers,
                        (xdrproc_t) xdr_kdb_fullresync_result_t,
                        (caddr_t) &clnt_res,
                        full_resync_timeout);
    if (status == RPC_PROCUNAVAIL) {
        status = clnt_call (clnt, IPROP_FULL_RESYNC,
                            (xdrproc_t) xdr_void,
                            (caddr_t *)&vers,
                            (xdrproc_t) xdr_kdb_fullresync_result_t,
                            (caddr_t) &clnt_res,
                            full_resync_timeout);
    }

    return (status == RPC_SUCCESS) ? &clnt_res : NULL;
}

/*
 * Beg for incrementals from the KDC.
 *
 * Returns 0 on success IFF runonce is true.
 * Returns > 0 on failure due to errors.
 */
static krb5_error_code
do_iprop(kdb_log_context *log_ctx)
{
    kadm5_ret_t retval;
    krb5_ccache cc;
    krb5_principal iprop_svc_principal;
    void *server_handle = NULL;
    char *iprop_svc_princstr = NULL;
    char *master_svc_princstr = NULL;
    unsigned int pollin, backoff_time;
    int backoff_cnt = 0;
    int reinit_cnt = 0;
    struct timeval iprop_start, iprop_end;
    uint64_t us;
    time_t frrequested = 0;
    time_t now;

    kdb_incr_result_t *incr_ret;
    kdb_last_t mylast;

    kdb_fullresync_result_t *full_ret;

    kadm5_iprop_handle_t handle;
    kdb_hlog_t *ulog;

    if (debug)
        fprintf(stderr, _("Incremental propagation enabled\n"));

    ulog = log_ctx->ulog;

    pollin = params.iprop_poll_time;
    if (pollin == 0)
        pollin = 10;

    /*
     * Grab the realm info and check if iprop is enabled.
     */
    if (def_realm == NULL) {
        retval = krb5_get_default_realm(kpropd_context, &def_realm);
        if (retval) {
            com_err(progname, retval,
                    _("Unable to get default realm"));
            return retval;
        }
    }

    params.mask |= KADM5_CONFIG_REALM;
    params.realm = def_realm;

    if (master_svc_princstr == NULL) {
        if ((retval = kadm5_get_kiprop_host_srv_name(kpropd_context,
                                                     def_realm,
                                                     &master_svc_princstr))) {
            com_err(progname, retval,
                    _("%s: unable to get kiprop host based "
                      "service name for realm %s\n"),
                    progname, def_realm);
            return retval;
        }
    }

    /*
     * Set cc to the default credentials cache
     */
    if ((retval = krb5_cc_default(kpropd_context, &cc))) {
        com_err(progname, retval,
                _("while opening default "
                  "credentials cache"));
        return retval;
    }

    retval = krb5_sname_to_principal(kpropd_context, NULL, KIPROP_SVC_NAME,
                                     KRB5_NT_SRV_HST, &iprop_svc_principal);
    if (retval) {
        com_err(progname, retval,
                _("while trying to construct host service principal"));
        return retval;
    }

    /* XXX referrals? */
    if (krb5_is_referral_realm(krb5_princ_realm(kpropd_context,
                                                iprop_svc_principal))) {
        krb5_data *r = krb5_princ_realm(kpropd_context,
                                        iprop_svc_principal);
        assert(def_realm != NULL);
        r->length = strlen(def_realm);
        r->data = strdup(def_realm);
        if (r->data == NULL) {
            com_err(progname, retval,
                    _("while determining local service principal name"));
            return retval;
        }
        /* XXX Memory leak: Old r->data value.  */
    }
    if ((retval = krb5_unparse_name(kpropd_context, iprop_svc_principal,
                                    &iprop_svc_princstr))) {
        com_err(progname, retval,
                _("while canonicalizing principal name"));
        krb5_free_principal(kpropd_context, iprop_svc_principal);
        return retval;
    }
    krb5_free_principal(kpropd_context, iprop_svc_principal);

reinit:
    /*
     * Authentication, initialize rpcsec_gss handle etc.
     */
    if (debug) {
        fprintf(stderr, _("Initializing kadm5 as client %s\n"),
                iprop_svc_princstr);
    }
    retval = kadm5_init_with_skey(kpropd_context, iprop_svc_princstr,
                                  srvtab,
                                  master_svc_princstr,
                                  &params,
                                  KADM5_STRUCT_VERSION,
                                  KADM5_API_VERSION_4,
                                  db_args,
                                  &server_handle);

    if (retval) {
        if (debug)
            fprintf(stderr, _("kadm5 initialization failed!\n"));
        if (retval == KADM5_RPC_ERROR) {
            reinit_cnt++;
            if (server_handle)
                kadm5_destroy((void *) server_handle);
            server_handle = (void *)NULL;
            handle = (kadm5_iprop_handle_t)NULL;

            com_err(progname, retval, _(
                        "while attempting to connect"
                        " to master KDC ... retrying"));
            backoff_time = backoff_from_master(&reinit_cnt);
            if (debug) {
                fprintf(stderr, _("Sleeping %d seconds to re-initialize "
                                  "kadm5 (RPC ERROR)\n"), backoff_time);
            }
            (void) sleep(backoff_time);
            goto reinit;
        } else {
            if (retval == KADM5_BAD_CLIENT_PARAMS ||
                retval == KADM5_BAD_SERVER_PARAMS) {
                com_err(progname, retval,
                        _("while initializing %s interface"),
                        progname);

                usage();
            }
            reinit_cnt++;
            com_err(progname, retval,
                    _("while initializing %s interface, retrying"),
                    progname);
            backoff_time = backoff_from_master(&reinit_cnt);
            if (debug) {
                fprintf(stderr, _("Sleeping %d seconds to re-initialize "
                                  "kadm5 (krb5kdc not running?)\n"),
                        backoff_time);
            }
            sleep(backoff_time);
            goto reinit;
        }
    }

    if (debug)
        fprintf(stderr, _("kadm5 initialization succeeded\n"));

    /*
     * Reset re-initialization count to zero now.
     */
    reinit_cnt = backoff_time = 0;

    /*
     * Reset the handle to the correct type for the RPC call
     */
    handle = server_handle;

    for (;;) {

        incr_ret = NULL;
        full_ret = NULL;

        /*
         * Get the most recent ulog entry sno + ts, which
         * we package in the request to the master KDC
         */
        mylast.last_sno = ulog->kdb_last_sno;
        mylast.last_time = ulog->kdb_last_time;

        /*
         * Loop continuously on an iprop_get_updates_1(),
         * so that we can keep probing the master for updates
         * or (if needed) do a full resync of the krb5 db.
         */

        if (debug)
            fprintf(stderr, _("Calling iprop_get_updates_1()\n"));
        gettimeofday(&iprop_start, NULL);
        incr_ret = iprop_get_updates_1(&mylast, handle->clnt);
        if (incr_ret == (kdb_incr_result_t *)NULL) {
            clnt_perror(handle->clnt,
                        _("iprop_get_updates call failed"));
            if (server_handle)
                kadm5_destroy((void *)server_handle);
            server_handle = (void *)NULL;
            handle = (kadm5_iprop_handle_t)NULL;
            if (debug) {
                fprintf(stderr, _("Reinitializing iprop because get updates "
                                  "failed\n"));
            }
            goto reinit;
        }

        switch (incr_ret->ret) {

        case UPDATE_FULL_RESYNC_NEEDED:
            /*
             * If we're already asked for a full resync and we still
             * need one and the last one hasn't timed out then just keep
             * asking for updates as eventually the resync will finish
             * (or, if it times out we'll just try again).  Note that
             * doit() also applies a timeout to the full resync, thus
             * it's OK for us to do the same here.
             */
            now = time(NULL);
            if (frrequested &&
                (now - frrequested) < params.iprop_resync_timeout)
                break;
            frrequested = now;
            if (debug)
                fprintf(stderr, _("Full resync needed\n"));
            syslog(LOG_INFO, "kpropd: Full resync needed.");

            full_ret = full_resync(handle->clnt);
            if (full_ret == (kdb_fullresync_result_t *)
                NULL) {
                clnt_perror(handle->clnt,
                            _("iprop_full_resync call failed"));
                if (server_handle)
                    kadm5_destroy((void *)
                                  server_handle);
                server_handle = (void *)NULL;
                handle = (kadm5_iprop_handle_t)NULL;
                goto reinit;
            }

            switch (full_ret->ret) {
            case UPDATE_OK:
                if (debug)
                    fprintf(stderr, _("Full resync request granted\n"));
                syslog(LOG_INFO, "Full resync request granted.");
                backoff_cnt = 0;
                break;

            case UPDATE_BUSY:
                /*
                 * Exponential backoff
                 */
                if (debug)
                    fprintf(stderr, _("Exponential backoff\n"));
                backoff_cnt++;
                break;

            case UPDATE_PERM_DENIED:
                if (debug)
                    fprintf(stderr, _("Full resync permission denied\n"));
                syslog(LOG_ERR, "Full resync, permission denied.");
                goto error;

            case UPDATE_ERROR:
                if (debug)
                    fprintf(stderr, _("Full resync error from master\n"));
                syslog(LOG_ERR, "Full resync, "
                       "error returned from master KDC.");
                goto error;

            default:
                backoff_cnt = 0;

                if (debug) {
                    fprintf(stderr,
                            _("Full resync invalid result from master\n"));
                }
                syslog(LOG_ERR, _("Full resync, "
                                  "invalid return from master KDC."));
                break;
            }
            break;

        case UPDATE_OK:
            backoff_cnt = 0;
            frrequested = 0;

            /*
             * ulog_replay() will convert the ulog updates to db
             * entries using the kdb conv api and will commit
             * the entries to the slave kdc database
             */
            if (debug) {
                fprintf(stderr,
                        _("Got incremental updates from the master\n"));
            }
            retval = ulog_replay(kpropd_context, incr_ret,
                                 db_args);
            if (retval) {
                const char *msg =
                    krb5_get_error_message(kpropd_context, retval);
                if (debug) {
                    fprintf(stderr, _("ulog_replay failed (%s), updates not "
                                      "registered\n"), msg);
                }
                syslog(LOG_ERR, "ulog_replay failed (%s), updates "
                       "not registered.", msg);
                krb5_free_error_message(kpropd_context, msg);
                break;
            }

            gettimeofday(&iprop_end, NULL);
            us = (iprop_end.tv_sec * 1000000 + iprop_end.tv_usec) -
                (iprop_start.tv_sec * 1000000 + iprop_start.tv_usec);
            syslog(LOG_INFO, "Incremental updates: %d updates / %llu us",
                   incr_ret->updates.kdb_ulog_t_len, us);

            if (debug) {
                fprintf(stderr, _("Incremental updates: %d updates / "
                                  "%llu us\n"),
                        incr_ret->updates.kdb_ulog_t_len, us);
            }
            break;

        case UPDATE_PERM_DENIED:
            if (debug)
                fprintf(stderr, _("get_updates permission denied\n"));
            syslog(LOG_ERR, "get_updates, permission denied.");
            goto error;

        case UPDATE_ERROR:
            if (debug)
                fprintf(stderr, _("get_updates error from master\n"));
            syslog(LOG_ERR, _("get_updates, error "
                              "returned from master KDC."));
            goto error;

        case UPDATE_BUSY:
            /*
             * Exponential backoff
             */
            if (debug)
                fprintf(stderr, _("get_updates master busy; backoff\n"));
            backoff_cnt++;
            break;

        case UPDATE_NIL:
            /*
             * Master-slave are in sync
             */
            if (debug)
                fprintf(stderr, _("Master, slave KDC's "
                                  "are in-sync, no updates\n"));
            backoff_cnt = 0;
            frrequested = 0;
            break;

        default:
            backoff_cnt = 0;
            if (debug)
                fprintf(stderr, _("get_updates invalid result from master\n"));
            syslog(LOG_ERR, "get_updates, invalid return from master KDC.");
            break;
        }

        if (runonce == 1)
            goto done;

        /*
         * Sleep for the specified poll interval (Default is 2 mts),
         * or do a binary exponential backoff if we get an
         * UPDATE_BUSY signal
         */
        if (backoff_cnt > 0) {
            backoff_time = backoff_from_master(&backoff_cnt);
            if (debug)
                fprintf(stderr, _("Busy signal received "
                                  "from master, backoff for %d secs\n"),
                        backoff_time);
            (void) sleep(backoff_time);
        } else {
            if (debug) {
                fprintf(stderr, _("Waiting for %d seconds before checking "
                                  "for updates again\n"), pollin);
            }
            (void) sleep(pollin);
        }

    }


error:
    if (debug)
        fprintf(stderr, _("ERROR returned by master, bailing\n"));
    syslog(LOG_ERR, _("ERROR returned by master KDC, bailing.\n"));
done:
    if(iprop_svc_princstr)
        free(iprop_svc_princstr);
    if (master_svc_princstr)
        free(master_svc_princstr);
    if ((retval = krb5_cc_close(kpropd_context, cc))) {
        com_err(progname, retval, _("while closing default ccache"));
        return retval;
    }
    if (def_realm && kpropd_context)
        krb5_free_default_realm(kpropd_context, def_realm);
    if (server_handle)
        kadm5_destroy((void *)server_handle);
    if (kpropd_context)
        krb5_free_context(kpropd_context);

    if (runonce == 1)
        return (0);
    else
        return 1;
}


/*
 * Do exponential backoff, since master KDC is BUSY or down
 */
unsigned int backoff_from_master(int *cnt) {
    unsigned int btime;

    btime = (unsigned int)(2<<(*cnt));
    if (btime > MAX_BACKOFF) {
        btime = MAX_BACKOFF;
        (*cnt)--;
    }

    return (btime);
}

static void
kpropd_com_err_proc(const char *whoami,
                    long code,
                    const char *fmt,
                    va_list args)
#if !defined(__cplusplus) && (__GNUC__ > 2)
    __attribute__((__format__(__printf__, 3, 0)))
#endif
    ;

static void
kpropd_com_err_proc(const char *whoami,
                    long code,
                    const char *fmt,
                    va_list args)
{
    char    error_buf[8096];

    error_buf[0] = '\0';
    if (fmt)
        vsnprintf(error_buf, sizeof(error_buf), fmt, args);
    syslog(LOG_ERR, "%s%s%s%s%s", whoami ? whoami : "", whoami ? ": " : "",
           code ? error_message(code) : "", code ? " " : "", error_buf);
}

void PRS(argv)
    char    **argv;
{
    register char   *word, ch;
    krb5_error_code retval;
    static const char       tmp[] = ".temp";
    kdb_log_context *log_ctx;

    (void) memset(&params, 0, sizeof (params));

    /* Since we may modify the KDB with ulog_replay(), we must read the KDC
     * profile. */
    retval = krb5int_init_context_kdc(&kpropd_context);
    if (retval) {
        com_err(argv[0], retval, _("while initializing krb5"));
        exit(1);
    }

    progname = *argv++;
    while ((word = *argv++)) {
        if (*word == '-') {
            word++;
            while (word && (ch = *word++)) {
                switch(ch){
                case 'f':
                    if (*word)
                        file = word;
                    else
                        file = *argv++;
                    if (!file)
                        usage();
                    word = 0;
                    break;
                case 'F':
                    if (*word)
                        kerb_database = word;
                    else
                        kerb_database = *argv++;
                    if (!kerb_database)
                        usage();
                    word = 0;
                    break;
                case 'p':
                    if (*word)
                        kdb5_util = word;
                    else
                        kdb5_util = *argv++;
                    if (!kdb5_util)
                        usage();
                    word = 0;
                    break;
                case 'P':
                    port = (*word != '\0') ? word : *argv++;
                    if (port == NULL)
                        usage();
                    word = 0;
                    break;
                case 'r':
                    if (*word)
                        realm = word;
                    else
                        realm = *argv++;
                    if (!realm)
                        usage();
                    word = 0;
                    break;
                case 's':
                    if (*word)
                        srvtab = word;
                    else
                        srvtab = *argv++;
                    if (!srvtab)
                        usage();
                    word = 0;
                    break;
                case 'D':
                    nodaemon++;
                    break;
                case 'd':
                    debug++;
                    break;
                case 'S':
                    fprintf(stderr,
                            _("warning: The -S option is now deprecated.\n"));
                    standalone++;
                    break;
                case 'a':
                    if (*word)
                        acl_file_name = word;
                    else
                        acl_file_name = *argv++;
                    if (!acl_file_name)
                        usage();
                    word = 0;
                    break;

                case 't':
                    /*
                     * Undocumented option - for testing only.
                     *
                     * Option to run the kpropd server exactly
                     * once.
                     */
                    runonce = 1;
                    break;

                case 'x':
                {
                    char **new_db_args;
                    new_db_args = realloc(db_args,
                                          (db_args_size+2)*sizeof(*db_args));
                    if (new_db_args == NULL) {
                        com_err(argv[0], errno, _("copying db args"));
                        exit(1);
                    }
                    db_args = new_db_args;
                    if (*word)
                        db_args[db_args_size] = word;
                    else
                        db_args[db_args_size] = *argv++;
                    word = 0;
                    if (db_args[db_args_size] == NULL)
                        usage();
                    db_args[db_args_size+1] = NULL;
                    db_args_size++;
                }

                default:
                    usage();
                }

            }
        } else
            /* We don't take any arguments, only options */
            usage();
    }
    openlog("kpropd", LOG_PID | LOG_ODELAY, SYSLOG_CLASS);
    if (!debug)
        set_com_err_hook(kpropd_com_err_proc);
    /*
     * Get my hostname, so we can construct my service name
     */
    retval = krb5_sname_to_principal(kpropd_context,
                                     NULL, KPROP_SERVICE_NAME,
                                     KRB5_NT_SRV_HST, &server);
    if (retval) {
        com_err(progname, retval,
                _("while trying to construct my service name"));
        exit(1);
    }
    if (realm) {
        retval = krb5_set_principal_realm(kpropd_context, server, realm);
        if (retval) {
            com_err(progname, errno,
                    _("while constructing my service realm"));
            exit(1);
        }
    }
    /*
     * Construct the name of the temporary file.
     */
    if (asprintf(&temp_file_name, "%s%s", file, tmp) < 0) {
        com_err(progname, ENOMEM,
                _("while allocating filename for temp file"));
        exit(1);
    }

    retval = kadm5_get_config_params(kpropd_context, 1, &params, &params);
    if (retval) {
        com_err(progname, retval, _("while initializing"));
        exit(1);
    }
    if (params.iprop_enabled == TRUE) {
        ulog_set_role(kpropd_context, IPROP_SLAVE);

        if (ulog_map(kpropd_context, params.iprop_logfile,
                     params.iprop_ulogsize, FKPROPD, db_args)) {
            com_err(progname, errno,
                    _("Unable to map log!\n"));
            exit(1);
        }
    }
    log_ctx = kpropd_context->kdblog_context;
    if (log_ctx && (log_ctx->iproprole == IPROP_SLAVE))
        ulog_set_role(kpropd_context, IPROP_SLAVE);
}

/*
 * Figure out who's calling on the other end of the connection....
 */
void
kerberos_authenticate(context, fd, clientp, etype, my_sin)
    krb5_context          context;
    int                   fd;
    krb5_principal      * clientp;
    krb5_enctype        * etype;
    struct sockaddr_storage * my_sin;
{
    krb5_error_code       retval;
    krb5_ticket         * ticket;
    struct sockaddr_storage  r_sin;
    GETSOCKNAME_ARG3_TYPE sin_length;
    krb5_keytab           keytab = NULL;

    /*
     * Set recv_addr and send_addr
     */
    sockaddr2krbaddr(context, my_sin->ss_family, (struct sockaddr *) my_sin,
                     &sender_addr);

    sin_length = sizeof(r_sin);
    if (getsockname(fd, (struct sockaddr *) &r_sin, &sin_length)) {
        com_err(progname, errno, _("while getting local socket address"));
        exit(1);
    }

    sockaddr2krbaddr(context, r_sin.ss_family, (struct sockaddr *) &r_sin,
                     &receiver_addr);

    if (debug) {
        char *name;

        retval = krb5_unparse_name(context, server, &name);
        if (retval) {
            com_err(progname, retval, _("while unparsing client name"));
            exit(1);
        }
        printf("krb5_recvauth(%d, %s, %s, ...)\n", fd, kprop_version, name);
        free(name);
    }

    retval = krb5_auth_con_init(context, &auth_context);
    if (retval) {
        syslog(LOG_ERR, _("Error in krb5_auth_con_ini: %s"),
               error_message(retval));
        exit(1);
    }

    retval = krb5_auth_con_setflags(context, auth_context,
                                    KRB5_AUTH_CONTEXT_DO_SEQUENCE);
    if (retval) {
        syslog(LOG_ERR, _("Error in krb5_auth_con_setflags: %s"),
               error_message(retval));
        exit(1);
    }

    retval = krb5_auth_con_setaddrs(context, auth_context, receiver_addr,
                                    sender_addr);
    if (retval) {
        syslog(LOG_ERR, _("Error in krb5_auth_con_setaddrs: %s"),
               error_message(retval));
        exit(1);
    }

    if (srvtab) {
        retval = krb5_kt_resolve(context, srvtab, &keytab);
        if (retval) {
            syslog(LOG_ERR, _("Error in krb5_kt_resolve: %s"),
                   error_message(retval));
            exit(1);
        }
    }

    retval = krb5_recvauth(context, &auth_context, (void *) &fd,
                           kprop_version, server, 0, keytab, &ticket);
    if (retval) {
        syslog(LOG_ERR, _("Error in krb5_recvauth: %s"),
               error_message(retval));
        exit(1);
    }

    retval = krb5_copy_principal(context, ticket->enc_part2->client, clientp);
    if (retval) {
        syslog(LOG_ERR, _("Error in krb5_copy_prinicpal: %s"),
               error_message(retval));
        exit(1);
    }

    *etype = ticket->enc_part.enctype;

    if (debug) {
        char * name;
        char etypebuf[100];

        retval = krb5_unparse_name(context, *clientp, &name);
        if (retval) {
            com_err(progname, retval, _("while unparsing client name"));
            exit(1);
        }

        retval = krb5_enctype_to_string(*etype, etypebuf, sizeof(etypebuf));
        if (retval) {
            com_err(progname, retval, _("while unparsing ticket etype"));
            exit(1);
        }

        printf(_("authenticated client: %s (etype == %s)\n"), name, etypebuf);
        free(name);
    }

    krb5_free_ticket(context, ticket);
}

krb5_boolean
authorized_principal(context, p, auth_etype)
    krb5_context context;
    krb5_principal p;
    krb5_enctype auth_etype;
{
    char                *name, *ptr;
    char                buf[1024];
    krb5_error_code     retval;
    FILE                *acl_file;
    int                 end;
    krb5_enctype        acl_etype;

    retval = krb5_unparse_name(context, p, &name);
    if (retval)
        return FALSE;

    acl_file = fopen(acl_file_name, "r");
    if (!acl_file)
        return FALSE;

    while (!feof(acl_file)) {
        if (!fgets(buf, sizeof(buf), acl_file))
            break;
        end = strlen(buf) - 1;
        if (buf[end] == '\n')
            buf[end] = '\0';
        if (!strncmp(name, buf, strlen(name))) {
            ptr = buf+strlen(name);

            /* if the next character is not whitespace or nul, then
               the match is only partial.  continue on to new lines. */
            if (*ptr && !isspace((int) *ptr))
                continue;

            /* otherwise, skip trailing whitespace */
            for (; *ptr && isspace((int) *ptr); ptr++) ;

            /* now, look for an etype string. if there isn't one,
               return true.  if there is an invalid string, continue.
               If there is a valid string, return true only if it
               matches the etype passed in, otherwise continue */

            if ((*ptr) &&
                ((retval = krb5_string_to_enctype(ptr, &acl_etype)) ||
                 (acl_etype != auth_etype)))
                continue;

            free(name);
            fclose(acl_file);
            return TRUE;
        }
    }
    free(name);
    fclose(acl_file);
    return FALSE;
}

void
recv_database(krb5_context context, int fd, int database_fd,
              krb5_data *confmsg)
{
    krb5_ui_4       database_size; /* This must be 4 bytes */
    int     received_size, n;
    char            buf[1024];
    krb5_data       inbuf, outbuf;
    krb5_error_code retval;

    /*
     * Receive and decode size from client
     */
    retval = krb5_read_message(context, (void *) &fd, &inbuf);
    if (retval) {
        send_error(context, fd, retval, "while reading database size");
        com_err(progname, retval,
                _("while reading size of database from client"));
        exit(1);
    }
    if (krb5_is_krb_error(&inbuf))
        recv_error(context, &inbuf);
    retval = krb5_rd_safe(context,auth_context,&inbuf,&outbuf,NULL);
    if (retval) {
        send_error(context, fd, retval,
                   "while decoding database size");
        krb5_free_data_contents(context, &inbuf);
        com_err(progname, retval,
                _("while decoding database size from client"));
        exit(1);
    }
    memcpy(&database_size, outbuf.data, sizeof(database_size));
    krb5_free_data_contents(context, &inbuf);
    krb5_free_data_contents(context, &outbuf);
    database_size = ntohl(database_size);

    /*
     * Initialize the initial vector.
     */
    retval = krb5_auth_con_initivector(context, auth_context);
    if (retval) {
        send_error(context, fd, retval,
                   "failed while initializing i_vector");
        com_err(progname, retval, _("while initializing i_vector"));
        exit(1);
    }

    if (debug)
        fprintf(stderr, _("Full propagation transfer started.\n"));

    /*
     * Now start receiving the database from the net
     */
    received_size = 0;
    while (received_size < database_size) {
        retval = krb5_read_message(context, (void *) &fd, &inbuf);
        if (retval) {
            snprintf(buf, sizeof(buf),
                     "while reading database block starting at offset %d",
                     received_size);
            com_err(progname, retval, "%s", buf);
            send_error(context, fd, retval, buf);
            exit(1);
        }
        if (krb5_is_krb_error(&inbuf))
            recv_error(context, &inbuf);
        retval = krb5_rd_priv(context, auth_context, &inbuf,
                              &outbuf, NULL);
        if (retval) {
            snprintf(buf, sizeof(buf),
                     "while decoding database block starting at offset %d",
                     received_size);
            com_err(progname, retval, "%s", buf);
            send_error(context, fd, retval, buf);
            krb5_free_data_contents(context, &inbuf);
            exit(1);
        }
        n = write(database_fd, outbuf.data, outbuf.length);
        krb5_free_data_contents(context, &inbuf);
        krb5_free_data_contents(context, &outbuf);
        if (n < 0) {
            snprintf(buf, sizeof(buf),
                     "while writing database block starting at offset %d",
                     received_size);
            send_error(context, fd, errno, buf);
        } else if (n != outbuf.length) {
            snprintf(buf, sizeof(buf), "incomplete write while writing "
                     "database block starting at \noffset %d (%d written, "
                     "%d expected)", received_size, n, outbuf.length);
            send_error(context, fd, KRB5KRB_ERR_GENERIC, buf);
        }
        received_size += outbuf.length;
        /* Report xfer progress to do_iprop() parent process */
    }
    /*
     * OK, we've seen the entire file.  Did we get too many bytes?
     */
    if (received_size > database_size) {
        snprintf(buf, sizeof(buf),
                 "Received %d bytes, expected %d bytes for database file",
                 received_size, database_size);
        send_error(context, fd, KRB5KRB_ERR_GENERIC, buf);
    }

    if (debug)
        fprintf(stderr, _("Full propagation transfer finished.\n"));

    /*
     * Create message acknowledging number of bytes received, but
     * don't send it until kdb5_util returns successfully.
     */
    database_size = htonl(database_size);
    inbuf.data = (char *) &database_size;
    inbuf.length = sizeof(database_size);
    retval = krb5_mk_safe(context,auth_context,&inbuf,confmsg,NULL);
    if (retval) {
        com_err(progname, retval,
                "while encoding # of receieved bytes");
        send_error(context, fd, retval,
                   "while encoding # of received bytes");
        exit(1);
    }
}


void
send_error(context, fd, err_code, err_text)
    krb5_context context;
    int fd;
    krb5_error_code     err_code;
    char        *err_text;
{
    krb5_error      error;
    const char      *text;
    krb5_data       outbuf;
    char            buf[1024];

    memset(&error, 0, sizeof(error));
    krb5_us_timeofday(context, &error.stime, &error.susec);
    error.server = server;
    error.client = client;

    if (err_text)
        text = err_text;
    else
        text = error_message(err_code);

    error.error = err_code - ERROR_TABLE_BASE_krb5;
    if (error.error > 127) {
        error.error = KRB_ERR_GENERIC;
        if (err_text) {
            snprintf(buf, sizeof(buf), "%s %s",
                     error_message(err_code), err_text);
            text = buf;
        }
    }
    error.text.length = strlen(text) + 1;
    error.text.data = strdup(text);
    if (error.text.data) {
        if (!krb5_mk_error(context, &error, &outbuf)) {
            (void) krb5_write_message(context, (void *)&fd,&outbuf);
            krb5_free_data_contents(context, &outbuf);
        }
        free(error.text.data);
    }
}

void
recv_error(context, inbuf)
    krb5_context context;
    krb5_data   *inbuf;
{
    krb5_error      *error;
    krb5_error_code retval;

    retval = krb5_rd_error(context, inbuf, &error);
    if (retval) {
        com_err(progname, retval,
                _("while decoding error packet from client"));
        exit(1);
    }
    if (error->error == KRB_ERR_GENERIC) {
        if (error->text.data)
            fprintf(stderr, _("Generic remote error: %s\n"), error->text.data);
    } else if (error->error) {
        com_err(progname,
                (krb5_error_code) error->error + ERROR_TABLE_BASE_krb5,
                _("signaled from server"));
        if (error->text.data) {
            fprintf(stderr, _("Error text from client: %s\n"),
                    error->text.data);
        }
    }
    krb5_free_error(context, error);
    exit(1);
}

void
load_database(context, kdb_util, database_file_name)
    krb5_context context;
    char *kdb_util;
    char *database_file_name;
{
    static char     *edit_av[10];
    int     error_ret, save_stderr = -1;
    int     child_pid;
    int     count;

    /* <sys/param.h> has been included, so BSD will be defined on
       BSD systems */
#if BSD > 0 && BSD <= 43
#ifndef WEXITSTATUS
#define WEXITSTATUS(w) (w).w_retcode
#endif
    union wait      waitb;
#else
    int     waitb;
#endif
    krb5_error_code retval;
    kdb_log_context *log_ctx;

    if (debug)
        printf("calling kdb5_util to load database\n");

    log_ctx = context->kdblog_context;

    edit_av[0] = kdb_util;
    count = 1;
    if (realm) {
        edit_av[count++] = "-r";
        edit_av[count++] = realm;
    }
    edit_av[count++] = "load";
    if (kerb_database) {
        edit_av[count++] = "-d";
        edit_av[count++] = kerb_database;
    }
    if (log_ctx && log_ctx->iproprole == IPROP_SLAVE) {
        edit_av[count++] = "-i";
    }
    edit_av[count++] = database_file_name;
    edit_av[count++] = NULL;

    switch(child_pid = fork()) {
    case -1:
        com_err(progname, errno, _("while trying to fork %s"), kdb_util);
        exit(1);
    case 0:
        if (!debug) {
            int devnull;

            devnull = open("/dev/null", O_RDWR);
            if (devnull == -1) {
                perror("opening /dev/null");
                exit(1);
            }
            save_stderr = dup(STDERR_FILENO);
            dup2(devnull, STDIN_FILENO);
            /* Allow [debug] output to be seen if it can be. */
            if (!standalone) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
            }
        }

        execv(kdb_util, edit_av);
        retval = errno;
        if (standalone) {
            /* No sense printing anything in inetd nowait service mode. */
            dup2(save_stderr, STDERR_FILENO);
            com_err(progname, retval, _("while trying to exec %s"), kdb_util);
        }
        _exit(1);
        /*NOTREACHED*/
    default:
        if (debug)
            printf("Child PID is %d\n", child_pid);
        if (wait(&waitb) < 0) {
            com_err(progname, errno, _("while waiting for %s"), kdb_util);
            exit(1);
        }
    }

    if (!WIFEXITED(waitb)) {
        com_err(progname, 0, _("%s load terminated"), kdb_util);
        exit(1);
    }

    error_ret = WEXITSTATUS(waitb);
    if (error_ret) {
        com_err(progname, 0, _("%s returned a bad exit status (%d)"),
                kdb_util, error_ret);
        exit(1);
    }
}

/*
 * Get the host base service name for the kiprop principal. Returns
 * KADM5_OK on success. Caller must free the storage allocated
 * for host_service_name.
 */
static kadm5_ret_t
kadm5_get_kiprop_host_srv_name(krb5_context context,
                               const char *realm_name,
                               char **host_service_name)
{
    char *name;
    char *host;

    host = params.admin_server; /* XXX */

    if (asprintf(&name, "%s/%s", KADM5_KIPROP_HOST_SERVICE, host) < 0) {
        free(host);
        return (ENOMEM);
    }
    *host_service_name = name;

    return (KADM5_OK);
}
