/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1994, 2008 by the Massachusetts Institute of Technology.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Base functions for a kadmin command line interface using the OVSecure
 * library */

/* for "_" macro */
#include "k5-platform.h"
#include <krb5.h>
#include <kadm5/admin.h>
#include <adm_proto.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <math.h>
#include <unistd.h>
#include <pwd.h>
/* #include <sys/timeb.h> */
#include <time.h>
#include "kadmin.h"

/* special struct to convert flag names for principals
   to actual krb5_flags for a principal */
struct pflag {
    char *flagname;             /* name of flag as typed to CLI */
    size_t flaglen;             /* length of string (not counting -,+) */
    krb5_flags theflag;         /* actual principal flag to set/clear */
    int set;                    /* 0 means clear, 1 means set (on '-') */
};

static struct pflag flags[] = {
    {"allow_postdated",     15,     KRB5_KDB_DISALLOW_POSTDATED,    1 },
    {"allow_forwardable",   17,     KRB5_KDB_DISALLOW_FORWARDABLE,  1 },
    {"allow_tgs_req",       13,     KRB5_KDB_DISALLOW_TGT_BASED,    1 },
    {"allow_renewable",     15,     KRB5_KDB_DISALLOW_RENEWABLE,    1 },
    {"allow_proxiable",     15,     KRB5_KDB_DISALLOW_PROXIABLE,    1 },
    {"allow_dup_skey",      14,     KRB5_KDB_DISALLOW_DUP_SKEY,     1 },
    {"allow_tix",            9,     KRB5_KDB_DISALLOW_ALL_TIX,      1 },
    {"requires_preauth",    16,     KRB5_KDB_REQUIRES_PRE_AUTH,     0 },
    {"requires_hwauth",     15,     KRB5_KDB_REQUIRES_HW_AUTH,      0 },
    {"needchange",          10,     KRB5_KDB_REQUIRES_PWCHANGE,     0 },
    {"allow_svr",            9,     KRB5_KDB_DISALLOW_SVR,          1 },
    {"password_changing_service", 25, KRB5_KDB_PWCHANGE_SERVICE,    0 },
    {"support_desmd5",      14,     KRB5_KDB_SUPPORT_DESMD5,        0 },
    {"ok_as_delegate",      14,     KRB5_KDB_OK_AS_DELEGATE,        0 },
    {"ok_to_auth_as_delegate", 22,  KRB5_KDB_OK_TO_AUTH_AS_DELEGATE, 0 },
    {"no_auth_data_required", 21,   KRB5_KDB_NO_AUTH_DATA_REQUIRED, 0 },
};

static char *prflags[] = {
    "DISALLOW_POSTDATED",       /* 0x00000001 */
    "DISALLOW_FORWARDABLE",     /* 0x00000002 */
    "DISALLOW_TGT_BASED",       /* 0x00000004 */
    "DISALLOW_RENEWABLE",       /* 0x00000008 */
    "DISALLOW_PROXIABLE",       /* 0x00000010 */
    "DISALLOW_DUP_SKEY",        /* 0x00000020 */
    "DISALLOW_ALL_TIX",         /* 0x00000040 */
    "REQUIRES_PRE_AUTH",        /* 0x00000080 */
    "REQUIRES_HW_AUTH",         /* 0x00000100 */
    "REQUIRES_PWCHANGE",        /* 0x00000200 */
    "UNKNOWN_0x00000400",       /* 0x00000400 */
    "UNKNOWN_0x00000800",       /* 0x00000800 */
    "DISALLOW_SVR",             /* 0x00001000 */
    "PWCHANGE_SERVICE",         /* 0x00002000 */
    "SUPPORT_DESMD5",           /* 0x00004000 */
    "NEW_PRINC",                /* 0x00008000 */
    "UNKNOWN_0x00010000",       /* 0x00010000 */
    "UNKNOWN_0x00020000",       /* 0x00020000 */
    "UNKNOWN_0x00040000",       /* 0x00040000 */
    "UNKNOWN_0x00080000",       /* 0x00080000 */
    "OK_AS_DELEGATE",           /* 0x00100000 */
    "OK_TO_AUTH_AS_DELEGATE",   /* 0x00200000 */
    "NO_AUTH_DATA_REQUIRED",    /* 0x00400000 */
};

int exit_status = 0;
char *def_realm = NULL;
char *whoami = NULL;

void *handle = NULL;
krb5_context context;
char *ccache_name = NULL;

int locked = 0;

static void
usage()
{
    fprintf(stderr,
            _("Usage: %s [-r realm] [-p principal] [-q query] "
              "[clnt|local args]\n"
              "\tclnt args: [-s admin_server[:port]] "
              "[[-c ccache]|[-k [-t keytab]]]|[-n]\n"
              "\tlocal args: [-x db_args]* [-d dbname] "
              "[-e \"enc:salt ...\"] [-m]\n"
              "where,\n\t[-x db_args]* - any number of database specific "
              "arguments.\n"
              "\t\t\tLook at each database documentation for supported "
              "arguments\n"), whoami);
    exit(1);
}

static char *
strdur(time_t duration)
{
    static char out[50];
    int neg, days, hours, minutes, seconds;

    if (duration < 0) {
        duration *= -1;
        neg = 1;
    } else
        neg = 0;
    days = duration / (24 * 3600);
    duration %= 24 * 3600;
    hours = duration / 3600;
    duration %= 3600;
    minutes = duration / 60;
    duration %= 60;
    seconds = duration;
    snprintf(out, sizeof(out), "%s%d %s %02d:%02d:%02d", neg ? "-" : "",
             days, days == 1 ? "day" : "days",
             hours, minutes, seconds);
    return out;
}

static char *
strdate(krb5_timestamp when)
{
    struct tm *tm;
    static char out[40];

    time_t lcltim = when;
    tm = localtime(&lcltim);
    strftime(out, sizeof(out), "%a %b %d %H:%M:%S %Z %Y", tm);
    return out;
}

/* this is a wrapper to go around krb5_parse_principal so we can set
   the default realm up properly */
static krb5_error_code
kadmin_parse_name(char *name, krb5_principal *principal)
{
    char *cp, *fullname;
    krb5_error_code retval;
    int result;

    /* assumes def_realm is initialized! */
    cp = strchr(name, '@');
    while (cp) {
        if (cp - name && *(cp - 1) != '\\')
            break;
        else
            cp = strchr(cp + 1, '@');
    }
    if (cp == NULL)
        result = asprintf(&fullname, "%s@%s", name, def_realm);
    else
        result = asprintf(&fullname, "%s", name);
    if (result < 0)
        return ENOMEM;
    retval = krb5_parse_name(context, fullname, principal);
    free(fullname);
    return retval;
}

static void
extended_com_err_fn(const char *myprog, errcode_t code,
                    const char *fmt, va_list args)
{
    const char *emsg;

    if (code) {
        emsg = krb5_get_error_message(context, code);
        fprintf(stderr, "%s: %s ", myprog, emsg);
        krb5_free_error_message(context, emsg);
    } else {
        fprintf(stderr, "%s: ", myprog);
    }
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
}

/* Create a principal using the oldest appropriate kadm5 API. */
static krb5_error_code
create_princ(kadm5_principal_ent_rec *princ, long mask, int n_ks,
             krb5_key_salt_tuple *ks, char *pass)
{
    if (ks)
        return kadm5_create_principal_3(handle, princ, mask, n_ks, ks, pass);
    else
        return kadm5_create_principal(handle, princ, mask, pass);
}

/* Randomize a principal's password using the oldest appropriate kadm5 API. */
static krb5_error_code
randkey_princ(krb5_principal princ, krb5_boolean keepold, int n_ks,
              krb5_key_salt_tuple *ks)
{
    if (keepold || ks) {
        return kadm5_randkey_principal_3(handle, princ, keepold, n_ks, ks,
                                         NULL, NULL);
    } else
        return kadm5_randkey_principal(handle, princ, NULL, NULL);
}

char *
kadmin_startup(int argc, char *argv[])
{
    extern char *optarg;
    char *princstr = NULL, *keytab_name = NULL, *query = NULL;
    char *password = NULL;
    char *luser, *canon, *cp;
    int optchar, freeprinc = 0, use_keytab = 0, use_anonymous = 0;
    struct passwd *pw;
    kadm5_ret_t retval;
    krb5_ccache cc;
    krb5_principal princ;
    kadm5_config_params params;
    char **db_args = NULL;
    int db_args_size = 0;
    char *db_name = NULL;
    char *svcname, *realm;

    memset(&params, 0, sizeof(params));

    if (strcmp(whoami, "kadmin.local") == 0)
        set_com_err_hook(extended_com_err_fn);

    retval = kadm5_init_krb5_context(&context);
    if (retval) {
        com_err(whoami, retval, _("while initializing krb5 library"));
        exit(1);
    }

    while ((optchar = getopt(argc, argv,
                             "x:r:p:knq:w:d:s:mc:t:e:ON")) != EOF) {
        switch (optchar) {
        case 'x':
            db_args_size++;
            db_args = realloc(db_args, sizeof(char*) * (db_args_size + 1));
            if (db_args == NULL) {
                fprintf(stderr,
                        _("%s: Cannot initialize. Not enough memory\n"),
                        argv[0]);
                exit(1);
            }
            db_args[db_args_size - 1] = optarg;
            db_args[db_args_size] = NULL;
            break;

        case 'r':
            def_realm = optarg;
            break;
        case 'p':
            princstr = optarg;
            break;
        case 'c':
            ccache_name = optarg;
            break;
        case 'k':
            use_keytab++;
            break;
        case 'n':
            use_anonymous++;
            break;
        case 't':
            keytab_name = optarg;
            break;
        case 'w':
            password = optarg;
            break;
        case 'q':
            query = optarg;
            break;
        case 'd':
            /* db_name has to be passed as part of the db_args. */
            free(db_name);
            asprintf(&db_name, "dbname=%s", optarg);

            db_args_size++;
            db_args = realloc(db_args, sizeof(char*) * (db_args_size + 1));
            if (db_args == NULL) {
                fprintf(stderr,
                        _("%s: Cannot initialize. Not enough memory\n"),
                        argv[0]);
                exit(1);
            }
            db_args[db_args_size - 1] = db_name;
            db_args[db_args_size] = NULL;
            break;
        case 's':
            params.admin_server = optarg;
            params.mask |= KADM5_CONFIG_ADMIN_SERVER;
            break;
        case 'm':
            params.mkey_from_kbd = 1;
            params.mask |= KADM5_CONFIG_MKEY_FROM_KBD;
            break;
        case 'e':
            retval = krb5_string_to_keysalts(optarg, ", \t", ":.-", 0,
                                             &params.keysalts,
                                             &params.num_keysalts);
            if (retval) {
                com_err(whoami, retval, _("while parsing keysalts %s"),
                        optarg);
                exit(1);
            }
            params.mask |= KADM5_CONFIG_ENCTYPES;
            break;
        case 'O':
            params.mask |= KADM5_CONFIG_OLD_AUTH_GSSAPI;
            break;
        case 'N':
            params.mask |= KADM5_CONFIG_AUTH_NOFALLBACK;
            break;
        default:
            usage();
        }
    }
    if ((ccache_name && use_keytab) ||
        (keytab_name && !use_keytab) ||
        (ccache_name && use_anonymous) ||
        (use_anonymous && use_keytab))
        usage();

    if (def_realm == NULL && krb5_get_default_realm(context, &def_realm)) {
        fprintf(stderr, _("%s: unable to get default realm\n"), whoami);
        exit(1);
    }

    params.mask |= KADM5_CONFIG_REALM;
    params.realm = def_realm;

    if (params.mask & KADM5_CONFIG_OLD_AUTH_GSSAPI)
        svcname = KADM5_ADMIN_SERVICE;
    else
        svcname = NULL;

    /*
     * Set cc to an open credentials cache, either specified by the -c
     * argument or the default.
     */
    if (ccache_name == NULL) {
        retval = krb5_cc_default(context, &cc);
        if (retval) {
            com_err(whoami, retval,
                    _("while opening default credentials cache"));
            exit(1);
        }
    } else {
        retval = krb5_cc_resolve(context, ccache_name, &cc);
        if (retval) {
            com_err(whoami, retval, _("while opening credentials cache %s"),
                    ccache_name);
            exit(1);
        }
    }

    /*
     * If no principal name is specified: If a ccache was specified
     * and its primary principal name can be read, it is used, else if
     * a keytab was specified, the principal name is host/hostname,
     * otherwise append "/admin" to the primary name of the default
     * ccache, $USER, or pw_name.
     *
     * Gee, 100+ lines to figure out the client principal name.  This
     * should be compressed...
     */

    if (princstr == NULL) {
        if (ccache_name != NULL &&
            !krb5_cc_get_principal(context, cc, &princ)) {
            retval = krb5_unparse_name(context, princ, &princstr);
            if (retval) {
                com_err(whoami, retval,
                        _("while canonicalizing principal name"));
                exit(1);
            }
            krb5_free_principal(context, princ);
            freeprinc++;
        } else if (use_keytab != 0) {
            retval = krb5_sname_to_principal(context, NULL, "host",
                                             KRB5_NT_SRV_HST, &princ);
            if (retval) {
                com_err(whoami, retval, _("creating host service principal"));
                exit(1);
            }
            retval = krb5_unparse_name(context, princ, &princstr);
            if (retval) {
                com_err(whoami, retval,
                        _("while canonicalizing principal name"));
                exit(1);
            }
            krb5_free_principal(context, princ);
            freeprinc++;
        } else if (!krb5_cc_get_principal(context, cc, &princ)) {
            if (krb5_unparse_name(context, princ, &canon)) {
                fprintf(stderr, _("%s: unable to canonicalize principal\n"),
                        whoami);
                exit(1);
            }
            /* Strip out realm of principal if it's there. */
            realm = strchr(canon, '@');
            while (realm) {
                if (realm > canon && *(realm - 1) != '\\')
                    break;
                realm = strchr(realm + 1, '@');
            }
            if (realm)
                *realm++ = '\0';
            cp = strchr(canon, '/');
            while (cp) {
                if (cp > canon && *(cp - 1) != '\\')
                    break;
                cp = strchr(cp + 1, '/');
            }
            if (cp != NULL)
                *cp = '\0';
            if (asprintf(&princstr, "%s/admin%s%s", canon,
                         (realm) ? "@" : "",
                         (realm) ? realm : "") < 0) {
                fprintf(stderr, _("%s: out of memory\n"), whoami);
                exit(1);
            }
            free(canon);
            krb5_free_principal(context, princ);
            freeprinc++;
        } else if ((luser = getenv("USER"))) {
            if (asprintf(&princstr, "%s/admin@%s", luser, def_realm) < 0) {
                fprintf(stderr, _("%s: out of memory\n"), whoami);
                exit(1);
            }
            freeprinc++;
        } else if ((pw = getpwuid(getuid()))) {
            if (asprintf(&princstr, "%s/admin@%s", pw->pw_name,
                         def_realm) < 0) {
                fprintf(stderr, _("%s: out of memory\n"), whoami);
                exit(1);
            }
            freeprinc++;
        } else {
            fprintf(stderr, _("%s: unable to figure out a principal name\n"),
                    whoami);
            exit(1);
        }
    }

    retval = krb5_klog_init(context, "admin_server", whoami, 0);
    if (retval) {
        com_err(whoami, retval, _("while setting up logging"));
        exit(1);
    }

    /*
     * Initialize the kadm5 connection.  If we were given a ccache,
     * use it.  Otherwise, use/prompt for the password.
     */
    if (ccache_name) {
        printf(_("Authenticating as principal %s with existing "
                 "credentials.\n"), princstr);
        retval = kadm5_init_with_creds(context, princstr, cc, svcname, &params,
                                       KADM5_STRUCT_VERSION,
                                       KADM5_API_VERSION_4, db_args, &handle);
    } else if (use_anonymous) {
        printf(_("Authenticating as principal %s with password; "
                 "anonymous requested.\n"), princstr);
        retval = kadm5_init_anonymous(context, princstr, svcname, &params,
                                      KADM5_STRUCT_VERSION,
                                      KADM5_API_VERSION_4, db_args, &handle);
    } else if (use_keytab) {
        if (keytab_name)
            printf(_("Authenticating as principal %s with keytab %s.\n"),
                   princstr, keytab_name);
        else
            printf(_("Authenticating as principal %s with default keytab.\n"),
                   princstr);
        retval = kadm5_init_with_skey(context, princstr, keytab_name, svcname,
                                      &params, KADM5_STRUCT_VERSION,
                                      KADM5_API_VERSION_4, db_args, &handle);
    } else {
        printf(_("Authenticating as principal %s with password.\n"),
               princstr);
        retval = kadm5_init_with_password(context, princstr, password, svcname,
                                          &params, KADM5_STRUCT_VERSION,
                                          KADM5_API_VERSION_4, db_args,
                                          &handle);
    }
    if (retval) {
        com_err(whoami, retval, _("while initializing %s interface"), whoami);
        if (retval == KADM5_BAD_CLIENT_PARAMS ||
            retval == KADM5_BAD_SERVER_PARAMS)
            usage();
        exit(1);
    }
    if (freeprinc)
        free(princstr);

    free(db_name);
    free(db_args);

    retval = krb5_cc_close(context, cc);
    if (retval) {
        com_err(whoami, retval, _("while closing ccache %s"), ccache_name);
        exit(1);
    }

    retval = kadm5_init_iprop(handle, 0);
    if (retval) {
        com_err(whoami, retval, _("while mapping update log"));
        exit(1);
    }

    return query;
}

int
quit()
{
    kadm5_ret_t retval;

    if (locked) {
        retval = kadm5_unlock(handle);
        if (retval) {
            com_err("quit", retval, _("while unlocking locked database"));
            return 1;
        }
        locked = 0;
    }

    kadm5_destroy(handle);
    if (ccache_name != NULL) {
        fprintf(stderr, "\n\a\a\a%s",
                _("Administration credentials NOT DESTROYED.\n"));
    }

    /* insert more random cleanup here */
    krb5_klog_close(context);
    krb5_free_context(context);
    return 0;
}

void
kadmin_lock(int argc, char *argv[])
{
    kadm5_ret_t retval;

    if (locked)
        return;
    retval = kadm5_lock(handle);
    if (retval) {
        com_err("lock", retval, "");
        return;
    }
    locked = 1;
}

void
kadmin_unlock(int argc, char *argv[])
{
    kadm5_ret_t retval;

    if (!locked)
        return;
    retval = kadm5_unlock(handle);
    if (retval) {
        com_err("unlock", retval, "");
        return;
    }
    locked = 0;
}

void
kadmin_delprinc(int argc, char *argv[])
{
    kadm5_ret_t retval;
    krb5_principal princ = NULL;
    char *canon = NULL;
    char reply[5];

    if (! (argc == 2 ||
           (argc == 3 && !strcmp("-force", argv[1])))) {
        fprintf(stderr, _("usage: delete_principal [-force] principal\n"));
        return;
    }
    retval = kadmin_parse_name(argv[argc - 1], &princ);
    if (retval) {
        com_err("delete_principal", retval, _("while parsing principal name"));
        return;
    }
    retval = krb5_unparse_name(context, princ, &canon);
    if (retval) {
        com_err("delete_principal", retval,
                _("while canonicalizing principal"));
        goto cleanup;
    }
    if (argc == 2) {
        printf(_("Are you sure you want to delete the principal \"%s\"? "
                 "(yes/no): "), canon);
        fgets(reply, sizeof (reply), stdin);
        if (strcmp("yes\n", reply)) {
            fprintf(stderr, _("Principal \"%s\" not deleted\n"), canon);
            goto cleanup;
        }
    }
    retval = kadm5_delete_principal(handle, princ);
    if (retval) {
        com_err("delete_principal", retval,
                _("while deleting principal \"%s\""), canon);
        goto cleanup;
    }
    printf(_("Principal \"%s\" deleted.\n"), canon);
    printf(_("Make sure that you have removed this principal from all ACLs "
             "before reusing.\n"));

cleanup:
    krb5_free_principal(context, princ);
    free(canon);
}

void
kadmin_renameprinc(int argc, char *argv[])
{
    kadm5_ret_t retval;
    krb5_principal oprinc = NULL, nprinc = NULL;
    char *ocanon = NULL, *ncanon = NULL;
    char reply[5];

    if (!(argc == 3 || (argc == 4 && !strcmp("-force", argv[1])))) {
        fprintf(stderr, _("usage: rename_principal [-force] old_principal "
                          "new_principal\n"));
        return;
    }
    retval = kadmin_parse_name(argv[argc - 2], &oprinc);
    if (retval) {
        com_err("rename_principal", retval,
                _("while parsing old principal name"));
        goto cleanup;
    }
    retval = kadmin_parse_name(argv[argc - 1], &nprinc);
    if (retval) {
        com_err("rename_principal", retval,
                _("while parsing new principal name"));
        goto cleanup;
    }
    retval = krb5_unparse_name(context, oprinc, &ocanon);
    if (retval) {
        com_err("rename_principal", retval,
                _("while canonicalizing old principal"));
        goto cleanup;
    }
    retval = krb5_unparse_name(context, nprinc, &ncanon);
    if (retval) {
        com_err("rename_principal", retval,
                _("while canonicalizing new principal"));
        goto cleanup;
    }
    if (argc == 3) {
        printf(_("Are you sure you want to rename the principal \"%s\" "
                 "to \"%s\"? (yes/no): "), ocanon, ncanon);
        fgets(reply, sizeof(reply), stdin);
        if (strcmp("yes\n", reply)) {
            fprintf(stderr, _("Principal \"%s\" not renamed\n"), ocanon);
            goto cleanup;
        }
    }
    retval = kadm5_rename_principal(handle, oprinc, nprinc);
    if (retval) {
        com_err("rename_principal", retval,
                _("while renaming principal \"%s\" to \"%s\""),
                ocanon, ncanon);
        goto cleanup;
    }
    printf(_("Principal \"%s\" renamed to \"%s\".\n"), ocanon, ncanon);
    printf(_("Make sure that you have removed the old principal from all ACLs "
             "before reusing.\n"));

cleanup:
    krb5_free_principal(context, nprinc);
    krb5_free_principal(context, oprinc);
    free(ncanon);
    free(ocanon);
}

static void
cpw_usage(const char *str)
{
    if (str)
        fprintf(stderr, "%s\n", str);
    fprintf(stderr, _("usage: change_password [-randkey] [-keepold] "
                      "[-e keysaltlist] [-pw password] principal\n"));
}

void
kadmin_cpw(int argc, char *argv[])
{
    kadm5_ret_t retval;
    static char newpw[1024];
    static char prompt1[1024], prompt2[1024];
    char *canon = NULL, *pwarg = NULL;
    int n_ks_tuple = 0, randkey = 0;
    krb5_boolean keepold = FALSE;
    krb5_key_salt_tuple *ks_tuple = NULL;
    krb5_principal princ = NULL;
    char **db_args = NULL;
    int db_args_size = 0;

    if (argc < 2) {
        cpw_usage(NULL);
        return;
    }
    for (argv++, argc--; argc > 1; argc--, argv++) {
        if (!strcmp("-x", *argv)) {
            argc--;
            if (argc < 1) {
                cpw_usage(_("change_password: missing db argument"));
                goto cleanup;
            }
            db_args_size++;
            db_args = realloc(db_args, sizeof(char*) * (db_args_size + 1));
            if (db_args == NULL) {
                fprintf(stderr, _("change_password: Not enough memory\n"));
                exit(1);
            }
            db_args[db_args_size - 1] = *++argv;
            db_args[db_args_size] = NULL;
        } else if (!strcmp("-pw", *argv)) {
            argc--;
            if (argc < 1) {
                cpw_usage(_("change_password: missing password arg"));
                goto cleanup;
            }
            pwarg = *++argv;
        } else if (!strcmp("-randkey", *argv)) {
            randkey++;
        } else if (!strcmp("-keepold", *argv)) {
            keepold = TRUE;
        } else if (!strcmp("-e", *argv)) {
            argc--;
            if (argc < 1) {
                cpw_usage(_("change_password: missing keysaltlist arg"));
                goto cleanup;
            }
            retval = krb5_string_to_keysalts(*++argv, ", \t", ":.-", 0,
                                             &ks_tuple, &n_ks_tuple);
            if (retval) {
                com_err("change_password", retval,
                        _("while parsing keysalts %s"), *argv);
                goto cleanup;
            }
        } else {
            cpw_usage(NULL);
            goto cleanup;
        }
    }
    if (*argv == NULL) {
        com_err("change_password", 0, _("missing principal name"));
        cpw_usage(NULL);
        goto cleanup;
    }
    retval = kadmin_parse_name(*argv, &princ);
    if (retval) {
        com_err("change_password", retval, _("while parsing principal name"));
        goto cleanup;
    }
    retval = krb5_unparse_name(context, princ, &canon);
    if (retval) {
        com_err("change_password", retval,
                _("while canonicalizing principal"));
        goto cleanup;
    }
    if (pwarg != NULL) {
        if (keepold || ks_tuple != NULL) {
            retval = kadm5_chpass_principal_3(handle, princ, keepold,
                                              n_ks_tuple, ks_tuple, pwarg);
        } else {
            retval = kadm5_chpass_principal(handle, princ, pwarg);
        }
        if (retval) {
            com_err("change_password", retval,
                    _("while changing password for \"%s\"."), canon);
            goto cleanup;
        }
        printf(_("Password for \"%s\" changed.\n"), canon);
    } else if (randkey) {
        retval = randkey_princ(princ, keepold, n_ks_tuple, ks_tuple);
        if (retval) {
            com_err("change_password", retval,
                    _("while randomizing key for \"%s\"."), canon);
            goto cleanup;
        }
        printf(_("Key for \"%s\" randomized.\n"), canon);
    } else {
        unsigned int i = sizeof (newpw) - 1;

        snprintf(prompt1, sizeof(prompt1),
                 _("Enter password for principal \"%s\""), canon);
        snprintf(prompt2, sizeof(prompt2),
                 _("Re-enter password for principal \"%s\""), canon);
        retval = krb5_read_password(context, prompt1, prompt2,
                                    newpw, &i);
        if (retval) {
            com_err("change_password", retval,
                    _("while reading password for \"%s\"."), canon);
            goto cleanup;
        }
        if (keepold || ks_tuple != NULL) {
            retval = kadm5_chpass_principal_3(handle, princ, keepold,
                                              n_ks_tuple, ks_tuple,
                                              newpw);
        } else {
            retval = kadm5_chpass_principal(handle, princ, newpw);
        }
        memset(newpw, 0, sizeof (newpw));
        if (retval) {
            com_err("change_password", retval,
                    _("while changing password for \"%s\"."), canon);
            goto cleanup;
        }
        printf(_("Password for \"%s\" changed.\n"), canon);
    }
cleanup:
    free(canon);
    free(db_args);
    krb5_free_principal(context, princ);
    free(ks_tuple);
}

static void
kadmin_free_tl_data(krb5_int16 *n_tl_datap, krb5_tl_data **tl_datap)
{
    krb5_tl_data *tl_data = *tl_datap, *next;
    int n_tl_data = *n_tl_datap;
    int i;

    *n_tl_datap = 0;
    *tl_datap = NULL;

    for (i = 0; tl_data && (i < n_tl_data); i++) {
        next = tl_data->tl_data_next;
        free(tl_data->tl_data_contents);
        free(tl_data);
        tl_data = next;
    }
}

/* Construct a tl_data element and add it to the tail of *tl_datap. */
static void
add_tl_data(krb5_int16 *n_tl_datap, krb5_tl_data **tl_datap,
            krb5_int16 tl_type, krb5_ui_2 len, krb5_octet *contents)
{
    krb5_tl_data *tl_data;
    krb5_octet *copy;

    copy = malloc(len);
    tl_data = calloc(1, sizeof(*tl_data));
    if (copy == NULL || tl_data == NULL) {
        fprintf(stderr, _("Not enough memory\n"));
        exit(1);
    }
    memcpy(copy, contents, len);

    tl_data->tl_data_type = tl_type;
    tl_data->tl_data_length = len;
    tl_data->tl_data_contents = copy;
    tl_data->tl_data_next = NULL;

    for (; *tl_datap != NULL; tl_datap = &(*tl_datap)->tl_data_next);
    *tl_datap = tl_data;
    (*n_tl_datap)++;
}

static void
unlock_princ(kadm5_principal_ent_t princ, long *mask, const char *caller)
{
    krb5_error_code retval;
    krb5_timestamp now;
    krb5_octet timebuf[4];

    /* Zero out the failed auth count. */
    princ->fail_auth_count = 0;
    *mask |= KADM5_FAIL_AUTH_COUNT;

    /* Record the timestamp of this unlock operation so that slave KDCs will
     * see it, since fail_auth_count is unreplicated. */
    retval = krb5_timeofday(context, &now);
    if (retval) {
        com_err(caller, retval, _("while getting time"));
        exit(1);
    }
    store_32_le((krb5_int32)now, timebuf);
    add_tl_data(&princ->n_tl_data, &princ->tl_data,
                KRB5_TL_LAST_ADMIN_UNLOCK, 4, timebuf);
    *mask |= KADM5_TL_DATA;
}

/*
 * Parse addprinc or modprinc arguments.  Some output fields may be
 * filled in on error.
 */
static int
kadmin_parse_princ_args(int argc, char *argv[], kadm5_principal_ent_t oprinc,
                        long *mask, char **pass, krb5_boolean *randkey,
                        krb5_key_salt_tuple **ks_tuple, int *n_ks_tuple,
                        char *caller)
{
    int i, attrib_set;
    size_t j;
    time_t date;
    time_t now;
    krb5_error_code retval;

    *mask = 0;
    *pass = NULL;
    *n_ks_tuple = 0;
    *ks_tuple = NULL;
    time(&now);
    *randkey = FALSE;
    for (i = 1; i < argc - 1; i++) {
        attrib_set = 0;
        if (!strcmp("-x",argv[i])) {
            if (++i > argc - 2)
                return -1;

            add_tl_data(&oprinc->n_tl_data, &oprinc->tl_data,
                        KRB5_TL_DB_ARGS, strlen(argv[i]) + 1,
                        (krb5_octet *)argv[i]);
            *mask |= KADM5_TL_DATA;
            continue;
        }
        if (!strcmp("-expire", argv[i])) {
            if (++i > argc - 2)
                return -1;
            date = get_date(argv[i]);
            if (date == (time_t)-1) {
                fprintf(stderr, _("Invalid date specification \"%s\".\n"),
                        argv[i]);
                return -1;
            }
            oprinc->princ_expire_time = date;
            *mask |= KADM5_PRINC_EXPIRE_TIME;
            continue;
        }
        if (!strcmp("-pwexpire", argv[i])) {
            if (++i > argc - 2)
                return -1;
            date = get_date(argv[i]);
            if (date == (time_t)-1) {
                fprintf(stderr, _("Invalid date specification \"%s\".\n"),
                        argv[i]);
                return -1;
            }
            oprinc->pw_expiration = date;
            *mask |= KADM5_PW_EXPIRATION;
            continue;
        }
        if (!strcmp("-maxlife", argv[i])) {
            if (++i > argc - 2)
                return -1;
            date = get_date(argv[i]);
            if (date == (time_t)-1) {
                fprintf(stderr, _("Invalid date specification \"%s\".\n"),
                        argv[i]);
                return -1;
            }
            oprinc->max_life = date - now;
            *mask |= KADM5_MAX_LIFE;
            continue;
        }
        if (!strcmp("-maxrenewlife", argv[i])) {
            if (++i > argc - 2)
                return -1;
            date = get_date(argv[i]);
            if (date == (time_t)-1) {
                fprintf(stderr, _("Invalid date specification \"%s\".\n"),
                        argv[i]);
                return -1;
            }
            oprinc->max_renewable_life = date - now;
            *mask |= KADM5_MAX_RLIFE;
            continue;
        }
        if (!strcmp("-kvno", argv[i])) {
            if (++i > argc - 2)
                return -1;
            oprinc->kvno = atoi(argv[i]);
            *mask |= KADM5_KVNO;
            continue;
        }
        if (!strcmp("-policy", argv[i])) {
            if (++i > argc - 2)
                return -1;
            oprinc->policy = argv[i];
            *mask |= KADM5_POLICY;
            continue;
        }
        if (!strcmp("-clearpolicy", argv[i])) {
            oprinc->policy = NULL;
            *mask |= KADM5_POLICY_CLR;
            continue;
        }
        if (!strcmp("-pw", argv[i])) {
            if (++i > argc - 2)
                return -1;
            *pass = argv[i];
            continue;
        }
        if (!strcmp("-randkey", argv[i])) {
            *randkey = TRUE;
            continue;
        }
        if (!strcmp("-unlock", argv[i])) {
            unlock_princ(oprinc, mask, caller);
            continue;
        }
        if (!strcmp("-e", argv[i])) {
            if (++i > argc - 2)
                return -1;
            retval = krb5_string_to_keysalts(argv[i], ", \t", ":.-", 0,
                                             ks_tuple, n_ks_tuple);
            if (retval) {
                com_err(caller, retval, _("while parsing keysalts %s"),
                        argv[i]);
                return -1;
            }
            continue;
        }
        for (j = 0; j < sizeof(flags) / sizeof(struct pflag); j++) {
            if (strlen(argv[i]) == flags[j].flaglen + 1 &&
                !strcmp(flags[j].flagname,
                        &argv[i][1] /* strip off leading + or - */)) {
                if ((flags[j].set && argv[i][0] == '-') ||
                    (!flags[j].set && argv[i][0] == '+')) {
                    oprinc->attributes |= flags[j].theflag;
                    *mask |= KADM5_ATTRIBUTES;
                    attrib_set++;
                    break;
                } else if ((flags[j].set && argv[i][0] == '+') ||
                           (!flags[j].set && argv[i][0] == '-')) {
                    oprinc->attributes &= ~flags[j].theflag;
                    *mask |= KADM5_ATTRIBUTES;
                    attrib_set++;
                    break;
                } else {
                    return -1;
                }
            }
        }
        if (!attrib_set)
            return -1;          /* nothing was parsed */
    }
    if (i != argc - 1)
        return -1;
    retval = kadmin_parse_name(argv[i], &oprinc->principal);
    if (retval) {
        com_err(caller, retval, _("while parsing principal"));
        return -1;
    }
    return 0;
}

static void
kadmin_addprinc_usage()
{
    fprintf(stderr, _("usage: add_principal [options] principal\n"));
    fprintf(stderr, _("\toptions are:\n"));
    fprintf(stderr,
            _("\t\t[-x db_princ_args]* [-expire expdate] "
              "[-pwexpire pwexpdate] [-maxlife maxtixlife]\n"
              "\t\t[-kvno kvno] [-policy policy] [-clearpolicy] [-randkey]\n"
              "\t\t[-pw password] [-maxrenewlife maxrenewlife]\n"
              "\t\t[-e keysaltlist]\n\t\t[{+|-}attribute]\n")
    );
    fprintf(stderr, _("\tattributes are:\n"));
    fprintf(stderr,
            _("\t\tallow_postdated allow_forwardable allow_tgs_req "
              "allow_renewable\n"
              "\t\tallow_proxiable allow_dup_skey allow_tix requires_preauth\n"
              "\t\trequires_hwauth needchange allow_svr "
              "password_changing_service\n"
              "\t\tok_as_delegate ok_to_auth_as_delegate "
              "no_auth_data_required\n"
              "\nwhere,\n\t[-x db_princ_args]* - any number of database "
              "specific arguments.\n"
              "\t\t\tLook at each database documentation for supported "
              "arguments\n"));
}

static void
kadmin_modprinc_usage()
{
    fprintf(stderr, _("usage: modify_principal [options] principal\n"));
    fprintf(stderr, _("\toptions are:\n"));
    fprintf(stderr,
            _("\t\t[-x db_princ_args]* [-expire expdate] "
              "[-pwexpire pwexpdate] [-maxlife maxtixlife]\n"
              "\t\t[-kvno kvno] [-policy policy] [-clearpolicy]\n"
              "\t\t[-maxrenewlife maxrenewlife] [-unlock] "
              "[{+|-}attribute]\n"));
    fprintf(stderr, "\tattributes are:\n");
    fprintf(stderr,
            _("\t\tallow_postdated allow_forwardable allow_tgs_req "
              "allow_renewable\n"
              "\t\tallow_proxiable allow_dup_skey allow_tix "
              "requires_preauth\n"
              "\t\trequires_hwauth needchange allow_svr "
              "password_changing_service\n"
              "\t\tok_as_delegate ok_to_auth_as_delegate "
              "no_auth_data_required\n"
              "\nwhere,\n\t[-x db_princ_args]* - any number of database "
              "specific arguments.\n"
              "\t\t\tLook at each database documentation for supported "
              "arguments\n"));
}

/* Create a dummy password for old-style (pre-1.8) randkey creation. */
static void
prepare_dummy_password(char *buf, size_t sz)
{
    size_t i;

    /* Must try to pass any password policy in place, and be valid UTF-8. */
    strlcpy(buf, "6F a[", sz);
    for (i = strlen(buf); i < sz - 1; i++)
        buf[i] = 'a' + (i % 26);
    buf[sz - 1] = '\0';
}

void
kadmin_addprinc(int argc, char *argv[])
{
    kadm5_principal_ent_rec princ;
    kadm5_policy_ent_rec defpol;
    long mask;
    krb5_boolean randkey = FALSE, old_style_randkey = FALSE;
    int n_ks_tuple;
    krb5_key_salt_tuple *ks_tuple = NULL;
    char *pass, *canon = NULL;
    krb5_error_code retval;
    char newpw[1024], dummybuf[256];
    static char prompt1[1024], prompt2[1024];

    /* Zero all fields in request structure */
    memset(&princ, 0, sizeof(princ));

    princ.attributes = 0;
    if (kadmin_parse_princ_args(argc, argv, &princ, &mask, &pass, &randkey,
                                &ks_tuple, &n_ks_tuple, "add_principal")) {
        kadmin_addprinc_usage();
        goto cleanup;
    }

    retval = krb5_unparse_name(context, princ.principal, &canon);
    if (retval) {
        com_err("add_principal", retval, _("while canonicalizing principal"));
        goto cleanup;
    }

    /*
     * If -policy was not specified, and -clearpolicy was not
     * specified, and the policy "default" exists, assign it.  If
     * -clearpolicy was specified, then KADM5_POLICY_CLR should be
     * unset, since it is never valid for kadm5_create_principal.
     */
    if (!(mask & KADM5_POLICY) && !(mask & KADM5_POLICY_CLR)) {
        if (!kadm5_get_policy(handle, "default", &defpol)) {
            fprintf(stderr, _("NOTICE: no policy specified for %s; "
                              "assigning \"default\"\n"), canon);
            princ.policy = "default";
            mask |= KADM5_POLICY;
            kadm5_free_policy_ent(handle, &defpol);
        } else
            fprintf(stderr, _("WARNING: no policy specified for %s; "
                              "defaulting to no policy\n"), canon);
    }
    mask &= ~KADM5_POLICY_CLR;

    if (randkey) {
        pass = NULL;
    } else if (pass == NULL) {
        unsigned int sz = sizeof(newpw) - 1;

        snprintf(prompt1, sizeof(prompt1),
                 _("Enter password for principal \"%s\""), canon);
        snprintf(prompt2, sizeof(prompt2),
                 _("Re-enter password for principal \"%s\""), canon);
        retval = krb5_read_password(context, prompt1, prompt2, newpw, &sz);
        if (retval) {
            com_err("add_principal", retval,
                    _("while reading password for \"%s\"."), canon);
            goto cleanup;
        }
        pass = newpw;
    }
    mask |= KADM5_PRINCIPAL;
    retval = create_princ(&princ, mask, n_ks_tuple, ks_tuple, pass);
    if (retval == EINVAL && randkey) {
        /*
         * The server doesn't support randkey creation.  Create the principal
         * with a dummy password and disallow tickets.
         */
        prepare_dummy_password(dummybuf, sizeof(dummybuf));
        princ.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
        mask |= KADM5_ATTRIBUTES;
        pass = dummybuf;
        retval = create_princ(&princ, mask, n_ks_tuple, ks_tuple, pass);
        old_style_randkey = 1;
    }
    if (retval) {
        com_err("add_principal", retval, "while creating \"%s\".", canon);
        goto cleanup;
    }
    if (old_style_randkey) {
        /* Randomize the password and re-enable tickets. */
        retval = randkey_princ(princ.principal, FALSE, n_ks_tuple, ks_tuple);
        if (retval) {
            com_err("add_principal", retval,
                    _("while randomizing key for \"%s\"."), canon);
            goto cleanup;
        }
        princ.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX; /* clear notix */
        mask = KADM5_ATTRIBUTES;
        retval = kadm5_modify_principal(handle, &princ, mask);
        if (retval) {
            com_err("add_principal", retval,
                    _("while clearing DISALLOW_ALL_TIX for \"%s\"."), canon);
            goto cleanup;
        }
    }
    printf("Principal \"%s\" created.\n", canon);

cleanup:
    krb5_free_principal(context, princ.principal);
    free(ks_tuple);
    free(canon);
    kadmin_free_tl_data(&princ.n_tl_data, &princ.tl_data);
}

void
kadmin_modprinc(int argc, char *argv[])
{
    kadm5_principal_ent_rec princ, oldprinc;
    krb5_principal kprinc = NULL;
    long mask;
    krb5_error_code retval;
    char *pass, *canon = NULL;
    krb5_boolean randkey = FALSE;
    int n_ks_tuple = 0;
    krb5_key_salt_tuple *ks_tuple = NULL;

    if (argc < 2) {
        kadmin_modprinc_usage();
        return;
    }

    memset(&oldprinc, 0, sizeof(oldprinc));
    memset(&princ, 0, sizeof(princ));

    retval = kadmin_parse_name(argv[argc - 1], &kprinc);
    if (retval) {
        com_err("modify_principal", retval, _("while parsing principal"));
        return;
    }
    retval = krb5_unparse_name(context, kprinc, &canon);
    if (retval) {
        com_err("modify_principal", retval,
                _("while canonicalizing principal"));
        goto cleanup;
    }
    retval = kadm5_get_principal(handle, kprinc, &oldprinc,
                                 KADM5_PRINCIPAL_NORMAL_MASK);
    if (retval) {
        com_err("modify_principal", retval, _("while getting \"%s\"."), canon);
        goto cleanup;
    }
    princ.attributes = oldprinc.attributes;
    kadm5_free_principal_ent(handle, &oldprinc);
    retval = kadmin_parse_princ_args(argc, argv,
                                     &princ, &mask,
                                     &pass, &randkey,
                                     &ks_tuple, &n_ks_tuple,
                                     "modify_principal");
    if (retval || ks_tuple != NULL || randkey || pass) {
        kadmin_modprinc_usage();
        goto cleanup;
    }
    if (mask) {
        /* Skip this if all we're doing is setting certhash. */
        retval = kadm5_modify_principal(handle, &princ, mask);
    }
    if (retval) {
        com_err("modify_principal", retval, _("while modifying \"%s\"."),
                canon);
        goto cleanup;
    }
    printf(_("Principal \"%s\" modified.\n"), canon);
cleanup:
    krb5_free_principal(context, kprinc);
    krb5_free_principal(context, princ.principal);
    kadmin_free_tl_data(&princ.n_tl_data, &princ.tl_data);
    free(canon);
    free(ks_tuple);
}

void
kadmin_getprinc(int argc, char *argv[])
{
    kadm5_principal_ent_rec dprinc;
    krb5_principal princ = NULL;
    krb5_error_code retval;
    char *canon = NULL, *princstr = NULL, *modprincstr = NULL;
    int i;
    size_t j;

    if (!(argc == 2 || (argc == 3 && !strcmp("-terse", argv[1])))) {
        fprintf(stderr, _("usage: get_principal [-terse] principal\n"));
        return;
    }

    memset(&dprinc, 0, sizeof(dprinc));

    retval = kadmin_parse_name(argv[argc - 1], &princ);
    if (retval) {
        com_err("get_principal", retval, _("while parsing principal"));
        return;
    }
    retval = krb5_unparse_name(context, princ, &canon);
    if (retval) {
        com_err("get_principal", retval, _("while canonicalizing principal"));
        goto cleanup;
    }
    retval = kadm5_get_principal(handle, princ, &dprinc,
                                 KADM5_PRINCIPAL_NORMAL_MASK | KADM5_KEY_DATA);
    if (retval) {
        com_err("get_principal", retval, _("while retrieving \"%s\"."), canon);
        goto cleanup;
    }
    retval = krb5_unparse_name(context, dprinc.principal, &princstr);
    if (retval) {
        com_err("get_principal", retval, _("while unparsing principal"));
        goto cleanup;
    }
    retval = krb5_unparse_name(context, dprinc.mod_name, &modprincstr);
    if (retval) {
        com_err("get_principal", retval, _("while unparsing principal"));
        goto cleanup;
    }
    if (argc == 2) {
        printf(_("Principal: %s\n"), princstr);
        printf(_("Expiration date: %s\n"), dprinc.princ_expire_time ?
               strdate(dprinc.princ_expire_time) : _("[never]"));
        printf(_("Last password change: %s\n"), dprinc.last_pwd_change ?
               strdate(dprinc.last_pwd_change) : _("[never]"));
        printf(_("Password expiration date: %s\n"),
               dprinc.pw_expiration ?
               strdate(dprinc.pw_expiration) : _("[none]"));
        printf(_("Maximum ticket life: %s\n"), strdur(dprinc.max_life));
        printf(_("Maximum renewable life: %s\n"),
               strdur(dprinc.max_renewable_life));
        printf(_("Last modified: %s (%s)\n"), strdate(dprinc.mod_date),
               modprincstr);
        printf(_("Last successful authentication: %s\n"),
               dprinc.last_success ? strdate(dprinc.last_success) :
               _("[never]"));
        printf("Last failed authentication: %s\n",
               dprinc.last_failed ? strdate(dprinc.last_failed) :
               "[never]");
        printf(_("Failed password attempts: %d\n"),
               dprinc.fail_auth_count);
        printf(_("Number of keys: %d\n"), dprinc.n_key_data);
        for (i = 0; i < dprinc.n_key_data; i++) {
            krb5_key_data *key_data = &dprinc.key_data[i];
            char enctype[BUFSIZ], salttype[BUFSIZ];

            if (krb5_enctype_to_name(key_data->key_data_type[0], FALSE,
                                     enctype, sizeof(enctype)))
                snprintf(enctype, sizeof(enctype), _("<Encryption type 0x%x>"),
                         key_data->key_data_type[0]);
            printf("Key: vno %d, %s, ", key_data->key_data_kvno, enctype);
            if (key_data->key_data_ver > 1) {
                if (krb5_salttype_to_string(key_data->key_data_type[1],
                                            salttype, sizeof(salttype)))
                    snprintf(salttype, sizeof(salttype), _("<Salt type 0x%x>"),
                             key_data->key_data_type[1]);
                printf("%s\n", salttype);
            } else
                printf(_("no salt\n"));
        }
        printf(_("MKey: vno %d\n"), dprinc.mkvno);

        printf(_("Attributes:"));
        for (j = 0; j < sizeof(prflags) / sizeof(char *); j++) {
            if (dprinc.attributes & (krb5_flags) 1 << j)
                printf(" %s", prflags[j]);
        }
        printf("\n");
        printf(_("Policy: %s\n"), dprinc.policy ? dprinc.policy : _("[none]"));
    } else {
        printf("\"%s\"\t%d\t%d\t%d\t%d\t\"%s\"\t%d\t%d\t%d\t%d\t\"%s\""
               "\t%d\t%d\t%d\t%d\t%d",
               princstr, dprinc.princ_expire_time, dprinc.last_pwd_change,
               dprinc.pw_expiration, dprinc.max_life, modprincstr,
               dprinc.mod_date, dprinc.attributes, dprinc.kvno,
               dprinc.mkvno, dprinc.policy ? dprinc.policy : "[none]",
               dprinc.max_renewable_life, dprinc.last_success,
               dprinc.last_failed, dprinc.fail_auth_count,
               dprinc.n_key_data);
        for (i = 0; i < dprinc.n_key_data; i++)
            printf("\t%d\t%d\t%d\t%d",
                   dprinc.key_data[i].key_data_ver,
                   dprinc.key_data[i].key_data_kvno,
                   dprinc.key_data[i].key_data_type[0],
                   dprinc.key_data[i].key_data_type[1]);
        printf("\n");
    }
cleanup:
    krb5_free_principal(context, princ);
    kadm5_free_principal_ent(handle, &dprinc);
    free(canon);
    free(princstr);
    free(modprincstr);
}

void
kadmin_getprincs(int argc, char *argv[])
{
    krb5_error_code retval;
    char *expr, **names;
    int i, count;

    expr = NULL;
    if (!(argc == 1 || (argc == 2 && (expr = argv[1])))) {
        fprintf(stderr, _("usage: get_principals [expression]\n"));
        return;
    }
    retval = kadm5_get_principals(handle, expr, &names, &count);
    if (retval) {
        com_err("get_principals", retval, _("while retrieving list."));
        return;
    }
    for (i = 0; i < count; i++)
        printf("%s\n", names[i]);
    kadm5_free_name_list(handle, names, count);
}

static int
kadmin_parse_policy_args(int argc, char *argv[], kadm5_policy_ent_t policy,
                         long *mask, char *caller)
{
    krb5_error_code retval;
    int i;
    time_t now, date;

    time(&now);
    *mask = 0;
    for (i = 1; i < argc - 1; i++) {
        if (!strcmp(argv[i], "-maxlife")) {
            if (++i > argc -2)
                return -1;
            date = get_date(argv[i]);
            if (date == (time_t)-1) {
                fprintf(stderr, _("Invalid date specification \"%s\".\n"),
                        argv[i]);
                return -1;
            }
            policy->pw_max_life = date - now;
            *mask |= KADM5_PW_MAX_LIFE;
            continue;
        } else if (!strcmp(argv[i], "-minlife")) {
            if (++i > argc - 2)
                return -1;
            date = get_date(argv[i]);
            if (date == (time_t)-1) {
                fprintf(stderr, _("Invalid date specification \"%s\".\n"),
                        argv[i]);
                return -1;
            }
            policy->pw_min_life = date - now;
            *mask |= KADM5_PW_MIN_LIFE;
            continue;
        } else if (!strcmp(argv[i], "-minlength")) {
            if (++i > argc - 2)
                return -1;
            policy->pw_min_length = atoi(argv[i]);
            *mask |= KADM5_PW_MIN_LENGTH;
            continue;
        } else if (!strcmp(argv[i], "-minclasses")) {
            if (++i > argc - 2)
                return -1;
            policy->pw_min_classes = atoi(argv[i]);
            *mask |= KADM5_PW_MIN_CLASSES;
            continue;
        } else if (!strcmp(argv[i], "-history")) {
            if (++i > argc - 2)
                return -1;
            policy->pw_history_num = atoi(argv[i]);
            *mask |= KADM5_PW_HISTORY_NUM;
            continue;
        } else if (strlen(argv[i]) == 11 &&
                   !strcmp(argv[i], "-maxfailure")) {
            if (++i > argc - 2)
                return -1;
            policy->pw_max_fail = atoi(argv[i]);
            *mask |= KADM5_PW_MAX_FAILURE;
            continue;
        } else if (strlen(argv[i]) == 21 &&
                   !strcmp(argv[i], "-failurecountinterval")) {
            if (++i > argc - 2)
                return -1;
            /* Allow bare numbers for compatibility with 1.8-1.9. */
            date = get_date(argv[i]);
            if (date != (time_t)-1)
                policy->pw_failcnt_interval = date - now;
            else if (isdigit(*argv[i]))
                policy->pw_failcnt_interval = atoi(argv[i]);
            else {
                fprintf(stderr, _("Invalid date specification \"%s\".\n"),
                        argv[i]);
                return -1;
            }
            *mask |= KADM5_PW_FAILURE_COUNT_INTERVAL;
            continue;
        } else if (strlen(argv[i]) == 16 &&
                   !strcmp(argv[i], "-lockoutduration")) {
            if (++i > argc - 2)
                return -1;
            /* Allow bare numbers for compatibility with 1.8-1.9. */
            date = get_date(argv[i]);
            if (date != (time_t)-1)
                policy->pw_lockout_duration = date - now;
            else if (isdigit(*argv[i]))
                policy->pw_lockout_duration = atoi(argv[i]);
            else {
                fprintf(stderr, _("Invalid date specification \"%s\".\n"),
                        argv[i]);
                return -1;
            }
            *mask |= KADM5_PW_LOCKOUT_DURATION;
            continue;
        } else if (!strcmp(argv[i], "-allowedkeysalts")) {
            krb5_key_salt_tuple *ks_tuple = NULL;
            int n_ks_tuple = 0;

            if (++i > argc - 2)
                return -1;
            retval = krb5_string_to_keysalts(argv[i], ", \t", ":.-", 0,
                                             &ks_tuple, &n_ks_tuple);
            if (retval) {
                com_err(caller, retval, _("while parsing keysalts %s"),
                        argv[i]);
                return -1;
            }
            free(ks_tuple);
            policy->allowed_keysalts = argv[i];
            *mask |= KADM5_POLICY_ALLOWED_KEYSALTS;
            continue;
        } else
            return -1;
    }
    if (i != argc -1) {
        fprintf(stderr, _("%s: parser lost count!\n"), caller);
        return -1;
    } else
        return 0;
}

static void
kadmin_addmodpol_usage(char *func)
{
    fprintf(stderr, _("usage; %s [options] policy\n"), func);
    fprintf(stderr, _("\toptions are:\n"));
    fprintf(stderr,
            _("\t\t[-maxlife time] [-minlife time] [-minlength length]\n"
              "\t\t[-minclasses number] [-history number]\n"
              "\t\t[-maxfailure number] [-failurecountinterval time]\n"
              "\t\t[-allowedkeysalts keysalts]\n"));
    fprintf(stderr, _("\t\t[-lockoutduration time]\n"));
}

void
kadmin_addpol(int argc, char *argv[])
{
    krb5_error_code retval;
    long mask;
    kadm5_policy_ent_rec policy;

    memset(&policy, 0, sizeof(policy));
    if (kadmin_parse_policy_args(argc, argv, &policy, &mask, "add_policy")) {
        kadmin_addmodpol_usage("add_policy");
        return;
    }
    policy.policy = argv[argc - 1];
    mask |= KADM5_POLICY;
    retval = kadm5_create_policy(handle, &policy, mask);
    if (retval) {
        com_err("add_policy", retval, _("while creating policy \"%s\"."),
                policy.policy);
    }
}

void
kadmin_modpol(int argc, char *argv[])
{
    krb5_error_code retval;
    long mask;
    kadm5_policy_ent_rec policy;

    memset(&policy, 0, sizeof(policy));
    if (kadmin_parse_policy_args(argc, argv, &policy, &mask,
                                 "modify_policy")) {
        kadmin_addmodpol_usage("modify_policy");
        return;
    }
    policy.policy = argv[argc - 1];
    retval = kadm5_modify_policy(handle, &policy, mask);
    if (retval) {
        com_err("modify_policy", retval, _("while modifying policy \"%s\"."),
                policy.policy);
    }
}

void
kadmin_delpol(int argc, char *argv[])
{
    krb5_error_code retval;
    char reply[5];

    if (!(argc == 2 || (argc == 3 && !strcmp("-force", argv[1])))) {
        fprintf(stderr, _("usage: delete_policy [-force] policy\n"));
        return;
    }
    if (argc == 2) {
        printf(_("Are you sure you want to delete the policy \"%s\"? "
                 "(yes/no): "), argv[1]);
        fgets(reply, sizeof(reply), stdin);
        if (strcmp("yes\n", reply)) {
            fprintf(stderr, _("Policy \"%s\" not deleted.\n"), argv[1]);
            return;
        }
    }
    retval = kadm5_delete_policy(handle, argv[argc - 1]);
    if (retval) {
        com_err("delete_policy:", retval, _("while deleting policy \"%s\""),
                argv[argc - 1]);
    }
}

void
kadmin_getpol(int argc, char *argv[])
{
    krb5_error_code retval;
    kadm5_policy_ent_rec policy;

    if (!(argc == 2 || (argc == 3 && !strcmp("-terse", argv[1])))) {
        fprintf(stderr, _("usage: get_policy [-terse] policy\n"));
        return;
    }
    retval = kadm5_get_policy(handle, argv[argc - 1], &policy);
    if (retval) {
        com_err("get_policy", retval, _("while retrieving policy \"%s\"."),
                argv[argc - 1]);
        return;
    }
    if (argc == 2) {
        printf(_("Policy: %s\n"), policy.policy);
        printf(_("Maximum password life: %ld\n"), policy.pw_max_life);
        printf(_("Minimum password life: %ld\n"), policy.pw_min_life);
        printf(_("Minimum password length: %ld\n"), policy.pw_min_length);
        printf(_("Minimum number of password character classes: %ld\n"),
               policy.pw_min_classes);
        printf(_("Number of old keys kept: %ld\n"), policy.pw_history_num);
        printf(_("Reference count: %ld\n"), policy.policy_refcnt);
        printf(_("Maximum password failures before lockout: %lu\n"),
               (unsigned long)policy.pw_max_fail);
        printf(_("Password failure count reset interval: %s\n"),
               strdur(policy.pw_failcnt_interval));
        printf(_("Password lockout duration: %s\n"),
               strdur(policy.pw_lockout_duration));
    } else {
        printf("\"%s\"\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%lu\t%ld\t%ld\n",
               policy.policy, policy.pw_max_life, policy.pw_min_life,
               policy.pw_min_length, policy.pw_min_classes,
               policy.pw_history_num, policy.policy_refcnt,
               (unsigned long)policy.pw_max_fail,
               (long)policy.pw_failcnt_interval,
               (long)policy.pw_lockout_duration);
    }
    kadm5_free_policy_ent(handle, &policy);
}

void
kadmin_getpols(int argc, char *argv[])
{
    krb5_error_code retval;
    char *expr, **names;
    int i, count;

    expr = NULL;
    if (!(argc == 1 || (argc == 2 && (expr = argv[1])))) {
        fprintf(stderr, _("usage: get_policies [expression]\n"));
        return;
    }
    retval = kadm5_get_policies(handle, expr, &names, &count);
    if (retval) {
        com_err("get_policies", retval, _("while retrieving list."));
        return;
    }
    for (i = 0; i < count; i++)
        printf("%s\n", names[i]);
    kadm5_free_name_list(handle, names, count);
}

void
kadmin_getprivs(int argc, char *argv[])
{
    static char *privs[] = {"INQUIRE", "ADD", "MODIFY", "DELETE"};
    krb5_error_code retval;
    size_t i;
    long plist;

    if (argc != 1) {
        fprintf(stderr, _("usage: get_privs\n"));
        return;
    }
    retval = kadm5_get_privs(handle, &plist);
    if (retval) {
        com_err("get_privs", retval, _("while retrieving privileges"));
        return;
    }
    printf(_("current privileges:"));
    for (i = 0; i < sizeof (privs) / sizeof (char *); i++) {
        if (plist & 1 << i)
            printf(" %s", privs[i]);
    }
    printf("\n");
}

void
kadmin_purgekeys(int argc, char *argv[])
{
    kadm5_ret_t retval;
    int keepkvno = -1;
    char *pname = NULL, *canon = NULL;
    krb5_principal princ;

    if (argc == 4 && strcmp(argv[1], "-keepkvno") == 0) {
        keepkvno = atoi(argv[2]);
        pname = argv[3];
    }
    if (argc == 2) {
        pname = argv[1];
    }
    if (pname == NULL) {
        fprintf(stderr, _("usage: purgekeys [-keepkvno oldest_kvno_to_keep] "
                          "principal\n"));
        return;
    }

    retval = kadmin_parse_name(pname, &princ);
    if (retval) {
        com_err("purgekeys", retval, _("while parsing principal"));
        return;
    }

    retval = krb5_unparse_name(context, princ, &canon);
    if (retval) {
        com_err("purgekeys", retval, _("while canonicalizing principal"));
        goto cleanup;
    }

    retval = kadm5_purgekeys(handle, princ, keepkvno);
    if (retval) {
        com_err("purgekeys", retval,
                _("while purging keys for principal \"%s\""), canon);
        goto cleanup;
    }

    printf(_("Old keys for principal \"%s\" purged.\n"), canon);
cleanup:
    krb5_free_principal(context, princ);
    free(canon);
    return;
}

void
kadmin_getstrings(int argc, char *argv[])
{
    kadm5_ret_t retval;
    char *pname, *canon = NULL;
    krb5_principal princ = NULL;
    krb5_string_attr *strings = NULL;
    int count, i;

    if (argc != 2) {
        fprintf(stderr, _("usage: get_strings principal\n"));
        return;
    }
    pname = argv[1];

    retval = kadmin_parse_name(pname, &princ);
    if (retval) {
        com_err("get_strings", retval, _("while parsing principal"));
        return;
    }

    retval = krb5_unparse_name(context, princ, &canon);
    if (retval) {
        com_err("get_strings", retval, _("while canonicalizing principal"));
        goto cleanup;
    }

    retval = kadm5_get_strings(handle, princ, &strings, &count);
    if (retval) {
        com_err("get_strings", retval,
                _("while getting attributes for principal \"%s\""), canon);
        goto cleanup;
    }

    if (count == 0)
        printf(_("(No string attributes.)\n"));
    for (i = 0; i < count; i++)
        printf("%s: %s\n", strings[i].key, strings[i].value);
    kadm5_free_strings(handle, strings, count);

cleanup:
    krb5_free_principal(context, princ);
    free(canon);
    return;
}

void
kadmin_setstring(int argc, char *argv[])
{
    kadm5_ret_t retval;
    char *pname, *canon = NULL, *key, *value;
    krb5_principal princ = NULL;

    if (argc != 4) {
        fprintf(stderr, _("usage: set_string principal key value\n"));
        return;
    }
    pname = argv[1];
    key = argv[2];
    value = argv[3];

    retval = kadmin_parse_name(pname, &princ);
    if (retval) {
        com_err("set_string", retval, _("while parsing principal"));
        return;
    }

    retval = krb5_unparse_name(context, princ, &canon);
    if (retval) {
        com_err("set_string", retval, _("while canonicalizing principal"));
        goto cleanup;
    }

    retval = kadm5_set_string(handle, princ, key, value);
    if (retval) {
        com_err("set_string", retval,
                _("while setting attribute on principal \"%s\""), canon);
        goto cleanup;
    }

    printf(_("Attribute set for principal \"%s\".\n"), canon);
cleanup:
    krb5_free_principal(context, princ);
    free(canon);
    return;
}

void
kadmin_delstring(int argc, char *argv[])
{
    kadm5_ret_t retval;
    char *pname, *canon = NULL, *key;
    krb5_principal princ = NULL;

    if (argc != 3) {
        fprintf(stderr, _("usage: del_string principal key\n"));
        return;
    }
    pname = argv[1];
    key = argv[2];

    retval = kadmin_parse_name(pname, &princ);
    if (retval) {
        com_err("delstring", retval, _("while parsing principal"));
        return;
    }

    retval = krb5_unparse_name(context, princ, &canon);
    if (retval) {
        com_err("del_string", retval, _("while canonicalizing principal"));
        goto cleanup;
    }

    retval = kadm5_set_string(handle, princ, key, NULL);
    if (retval) {
        com_err("del_string", retval,
                _("while deleting attribute from principal \"%s\""), canon);
        goto cleanup;
    }

    printf(_("Attribute removed from principal \"%s\".\n"), canon);
cleanup:
    krb5_free_principal(context, princ);
    free(canon);
    return;
}
