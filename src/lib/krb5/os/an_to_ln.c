/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/os/an_to_ln.c */
/*
 * Copyright 1990,1991,2007,2008 by the Massachusetts Institute of Technology.
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
 * We're only to AN_TO_LN rules at this point, and not doing the
 * database lookup  (moved from configure script)
 */
#define AN_TO_LN_RULES

#include "k5-int.h"
#include "kdb.h"
#include "kdb5int.h"
#include <ctype.h>
#if     HAVE_REGEX_H
#include <regex.h>
#endif  /* HAVE_REGEX_H */
#include <string.h>
/*
 * Use compile(3) if no regcomp present.
 */
#if     !defined(HAVE_REGCOMP) && defined(HAVE_REGEXPR_H) && defined(HAVE_COMPILE)
#define RE_BUF_SIZE     1024
#include <regexpr.h>
#endif  /* !HAVE_REGCOMP && HAVE_REGEXP_H && HAVE_COMPILE */

#define MAX_FORMAT_BUFFER       ((size_t)1024)
#ifndef min
#define min(a,b)        ((a>b) ? b : a)
#endif  /* min */

/*
 * Find the portion of the flattened principal name that we use for mapping.
 */
static char *
aname_full_to_mapping_name(char *fprincname)
{
    char        *atp;
    size_t      mlen;
    char        *mname;

    mname = (char *) NULL;
    if (fprincname) {
        atp = strrchr(fprincname, '@');
        if (!atp)
            atp = &fprincname[strlen(fprincname)];
        mlen = (size_t) (atp - fprincname);

        if ((mname = (char *) malloc(mlen+1))) {
            strncpy(mname, fprincname, mlen);
            mname[mlen] = '\0';
        }
    }
    return(mname);
}

#ifdef ANAME_CDB

#include <cdb.h>

static krb5_error_code
cdb_an_to_ln(krb5_context context, char *dbname, krb5_const_principal aname,
	     const unsigned int lnsize, char *lname)
{
#if !defined(_WIN32)
    struct cdb cdb;
    char *key;
    char *val;
    unsigned int keylen;
    unsigned int vallen;
    krb5_error_code retval;
    int fd;
    int ret;
    char *princ_name;
    char foldpre[4];
    char *foldkey;
    size_t princ_length;
    size_t i;
    const krb5_data *crealm;

    if (lnsize == 0)
	return KRB5_LNAME_NOTRANS;
    lname[0] = '\0';
    if ((retval = krb5_unparse_name(context, aname, &princ_name)))
        return(retval);
    princ_length = strlen(princ_name);

    crealm = krb5_princ_realm(kdc_context, aname);

    fd = open(dbname, O_RDONLY);
    if (fd == -1) {
        free(princ_name);
        return KRB5_LNAME_CANTOPEN;
    }
    ret = cdb_init(&cdb, fd);
    if (ret < 0) {
        free(princ_name);
	(void) close(fd);
        return KRB5_LNAME_CANTOPEN;
    }

    foldkey = calloc(1, strlen(foldpre) + crealm->length + 1 );
    if (foldkey == NULL) {
	krb5_xfree(princ_name);
	cdb_free(&cdb);
	(void) close(fd);
	return ENOMEM;
    }
    strncat(foldkey, foldpre, strlen(foldpre));
    strncat(foldkey, crealm->data, crealm->length);

    ret = cdb_find(&cdb, foldkey, strlen(foldkey));
    free(foldkey);
    if (ret < 0) {
	krb5_xfree(princ_name);
	cdb_free(&cdb);
	(void) close(fd);
        return KRB5_LNAME_BADFORMAT; /* XXX need a better error */
    }

    /* If found foldkey then we need to fold the case of the princ */
    for (i = (ret == 1) ? 0 : princ_length;
	 i < (princ_length - crealm->length - 1);
	 i++) {
	princ_name[i] = tolower(princ_name[i]);
    }

    ret = cdb_find(&cdb, princ_name, strlen(princ_name));
    krb5_xfree(princ_name);
    if (ret < 1) {
	cdb_free(&cdb);
	(void) close(fd);
	if (ret == 0)
	    return KRB5_LNAME_NOTRANS;
	return KRB5_LNAME_BADFORMAT; /* XXX need a better error */
    }

    /* Found an entry */
    vallen = cdb_datalen(&cdb);
    if (vallen >= lnsize) {
	cdb_free(&cdb);
	(void) close(fd);
	return KRB5_CONFIG_NOTENUFSPACE;
    }

    /* Read the entry straight into lname[] */
    ret = cdb_read(&cdb, lname, vallen, cdb_datapos(&cdb));
    lname[vallen] = '\0';
    if (ret < 0) {
	lname[0] = '\0';
	free(val);
	cdb_free(&cdb);
	(void) close(fd);
	return KRB5_LNAME_BADFORMAT; /* XXX need a better error */
    }
    return 0;

#else   /* !_WIN32 && !MACINTOSH */
    /*
     * If we don't have support for a database mechanism, then we can't
     * translate this now, can we?
     */
    return KRB5_LNAME_NOTRANS;
#endif  /* !_WIN32 && !MACINTOSH */
}
#endif /*ANAME_CDB*/

#ifdef  AN_TO_LN_RULES
/*
 * Format and transform a principal name to a local name.  This is particularly
 * useful when Kerberos principals and local user names are formatted to
 * some particular convention.
 *
 * There are three parts to each rule:
 * First part - formulate the string to perform operations on:  If not present
 * then the string defaults to the fully flattened principal minus the realm
 * name.  Otherwise the syntax is as follows:
 *      "[" <ncomps> ":" <format> "]"
 *              Where:
 *                      <ncomps> is the number of expected components for this
 *                      rule.  If the particular principal does not have this
 *                      many components, then this rule does not apply.
 *
 *                      <format> is a string of <component> or verbatim
 *                      characters to be inserted.
 *
 *                      <component> is of the form "$"<number> to select the
 *                      <number>th component.  <number> begins from 1.
 *
 * Second part - select rule validity:  If not present, then this rule may
 * apply to all selections.  Otherwise the syntax is as follows:
 *      "(" <regexp> ")"
 *              Where:  <regexp> is a selector regular expression.  If this
 *                      regular expression matches the whole pattern generated
 *                      from the first part, then this rule still applies.
 *
 * Last part - Transform rule:  If not present, then the selection string
 * is passed verbatim and is matched.  Otherwise, the syntax is as follows:
 *      <rule> ...
 *              Where:  <rule> is of the form:
 *                      "s/" <regexp> "/" <text> "/" ["g"]
 *
 * In order to be able to select rule validity, the native system must support
 * one of compile(3), re_comp(3) or regcomp(3).  In order to be able to
 * transform (e.g. substitute), the native system must support regcomp(3) or
 * compile(3).
 */

/*
 * aname_do_match()     - Does our name match the parenthesized regular
 *                        expression?
 *
 * Chew up the match portion of the regular expression and update *contextp.
 * If no re_comp() or regcomp(), then always return a match.
 */
static krb5_error_code
aname_do_match(char *string, char **contextp)
{
    krb5_error_code     kret;
    char                *regexp, *startp, *endp = 0;
    size_t              regexlen;
#if     HAVE_REGCOMP
    regex_t             match_exp;
    regmatch_t          match_match;
#elif   HAVE_REGEXPR_H
    char                regexp_buffer[RE_BUF_SIZE];
#endif  /* HAVE_REGEXP_H */

    kret = 0;
    /*
     * Is this a match expression?
     */
    if (**contextp == '(') {
        kret = KRB5_CONFIG_BADFORMAT;
        startp = (*contextp) + 1;
        endp = strchr(startp, ')');
        /* Find the end of the match expression. */
        if (endp) {
            regexlen = (size_t) (endp - startp);
            regexp = (char *) malloc((size_t) regexlen+1);
            kret = ENOMEM;
            if (regexp) {
                strncpy(regexp, startp, regexlen);
                regexp[regexlen] = '\0';
                kret = KRB5_LNAME_NOTRANS;
                /*
                 * Perform the match.
                 */
#if     HAVE_REGCOMP
                if (!regcomp(&match_exp, regexp, REG_EXTENDED) &&
                    !regexec(&match_exp, string, 1, &match_match, 0)) {
                    if ((match_match.rm_so == 0) &&
                        ((unsigned int) match_match.rm_eo == strlen(string)))
                        kret = 0;
                }
                regfree(&match_exp);
#elif   HAVE_REGEXPR_H
                compile(regexp,
                        regexp_buffer,
                        &regexp_buffer[RE_BUF_SIZE]);
                if (step(string, regexp_buffer)) {
                    if ((loc1 == string) &&
                        (loc2 == &string[strlen(string)]))
                        kret = 0;
                }
#elif   HAVE_RE_COMP
                if (!re_comp(regexp) && re_exec(string))
                    kret = 0;
#else   /* HAVE_RE_COMP */
                kret = 0;
#endif  /* HAVE_RE_COMP */
                free(regexp);
            }
            endp++;
        }
        else
            endp = startp;
    }
    *contextp = endp;
    return(kret);
}

/*
 * do_replacement()     - Replace the regular expression with the specified
 *                        replacement.
 *
 * If "doall" is set, it's a global replacement, otherwise, just a oneshot
 * deal.
 * If no regcomp() then just return the input string verbatim in the output
 * string.
 */
#define use_bytes(x)                                    \
    out_used += (x);                                    \
    if (out_used > MAX_FORMAT_BUFFER) goto mem_err

static int
do_replacement(char *regexp, char *repl, int doall, char *in, char *out)
{
    size_t out_used = 0;
#if     HAVE_REGCOMP
    regex_t     match_exp;
    regmatch_t  match_match;
    int         matched;
    char        *cp;
    char        *op;

    if (!regcomp(&match_exp, regexp, REG_EXTENDED)) {
        cp = in;
        op = out;
        matched = 0;
        do {
            if (!regexec(&match_exp, cp, 1, &match_match, 0)) {
                if (match_match.rm_so) {
                    use_bytes(match_match.rm_so);
                    strncpy(op, cp, match_match.rm_so);
                    op += match_match.rm_so;
                }
                use_bytes(strlen(repl));
                strncpy(op, repl, MAX_FORMAT_BUFFER - 1 - (op - out));
                op += strlen(op);
                cp += match_match.rm_eo;
                if (!doall) {
                    use_bytes(strlen(cp));
                    strncpy(op, cp, MAX_FORMAT_BUFFER - 1 - (op - out));
                }
                matched = 1;
            }
            else {
                use_bytes(strlen(cp));
                strncpy(op, cp, MAX_FORMAT_BUFFER - 1 - (op - out));
                matched = 0;
            }
        } while (doall && matched);
        regfree(&match_exp);
    }
#elif   HAVE_REGEXPR_H
    int         matched;
    char        *cp;
    char        *op;
    char        regexp_buffer[RE_BUF_SIZE];
    size_t      sdispl, edispl;

    compile(regexp,
            regexp_buffer,
            &regexp_buffer[RE_BUF_SIZE]);
    cp = in;
    op = out;
    matched = 0;
    do {
        if (step(cp, regexp_buffer)) {
            sdispl = (size_t) (loc1 - cp);
            edispl = (size_t) (loc2 - cp);
            if (sdispl) {
                use_bytes(sdispl);
                strncpy(op, cp, sdispl);
                op += sdispl;
            }
            use_bytes(strlen(repl));
            strncpy(op, repl, MAX_FORMAT_BUFFER - 1 - (op - out));
            op += strlen(repl);
            cp += edispl;
            if (!doall) {
                use_bytes(strlen(cp));
                strncpy(op, cp, MAX_FORMAT_BUFFER - 1 - (op - out));
            }
            matched = 1;
        }
        else {
            use_bytes(strlen(cp));
            strncpy(op, cp, MAX_FORMAT_BUFFER - 1 - (op - out));
            matched = 0;
        }
    } while (doall && matched);
#else   /* HAVE_REGEXP_H */
    memcpy(out, in, MAX_FORMAT_BUFFER);
#endif  /* HAVE_REGCOMP */
    return 1;
mem_err:
#ifdef HAVE_REGCMP
    regfree(&match_exp);
#endif
    return 0;

}
#undef use_bytes

/*
 * aname_replacer()     - Perform the specified substitutions on the input
 *                        string and return the result.
 *
 * This routine enforces the "s/<pattern>/<replacement>/[g]" syntax.
 */
static krb5_error_code
aname_replacer(char *string, char **contextp, char **result)
{
    krb5_error_code     kret;
    char                *in = NULL, *out = NULL, *rule = NULL, *repl = NULL;
    char                *cp, *ep, *tp;
    size_t              rule_size, repl_size;
    int                 doglobal;

    *result = NULL;

    /* Allocate the formatting buffers */
    in = malloc(MAX_FORMAT_BUFFER);
    if (!in)
        return ENOMEM;
    out = malloc(MAX_FORMAT_BUFFER);
    if (!out) {
        kret = ENOMEM;
        goto cleanup;
    }

    /*
     * Prime the buffers.  Copy input string to "out" to simulate it
     * being the result of an initial iteration.
     */
    strlcpy(out, string, MAX_FORMAT_BUFFER);
    in[0] = '\0';
    kret = 0;
    /*
     * Pound through the expression until we're done.
     */
    for (cp = *contextp; *cp; ) {
        /* Skip leading whitespace */
        while (isspace((int) (*cp)))
            cp++;

        /*
         * Find our separators.  First two characters must be "s/"
         * We must also find another "/" followed by another "/".
         */
        if (!((cp[0] == 's') &&
              (cp[1] == '/') &&
              (ep = strchr(&cp[2], '/')) &&
              (tp = strchr(&ep[1], '/')))) {
            /* Bad syntax */
            kret = KRB5_CONFIG_BADFORMAT;
            goto cleanup;
        }

        /* Figure out sizes of strings and allocate them */
        rule_size = (size_t) (ep - &cp[2]);
        repl_size = (size_t) (tp - &ep[1]);
        rule = malloc(rule_size + 1);
        if (!rule) {
            kret = ENOMEM;
            goto cleanup;
        }
        repl = malloc(repl_size + 1);
        if (!repl) {
            kret = ENOMEM;
            goto cleanup;
        }

        /* Copy the strings */
        memcpy(rule, &cp[2], rule_size);
        memcpy(repl, &ep[1], repl_size);
        rule[rule_size] = repl[repl_size] = '\0';

        /* Check for trailing "g" */
        doglobal = (tp[1] == 'g') ? 1 : 0;
        if (doglobal)
            tp++;

        /* Swap previous in and out buffers */
        ep = in;
        in = out;
        out = ep;

        /* Do the replacemenbt */
        memset(out, '\0', MAX_FORMAT_BUFFER);
        if (!do_replacement(rule, repl, doglobal, in, out)) {
            kret = KRB5_LNAME_NOTRANS;
            goto cleanup;
        }
        free(rule);
        free(repl);
        rule = repl = NULL;

        /* If we have no output buffer left, this can't be good */
        if (strlen(out) == 0) {
            kret = KRB5_LNAME_NOTRANS;
            goto cleanup;
        }

        /* Advance past trailer */
        cp = &tp[1];
    }
    free(in);
    *result = out;
    return 0;
cleanup:
    free(in);
    free(out);
    free(repl);
    free(rule);
    return kret;
}

/*
 * Compute selection string for RULE rules.
 *
 * Advance *contextp to the string position after the selectring
 * string part if present, and set *result to the selection string.
 */
static krb5_error_code
aname_get_selstring(krb5_context context, krb5_const_principal aname,
                    char **contextp, char **result)
{
    krb5_error_code kret;
    char *fprincname, *current, *str;
    long num_comps, compind;
    const krb5_data *datap;
    struct k5buf selstring;
    size_t nlit;

    *result = NULL;
    if (**contextp != '[') {
        /* No selstring part; use the full flattened principal name. */
        kret = krb5_unparse_name(context, aname, &fprincname);
        if (kret)
            return kret;
        str = aname_full_to_mapping_name(fprincname);
        free(fprincname);
        if (!str)
            return ENOMEM;
        *result = str;
        return 0;
    }

    /* Advance past the '[' and read the number of components. */
    current = *contextp + 1;
    errno = 0;
    num_comps = strtol(current, &current, 10);
    if (errno != 0 || num_comps < 0 || *current != ':')
        return KRB5_CONFIG_BADFORMAT;
    if (num_comps != aname->length)
        return KRB5_LNAME_NOTRANS;
    current++;

    krb5int_buf_init_dynamic(&selstring);
    while (1) {
        /* Copy in literal characters up to the next $ or ]. */
        nlit = strcspn(current, "$]");
        krb5int_buf_add_len(&selstring, current, nlit);
        current += nlit;
        if (*current != '$')
            break;

        /* Expand $ substitution to a principal component. */
        errno = 0;
        compind = strtol(current + 1, &current, 10);
        if (errno || compind > num_comps)
            break;
        datap = (compind > 0)
            ? krb5_princ_component(context, aname, compind - 1)
            : krb5_princ_realm(context, aname);
        if (!datap)
            break;
        krb5int_buf_add_len(&selstring, datap->data, datap->length);
    }

    /* Check that we hit a ']' and not the end of the string. */
    if (*current != ']') {
        krb5int_free_buf(&selstring);
        return KRB5_CONFIG_BADFORMAT;
    }

    str = krb5int_buf_data(&selstring);
    if (str == NULL)
        return ENOMEM;

    *contextp = current + 1;
    *result = str;
    return 0;
}

/* Handle aname to lname translations for RULE rules. */
static krb5_error_code
rule_an_to_ln(krb5_context context, char *rule, krb5_const_principal aname,
              const unsigned int lnsize, char *lname)
{
    krb5_error_code kret;
    char *current, *selstring = 0, *outstring = 0;

    /* Compute the selection string. */
    current = rule;
    kret = aname_get_selstring(context, aname, &current, &selstring);
    if (kret)
        return kret;

    /* Check the selection string against the regexp, if present. */
    if (*current == '(') {
        kret = aname_do_match(selstring, &current);
        if (kret)
            goto cleanup;
    }

    /* Perform the substitution. */
    outstring = NULL;
    kret = aname_replacer(selstring, &current, &outstring);
    if (kret)
        goto cleanup;

    /* Copy out the value if there's enough room. */
    if (strlcpy(lname, outstring, lnsize) >= lnsize)
        kret = KRB5_CONFIG_NOTENUFSPACE;

cleanup:
    free(selstring);
    free(outstring);
    return kret;
}
#endif  /* AN_TO_LN_RULES */

/*
 * Implementation:  This version checks the realm to see if it is the local
 * realm; if so, and there is exactly one non-realm component to the name,
 * that name is returned as the lname.
 */
static krb5_error_code
default_an_to_ln(krb5_context context, krb5_const_principal aname, const unsigned int lnsize, char *lname)
{
    krb5_error_code retval;
    char *def_realm;
    unsigned int realm_length;

    realm_length = krb5_princ_realm(context, aname)->length;

    if ((retval = krb5_get_default_realm(context, &def_realm))) {
        return(retval);
    }
    if (!data_eq_string(*krb5_princ_realm(context, aname), def_realm)) {
        free(def_realm);
        return KRB5_LNAME_NOTRANS;
    }

    if (krb5_princ_size(context, aname) != 1) {
        if (krb5_princ_size(context, aname) == 2 ) {
            /* Check to see if 2nd component is the local realm. */
            if ( strncmp(krb5_princ_component(context, aname,1)->data,def_realm,
                         realm_length) ||
                 realm_length != krb5_princ_component(context, aname,1)->length)
                return KRB5_LNAME_NOTRANS;
        }
        else
            /* no components or more than one component to non-realm part of name
               --no translation. */
            return KRB5_LNAME_NOTRANS;
    }

    free(def_realm);
    strncpy(lname, krb5_princ_component(context, aname,0)->data,
            min(krb5_princ_component(context, aname,0)->length,lnsize));
    if (lnsize <= krb5_princ_component(context, aname,0)->length ) {
        retval = KRB5_CONFIG_NOTENUFSPACE;
    } else {
        lname[krb5_princ_component(context, aname,0)->length] = '\0';
        retval = 0;
    }
    return retval;
}

#ifdef USE_DLOPEN
#include <dlfcn.h>
#endif

static krb5_error_code (*kdb_setup_handle_func)(krb5_context) = NULL;
static void *kdb_dlhandle = NULL;

MAKE_INIT_FUNCTION(aname2lname_db_init);
MAKE_FINI_FUNCTION(aname2lname_db_fini);

static
int
aname2lname_db_init(void)
{
#if USE_DLOPEN
    void *dlhandle;

#ifdef RTLD_GROUP
#define KDB_DLOPEN_FLAGS (RTLD_LOCAL | RTLD_GROUP)
#else
#ifdef RTLD_DEEPBIND
#define KDB_DLOPEN_FLAGS (RTLD_LOCAL | RTLD_DEEPBIND)
#else
#define KDB_DLOPEN_FLAGS (RTLD_LOCAL)
#endif 
#endif 

    dlhandle = dlopen("../../libkdb.so", KDB_DLOPEN_FLAGS);
    if (dlhandle == NULL)
        return 0;
    kdb_setup_handle_func = dlsym(dlhandle, "krb5_db_setup_lib_handle");
#endif
    return 0;
}

static
void
aname2lname_db_fini(void)
{
    if (kdb_dlhandle)
        (void) dlclose(kdb_dlhandle);
}


/*
  Converts an authentication name to a local name suitable for use by
  programs wishing a translation to an environment-specific name (e.g.
  user account name).

  lnsize specifies the maximum length name that is to be filled into
  lname.
  The translation will be null terminated in all non-error returns.

  returns system errors, NOT_ENOUGH_SPACE
*/

krb5_error_code KRB5_CALLCONV
krb5_aname_to_localname(krb5_context context, krb5_const_principal aname, int lnsize_in, char *lname)
{
    krb5_error_code     kret;
    char                *realm;
    char                *pname;
    char                *mname;
    const char          *hierarchy[5];
    char                **mapping_values;
    int                 i, nvalid;
    char                *cp, *s;
    char                *typep, *argp;
    unsigned int        lnsize;
    int                 an_to_ln_db_err = ENOENT;

    kret = CALL_INIT_FUNCTION(aname2lname_db_init);
    if (kdb_setup_handle_func)
        an_to_ln_db_err = kdb_setup_handle_func(context);

    if (lnsize_in < 0)
        return KRB5_CONFIG_NOTENUFSPACE;

    lnsize = lnsize_in; /* Unsigned */

    /*
     * First get the default realm.
     */
    if (!(kret = krb5_get_default_realm(context, &realm))) {
        /* Flatten the name */
        if (!(kret = krb5_unparse_name(context, aname, &pname))) {
            if ((mname = aname_full_to_mapping_name(pname))) {
                /*
                 * Search first for explicit mappings of the form:
                 *
                 * [realms]->realm->"auth_to_local_names"->mapping_name
                 */
                hierarchy[0] = KRB5_CONF_REALMS;
                hierarchy[1] = realm;
                hierarchy[2] = KRB5_CONF_AUTH_TO_LOCAL_NAMES;
                hierarchy[3] = mname;
                hierarchy[4] = (char *) NULL;
                if (!(kret = profile_get_values(context->profile,
                                                hierarchy,
                                                &mapping_values))) {
                    /* We found one or more explicit mappings. */
                    for (nvalid=0; mapping_values[nvalid]; nvalid++);

                    /* Just use the last one. */
                    /* Trim the value. */
                    s = mapping_values[nvalid-1];
                    cp = s + strlen(s);
                    while (cp > s) {
                        cp--;
                        if (!isspace((int)(*cp)))
                            break;
                        *cp = '\0';
                    }

                    /* Copy out the value if there's enough room */
                    if (strlcpy(lname, mapping_values[nvalid-1],
                                lnsize) >= lnsize)
                        kret = KRB5_CONFIG_NOTENUFSPACE;

                    /* Free residue */
                    profile_free_list(mapping_values);
                }
                else {
                    /*
                     * OK - There's no explicit mapping.  Now check for
                     * general auth_to_local rules of the form:
                     *
                     * [realms]->realm->"auth_to_local"
                     *
                     * This can have one or more of the following kinds of
                     * values:
                     *  DB:<filename>   - Look up principal in aname database.
                     *  RULE:<sed-exp>  - Formulate lname from sed-exp.
                     *  DEFAULT         - Use default rule.
                     * The first rule to find a match is used.
                     */
                    hierarchy[0] = KRB5_CONF_REALMS;
                    hierarchy[1] = realm;
                    hierarchy[2] = KRB5_CONF_AUTH_TO_LOCAL;
                    hierarchy[3] = (char *) NULL;
                    if (!(kret = profile_get_values(context->profile,
                                                    hierarchy,
                                                    &mapping_values))) {
                        /*
                         * Loop through all the mapping values.
                         */
                        for (i=0; mapping_values[i]; i++) {
                            typep = mapping_values[i];
                            argp = strchr(typep, ':');
                            if (argp) {
                                *argp = '\0';
                                argp++;
                            }
                            if (!strcmp(typep, "DB") && argp) {
                                kdb_vftabl *v;

                                v = &context->dal_handle->lib_handle->vftabl;
                                if (an_to_ln_db_err || !v) {
                                    kret = KRB5_LNAME_CANTOPEN;
                                    break;
                                }
                                kret = v->aname_to_localname(context,
                                                             argp,
                                                             aname,
                                                             lnsize,
                                                             lname);
                                if (kret != KRB5_LNAME_NOTRANS)
                                    break;
                            }
                            else
#ifdef ANAME_CDB
                            if (!strcmp(typep, "CDB") && argp) {
                                kret = cdb_an_to_ln(context,
                                                    argp,
                                                    aname,
                                                    lnsize,
                                                    lname);
                                if (kret != KRB5_LNAME_NOTRANS)
                                    break;
                            }
                            else
#endif
#ifdef  AN_TO_LN_RULES
                                if (!strcmp(typep, "RULE") && argp) {
                                    kret = rule_an_to_ln(context,
                                                         argp,
                                                         aname,
                                                         lnsize,
                                                         lname);
                                    if (kret != KRB5_LNAME_NOTRANS)
                                        break;
                                }
                                else
#endif  /* AN_TO_LN_RULES */
                                    if (!strcmp(typep, "DEFAULT") && !argp) {
                                        kret = default_an_to_ln(context,
                                                                aname,
                                                                lnsize,
                                                                lname);
                                        if (kret != KRB5_LNAME_NOTRANS)
                                            break;
                                    }
                                    else {
                                        kret = KRB5_CONFIG_BADFORMAT;
                                        break;
                                    }
                        }

                        /* We're done, clean up the droppings. */
                        profile_free_list(mapping_values);
                    }
                    else {
                        /*
                         * No profile relation found, try default mapping.
                         */
                        kret = default_an_to_ln(context,
                                                aname,
                                                lnsize,
                                                lname);
                    }
                }
                free(mname);
            }
            else
                kret = ENOMEM;
            free(pname);
        }
        free(realm);
    }
    return(kret);
}
