/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* #pragma ident        "@(#)kdb_log.c  1.3     04/02/23 SMI" */

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <k5-int.h>
#include <stdlib.h>
#include <limits.h>
#include <syslog.h>
#include "kdb5.h"
#include "kdb_log.h"
#include "kdb5int.h"

#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif

/*
 * This modules includes all the necessary functions that create and
 * modify the Kerberos principal update and header logs.
 */

#define getpagesize()   sysconf(_SC_PAGESIZE)

static int              pagesize = 0;

#define INIT_ULOG(ctx)                          \
    log_ctx = ctx->kdblog_context;              \
    assert(log_ctx != NULL);                    \
    ulog = log_ctx->ulog;                       \
    assert(ulog != NULL)

/* XXX */
typedef unsigned long ulong_t;
typedef unsigned int uint_t;

static int extend_file_to(int fd, uint_t new_size);
static void ulog_reset(kdb_hlog_t *);

krb5_error_code
ulog_lock(krb5_context ctx, int mode)
{
    kdb_log_context *log_ctx = NULL;

    if (ctx == NULL)
        return KRB5_LOG_ERROR;
    if (ctx->kdblog_context == NULL || ctx->kdblog_context->iproprole == IPROP_NULL)
        return 0;
    log_ctx = ctx->kdblog_context;
    assert(log_ctx != NULL);
    return krb5_lock_file(ctx, log_ctx->ulogfd, mode);
}

/*
 * Sync update entry to disk.
 */
static krb5_error_code
ulog_sync_update(kdb_hlog_t *ulog, kdb_ent_header_t *upd)
{
    ulong_t             start, end, size;
    krb5_error_code     retval;

    if (ulog == NULL)
        return (KRB5_LOG_ERROR);

    if (!pagesize)
        pagesize = getpagesize();

    start = ((ulong_t)upd) & (~(pagesize-1));

    end = (((ulong_t)upd) + ulog->kdb_block +
           (pagesize-1)) & (~(pagesize-1));

    size = end - start;
    if ((retval = msync((caddr_t)start, size, MS_SYNC))) {
        return (retval);
    }

    return (0);
}

/*
 * Sync memory to disk for the update log header.
 */
void
ulog_sync_header(kdb_hlog_t *ulog)
{

    if (!pagesize)
        pagesize = getpagesize();

    if (msync((caddr_t)ulog, pagesize, MS_SYNC)) {
        /*
         * Couldn't sync to disk, let's panic
         */
        syslog(LOG_ERR, _("ulog_sync_header: could not sync to disk"));
        abort();
    }
}

/*
 * Resizes the array elements.  We reinitialize the update log rather than
 * unrolling the the log and copying it over to a temporary log for obvious
 * performance reasons.  Slaves will subsequently do a full resync, but
 * the need for resizing should be very small.  Note that the requested
 * ulogentries count is an optional suggestion (from the configuration),
 * while recsize is a requirement.
 *
 * Returns 0 on success.
 * Returns EFBIG, ERANGE, or any errno that fstat(2) returns on failure.
 */
static krb5_error_code
ulog_resize(kdb_log_context *log_ctx, uint32_t ulogentries, uint_t recsize)
{
    size_t              new_block, new_size;
    struct stat         st;
    uint32_t            orig_ulogentries = ulogentries;
    krb5_boolean        do_reset = FALSE;
    kdb_hlog_t          *ulog = log_ctx->ulog;

    assert(ulog != NULL);

    if (ulogentries == 0 || ulog->kdb_num > ulogentries)
        ulogentries = (st.st_size - sizeof (*ulog)) / ulog->kdb_block;

    /*
     * We want to do some overflow checking.  There's no OFF_MAX, so we use
     * SSIZE_MAX since a) mmap() takes a size_t for the length, b) we need to
     * check against a signed max because off_t is signed, c) off_t can be
     * wider than size_t/ssize_t, but is extremely unlikely to be narrower than
     * them.
     */
    new_block = recsize / ULOG_BLOCK;
    if (recsize % ULOG_BLOCK)
        new_block++;           /* this is safe, since we divided recsize */

    if ((SSIZE_MAX / ULOG_BLOCK) < new_block)
        goto erange;
    new_block *= ULOG_BLOCK;

    if (ulogentries == 0 || ulog->kdb_num > ulogentries)
        ulogentries = (st.st_size - sizeof (*ulog)) / ulog->kdb_block;

    while (ulogentries > 2 && (SSIZE_MAX / ulogentries) < new_block)
        ulogentries /= 2;
    if (ulogentries < 2)
        goto erange;

    if (orig_ulogentries > ulogentries) {
        syslog(LOG_INFO, _("ulog_resize: using %d ulog entries instead of "
                           "requested (%d)"), ulogentries, orig_ulogentries);
        do_reset = TRUE;
    }

    if ((SSIZE_MAX / ulogentries) < new_block)
        goto erange;
    new_size = ulogentries * new_block;

    if (SSIZE_MAX - new_size < sizeof(kdb_hlog_t))
        goto erange;
    new_size += sizeof(kdb_hlog_t);

    if (fstat(log_ctx->ulogfd, &st) == -1)
        return errno;

    /*
     * Check that we're not accidentally clobbering a ulog by running a 32-bit
     * libkadm5srv app against too large a ulog on a system where 64-bit
     * libkadm5srv apps are meant to run only.
     */
    if (st.st_size > SSIZE_MAX || new_size > SSIZE_MAX) {
        syslog(LOG_ERR, _("ulog_resize: ulog is too large to mmap() in; use "
                          "a 64-bit version of this application"));
        return EFBIG;
    }

    if (new_size > (size_t)st.st_size) {
        if (extend_file_to(log_ctx->ulogfd, new_size) < 0)
            return errno;
    }

    if (do_reset)
        ulog_reset(ulog);
    ulog->kdb_block = new_block;
    ulog_sync_header(ulog);
    log_ctx->ulogentries = ulogentries;
    return (0);

erange:
    syslog(LOG_ERR, _("ulog_resize: principal record too large to iprop"));
    return ERANGE;
}

/*
 * Adds an entry to the update log.
 * The layout of the update log looks like:
 *
 * header log -> [ update header -> xdr(kdb_incr_update_t) ], ...
 */
krb5_error_code
ulog_add_update(krb5_context context, kdb_incr_update_t *upd)
{
    XDR         xdrs;
    kdbe_time_t ktime;
    struct timeval      timestamp;
    kdb_ent_header_t *indx_log;
    uint_t              i, recsize;
    ulong_t             upd_size;
    krb5_error_code     retval;
    kdb_sno_t   cur_sno;
    kdb_log_context     *log_ctx;
    kdb_hlog_t  *ulog = NULL;
    uint32_t    ulogentries;
    int         ulogfd;

    INIT_ULOG(context);
    ulogentries = log_ctx->ulogentries;
    ulogfd = log_ctx->ulogfd;

    if (upd == NULL)
        return (KRB5_LOG_ERROR);

    (void) gettimeofday(&timestamp, NULL);
    ktime.seconds = timestamp.tv_sec;
    ktime.useconds = timestamp.tv_usec;

    upd_size = xdr_sizeof((xdrproc_t)xdr_kdb_incr_update_t, upd);

    recsize = sizeof (kdb_ent_header_t) + upd_size;

    if (recsize > ulog->kdb_block) {
        /* XXX Er, we should re-map now, no?! */
        if ((retval = ulog_resize(log_ctx, ulogentries, recsize))) {
            /* Resize element array failed */
            return (retval);
        }
    }

    cur_sno = ulog->kdb_last_sno;

    /*
     * We need to overflow our sno, replicas will do full
     * resyncs once they see their sno > than the masters.
     */
    if (cur_sno == (kdb_sno_t)-1)
        cur_sno = 1;
    else
        cur_sno++;

    /*
     * We squirrel this away for finish_update() to index
     */
    upd->kdb_entry_sno = cur_sno;

    i = (cur_sno - 1) % ulogentries;

    indx_log = (kdb_ent_header_t *)INDEX(ulog, i);

    (void) memset(indx_log, 0, ulog->kdb_block);

    indx_log->kdb_umagic = KDB_ULOG_MAGIC;
    indx_log->kdb_entry_size = upd_size;
    indx_log->kdb_entry_sno = cur_sno;
    indx_log->kdb_time = upd->kdb_time = ktime;
    indx_log->kdb_commit = upd->kdb_commit = FALSE;

    ulog->kdb_state = KDB_UNSTABLE;

    xdrmem_create(&xdrs, (char *)indx_log->entry_data,
                  indx_log->kdb_entry_size, XDR_ENCODE);
    if (!xdr_kdb_incr_update_t(&xdrs, upd))
        return (KRB5_LOG_CONV);

    if ((retval = ulog_sync_update(ulog, indx_log)))
        return (retval);

    if (ulog->kdb_num < ulogentries)
        ulog->kdb_num++;

    ulog->kdb_last_sno = cur_sno;
    ulog->kdb_last_time = ktime;

    /*
     * Since this is a circular array, once we circled, kdb_first_sno is
     * always kdb_entry_sno + 1.
     */
    if (cur_sno > ulogentries) {
        i = upd->kdb_entry_sno % ulogentries;
        indx_log = (kdb_ent_header_t *)INDEX(ulog, i);
        ulog->kdb_first_sno = indx_log->kdb_entry_sno;
        ulog->kdb_first_time = indx_log->kdb_time;
    } else if (cur_sno == 1) {
        ulog->kdb_first_sno = 1;
        ulog->kdb_first_time = indx_log->kdb_time;
    }

    ulog_sync_header(ulog);

    return (0);
}

/*
 * Mark the log entry as committed and sync the memory mapped log
 * to file.
 */
krb5_error_code
ulog_finish_update(krb5_context context, kdb_incr_update_t *upd)
{
    krb5_error_code     retval;
    kdb_ent_header_t    *indx_log;
    uint_t              i;
    kdb_log_context     *log_ctx;
    kdb_hlog_t          *ulog = NULL;
    uint32_t            ulogentries;

    INIT_ULOG(context);
    ulogentries = log_ctx->ulogentries;

    i = (upd->kdb_entry_sno - 1) % ulogentries;

    indx_log = (kdb_ent_header_t *)INDEX(ulog, i);

    indx_log->kdb_commit = TRUE;

    ulog->kdb_state = KDB_STABLE;

    if ((retval = ulog_sync_update(ulog, indx_log)))
        return (retval);

    ulog_sync_header(ulog);

    return (0);
}

/*
 * Set the header log details on the slave and sync it to file.
 */
static void
ulog_finish_update_slave(kdb_hlog_t *ulog, kdb_last_t lastentry)
{

    ulog->kdb_last_sno = lastentry.last_sno;
    ulog->kdb_last_time = lastentry.last_time;

    ulog_sync_header(ulog);
}

/*
 * Delete an entry to the update log.
 */
krb5_error_code
ulog_delete_update(krb5_context context, kdb_incr_update_t *upd)
{

    upd->kdb_deleted = TRUE;

    return (ulog_add_update(context, upd));
}

/*
 * Used by the slave or master (during ulog_check) to update it's hash db from
 * the incr update log.
 *
 * Must be called with lock held.
 */
krb5_error_code
ulog_replay(krb5_context context, kdb_incr_result_t *incr_ret, char **db_args)
{
    krb5_db_entry       *entry = NULL;
    kdb_incr_update_t   *upd = NULL, *fupd;
    int                 i, no_of_updates;
    krb5_error_code     retval;
    krb5_principal      dbprinc = NULL;
    kdb_last_t          errlast;
    char                *dbprincstr = NULL;
    kdb_log_context     *log_ctx;
    kdb_hlog_t          *ulog = NULL;

    INIT_ULOG(context);

    no_of_updates = incr_ret->updates.kdb_ulog_t_len;
    upd = incr_ret->updates.kdb_ulog_t_val;
    fupd = upd;

    /*
     * We reset last_sno and last_time to 0, if krb5_db2_db_put_principal
     * or krb5_db2_db_delete_principal fail.
     */
    errlast.last_sno = (unsigned int)0;
    errlast.last_time.seconds = (unsigned int)0;
    errlast.last_time.useconds = (unsigned int)0;

    if ((retval = krb5_db_open(context, db_args,
                               KRB5_KDB_OPEN_RW|KRB5_KDB_SRV_TYPE_ADMIN)))
        goto cleanup;

    for (i = 0; i < no_of_updates; i++) {
        if (!upd->kdb_commit)
            continue;

        if (upd->kdb_deleted) {
            dbprincstr = malloc((upd->kdb_princ_name.utf8str_t_len
                                 + 1) * sizeof (char));

            if (dbprincstr == NULL) {
                retval = ENOMEM;
                goto cleanup;
            }

            (void) strncpy(dbprincstr,
                           (char *)upd->kdb_princ_name.utf8str_t_val,
                           (upd->kdb_princ_name.utf8str_t_len + 1));
            dbprincstr[upd->kdb_princ_name.utf8str_t_len] = 0;

            if ((retval = krb5_parse_name(context, dbprincstr,
                                          &dbprinc))) {
                goto cleanup;
            }

            free(dbprincstr);

            retval = krb5int_delete_principal_no_log(context, dbprinc);

            if (dbprinc) {
                krb5_free_principal(context, dbprinc);
                dbprinc = NULL;
            }

            if (retval)
                goto cleanup;
        } else {
            entry = (krb5_db_entry *)malloc(sizeof (krb5_db_entry));

            if (!entry) {
                retval = errno;
                goto cleanup;
            }

            (void) memset(entry, 0, sizeof (krb5_db_entry));

            if ((retval = ulog_conv_2dbentry(context, &entry, upd)))
                goto cleanup;

            retval = krb5int_put_principal_no_log(context, entry);

            if (entry) {
                krb5_db_free_principal(context, entry);
                entry = NULL;
            }
            if (retval)
                goto cleanup;
        }

        upd++;
    }

cleanup:
    if (fupd)
        ulog_free_entries(fupd, no_of_updates);

    if (log_ctx && (log_ctx->iproprole == IPROP_SLAVE)) {
        if (retval)
            ulog_finish_update_slave(ulog, errlast);
        else
            ulog_finish_update_slave(ulog, incr_ret->lastentry);
    }

    return (retval);
}

/*
 * Validate the log file and resync any uncommitted update entries
 * to the principal database.
 *
 * Must be called with lock held.
 */
static krb5_error_code
ulog_check(krb5_context context, kdb_hlog_t *ulog, char **db_args)
{
    XDR                 xdrs;
    krb5_error_code     retval = 0;
    unsigned int        i;
    kdb_ent_header_t    *indx_log;
    kdb_incr_update_t   *upd = NULL;
    kdb_incr_result_t   *incr_ret = NULL;

    ulog->kdb_state = KDB_STABLE;

    for (i = 0; i < ulog->kdb_num; i++) {
        indx_log = (kdb_ent_header_t *)INDEX(ulog, i);

        if (indx_log->kdb_umagic != KDB_ULOG_MAGIC) {
            /*
             * Update entry corrupted we should scream and die
             */
            ulog->kdb_state = KDB_CORRUPT;
            retval = KRB5_LOG_CORRUPT;
            break;
        }

        if (indx_log->kdb_commit == FALSE) {
            ulog->kdb_state = KDB_UNSTABLE;

            incr_ret = (kdb_incr_result_t *)
                malloc(sizeof (kdb_incr_result_t));
            if (incr_ret == NULL) {
                retval = errno;
                goto error;
            }

            upd = (kdb_incr_update_t *)
                malloc(sizeof (kdb_incr_update_t));
            if (upd == NULL) {
                retval = errno;
                goto error;
            }

            (void) memset(upd, 0, sizeof (kdb_incr_update_t));
            xdrmem_create(&xdrs, (char *)indx_log->entry_data,
                          indx_log->kdb_entry_size, XDR_DECODE);
            if (!xdr_kdb_incr_update_t(&xdrs, upd)) {
                retval = KRB5_LOG_CONV;
                goto error;
            }

            incr_ret->updates.kdb_ulog_t_len = 1;
            incr_ret->updates.kdb_ulog_t_val = upd;

            upd->kdb_commit = TRUE;

            /*
             * We don't want to readd this update and just use the
             * existing update to be propagated later on
             */
            ulog_set_role(context, IPROP_NULL);
            retval = ulog_replay(context, incr_ret, db_args);

            /*
             * upd was freed by ulog_replay, we NULL
             * the pointer in case we subsequently break from loop.
             */
            upd = NULL;
            if (incr_ret) {
                free(incr_ret);
                incr_ret = NULL;
            }
            ulog_set_role(context, IPROP_MASTER);

            if (retval)
                goto error;

            /*
             * We flag this as committed since this was
             * the last entry before kadmind crashed, ergo
             * the slaves have not seen this update before
             */
            indx_log->kdb_commit = TRUE;
            retval = ulog_sync_update(ulog, indx_log);
            if (retval)
                goto error;

            ulog->kdb_state = KDB_STABLE;
        }
    }

error:
    if (upd)
        ulog_free_entries(upd, 1);

    free(incr_ret);

    ulog_sync_header(ulog);

    return (retval);
}

static void
ulog_reset(kdb_hlog_t *ulog)
{
    (void) memset(ulog, 0, sizeof (*ulog));
    ulog->kdb_hmagic = KDB_ULOG_HDR_MAGIC;
    ulog->db_version_num = KDB_VERSION;
    ulog->kdb_state = KDB_STABLE;
    ulog->kdb_block = ULOG_BLOCK;
}

/*
 * Map the log file to memory for performance and simplicity.
 *
 * Called by: if iprop_enabled then ulog_map();
 * Assumes that the caller will terminate on ulog_map, hence munmap and
 * closing of the fd are implicitly performed by the caller.
 *
 * The ulogentries argument is a suggested size.  If ulog_map() is called
 * again (for the same context) after having succeeded once, then it will be a
 * no-op.  Else ulogentries will be taken as a minimum (not maximum) and the
 * ulog will be resized if need be.
 *
 * Semantics for various values of caller:
 *
 *  - FKPROPLOG
 *
 *    Don't create if it doesn't exist, map as MAP_PRIVATE.
 *
 *  - FKPROPD
 *
 *    Create and initialize if need be, map as MAP_SHARED, mark slave
 *    status in ulog so that writes to replicated attributes can be
 *    rejected.
 *
 *  - FKLOAD
 *
 *    Create if need be, initialize (even if the ulog was already present), map
 *    as MAP_SHARED.  (Intended for kdb5_util load of iprop dump.)
 *
 *  - FKCOMMAND
 *
 *    Create and [re-]initialize if need be, size appropriately, map as
 *    MAP_SHARED.  (Intended for kdb5_util create and kdb5_util load of
 *    non-iprop dump.)
 *
 *  - FKADMIN
 *
 *    Create and [re-]initialize if need be, size appropriately, map as
 *    MAP_SHARED, and check consistency and recover as necessary.  (Intended
 *    for kadmind and kadmin.local.)
 *
 * Returns 0 on success else failure.
 */
krb5_error_code
ulog_remap(krb5_context context, const char *logname, uint32_t ulogentries,
           int caller, char **db_args)
krb5_error_code
ulog_map(krb5_context context, const char *logname, uint32_t ulogentries,
         int caller, char **db_args)
{
    struct stat st;
    krb5_error_code     retval;
    kdb_log_context     *log_ctx = context->kdblog_context;
    kdb_hlog_t  *ulog = NULL;
    int         ulogfd = -1;
    int         locked = 0;
    krb5_boolean        do_reset = FALSE;

    /*
     * If context->kdblog_context != NULL... we got called again.  This may be
     * a no-op.
     *
     * We can have ulog_map() called twice in some cases.  It's just twice, but
     * still, we don't want to leak, so we clean up after the previous one.
     */
    if (log_ctx != NULL) {
        if (log_ctx->ulog != NULL && log_ctx->ulogfd > -1 &&
            log_ctx->map_type == caller)
            return (0);
        if (log_ctx->ulogfd > -1) {
            close(log_ctx->ulogfd);
            log_ctx->ulogfd = -1;
        }
        if (log_ctx->ulog != NULL) {
            munmap(log_ctx->ulog, log_ctx->map_size);
            log_ctx->ulog = NULL;
            log_ctx->map_size = 0;
        }
        log_ctx->map_type = 0;
    }

    if (stat(logname, &st) == -1) {
        if (caller == FKPROPLOG)
            return (errno);
        ulogfd = open(logname, O_RDWR | O_CREAT, 0600);
        do_reset = TRUE;
    } else {
        ulogfd = open(logname, O_RDWR, 0600);
    }
    if (ulogfd == -1)
        return (errno);

    if (log_ctx == NULL) {
        if (!(log_ctx = calloc(1, sizeof (kdb_log_context)))) {
            retval = ENOMEM;
            goto error;
        }
    }
    context->kdblog_context = log_ctx;
    log_ctx->ulog = ulog;
    log_ctx->ulogentries = ulogentries;
    log_ctx->ulogfd = ulogfd;
    retval = ulog_lock(context, KRB5_LOCKMODE_EXCLUSIVE);
    if (retval)
        goto error;
    locked = 1;

    /* We need the size after obtaining the lock. */
    if (fstat(ulogfd, &st) == -1) {
        retval = errno;
        goto error;
    }

    do_reset = do_reset || (st.st_size == 0);

    if (extend_file_to(ulogfd, sizeof (*ulog)) < 0) {
        retval = errno;
        goto error;
    }
    st.st_size = (st.st_size > sizeof (*ulog)) ? st.st_size : sizeof (*ulog);

    /* Map only the header for now until we've resized the file if need be. */
    ulog = mmap(0, sizeof (*ulog), PROT_READ | PROT_WRITE, MAP_SHARED,
                ulogfd, 0);
    if (ulog == MAP_FAILED) {
        retval = errno;
        goto error;
    }
    log_ctx->map_size = sizeof (*ulog);
    log_ctx->ulog = ulog;

    /*
     * We've mapped only the header at this point, and that may be enough for
     * some callers.
     */
    if (caller == FKLOAD) {
        ulog_reset(ulog);
        ulog_sync_header(ulog);
        ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
        return (0);
    }

    if (do_reset)
        ulog_reset(ulog);

    if (ulog->kdb_hmagic != KDB_ULOG_HDR_MAGIC &&
        ulog->kdb_hmagic != KDB_ULOG_HDR_SLAVE_MAGIC) {
        retval = KRB5_LOG_CORRUPT;
        goto error;
    }

    if (caller == FKPROPLOG) {
        ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
        return (0);
    }

    if (caller == FKPROPD) {
        /*
         * We're on a slave KDC... because we're running kpropd on it.  Note
         * this in the ulog so that we can disallow updates of replicated
         * attributes.
         */
        ulog->kdb_hmagic = KDB_ULOG_HDR_SLAVE_MAGIC;
        ulog_sync_header(ulog);
        ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
        return (0);
    }


    /*
     * Resize the ulog if need be, then re-mmap() it, this time the whole file.
     *
     * We take ulogentries as a minimum, but to avoid truncating the ulog
     * (which would require resetting the ulog, else we might corrupt its
     * state) we compute the actual ulogentries from the file size -- you can't
     * truncate the ulog by reducing the size in the config file.  To truncate
     * use kproplog -R to reset the ulog.
     *
     * XXX Check for overflow in left-hand side of comparison below!
     */
    assert(caller == FKADMIND || caller == FKCOMMAND);
    if ((sizeof (*ulog) + ulog->kdb_num * ulog->kdb_block) >
        (size_t)st.st_size ||
        ulog->kdb_last_sno > ulog->kdb_num) {
        /* XXX Corruption? */
        ulog_reset(ulog);
        ulog_sync_header(ulog);
    }

    /* Resize if need be and... */
    retval = ulog_resize(log_ctx, ulogentries, ulog->kdb_block);
    if (retval)
        goto error;

    if (fstat(ulogfd, &st) == -1) {
        retval = errno;
        goto error;
    }

    /* ...re-mmap() */
    munmap(ulog, sizeof (*ulog));
    log_ctx->ulog = NULL;
    log_ctx->map_size = 0;
    ulog = mmap(0, st.st_size, PROT_READ | PROT_WRITE,
                (caller == FKPROPLOG) ? MAP_PRIVATE : MAP_SHARED, ulogfd, 0);
    if (ulog == MAP_FAILED) {
        retval = errno;
        goto error;
    }

    log_ctx->ulogentries = ulogentries;
    log_ctx->ulog = ulog;
    log_ctx->map_size = st.st_size;

    if (caller == FKADMIND && ulog->kdb_hmagic != KDB_ULOG_HDR_SLAVE_MAGIC) {
        switch (ulog->kdb_state) {
        case KDB_STABLE:
        case KDB_UNSTABLE:
            /*
             * Log is currently un/stable, check anyway
             */
            retval = ulog_check(context, ulog, db_args);
            ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
            if (retval)
                return (retval);
            break;
        case KDB_CORRUPT:
            ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
            return (KRB5_LOG_CORRUPT);
        default:
            /*
             * Invalid db state
             */
            ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
            return (KRB5_LOG_ERROR);
        }
    }

    ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
    return (0);

error:
    if (locked)
        ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
    if (ulog != NULL) {
        if (log_ctx->ulog == ulog)
            log_ctx->ulog = NULL;
        munmap(ulog, log_ctx->map_size);
    }
    if (ulogfd != -1)
        close(ulogfd);
    if (log_ctx != context->kdblog_context)
        free(log_ctx);
    return retval;
}

/*
 * Get the last set of updates seen, (last+1) to n is returned.
 */
krb5_error_code
ulog_get_entries(krb5_context context,          /* input - krb5 lib config */
                 kdb_last_t last,               /* input - slave's last sno */
                 kdb_incr_result_t *ulog_handle) /* output - incr result for slave */
{
    XDR                 xdrs;
    kdb_ent_header_t    *indx_log;
    kdb_incr_update_t   *upd;
    uint_t              indx, count;
    uint32_t            sno;
    krb5_error_code     retval;
    kdb_log_context     *log_ctx;
    kdb_hlog_t          *ulog = NULL;
    uint32_t            ulogentries;

    INIT_ULOG(context);
    ulogentries = log_ctx->ulogentries;

    retval = ulog_lock(context, KRB5_LOCKMODE_SHARED);
    if (retval)
        return retval;

    /*
     * Check to make sure we don't have a corrupt ulog first.
     */
    if (ulog->kdb_state == KDB_CORRUPT) {
        ulog_handle->ret = UPDATE_ERROR;
        (void) ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
        return (KRB5_LOG_CORRUPT);
    }

    /*
     * We need to lock out other processes here, such as kadmin.local,
     * since we are looking at the last_sno and looking up updates.  So
     * we can share with other readers.
     */
    retval = krb5_db_lock(context, KRB5_LOCKMODE_SHARED);
    if (retval) {
        (void) ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
        return (retval);
    }

    /*
     * We may have overflowed the update log or we shrunk the log, or
     * the client's ulog has just been created.
     */
    if ((last.last_sno > ulog->kdb_last_sno) ||
        (last.last_sno < ulog->kdb_first_sno) ||
        (last.last_sno == 0)) {
        ulog_handle->lastentry.last_sno = ulog->kdb_last_sno;
        (void) ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
        (void) krb5_db_unlock(context);
        ulog_handle->ret = UPDATE_FULL_RESYNC_NEEDED;
        return (0);
    } else if (last.last_sno <= ulog->kdb_last_sno) {
        sno = last.last_sno;

        indx = (sno - 1) % ulogentries;

        indx_log = (kdb_ent_header_t *)INDEX(ulog, indx);

        /*
         * Validate the time stamp just to make sure it was the same sno
         */
        if ((indx_log->kdb_time.seconds == last.last_time.seconds) &&
            (indx_log->kdb_time.useconds == last.last_time.useconds)) {

            /*
             * If we have the same sno we return success
             */
            if (last.last_sno == ulog->kdb_last_sno) {
                (void) ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
                (void) krb5_db_unlock(context);
                ulog_handle->ret = UPDATE_NIL;
                return (0);
            }

            count = ulog->kdb_last_sno - sno;

            ulog_handle->updates.kdb_ulog_t_val =
                (kdb_incr_update_t *)malloc(
                    sizeof (kdb_incr_update_t) * count);

            upd = ulog_handle->updates.kdb_ulog_t_val;

            if (upd == NULL) {
                (void) ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
                (void) krb5_db_unlock(context);
                ulog_handle->ret = UPDATE_ERROR;
                return (errno);
            }

            while (sno < ulog->kdb_last_sno) {
                indx = sno % ulogentries;

                indx_log = (kdb_ent_header_t *)
                    INDEX(ulog, indx);

                (void) memset(upd, 0,
                              sizeof (kdb_incr_update_t));
                xdrmem_create(&xdrs,
                              (char *)indx_log->entry_data,
                              indx_log->kdb_entry_size, XDR_DECODE);
                if (!xdr_kdb_incr_update_t(&xdrs, upd)) {
                    (void) ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
                    (void) krb5_db_unlock(context);
                    ulog_handle->ret = UPDATE_ERROR;
                    return (KRB5_LOG_CONV);
                }
                /*
                 * Mark commitment since we didn't
                 * want to decode and encode the
                 * incr update record the first time.
                 */
                upd->kdb_commit = indx_log->kdb_commit;

                upd++;
                sno++;
            } /* while */

            ulog_handle->updates.kdb_ulog_t_len = count;

            ulog_handle->lastentry.last_sno = ulog->kdb_last_sno;
            ulog_handle->lastentry.last_time.seconds =
                ulog->kdb_last_time.seconds;
            ulog_handle->lastentry.last_time.useconds =
                ulog->kdb_last_time.useconds;
            ulog_handle->ret = UPDATE_OK;

            (void) ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
            (void) krb5_db_unlock(context);

            return (0);
        } else {
            /*
             * We have time stamp mismatch or we no longer have
             * the slave's last sno, so we brute force it
             */
            (void) ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
            (void) krb5_db_unlock(context);
            ulog_handle->ret = UPDATE_FULL_RESYNC_NEEDED;

            return (0);
        }
    }

    /*
     * Should never get here, return error
     */
    (void) ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
    ulog_handle->ret = UPDATE_ERROR;
    return (KRB5_LOG_ERROR);
}

krb5_error_code
ulog_set_role(krb5_context ctx, iprop_role role)
{
    kdb_log_context     *log_ctx;

    if (!ctx->kdblog_context) {
        if (!(log_ctx = malloc(sizeof (kdb_log_context))))
            return (errno);
        memset(log_ctx, 0, sizeof(*log_ctx));
        log_ctx->ulogfd = -1;
        ctx->kdblog_context = log_ctx;
    } else
        log_ctx = ctx->kdblog_context;

    log_ctx->iproprole = role;

    return (0);
}

/*
 * Extend update log file.
 */
static int extend_file_to(int fd, uint_t new_size)
{
    off_t current_offset;
    static const char zero[512] = { 0, };

    current_offset = lseek(fd, 0, SEEK_END);
    if (current_offset < 0)
        return -1;
    /* XXX INT_MAX?! */
    if (new_size > INT_MAX) {
        errno = EINVAL;
        return -1;
    }
    while (current_offset < (off_t)new_size) {
        int write_size, wrote_size;
        write_size = new_size - current_offset;
        if (write_size > 512)
            write_size = 512;
        wrote_size = write(fd, zero, write_size);
        if (wrote_size < 0)
            return -1;
        if (wrote_size == 0) {
            errno = EINVAL;     /* XXX ?? */
            return -1;
        }
        current_offset += wrote_size;
        write_size = new_size - current_offset;
    }
    return 0;
}
