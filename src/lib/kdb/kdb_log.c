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

static int extend_file_to(int fd, size_t new_size);
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
 * Adds an entry to the update log.  As a possible side-effect the ulog may get
 * resized and/or re-mmap()ed in.
 *
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
    uint16_t            new_block;

    INIT_ULOG(context);

    assert(upd != NULL);
    assert(log_ctx->size > sizeof (*ulog));

    (void) gettimeofday(&timestamp, NULL);
    ktime.seconds = timestamp.tv_sec;
    ktime.useconds = timestamp.tv_usec;

    upd_size = xdr_sizeof((xdrproc_t)xdr_kdb_incr_update_t, upd);

    recsize = sizeof (kdb_ent_header_t) + upd_size;

    /* Re-map the ulog if need be */
    retval = ulog_map(context, NULL, 0, ULOG_MAP_ENTRIES, NULL);
    if (retval)
        return (retval);

    if (recsize > ULOG_MAX_BLOCK) {
        /*
         * Oops, we can't store this in the ulog.  So force a full resync and
         * pretend we did something anyways, that way the change to the
         * principal can still go through.
         */
        ulog_reset(ulog);
        return (0);
    }

    /* Resize the ulog block size if need be (but not the file). */
    if (recsize > ulog->kdb_block) {
        ulog_reset(ulog);

        /* Note that recsize <= ULOG_MAX_BLOCK (< UINT16_MAX) here. */
        new_block = recsize / ULOG_BLOCK;
        if (recsize % ULOG_BLOCK)
            new_block++;
        assert(new_block < ((UINT16_MAX - sizeof (*ulog)) / ULOG_BLOCK));
        new_block *= ULOG_BLOCK;
        ulog->kdb_block = new_block;
        /* The block size changed; recompute ulogentries. */
        log_ctx->ulogentries =
            (log_ctx->size - sizeof (*ulog)) / ulog->kdb_block;
    }

    ulogentries = log_ctx->ulogentries;
    ulog = log_ctx->ulog;

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

    /* Do not write past the mmap()! */
    assert((uintptr_t)indx_log + ulog->kdb_block <=
           (uintptr_t)ulog + log_ctx->size);

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
 * Used by the slave to update it's hash db from the incr update log.
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

    if (retval)
        ulog_finish_update_slave(ulog, errlast);
    else
        ulog_finish_update_slave(ulog, incr_ret->lastentry);

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

/* Helper for ulog_map(). */
static
int
ulog_reopen_check(kdb_log_context *log_ctx)
{
    struct stat st;

    if (log_ctx->ulogfd == -1) {
        assert(log_ctx->ulog == NULL);
        return 1;
    }
    if (fstat(log_ctx->ulogfd, &st) == -1)
        return 1;
    if (log_ctx->mtime != st.st_mtime || log_ctx->size != (size_t)st.st_size)
        return 1;
    return 0;
}

/*
 * Map the log file to memory for performance and simplicity.
 *
 * Called by kadmind, kadmin.local, kpropd, kproplog, and kdb5_util if
 * iprop_enabled.
 *
 * Assumes that the caller will terminate on ulog_map, hence munmap and
 * closing of the fd are implicitly performed by the caller.
 *
 * This function can be called multiple times, and in particular is intended to
 * be called repeatedly through ulog_add_update() so as to make sure that we
 * re-open the ulog if need be or adapt to ulog size changes.
 *
 * The ulogentries argument is a suggested size; the maximum ulog entry size is
 * assumed in initially sizing a ulog.  If a ulog already exists and its size
 * is reasonable then the ulogentries argument is ignored.  If ulogentries is
 * zero and the ULOG_MAP_ENTRIES flag is passed then DEF_ULOGENTRIES is used.
 *
 * The db_args argument is ignored.
 *
 * Semantics for various flags:
 *
 *  - ULOG_RESET
 *
 *    Truncate the ulog and re-initialize it.
 *
 *  - ULOG_DONT_CREATE
 *
 *    If the ulog doesn't exist just return an error.
 *
 *  - ULOG_MAP_PRIVATE
 *
 *    mmap() the ulog with MAP_PRIVATE.
 *
 *  - ULOG_MAP_ENTRIES
 *
 *    mmap() the entire ulog, not just the header.
 *
 * Returns 0 on success else a krb5 error code on failure.
 */
krb5_error_code
ulog_map(krb5_context context, const char *logname, uint32_t ulogentries,
         int flags, char **db_args)
{
    struct stat st;
    krb5_error_code     retval;
    kdb_log_context     *log_ctx = context->kdblog_context;
    kdb_hlog_t  *ulog = NULL;
    int         ulogfd = -1;
    int         locked = 0;
    krb5_boolean        do_reset = (flags & ULOG_RESET) ? TRUE : FALSE;

    if ((flags & ULOG_MAP_ENTRIES) && ulogentries == 0)
        ulogentries = DEF_ULOGENTRIES;
    if (ulogentries > 0 && ulogentries < MIN_ULOGENTRIES)
        ulogentries = MIN_ULOGENTRIES;

    if (log_ctx != NULL && log_ctx->logname != NULL) {
        if (!ulog_reopen_check(log_ctx))
            return 0;          /* Perfect, nothing to do. */
        logname = (char *)log_ctx->logname;
        /* Cleanup after previous ulog_map(). */
        if (log_ctx->ulogfd > -1) {
            close(log_ctx->ulogfd);
            log_ctx->ulogfd = -1;
        }
        if (log_ctx->ulog != NULL) {
            assert(log_ctx->size > 0);
            munmap(log_ctx->ulog, log_ctx->size);
            log_ctx->ulog = NULL;
            log_ctx->size = 0;
        }
        log_ctx->flags = 0;
    }

    if (stat(logname, &st) == -1) {
        if ((flags & ULOG_DONT_CREATE))
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
    if (log_ctx->logname == NULL) {
        log_ctx->logname = strdup(logname);
        if (log_ctx->logname == NULL)
            return ENOMEM;
    }

    /* From here on we must goto error; there's just one return 0 below. */
    context->kdblog_context = log_ctx;
    log_ctx->flags = flags & ULOG_MAP_FLAGS;
    log_ctx->ulog = ulog;
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

    /*
     * Compute the ulog size given ulogentries and the size of the existing
     * file.  We want to use the existing size whenever possible and only use
     * ulogentries (or DEF_ULOGENTRIES) when the file is too small (probably
     * because we just created it, or because a slave was promoted to a master
     * by running kadmind on it, or because someone ran kadmin.local on a
     * slave).
     *
     * (Because we know that st_size is never negative if fstat(2) succeeded we
     * don't bother writing "st.st_size >= 0 && (size_t)st.st_size ...".)
     *
     * We don't care for (st.st_size - sizeof (*ulog)) % ulog->kdb_block to be
     * zero: as kdb_block changes we don't resize the file, so this is bound to
     * be not zero.
     */
    assert(st.st_size >= 0);
    log_ctx->size = sizeof (*ulog) + ulogentries * ULOG_MAX_BLOCK;
    if (!(flags & ULOG_MAP_ENTRIES))
        log_ctx->size = sizeof (*ulog);
    else if ((size_t)st.st_size > sizeof (*ulog) &&
        (((size_t)st.st_size - sizeof (*ulog)) / ULOG_MAX_BLOCK) >=
        MIN_ULOGENTRIES)
        log_ctx->size = st.st_size;

    /*
     * Make sure that the file is the desired size.  We have to do this because
     * the standard says behavior is undefined for any mmmap()ing of file space
     * beyond the end of the file.  Behavior in the face of truncation is also
     * undefined.  We don't want a hole-y file; ftruncate() is insufficient for
     * growing a file.
     */
    if ((flags & ULOG_RESET) && !(flags & ULOG_MAP_ENTRIES)) {
        assert(log_ctx->size == sizeof (*ulog));
        ftruncate(ulogfd, sizeof (*ulog));
    }
    if (extend_file_to(ulogfd, log_ctx->size) < 0) {
        retval = errno;
        goto error;
    }

    /*
     * We mmap() the whole ulog if ULOG_MAP_ENTRIES or just the header
     * otherwise.
     */
    ulog = mmap(0, log_ctx->size, PROT_READ | PROT_WRITE, MAP_SHARED,
                log_ctx->ulogfd, 0);
    if (ulog == MAP_FAILED) {
        retval = errno;
        goto error;
    }
    log_ctx->ulog = ulog;

    /* Reset if requested or if the header looks off */
    if (do_reset || ulog->kdb_block < ULOG_BLOCK ||
        ulog->kdb_block > ULOG_MAX_BLOCK ||
        (SSIZE_MAX - sizeof (*ulog)) / ulog->kdb_block < ulog->kdb_num ||
        (sizeof (*ulog) + ulog->kdb_num * ulog->kdb_block) > (size_t)st.st_size ||
        (ulog->kdb_last_sno > ulog->kdb_num && ulog->kdb_num != 0)) {
        ulog_reset(ulog);
    }

    if (ulog->kdb_hmagic != KDB_ULOG_HDR_MAGIC) {
        retval = KRB5_LOG_CORRUPT;
        goto error;
    }

    /*
     * Now that we know that ulog->kdb_block is valid we compute ulogentries
     * from that and the ulog size.
     */
    ulogentries = (log_ctx->size - sizeof (*ulog)) / ulog->kdb_block;
    log_ctx->ulogentries = ulogentries;

    if (flags & ULOG_MAP_PRIVATE) {
        /*
         * Re-mmap() as read-only and private (but note that MAP_PRIVATE is
         * NOT atomic).  This is rather pointless as the only use of this is
         * kproplog and there's very little (or no) risk of it corrupting the
         * ulog by corrupting memory.
         */
        ulog_sync_header(ulog);
        munmap(ulog, log_ctx->size);
        ulog = mmap(0, log_ctx->size, PROT_READ, MAP_PRIVATE,
                    log_ctx->ulogfd, 0);
        if (ulog == MAP_FAILED) {
            retval = errno;
            goto error;
        }
        log_ctx->ulog = ulog;
    }

    ulog_sync_header(ulog);
    if (fstat(ulogfd, &st) == -1) {
        retval = errno;
        goto error;
    }
    log_ctx->mtime = st.st_mtime;

    /*
     * This is the only place we return 0 other than the no-op case at the top.
     */
    ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
    return (0);

error:
    if (locked)
        ulog_lock(context, KRB5_LOCKMODE_UNLOCK);
    if (ulog != NULL) {
        if (log_ctx->ulog == ulog)
            log_ctx->ulog = NULL;
        munmap(ulog, log_ctx->size);
        log_ctx->size = 0;
    }
    if (ulogfd != -1)
        close(ulogfd);
    log_ctx->ulogfd = -1;
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
static int extend_file_to(int fd, size_t new_size)
{
    off_t current_offset;
    static const char zero[512] = { 0, };

    assert(new_size <= SSIZE_MAX);

    current_offset = lseek(fd, 0, SEEK_END);
    if (current_offset == (off_t)-1)
        return -1;

    /* There's no OFF_MAX, oddly enough. */
    if (new_size > SSIZE_MAX) {
        errno = EINVAL;
        return -1;
    }

    if (current_offset >= (off_t)new_size)
        return 0;

    while (current_offset < (off_t)new_size) {
        ssize_t write_size, wrote_size;
        write_size = new_size - current_offset;
        /* XXX Use sysconf(_SC_PAGESIZE) instead of 512? */
        if (write_size > 512)
            write_size = 512;
        wrote_size = write(fd, zero, write_size);
        if (wrote_size == -1)
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
