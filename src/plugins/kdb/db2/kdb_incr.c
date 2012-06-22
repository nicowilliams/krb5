/*
 * lib/kdb/kdb_incr.c
 */

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if 1 /* XXX HAVE_DIRENT_WHATEVER */
#include <dirent.h>
#endif

#include "k5-int.h"
#include <stdio.h>
#include "kdb.h"
#include "kdb_incr.h"
#include "kdb_xdr.h"
#include <syslog.h>

/*
 * Utility routine: generate name of database file.  We all get our own copy!
 */
static char *gen_dbsuffix(const char *db_name, char *sfx)
{
    char *dbsuffix;
    
    if (sfx == NULL)
	return((char *) NULL);

    dbsuffix = malloc (strlen(db_name) + strlen(sfx) + 1);
    if (!dbsuffix)
	return(0);
    (void) strcpy(dbsuffix, db_name);
    (void) strcat(dbsuffix, sfx);
    return dbsuffix;
}

krb5_error_code krb5_dbinc_init_ctx(krb5_dbinc_ctx *ictx, krb5_context ctx, 
				    const char *db_name)
{
  ictx->ctx = ctx;
  ictx->db_name = db_name;
  if (db_name == NULL)
      return EINVAL;

  ictx->journal_name = gen_dbsuffix(db_name, ".journal");
  ictx->dvn_name = gen_dbsuffix(ictx->journal_name, "/version");
  ictx->lock_name = gen_dbsuffix(ictx->journal_name, "/lock");
  ictx->lock_fd = ictx->lock_cnt = -1;
  if (ictx->journal_name == NULL || ictx->dvn_name == NULL ||
      ictx->lock_name == NULL) {
      if (ictx->journal_name != NULL)
	  free(ictx->journal_name);
      if (ictx->dvn_name != NULL)
	  free(ictx->dvn_name);
      if (ictx->lock_name != NULL)
	  free(ictx->lock_name);
      return ENOMEM;
  }
  return 0;
}

void krb5_dbinc_release_ctx(krb5_dbinc_ctx *ictx)
{
  free(ictx->journal_name);
  free(ictx->dvn_name);
  free(ictx->lock_name);
  ictx->db_name = ictx->journal_name = ictx->dvn_name = ictx->lock_name = NULL;
  ictx->lock_cnt = ictx->lock_fd = -1;
}

krb5_error_code krb5_dbinc_init_journal(krb5_dbinc_ctx *ctx)
{
    krb5_error_code retval;
    int fd;
    FILE *f;

    memset(ctx, 0, sizeof(*ctx));
    
    /*
      Create the journal; fail if it exists.
    */
    if (mkdir(ctx->journal_name, 0700) < 0)
	return errno;

    /*
      Create the lock file; fail if it exists.
    */
    fd = open(ctx->lock_name, O_RDWR|O_CREAT|O_EXCL, 0600);
    if (fd < 0)
	return errno;
    write(fd, "", 1);
    close(fd);

    /*
      Lock the journal, failing immediately if we can't.
    */
    if ((retval = krb5_dbinc_lock_journal(ctx, (KRB5_LOCKMODE_EXCLUSIVE|
					       KRB5_LOCKMODE_DONTBLOCK))))
	return retval;

    /*
      Now we are sure no one else is trying this right now.  Create the DVN.
    */

    f = fopen(ctx->dvn_name, "wb");
    if (f == NULL)
	retval = errno ? errno : ENOENT;
    if (! retval && (fprintf(f, "%u\n", time(0)) <= 0 || fclose(f) != 0))
	retval = errno ? errno : EINVAL;

    /*
      Unlock.
    */
    if (retval)
	krb5_dbinc_lock_journal(ctx, KRB5_LOCKMODE_UNLOCK);
    else
	retval = krb5_dbinc_lock_journal(ctx, KRB5_LOCKMODE_UNLOCK);

    return retval;
}

krb5_error_code krb5_dbinc_destroy_journal(krb5_dbinc_ctx *ctx)
{
    krb5_error_code retval;
    DIR *dir = NULL;
    struct dirent *dp;
    char buf[1024]; /* big enough for any files we expect to be there */
    
    if ((retval = krb5_dbinc_lock_journal(ctx, KRB5_LOCKMODE_EXCLUSIVE)))
	return retval;

    dir = opendir(ctx->journal_name);
    if (dir == NULL) {
	retval = errno;
	goto fail;
    }

    /*
      This is not thread safe, though it would take a non-krb5_dbinc
      caller to make a problem.  It could also be more efficient, but
      who cares?
    */
    while ((dp = readdir(dir)) != NULL) {
	if (strcmp(dp->d_name, ".") != 0 &&
	    strcmp(dp->d_name, "..") != 0 &&
	    strcmp(dp->d_name, "lock") != 0 &&
	    (strlen(ctx->journal_name)+strlen(dp->d_name)+2) < sizeof(buf)) {
	    strcpy(buf, ctx->journal_name);
	    strcat(buf, "/");
	    strcat(buf, dp->d_name);
	    if (unlink(buf) < 0) {
		retval = errno;
		goto fail;
	    }
	}
    }

    if (dir != NULL)
	closedir(dir);
    dir = NULL;

    if ((retval = krb5_dbinc_lock_journal(ctx, KRB5_LOCKMODE_UNLOCK)))
	return retval;
    if (unlink(ctx->lock_name) < 0 ||
	rmdir(ctx->journal_name) < 0)	
	return retval;
    return 0;

 fail:
    if (dir != NULL)
	closedir(dir);
    if (retval)
	krb5_dbinc_lock_journal(ctx, KRB5_LOCKMODE_UNLOCK);
    else
	retval = krb5_dbinc_lock_journal(ctx, KRB5_LOCKMODE_UNLOCK);
    return retval;
}

int krb5_dbinc_journal_exists(krb5_dbinc_ctx *ctx)
{
    struct stat st;
    return (stat(ctx->journal_name, &st) == 0);
}
    
krb5_error_code krb5_dbinc_lock_journal(krb5_dbinc_ctx *ctx, int mode)
{
    int retval = 0;

    if ((mode & KRB5_LOCKMODE_UNLOCK) == 0) {
	if (ctx->lock_fd != -1) {
	    if (ctx->lock_mode != mode) {
		syslog(LOG_NOTICE,
		       "Tried to change incremental propagation lock mode");
		return EINVAL; /* dbinc locks cannot be up/downgraded */
	    }
	    ctx->lock_cnt += 1;
	} else if ((ctx->lock_fd = open(ctx->lock_name, O_RDWR, 0600)) < 0) {
	    syslog(LOG_NOTICE,
		   "Couldn't open incremental propagation lock file %s (%d)",
		   ctx->lock_name, errno);
	    retval = errno;
	} else {
	    retval = krb5_lock_file(ctx->ctx, ctx->lock_fd, mode);
	    if (retval) {
		close(ctx->lock_fd);
		ctx->lock_fd = -1;
		syslog(LOG_NOTICE,
		       "Couldn't lock incremental propagation lock file %s "
		       "with mode %x (%d)",
		       ctx->lock_name, mode, errno);
	    } else {
		ctx->lock_cnt = 1;
		ctx->lock_mode = mode;
	    }
	}
    } else {
	if (ctx->lock_cnt > 1) {
	    ctx->lock_cnt -= 1;
	} else if (ctx->lock_cnt != 1 || ctx->lock_fd < 0) {
	    retval = KRB5_KDB_NOTLOCKED;
	    syslog(LOG_NOTICE, "Tried to unlock incremental propagation while "
		   "not holding lock");
	} else {
	    retval = krb5_lock_file(ctx->ctx, ctx->lock_fd, mode);
	    if (retval == 0) {
		close(ctx->lock_fd);
		ctx->lock_cnt -= 1;
		ctx->lock_fd = -1;
	    } else {
		syslog(LOG_NOTICE, "Failed to unlock incremental propagation "
		       "lock file! (%d)", errno);
	    }
	}
    }
    return retval;
}

krb5_error_code krb5_dbinc_get_dvn(krb5_dbinc_ctx *ctx, krb5_ui_4 *dvn)
{
    FILE *f;

    *dvn = 0;

    f = fopen(ctx->dvn_name, "rb");
    if (f == NULL) {
	syslog(LOG_INFO, "Could not open DVN file %s (%d)", ctx->dvn_name,
	       errno);
	return errno ? errno : ENOENT;
    }
    if (fscanf(f, "%u", dvn) != 1) {
	syslog(LOG_NOTICE, "Corrupted incremental propagation DVN file %s",
	       ctx->dvn_name);
	fclose(f);
	return EINVAL; /* need my own error codes */
    }
    if (fclose(f) != 0) {
	/*
	 * This should really never happen, and it's not really a bad
	 * enough error that we couldn't just ignore it...
	 */
	syslog(LOG_NOTICE, "fclose() of DVN file failed!");
	return errno ? errno : EINVAL; /* need my own error codes */
    }
    return 0;
}

krb5_error_code krb5_dbinc_put_dvn(krb5_dbinc_ctx *ctx, krb5_ui_4 dvn)
{
    FILE *f = fopen(ctx->dvn_name, "rb+");
    if (f == NULL) {
	syslog(LOG_NOTICE, "Could not open iprop journal version file %s (%d)",
	       ctx->dvn_name, errno);
	return errno ? errno : EINVAL; /* need my own error codes */
    }
    /*
     * Note that for any date after 2001-09-09 this write should be
     * atomic for typical filesystems because it will be the same size
     * as the file's previous size.  A bit lame... but it'll do.
     */
    if (fprintf(f, "%u\n", dvn) < 0) {
	syslog(LOG_NOTICE, "Could not write to iprop journal version file "
		"%s (%d)", ctx->dvn_name, errno);
	fclose(f);
	return errno ? errno : EINVAL; /* need my own error codes */
    }
    if (fflush(f) != 0) {
	syslog(LOG_NOTICE, "Could not flush writes iprop journal version file "
		"%s (%d)", ctx->dvn_name, errno);
	return errno ? errno : EINVAL; /* need my own error codes */
    }
#if (_BSD_SOURCE || _XOPEN_SOURCE)
    if (fsync(fileno(f)) == -1)
	syslog(LOG_NOTICE, "Could not sync iprop journal file %s (%d)",
	       ctx->dvn_name, errno);
#endif
    if (fclose(f) != 0) {
	syslog(LOG_NOTICE, "Could not close iprop journal version file "
		"%s (%d)", ctx->dvn_name, errno);
	return errno ? errno : EINVAL; /* need my own error codes */
    }
    return 0;
}

char *krb5_dbinc_make_entry_name(krb5_dbinc_ctx *ctx, krb5_ui_4 dvn)
{
    char buf[256];
    /* a 4-byte int cannot have >256 digits... */
    sprintf(buf, "/%u", dvn);
    return gen_dbsuffix(ctx->journal_name, buf);
}

krb5_error_code krb5_dbinc_make_entry_wrapped(krb5_dbinc_ctx *ctx,
					      krb5_dbinc_entry_type cmd,
					      krb5_data *data)
{
    int retval;
    krb5_ui_4 dvn;
    FILE *f = NULL;
    char *entryname;

    /*
      If there is no journal, incremental propagation is not
      enabled.  Just "succeed" by doing nothing.
    */
    if (! krb5_dbinc_journal_exists(ctx))
	return 0;
    
    if ((retval = krb5_dbinc_lock_journal(ctx, KRB5_LOCKMODE_EXCLUSIVE)))
	return retval;
    
    if ((retval = krb5_dbinc_get_dvn(ctx, &dvn)))
	goto cleanup;

    dvn += 1;

    entryname = krb5_dbinc_make_entry_name(ctx, dvn);
    if (entryname == NULL) {
	retval = ENOMEM;
	syslog(LOG_NOTICE, "Out of memory while updating iprop journal");
	goto cleanup;
    }
    f = fopen(entryname, "wb");
    free(entryname);
    if (f == NULL) {
	retval = errno ? errno : EINVAL; /* need my own error codes */
	syslog(LOG_NOTICE, "Could not create/truncate journal entry %u (%d)",
	       dvn, errno);
	goto cleanup;
    }
  
    if (fprintf(f, "%s\t%u\t", 
		(cmd == KRB5_DBINC_PUT) ? "put" : "del",
		data->length) < 0 ||
	fwrite(data->data, (size_t)1, (size_t)data->length, f) != data->length ||
	fputc('\n', f) == EOF) {
	retval = errno ? errno : EINVAL; /* need my own error codes */
	(void) fclose(f);
	syslog(LOG_NOTICE, "Could not write journal entry %u (%d)",
	       dvn, errno);
	goto cleanup;
    }

    if (fclose(f) != 0) {
	retval = errno ? errno : EINVAL; /* need my own error codes */
	syslog(LOG_NOTICE, "Failed to close new journal entry %u (%d)",
	       dvn, errno);
	goto cleanup;
    }

    /*
     * At this point the file has been written successfully.
     */
    retval = krb5_dbinc_put_dvn(ctx, dvn);

 cleanup:
    /*
     * Unlock the journal.  If we failed above we don't want to clobber
     * the retval, else we want to communicate any possible unlock
     * failure.
     */
    if (retval != 0)
	krb5_dbinc_lock_journal(ctx, KRB5_LOCKMODE_UNLOCK);
    else
	retval = krb5_dbinc_lock_journal(ctx, KRB5_LOCKMODE_UNLOCK);

    return retval;
}

krb5_error_code krb5_dbinc_make_entry(krb5_dbinc_ctx *ctx, 
				      krb5_dbinc_entry_type cmd,
				      krb5_data *data)
{
    int retval = krb5_dbinc_make_entry_wrapped(ctx, cmd, data);
    if (retval)
	com_err("kdb_incr", retval, "making entry");
    return retval;
}

/*
 * This function takes an entry from the journal and replaces the entry
 * data part with the entry data from the KDB, if there's a KDB entry.
 * Note that a "put" can become a "del", and vice-versa.
 *
 * It'd be nice if we could just change the format of the entry that
 * appears in the logfile, but that'd be too risky a change, and it'd
 * require resetting incremental propagation.
 */
krb5_error_code krb5_dbinc_get_entry_from_db(krb5_dbinc_ctx *ctx,
					     krb5_data *entry,
					     krb5_data *new_entry)
{
    krb5_error_code retval;
    krb5_db_entry *dbentry = NULL;
    krb5_principal princ = NULL;
    krb5_data data;
    krb5_data encoded_entry;
    krb5_data dbkey;
    int one = 1;
    char cmd[4];
    unsigned int len;
    int slen, ofs;

    new_entry->data = NULL;
    new_entry->length = 0;

    encoded_entry.data = NULL;
    encoded_entry.length = 0;
    dbkey.data = NULL;
    dbkey.length = 0;

    /* Parse dbinc entry */
    if (sscanf(entry->data, "%4s %u %n", cmd, &len, &ofs) != 2)
       return EINVAL; /* need my own error codes */

    /*
     * 'data' refers to the {encoded KDB entry, or encoded KDB lookup
     * key} from the dbinc entry.
     */
    data.length = len;
    data.data = entry->data + ofs;

    if (strcmp(cmd, "put") != 0 && strcmp(cmd, "del") != 0)
       return EINVAL;

    /*
     * The common case will be a "put", in which case we need to decode
     * the encoded KDB entry from the dbinc entry, extract the principal
     * name, look it up in the KDB, and if we find an entry, then
     * re-encode it and format a new dbinc entry.
     */

    /* Get the principal name from the entry */
    if (strcmp(cmd, "del") == 0) {
       /* data.data *is* null-terminated in this case */
       retval = krb5_parse_name(ctx->ctx, data.data, &princ);
       if (retval)
           return retval;
    } else if (strcmp(cmd, "put") == 0) {
       /* data.data is an encoded KDB entry; decode */
       retval = krb5_decode_princ_entry(ctx->ctx, &data, &dbentry);
       if (retval != 0)
           goto cleanup;
	retval = krb5_copy_principal(ctx->ctx, dbentry->princ, &princ);
	if (retval != 0)
	    goto cleanup;
    }

    /* Lookup the current KDB entry for the affected princ */
    retval = krb5_db_get_principal(ctx->ctx, princ, 0, &dbentry);

    /* in case of an unrecoverable error */
    if (retval != 0 || retval != KRB5_KDB_NOENTRY)
	goto cleanup;

    /* mimic the old nentries behavior */
    if (retval == KRB5_KDB_NOENTRY)
	one = 0;

    /* If the log entry was a "del" and the princ doesn't exist, we're done */
    if (strcmp(cmd, "del") == 0 && one == 0)
	goto cleanup; /* success */

    /* We need to format a new dbinc entry */
    if (one == 1) {
	/* 
	 * ...encode the entry from the KDB, if there was one,...
	 *
	 * (What a waste!  krb5_db_get_principal will have called
	 * krb5_decode_princ_contents() just so we can call
	 * krb5_encode_princ_entry() on the result.  We could add a
	 * krb5_db_get_principal_decoded() function, but, should we
	 * bother?)
	 */
	retval = krb5_encode_princ_entry(ctx->ctx, &encoded_entry,
					    dbentry);
	if (retval)
	    goto cleanup;
	/* If nothing changes, we're done (a minor optimization) */
	if (strcmp(cmd, "put") == 0 &&
	    data.length == encoded_entry.length &&
	    memcmp(data.data, encoded_entry.data, (size_t)data.length) == 0)
	    goto cleanup;
	data = encoded_entry;
    } else {
	/*
	 * This was a "put" but the principal doesn't exist, so we'll
	 * make a "del" entry instead.
	 */
	retval = krb5_encode_princ_dbkey(ctx->ctx, &dbkey, princ);
	if (retval)
	    goto cleanup;
	data = dbkey;
    }

    /* ...and finally cobble together a new dbinc entry */
    new_entry->data = malloc((size_t)data.length + 256);
    slen = sprintf(new_entry->data, "%s\t%u\t",
		   (one == 1) ? "put" : "del", data.length);
    if (slen < 0) {
	/* Shouldn't happen */
	retval = errno ? errno : EINVAL;
	goto cleanup;
    }

    (void) memcpy(new_entry->data + slen, data.data, (size_t)data.length);
    new_entry->data[slen + data.length] = '\n';
    new_entry->length = slen + data.length + 1;

    retval = 0;

cleanup:
    krb5_free_data_contents(ctx->ctx, &encoded_entry);
    krb5_free_data_contents(ctx->ctx, &dbkey);
    krb5_free_principal(ctx->ctx, princ);

    /*
     * krb5_dbe_free() ought to check that its arg is NULL
     * and bail early if so, like the other krb5_free*()s, so we
     * don't have to here.
     */
    if (dbentry != NULL)
	krb5_dbe_free(ctx->ctx, dbentry);

    if (retval) {
	free(new_entry->data);
	new_entry->data = NULL;
	syslog(LOG_INFO, "Failed to normalize iprop entry (%d)", retval);
    }

    return retval;
}


krb5_error_code krb5_dbinc_get_entry(krb5_dbinc_ctx *ctx, krb5_ui_4 dvn,
				     krb5_data *entry)
{
    int retval;
    FILE *f = NULL;
    char *entryname = NULL;
    struct stat st;
    krb5_data new_entry;

    entryname = krb5_dbinc_make_entry_name(ctx, dvn);
    if (entryname == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
  
    if (stat(entryname, &st) < 0) {
	retval = errno;
	goto cleanup;
    }

    if (entry != NULL) {
	f = fopen(entryname, "rb");
	if (f == NULL) {
	    syslog(LOG_INFO, "Could not open journal entry %u (%d)",
		   dvn, errno);
	    retval = ENOENT;
	    goto cleanup;
	}
	
	entry->length = st.st_size;
	entry->data = malloc(st.st_size);
	if (entry->data == NULL) {
	    retval = ENOMEM;
	    syslog(LOG_INFO, "Out of memory while reading journal");
	    goto cleanup;
	}
	
	if (fread(entry->data, 1, entry->length, f) != entry->length) {
	    syslog(LOG_INFO, "Could not read journal entry %u (%d)",
		   dvn, errno);
	    retval = EINVAL; /* need my own error codes */
	    goto cleanup;
	}
    }

    /*
     * We used to send the encoded KDB entry that appears in the log,
     * but that approach has some interesting failure modes.  Now we
     * decode the entry from the log to find the entry's principal name,
     * then we get that principal's current entry from the DB (if it has
     * one any more).
     */
    if (entry != NULL) {
	retval = krb5_dbinc_get_entry_from_db(ctx, entry, &new_entry);
	if (retval)
	    goto cleanup;
	if (new_entry.data != NULL) {
	    free(entry->data);
	    *entry = new_entry;
	}
    }

#if 0
    if (entry != NULL) {
	FILE *tmpf;
	char tmpbuf[256];

	(void) sprintf(tmpbuf, "/tmp/kprop-debug/%u", dvn);
	tmpf = fopen(tmpbuf, "wb");
	if (tmpf != NULL) {
	    fwrite(entry->data, (size_t)entry->length, 1, tmpf);
	    (void) fclose(tmpf);
	}
    }
#endif

 cleanup:
    if (f != NULL && fclose(f) != 0) {
	if (retval == 0)
	    retval = errno ? errno : EINVAL;  /* need my own error codes */
    }

    if (entry != NULL) {
	if (retval != 0 && entry->data != NULL) {
	    free(entry->data);
	    entry->data = NULL;
	}
    }

    if (entryname != NULL)
	free(entryname);
    
    return retval;
}

krb5_error_code krb5_dbinc_apply_entry(krb5_dbinc_ctx *ctx, krb5_data *entry)
{
    krb5_db_entry *dbentry = NULL;
    krb5_principal principal;
    krb5_error_code retval;
    krb5_data data;
    char cmd[4];
    int ofs;
    unsigned int len;

    if (sscanf(entry->data, "%4s %u %n", cmd, &len, &ofs) != 2) {
	syslog(LOG_NOTICE, "Failed to parse iprop journal entry from master");
	return EINVAL; /* need my own error codes */
    }

    data.length = len;
    data.data = entry->data + ofs;

    if (strcmp(cmd, "put") == 0) {
	retval = krb5_decode_princ_entry(ctx->ctx, &data, &dbentry);
	if (retval != 0) {
	    syslog(LOG_NOTICE, "Failed to parse iprop journal dbentry from "
		   "master (%d)", retval);
	    return retval;
	}
	retval = krb5_db_put_principal(ctx->ctx, dbentry);
	krb5_dbe_free(ctx->ctx, dbentry);
	if (retval != 0) {
	    syslog(LOG_NOTICE, "Failed to put a record into the KDB (%d)",
		   retval);
	    return retval;
	}
    } else if (strcmp(cmd, "del") == 0) {
	/* data.data *is* null-terminated in this case */
	retval = krb5_parse_name(ctx->ctx, data.data, &principal);
	if (retval) {
	    syslog(LOG_NOTICE, "Failed to parse deleted principal name from "
		   "master (%d)", retval);
	    return retval;
	}
	retval = krb5_db_delete_principal(ctx->ctx, principal);
	krb5_free_principal(ctx->ctx, principal);
	if (retval == KRB5_KDB_NOENTRY)
	    retval = 0;
	if (retval) {
	    syslog(LOG_NOTICE, "Failed to delete a record from the KDB (%d)",
		   retval);
	    return retval;
	}
    } else {
	syslog(LOG_NOTICE, "Malformed iprop journal entry from the master");
	return EINVAL; /* need my own error codes */
    }

    return 0;
}
