typedef struct _krb5_dbinc_ctx {
    krb5_context ctx;
    const char *db_name;
    char *journal_name;
    char *dvn_name;
    char *lock_name;
    int lock_fd, lock_cnt, lock_mode;
    int db_initted;
} krb5_dbinc_ctx;

typedef enum { KRB5_DBINC_PUT, KRB5_DBINC_DEL } krb5_dbinc_entry_type;

krb5_error_code krb5_dbinc_init_ctx(krb5_dbinc_ctx *ictx, krb5_context ctx,
                                    const char *db_name);
void krb5_dbinc_release_ctx(krb5_dbinc_ctx *ctx);
krb5_error_code krb5_dbinc_init_journal(krb5_dbinc_ctx *ctx);
krb5_error_code krb5_dbinc_destroy_journal(krb5_dbinc_ctx *ctx);
krb5_error_code krb5_dbinc_get_dvn(krb5_dbinc_ctx *ctx, krb5_ui_4 *dvn);
krb5_error_code krb5_dbinc_lock_journal(krb5_dbinc_ctx *ctx, int mode);
krb5_error_code krb5_dbinc_make_entry(krb5_dbinc_ctx *ctx,
                                      krb5_dbinc_entry_type cmd,
                                      krb5_data *data);
krb5_error_code krb5_dbinc_get_entry(krb5_dbinc_ctx *ctx, krb5_ui_4 dvn,
                                     krb5_data *entry);
krb5_error_code krb5_dbinc_apply_entry(krb5_dbinc_ctx *ctx, krb5_data *entry);
int krb5_dbinc_journal_exists(krb5_dbinc_ctx *ctx);
krb5_error_code krb5_dbinc_put_dvn(krb5_dbinc_ctx *ctx, krb5_ui_4 dvn);
char *krb5_dbinc_make_entry_name(krb5_dbinc_ctx *ctx, krb5_ui_4 dvn);
krb5_error_code krb5_dbinc_make_entry_wrapped(krb5_dbinc_ctx *ctx,
                                              krb5_dbinc_entry_type cmd, krb5_data *data);
krb5_error_code krb5_dbinc_get_entry_from_db(krb5_dbinc_ctx *ctx,
	                                     krb5_data *entry,
					     krb5_data *new_entry);
