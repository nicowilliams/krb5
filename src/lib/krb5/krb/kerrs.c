/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/kerrs.c - Error message functions */
/*
 * Copyright 2006 Massachusetts Institute of Technology.
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

#include <stdarg.h>
#include "k5-int.h"
#include "int-proto.h"

#ifdef DEBUG
static int error_message_debug = 0;
#ifndef ERROR_MESSAGE_DEBUG
#define ERROR_MESSAGE_DEBUG() (error_message_debug != 0)
#endif
#endif

#undef krb5_set_error_message
void KRB5_CALLCONV_C
krb5_set_error_message(krb5_context ctx, krb5_error_code code,
                       const char *fmt, ...)
{
    va_list args;

    if (ctx == NULL)
        return;
    va_start(args, fmt);
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG()) {
        fprintf(stderr,
                "krb5_set_error_message(ctx=%p/err=%p, code=%ld, ...)\n",
                ctx, &ctx->err, (long)code);
    }
#endif
    k5_vset_error(&ctx->err, code, fmt, args);
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG())
        fprintf(stderr, "->%s\n", ctx->err.msg);
#endif
    va_end(args);
}

void KRB5_CALLCONV_C
krb5_set_error_message_fl(krb5_context ctx, krb5_error_code code,
                          const char *file, int line, const char *fmt, ...)
{
    va_list args;

    if (ctx == NULL)
        return;
    va_start(args, fmt);
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG()) {
        fprintf(stderr,
                "krb5_set_error_message(ctx=%p/err=%p, code=%ld, ...)\n",
                ctx, &ctx->err, (long)code);
    }
#endif
    k5_vset_error_fl(&ctx->err, code, file, line, fmt, args);
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG())
        fprintf(stderr, "->%s\n", ctx->err.msg);
#endif
    va_end(args);
}

void KRB5_CALLCONV
krb5_vset_error_message(krb5_context ctx, krb5_error_code code,
                        const char *fmt, va_list args)
{
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG()) {
        fprintf(stderr, "krb5_vset_error_message(ctx=%p, code=%ld, ...)\n",
                ctx, (long)code);
    }
#endif
    if (ctx == NULL)
        return;
    k5_vset_error(&ctx->err, code, fmt, args);
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG())
        fprintf(stderr, "->%s\n", ctx->err.msg);
#endif
}

/* Set the error message state of dest_ctx to that of src_ctx. */
void KRB5_CALLCONV
krb5_copy_error_message(krb5_context dest_ctx, krb5_context src_ctx)
{
    if (dest_ctx == src_ctx)
        return;
    if (src_ctx->err.msg != NULL) {
        k5_set_error(&dest_ctx->err, src_ctx->err.code, "%s",
                     src_ctx->err.msg);
    } else {
        k5_clear_error(&dest_ctx->err);
    }
}

static const char *
err_fmt_fmt(const char *err_fmt, long code, const char *msg)
{
    const char *p;
    char *s;
    char *new_msg;
    char code_buf[40];          /* enough for a 128-bit integer, + NUL */
    size_t c_count = 0;
    size_t m_count = 0;
    size_t bytes;

    if (err_fmt == NULL)
        return NULL;

    for (p = err_fmt; p != NULL && *p != '\0'; p++) {
        if (*p != '%')
            continue;
        switch (*++p) {
        case 'M':
            m_count++;
            continue;
        case 'C':
            c_count++;
            continue;
        }
    }

    if (c_count == 0 && m_count == 0)
        return NULL;

    bytes = snprintf(code_buf, sizeof(code_buf), "%ld", code);
    if (bytes < 0 || bytes >= sizeof(code_buf))
        return NULL;
    bytes = strlen(err_fmt) + c_count * bytes + m_count * strlen(msg);
    new_msg = calloc(1, bytes + 1);
    if (new_msg == NULL)
        return NULL;

    for (s = new_msg, p = err_fmt; p != NULL && *p != '\0'; p++) {
        assert(new_msg + bytes > s);
        if (*p != '%') {
            *s++ = *p;
            continue;
        }
        switch (p[1]) {
        case 'M':
            if (strlcat(new_msg, msg, bytes) >= bytes) {
                assert(0);
                free(new_msg);
                return NULL;
            }
            p++;
            s += strlen(msg);
            continue;
        case 'C':
            if (strlcat(new_msg, code_buf, bytes) >= bytes) {
                assert(0);
                free(new_msg);
                return NULL;
            }
            p++;
            s += strlen(code_buf);
            continue;
        case '\0':
            break;
        case '%':
            *s++ = '%';
            p++;
            continue;
        default:
            *s++ = '%';
            *s++ = p[1];
            p++;
            continue;
        }
    }

    return new_msg;
}

const char * KRB5_CALLCONV
krb5_get_error_message(krb5_context ctx, krb5_error_code code)
{
    const char *std, *custom;

#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG())
        fprintf(stderr, "krb5_get_error_message(%p, %ld)\n", ctx, (long)code);
#endif
    if (ctx == NULL)
        return error_message(code);

    std = k5_get_error(&ctx->err, code);
    custom = err_fmt_fmt(ctx->err_fmt, code, std);
    if (custom != NULL) {
        free((char *)std);
        return custom;
    }
    return std;
}

void KRB5_CALLCONV
krb5_free_error_message(krb5_context ctx, const char *msg)
{
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG())
        fprintf(stderr, "krb5_free_error_message(%p, %p)\n", ctx, msg);
#endif
    if (ctx == NULL)
        return;
    k5_free_error(&ctx->err, msg);
}

void KRB5_CALLCONV
krb5_clear_error_message(krb5_context ctx)
{
#ifdef DEBUG
    if (ERROR_MESSAGE_DEBUG())
        fprintf(stderr, "krb5_clear_error_message(%p)\n", ctx);
#endif
    if (ctx == NULL)
        return;
    k5_clear_error(&ctx->err);
}

void
k5_save_ctx_error(krb5_context ctx, krb5_error_code code, struct errinfo *out)
{
    out->code = code;
    out->msg = NULL;
    if (ctx != NULL && ctx->err.code == code) {
        out->msg = ctx->err.msg;
        ctx->err.code = 0;
        ctx->err.msg = NULL;
    }
}

krb5_error_code
k5_restore_ctx_error(krb5_context ctx, struct errinfo *in)
{
    krb5_error_code code = in->code;

    if (ctx != NULL) {
        k5_clear_error(&ctx->err);
        ctx->err.code = in->code;
        ctx->err.msg = in->msg;
        in->msg = NULL;
    } else {
        k5_clear_error(in);
    }
    return code;
}
