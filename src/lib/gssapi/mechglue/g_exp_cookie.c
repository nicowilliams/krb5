/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* src/lib/gssapi/mechglue/g_exp_cookie.c - */
/*
 * Copyright (C) 2016 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * glue routine for gss_export_sec_context_cookie()
 */

#ifndef LEAN_CLIENT

#include "mglueP.h"
#include <stdio.h>
#include <errno.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>

static OM_uint32
val_exp_sec_ctx_args(OM_uint32 *minor_status,
                     gss_ctx_id_t *context_handle,
                     uint64_t req_flags,
                     gss_buffer_t cookie)
{
    /* Initialize outputs. */
    if (minor_status != NULL)
        *minor_status = 0;
    
    if (cookie != GSS_C_NO_BUFFER) {
        cookie->length = 0;
        cookie->value = NULL;
    }

    /* Validate arguments. */
    if (minor_status == NULL)
        return (GSS_S_CALL_INACCESSIBLE_WRITE);

    if (context_handle == NULL || *context_handle == GSS_C_NO_CONTEXT)
        return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT);

    if (req_flags < GSS_SEC_CTX_EXPORT_FIRST_FLAG ||
        req_flags > GSS_SEC_CTX_EXPORT_LAST_FLAG * 2 - 1)
        return (GSS_S_FAILURE); /* XXX Need GSS_S_BAD_FLAGS or
                                   GSS_S_UNSUPPORTED */

    if (cookie == GSS_C_NO_BUFFER)
        return (GSS_S_CALL_INACCESSIBLE_WRITE);

    return (GSS_S_COMPLETE);
}


OM_uint32 KRB5_CALLCONV
gss_export_sec_context_cookie(OM_uint32 *minor_status,
                              gss_ctx_id_t context_handle,
                              uint64_t req_flags,
                              OM_uint32 lifetime_req,
                              uint64_t *ret_flags,
                              gss_buffer_t output_token)
{
    OM_uint32 maj, min;
    OM_uint32 length;
    gss_union_ctx_id_t ctx = NULL;
    gss_mechanism mech;
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
    char *buf;

    maj = val_exp_sec_ctx_args(minor_status, context_handle,
                                  output_token);
    if (maj != GSS_S_COMPLETE)
        return (maj);

    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */
    ctx = (gss_union_ctx_id_t)*context_handle;
    mech = gssint_get_mechanism(ctx->mech_type);
    if (mech == NULL)
        return GSS_S_BAD_MECH;
    if (mech->gss_export_sec_context_cookie == NULL)
        return (GSS_S_UNAVAILABLE);

    maj = mech->gss_export_sec_context_cookie(minor_status,
                                              &ctx->internal_ctx_id,
                                              req_flags,
                                              lifetime_req,
                                              ret_flags,
                                              &token);
    if (maj != GSS_S_COMPLETE) {
        map_error(minor_status, mech);
        goto cleanup;
    }

    length = token.length + 4 + ctx->mech_type->length;
    output_token->length = length;
    output_token->value = malloc(length);
    if (output_token->value == 0) {
        *minor_status = ENOMEM;
        maj = GSS_S_FAILURE;
        goto cleanup;
    }
    buf = output_token->value;
    length = ctx->mech_type->length;
    buf[3] = (unsigned char) (length & 0xFF);
    length >>= 8;
    buf[2] = (unsigned char) (length & 0xFF);
    length >>= 8;
    buf[1] = (unsigned char) (length & 0xFF);
    length >>= 8;
    buf[0] = (unsigned char) (length & 0xFF);
    memcpy(buf+4, ctx->mech_type->elements, (size_t) ctx->mech_type->length);
    memcpy(buf+4+ctx->mech_type->length, token.value, token.length);

    maj = GSS_S_COMPLETE;

cleanup:
    (void) gss_release_buffer(&min, &token);
    if (ctx != NULL && ctx->internal_ctx_id == GSS_C_NO_CONTEXT) {
        /* If the mech deleted its context, delete the union context. */
        free(ctx->mech_type->elements);
        free(ctx->mech_type);
        free(ctx);
        *context_handle = GSS_C_NO_CONTEXT;
    }
    return maj;
}
#endif /*LEAN_CLIENT */
