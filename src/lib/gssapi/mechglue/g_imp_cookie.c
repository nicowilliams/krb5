/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* src/lib/gssapi/mechglue/g_imp_cookie.c - */
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
 *  glue routine gss_import_sec_context_cookie()
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
val_imp_sec_ctx_args(
    OM_uint32 *minor_status,
    gss_buffer_t cookie,
    gss_ctx_id_t *context_handle,
    uint64_t *ret_flags)
{

    /* Initialize outputs. */
    if (minor_status != NULL)
        *minor_status = 0;

    if (context_handle != NULL)
        *context_handle = GSS_C_NO_CONTEXT;

    if (ret_flags != NULL)
        *ret_flags = 0;

    /* Validate arguments. */
    if (minor_status == NULL)
        return (GSS_S_CALL_INACCESSIBLE_WRITE);

    if (context_handle == NULL)
        return (GSS_S_CALL_INACCESSIBLE_WRITE);

    if (cookie == GSS_C_NO_BUFFER)
        return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_DEFECTIVE_TOKEN);

    if (GSS_EMPTY_BUFFER(cookie))
        return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_DEFECTIVE_TOKEN);

    return (GSS_S_COMPLETE);
}


OM_uint32 KRB5_CALLCONV
gss_import_sec_context_cookie(OM_uint32 *minor_status,
                              gss_buffer_t cookie,
                              gss_ctx_id_t *context_handle,
                              uint64_t *ret_flags)
{
    OM_uint32           length = 0;
    OM_uint32           maj;
    char                *p;
    gss_union_ctx_id_t  ctx;
    gss_ctx_id_t        mctx;
    gss_buffer_desc     token;
    gss_OID_desc        token_mech;
    gss_OID             selected_mech = GSS_C_NO_OID;
    gss_mechanism       mech;

    maj = val_imp_sec_ctx_args(minor_status, cookie, context_handle);
    if (maj != GSS_S_COMPLETE)
        return (maj);

    maj = GSS_S_FAILURE;

    ctx = (gss_union_ctx_id_t) malloc(sizeof(gss_union_ctx_id_desc));
    if (!ctx)
        return (GSS_S_FAILURE);

    if (cookie->length >= sizeof (OM_uint32)) {
        p = cookie->value;
        length = (OM_uint32)*p++;
        length = (OM_uint32)(length << 8) + *p++;
        length = (OM_uint32)(length << 8) + *p++;
        length = (OM_uint32)(length << 8) + *p++;
    }

    if (length == 0 ||
        length > (cookie->length - sizeof (OM_uint32))) {
        free(ctx);
        return (GSS_S_CALL_BAD_STRUCTURE | GSS_S_DEFECTIVE_TOKEN);
    }

    token_mech.length = length;
    token_mech.elements = p;

    p += length;

    token.length = cookie->length - sizeof (OM_uint32) - length;
    token.value = p;

    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */

    maj = gssint_select_mech_type(minor_status, &token_mech,
                                     &selected_mech);
    if (maj != GSS_S_COMPLETE)
        goto error_out;

    mech = gssint_get_mechanism(selected_mech);
    if (!mech) {
        maj = GSS_S_BAD_MECH;
        goto error_out;
    }
    if (mech->gss_import_sec_context_cookie == NULL) {
        maj = GSS_S_UNAVAILABLE;
        goto error_out;
    }

    if (generic_gss_copy_oid(minor_status, selected_mech,
                             &ctx->mech_type) != GSS_S_COMPLETE) {
        maj = GSS_S_FAILURE;
        goto error_out;
    }

    maj = mech->gss_import_sec_context(minor_status, &cookie, &mctx);
    if (maj == GSS_S_COMPLETE) {
        ctx->internal_ctx_id = mctx;
        ctx->loopback = ctx;
        *context_handle = (gss_ctx_id_t)ctx;
        return (GSS_S_COMPLETE);
    }
    map_error(minor_status, mech);
    free(ctx->mech_type->elements);
    free(ctx->mech_type);

error_out:
    free(ctx);
    return maj;
}
#endif /* LEAN_CLIENT */
