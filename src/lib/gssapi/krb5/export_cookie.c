/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/gssapi/krb5/export_sec_context.c - Externalize a security context */
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
 * <<< Longer description of file >>>
 */

#include "gssapiP_krb5.h"
#ifndef LEAN_CLIENT
OM_uint32 KRB5_CALLCONV
krb5_gss_export_sec_context_cookie(OM_uint32 *minor_status,
                                   OM_uint32 context_handle,
                                   uint64_t req_flags,
                                   OM_uint32 liftime_req,
                                   uint64_t *ret_flags,
                                   gss_buffer_t cookie)
{
    krb5_context        context = NULL;
    krb5_error_code     kret;
    OM_uint32           retval;
    size_t              bufsize, blen;
    krb5_gss_ctx_id_t   ctx;
    krb5_octet          *obuffer, *obp;

    /* Assume a tragic failure */
    obuffer = (krb5_octet *) NULL;
    retval = GSS_S_FAILURE;
    *minor_status = 0;

    ctx = (krb5_gss_ctx_id_t) *context_handle;
    if (ctx->terminated) {
        *minor_status = KG_CTX_INCOMPLETE;
        return (GSS_S_NO_CONTEXT);
    }

    context = ctx->k5_context;
    kret = krb5_gss_ser_init(context);
    if (kret)
        goto error_out;

    /* Determine size needed for externalization of context */
    bufsize = 0;
    if ((kret = kg_ctx_size(context, (krb5_pointer) ctx,
                            &bufsize)))
        goto error_out;

    /* Allocate the buffer */
    if ((obuffer = gssalloc_malloc(bufsize)) == NULL) {
        kret = ENOMEM;
        goto error_out;
    }

    obp = obuffer;
    blen = bufsize;
    /* Externalize the context */
    if ((kret = kg_ctx_externalize(context,
                                   (krb5_pointer) ctx, &obp, &blen)))
        goto error_out;

    /* Success!  Return the buffer */
    cookie->length = bufsize - blen;
    cookie->value = obuffer;
    *minor_status = 0;
    retval = GSS_S_COMPLETE;

    /* Now, clean up the context state */
    (void)krb5_gss_delete_sec_context_cookie(minor_status, context_handle, NULL);
    *context_handle = GSS_C_NO_CONTEXT;

    return (GSS_S_COMPLETE);

error_out:
    if (retval != GSS_S_COMPLETE)
        if (kret != 0 && context != 0)
            save_error_info((OM_uint32)kret, context);
    if (obuffer && bufsize) {
        memset(obuffer, 0, bufsize);
        xfree(obuffer);
    }
    if (*minor_status == 0)
        *minor_status = (OM_uint32) kret;
    return(retval);
}
#endif /* LEAN_CLIENT */
