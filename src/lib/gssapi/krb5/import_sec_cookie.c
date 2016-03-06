/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/gssapi/krb5/import_sec_context.c - Internalize the security context cookies */
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
 * Import a security context from a cookie made by
 * krb5_gss_export_sec_context_cookie().
 *
 * The fundamental difference between an exported security context token
 * and an exported security context cookie, is that cookies support
 * partial content, encryption of the cookie, and always include a MAC.
 *
 * Also, we try to make cookies small.
 */

#include "gssapiP_krb5.h"
/* for serialization initialization functions */
#include "k5-int.h"

/* Variant of krb5_gss_convert_static_mech_oid that doesn't release oid */
static int
convert_static_mech_oid(gss_OID oid)
{
    const gss_OID_desc      *p;
    OM_uint32               minor_status;

    for (p = krb5_gss_oid_array; p->length; p++) {
        if ((oid->length == p->length) &&
            (memcmp(oid->elements, p->elements, p->length) == 0)) {
            *oid = *p;
            return 1;
        }
    }
    return 0;
}

/*
 * Based on the standard hash function DJB2, by DJB.
 *
 * Note that this does not deal in C strings; embedded NULs are skipped.  Also,
 * if s == NULL then a little-endian encoding of `n' is used as the string.
 */
static unsigned int
hash_djb2(unsigned int hash, unsigned char *s, size_t len, uintmax_t n)
{
    size_t i;
    unsigned char bytes[sizeof(n)];

    if (s == NULL) {
        /*
         * This is probably overwrought.  We could just cast &n as an unsigned
         * char *.  We probably won't have heterogeneous endianness clusters.
         * Still, it's OK.
         */
        for (i = 0; i < sizeof(n); i++) {
            bytes[i] = n & 0xFF;
            n >>= CHAR_BIT;
        }
        s = bytes;
        len = sizeof(bytes);
    }

    for (i = 0, hash = ((hash == 0) ? 5381 : hash); i < len; s++, i++)
        if (*s != 0)
            hash = ((hash << 5) + hash) + *s;
    return hash;
}

static inline krb5_error_code
decode_uint(krb5_octet **pp, size_t *lenp, uintmax_t *out, size_t max)
{
    uintmax_t n;
    krb5_octet *p = *pp;
    krb5_octet c;
    size_t len = *lenp;
    size_t i;

    for (i = 0, n = 0, c = 0x80; i < max; i++)
        n = (n << 7) + ((c = *p++) & 0x7f);
    *lenp -= i;
    *out = n;
    *pp = p;
    return ((c & 0x80)) ? EOVERFLOW : 0;
}

/* XXX Move this elsewhere for DRY */
#define COOKIE_EPOCH 1451606400 /* 2016-01-01T00:00:00Z */

static krb5_error_code
parse_cookie(krb5_context context, krb5_gss_ctx_id_t ctx,
             krb5_boolean was_encrypted, krb5_principal svc_princ,
             krb5_octet *p, size_t len, uint64_t *ret_flags)
{
    krb5_error_code ret;
    krb5_timestamp exp = 0;     /* Cookie expiration time */
    krb5_timestamp now;
    size_t icnlen = 0;          /* Length of initiator composite name */

    /* Error codes are fixed upstairs */

    ctx->initiate = 0;
    ctx->established = 0;
    ctx->have_acceptor_subkey = 0;
    ctx->seed_init = 0;
    ctx->terminated = 0;
    ctx->gss_flags = 0;

    /*
     * Expiration time: variable length integer counting 120s units since
     * 2016-01-01T00.
     */
    ret = decode_uint(&p, &len, &n, sizeof(exp));
    if (ret)
        return ret;
    exp = COOKIE_EPOCH + n * 120;
    if (exp != (uintmax_t)(COOKIE_EPOCH + n * 120))
        return EINVAL;
    ret = krb5_timeofday(context, &now);
    if (ret)
        return ret;
    if (now >= exp)
        return KRB_AP_ERR_TKT_EXPIRED;

    /* Security context flags */
    ret = decode_uint(&p, &len, &n, sizeof(&ctx->gss_flags));
    if (ret)
        return ret;
    ctx->gss_flags = n;

    /* Content flags: variable length integer bit string. */
    ret = decode_uint(&p, &len, &n, sizeof(*ret_flags));
    if (ret)
        return ret;
    *ret_flags = n;

    if ((*ret_flags & GSS_SEC_CTX_EXPORT_INITIATOR_NAME_FLAG)) {
        size_t plen = 0;
        size_t common_suffix_labels;
        char *pstr = NULL;

        ret = decode_uint(&p, &len, &n, sizeof(plen));
        if (ret)
            return ret;
        plen = n;
        if (len < plen)
            return EINVAL;
        pstr = p;
        p += plen;
        len -= plen;

        if (len < 1)
            return EINVAL;
        common_suffix_labels = *p;
        len--;
        /* XXX FINISH fixup the princ name, set ctx->there */
        ret = fixup_initiator_name(context, ctx, svc_princ, pstr, plen,
                                   common_suffix_labels);
        if (ret)
            return ret;
    }

    if ((*ret_flags & GSS_SEC_CTX_EXPORT_INITIATOR_NAME_COMPOSITE_FLAG)) {
        /*
         * Currently not supported here; this should be a Ticket that we can
         * use to recover authorization data -and other things- from.
         *
         * Also, this could really be the plaintext of the Ticket's enc-part
         * IFF the cookie was encrypted.
         */
        ret = decode_uint(&p, &len, &n, sizeof(n));
        if (ret)
            return ret;
    }

    /* There's nothing to do for LOCAL_NAME and LOCAL_NAME_COMPOSITE. */
    /* XXX Make ctx->here == svc_princ */

    if ((*ret_flags & GSS_SEC_CTX_EXPORT_IS_OPEN_FLAG))
        ctx->established = 1;

    if ((*ret_flags & GSS_SEC_CTX_EXPORT_SEQUENCE_STATE)) {
        uint64_t base, next, mask;
        ret = decode_uint(&p, &len, &base, sizeof(base));
        if (ret == 0)
            ret = decode_uint(&p, &len, &next, sizeof(next));
        if (ret == 0)
            ret = decode_uint(&p, &len, &mask, sizeof(mask));
        if (ret)
            return ret;
        /*
         * XXX Initialize sequence number window state in ctx with
         * base/next/mask.
         *
         * This will require adding a constructor to util_seqstate.c.
         */
    }
}

/*
 * Produce a key ID hash of a keytab entry.
 *
 * The following things are hashed:
 *
 *  - the number of components of the keytab entry's principal
 *  - each component of the keytab entry's principal, followed by "/"
 *  - "@" then the keytab entry's principal's realm
 *  - the keytab entry's kvno
 *  - the keytab entry's enctype
 */
unsigned int
krb5int_gss_kte2keyid(krb5_context context, krb5_keytab_entry *kte)
{
    unsigned int hash = 0;
    krb5_data d;
    size_t i;

    hash = hash_djb2(hash, NULL, 0, krb5_princ_size(context, kte->principal));
    for (i = 0; i < krb5_princ_size(context, kte->principal); i++) {
        d = krb5_princ_component(context, kte->principal, i);
        hash = hash_djb2(hash, d.data, d.length);
        hash = hash_djb2(hash, "/", sizeof("/") - 1);
    }
    hash = hash_djb2(hash, "@", sizeof("@") - 1);
    d = krb5_princ_realm(context, kte->principal);
    hash = hash_djb2(hash, d.data, d.length);
    hash = hash_djb2(hash, NULL, len, (uintmax_t)kte->vno);
    hash = hash_djb2(hash, NULL, 0, (uintmax_t)kte->key.enctype);
}

static krb5_error_code
decrypt_cookie(krb5_context context, krb5_gss_ctx_id_t ctx,
               unsigned int keyid, krb5_octet *c, size_t len,
               uint64_t *ret_flags)
{
    krb5_error_code ret;
    krb5_keytab kt;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_principal princ;
    krb5_data ct, pt;

    ct.data = c;
    ct.length = len;

    if ((ret = krb5_kt_default(context, &kt)))
        return ret;

    if ((ret = krb5_kt_start_seq_get(context, kt, &cursor))) {
        krb5_kt_close(context, kt);
        return ret;
    }

    while ((ret = krb5_kt_next_entry(context, kt, &entry, &cursor)) == 0) {
        if (krb5int_gss_kte2keyid(context, entry) != keyid) {
            krb5_free_keytab_entry_contents(context, &entry);
            continue;
        }
        if ((ret = krb5_k_decrypt(context, entry.key, XXX_KEYUSAGE, NULL,
                                  ct, &pt))) {
            krb5_free_keytab_entry_contents(context, &entry);
            continue;
        }
        princ = entry.principal;
        entry.principal = NULL;
        krb5_free_keytab_entry_contents(context, &entry);
        ret = 0;
        break;
    }
    (void) krb5_kt_end_seq_get(context, kt, &cursor);
    (void) krb5_kt_close(context, kt);
    if (ret == 0)
        ret = parse_cookie(context, ctx, TRUE, princ, p, len, ret_flags);
    return ret == KRB5_KT_END ? KRB5_KT_NOTFOUND : ret;
}

static krb5_error_code
validate_cookie_cksum(krb5_context context, krb5_gss_ctx_id_t ctx,
                      unsigned int keyid, krb5_octet *c, size_t len,
                      uint64_t *ret_flags)
{
    krb5_error_code ret;
    krb5_keytab kt;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_principal princ;
    krb5_cksumtype cksumtype;
    krb5_data cookie, their_cksum;
    krb5_checksum our_cksum;
    int is_valid = 0;

    if ((ret = krb5_kt_default(context, &kt)))
        return ret;

    if ((ret = krb5_kt_start_seq_get(context, kt, &cursor))) {
        krb5_kt_close(context, kt);
        return ret;
    }

    cookie.data = c;
    their_cksum.data = NULL;
    while ((ret = krb5_kt_next_entry(context, kt, &entry, &cursor)) == 0) {
        if (krb5int_gss_kte2keyid(context, entry) != keyid) {
            krb5_free_keytab_entry_contents(context, &entry);
            continue;
        }
        /* We always use the mandatory checksum type of the enctype used */
        ret = krb5int_c_mandatory_cksumtype(context, entry.key.enctype,
                                            &cksumtype);

        /*
         * The cookie does not have a length field to separate the checksum
         * from the payload.  The checksum goes at the end and is whatever size
         * is required by the mandatory checksum type of the enctype used.
         */
        if (ret == 0)
            ret = krb5_c_checksum_length(context, cksumtype, &their_cksum.length);
        if (ret == 0) {
            if (len < their_cksum.length)
                ret = KRB5_KT_NOTFOUND;
            else
                their_cksum.data = c + (len - their_cksum.length);
        }
        if (ret == 0) {
            /* Adjust the cookie length; compute the checksum */
            cookie.length = len - their_cksum.length;
            ret = krb5_k_make_checksum(context, 0, entry.key, XXX_KEYUSAGE,
                                       cookie, &our_cksum);
        }
        princ = entry.principal;
        entry.principal = NULL;
        krb5_free_keytab_entry_contents(context, &entry);

        /* Compare the two checksums for equality */
        if (ret == 0 && our_cksum.length == their_cksum.length)
            is_valid = (k5_bcmp(our_cksum.data, their_cksum.data,
                                their_cksum.length) == 0);
        krb5_free_data_contents(context, &our_cksum);
        if (is_valid)
            break;
    }
    (void) krb5_kt_end_seq_get(context, kt, &cursor);
    (void) krb5_kt_close(context, kt);

    /* If success (and only then) -> parse the cookie */
    if (ret == 0 && is_valid)
        ret = parse_cookie(context, ctx, FALSE, princ,
                           c, cookie.length, ret_flags);
    return ret == KRB5_KT_END ? KRB5_KT_NOTFOUND : ret;
}

OM_uint32 KRB5_CALLCONV
krb5_gss_import_sec_context_cookie(OM_uint32 *minor_status,
                                   gss_buffer_t cookie,
                                   gss_ctx_id_t *context_handle,
                                   uint64_t *ret_flags)
{
    krb5_context        context;
    krb5_error_code     kret = 0;
    OM_uint32           mech_len;
    OM_uint32           min;
    size_t              i;
    size_t              len;
    size_t              cksum_len = 0;
    uint32_t            keyid;
    krb5_gss_ctx_id_t   ctx;
    krb5_octet          *p, c;
    krb5_data           cksum;
    gss_OID             oid;
    int                 is_encrypted = 0;

    *minor_status = 0;
    *context_handle = GSS_C_NO_CONTEXT;
    *ret_flags = 0;

    cksum.data = NULL;
    cksum.length = 0;

    /*
     * Get the mechanism OID from the cookie.
     *
     * We use a variable-length encoding using 7 bits per-bytes, with the high
     * bit indicating whether the next byte is part of the length; MSB first.
     *
     * The first byte's next highest bit indicates whether the cookie payload
     * is encrypted (and it's not part of the mech OID length, naturally).
     *
     * Up to three bytes are used for the length, yielding 6 + 7 + 7 = 20 bits
     * of OID length, which should be plenty.
     *
     * This has to be replicated in the mechglue, and all the mechs.
     */
    if (cookie->length < 1)
        return GSS_S_DEFECTIVE_TOKEN;

    p = cookie->value;
    len = cookie->len;
    for (i = 0, mech_len = 0; i < 3; i++) {
        if (len < 1)
            return GSS_S_DEFECTIVE_TOKEN;
        c = *p++;
        len--;
        if (i == 0) {
            is_encrypted = (c & 0x40);
            c &= ~0x40;
        }
        mech_len = (mech_len << 7) | (c & 0x7F);
    }
    if ((c & 0x80))
        return GSS_S_DEFECTIVE_TOKEN;

    /* Validate the mech from the cookie */
    oid.elements = p;
    oid.length = mech_len;
    if (!convert_static_mech_oid(&oid))
        return GSS_S_BAD_MECH;

    p += mech_len;
    len -= mech_len;

    /*
     * We use a hash of the service principal name, kvno, enctype, to identify
     * the keytab entry we'll need to decrypt/verify the cookie.
     */
    if (len < 4)
        return GSS_S_DEFECTIVE_TOKEN;
    keyid = *p++;
    keyid = (keyid << CHAR_BIT) + *p++;
    keyid = (keyid << CHAR_BIT) + *p++;
    keyid = (keyid << CHAR_BIT) + *p++;
    len -= 4;

    if (!is_encrypted) {
        if (len < 2)
            return GSS_S_FAILURE;
        cksum.length = *p++;
        cksum.length = (cksum_len << CHAR_BIT) + *p++;
        len -= 2;
        
        if (len < cksum_len)
            return GSS_S_FAILURE;
        cksum.data = p;
        p += cksum.length;
        len -= cksum.length;
    }

    /* Now we have everything we need to start unmarshalling the contents */
    kret = krb5_gss_init_context(&context);
    if (kret) {
        *minor_status = kret;
        return GSS_S_FAILURE;
    }

    ctx = k5calloc(1, sizeof(*ctx), &kret);
    *minor_status = kret;
    if (ctx == NULL)
        return GSS_S_FAILURE;
    ctx->mech_used = krb5_gss_convert_static_mech_oid(ctx->mech_used);

    if (!is_encrypted) {
        krb5_data cookie;

        /* The cookie is only checksumed */
        cookie.data = p;
        cookie.length = len;
        kret = validate_cookie_cksum(context, keyid, cksum, p, len);
    } else {
        /* The rest of the cookie is encrypted */
        kret = decrypt_cookie(context, ctx, keyid, p, len, ret_flags);
    }

    *minor_status = kret;
    if (kret) {
        (void) krb5_gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
        return GSS_S_DEFECTIVE_TOKEN;
    }

    *context_handle = (gss_ctx_id_t)ctx;
    return (GSS_S_COMPLETE);
}
