#include <sys/types.h>
#include <krb5.h>
#include <gssrpc/rpc.h>
#include <kdb.h>
#include "policy_db.h"
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <string.h>

static
bool_t xdr_nullstring(XDR *xdrs, char **objp)
{
     u_int size;

     if (xdrs->x_op == XDR_ENCODE) {
          if (*objp == NULL)
               size = 0;
          else
               size = strlen(*objp) + 1;
     }
     if (! xdr_u_int(xdrs, &size)) {
          return FALSE;
        }
     switch (xdrs->x_op) {
     case XDR_DECODE:
          if (size == 0) {
               *objp = NULL;
               return TRUE;
          } else if (*objp == NULL) {
               *objp = (char *) mem_alloc(size);
               if (*objp == NULL) {
                    errno = ENOMEM;
                    return FALSE;
               }
          }
          return (xdr_opaque(xdrs, *objp, size));

     case XDR_ENCODE:
          if (size != 0)
               return (xdr_opaque(xdrs, *objp, size));
          return TRUE;

     case XDR_FREE:
          if (*objp != NULL)
               mem_free(*objp, size);
          *objp = NULL;
          return TRUE;
     }

     return FALSE;
}

static
bool_t xdr_krb5_tl_data(XDR *xdrs, krb5_tl_data **tl_data_head)
{
     krb5_tl_data *tl, *tl2;
     bool_t more;
     unsigned int len;

     switch (xdrs->x_op) {
     case XDR_FREE:
          tl = tl2 = *tl_data_head;
          while (tl) {
               tl2 = tl->tl_data_next;
               free(tl->tl_data_contents);
               free(tl);
               tl = tl2;
          }
          break;

     case XDR_ENCODE:
          tl = *tl_data_head;
          while (1) {
               more = (tl != NULL);
               if (!xdr_bool(xdrs, &more))
                    return FALSE;
               if (tl == NULL)
                    break;
               if (!xdr_short(xdrs, &tl->tl_data_type))
                    return FALSE;
               len = tl->tl_data_length;
               if (!xdr_bytes(xdrs, (char **) &tl->tl_data_contents, &len, ~0))
                    return FALSE;
               tl = tl->tl_data_next;
          }
          break;

     case XDR_DECODE:
          tl = NULL;
          while (1) {
               if (!xdr_bool(xdrs, &more))
                    return FALSE;
               if (more == FALSE)
                    break;
               tl2 = (krb5_tl_data *) malloc(sizeof(krb5_tl_data));
               if (tl2 == NULL)
                    return FALSE;
               memset(tl2, 0, sizeof(krb5_tl_data));
               if (!xdr_short(xdrs, &tl2->tl_data_type))
                    return FALSE;
               if (!xdr_bytes(xdrs, (char **)&tl2->tl_data_contents, &len, ~0))
                    return FALSE;
               tl2->tl_data_length = len;

               tl2->tl_data_next = tl;
               tl = tl2;
          }

          *tl_data_head = tl;
          break;
     }

     return TRUE;
}

static
bool_t xdr_nulltype(XDR *xdrs, void **objp, xdrproc_t proc)
{
     bool_t null;

     switch (xdrs->x_op) {
     case XDR_DECODE:
          if (!xdr_bool(xdrs, &null))
              return FALSE;
          if (null) {
               *objp = NULL;
               return TRUE;
          }
          return (*proc)(xdrs, objp);

     case XDR_ENCODE:
          if (*objp == NULL)
               null = TRUE;
          else
               null = FALSE;
          if (!xdr_bool(xdrs, &null))
               return FALSE;
          if (null == FALSE)
               return (*proc)(xdrs, objp);
          return TRUE;

     case XDR_FREE:
          if (*objp)
               return (*proc)(xdrs, objp);
          return TRUE;
     }

     return FALSE;
}

static int
osa_policy_min_vers(osa_policy_ent_t objp)
{
    if (objp->attributes ||
        objp->max_life ||
        objp->max_renewable_life ||
        objp->keygen_enctypes ||
        objp->n_tl_data)
        return OSA_ADB_POLICY_VERSION_3;

    if (objp->pw_max_fail ||
        objp->pw_failcnt_interval ||
        objp->pw_lockout_duration)
        return OSA_ADB_POLICY_VERSION_2;

    return OSA_ADB_POLICY_VERSION_1;
}

bool_t
xdr_osa_policy_ent_rec(XDR *xdrs, osa_policy_ent_t objp)
{
    switch (xdrs->x_op) {
    case XDR_ENCODE:
	 objp->version = osa_policy_min_vers(objp);
	 /* fall through */
    case XDR_FREE:
	 if (!xdr_int(xdrs, &objp->version))
	      return FALSE;
	 break;
    case XDR_DECODE:
	 if (!xdr_int(xdrs, &objp->version))
	      return FALSE;
	 if (objp->version != OSA_ADB_POLICY_VERSION_1 &&
             objp->version != OSA_ADB_POLICY_VERSION_2)
	      return FALSE;
	 break;
    }

    if(!xdr_nullstring(xdrs, &objp->name))
	return (FALSE);
    if (!xdr_u_int32(xdrs, &objp->pw_min_life))
	return (FALSE);
    if (!xdr_u_int32(xdrs, &objp->pw_max_life))
	return (FALSE);
    if (!xdr_u_int32(xdrs, &objp->pw_min_length))
	return (FALSE);
    if (!xdr_u_int32(xdrs, &objp->pw_min_classes))
	return (FALSE);
    if (!xdr_u_int32(xdrs, &objp->pw_history_num))
	return (FALSE);
    if (!xdr_u_int32(xdrs, &objp->policy_refcnt))
	return (FALSE);
    if (objp->version > OSA_ADB_POLICY_VERSION_1) {
        if (!xdr_u_int32(xdrs, &objp->pw_max_fail))
	    return (FALSE);
        if (!xdr_u_int32(xdrs, &objp->pw_failcnt_interval))
	    return (FALSE);
        if (!xdr_u_int32(xdrs, &objp->pw_lockout_duration))
	    return (FALSE);
    }
    if (objp->version > OSA_ADB_POLICY_VERSION_2) {
        if (!xdr_u_int32(xdrs, &objp->attributes))
	    return (FALSE);
        if (!xdr_u_int32(xdrs, &objp->max_life))
	    return (FALSE);
        if (!xdr_u_int32(xdrs, &objp->max_renewable_life))
	    return (FALSE);
        if (!xdr_string(xdrs, &objp->keygen_enctypes, 256))
	    return (FALSE);
        if (!xdr_short(xdrs, &objp->n_tl_data))
            return (FALSE);
        if (!xdr_nulltype(xdrs, (void **) &objp->tl_data,
                          xdr_krb5_tl_data))
            return FALSE;
    }
    return (TRUE);
}

