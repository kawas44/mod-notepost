/*
 * ModNotePost for Apache 2.x
 * Copyright (c) 2012 kawas44 [kawas44 @ gmail . com]
 *
 * File: mod_notepost.c
 * Version: 1.0.00
 * Date creation: 2012/02/16
 *
 *
 * ---------------------------------------------------------------------------
 * COMPILATION
 * ---------------------------------------------------------------------------
 *   apxs -c -i mod_notepost.c
 *
 * ---------------------------------------------------------------------------
 * HTTPD CONFIGURATION
 * ---------------------------------------------------------------------------
 *   LoadModule notepost_module modules/mod_notepost.so
 *   <IfModule notepost_module>
 *       NoteMaxSize 1024
 *       SetInputFilter NOTEPOST_FILTER
 *   </IfModule>
 *
 *   LogFormat "%{NOTEPOST_DATA}n"
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "util_filter.h"


module AP_MODULE_DECLARE_DATA notepost_module;


#define DEFAULT_NOTE_MAX_SIZE 1024
#define NOTE_POST_DATA "NOTEPOST_DATA"

/* Module configuration structure */
typedef struct notepost_cfg_t_ {
    apr_size_t note_max_size;
} notepost_cfg_t;

/* Module filter context */
typedef struct notepost_ctx_t_ {
    char *buffer;
    apr_size_t buf_max_size;
    apr_size_t buf_size;
    apr_size_t buf_free_size;
} notepost_ctx_t;


/* Create per-server configuration */
static void *notepost_init_srv_config(apr_pool_t *p, server_rec *s)
{
    notepost_cfg_t *newcfg =
            (notepost_cfg_t *) apr_pcalloc(p, sizeof(notepost_cfg_t));

    newcfg->note_max_size = DEFAULT_NOTE_MAX_SIZE;

    return (void *) newcfg;
}

/* Set note max size configuration */
static const char *notepost_set_note_max_size(
        cmd_parms *parms, void *mconfig, const char *arg)
{
    notepost_cfg_t *cfg =
            (notepost_cfg_t *) ap_get_module_config(
                                    parms->server->module_config,
                                    &notepost_module);

    apr_size_t sz = (apr_size_t) atol(arg);
    if (sz > 0)
    {
        cfg->note_max_size = sz;
    }

    return NULL;
}

/* Test if request can be processed */
static apr_size_t is_valid_request(request_rec *r)
{
    // work only on initial POST request
    if (r == NULL || !ap_is_initial_req(r) || r->method_number != M_POST)
    {
        return 0;
    }

    // work only on form urlencoded data or plain text
    char *cont_type = (char *) apr_table_get(r->headers_in, "Content-Type");
    if (cont_type == NULL ||
        (strcmp(cont_type, "application/x-www-form-urlencoded") != 0 &&
            strncmp(cont_type, "text/", 5) != 0))
    {
        return 0;
    }

    // work only if content length is set
    char *cont_len = (char *) apr_table_get(r->headers_in, "Content-Length");
    if (cont_len == NULL)
    {
        return 0;
    }
    return (apr_size_t) atol(cont_len);
}


/* Filter POST data and save first few bytes in note */
static apr_status_t notepost_in_filter(
        ap_filter_t *f, apr_bucket_brigade *bb,
        ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    request_rec *r = f->r;
    notepost_ctx_t *ctx = f->ctx;
    notepost_cfg_t *cfg;
    apr_status_t rv;
    apr_bucket *b;
    int is_eos = 0;

    // make sure filter's persitent context is not null
    if (!ctx)
    {
        apr_size_t cont_len;
        apr_size_t cont_max_len;

        // validate request for filtering
        cont_len = is_valid_request(r);
        if (!cont_len)
        {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "Ignore request");
            ap_remove_input_filter(f);
            return ap_get_brigade(f->next, bb, mode, block, readbytes);
        }

        // get module configuration
        cfg = (notepost_cfg_t *) ap_get_module_config(
                                    r->server->module_config,
                                    &notepost_module);
        cont_max_len = cfg->note_max_size;

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "Allocate context cfg_max=%lu  req_len=%lu",
                (unsigned long) cont_max_len, (unsigned long) cont_len);

        ctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(notepost_ctx_t));
        ctx->buf_max_size =
            (cont_len <= cont_max_len) ? cont_len : cont_max_len;
        ctx->buf_free_size = ctx->buf_max_size;
        ctx->buf_size = 0;
        ctx->buffer = apr_pcalloc(r->pool, ctx->buf_max_size + 1);
    }

    // get brigade from next filter
    rv = ap_get_brigade(f->next, bb, mode, block, readbytes);
    if (rv != APR_SUCCESS)
    {
        return rv;
    }

    // loop over stream of buckets
    for (b = APR_BRIGADE_FIRST(bb);
            b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
    {
        const char *data;
        apr_size_t len;
        apr_size_t to_copy;

        // remember end of stream
        if (APR_BUCKET_IS_EOS(b))
        {
            is_eos = 1;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "Found EOS");
            break;
        }

        // ignore metadata buckets
        if (APR_BUCKET_IS_METADATA(b))
            continue;

        // stop if buffer is full
        if (ctx->buf_free_size <= 0)
        {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "Buffer is full");
            break;
        }

        // read data bucket
        rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS)
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                    "Failed to read bucket");
            return rv;
        }

        // copy enough data in buffer
        to_copy = len;
        if (to_copy > ctx->buf_free_size)
        {
            to_copy = ctx->buf_free_size;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "Read %lu bytes - Copy %lu bytes",
                    (unsigned long) len, (unsigned long) to_copy);

        memcpy(ctx->buffer + ctx->buf_size, data, to_copy);
        ctx->buf_size += to_copy;
        ctx->buf_free_size -= to_copy;
    }

    // test if filter's job is done
    if (is_eos || ctx->buf_free_size <= 0)
    {
        // end buffer string
        ctx->buffer[ctx->buf_size] = '\0';
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "Data sz=%lu, str=%s",
                    (unsigned long) ctx->buf_size, ctx->buffer);

        // save note
        apr_table_setn(r->notes, NOTE_POST_DATA, ctx->buffer);

        // remove filter from chain
        ap_remove_input_filter(f);
    }

    return APR_SUCCESS;
}


/**
 *   Define configuration directives
 */
static const command_rec notepost_cmds[] = {
    AP_INIT_TAKE1(
        "NoteMaxSize",
        notepost_set_note_max_size,
        NULL,
        RSRC_CONF,
        "Set note max size"
    ),
    { NULL }
};

/**
 *   Register hook functions
 */
static void notepost_register_hooks(apr_pool_t *p)
{
    ap_register_input_filter(
            "NOTEPOST_FILTER", notepost_in_filter, NULL, AP_FTYPE_RESOURCE);
}

/**
 *   Define module configuration, filters and hooks handlers
 */
module AP_MODULE_DECLARE_DATA notepost_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                      // create per-directory conf
    NULL,                      // merge per-directory conf
    notepost_init_srv_config,// create per-server conf
    NULL,                      // merge per-server conf
    notepost_cmds,           // conf directive handlers
    notepost_register_hooks  // hook handlers
};

