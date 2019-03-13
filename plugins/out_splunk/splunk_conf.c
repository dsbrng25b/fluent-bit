/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_utils.h>

#include "splunk.h"
#include "splunk_conf.h"

struct flb_splunk *flb_splunk_conf_create(struct flb_output_instance *ins,
                                          struct flb_config *config)
{
    int io_flags = 0;
    char *tmp;
    flb_sds_t t;
    struct flb_config_prop *prop;
    struct mk_list *head;
    struct mk_list *split;
    struct flb_split_entry *sentry;
    struct flb_upstream *upstream;
    struct flb_splunk *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_splunk));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Get network configuration */
    if (!ins->host.name) {
        ins->host.name = flb_strdup(FLB_SPLUNK_DEFAULT_HOST);
    }

    if (ins->host.port == 0) {
        ins->host.port = FLB_SPLUNK_DEFAULT_PORT;
    }

    /* use TLS ? */
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags,
                                   &ins->tls);
    if (!upstream) {
        flb_error("[out_splunk] cannot create Upstream context");
        flb_splunk_conf_destroy(ctx);
        return NULL;
    }

    /* Set manual Index and Type */
    ctx->u = upstream;

    /* Splunk Auth Token */
    tmp = flb_output_get_property("splunk_token", ins);
    if (tmp) {
        ctx->auth_header = flb_sds_create("Splunk ");
        t = flb_sds_cat(ctx->auth_header, tmp, strlen(tmp));
        if (t) {
            ctx->auth_header = t;
        }
        else {
            flb_error("[out_splunk] error on token generation");
            flb_splunk_conf_destroy(ctx);
            return NULL;
        }
    }
    else {
        flb_error("[out_splunk] no splunk_token configuration key defined");
        flb_splunk_conf_destroy(ctx);
        return NULL;
    }

    /* HTTP Auth */
    tmp = flb_output_get_property("http_user", ins);
    if (tmp && ctx->auth_header) {
        flb_error("[out_splunk] splunk_token and http_user cannot be used at"
                  " the same time");
        flb_splunk_conf_destroy(ctx);
        return NULL;
    }
    if (tmp) {
        ctx->http_user = flb_strdup(tmp);
        tmp = flb_output_get_property("http_passwd", ins);
        if (tmp) {
            ctx->http_passwd = flb_strdup(tmp);
        }
        else {
            ctx->http_passwd = flb_strdup("");
        }
    }

    /* Event format, send all fields or pack into event map */
    tmp = flb_output_get_property("splunk_send_raw", ins);
    if (tmp) {
        ctx->splunk_send_raw = flb_utils_bool(tmp);
    }
    else {
        ctx->splunk_send_raw = FLB_FALSE;
    }

    /* Splunk meta data */
    tmp = flb_output_get_property("add_meta", ins);
    if (tmp) {
	    mk_list_init(&ctx->splunk_meta);
    }
    mk_list_foreach(head, &ins->properties) {
        prop = mk_list_entry(head, struct flb_config_prop, _head);
        if (strncasecmp(prop->key, "add_meta", 8) == 0) {
            split = flb_utils_split(prop->val, ' ', 2);
	    if (mk_list_size(split) != 2) {
                flb_error("[out_splunk] add_meta needs to argments");
                flb_utils_split_free(split);
                flb_splunk_conf_destroy(ctx);
                return NULL;
	    }
	    struct flb_config_prop *meta_prop;
	    meta_prop = flb_calloc(1, sizeof(struct flb_config_prop));

	    sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
	    meta_prop->key = sentry->value;

	    sentry = mk_list_entry_next(&sentry->_head, struct flb_split_entry, _head, split);
	    meta_prop->val = sentry->value;

	    mk_list_add(&meta_prop->_head, &ctx->splunk_meta);

        }
    }

    return ctx;
}


int flb_splunk_conf_destroy(struct flb_splunk *ctx)
{
    if (!ctx) {
        return -1;
    }

    if (ctx->auth_header) {
        flb_sds_destroy(ctx->auth_header);
    }
    if (ctx->http_user) {
        flb_free(ctx->http_user);
    }
    if (ctx->http_passwd) {
        flb_free(ctx->http_passwd);
    }
    flb_upstream_destroy(ctx->u);
    flb_free(ctx);

    return 0;
}
