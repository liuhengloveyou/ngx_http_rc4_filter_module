#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/rc4.h>

typedef struct {
	ngx_flag_t                enable;
	size_t                    buff_size;
	ngx_http_complex_value_t *rc4_key_str;
} ngx_http_rc4_filter_conf_t;

typedef struct {
	RC4_KEY       *rc4_key;
	ngx_buf_t     *buff;
} ngx_http_rc4_filter_ctx_t;

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

ngx_module_t  ngx_http_rc4_filter_module;

static void rc4(RC4_KEY *key, ngx_buf_t *buf, ngx_buf_t *tbuf, size_t tsize)
{
	size_t len = 0;
	int p = 0;

	size_t bsize = ngx_buf_size(buf);
	if (bsize <= 0) {
		return;
	}

	while (buf->pos + p < buf->last) {
		len = (bsize > tsize) ? tsize : bsize;

		RC4(key, len, buf->pos + p, tbuf->pos);
		ngx_memcpy(buf->pos + p, tbuf->pos, len);

		bsize -= len;
		p += len;
	}
}

static ngx_int_t ngx_http_rc4_header_filter(ngx_http_request_t *r)
{
	ngx_http_rc4_filter_conf_t *conf;
	ngx_http_rc4_filter_ctx_t *ctx;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_rc4_filter_module);

	if (r != r->main || r->headers_out.status != NGX_HTTP_OK || r->header_only
	    || conf->enable == 0
	    || NULL == conf->rc4_key_str)
	{
		return ngx_http_next_header_filter(r);
	}

	if (NULL == conf->rc4_key_str->value.data) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "rc4_key must not be NULL");
		conf->enable = 0;
		return NGX_ERROR;
	}

	ctx = ngx_http_get_module_ctx(r, ngx_http_rc4_filter_module);
	if (ctx == NULL) {
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_rc4_filter_ctx_t));
		if (ctx == NULL) {
			return NGX_ERROR;
		}

		ngx_http_set_ctx(r, ctx, ngx_http_rc4_filter_module);

		ctx->rc4_key = (RC4_KEY *)ngx_pcalloc(r->pool, sizeof(RC4_KEY));
		if (NULL == ctx->rc4_key) {
			return NGX_ERROR;
		}
		RC4_set_key(ctx->rc4_key, conf->rc4_key_str->value.len, conf->rc4_key_str->value.data);
	}

	return ngx_http_next_header_filter(r);
}

static ngx_int_t ngx_http_rc4_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	ngx_chain_t                *cl;
	ngx_http_rc4_filter_conf_t *conf;
	ngx_http_rc4_filter_ctx_t *ctx;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_rc4_filter_module);
	if (conf->enable == 0) {
		return ngx_http_next_header_filter(r);
	}

	ctx = ngx_http_get_module_ctx(r, ngx_http_rc4_filter_module);
	if (ctx == NULL || r->header_only) {
		return ngx_http_next_body_filter(r, in);
	}

	if (NULL == ctx->buff) {
		ctx->buff = ngx_create_temp_buf(r->pool, conf->buff_size);
		if (NULL == ctx->buff) {
			return NGX_ERROR;
		}
	}

	for (cl = in; cl; cl = cl->next) {
		rc4(ctx->rc4_key, in->buf, ctx->buff, conf->buff_size);
	}

	return ngx_http_next_body_filter(r, in);
}


static char *ngx_http_rc4_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_rc4_filter_conf_t *prev = parent;
	ngx_http_rc4_filter_conf_t *conf = child;

	ngx_conf_merge_value(conf->enable, prev->enable, 0);
	ngx_conf_merge_size_value(conf->buff_size, prev->buff_size, 512);

	if (conf->rc4_key_str == NULL) {
		conf->rc4_key_str = prev->rc4_key_str;
	}

	return NGX_CONF_OK;
}

static void *ngx_http_rc4_filter_create_conf(ngx_conf_t *cf)
{
	ngx_http_rc4_filter_conf_t *conf;

	conf = (ngx_http_rc4_filter_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_rc4_filter_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	conf->enable = NGX_CONF_UNSET;
	conf->buff_size = NGX_CONF_UNSET_SIZE;

	return conf;
}

static ngx_int_t ngx_http_rc4_filter_init(ngx_conf_t *cf)
{
	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_rc4_header_filter;

	ngx_http_next_body_filter = ngx_http_top_body_filter;
	ngx_http_top_body_filter = ngx_http_rc4_body_filter;

	return NGX_OK;
}

static ngx_command_t  ngx_http_rc4_commands[] = {

	{ ngx_string("rc4_body"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_rc4_filter_conf_t, enable),
	  NULL },
	{ ngx_string("rc4_key"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_http_set_complex_value_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_rc4_filter_conf_t, rc4_key_str),
	  NULL },
	{ ngx_string("rc4_buff_size"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_size_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_rc4_filter_conf_t, buff_size),
      NULL },

	ngx_null_command
};

static ngx_http_module_t ngx_http_rc4_filter_module_ctx = {
	NULL,                                  /* preconfiguration */
	ngx_http_rc4_filter_init,              /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_http_rc4_filter_create_conf,       /* create location configuration */
	ngx_http_rc4_filter_merge_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_rc4_filter_module = {
	NGX_MODULE_V1,
	&ngx_http_rc4_filter_module_ctx,       /* module context */
	ngx_http_rc4_commands,                 /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};
