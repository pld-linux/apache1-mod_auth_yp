/*
 * Authenticates user names/passwords and
 * user names/groups through NIS (Yellow Pages).
 *
 * July 1999
 * Ian Prideaux
 */

/*
 * http_auth: authentication
 * 
 * Rob McCool
 * 
 * Adapted to Apache by rst.
 *
 * dirkx - Added Authoritative control to allow passing on to lower
 *         modules if and only if the user-id is not known to this
 *         module. A known user with a faulty or absent password still
 *         causes an AuthRequired. The default is 'Authoritative', i.e.
 *         no control is passed along.
 */

#include <rpc/rpc.h>
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yp_prot.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_md5.h"

typedef struct auth_yp_config_struct {
    char *auth_yp_domain;
    char *auth_yp_pwtable;
    char *auth_yp_grptable;
    int auth_yp_authoritative;
	int auth_yp;
} auth_yp_config_rec;

static void *create_auth_yp_dir_config(pool *p, char *d)
{
    auth_yp_config_rec *sec =
    (auth_yp_config_rec *) ap_pcalloc(p, sizeof(auth_yp_config_rec));
    sec->auth_yp_domain = NULL;
    sec->auth_yp_pwtable = NULL;	/* just to illustrate the default really */
    sec->auth_yp_grptable = NULL;	/* unless you have a broken HP cc */
    sec->auth_yp_authoritative = 1;	/* keep the fortress secure by default */
	sec->auth_yp = NULL;
    return sec;
}

static const char *set_auth_yp_slot(cmd_parms *cmd, void *offset, char *f, char *t)
{
if (t && strcmp(t, "standard"))
	return ap_pstrcat(cmd->pool, "Invalid auth file type: ", t, NULL);

return ap_set_file_slot(cmd, offset, f);
}

static const command_rec auth_yp_cmds[] =
{
	{"AuthYPDomain", set_auth_yp_slot,
	 (void *) XtOffsetOf(auth_yp_config_rec, auth_yp_domain), OR_AUTHCFG, TAKE1,
	 "NIS domain name"},
	{"AuthYPUserTable", set_auth_yp_slot,
	 (void *) XtOffsetOf(auth_yp_config_rec, auth_yp_pwtable), OR_AUTHCFG, TAKE1,
	 "NIS table containing user IDs and passwords"},
	{"AuthYPGroupTable", set_auth_yp_slot,
	 (void *) XtOffsetOf(auth_yp_config_rec, auth_yp_grptable), OR_AUTHCFG, TAKE1,
	 "NIS table containing group names and member user IDs"},
	{"AuthYPAuthoritative", ap_set_flag_slot,
	 (void *) XtOffsetOf(auth_yp_config_rec, auth_yp_authoritative),
	 OR_AUTHCFG, FLAG,
	 "Set to 'no' to allow access control to be passed along to lower modules if the UserID is not known to this module"},
	{"AuthYP", ap_set_flag_slot,
	 (void*)XtOffsetOf(auth_yp_config_rec, auth_yp), OR_AUTHCFG, FLAG,
	 "Authenticate user using yp (nis)"},
	{NULL}
};

module MODULE_VAR_EXPORT auth_yp_module;

static char *get_yp_domain(request_rec *r, char *auth_yp_domain)
{
char *domainname;
int err;

if(auth_yp_domain)	return(auth_yp_domain);

err=yp_get_default_domain(&domainname);
if(err == 0)
	{
	return(domainname);
	}
else
	{
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r, "%s", yperr_string(err) );
	return NULL;
	}
}

static char *user_in_yp_group(request_rec *r, const char *group_to_check, char *auth_yp_grptable, char *auth_yp_domain)
{
char *user=r->connection->user;
char *domainname, *value, *groups;
char groupline[MAX_STRING_LEN], uname[MAX_STRING_LEN];
int err, valuelen, unameidx, colons;

domainname=get_yp_domain(r, auth_yp_domain);
if(!domainname)	return NULL;

if(!auth_yp_grptable)	auth_yp_grptable="group.byname";

err=yp_match(domainname, auth_yp_grptable, group_to_check, strlen(group_to_check), &value, &valuelen);
if(err != 0)
	{
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r, "%s", yperr_string(err) );
	return NULL;
	}

strncpy(groupline, value, valuelen);
groupline[valuelen]=(char)NULL;
for(colons=3, groups=groupline; colons; groups++)
	if(*groups == ':')      colons--;

while(isprint((int)*groups))
	{
	unameidx=0;
	while(isprint((int)*groups) && *groups != ',')
		{
		uname[unameidx++]=*groups++;
		}
	groups++;
	uname[unameidx++]=(char)NULL;
	printf("%s\n", uname);
 
	if(!strcmp(user, uname))
		{
		/* printf("Found %s\n", argv[2]); */
		return group_to_check;
		}
	}
/* printf("Unable to find %s\n", argv[2]); */
return NULL;
}

static char *get_pw(request_rec *r, char *user, char *auth_yp_pwtable, char *auth_yp_domain)
{
char *domainname, *value, *passwd, *passwdend;
char passwdline[MAX_STRING_LEN];
int err, valuelen;

domainname=get_yp_domain(r, auth_yp_domain);
if(!domainname)	return NULL;

if(!auth_yp_pwtable)	auth_yp_pwtable="passwd.byname";
err=yp_match(domainname, auth_yp_pwtable, user, strlen(user), &value, &valuelen);
if(err != 0)
	{
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r, "%s", yperr_string(err) );
	return NULL;
	}
 
strcpy(passwdline, value);
 
for(passwd=passwdline; *passwd!=':'; passwd++);
passwd++;
 
for(passwdend=passwd; *passwdend!=':'; passwdend++);
*passwdend=(char)NULL;
 
return ap_pstrdup (r->pool, passwd);
}

/* These functions return 0 if client is OK, and proper error status
 * if not... either AUTH_REQUIRED, if we made a check, and it failed, or
 * SERVER_ERROR, if things are so totally confused that we couldn't
 * figure out how to tell if the client is authorized or not.
 *
 * If they return DECLINED, and all other modules also decline, that's
 * treated by the server core as a configuration error, logged and
 * reported as such.
 */

/* Determine user ID, and check if it really is that user, for HTTP
 * basic authentication...
 */

static int authenticate_basic_user(request_rec *r)
{
    auth_yp_config_rec *sec =
    (auth_yp_config_rec *) ap_get_module_config(r->per_dir_config, &auth_yp_module);
    conn_rec *c = r->connection;
    const char *sent_pw;
    char *real_pw;
    char *invalid_pw;
    int res;

    if ((res = ap_get_basic_auth_pw(r, &sent_pw)))
	return res;

    /* If YP is not enabled - IanP */
    if(!sec->auth_yp)	return DECLINED;

    if (!(real_pw = get_pw(r, c->user, sec->auth_yp_pwtable, sec->auth_yp_domain))) {
	if (!(sec->auth_yp_authoritative))
	    return DECLINED;
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		    "user %s not found: %s", c->user, r->uri);
	ap_note_basic_auth_failure(r);
	return AUTH_REQUIRED;
    }
    invalid_pw = ap_validate_password(sent_pw, real_pw);
    if (invalid_pw != NULL) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		      "user %s: authentication failure for \"%s\": %s",
		      c->user, r->uri, invalid_pw);
	ap_note_basic_auth_failure(r);
	return AUTH_REQUIRED;
    }
    return OK;
}

/* Checking ID */

static int check_user_access(request_rec *r)
{
    auth_yp_config_rec *sec =
    (auth_yp_config_rec *) ap_get_module_config(r->per_dir_config, &auth_yp_module);
    char *user = r->connection->user;
    int m = r->method_number;
    int method_restricted = 0;
    register int x;
    const char *t, *w;
    table *grpstatus;
    const array_header *reqs_arr = ap_requires(r);
    require_line *reqs;

    /* If YP is not enabled - IanP */
    if(!sec->auth_yp)	return DECLINED;

    /* BUG FIX: tadc, 11-Nov-1995.  If there is no "requires" directive, 
     * then any user will do.
     */
    if (!reqs_arr)	return (OK);

    reqs = (require_line *) reqs_arr->elts;

    for (x = 0; x < reqs_arr->nelts; x++) {

	if (!(reqs[x].method_mask & (1 << m)))
	    continue;

	method_restricted = 1;

	t = reqs[x].requirement;
	w = ap_getword_white(r->pool, &t);
	if (!strcmp(w, "valid-user"))
	    return OK;
	if (!strcmp(w, "user")) {
	    while (t[0]) {
		w = ap_getword_conf(r->pool, &t);
		if (!strcmp(user, w))
		    return OK;
	    }
	}
	else if (!strcmp(w, "group")) {
	    /* if (!grpstatus)
		return DECLINED;	/* DBM group?  Something else? */

	    while (t[0]) {
		w = ap_getword_conf(r->pool, &t); /* w=group name - IanP */
		/* New Function - IanP */
        if(user_in_yp_group(r, w, sec->auth_yp_grptable, sec->auth_yp_domain))
			return OK;
	    }
	} else if (sec->auth_yp_authoritative) {
	    /* if we aren't authoritative, any require directive could be
	     * valid even if we don't grok it.  However, if we are 
	     * authoritative, we can warn the user they did something wrong.
	     * That something could be a missing "AuthAuthoritative off", but
	     * more likely is a typo in the require directive.
	     */
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		"access to %s failed, reason: unknown require directive:"
		"\"%s\"", r->uri, reqs[x].requirement);
	}
    }

    if (!method_restricted)
	return OK;

    if (!(sec->auth_yp_authoritative))
	return DECLINED;

    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
	"access to %s failed, reason: user %s not allowed access",
	r->uri, user);
	
    ap_note_basic_auth_failure(r);
    return AUTH_REQUIRED;
}

module MODULE_VAR_EXPORT auth_yp_module =
{
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    create_auth_yp_dir_config,	/* dir config creater */
    NULL,			/* dir merger --- default is to override */
    NULL,			/* server config */
    NULL,			/* merge server config */
    auth_yp_cmds,			/* command table */
    NULL,			/* handlers */
    NULL,			/* filename translation */
    authenticate_basic_user,	/* check_user_id */
    check_user_access,		/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    NULL			/* post read-request */
};
