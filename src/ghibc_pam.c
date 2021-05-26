/*
 * Copyright (c) 2020 Chia Jason
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * ghibc - pam lib
 * only provides auth (pam_authenticate)
 */

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#include "ghibli.h"

/*
 * defined in pwd.h
 * struct passwd {
 *                char   *pw_name;       // username
 *                char   *pw_passwd;     // user password
 *                uid_t   pw_uid;        // user ID
 *                gid_t   pw_gid;        // group ID
 *                char   *pw_gecos;      // user information
 *                char   *pw_dir;        // home directory
 *                char   *pw_shell;      // shell program
 * };
*/
extern char **environ;

// PAM entry point for authentication verification (ensure user is who they claim they are)
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	// TODO: handle authentication code here
	// flags: PAM_SILENT, PAM_DISALLOW_NULL_AUTHTOK
	char *user = NULL; //variable to store username
	int rc, flag = 0;
	pam_set_item(pamh, PAM_AUTHTOK, ""); //set an empty authtok (no password)

	// ensure pkfile specified
	if(argc < 1){
		fprintf(stderr,"pkfile not set.\n");
		return PAM_NO_MODULE_DATA;
	}
	char *pkfname = (char *) argv[0];//store pkfilename

	// get username, 3rd arg is prompt "login:" (default).
	rc = pam_get_user(pamh, (const char **) &user, "login: ");
	if (rc != PAM_SUCCESS || user == NULL) {
		// username error
		return PAM_USER_UNKNOWN;
	}

	uid_t euid; // program effective uid
	struct passwd *pdat; // /etc/passwd data struct
	// get passwd struct from /etc/passwd corresponding to username
	pdat = pam_modutil_getpwnam(pamh, user);
	if (pdat == NULL) {
		// no pwd data in /etc/passwd (probably not a valid linux user)
		return PAM_USER_UNKNOWN;
	}

	// get user auth socket (at home)
#if SOCK_AT_USER_HOME
	char *asock = (char *) calloc(64, 1);
	snprintf(asock, 64, "%s/.ghibc/agent.sock", pdat->pw_dir); //socket @ user home
#else
	assert(0); //issues not fixed yet, how to get pam to use the user's env
	// unable to get GHIBC_AUTH_SOCK from getenv if running from libpam context
#endif

	// get and store euid of the runner
	euid = geteuid();
	if(getuid() != euid || euid == 0 ){
		rc = seteuid(pdat->pw_uid); //drop privilege to user's privilege
		if (rc < 0){
			perror("seteuid");
			return PAM_AUTH_ERR;
		}
		flag = 1;
		//rmb to reset euid back to original 'euid'
	}

	ghibc_init();
	rc = ghibfile.pingver(pkfname, user, strlen(user), asock, strlen(asock), 0);
	switch(rc){
		case GHIBC_NO_ERR:
			//all ok
			break;
		case GHIBC_FAIL:
			// auth fail
			return PAM_AUTH_ERR;
		case GHIBC_FILE_ERR:
			// file cannot be read (module config error)
			return PAM_NO_MODULE_DATA;
		case GHIBC_CONN_ERR:
			// unable to openfile/read socket
			return PAM_AUTHINFO_UNAVAIL;
		case GHIBC_SOCK_ERR:
			// socket creation/configuration failed
			return PAM_SYSTEM_ERR;
		case GHIBC_BUFF_ERR:
			// buffer not enough
			return PAM_BUF_ERR;
		default:
			// error not handled?
			return PAM_SERVICE_ERR;
	}

	if(flag){
		rc = seteuid(euid);
		if(rc < 0){
			// something is wrong?
			perror("seteuid");
			return PAM_AUTH_ERR;
		}
	}

	// see /usr/include/security/_pam_types.h for a list of return codes.
	return PAM_SUCCESS; //return this if and only if you are sure the user valid and present.
}

// PAM entry point for session creation
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	//TODO: handle session start
	//code runs when app calls pam_open_session
	// flags: PAM_SILENT
	return PAM_IGNORE;
}

// PAM entry point for session cleanup
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	//TODO: handle session close
	//code runs when app calls pam_close_session
	// flags: PAM_SILENT
	return PAM_IGNORE;
}

// PAM entry point for setting user credentials (that is, to actually
// establish the authenticated user's credentials to the service provider)
// this runs BEFORE session opens, see man pam_setcred
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	// TODO: handle credential change
	// user has been authenticated, and would like to change their credentials
	// flags:
	// PAM_SILENT, PAM_ESTABLISH_CRED, PAM_DELETE_CRED, PAM_REINITIALIZE_CRED, PAM_REFRESH_CRED
	return PAM_IGNORE;
}

// PAM entry point for authentication token (password) changes
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	// TODO: handle (re-)set of the authentication token of the user
	// flags:
	// PAM_SILENT, PAM_CHANGE_EXPIRED_AUTHTOK, PAM_PRELIM_CHECK, PAM_UPDATE_AUTHTOK
	return PAM_IGNORE;
}
