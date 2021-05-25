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
 * ghibc - cli tool
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <argp.h>
#include <stdbool.h>
#include <errno.h>

#include "ghibli.h"
#include "utils/bufhelp.h"
#include "utils/debug.h"

const char *argp_program_version = "ghibc version 0.1";
const char *argp_program_bug_address = "chia_jason96@live.com";
static char doc[] = "Identity-based identification command line tool.";
static char args_doc[] = "[MODE]"; //[STRING]... for multiple args
static struct argp_option options[] = {
	{ "mskfile", 's', "MASTERKEY", 0, "Read/write MASTERKEY as master-key."},
	{ "mpkfile", 'p', "MASTERPUB", 0, "Read MASTERPUB as master-public (validation only)."},
	{ "uskfile", 'u', "USERKEY", 0, "Read/write USERKEY as user-key."},
	{ "identity", 'i', "IDENTITY", 0, "Issue user-key bound  to IDENTITY."},
	{ "algo", 'a', "ALGO", 0, "Use ALGO (keygen only)."},
	{ "agentsock", 'q', "PATH", 0, "Location (PATH) of auth agent socket (ping-verify)"},
	{ "verbose", 'v' ,0 ,0 , "Enable verbose messages."},
	{ 0 }
};

struct arguments {
	enum { MSKGEN, USKGEN, USKVRF, AGENT, PINGVER } mode;
	int algo; //algo number
	char *uskfile; //user secret key filename
	char *mskfile; //master secret key filename
	char *mpkfile; //master public key filename
	char *uident; //user identity
	char *agsock;
	int flags;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
	struct arguments *arguments = state->input;
	char *end;
	switch (key) {
	case 's':
		arguments->mskfile = arg; break;
	case 'u':
		arguments->uskfile = arg; break;
	case 'i':
		arguments->uident = arg; break;
	case 'p':
		arguments->mpkfile = arg; break;
	case 'q':
		arguments->agsock = arg; break;
	case 'v':
		arguments->flags |= GHIBC_FLAG_VERBOSE; break; //enable verbose message
	case 'a':
		arguments->algo = strtol( arg, &end, 10); //parse to base10
		if( errno == ERANGE ){
			//error handling
			lerror("Range_Error on algo\n");
			errno = 0;
			arguments->algo = 0; //fallback value
		} break;
	case ARGP_KEY_ARG:
		if (strcmp(arg, "keygen") == 0) {
			arguments->mode = MSKGEN;
		} else if (strcmp(arg, "issue") == 0) {
			arguments->mode = USKGEN;
		} else if (strcmp(arg, "validate") == 0) {
			arguments->mode = USKVRF;
		} else if (strcmp(arg, "agent") == 0) {
			arguments->mode = AGENT;
		} else if (strcmp(arg, "pingv") == 0) {
			arguments->mode = PINGVER;
		} else {
			lerror("Invalid mode: %s. modes: keygen, issue, validate, agent, pingv\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if( state->arg_num < 1 ){
			lerror("No mode specified. Modes: keygen, issue, validate, agent, pingv\n", arg);
			argp_usage(state);

		}
		break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

int main(int argc, char *argv[], char *envp[]){
	struct arguments arguments;
	arguments.algo = 0; //default algo
	arguments.mskfile = NULL;
	arguments.uskfile = NULL;
	arguments.uident = NULL;
	arguments.mpkfile = NULL;
	arguments.agsock = NULL;
	arguments.flags = 0;
	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	int rc;
	char tcb[128]; size_t len;

	switch(arguments.mode){
		case MSKGEN:
			if(arguments.mskfile == NULL){
				lerror("Unspecified msk(-s) file in master mode.\n");
				return -1;
			}
			snprintf(tcb, 128, "%s.pub", arguments.mskfile);
			rc = ghibfile.setup(arguments.mskfile, tcb, arguments.algo, arguments.flags);
			printf("Master key generated to files %s and %s\n",arguments.mskfile, tcb);
			break;
		case USKGEN:
			if(arguments.mskfile == NULL || arguments.uskfile == NULL || arguments.uident == NULL){
				lerror("Unspecified msk(-s)/usk(-u)/identity(-i) file in issue mode.\n");
				return -1;
			}
			rc = ghibfile.issue(arguments.mskfile, arguments.uskfile, arguments.uident, arguments.flags);
			printf("User key (%s) generated to file %s.\n", arguments.uident, arguments.uskfile);
			break;
		case USKVRF:
			if(arguments.mpkfile == NULL || arguments.uskfile == NULL){
				lerror("Unspecified mpk(-p)/usk(-u) file in validate mode.\n");
				return -1;
			}
			rc = ghibfile.keycheck(arguments.mpkfile, arguments.uskfile, &arguments.uident, &len, arguments.flags);
			if(rc == 0){
				printf("User key (%s) on file %s is valid.\n", arguments.uident, arguments.uskfile);
			}
			if(rc == GHIBC_FAIL || rc == GHIBC_NO_ERR){
				free(arguments.uident);
			}
			break;
		case AGENT:
			if(arguments.uskfile == NULL){
				lerror("Unspecified usk(-u) file in agent mode.\n");
				return -1;
			}
			ghibfile.agent(arguments.uskfile, arguments.flags);
			// won't reach here
			break;
		case PINGVER:
			if(arguments.mpkfile == NULL || arguments.uident == NULL || arguments.agsock == NULL){
				lerror("Unspecified mpk(-p)/identity(-i)/agentsock(-q) in ping-verify(pingv) mode.\n");
				return -1;
			}
			rc = ghibfile.pingver(arguments.mpkfile, arguments.uident, strlen(arguments.uident), arguments.agsock, strlen(arguments.agsock), arguments.flags);
			if(rc == 0){
				printf("Ping verify succeed for id: %s on agent socket:%s\n", arguments.uident, arguments.agsock);
			}else{
				printf("Ping verify failed for id: %s on agent socket:%s\n", arguments.uident, arguments.agsock);
			}
			break;
		default:
			lerror("Mode error.\n");
	}
	//struct __ghibli *ghibli = ghibli_init();
	//ghibli->core.randombytes(buf, 64);
	//ucbprint(buf, 64);
}
