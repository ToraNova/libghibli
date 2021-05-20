#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <argp.h>
#include <stdbool.h>
#include <errno.h>

#include "ghibli.h"
#include "utils/bufhelp.h"

const char *argp_program_version = "ghibc version 0.1";
const char *argp_program_bug_address = "chia_jason96@live.com";
static char doc[] = "Identity-based identification command line tool.";
static char args_doc[] = "[MODE]"; //[STRING]... for multiple args
static struct argp_option options[] = {
	{ "mskfile", 's', "MASTERKEY", 0, "Read/write MASTERKEY as master-key."},
	{ "uskfile", 'u', "USERKEY", 0, "Read/write USERKEY as user-key."},
	{ "identity", 'i', "IDENTITY", 0, "Issue user-key bound  to IDENTITY."},
	{ "algo", 'a', "ALGO", 0, "Use ALGO for the operations."},
	{ 0 }
};

struct arguments {
	enum { MSKGEN, USKGEN, AGENT } mode;
	char *algo; //name of algorithm
	char *uskfile; //user secret key filename
	char *mskfile; //master secret key filename
	char *uident; //user identity
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
	struct arguments *arguments = state->input;
	switch (key) {
	case 's':
		arguments->mskfile = arg; break;
	case 'u':
		arguments->uskfile = arg; break;
	case 'i':
		arguments->uident = arg; break;
	case 'a':
		arguments->algo = arg; break;
	case ARGP_KEY_ARG:
		if (strcmp(arg, "keygen") == 0) {
			arguments->mode = MSKGEN;
		}
		else if (strcmp(arg, "issue") == 0) {
			arguments->mode = USKGEN;
		}
		else if (strcmp(arg, "agent") == 0) {
			arguments->mode = AGENT;
		}
		else {
			fprintf(stderr,"invalid mode: %s. modes: keygen, issue, agent\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if( state->arg_num > 1 ){
			fprintf(stderr,"too many arguments.", arg);
			argp_usage(state);
		}
		break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

int main(int argc, char *argv[], char *envp[]){
	char dalgo[] = "schibi"; //TODO: change default to something else.

	struct arguments arguments;
	arguments.algo = dalgo; //default algo
	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	switch(arguments.mode){
		case MSKGEN:
			if(arguments.mskfile == NULL){
				fprintf(stderr,"unspecified msk file in master mode.\n");
				break;
			}
			break;
		case USKGEN:
			if(arguments.mskfile == NULL || arguments.uskfile == NULL || arguments.uident == NULL){
				fprintf(stderr,"unspecified msk/usk file in issue mode.\n");
				break;
			}
			break;
		case AGENT:
			if(arguments.uskfile == NULL){
				fprintf(stderr,"unspecified usk file in agent mode.\n");
				break;
			}
			break;
	}
	//struct __ghibli *ghibli = ghibli_init();
	//ghibli->core.randombytes(buf, 64);
	//ucbprint(buf, 64);
}
