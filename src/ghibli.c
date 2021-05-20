#include "ghibli.h"
#include "utils/futil.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// generates the master key to a file, based on AN
int __mastergen_file(char *skfilename, char *pkfilename, int an){
	void *secret, *public;
	unsigned char *bptr; size_t blen;

	FILE *skfile = fopen(skfilename, "w");
	if(skfile == NULL){
		fprintf(stderr,"Unable to open file %s for writing.\n", skfilename); return -1;
	}
	FILE *pkfile = fopen(pkfilename, "w");
	if(skfile == NULL){
		fprintf(stderr,"Unable to open file %s for writing.\n", pkfilename); return -1;
	}

	ghibcore.init(an);
	ghibcore.ibi->keygen(&secret);
	ghibcore.ibi->pkext(secret, &public);

	blen = ghibcore.ibi->skserial(secret, &bptr);
	ghibcore.ibi->skprint(secret);
	ghibcore.ibi->skfree(secret);
	write_b64(skfile, bptr, blen);
	free(bptr);

	blen = ghibcore.ibi->pkserial(public, &bptr);
	ghibcore.ibi->pkprint(public);
	ghibcore.ibi->pkfree(public);
	write_b64(pkfile, bptr, blen);
	free(bptr);
	return 0;
}

int __usergen_file(char *skfilename, char *ukfilename, char *identity, int an){
	void *secret, *user;
	unsigned char *bptr; size_t blen;

	FILE *skfile = fopen(skfilename, "r");
	if(skfile == NULL){
		fprintf(stderr,"Unable to open file %s for reading.\n", skfilename); return -1;
	}
	FILE *ukfile = fopen(ukfilename, "w");
	if(ukfile == NULL){
		fprintf(stderr,"Unable to open file %s for writing.\n", ukfilename); return -1;
	}

	ghibcore.init(an);
	bptr = read_b64( skfile, &blen);
	ghibcore.ibi->skconstr(bptr, &secret);
	free(bptr);

	ghibcore.ibi->issue(secret, identity, strlen(identity), &user);
	ghibcore.ibi->skprint(secret);
	ghibcore.ibi->skfree(secret);
	blen = ghibcore.ibi->ukserial(user, &bptr);
	ghibcore.ibi->ukprint(user);
	ghibcore.ibi->ukfree(user);
	//fprintf(user, "algoname "); //TODO: include algoname
	write_b64(ukfile, bptr, blen);
	free(bptr);
	return 0;
}

int __userval_file(char *pkfilename, char *ukfilename, int an, char **identity, size_t *idlen ){
	void *public, *user; int rc;
	unsigned char *bptr; size_t blen;

	FILE *pkfile = fopen(pkfilename, "r");
	if(pkfile == NULL){
		fprintf(stderr,"Unable to open file %s for reading.\n", pkfilename); return -1;
	}
	FILE *ukfile = fopen(ukfilename, "r");
	if(ukfile == NULL){
		fprintf(stderr,"Unable to open file %s for reading.\n", ukfilename); return -1;
	}

	ghibcore.init(an);
	bptr = read_b64( pkfile, &blen);
	ghibcore.ibi->pkconstr(bptr, &public);
	free(bptr);

	bptr = read_b64( ukfile, &blen);
	ghibcore.ibi->ukconstr(bptr, blen, &user);
	free(bptr);

	ghibcore.ibi->validate(public, user, &rc);
	*idlen = ghibcore.ibi->idext(user, (unsigned char **)identity);

	ghibcore.ibi->pkprint(public);
	ghibcore.ibi->ukprint(user);

	ghibcore.ibi->pkfree(public);
	ghibcore.ibi->ukfree(user);
	if(rc){
		fprintf(stderr,"Invalid user key %s for %s identity.\n", ukfilename, *identity);
		return -1;
	}
	return 0;
}

const struct __ghibli_file ghibfile = {
	.mastergen = __mastergen_file,
	.usergen = __usergen_file,
	.userval = __userval_file,
};
