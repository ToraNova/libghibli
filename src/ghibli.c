#include "ghibli.h"
#include "utils/futil.h"
#include "utils/debug.h"
#include "utils/simplesock.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>


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

	ghibc_init(an);

	//ghibcore.ibi->keygen(&secret);
	//ghibcore.ibi->pkext(secret, &public);

	//blen = ghibcore.ibi->skserial(secret, &bptr);
	//ghibcore.ibi->skprint(secret);
	//ghibcore.ibi->skfree(secret);
	//write_b64(skfile, bptr, blen);
	//free(bptr);

	//blen = ghibcore.ibi->pkserial(public, &bptr);
	//ghibcore.ibi->pkprint(public);
	//ghibcore.ibi->pkfree(public);
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

	ghibc_init(an);

	//bptr = read_b64( skfile, &blen);
	//ghibcore.ibi->skconstr(bptr, &secret);
	//free(bptr);

	//ghibcore.ibi->issue(secret, identity, strlen(identity), &user);
	//ghibcore.ibi->skprint(secret);
	//ghibcore.ibi->skfree(secret);
	//blen = ghibcore.ibi->ukserial(user, &bptr);
	//ghibcore.ibi->ukprint(user);
	//ghibcore.ibi->ukfree(user);
	////fprintf(user, "algoname "); //TODO: include algoname
	//write_b64(ukfile, bptr, blen);
	//free(bptr);
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

	ghibc_init(an);

	//bptr = read_b64( pkfile, &blen);
	//ghibcore.ibi->pkconstr(bptr, &public);
	//free(bptr);

	//bptr = read_b64( ukfile, &blen);
	//ghibcore.ibi->ukconstr(bptr, blen, &user);
	//free(bptr);

	//ghibcore.ibi->validate(public, user, &rc);
	//*idlen = ghibcore.ibi->idext(user, (unsigned char **)identity);

	//ghibcore.ibi->pkprint(public);
	//ghibcore.ibi->ukprint(user);

	//ghibcore.ibi->pkfree(public);
	//ghibcore.ibi->ukfree(user);
	//if(rc){
	//	lerror("Invalid user key %s for %s identity.\n", ukfilename, *identity);
	//	return -1;
	//}
	return 0;
}

int __prover_file(char *ukfilename, int an){
	void *user, *pst;

	ghibc_init(an);

	//if( ghibcore.ibi->cmtlen > 320 || ghibcore.ibi->reslen > 320 ){
	//	lerror("Insufficient sendbuffer size.\n");
	//	return -1;
	//}else if( ghibcore.ibi->chalen > 64 ){
	//	lerror("Insufficient recvbuffer size.\n");
	//	return -1;
	//}

	//char sockname[64];
	//struct sockaddr_un addr;
	//struct sockaddr_un from;
	//socklen_t fromlen = sizeof(from);
	//int fd, c, pid, rc;

	//unsigned char sbuf[320];
	//unsigned char rbuf[64];

	//fd = socket(AF_UNIX, SOCK_STREAM, 0);
	//if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	//	lerror("Socket creation failed.\n");
	//	return -1;
	//}

	//pid = getpid();
	//sprintf(sockname, "/tmp/ghibc-ag%d", pid);

	//memset(&addr, 0, sizeof(addr));
	//addr.sun_family = AF_UNIX;
	//strcpy(addr.sun_path, sockname);
	//unlink(sockname);
	//if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	//	lerror("Socket binding failed.\n");
	//	return -1
	//}
	//listen(fd, 3); //allow up to 3 incoming connections to queue

	//while(1){
	//	c = accept(fd, (struct sockaddr *)&from, (socklen_t*)&fromlen);

	//	ghibcore.ibi->prvinit(user, &pst); //init prover
	//	ghibcore.ibi->cmtgen(&pst, sbuf);
	//	sendbuf(c, (char *)sbuf, ghibcore.ibi->cmtlen);

	//	// receive challenge
	//	fixed_recvbuf(c, (char *) rbuf, ghibcore.ibi->chalen);

	//	ghibcore.ibi->resgen(rbuf, pst, sbuf);
	//	sendbuf(c, (char *)sbuf, ghibcore.ibi->reslen);
	//	close(c);
	//}
}

const struct __ghibli_file ghibfile = {
	.setup = __mastergen_file,
	.issue = __usergen_file,
	.keycheck = __userval_file,
	.agent = __prover_file,
};
