#include "ghibli.h"
#include "utils/futil.h"
#include "utils/debug.h"
#include "utils/simplesock.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>

// generates the master key to a file, based on AN
int __mastergen_file(char *skfilename, char *pkfilename, int an, int flags){
	void *sk, *pk;
	unsigned char buf[GHIBC_BLEN]; size_t blen;

	FILE *skfile = fopen(skfilename, "w");
	if(skfile == NULL){
		if( flags & GHIBC_FLAG_VERBOSE )
			lerror("Unable to open file %s for writing.\n", skfilename);
		return GHIBC_FILE_ERR;
	}
	FILE *pkfile = fopen(pkfilename, "w");
	if(skfile == NULL){
		if( flags & GHIBC_FLAG_VERBOSE )
			lerror("Unable to open file %s for writing.\n", pkfilename);
		fclose(skfile);
		return GHIBC_FILE_ERR;
	}

	ghibc_init();

	gc.ibi->setup(an, &sk, &pk);
	if( flags & GHIBC_FLAG_VERBOSE ){
		gc.ibi->kprint(sk);
		gc.ibi->kprint(pk);
	}

	blen = gc.ibi->kserial(sk, buf, GHIBC_BLEN);
	gc.ibi->kfree(sk);
	write_b64(skfile, buf, blen);
	fclose(skfile);

	blen = gc.ibi->kserial(pk, buf, GHIBC_BLEN);
	gc.ibi->kfree(pk);
	write_b64(pkfile, buf, blen);
	fclose(pkfile);
	return GHIBC_NO_ERR;
}

int __usergen_file(char *skfilename, char *ukfilename, char *identity, int flags){
	void *sk, *uk;
	unsigned char *bptr; size_t blen;
	unsigned char buf[GHIBC_BLEN];

	FILE *skfile = fopen(skfilename, "r");
	if(skfile == NULL){
		if( flags & GHIBC_FLAG_VERBOSE )
			lerror("Unable to open file %s for reading.\n", skfilename);
		return GHIBC_FILE_ERR;
	}
	FILE *ukfile = fopen(ukfilename, "w");
	if(ukfile == NULL){
		if( flags & GHIBC_FLAG_VERBOSE )
			lerror("Unable to open file %s for writing.\n", ukfilename);
		fclose(skfile);
		return GHIBC_FILE_ERR;
	}

	ghibc_init();

	bptr = read_b64(skfile, &blen);
	fclose(skfile);
	gc.ibi->kconstr(bptr, &sk);
	free(bptr);

	gc.ibi->issue(sk, identity, strlen(identity), &uk);

	if( flags & GHIBC_FLAG_VERBOSE ){
		gc.ibi->kprint(sk);
		gc.ibi->uprint(uk);
	}

	blen = gc.ibi->userial(uk, buf, GHIBC_BLEN);

	gc.ibi->kfree(sk);
	gc.ibi->ufree(uk);

	write_b64(ukfile, buf, blen);
	fclose(ukfile);
	return GHIBC_NO_ERR;
}

int __userval_file(char *pkfilename, char *ukfilename, char **identity, size_t *idlen, int flags ){
	void *pk, *uk; int rc;
	unsigned char *bptr; size_t blen;

	FILE *pkfile = fopen(pkfilename, "r");
	if(pkfile == NULL){
		if( flags & GHIBC_FLAG_VERBOSE )
			lerror("Unable to open file %s for reading.\n", pkfilename);
		return GHIBC_FILE_ERR;
	}
	FILE *ukfile = fopen(ukfilename, "r");
	if(ukfile == NULL){
		fclose(pkfile);
		if( flags & GHIBC_FLAG_VERBOSE )
			lerror("Unable to open file %s for reading.\n", ukfilename);
		return GHIBC_FILE_ERR;
	}

	ghibc_init();

	bptr = read_b64( pkfile, &blen);
	fclose(pkfile);
	gc.ibi->kconstr(bptr, &pk);
	free(bptr);

	bptr = read_b64( ukfile, &blen);
	gc.ibi->uconstr(bptr, blen, &uk);
	free(bptr);

	if( flags & GHIBC_FLAG_VERBOSE ){
		gc.ibi->kprint(pk);
		gc.ibi->uprint(uk);
	}

	gc.ibi->validate(pk, uk, &rc);
	gc.ibi->kfree(pk);
	gc.ibi->uiread(uk, (unsigned char **) identity, idlen);

	gc.ibi->ufree(uk);
	fclose(ukfile);

	if(rc){
		return GHIBC_FAIL;
	}else{
		return GHIBC_NO_ERR;
	}
}

int __ping_verifier_file(char *pkfilename, char *uid, size_t uidlen, char *sp, size_t splen, int flags){
	//request for verification once on a socket
	void *pk, *pst;
	unsigned char *bptr; size_t blen;
	unsigned char rbuf[320];
	unsigned char sbuf[64];
	int sd, rc, an;

	struct sockaddr_un addr;

	FILE *pkfile = fopen(pkfilename, "r");
	if(pkfile == NULL){
		if( flags & GHIBC_FLAG_VERBOSE )
			lerror("Unable to open file %s for reading.\n", pkfilename);
		return GHIBC_FILE_ERR;
	}
	bptr = read_b64(pkfile, &blen);
	fclose(pkfile);

	ghibc_init();
	gc.ibi->kconstr(bptr, &pk);
	free(bptr);
	an = gc.ibi->karead(pk);

	if( gc.ibi->cmtlen(an) > 320 || gc.ibi->reslen(an) > 320 ){
		if( flags & GHIBC_FLAG_VERBOSE )
			lerror("Insufficient recvbuffer size.\n");
		rc =  GHIBC_BUFF_ERR;
		goto teardown;
	}else if( gc.ibi->chalen(an) > 64 ){
		if( flags & GHIBC_FLAG_VERBOSE )
			lerror("Insufficient sendbuffer size.\n");
		rc = GHIBC_BUFF_ERR;
		goto teardown;
	}

	//create socket
	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(sd < 0){
		if( flags & GHIBC_FLAG_VERBOSE )
			perror("socket");
		rc = GHIBC_SOCK_ERR;
		goto teardown;
	}

	// sp not set, use env or home sock
	if( !sp ){
		// get auth socket
#if SOCK_AT_USER_HOME
		char *uh = getenv("HOME"); //user home directory
		sp = (char *) calloc(64, 1);
		snprintf(sp, 64, "%s/.ghibc/agent.sock", uh); //socket @ user home
#else
		sp = getenv("GHIBC_AUTH_SOCK");
		if( !sp ){
			fprintf(stderr,"GHIBC_AUTH_SOCK not set.\n");
			return PAM_AUTHINFO_UNAVAIL;
		}
#endif
		splen = strlen(sp);
	}

	// initialize socket addr
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX; //set address type
	memcpy(addr.sun_path, sp, splen); //set socket path

	// connect
	//debug("Establishing connection to auth socket: %s\n", sp);
	rc = connect(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0){
		if( flags & GHIBC_FLAG_VERBOSE )
			perror("connect");
		close(sd);
		rc = GHIBC_CONN_ERR;
		goto teardown;
	}

	gc.ibi->verinit(pk, (unsigned char *)uid, uidlen, &pst);

	rc = recv(sd, rbuf, gc.ibi->cmtlen(an), 0);
	gc.ibi->chagen(rbuf, &pst, sbuf);
	rc = send(sd, sbuf, gc.ibi->chalen(an), 0);
	rc = recv(sd, rbuf, gc.ibi->reslen(an), 0);
	gc.ibi->protdc(rbuf, pst, &rc);
	if(rc == 0){
		rc = GHIBC_NO_ERR;
	}else{
		rc = GHIBC_FAIL;
	}
	close(sd);

teardown:
	gc.ibi->kfree(pk);
	return rc;
}

int __prover_unix_agent_file(char *ukfilename, int flags){
	void *uk, *pst;
	unsigned char *bptr; size_t blen;
	int an, rc, sd, cd;
	unsigned char sbuf[320];
	unsigned char rbuf[64];
	struct sockaddr_un addr; //sockaddr type for unix
	struct sockaddr_un remote; //client remote address
	socklen_t raddrlen = sizeof(remote);

	FILE *ukfile = fopen(ukfilename, "r");
	if(ukfile == NULL){
		if( flags & GHIBC_FLAG_VERBOSE )
			lerror("Unable to open file %s for reading.\n", ukfilename);
		return GHIBC_FILE_ERR;
	}

	ghibc_init();

	bptr = read_b64( ukfile, &blen);
	fclose(ukfile);
	gc.ibi->uconstr(bptr, blen, &uk);
	free(bptr);

	an = gc.ibi->uaread(uk);

	if( gc.ibi->cmtlen(an) > 320 || gc.ibi->reslen(an) > 320 ){
		if( flags & GHIBC_FLAG_VERBOSE )
			lerror("Insufficient sendbuffer size.\n");
		rc = GHIBC_BUFF_ERR;
		goto teardown;
	}else if( gc.ibi->chalen(an) > 64 ){
		if( flags & GHIBC_FLAG_VERBOSE )
			lerror("Insufficient recvbuffer size.\n");
		rc = GHIBC_BUFF_ERR;
		goto teardown;
	}

	//create socket
	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(sd < 0){
		if( flags & GHIBC_FLAG_VERBOSE )
			perror("socket");
		rc = GHIBC_SOCK_ERR;
		goto teardown;
	}

	pid_t pid = getpid();
	char sp[64];
#if SOCK_AT_USER_HOME
	char *uh = getenv("HOME"); //user home directory
	snprintf(sp, 64, "%s/.ghibc", uh); //socket @ user home
	rc = mkdir(sp, 0700);
	if( rc == -1 && errno != EEXIST){
		//error but is not already exist error
		if( flags & GHIBC_FLAG_VERBOSE )
			perror("mkdir");
		close(sd);
		rc = GHIBC_SOCK_ERR;
		goto teardown;
	}
	snprintf(sp, 64, "%s/.ghibc/agent.sock", uh); //ssh-agent style
#else
	assert(0); //TODO: only use this when pam is fixed
	snprintf(sp, 64, "/tmp/ghibc-ag%d", pid); //ssh-agent style
#endif

	// initialize socket addr
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX; //set address type
	memcpy(addr.sun_path, sp, strlen(sp)); //set socket path
	unlink(sp);

	rc = bind(sd, (struct sockaddr *)&addr, sizeof(addr));
	if( rc < 0 ){
		if( flags & GHIBC_FLAG_VERBOSE )
			perror("bind");
		close(sd);
		rc = GHIBC_SOCK_ERR;
		goto teardown;
	}

	listen(sd, 3); //allow up to 3 incoming connections to queue
	fprintf(stdout, "GHIBC_AUTH_SOCK=%s; export GHIBC_AUTH_SOCK;\n", sp);
	fprintf(stdout, "GHIBC_AGENT_PID=%d; export GHIBC_AGENT_PID;\n", pid);
	fprintf(stdout, "echo Agent pid %d\n", pid);

	time_t rtime;
  	struct tm * tinfo;
	//TODO: properly handle keyboard interrupts and teardown nicely
	while(1){
		cd = accept(sd, (struct sockaddr *)&remote, &raddrlen);
		if( flags & GHIBC_FLAG_VERBOSE ){
			time(&rtime);
			tinfo = localtime (&rtime);
			fprintf(stdout, "Prove request at: %s", asctime(tinfo));
		}

		gc.ibi->prvinit(uk, &pst); //initialize prover
		gc.ibi->cmtgen(&pst, sbuf);

		rc = send(cd, sbuf, gc.ibi->cmtlen(an), 0);
		assert( rc == gc.ibi->cmtlen(an));

		rc = recv(cd, rbuf, gc.ibi->chalen(an), 0);
		assert( rc == gc.ibi->chalen(an));

		gc.ibi->resgen(rbuf, pst, sbuf);
		rc = send(cd, sbuf, gc.ibi->reslen(an), 0);
		assert( rc == gc.ibi->reslen(an));
		close(cd);
	}
	//won't reach, but cleanup code for further use
teardown:
	gc.ibi->ufree(uk);
	return rc;
}

const struct __ghibli_file ghibfile = {
	.setup = __mastergen_file,
	.issue = __usergen_file,
	.keycheck = __userval_file,
	.agent = __prover_unix_agent_file,
	.pingver = __ping_verifier_file,
};
