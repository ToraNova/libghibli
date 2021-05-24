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


// generates the master key to a file, based on AN
int __mastergen_file(char *skfilename, char *pkfilename, int an){
	void *sk, *pk;
	unsigned char buf[160]; size_t blen;

	FILE *skfile = fopen(skfilename, "w");
	if(skfile == NULL){
		lerror("Unable to open file %s for writing.\n", skfilename); return -1;
	}
	FILE *pkfile = fopen(pkfilename, "w");
	if(skfile == NULL){
		lerror("Unable to open file %s for writing.\n", pkfilename); return -1;
	}

	ghibc_init();

	gc.ibi->setup(an, &sk, &pk);
	gc.ibi->kprint(sk);
	gc.ibi->kprint(pk);

	blen = gc.ibi->kserial(sk, buf);
	gc.ibi->kfree(sk);
	write_b64(skfile, buf, blen);

	blen = gc.ibi->kserial(pk, buf);
	gc.ibi->kfree(pk);
	write_b64(pkfile, buf, blen);
	return 0;
}

int __usergen_file(char *skfilename, char *ukfilename, char *identity){
	void *sk, *uk;
	unsigned char *bptr; size_t blen;
	unsigned char buf[160];

	FILE *skfile = fopen(skfilename, "r");
	if(skfile == NULL){
		lerror("Unable to open file %s for reading.\n", skfilename); return -1;
	}
	FILE *ukfile = fopen(ukfilename, "w");
	if(ukfile == NULL){
		lerror("Unable to open file %s for writing.\n", ukfilename); return -1;
	}

	ghibc_init();

	bptr = read_b64(skfile, &blen);
	gc.ibi->kconstr(bptr, &sk);
	free(bptr);

	gc.ibi->kprint(sk);

	gc.ibi->issue(sk, identity, strlen(identity), &uk);
	gc.ibi->kfree(sk);

	gc.ibi->uprint(uk);
	blen = gc.ibi->userial(uk, buf);
	gc.ibi->ufree(uk);

	write_b64(ukfile, buf, blen);
	return 0;
}

int __userval_file(char *pkfilename, char *ukfilename, char **identity, size_t *idlen ){
	void *pk, *uk; int rc;
	unsigned char *bptr; size_t blen;

	FILE *pkfile = fopen(pkfilename, "r");
	if(pkfile == NULL){
		lerror("Unable to open file %s for reading.\n", pkfilename); return -1;
	}
	FILE *ukfile = fopen(ukfilename, "r");
	if(ukfile == NULL){
		lerror("Unable to open file %s for reading.\n", ukfilename); return -1;
	}

	ghibc_init();

	bptr = read_b64( pkfile, &blen);
	gc.ibi->kconstr(bptr, &pk);
	free(bptr);

	bptr = read_b64( ukfile, &blen);
	gc.ibi->uconstr(bptr, blen, &uk);
	free(bptr);

	gc.ibi->validate(pk, uk, &rc);
	gc.ibi->kfree(pk);
	gc.ibi->uiread(uk, (unsigned char **) identity, idlen);
	gc.ibi->uprint(uk);
	gc.ibi->ufree(uk);

	if(rc){
		lerror("Invalid user key %s for %s identity.\n", ukfilename, *identity);
		return -1;
	}
	return 0;
}

int __ping_verifier_file(char *pkfilename, char *uid, size_t uidlen, char *sp, size_t splen){
	//request for verification once on a socket
	void *pk, *pst;
	unsigned char *bptr; size_t blen;
	unsigned char rbuf[320];
	unsigned char sbuf[64];
	int sd, rc, an;

	struct sockaddr_un addr;

	FILE *pkfile = fopen(pkfilename, "r");
	if(pkfile == NULL){
		//lerror("Unable to open file %s for reading.\n", pkfilename);
		return GHIBC_FILE_ERR;
	}

	ghibc_init();

	bptr = read_b64( pkfile, &blen);
	gc.ibi->kconstr(bptr, &pk);
	free(bptr);

	an = gc.ibi->karead(pk);

	if( gc.ibi->cmtlen(an) > 320 || gc.ibi->reslen(an) > 320 ){
		//lerror("Insufficient recvbuffer size.\n");
		return GHIBC_BUFF_ERR;
	}else if( gc.ibi->chalen(an) > 64 ){
		//lerror("Insufficient sendbuffer size.\n");
		return GHIBC_BUFF_ERR;
	}

	//create socket
	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(sd < 0){
		//perror("socket");
		return GHIBC_SOCK_ERR;
		return -1;
	}

	// initialize socket addr
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX; //set address type
	memcpy(addr.sun_path, sp, splen); //set socket path

	// connect
	//debug("Establishing connection to auth socket: %s\n", sp);
	rc = connect(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0){
		//perror("connect");
		close(sd);
		return GHIBC_CONN_ERR;
	}

	gc.ibi->verinit(pk, (unsigned char *)uid, uidlen, &pst);

	rc = recv(sd, rbuf, gc.ibi->cmtlen(an), 0);
	gc.ibi->chagen(rbuf, &pst, sbuf);

	rc = send(sd, sbuf, gc.ibi->chalen(an), 0);

	rc = recv(sd, rbuf, gc.ibi->reslen(an), 0);
	gc.ibi->protdc(rbuf, pst, &rc);
	close(sd);
	gc.ibi->kfree(pk);
	//debug("PingV ok. res: %d\n",rc);
	if(rc == 0){
		return GHIBC_NO_ERR;
	}else{
		return GHIBC_FAIL;
	}
}

int __prover_unix_agent_file(char *ukfilename){
	void *uk, *pst;
	pid_t pid;
	unsigned char *bptr; size_t blen;
	int an, rc, sd, cd;
	char sp[64];
	unsigned char sbuf[320];
	unsigned char rbuf[64];
	struct sockaddr_un addr; //sockaddr type for unix
	struct sockaddr_un remote; //client remote address
	socklen_t raddrlen = sizeof(remote);

	FILE *ukfile = fopen(ukfilename, "r");
	if(ukfile == NULL){
		lerror("Unable to open file %s for reading.\n", ukfilename); return -1;
	}

	ghibc_init();

	bptr = read_b64( ukfile, &blen);
	gc.ibi->uconstr(bptr, blen, &uk);
	free(bptr);

	an = gc.ibi->uaread(uk);

	if( gc.ibi->cmtlen(an) > 320 || gc.ibi->reslen(an) > 320 ){
		lerror("Insufficient sendbuffer size.\n");
		return -1;
	}else if( gc.ibi->chalen(an) > 64 ){
		lerror("Insufficient recvbuffer size.\n");
		return -1;
	}

	//create socket
	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(sd < 0){
		perror("socket");
		return -1;
	}

	// initialize socket addr
	pid = getpid();
	sprintf(sp, "/tmp/ghibc-ag%d", pid);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX; //set address type
	memcpy(addr.sun_path, sp, strlen(sp)); //set socket path
	unlink(sp);

	rc = bind(sd, (struct sockaddr *)&addr, sizeof(addr));
	if( rc < 0 ){
		perror("bind");
		return -1;
	}

	listen(sd, 3); //allow up to 3 incoming connections to queue
	fprintf(stdout, "GHIBC_AUTH_SOCK=%s; export GHIBC_AUTH_SOCK;\n", sp);
	fprintf(stdout, "GHIBC_AGENT_PID=%d; export GHIBC_AGENT_PID;\n", pid);
	fprintf(stdout, "echo Agent pid %d\n", pid);
	while(1){
		cd = accept(sd, (struct sockaddr *)&remote, &raddrlen);

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
	gc.ibi->ufree(uk);
}

const struct __ghibli_file ghibfile = {
	.setup = __mastergen_file,
	.issue = __usergen_file,
	.keycheck = __userval_file,
	.agent = __prover_unix_agent_file,
	.pingver = __ping_verifier_file,
};
