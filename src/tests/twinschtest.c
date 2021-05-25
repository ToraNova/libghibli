/*
 * Test code for ibi functions
 */

#include "../core.h"
#include "../utils/bufhelp.h"
//#include "../impl/ibi.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

int main(int argc, char *argv[]){

	void *secret;
	void *signat;
	void *pubkey;
	int rc;
	unsigned char msg[] = "hello world\n";

	unsigned char bptr[160];
	size_t blen;

	ghibc_init(); //doesn't matter, not using gc

	__chin15.skgen(&secret);

	blen = __chin15.skserial(secret, bptr);
	assert(blen == __chin15.sklen);
	printf("SK :"); ucbprint(bptr, blen); printf("\n");
	__chin15.skfree(secret); secret = NULL;
	__chin15.skconstr(bptr, &secret);

	__chin15.pkext(secret, &pubkey); //??

	blen = __chin15.pkserial(pubkey, bptr);
	assert(blen == __chin15.pklen);
	printf("PK :"); ucbprint(bptr, blen); printf("\n");
	__chin15.pkfree(pubkey);
	__chin15.pkconstr(bptr, &pubkey);

	__chin15.siggen(secret, msg, strlen(msg), &signat);

	blen = __chin15.sgserial(signat, bptr);
	assert(blen == __chin15.sglen);
	printf("SG :"); ucbprint(bptr, blen); printf("\n");
	printf("SGL:%u\n", blen);
	__chin15.sgfree(signat);
	__chin15.sgconstr(bptr, &signat);

	__chin15.sigvrf(pubkey, signat, msg, strlen(msg), &rc);
	assert(rc == 0);
	printf("%s : %d\n",msg,rc);

	msg[0] = 'm';
	__chin15.sigvrf(pubkey, signat, msg, strlen(msg), &rc);
	assert(rc < 0);
	printf("%s : %d\n",msg,rc);

	msg[0] = 'h';
	__chin15.sigvrf(pubkey, signat, msg, strlen(msg), &rc);
	assert(rc == 0);
	printf("%s : %d\n",msg,rc);

	__chin15.skprint(secret);
	__chin15.pkprint(pubkey);
	__chin15.sgprint(signat);

	unsigned char cmt[160];
	unsigned char cha[64];
	unsigned char res[160];
	void *pst, *vst;

	chin15.prvinit(signat, msg, strlen(msg), &pst);
	chin15.cmtgen(&pst, cmt);
	printf("T1 :"); ucbprint(cmt, chin15.cmtlen); printf("\n");

	chin15.verinit(pubkey, msg, strlen(msg), &vst);
	chin15.chagen(cmt, &vst, cha);
	printf("T2 :"); ucbprint(cha, chin15.chalen); printf("\n");

	chin15.resgen(cha, pst, res);
	printf("T3 :"); ucbprint(res, chin15.reslen); printf("\n");

	chin15.protdc(res, vst, &rc);
	assert(rc == 0); //OK
	printf("prot : %d\n",rc);

	__chin15.skfree(secret);
	__chin15.pkfree(pubkey);
	__chin15.sgfree(signat);
}