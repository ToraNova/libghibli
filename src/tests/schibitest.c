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

	schnorr91.skgen(&secret);

	blen = schnorr91.skserial(secret, bptr);
	assert(blen == schnorr91.sklen);
	printf("SK :"); ucbprint(bptr, blen); printf("\n");
	schnorr91.skfree(secret);
	schnorr91.skconstr(bptr, &secret);

	schnorr91.pkext(secret, &pubkey);

	blen = schnorr91.pkserial(pubkey, bptr);
	assert(blen == schnorr91.pklen);
	printf("PK :"); ucbprint(bptr, blen); printf("\n");
	schnorr91.pkfree(pubkey);
	schnorr91.pkconstr(bptr, &pubkey);

	schnorr91.siggen(secret, msg, strlen(msg), &signat);

	blen = schnorr91.sgserial(signat, bptr);
	assert(blen == schnorr91.sglen);
	printf("SG :"); ucbprint(bptr, blen); printf("\n");
	printf("SGL:%u\n", blen);
	schnorr91.sgfree(signat);
	schnorr91.sgconstr(bptr, &signat);

	schnorr91.sigvrf(pubkey, signat, msg, strlen(msg), &rc);
	assert(rc == 0);
	printf("%s : %d\n",msg,rc);

	msg[0] = 'm';
	schnorr91.sigvrf(pubkey, signat, msg, strlen(msg), &rc);
	assert(rc < 0);
	printf("%s : %d\n",msg,rc);

	msg[0] = 'h';
	schnorr91.sigvrf(pubkey, signat, msg, strlen(msg), &rc);
	assert(rc == 0);
	printf("%s : %d\n",msg,rc);

	schnorr91.skprint(secret);
	schnorr91.pkprint(pubkey);
	schnorr91.sgprint(signat);

	unsigned char cmt[160];
	unsigned char cha[64];
	unsigned char res[160];
	void *pst, *vst;

	heng04.prvinit(signat, msg, strlen(msg), &pst);
	heng04.cmtgen(&pst, cmt);
	printf("T1 :"); ucbprint(cmt, heng04.cmtlen); printf("\n");

	heng04.verinit(pubkey, msg, strlen(msg), &vst);
	heng04.chagen(cmt, &vst, cha);
	printf("T2 :"); ucbprint(cha, heng04.chalen); printf("\n");

	heng04.resgen(cha, pst, res);
	printf("T3 :"); ucbprint(res, heng04.reslen); printf("\n");

	heng04.protdc(res, vst, &rc);
	assert(rc == 0); //OK
	printf("prot : %d\n",rc);

	schnorr91.skfree(secret);
	schnorr91.pkfree(pubkey);
	schnorr91.sgfree(signat);
}
