/*
 * Test code for ibi functions
 */

#include "../impl.h"
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

	unsigned char *bptr;
	size_t blen;

	schnorr.init(); //uses whatev backend we use

	schnorr.keygen(&secret);

	blen = schnorr.skserial(secret, &bptr);
	assert(blen == schnorr.sklen);
	printf("SK :"); ucbprint(bptr, blen); printf("\n");
	schnorr.skfree(secret);
	schnorr.skconstr(bptr, &secret);
	free(bptr);

	schnorr.pkext(secret, &pubkey);

	blen = schnorr.pkserial(pubkey, &bptr);
	assert(blen == schnorr.pklen);
	printf("PK :"); ucbprint(bptr, blen); printf("\n");
	schnorr.pkfree(pubkey);
	schnorr.pkconstr(bptr, &pubkey);
	free(bptr);

	schnorr.siggen(secret, msg, strlen(msg), &signat);

	blen = schnorr.sgserial(signat, &bptr);
	assert(blen == schnorr.sglen);
	printf("SG :"); ucbprint(bptr, blen); printf("\n");
	printf("SGL:%u\n", blen);
	schnorr.sgfree(signat);
	schnorr.sgconstr(bptr, &signat);
	free(bptr);

	schnorr.sigvrf(pubkey, signat, msg, strlen(msg), &rc);
	assert(rc == 0);
	printf("%s : %d\n",msg,rc);

	msg[0] = 'm';
	schnorr.sigvrf(pubkey, signat, msg, strlen(msg), &rc);
	assert(rc < 0);
	printf("%s : %d\n",msg,rc);

	msg[0] = 'h';
	schnorr.sigvrf(pubkey, signat, msg, strlen(msg), &rc);
	assert(rc == 0);
	printf("%s : %d\n",msg,rc);

	schnorr.skprint(secret);
	schnorr.pkprint(pubkey);
	schnorr.sgprint(signat);

	//unsigned char *cmt, *cha, *res;
	//void *pst, *vst;
	//int dec;
	//schnorr.prvinit(signat, msg, strlen(msg), &pst);
	//schnorr.cmtgen(&pst, &cmt);
	//printf("T1 :"); ucbprint(cmt, schnorr.cmtlen); printf("\n");

	//schnorr.verinit(pubkey, msg, strlen(msg), &vst);
	//schnorr.chagen(cmt, &vst, &cha);
	//printf("T2 :"); ucbprint(cha, schnorr.chalen); printf("\n");

	//schnorr.resgen(cha, pst, &res);
	//printf("T3 :"); ucbprint(res, schnorr.reslen); printf("\n");

	//schnorr.protdc(res, vst, &dec);
	//assert(dec == 0); //OK
	//printf("prot : %d\n",dec);

	//free(cmt);
	//free(cha);
	//free(res);

	schnorr.skfree(secret);
	schnorr.pkfree(pubkey);
	schnorr.sgfree(signat);
}
