/*
 * Test code for ibi functions
 */

#include "../impl.h"
#include "../utils/bufhelp.h"
//#include "../impl/ibi.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]){

	void *secret;
	void *signat;
	void *pubkey;
	int rc;
	unsigned char msg[] = "hello world\n";

	schibi.init(); //uses whatev backend we use

	schibi.keygen(&secret);
	schibi.pkext(secret, &pubkey);

	schibi.siggen(secret, msg, strlen(msg), &signat);
	schibi.sigvrf(pubkey, signat, msg, strlen(msg), &rc);
	printf("%s : %d\n",msg,rc);

	msg[0] = 'm';
	schibi.sigvrf(pubkey, signat, msg, strlen(msg), &rc);
	printf("%s : %d\n",msg,rc);

	msg[0] = 'h';
	schibi.sigvrf(pubkey, signat, msg, strlen(msg), &rc);
	printf("%s : %d\n",msg,rc);

	schibi.skprint(secret);
	schibi.sgprint(signat);

	unsigned char *cmt, *cha, *res;
	void *pst, *vst;
	int dec;
	schibi.prvinit(signat, msg, strlen(msg), &pst);
	schibi.cmtgen(&pst, &cmt);
	printf("T1 :"); ucbprint(cmt, schibi.cmtlen); printf("\n");

	schibi.verinit(pubkey, msg, strlen(msg), &vst);
	schibi.chagen(cmt, &vst, &cha);
	printf("T2 :"); ucbprint(cha, schibi.chalen); printf("\n");

	schibi.resgen(cha, pst, &res);
	printf("T3 :"); ucbprint(res, schibi.reslen); printf("\n");

	schibi.protdc(res, vst, &dec);
	printf("prot : %d\n",dec);

	free(cmt);
	free(cha);
	free(res);

	schibi.skfree(secret);
	schibi.pkfree(pubkey);
	schibi.sgfree(signat);
}

