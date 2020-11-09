/*
 * Test code for ibi functions
 */

#include "../core.h"
#include "../utils/bufhelp.h"
//#include "../impl/ibi.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]){

	void *secret;
	void *signat;
	void *pubkey;
	int rc;
	unsigned char msg[] = "hello world\n";

	cryptoinit(); //uses whatev backend we use

	ghibcore.ibi_impls[IBIAL_SCHIBI]->randkeygen(&secret);
	ghibcore.ibi_impls[IBIAL_SCHIBI]->getpubkey(secret, &pubkey);

	ghibcore.ibi_impls[IBIAL_SCHIBI]->signatgen(secret, msg, strlen(msg), &signat);
	ghibcore.ibi_impls[IBIAL_SCHIBI]->signatchk(pubkey, signat, msg, strlen(msg), &rc);
	printf("%s : %d\n",msg,rc);

	msg[0] = 'm';
	ghibcore.ibi_impls[IBIAL_SCHIBI]->signatchk(pubkey, signat, msg, strlen(msg), &rc);
	printf("%s : %d\n",msg,rc);

	msg[0] = 'h';
	ghibcore.ibi_impls[IBIAL_SCHIBI]->signatchk(pubkey, signat, msg, strlen(msg), &rc);
	printf("%s : %d\n",msg,rc);

	ghibcore.ibi_impls[IBIAL_SCHIBI]->skprint(secret);
	ghibcore.ibi_impls[IBIAL_SCHIBI]->sgprint(signat);

	unsigned char *cmt, *cha, *res;
	void *pst, *vst;
	int dec;
	ghibcore.ibi_impls[IBIAL_SCHIBI]->prvinit(signat, msg, strlen(msg), &pst);
	ghibcore.ibi_impls[IBIAL_SCHIBI]->cmtgen(&pst, &cmt);
	printf("T1 :"); ucbprint(cmt, ghibcore.ibi_impls[IBIAL_SCHIBI]->cmtlen); printf("\n");

	ghibcore.ibi_impls[IBIAL_SCHIBI]->verinit(pubkey, msg, strlen(msg), &vst);
	ghibcore.ibi_impls[IBIAL_SCHIBI]->chagen(cmt, &vst, &cha);
	printf("T2 :"); ucbprint(cha, ghibcore.ibi_impls[IBIAL_SCHIBI]->chalen); printf("\n");

	ghibcore.ibi_impls[IBIAL_SCHIBI]->resgen(cha, pst, &res);
	printf("T3 :"); ucbprint(res, ghibcore.ibi_impls[IBIAL_SCHIBI]->reslen); printf("\n");

	ghibcore.ibi_impls[IBIAL_SCHIBI]->protdc(res, vst, &dec);
	printf("prot : %d\n",dec);

	free(cmt);
	free(cha);
	free(res);

	ghibcore.ibi_impls[IBIAL_SCHIBI]->skfree(secret);
	ghibcore.ibi_impls[IBIAL_SCHIBI]->pkfree(pubkey);
	ghibcore.ibi_impls[IBIAL_SCHIBI]->sgfree(signat);
}

