/*
 * Test code for ibi functions
 */

#include "../core.h"
#include "../utils/bufhelp.h"
//#include "../impl/ibi.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(int argc, char *argv[]){

	void *secret;
	void *signat;
	void *pubkey;
	int rc;
	unsigned char msg[64];

	ghibcore.init(); //uses whatev backend we use

	unsigned char *cmt, *cha, *res;
	void *pst, *vst;
	int dec;

	for(int i=0;i<2;i++){
		printf("testing algo %d\n",i);
		for(int j=0;j<100;j++){
			ghibcore.randombytes(msg, 64);
			//printf("m :"); ucbprint(msg, 64); printf("\n");
			ghibcore.ibi_impls[i]->keygen(&secret);
			ghibcore.ibi_impls[i]->pkext(secret, &pubkey);

			ghibcore.ibi_impls[i]->siggen(secret, msg, strlen(msg), &signat);
			ghibcore.ibi_impls[i]->sigvrf(pubkey, signat, msg, strlen(msg), &rc);
			assert(rc == 0);

			msg[0] ^= 0x01;
			ghibcore.ibi_impls[i]->sigvrf(pubkey, signat, msg, strlen(msg), &rc);
			assert(rc < 0);

			msg[0] ^= 0x01;
			ghibcore.ibi_impls[i]->sigvrf(pubkey, signat, msg, strlen(msg), &rc);
			assert(rc == 0);

			//ghibcore.ibi_impls[i]->skprint(secret);
			//ghibcore.ibi_impls[i]->sgprint(signat);

			ghibcore.ibi_impls[i]->prvinit(signat, msg, strlen(msg), &pst);
			ghibcore.ibi_impls[i]->cmtgen(&pst, &cmt);
			//printf("T1 :"); ucbprint(cmt, ghibcore.ibi_impls[i]->cmtlen); printf("\n");

			ghibcore.ibi_impls[i]->verinit(pubkey, msg, strlen(msg), &vst);
			ghibcore.ibi_impls[i]->chagen(cmt, &vst, &cha);
			//printf("T2 :"); ucbprint(cha, ghibcore.ibi_impls[i]->chalen); printf("\n");

			ghibcore.ibi_impls[i]->resgen(cha, pst, &res);
			//printf("T3 :"); ucbprint(res, ghibcore.ibi_impls[i]->reslen); printf("\n");

			ghibcore.ibi_impls[i]->protdc(res, vst, &dec);
			//printf("prot : %d\n",dec);
			assert(dec == 0);

			free(cmt);
			free(cha);
			free(res);
			ghibcore.ibi_impls[i]->skfree(secret);
			ghibcore.ibi_impls[i]->pkfree(pubkey);
			ghibcore.ibi_impls[i]->sgfree(signat);
		}
	}

	printf("all ok\n");
}

