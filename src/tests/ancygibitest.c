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

	void *msk;
	void *mpk;
	void *gsk;
	void **gusk; //assume 5 members
	void **gupk;
	void **greq;
	int rc;
	unsigned char msg[64];
	unsigned char msg2[32];
	unsigned char *cmt, *cha, *res;
	void *pst, *vst;
	int dec;

	printf("running ancy group-ibi test\n");
	cryptoinit(); //uses whatev backend we use

	int rnc = 5;
	int gmc = 5;

	for(int i=0;i<rnc;i++){
		ghibcore.randombytes(msg, 64);
		ghibcore.randombytes(msg2, 32);

		//ta keygen
		ancygibi.randkeygen(&msk);
		ancygibi.getpubkey(msk, &mpk);

		//group secret gen to group master
		ancygibi.signatgen(msk, msg, strlen(msg), &gsk);
		ancygibi.signatchk(mpk, gsk, msg, strlen(msg), &rc);
		assert(rc==0); //assure valid group key

		//derive member keys
		gusk = (void **) malloc( gmc*sizeof(void *) );
		gupk = (void **) malloc( gmc*sizeof(void *) );
		for(int j=0;j<gmc;j++){
			ancygibi.gmemkeyder(mpk, &(gusk[j]));
			ancygibi.getpubkey(gusk[j], &(gupk[j]));
		}

		//simulate, member 0 desire identification. gen signature
		greq = (void **) malloc( gmc*sizeof(void *) );
		for(int j=0;j<gmc;j++){
			ancygibi.gidreqgen( gusk[j], msg2, strlen(msg2), &(greq[j]) );
			ancygibi.gidreqchk( gupk[j], greq[j], msg2, strlen(msg2), &rc);
			assert(rc==0);
		}

		ancygibi.prvinit(gsk, msg, strlen(msg), &pst);
		ancygibi.cmtgen(&pst, &cmt);
		ancygibi.verinit(mpk, msg, strlen(msg), &vst);
		ancygibi.chagen(cmt, &vst, &cha);
		ancygibi.resgen(cha, pst, &res);
		ancygibi.protdc(res, vst, &dec);
		assert(dec==0);

		free(cmt);
		free(cha);
		free(res);
		ancygibi.skfree(msk);
		ancygibi.pkfree(mpk);
		ancygibi.sgfree(gsk);
		for(int j=0;j<gmc;j++){
			ancygibi.skfree(gusk[j]);
			ancygibi.pkfree(gupk[j]);
			ancygibi.sgfree(greq[j]);
		}
		free(gusk);
		free(gupk);
		free(greq);
	}
}

