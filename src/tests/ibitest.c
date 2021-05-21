/*
 * Test code for ibi functions
 */

#include "../core.h"
#include "../utils/bufhelp.h"
#include "../utils/jbase64.h"
//#include "../impl/ibi.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(int argc, char *argv[]){

	void *sk;
	void *uk;
	void *pk;
	int rc;
	unsigned char msg[64];// = "toranova";

	unsigned char cmt[160];
	unsigned char cha[64];
	unsigned char res[160];
	void *pst, *vst;

	unsigned char buf[160];
	size_t alen, blen;
	char *aptr;
	unsigned char *bptr;

	for(int i=0;i<1;i++){
		printf("testing ibi-algo %d\n",i);
		//gc.init(i);
		ghibc_init(i); //uses whatev backend we use
		for(int j=0;j<100;j++){
			gc.randbytes(msg, 64);
			//printf("m :"); ucbprint(msg, 64); printf("\n");
			gc.ibi->setup(i, &sk, &pk);

			// serialize sk
			blen = gc.ibi->kserial(sk, buf);
			assert(blen == gc.ibi->sklen(i));
			gc.ibi->kfree(sk); sk = NULL; //free

			// to base64 and back (testing)
			aptr = b64_encode(buf, blen, BASE64_DEFAULT_WRAP);
			bptr = b64_decode(aptr);
			blen = b64_decoded_size(aptr);
			free(aptr);

			// unserialize
			blen = gc.ibi->kconstr(bptr, &sk);
			assert(blen == gc.ibi->sklen(i));
			assert(gc.ibi->karead(sk) == i);
			assert(gc.ibi->ktread(sk) == 0);
			free(bptr);

			// serialize pk
			blen = gc.ibi->kserial(pk, buf);
			assert(blen == gc.ibi->pklen(i));
			gc.ibi->kfree(pk); pk = NULL; //free

			//unserialize pk
			blen = gc.ibi->kconstr(buf, &pk);
			assert(blen == gc.ibi->pklen(i));
			assert(gc.ibi->karead(pk) == i);
			assert(gc.ibi->ktread(pk) == 1);

			gc.ibi->issue(sk, msg, 64, &uk);

			blen = gc.ibi->userial(uk, buf);
			assert(blen == gc.ibi->ukbslen(i) + 64);
			gc.ibi->ufree(uk); uk = NULL;

			blen = gc.ibi->uconstr(buf, blen, &uk);
			assert(blen == gc.ibi->ukbslen(i) + 64);
			assert(gc.ibi->uaread(uk) == i);

			gc.ibi->uiread(uk, (unsigned char **) (&aptr), &alen);
			assert(alen == 64);
			//assert(strcmp(aptr, msg) == 0);
			for(size_t i=0;i<64;i++){
				assert(((unsigned char )aptr[i]) == msg[i]);
			}

			gc.ibi->validate(pk, uk, &rc);
			assert(rc==0);
			gc.ibi->ufree(uk); uk = NULL;

			buf[1] ^= 1; //flip 1 bit
			blen = gc.ibi->uconstr(buf, blen, &uk);

			gc.ibi->validate(pk, uk, &rc);
			assert(rc!=0);

			buf[1] ^= 1; //set it back
			blen = gc.ibi->uconstr(buf, blen, &uk);
			gc.ibi->validate(pk, uk, &rc);
			assert(rc==0);

			gc.ibi->prvinit(uk, &pst);
			gc.ibi->cmtgen(&pst, cmt);
			//printf("T1 :"); ucbprint(cmt, gc.ibi->cmtlen(i)); printf("\n");

			gc.ibi->verinit(pk, msg, 64, &vst);
			gc.ibi->chagen(cmt, &vst, cha);
			//printf("T2 :"); ucbprint(cha, gc.ibi->chalen(i)); printf("\n");

			gc.ibi->resgen(cha, pst, res);
			//printf("T3 :"); ucbprint(res, gc.ibi->reslen(i)); printf("\n");

			gc.ibi->protdc(res, vst, &rc);
			//printf("prot : %d\n",rc);
			assert(rc==0);

			gc.ibi->kfree(sk);
			gc.ibi->kfree(pk);
			gc.ibi->ufree(uk);
		}
	}

	printf("all ok\n");
}

