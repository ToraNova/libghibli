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

	void *secret;
	void *user;
	void *pubkey;
	int rc;
	unsigned char msg[64];

	unsigned char *cmt, *cha, *res;
	void *pst, *vst;
	int dec;

	char *aptr; size_t alen;
	unsigned char *bptr; size_t blen;

	for(int i=0;i<1;i++){
		printf("testing algo %d\n",i);
		ghibcore.init(i); //uses whatev backend we use
		for(int j=0;j<100;j++){
			ghibcore.randombytes(msg, 64);
			//printf("m :"); ucbprint(msg, 64); printf("\n");
			ghibcore.ibi_impls[i]->keygen(&secret);

			blen = ghibcore.ibi_impls[i]->skserial(secret, &bptr);
			assert(blen == ghibcore.ibi_impls[i]->sklen);
			ghibcore.ibi_impls[i]->skfree(secret);

			aptr = b64_encode(bptr, blen, BASE64_DEFAULT_WRAP);
			free(bptr);
			bptr = b64_decode(aptr);
			blen = b64_decoded_size(aptr);
			free(aptr);

			blen = ghibcore.ibi_impls[i]->skconstr(bptr, &secret);
			assert(blen == ghibcore.ibi_impls[i]->sklen);
			free(bptr);

			ghibcore.ibi_impls[i]->pkext(secret, &pubkey);

			blen = ghibcore.ibi_impls[i]->pkserial(pubkey, &bptr);
			assert(blen == ghibcore.ibi_impls[i]->pklen);
			ghibcore.ibi_impls[i]->pkfree(pubkey);

			aptr = b64_encode(bptr, blen, BASE64_DEFAULT_WRAP);
			free(bptr);
			bptr = b64_decode(aptr);
			blen = b64_decoded_size(aptr);
			free(aptr);

			blen =ghibcore.ibi_impls[i]->pkconstr(bptr, &pubkey);
			assert(blen == ghibcore.ibi_impls[i]->pklen);
			free(bptr);

			ghibcore.ibi_impls[i]->issue(secret, msg, strlen(msg), &user);

			blen = ghibcore.ibi_impls[i]->ukserial(user, &bptr);
			assert(blen == ghibcore.ibi_impls[i]->ukbaselen + strlen(msg));
			ghibcore.ibi_impls[i]->ukfree(user);

			aptr = b64_encode(bptr, blen, BASE64_DEFAULT_WRAP);
			free(bptr);
			bptr = b64_decode(aptr);
			blen = b64_decoded_size(aptr);
			free(aptr);

			blen = ghibcore.ibi_impls[i]->ukconstr(bptr, blen, &user);
			assert(blen == ghibcore.ibi_impls[i]->ukbaselen + strlen(msg));
			free(bptr);

			ghibcore.ibi_impls[i]->validate(pubkey, user, &rc);
			assert(rc==0);

			//ghibcore.ibi_impls[i]->sigvrf(pubkey, user, msg, strlen(msg), &rc);
			//assert(rc == 0);

			//msg[0] ^= 0x01;
			//ghibcore.ibi_impls[i]->sigvrf(pubkey, user, msg, strlen(msg), &rc);
			//assert(rc < 0);

			//msg[0] ^= 0x01;
			//ghibcore.ibi_impls[i]->sigvrf(pubkey, user, msg, strlen(msg), &rc);
			//assert(rc == 0);

			//ghibcore.ibi_impls[i]->skprint(secret);
			//ghibcore.ibi_impls[i]->sgprint(user);

			ghibcore.ibi_impls[i]->prvinit(user, &pst);
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
			ghibcore.ibi_impls[i]->ukfree(user);
		}
	}

	printf("all ok\n");
}

