/*
 * Test code for ds functions
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
	void *sg;
	void *pk;
	int rc;
	unsigned char msg[64];

	unsigned char buf[160];
	size_t alen, blen;
	char *aptr;
	unsigned char *bptr;

	for(int i=0;i<1;i++){
		printf("testing ds-algo %d\n",i);
		//gc.init(i);
		ghibc_init(i); //uses whatev backend we use
		for(int j=0;j<100;j++){
			gc.randbytes(msg, 64);
			//keygen
			gc.ds->keygen(i, &sk, &pk);

			// serialize sk
			blen = gc.ds->kserial(sk, buf);
			assert(blen == gc.ds->sklen(i));
			gc.ds->kfree(sk); sk = NULL; //free

			// to base64 and back (testing)
			aptr = b64_encode(buf, blen, BASE64_DEFAULT_WRAP);
			bptr = b64_decode(aptr);
			blen = b64_decoded_size(aptr);
			free(aptr);

			// unserialize
			blen = gc.ds->kconstr(bptr, &sk);
			assert(blen == gc.ds->sklen(i));
			assert(gc.ds->karead(sk) == i);
			assert(gc.ds->ktread(sk) == 0);
			free(bptr);

			//gc.ds->kprint(sk);

			// serialize pk
			blen = gc.ds->kserial(pk, buf);
			assert(blen == gc.ds->pklen(i));
			gc.ds->kfree(pk); pk = NULL; //free

			//unserialize pk
			blen = gc.ds->kconstr(buf, &pk);
			assert(blen == gc.ds->pklen(i));
			assert(gc.ds->karead(pk) == i);
			assert(gc.ds->ktread(pk) == 1);

			//gc.ds->kprint(pk);

			// sign
			gc.ds->sign(sk, msg, strlen(msg), &sg);

			blen = gc.ds->rserial(sg, buf);
			assert(blen == gc.ds->sglen(i));
			gc.ds->rfree(sg); sg = NULL;

			blen = gc.ds->rconstr(buf, &sg);
			assert(blen == gc.ds->sglen(i));
			assert(gc.ds->raread(sg) == i);

			gc.ds->verify(pk, sg, msg, strlen(msg), &rc);
			assert(rc==0);
			gc.ds->rfree(sg); sg = NULL;

			buf[1] ^= 1; //flip 1 bit
			blen = gc.ds->rconstr(buf, &sg);

			gc.ds->verify(pk, sg, msg, strlen(msg), &rc);
			assert(rc!=0);

			gc.ds->rfree(sg); sg = NULL;
			buf[1] ^= 1; //flip 1 bit
			blen = gc.ds->rconstr(buf, &sg);

			gc.ds->verify(pk, sg, msg, strlen(msg), &rc);
			assert(rc==0);

			gc.ds->kfree(sk);
			gc.ds->kfree(pk);
			gc.ds->rfree(sg);
		}
	}

	printf("all ok\n");
}

