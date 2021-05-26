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

	unsigned char un0[] = "nusa_subang_authority";
	unsigned char un1[] = "qamari_road_residents";
	unsigned char un2[] = "terrace_31";

	unsigned char cmt[160];
	unsigned char cha[64];
	unsigned char res[160];
	void *pst, *vst;

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

//-------------protocol---------------------------
	printf("----prot----\n");
	chin15.prvinit(signat, NULL, 0, &pst);
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

//-------------hier---------------------------
	void *u0, *u1, *u2;
	__vangujar19.skgen(&secret);
	__vangujar19.pkext(secret, &pubkey); //??

	printf("----h0----\n");
	__vangujar19.siggen(secret, un0, strlen(un0), &u0); //base key
	__vangujar19.sgprint(u0);
	__vangujar19.sigvrf(pubkey, u0, un0, strlen(un0), &rc);
	assert(rc == 0);

	printf("----h1----\n");
	__vangujar19.siggen(u0, un1, strlen(un1), &u1); // l1 key

	blen = __vangujar19.sgserial(u1, bptr);
	assert(blen == __vangujar19.sglen + strlen(un0) + strlen(un1) + 1);
	printf("u1 :"); ucbprint(bptr, blen); printf("\n");
	__vangujar19.sgfree(u1); u1= NULL;
	blen = __vangujar19.sgconstr(bptr, &u1);
	assert(blen == __vangujar19.sglen + strlen(un0) + strlen(un1) + 1);

	__vangujar19.sgprint(u1);
	__vangujar19.sigvrf(pubkey, u1, un1, strlen(un1), &rc);
	assert(rc == 0);

	printf("----h2----\n");
	__vangujar19.siggen(u1, un2, strlen(un2), &u2); // l1 key
	__vangujar19.sgprint(u2);
	__vangujar19.sigvrf(pubkey, u2, un2, strlen(un2), &rc);
	assert(rc == 0);
	un2[0] += 1;
	__vangujar19.sigvrf(pubkey, u2, un2, strlen(un2), &rc);
	assert(rc != 0);
	un2[0] -= 1;
	__vangujar19.sigvrf(pubkey, u2, un2, strlen(un2), &rc);
	assert(rc == 0);

	char *fqn;
	blen = __vangujar19.fqnread(u2, (unsigned char **)&fqn);
	printf("fqn :%s (%u)\n", fqn, blen);

	printf("----hprot----\n");
	vangujar19.prvinit(u2, NULL, 0, &pst); //hier no need to specify id
	vangujar19.cmtgen(&pst, cmt);
	printf("T1 :"); ucbprint(cmt, vangujar19.cmtlen); printf("\n");

	vangujar19.verinit(pubkey, fqn, blen, &vst);
	vangujar19.chagen(cmt, &vst, cha);
	printf("T2 :"); ucbprint(cha, vangujar19.chalen); printf("\n");

	vangujar19.resgen(cha, pst, res);
	printf("T3 :"); ucbprint(res, vangujar19.reslen); printf("\n");

	vangujar19.protdc(res, vst, &rc);
	assert(rc == 0); //OK
	printf("prot : %d\n",rc);

	free(fqn);
	__vangujar19.sgfree(u0);
	__vangujar19.sgfree(u1);
	__vangujar19.sgfree(u2);
	__vangujar19.skfree(secret);
	__vangujar19.pkfree(pubkey);

}
