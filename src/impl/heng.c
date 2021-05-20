/*
 * Copyright (c) 2020 Chia Jason
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <string.h>
#include <assert.h>
#include <sodium.h>
#include "../utils/bufhelp.h"
#include "../utils/debug.h"
#include "__crypto.h"
#include "schnorr.h"
#include "ibi.h"

#define CMTLEN (2*RRE)
#define CHALEN RRS
#define RESLEN RRS

//prover and verifier protocol states
struct __schibi_prvst {
	unsigned char *s;
	unsigned char *U; //precomputation
	unsigned char *nonce;
	unsigned char *mbuf;
	size_t mlen;
};

struct __schibi_verst {
	unsigned char *A;
	unsigned char *c;
	unsigned char *U; //precompute
	unsigned char *V; //nonceB
	unsigned char *mbuf;
	size_t mlen;
};

void __schibi_prvstfree(void *state){
	struct __schibi_prvst *tmp = (struct __schibi_prvst *)state; //parse state
	sodium_free(tmp->s);
	sodium_free(tmp->nonce);
	memset(tmp->U, 0, RRE);//clear and free
	free(tmp->U);
	free(tmp->mbuf);
	free(tmp);
}

void __schibi_verstfree(void *state){
	struct __schibi_verst *tmp = (struct __schibi_verst *)state; //parse state
	free(tmp->A);
	free(tmp->c);
	free(tmp->U);
	free(tmp->V);
	free(tmp->mbuf);
	free(tmp);
}

void __schibi_ukgen(
	void *vkey,
	const unsigned char *mbuf, size_t mlen,
	void **out
){
	struct __ibi_uk *tmp = __ibi_ukinit(mlen);
	__schnorr_signatgen(vkey, mbuf, mlen, &(tmp->k));
	memcpy(tmp->m, mbuf, mlen);
	*out = (void *) tmp;
}

void __schibi_ukfree(void *in){
	struct __ibi_uk *ri = (struct __ibi_uk *)in;
	__schnorr_sgfree( ri->k );
	free(ri->m);
	sodium_free(ri);
}

void __schibi_ukprint(void *in){
	struct __ibi_uk *ri = (struct __ibi_uk *)in;
	__schnorr_sgprint((void *)ri->k);
	printf("m :%s\n", ri->m);
}

size_t __schibi_ukserial(void *in, unsigned char **out){
	size_t rs;
	struct __ibi_uk *ri = (struct __ibi_uk *)in;//recast the obj
	//set size and allocate
	unsigned char *tmp;
	rs = __schnorr_sgserial(ri->k, &tmp);
	*out = (unsigned char *)malloc( rs + ri->mlen );
	rs = copyskip( *out, tmp, 	0, 	rs);
	rs = copyskip( *out, ri->m, 	rs, 	ri->mlen);
	free(tmp);
	return rs;
}

size_t __schibi_ukconstr(const unsigned char *in, size_t len, void **out){
	size_t rs;
	//allocate memory for seckey
	int mlen = len - SCHNORR_SGLEN;
	struct __ibi_uk *tmp = __ibi_ukinit(mlen);
	rs = __schnorr_sgconstr(in, &(tmp->k));
	rs = skipcopy( tmp->m,   in, rs, mlen);
	*out = (void *) tmp;
	return rs;
}

void __schibi_validate(void *vpar, void *vusk, int *res){
	struct __ibi_uk *usk = (struct __ibi_uk *)vusk; //parse usk
	struct __schnorr_sg *sma = (struct __schnorr_sg *)(usk->k);
	__schnorr_signatchk(vpar, usk->k, usk->m, usk->mlen, res);
}

size_t __schibi_getukid(void *vusk, unsigned char **out){
	struct __ibi_uk *usk = (struct __ibi_uk *)vusk; //parse usk
	*out = (unsigned char *)malloc( usk->mlen );
	memcpy(*out, usk->m, usk->mlen);
	return usk->mlen;
}

void __schibi_prvinit(void *vusk, void **state){
	struct __ibi_uk *usk = (struct __ibi_uk *)vusk; //parse usk
	struct __schnorr_sg *sma = (struct __schnorr_sg *)(usk->k);
	struct __schibi_prvst *tmp;
	tmp = (struct __schibi_prvst *)malloc(sizeof(struct __schibi_prvst));

	//allocate and copy for mbuf
	tmp->mbuf = (unsigned char *)malloc(usk->mlen);
	tmp->mlen = usk->mlen;
	memcpy(tmp->mbuf, usk->m, tmp->mlen);

	//copy secrets, vusk no longer needed
	tmp->s = (unsigned char *)sodium_malloc(RRS);
	memcpy( tmp->s, sma->s, RRS);
	tmp->U = (unsigned char *)malloc(RRE);
	memcpy( tmp->U, sma->U, RRE); //x is not copied as it is not needed

	*state = (void *)tmp; //recast and return
}

//mbuf and mlen unused in this case, but generally it could be used
void __schibi_cmtgen(void **state, unsigned char **cmt){
	struct __schibi_prvst *tmp = (struct __schibi_prvst *)(*state); //parse state

	unsigned char tbuf[RRE]; int rc;
	tmp->nonce = (unsigned char *)sodium_malloc(RRS); //allocate nonce

	crypto_core_ristretto255_scalar_random(tmp->nonce); //sample nonce and compute cmt
	rc = crypto_scalarmult_ristretto255_base(tbuf , tmp->nonce);
	assert(rc == 0);
	//create commit message
	*cmt = (unsigned char *)malloc(CMTLEN); //commit = U, V = vB where v is nonce
	copyskip( *cmt, tmp->U, 	0, 	RRE);
	copyskip( *cmt, tbuf, 		RRE, 	RRE);
	*state = (void *)tmp; //recast and return
}

void __schibi_resgen(const unsigned char *cha, void *state, unsigned char **res){
	struct __schibi_prvst *tmp = (struct __schibi_prvst *)state; //parse state
	//allocate mem for response
	*res = (unsigned char *)malloc(RESLEN); //response : y=t+cs where t is nonce

	//compute response
	crypto_core_ristretto255_scalar_mul( *res, cha, tmp->s ); //
	crypto_core_ristretto255_scalar_add( *res, *res, tmp->nonce );
	__schibi_prvstfree(state); //critical, PLEASE FREE BEFORE RETURNING
}

void __schibi_verinit(void *vpar, const unsigned char *mbuf, size_t mlen, void **state){
	struct __schnorr_pk *par = (struct __schnorr_pk *)vpar; //parse mpk
	struct __schibi_verst *tmp;
	//allocate
	tmp = (struct __schibi_verst *)malloc(sizeof(struct __schibi_verst));

	//copy mbuf
	tmp->mbuf = (unsigned char *)malloc(mlen);
	memcpy(tmp->mbuf, mbuf, mlen);
	tmp->mlen = mlen;

	//copy public params
	tmp->A = (unsigned char *)malloc(RRE);
	memcpy(tmp->A, par->A, RRE);

	*state = (void *)tmp; //recast and return
}

//vpar unused, but generally it MAY be used
void __schibi_chagen(const unsigned char *cmt, void **state, unsigned char **cha){
	struct __schibi_verst *tmp = (struct __schibi_verst *)(*state); //parse state

	tmp->U = (unsigned char *)malloc(RRE);
	tmp->V = (unsigned char *)malloc(RRE);

	//parse commit
	skipcopy( tmp->U, cmt, 0, 	RRE);
	skipcopy( tmp->V, cmt, RRE, 	RRE);

	//generate challenge
	//commit = U', V = vB where v is nonce
	tmp->c = (unsigned char *)malloc(RRS);
	*cha = (unsigned char *)malloc(CHALEN);
	crypto_core_ristretto255_scalar_random(tmp->c);
	memcpy(*cha, tmp->c, RRS);

	*state = (void *)tmp; //recast and return
}

//main decision function for protocol
void __schibi_protdc(const unsigned char *res, void *state, int *dec){
	struct __schibi_verst *tmp = (struct __schibi_verst *)(state); //parse state

	unsigned char rhs[RRE]; unsigned char lhs[RRE]; unsigned char tbuf[RRS];
	__schnorr_hashexec(tmp->mbuf, tmp->mlen, tmp->U, tmp->A, tbuf);

	// yB = T + c( U' - xP1 )
	*dec += crypto_scalarmult_ristretto255_base(lhs, res); // yB
	*dec = crypto_scalarmult_ristretto255( rhs, tbuf, tmp->A); // xP1
	*dec += crypto_core_ristretto255_sub( rhs, tmp->U, rhs); // U' - xP1
	*dec += crypto_scalarmult_ristretto255( rhs, tmp->c, rhs); // c( U' - xP1 )
	*dec += crypto_core_ristretto255_add( rhs, tmp->V, rhs);// T + c(U' - xP1)

	__schibi_verstfree(state);
	*dec += crypto_verify_32(lhs, rhs);
}

const struct __ibi schnorr_ibi = {
	.init = __sodium_init,
	.keygen = __schnorr_randkeygen,
	.pkext = __schnorr_getpubkey,
	.skfree = __schnorr_skfree,
	.pkfree = __schnorr_pkfree,
	.skprint = __schnorr_skprint,
	.pkprint = __schnorr_pkprint,
	.sklen = SCHNORR_SKLEN,
	.pklen = SCHNORR_PKLEN,
	.ukbaselen = SCHNORR_SGLEN,
	.skserial = __schnorr_skserial,
	.pkserial = __schnorr_pkserial,
	.skconstr = __schnorr_skconstr,
	.pkconstr = __schnorr_pkconstr,
	.issue = __schibi_ukgen, //ukgen
	.validate = __schibi_validate,
	.idext = __schibi_getukid,
	.ukfree = __schibi_ukfree,
	.ukprint = __schibi_ukprint,
	.ukserial = __schibi_ukserial,
	.ukconstr = __schibi_ukconstr,
	.prvinit = __schibi_prvinit, //proto
	.cmtgen = __schibi_cmtgen,
	.resgen = __schibi_resgen,
	.verinit = __schibi_verinit,
	.chagen = __schibi_chagen,
	.protdc = __schibi_protdc,
	.cmtlen = CMTLEN,
	.chalen = CHALEN,
	.reslen = RESLEN,
};
