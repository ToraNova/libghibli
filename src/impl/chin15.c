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

// TWIN SCHNORR IBI implementation

#include <string.h>
#include <assert.h>
#include <sodium.h>
#include "../utils/bufhelp.h"
#include "../utils/debug.h"
#include "__crypto.h"
#include "ibi.h"
#include "chin15.h"

void __chin15_prvstfree(void *state){
	struct __chin15_prvst *tmp = (struct __chin15_prvst *)state; //parse state
	sodium_free(tmp->s1);
	sodium_free(tmp->s2);
	sodium_free(tmp->nonce1);
	sodium_free(tmp->nonce2);
	memset(tmp->U, 0, RRE); //clear and free
	free(tmp->U);
	free(tmp->B2);
	free(tmp->mbuf);
	free(tmp);
}

void __chin15_verstfree(void *state){
	struct __chin15_verst *tmp = (struct __chin15_verst *)state; //parse state
	free(tmp->A);
	free(tmp->B2);
	free(tmp->c);
	free(tmp->U);
	free(tmp->NE);
	free(tmp->mbuf);
	free(tmp);
}

void __chin15_prvinit(void *vusk, const uint8_t *mbuf, size_t mlen, void **state){
	struct __chin15_sg *usk = (struct __chin15_sg *)vusk;
	struct __chin15_prvst *tmp;
	tmp = (struct __chin15_prvst *)malloc(sizeof(struct __chin15_prvst));

	//allocate and copy for mbuf
	tmp->mbuf = (uint8_t *)malloc(mlen);
	tmp->mlen = mlen;
	memcpy(tmp->mbuf, mbuf, mlen);

	//copy secrets, vusk no longer needed
	tmp->s1 = (uint8_t *)sodium_malloc(RRS);
	tmp->s2 = (uint8_t *)sodium_malloc(RRS);
	tmp->U  = (uint8_t *)malloc(RRE);
	tmp->B2 = (uint8_t *)malloc(RRE);
	memcpy( tmp->s1, usk->s1, RRS);
	memcpy( tmp->s2, usk->s2, RRS);
	memcpy( tmp->U,  usk->U, RRE);
	memcpy( tmp->B2, usk->B2, RRE); //x is not copied as it is not needed

	*state = (void *)tmp; //recast and return
}

//mbuf and mlen unused in this case, but generally it could be used
void __chin15_cmtgen(void **state, uint8_t *cmt){
	struct __chin15_prvst *tmp = (struct __chin15_prvst *)(*state); //parse state

	uint8_t tbuf[RRE]; int rc;
	tmp->nonce1 = (uint8_t *)sodium_malloc(RRS);
	tmp->nonce2 = (uint8_t *)sodium_malloc(RRS); //allocate nonce
	crypto_core_ristretto255_scalar_random(tmp->nonce1);
	crypto_core_ristretto255_scalar_random(tmp->nonce2); //sample nonce and compute cmt

	rc = crypto_scalarmult_ristretto255_base(tbuf, tmp->nonce1);
	rc += crypto_scalarmult_ristretto255(cmt, tmp->nonce2, tmp->B2);
	rc += crypto_core_ristretto255_add(cmt+RRE, tbuf, cmt);// tbuf @ RRE after cmt

	copyskip(cmt, tmp->U, 0, RRE); //send U first
	*state = (void *)tmp; //recast and return
}

void __chin15_resgen(const uint8_t *cha, void *state, uint8_t *res){
	struct __chin15_prvst *tmp = (struct __chin15_prvst *)state; //parse state
	//y1 = t1 + c s1
	crypto_core_ristretto255_scalar_mul( res, cha, tmp->s1 );
	crypto_core_ristretto255_scalar_add( res, res, tmp->nonce1 );
	//y2 = t2 + c s2
	crypto_core_ristretto255_scalar_mul( res+RRE, cha, tmp->s2 );
	crypto_core_ristretto255_scalar_add( res+RRE, res+RRE, tmp->nonce2 );
	__chin15_prvstfree(state); //critical, PLEASE FREE BEFORE RETURNING
}

void __chin15_verinit(void *vpar, const uint8_t *mbuf, size_t mlen, void **state){
	struct __chin15_pk *par = (struct __chin15_pk *)vpar; //parse mpk
	struct __chin15_verst *tmp;
	//allocate
	tmp = (struct __chin15_verst *)malloc(sizeof(struct __chin15_verst));

	//copy mbuf
	tmp->mbuf = (uint8_t *)malloc(mlen);
	memcpy(tmp->mbuf, mbuf, mlen);
	tmp->mlen = mlen;

	//copy public params
	tmp->A = (uint8_t *)malloc(RRE);
	tmp->B2 = (uint8_t *)malloc(RRE);
	memcpy(tmp->A,  par->A, RRE);
	memcpy(tmp->B2, par->B2, RRE);

	*state = (void *)tmp; //recast and return
}

//vpar unused, but generally it MAY be used
void __chin15_chagen(const uint8_t *cmt, void **state, uint8_t *cha){
	struct __chin15_verst *tmp = (struct __chin15_verst *)(*state); //parse state

	tmp->U = (uint8_t *)malloc(RRE);
	tmp->NE = (uint8_t *)malloc(RRE);

	//parse commit
	skipcopy( tmp->U,  cmt, 0, 	RRE);
	skipcopy( tmp->NE, cmt, RRE, 	RRE);

	//generate challenge
	//commit = U', V = vB where v is nonce
	tmp->c = (uint8_t *)malloc(RRS);
	//*cha = (uint8_t *)malloc(CHIN15_CHALEN); //leave it up to user to allocate
	crypto_core_ristretto255_scalar_random(tmp->c);
	memcpy(cha, tmp->c, RRS);

	*state = (void *)tmp; //recast and return
}

//main decision function for protocol
void __chin15_protdc(const uint8_t *res, void *state, int *dec){
	struct __chin15_verst *tmp = (struct __chin15_verst *)(state); //parse state

	uint8_t rhs[RRE]; uint8_t lhs[RRE]; uint8_t tbuf[RRS];
	__sodium_2rinhashexec(tmp->mbuf, tmp->mlen, tmp->U, tmp->A, rhs);

	// yB = T + c( U' - xP1 )
	*dec = crypto_scalarmult_ristretto255_base( lhs, res); //y1B1
	*dec += crypto_scalarmult_ristretto255( tbuf, res+RRS, tmp->B2); //y2B2
	*dec += crypto_core_ristretto255_add( lhs, lhs, tbuf); // lhs :y1B1 + y2B2

	*dec += crypto_scalarmult_ristretto255( rhs, rhs, tmp->A); // xA
	*dec += crypto_core_ristretto255_sub( rhs, tmp->U, rhs); // U' - xA
	*dec += crypto_scalarmult_ristretto255(rhs, tmp->c, rhs); // c(U' - xA)
	*dec += crypto_core_ristretto255_add(rhs, tmp->NE, rhs);// T + c(U' - xA)

	__chin15_verstfree(state);
	*dec += crypto_verify_32(lhs, rhs);
}

// memory allocation
struct __chin15_pk *__chin15_pkinit(void){
	struct __chin15_pk *out;
	out = (struct __chin15_pk *)malloc( sizeof(struct __chin15_pk) );
	out->A = (uint8_t *)malloc( RRE );
	out->B2 = (uint8_t *)malloc( RRE );
	return out;
}
struct __chin15_sk *__chin15_skinit(void){
	struct __chin15_sk *out;
	out = (struct __chin15_sk *)malloc( sizeof(struct __chin15_sk) );
	out->hf = 0;
	out->a1 = (uint8_t *)sodium_malloc( RRS );
	out->a2 = (uint8_t *)sodium_malloc( RRS );
	out->pub = __chin15_pkinit();
	return out;
}
struct __chin15_sg *__chin15_sginit(void){
	struct __chin15_sg *out;
	out = (struct __chin15_sg *)malloc( sizeof( struct __chin15_sg) );
	out->s1 = (uint8_t *)sodium_malloc( RRS );
	out->s2 = (uint8_t *)sodium_malloc( RRS );
	out->x = (uint8_t *)malloc( RRS );
	out->U = (uint8_t *)malloc( RRE );
	out->B2 = (uint8_t *)malloc( RRE );
	return out;
}

//memory free
void __chin15_pkfree(void *in){
	//key recast
	struct __chin15_pk *ri = (struct __chin15_pk *)in;
	//free up memory
	free(ri->A);
	free(ri->B2);
	free(ri);
}
void __chin15_skfree(void *in){
	//key recast
	struct __chin15_sk *ri = (struct __chin15_sk *)in;
	//zero out the secret component
	//sodium_memzero(ri->a1, RRS);
	//sodium_memzero(ri->a2, RRS);

	//free memory
	sodium_free(ri->a1);
	sodium_free(ri->a2);
	__chin15_pkfree(ri->pub);
	free(ri);
}
void __chin15_sgfree(void *in){
	//key recast
	struct __chin15_sg *ri = (struct __chin15_sg *)in;
	//clear the components
	//sodium_memzero(ri->s, RRS); //sodium_free already does this
	//sodium_memzero(ri->x, RRS);
	//sodium_memzero(ri->U, RRE);
	//free memory
	sodium_free(ri->s1);
	sodium_free(ri->s2);
	free(ri->x);
	//free(ri->x);
	free(ri->U);
	free(ri->B2);
	free(ri);
}

void __chin15_skgen(void **out){
	int rc;
	//declare and allocate memory for key
	struct __chin15_sk *tmp = __chin15_skinit();
	uint8_t neg[RRS], tbuf[RRE];

	//sample secret a
	crypto_core_ristretto255_random( tmp->pub->B2 );
	crypto_core_ristretto255_scalar_random( tmp->a1 );
	crypto_core_ristretto255_scalar_random( tmp->a2 );

	crypto_core_ristretto255_scalar_negate(neg , tmp->a1);
	rc = crypto_scalarmult_ristretto255_base(tbuf, neg);
	crypto_core_ristretto255_scalar_negate(neg , tmp->a2);
	rc += crypto_scalarmult_ristretto255(tmp->pub->A, neg, tmp->pub->B2);
	rc += crypto_core_ristretto255_add(tmp->pub->A, tbuf, tmp->pub->A);

	memset(tbuf, 0, RRE); // zero memory
	memset(neg, 0, RRS); // zero memory
	assert(rc == 0);

	//recast and return
	*out = (void *) tmp;
}

void __chin15_pkext(void *vkey, void **out){
	//key recast
	struct __chin15_sk *key = ((struct __chin15_sk *)vkey);
	//allocate for pk
	struct __chin15_pk *tmp = __chin15_pkinit();
	size_t rs;
	memcpy(tmp->A, key->pub->A, RRE);
	memcpy(tmp->B2, key->pub->B2, RRE);
	*out = (void *)tmp;
}

void __chin15_siggen(
	void *vkey,
	const uint8_t *mbuf, size_t mlen,
	void **out
){
	int rc;
 	//key recast
	struct __chin15_sk *key = (struct __chin15_sk *)vkey;
	//declare and allocate for signature struct
	struct __chin15_sg *tmp = __chin15_sginit();

	//--------------------------TODO START
	//nonce, r and hash
	uint8_t nonce1[RRS], nonce2[RRS];

	//sample r (MUST RANDOMIZE, else secret key a will be exposed)
	crypto_core_ristretto255_scalar_random(nonce1);
	crypto_core_ristretto255_scalar_random(nonce2);

	rc = crypto_scalarmult_ristretto255_base( tmp->U, nonce1); // nP
	rc += crypto_scalarmult_ristretto255(tmp->B2, nonce2, key->pub->B2); // n2P2

	rc += crypto_core_ristretto255_add(tmp->U, tmp->U, tmp->B2);
	__sodium_2rinhashexec(mbuf, mlen, tmp->U, key->pub->A, tmp->x);

	// s1 = r1 + xa1
	crypto_core_ristretto255_scalar_mul( tmp->s1 , tmp->x, key->a1 );
	crypto_core_ristretto255_scalar_add( tmp->s1, tmp->s1, nonce1 );

	// s2 = r2 + xa2
	crypto_core_ristretto255_scalar_mul( tmp->s2 , tmp->x, key->a2 );
	crypto_core_ristretto255_scalar_add( tmp->s2, tmp->s2, nonce2 );
	assert(rc == 0);

	//store B2 on the signature
	memcpy( tmp->B2, key->pub->B2, RRE );

	//ensure zero
	memset( nonce1, 0, RRS);
	memset( nonce2, 0, RRS);

	*out = (void *) tmp;
}

void __chin15_sigvrf(
	void *vpar,
	void *vsig,
	const uint8_t *mbuf, size_t mlen,
	int *res
){
	//key recast
	uint8_t xp[RRS];
	struct __chin15_pk *par = (struct __chin15_pk *)vpar;
	struct __chin15_sg *sig = (struct __chin15_sg *)vsig;

	uint8_t tmp1[RRE]; //tmp array
	uint8_t tmp2[RRE]; //tmp array

	// U' = sB - A
	*res = crypto_scalarmult_ristretto255_base(tmp1, sig->s1); //s1B
	*res += crypto_scalarmult_ristretto255(tmp2, sig->s2, sig->B2); // s2B2
	*res += crypto_core_ristretto255_add(tmp1, tmp1, tmp2); // (s1B + s2B2)

	*res += crypto_scalarmult_ristretto255(tmp2, sig->x, par->A); // xA
	*res += crypto_core_ristretto255_add(tmp1, tmp1, tmp2); // U' = (s1B+s2B2)-xA

	__sodium_2rinhashexec(mbuf, mlen, tmp1, par->A, xp);
	//check if hash is equal to x from vsig
	*res += crypto_verify_32( xp, sig->x );
}

//debugging use only
void __chin15_pkprint(void *in){
	struct __chin15_pk *ri = (struct __chin15_pk *)in;
	printf("A :"); ucbprint(ri->A, RRE); printf("\n");
	printf("B2:"); ucbprint(ri->B2, RRE); printf("\n");
}

void __chin15_skprint(void *in){
	struct __chin15_sk *ri = (struct __chin15_sk *)in;
	printf("a1:"); ucbprint(ri->a1, RRS); printf("\n");
	printf("a2:"); ucbprint(ri->a2, RRS); printf("\n");
	__chin15_pkprint((void *)ri->pub);
}

void __chin15_sgprint(void *in){
	struct __chin15_sg *ri = (struct __chin15_sg *)in;
	printf("s1:"); ucbprint(ri->s1, RRS); printf("\n");
	printf("s2:"); ucbprint(ri->s2, RRS); printf("\n");
	printf("x :"); ucbprint(ri->x, RRS); printf("\n");
	printf("U :"); ucbprint(ri->U, RRE); printf("\n");
	printf("B2:"); ucbprint(ri->B2, RRE); printf("\n");
}

size_t __chin15_pkserial(void *in, uint8_t *out){
	size_t rs;
	struct __chin15_pk *ri = (struct __chin15_pk *)in;//recast the key
	rs = copyskip( out, ri->A, 	0, 	RRE);
	rs = copyskip( out, ri->B2, 	rs, 	RRE);
	return rs;
}

size_t __chin15_skserial(void *in, uint8_t *out){
	size_t rs;
	struct __chin15_sk *ri = (struct __chin15_sk *)in;//recast the key
	rs = copyskip( out, ri->a1, 		0, 	RRS);
	rs = copyskip( out, ri->a2, 		rs, 	RRS);
	rs = copyskip( out, ri->pub->A, 	rs, 	RRE);
	rs = copyskip( out, ri->pub->B2, 	rs, 	RRE);
	return rs;
}

size_t __chin15_sgserial(void *in, uint8_t *out){
	size_t rs;
	struct __chin15_sg *ri = (struct __chin15_sg *)in;//recast the obj
	rs = copyskip( out, ri->s1, 	0, 	RRS);
	rs = copyskip( out, ri->s2, 	rs, 	RRS);
	rs = copyskip( out, ri->x, 	rs, 	RRS);
	rs = copyskip( out, ri->U, 	rs, 	RRE);
	rs = copyskip( out, ri->B2, 	rs, 	RRE);
	return rs;
}

size_t __chin15_pkconstr(const uint8_t *in, void **out){
	size_t rs;
	struct __chin15_pk *tmp = __chin15_pkinit();
	rs = skipcopy( tmp->A,		in, 0, 	RRE);
	rs = skipcopy( tmp->B2,		in, rs, RRE);
	*out = (void *) tmp;
	return rs;
}

size_t __chin15_skconstr(const uint8_t *in, void **out){
	size_t rs;
	struct __chin15_sk *tmp = __chin15_skinit();
	rs = skipcopy( tmp->a1,		in, 0, 	RRS);
	rs = skipcopy( tmp->a2,		in, rs,	RRS);
	rs = skipcopy( tmp->pub->A,	in, rs, RRE);
	rs = skipcopy( tmp->pub->B2,	in, rs, RRE);
	*out = (void *) tmp;
	return rs;
}

size_t __chin15_sgconstr(const uint8_t *in, void **out){
	size_t rs;
	struct __chin15_sg *tmp = __chin15_sginit();
	rs = skipcopy( tmp->s1,		in, 0, 	RRS);
	rs = skipcopy( tmp->s2,		in, rs,	RRS);
	rs = skipcopy( tmp->x,		in, rs, RRS);
	rs = skipcopy( tmp->U,		in, rs, RRE);
	rs = skipcopy( tmp->B2,		in, rs, RRE);
	*out = (void *) tmp;
	return rs;
}

const ds_t __chin15 = {
	.skgen = __chin15_skgen,
	.pkext = __chin15_pkext,
	.siggen = __chin15_siggen,
	.sigvrf = __chin15_sigvrf,
	.skfree = __chin15_skfree,
	.pkfree = __chin15_pkfree,
	.sgfree = __chin15_sgfree,
	.skprint = __chin15_skprint,
	.pkprint = __chin15_pkprint,
	.sgprint = __chin15_sgprint,
	.skserial = __chin15_skserial,
	.pkserial = __chin15_pkserial,
	.sgserial = __chin15_sgserial,
	.skconstr = __chin15_skconstr,
	.pkconstr = __chin15_pkconstr,
	.sgconstr = __chin15_sgconstr,
	.sklen = CHIN15_SKLEN,
	.pklen = CHIN15_PKLEN,
	.sglen = CHIN15_SGLEN,
};

const ibi_t chin15 = {
	.ds = (ds_t *)&__chin15,
	.prvinit = __chin15_prvinit, //proto
	.cmtgen = __chin15_cmtgen,
	.resgen = __chin15_resgen,
	.verinit = __chin15_verinit,
	.chagen = __chin15_chagen,
	.protdc = __chin15_protdc,
	.cmtlen = CHIN15_CMTLEN,
	.chalen = CHIN15_CHALEN,
	.reslen = CHIN15_RESLEN,
};

// Hierarchical IBI implementation
// TODO: vangujar's scheme is incomplete.
/*

struct __vangujar19_sg {
	uint8_t hf;
	uint8_t hl; //hier level: 0-root
	uint8_t *A; //public stored here as well
	void *d; //key (chin15 design)
	uint8_t *hn; //hier name
	size_t hnlen; //hier name length
};

struct __vangujar19_sg *__vangujar19_sginit(size_t hnlen){
	struct __vangujar19_sg *out;
	out = (struct __vangujar19_sg *)malloc( sizeof( struct __vangujar19_sg) );
	out->hf = 1; //this is a hierarchical key
	out->hn = (uint8_t *)malloc(hnlen);
	out->A = (uint8_t *)malloc(RRE);
	out->hnlen = hnlen;
	return out;
};

void __vangujar19_sgfree(void *in){
	struct __vangujar19_sg *ri = (struct __vangujar19_sg *)in;
	__chin15.sgfree( ri->d ); //free chin15 sig
	free(ri);
}

void __vangujar19_siggen(
	void *vkey,
	const uint8_t *mbuf, size_t mlen,
	void **out
){
	int rc;
	//declare and allocate for signature struct
	struct __vangujar19_sg *tmp;

	if(!((uint8_t *)vkey)[0]) {
 		//key recast
		struct __chin15_sk *key = (struct __chin15_sk *)vkey;
		tmp = __vangujar19_sginit(mlen);
		//normal chin15 sig (the is the base of the hier
		__chin15.siggen(vkey, mbuf, mlen, &(tmp->d));
		// create signature will have hf set to 1
		tmp->hl = 0; //this is the root key (ID0)
		memcpy(tmp->hn, mbuf, mlen); //copy hier name
		memcpy(tmp->A,  key->pub->A, RRE);
	}else{
		//key recast
		struct __vangujar19_sg *key = (struct __vangujar19_sg *)vkey;
		tmp = __vangujar19_sginit(key->hnlen+mlen+1);
		tmp->hl = key->hl + 1; //hier down
		memcpy( tmp->hn, key->hn, key->hnlen);
		(tmp->hn)[key->hnlen] = '.'; //hier separator
		memcpy( (tmp->hn+key->hnlen+1), mbuf, mlen);

		struct __chin15_sg *ri = __chin15_sginit();
		struct __chin15_sg *rk = (struct __chin15_sg *) key->d;

		uint8_t nonce1[RRS], nonce2[RRS];
		//sample r (MUST RANDOMIZE, else secret key a will be exposed)
		crypto_core_ristretto255_scalar_random(nonce1);
		crypto_core_ristretto255_scalar_random(nonce2);
		crypto_core_ristretto255_scalar_add(nonce1, rk->s1, nonce1);
		crypto_core_ristretto255_scalar_add(nonce2, rk->s2, nonce2);

		rc = crypto_scalarmult_ristretto255_base( ri->U, nonce1); // nP
		rc += crypto_scalarmult_ristretto255(ri->B2, nonce2, rk->B2); // n2P2
		rc += crypto_core_ristretto255_add(ri->U, ri->U, ri->B2);

		__sodium_2rinhashexec(tmp->hn, tmp->hnlen, ri->U, key->A, ri->x);
		printf("----U :"); ucbprint(ri->U, RRE); printf("\n");
		printf("----A :"); ucbprint(key->A, RRE); printf("\n");
		printf("----mb:%s\n", tmp->hn);

		// s1 = r1 + xa1
		crypto_core_ristretto255_scalar_add( ri->s1 , ri->x, rk->s1 );
		crypto_core_ristretto255_scalar_add( ri->s1, ri->s1, nonce1 );

		// s2 = r2 + xa2
		crypto_core_ristretto255_scalar_add( ri->s2 , ri->x, rk->s2 );
		crypto_core_ristretto255_scalar_add( ri->s2, ri->s2, nonce2 );
		assert(rc == 0);

		//store B2 and A on the signature
		memcpy( ri->B2, rk->B2, RRE );
		memcpy( tmp->A, key->A, RRE );
		tmp->d = ri; //assign signature into

		//ensure zero
		memset( nonce1, 0, RRS);
		memset( nonce2, 0, RRS);
	}
	*out = (void *) tmp;
}

void __vangujar19_sigvrf(
	void *vpar,
	void *vsig,
	const uint8_t *mbuf, size_t mlen,
	int *res
){
	struct __vangujar19_sg *sig = (struct __vangujar19_sg *)vsig;

	if(sig->hl < 1){
		__chin15.sigvrf(vpar, (void *)(sig->d), mbuf, mlen, res);
	}else{
		__chin15.sigvrf(vpar, (void *)(sig->d), sig->hn, sig->hnlen, res);
	}
}

void __vangujar19_sgprint(void *in){
	struct __vangujar19_sg *ri = (struct __vangujar19_sg *)in;
	printf("hl:%u hnlen:%u\n", ri->hl, ri->hnlen);
	printf("hn:%s\n", ri->hn);
	__chin15.sgprint(ri->d);
	printf("A :"); ucbprint(ri->A, RRE); printf("\n");
}

const ds_t __vangujar19 = {
	.skgen = __chin15_skgen,
	.pkext = __chin15_pkext,
	.siggen = __vangujar19_siggen, //hc
	.sigvrf = __vangujar19_sigvrf, //hc
	.skfree = __chin15_skfree,
	.pkfree = __chin15_pkfree,
	.sgfree = __chin15_sgfree,
	.skprint = __chin15_skprint,
	.pkprint = __chin15_pkprint,
	.sgprint = __vangujar19_sgprint,
	.skserial = __chin15_skserial,
	.pkserial = __chin15_pkserial,
	.sgserial = __chin15_sgserial,
	.skconstr = __chin15_skconstr,
	.pkconstr = __chin15_pkconstr,
	.sgconstr = __chin15_sgconstr,
	.sklen = CHIN15_SKLEN,
	.pklen = CHIN15_PKLEN,
	.sglen = CHIN15_SGLEN,
};
*/
