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
#include "sodium_macro.h"
#include "ibi.h"

#define __SCHIBI_CMTLEN 2*RRE
#define __SCHIBI_CHALEN RRS
#define __SCHIBI_RESLEN RRS

struct __schibi_pk {
	unsigned char *A;
};

struct __schibi_sk {
	struct __schibi_pk *pub;
	unsigned char *a;
};

struct __schibi_sg {
	unsigned char *s;
	unsigned char *x;
	unsigned char *U; //precomputation
};

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

void __schibi_randkeygen(void **out){
	//declare and allocate memory for key
	int rc; struct __schibi_sk *tmp;
	tmp = (struct __schibi_sk *)malloc( sizeof(struct __schibi_sk) );
	//allocate memory for pubkey
	tmp->pub = (struct __schibi_pk *)malloc( sizeof(struct __schibi_pk) );
	unsigned char neg[RRS];

	tmp->a = (unsigned char *)sodium_malloc( RRS );
	tmp->pub->A = (unsigned char *)malloc( RRE );

	//sample secret a
	crypto_core_ristretto255_scalar_random( tmp->a );

	crypto_core_ristretto255_scalar_negate(neg , tmp->a);
	rc = crypto_scalarmult_ristretto255_base(
			tmp->pub->A,
			neg
			); // A = aB
	assert(rc == 0);

	//recast and return
	*out = (void *) tmp;
}

void __schibi_getpubkey(void *vkey, void **out){
	struct __schibi_pk *tmp;
	struct __schibi_sk *key = ((struct __schibi_sk *)vkey);
	tmp = (struct __schibi_pk *)malloc( sizeof(struct __schibi_pk) );
	tmp->A = (unsigned char *)malloc( RRE );
	copyskip(tmp->A, key->pub->A, 0, RRE);
	*out = (void *)tmp;
}

//assumes arr is alloc with RRS
void __schibi_hashexec(
	const unsigned char *mbuf, size_t mlen,
	unsigned char *ubuf,
	unsigned char *vbuf,
	unsigned char *oarr
){
	crypto_hash_sha512_state state;
	unsigned char tbuf[RRH]; //hash
	//compute hash
	crypto_hash_sha512_init( &state );
	crypto_hash_sha512_update( &state, mbuf, mlen);
	crypto_hash_sha512_update( &state, ubuf, RRE);
	crypto_hash_sha512_update( &state, vbuf, RRE);
	crypto_hash_sha512_final( &state, tbuf);
	crypto_core_ristretto255_scalar_reduce(
		oarr, (const unsigned char *)tbuf
	);
}

void __schibi_signatgen(
	void *vkey,
	const unsigned char *mbuf, size_t mlen,
	void **out
){
	//key recast
	int rc; struct __schibi_sg *tmp;
	struct __schibi_sk *key = (struct __schibi_sk *)vkey;
	//declare and allocate for signature struct
	tmp = (struct __schibi_sg *)malloc( sizeof( struct __schibi_sg) );

	//--------------------------TODO START
	//nonce, r and hash
	unsigned char nonce[RRS];

	//allocate for components
	tmp->s = (unsigned char *)sodium_malloc( RRS );
	tmp->x = (unsigned char *)sodium_malloc( RRS );
	tmp->U = (unsigned char *)malloc( RRE );

	//sample r (MUST RANDOMIZE, else secret key a will be exposed)
	crypto_core_ristretto255_scalar_random(nonce);

	rc = crypto_scalarmult_ristretto255_base(
			tmp->U,
			nonce
			); // U = rB
	assert(rc == 0);

	__schibi_hashexec(mbuf, mlen, tmp->U, key->pub->A, tmp->x);

	// s = r + xa
	crypto_core_ristretto255_scalar_mul( tmp->s , tmp->x, key->a );
	crypto_core_ristretto255_scalar_add( tmp->s, tmp->s, nonce );
	//--------------------------TODO END

	*out = (void *) tmp;
}

void __schibi_signatchk(
	void *vpar,
	void *vsig,
	const unsigned char *mbuf, size_t mlen,
	int *res
){
	//key recast
	unsigned char xp[RRS];
	struct __schibi_pk *par = (struct __schibi_pk *)vpar;
	struct __schibi_sg *sig = (struct __schibi_sg *)vsig;

	//--------------------------TODO START
	unsigned char tmp1[RRE]; //tmp array
	unsigned char tmp2[RRE]; //tmp array

	// U' = sB - A
	*res = crypto_scalarmult_ristretto255_base(
			tmp1,
			sig->s
			);
	*res += crypto_scalarmult_ristretto255(
			tmp2,
			sig->x,
			par->A
			);
	*res += crypto_core_ristretto255_add( tmp1, tmp1, tmp2 ); //tmp3 U'

	__schibi_hashexec(mbuf, mlen, tmp1, par->A, xp);

	//check if hash is equal to x from vsig
	*res += crypto_verify_32( xp, sig->x );
	//--------------------------TODO END
}

//destroy secret key
void __schibi_pkfree(void *in){
	//key recast
	struct __schibi_pk *ri = (struct __schibi_pk *)in;
	//free up memory
	free(ri->A);
	free(ri);
}

void __schibi_skfree(void *in){
	//key recast
	struct __schibi_sk *ri = (struct __schibi_sk *)in;
	//zero out the secret component
	sodium_memzero(ri->a, RRS);

	//free memory
	sodium_free(ri->a);
	__schibi_pkfree(ri->pub);
	free(ri);
}

void __schibi_sgfree(void *in){
	//key recast
	struct __schibi_sg *ri = (struct __schibi_sg *)in;
	//clear the components
	//sodium_memzero(ri->s, RRS);
	//sodium_memzero(ri->x, RRS);
	sodium_memzero(ri->U, RRE);
	//free memory
	sodium_free(ri->s);
	sodium_free(ri->x);
	//free(ri->x);
	free(ri->U);
	free(ri);
}

//debugging use only
void __schibi_pkprint(void *in){
	struct __schibi_pk *ri = (struct __schibi_pk *)in;
	printf("A :"); ucbprint(ri->A, RRE); printf("\n");
}

void __schibi_skprint(void *in){
	struct __schibi_sk *ri = (struct __schibi_sk *)in;
	printf("a :"); ucbprint(ri->a, RRS); printf("\n");
	__schibi_pkprint((void *)ri->pub);
}

void __schibi_sgprint(void *in){
	struct __schibi_sg *ri = (struct __schibi_sg *)in;
	printf("s :"); ucbprint(ri->s, RRS); printf("\n");
	printf("x :"); ucbprint(ri->x, RRS); printf("\n");
	printf("U :"); ucbprint(ri->U, RRE); printf("\n");
}

void __schibi_prvinit(void *vusk, const unsigned char *mbuf, size_t mlen, void **state){
	struct __schibi_sg *usk = (struct __schibi_sg *)vusk; //parse usk
	struct __schibi_prvst *tmp;
	tmp = (struct __schibi_prvst *)malloc(sizeof(struct __schibi_prvst));

	//allocate and copy for mbuf
	tmp->mbuf = (unsigned char *)malloc(mlen);
	memcpy(tmp->mbuf, mbuf, mlen);
	tmp->mlen = mlen;

	//copy secrets, vusk no longer needed
	tmp->s = (unsigned char *)sodium_malloc(RRS);
	memcpy( tmp->s, usk->s, RRS);
	tmp->U = (unsigned char *)malloc(RRE);
	memcpy( tmp->U, usk->U, RRE); //x is not copied as it is not needed

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
	*cmt = (unsigned char *)malloc(__SCHIBI_CMTLEN); //commit = U, V = vB where v is nonce
	copyskip( *cmt, tmp->U, 	0, 	RRE);
	copyskip( *cmt, tbuf, 	RRE, 	RRE);
	*state = (void *)tmp; //recast and return
}

void __schibi_resgen(const unsigned char *cha, void *state, unsigned char **res){
	struct __schibi_prvst *tmp = (struct __schibi_prvst *)state; //parse state
	//allocate mem for response
	*res = (unsigned char *)malloc(__SCHIBI_RESLEN); //response : y=t+cs where t is nonce

	//compute response
	crypto_core_ristretto255_scalar_mul( *res, cha, tmp->s ); //
	crypto_core_ristretto255_scalar_add( *res, *res, tmp->nonce );
	__schibi_prvstfree(state); //critical, PLEASE FREE BEFORE RETURNING
}

void __schibi_verinit(void *vpar, const unsigned char *mbuf, size_t mlen, void **state){
	struct __schibi_pk *par = (struct __schibi_pk *)vpar; //parse mpk
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
	*cha = (unsigned char *)malloc(__SCHIBI_CHALEN);
	crypto_core_ristretto255_scalar_random(tmp->c);
	memcpy(*cha, tmp->c, RRS);

	*state = (void *)tmp; //recast and return
}

//main decision function for protocol
void __schibi_protdc(const unsigned char *res, void *state, int *dec){
	struct __schibi_verst *tmp = (struct __schibi_verst *)(state); //parse state

	unsigned char rhs[RRE]; unsigned char lhs[RRE]; unsigned char tbuf[RRS];
	__schibi_hashexec(tmp->mbuf, tmp->mlen, tmp->U, tmp->A, tbuf);

	// yB = T + c( U' - xP1 )
	*dec += crypto_scalarmult_ristretto255_base(lhs, res); // yB
	*dec = crypto_scalarmult_ristretto255( rhs, tbuf, tmp->A); // xP1
	*dec += crypto_core_ristretto255_sub( rhs, tmp->U, rhs); // U' - xP1
	*dec += crypto_scalarmult_ristretto255( rhs, tmp->c, rhs); // c( U' - xP1 )
	*dec += crypto_core_ristretto255_add( rhs, tmp->V, rhs);// T + c(U' - xP1)

	__schibi_verstfree(state);
	*dec += crypto_verify_32(lhs, rhs);
}

const struct __ibi schibi = {
	.init = __crypto_init,
	.keygen = __schibi_randkeygen,
	.pkext = __schibi_getpubkey,
	.siggen = __schibi_signatgen,
	.sigvrf = __schibi_signatchk,
	.skfree = __schibi_skfree,
	.pkfree = __schibi_pkfree,
	.sgfree = __schibi_sgfree,
	.skprint = __schibi_skprint,
	.pkprint = __schibi_pkprint,
	.sgprint = __schibi_sgprint,
	.prvinit = __schibi_prvinit,
	.cmtgen = __schibi_cmtgen,
	.resgen = __schibi_resgen,
	.verinit = __schibi_verinit,
	.chagen = __schibi_chagen,
	.protdc = __schibi_protdc,
	.cmtlen = __SCHIBI_CMTLEN,
	.chalen = __SCHIBI_CHALEN,
	.reslen = __SCHIBI_RESLEN,
};


