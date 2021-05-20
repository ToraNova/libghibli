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
#include <sodium.h>
#include <assert.h>
#include "../utils/bufhelp.h"
#include "../utils/debug.h"
#include "__crypto.h"
#include "ibi.h"

#define TSCIBI_CMTLEN 3*RRE
#define TSCIBI_CHALEN RRS
#define TSCIBI_RESLEN RRS

#define TSCIBI_PKLEN 3*RRE
#define TSCIBI_SKLEN RRS+TSCIBI_PKLEN
#define TSCIBI_SGLEN 2*RRS+2*RRE

struct __tscibi_pk {
	unsigned char *A; //y = aB
	unsigned char *A2; //y2 = aB2
	unsigned char *B2; //second base
};

struct __tscibi_sk {
	struct __tscibi_pk *pub;
	unsigned char *a;
};

struct __tscibi_sg {
	unsigned char *s;
	unsigned char *x;
	unsigned char *U; //precomputation
	unsigned char *V; //precomputation
};

//prover and verifier protocol states
struct __tscibi_prvst {
	unsigned char *s;
	unsigned char *U; //precomputation 1
	unsigned char *V; //precomputation 2
	unsigned char *nonce;
	unsigned char *mbuf;
	size_t mlen;
};

struct __tscibi_verst {
	unsigned char *A;
	unsigned char *A2;
	unsigned char *B2;
	unsigned char *c;
	unsigned char *U; //precompute1
	unsigned char *V; //precompute2
	unsigned char *W; //nonceB
	unsigned char *mbuf;
	size_t mlen;
};

//TODO: not done with freeing
void __tscibi_prvstfree(void *state){
	struct __tscibi_prvst *tmp = (struct __tscibi_prvst *)state; //parse state
	sodium_free(tmp->s);
	sodium_free(tmp->nonce);
	memset(tmp->U, 0, RRE);//clear and free
	free(tmp->U);
	memset(tmp->V, 0, RRE);//clear and free
	free(tmp->V);
	free(tmp->mbuf);
	free(tmp);
}

void __tscibi_verstfree(void *state){
	struct __tscibi_verst *tmp = (struct __tscibi_verst *)state; //parse state
	free(tmp->A);
	free(tmp->A2);
	free(tmp->B2);
	free(tmp->c);
	free(tmp->U);
	free(tmp->V);
	free(tmp->W);
	free(tmp->mbuf);
	free(tmp);
}

// memory allocation
struct __tscibi_pk *__tscibi_pkinit(void){
	struct __tscibi_pk *out;
	out = (struct __tscibi_pk *)malloc( sizeof(struct __tscibi_pk) );
	out->A = (unsigned char *)malloc( RRE );
	out->A2 = (unsigned char *)malloc( RRE );
	out->B2 = (unsigned char *)malloc( RRE );
	return out;
}
struct __tscibi_sk *__tscibi_skinit(void){
	struct __tscibi_sk *out;
	out = (struct __tscibi_sk *)sodium_malloc( sizeof(struct __tscibi_sk) );
	out->a = (unsigned char *)sodium_malloc( RRS );
	out->pub = __tscibi_pkinit();
	return out;
}
struct __tscibi_sg *__tscibi_sginit(void){
	struct __tscibi_sg *out;
	out = (struct __tscibi_sg *)sodium_malloc( sizeof( struct __tscibi_sg) );
	out->s = (unsigned char *)sodium_malloc( RRS );
	out->x = (unsigned char *)sodium_malloc( RRS );
	out->U = (unsigned char *)sodium_malloc( RRE );
	out->V = (unsigned char *)sodium_malloc( RRE );
	return out;
}

void __tscibi_randkeygen(void **out){
	//declare and allocate memory for key
	int rc;
	//allocate memory for pubkey
	struct __tscibi_sk *tmp = __tscibi_skinit();
	unsigned char neg[RRS];

	//sample secret a
	crypto_core_ristretto255_scalar_random( tmp->a );
	rc = crypto_scalarmult_ristretto255_base(
			tmp->pub->B2,
			tmp->a
			); // create a new base 2

	//sample actual secret
	crypto_core_ristretto255_scalar_random( tmp->a );
	crypto_core_ristretto255_scalar_negate(neg , tmp->a);
	rc += crypto_scalarmult_ristretto255_base(
			tmp->pub->A,
			neg
			); // A = aB


	rc += crypto_scalarmult_ristretto255(
			tmp->pub->A2,
			neg,
			tmp->pub->B2
			); // A2 = aB2

	assert(rc == 0);

	//recast and return
	*out = (void *) tmp;
}

void __tscibi_getpubkey(void *vkey, void **out){
	//key recast
	struct __tscibi_sk *key = ((struct __tscibi_sk *)vkey);
	struct __tscibi_pk *tmp = __tscibi_pkinit();

	copyskip(tmp->A, key->pub->A,  	0, RRE);
	copyskip(tmp->A2, key->pub->A2, 0, RRE);
	copyskip(tmp->B2, key->pub->B2, 0, RRE);
	*out = (void *)tmp;
}

//assumes arr is alloc with RRS
void __tscibi_hashexec(
	const unsigned char *mbuf, size_t mlen,
	unsigned char *ubuf,
	unsigned char *vbuf,
	unsigned char *wbuf,
	unsigned char *xbuf,
	unsigned char *oarr
){
	crypto_hash_sha512_state state;
	unsigned char tbuf[RRH]; //hash
	//compute hash
	crypto_hash_sha512_init( &state );
	crypto_hash_sha512_update( &state, mbuf, mlen);
	crypto_hash_sha512_update( &state, ubuf, RRE);
	crypto_hash_sha512_update( &state, vbuf, RRE);
	crypto_hash_sha512_update( &state, wbuf, RRE);
	crypto_hash_sha512_update( &state, xbuf, RRE);
	crypto_hash_sha512_final( &state, tbuf);
	crypto_core_ristretto255_scalar_reduce(
		oarr, (const unsigned char *)tbuf
	);
}

void __tscibi_signatgen(
	void *vkey,
	const unsigned char *mbuf, size_t mlen,
	void **out
){
	int rc;
	//key recast
	struct __tscibi_sk *key = (struct __tscibi_sk *)vkey;
	//declare and allocate for signature struct
	struct __tscibi_sg *tmp = __tscibi_sginit();

	//--------------------------TODO START
	//nonce, r and hash
	unsigned char nonce[RRS];

	//sample r (MUST RANDOMIZE, else secret key a will be exposed)
	crypto_core_ristretto255_scalar_random(nonce);

	rc = crypto_scalarmult_ristretto255_base(
			tmp->U,
			nonce
			); // U = rB

	rc += crypto_scalarmult_ristretto255(
			tmp->V,
			nonce,
			key->pub->B2
			); // V = rP1
	assert( rc == 0);

	__tscibi_hashexec(mbuf, mlen, tmp->U, tmp->V, key->pub->A, key->pub->A2, tmp->x);

	// s = r + xa
	crypto_core_ristretto255_scalar_mul( tmp->s , tmp->x, key->a );
	crypto_core_ristretto255_scalar_add( tmp->s, tmp->s, nonce );
	//--------------------------TODO END

	*out = (void *) tmp;
}

void __tscibi_signatchk(
	void *vpar,
	void *vsig,
	const unsigned char *mbuf, size_t mlen,
	int *res
){
	//key recast
	unsigned char xp[RRS];
	struct __tscibi_pk *par = (struct __tscibi_pk *)vpar;
	struct __tscibi_sg *sig = (struct __tscibi_sg *)vsig;

	//--------------------------TODO START
	unsigned char tmp1[RRE]; //tmp array
	unsigned char tmp2[RRE]; //tmp array
	unsigned char tmp3[RRE]; //tmp array

	// U' = sB - xP1
	*res = crypto_scalarmult_ristretto255_base(
			tmp1,
			sig->s
			);
	*res += crypto_scalarmult_ristretto255(
			tmp2,
			sig->x,
			par->A
			);
	*res += crypto_core_ristretto255_add( tmp3, tmp1, tmp2 ); //tmp3 U'

	// V' = sP1 - xP2
	*res += crypto_scalarmult_ristretto255(
			tmp1,
			sig->s,
			par->B2
			);
	*res += crypto_scalarmult_ristretto255(
			tmp2,
			sig->x,
			par->A2
			);
	*res += crypto_core_ristretto255_add( tmp2, tmp1, tmp2 ); //tmp4 V'

	__tscibi_hashexec(mbuf, mlen, tmp3, tmp2, par->A, par->A2, xp);

	//check if tmp is equal to x from obuffer
	*res += crypto_verify_32( xp, sig->x );
	//--------------------------TODO END
}

//destroy secret key
void __tscibi_pkfree(void *in){
	//key recast
	struct __tscibi_pk *ri = (struct __tscibi_pk *)in;
	//free up memory
	free(ri->A);
	free(ri->A2);
	free(ri->B2);
	free(ri);
}

void __tscibi_skfree(void *in){
	//key recast
	struct __tscibi_sk *ri = (struct __tscibi_sk *)in;
	//zero out the secret component
	sodium_memzero(ri->a, RRS);

	//free memory
	sodium_free(ri->a);
	__tscibi_pkfree(ri->pub);
	sodium_free(ri);
}

void __tscibi_sgfree(void *in){
	//key recast
	struct __tscibi_sg *ri = (struct __tscibi_sg *)in;
	//clear the components
	//sodium_memzero(ri->U, RRE);
	//sodium_memzero(ri->V, RRE);
	sodium_free(ri->s);
	sodium_free(ri->x);
	sodium_free(ri->U);
	sodium_free(ri->V);
	sodium_free(ri);
}

//debugging use only
void __tscibi_pkprint(void *in){
	struct __tscibi_pk *ri = (struct __tscibi_pk *)in;
	printf("A :"); ucbprint(ri->A, RRE); printf("\n");
	printf("A2:"); ucbprint(ri->A2, RRE); printf("\n");
	printf("B2:"); ucbprint(ri->B2, RRE); printf("\n");
}

void __tscibi_skprint(void *in){
	struct __tscibi_sk *ri = (struct __tscibi_sk *)in;
	printf("a :"); ucbprint(ri->a, RRS); printf("\n");
	__tscibi_pkprint((void *)ri->pub);
}

void __tscibi_sgprint(void *in){
	struct __tscibi_sg *ri = (struct __tscibi_sg *)in;
	printf("s :"); ucbprint(ri->s, RRS); printf("\n");
	printf("x :"); ucbprint(ri->x, RRS); printf("\n");
	printf("U :"); ucbprint(ri->U, RRE); printf("\n");
	printf("V :"); ucbprint(ri->V, RRE); printf("\n");
}

void __tscibi_prvinit(void *vusk, const unsigned char *mbuf, size_t mlen, void **state){
	struct __tscibi_sg *usk = (struct __tscibi_sg *)vusk; //parse usk
	struct __tscibi_prvst *tmp;
	tmp = (struct __tscibi_prvst *)malloc(sizeof(struct __tscibi_prvst));

	//allocate and copy for mbuf
	tmp->mbuf = (unsigned char *)malloc(mlen);
	memcpy(tmp->mbuf, mbuf, mlen);
	tmp->mlen = mlen;

	//copy secrets, vusk no longer needed
	tmp->s = (unsigned char *)sodium_malloc(RRS);
	memcpy( tmp->s, usk->s, RRS);
	tmp->U = (unsigned char *)malloc(RRE);
	memcpy( tmp->U, usk->U, RRE); //x is not copied as it is not needed
	tmp->V = (unsigned char *)malloc(RRE);
	memcpy( tmp->V, usk->V, RRE); //x is not copied as it is not needed

	*state = (void *)tmp; //recast and return
}

//mbuf and mlen unused in this case, but generally it could be used
void __tscibi_cmtgen(void **state, unsigned char **cmt){
	struct __tscibi_prvst *tmp = (struct __tscibi_prvst *)(*state); //parse state

	unsigned char tbuf[RRE]; int rc;
	tmp->nonce = (unsigned char *)sodium_malloc(RRS); //allocate nonce

	crypto_core_ristretto255_scalar_random(tmp->nonce); //sample nonce and compute cmt
	rc = crypto_scalarmult_ristretto255_base(tbuf , tmp->nonce);
	assert(rc == 0);
	//create commit message
	*cmt = (unsigned char *)malloc(TSCIBI_CMTLEN); //commit = U, V = vB where v is nonce
	copyskip( *cmt, tmp->U, 	0, 	RRE);
	copyskip( *cmt, tmp->V, 	1*RRE, 	RRE);
	copyskip( *cmt, tbuf, 		2*RRE, 	RRE);
	*state = (void *)tmp; //recast and return
}

void __tscibi_resgen(const unsigned char *cha, void *state, unsigned char **res){
	struct __tscibi_prvst *tmp = (struct __tscibi_prvst *)state; //parse state
	//allocate mem for response
	*res = (unsigned char *)malloc(TSCIBI_RESLEN); //response : y=t+cs where t is nonce

	//compute response
	crypto_core_ristretto255_scalar_mul( *res, cha, tmp->s ); //
	crypto_core_ristretto255_scalar_add( *res, *res, tmp->nonce );
	__tscibi_prvstfree(state); //critical, PLEASE FREE BEFORE RETURNING
}

void __tscibi_verinit(void *vpar, const unsigned char *mbuf, size_t mlen, void **state){
	struct __tscibi_pk *par = (struct __tscibi_pk *)vpar; //parse mpk
	struct __tscibi_verst *tmp;
	//allocate
	tmp = (struct __tscibi_verst *)malloc(sizeof(struct __tscibi_verst));

	//copy mbuf
	tmp->mbuf = (unsigned char *)malloc(mlen);
	memcpy(tmp->mbuf, mbuf, mlen);
	tmp->mlen = mlen;

	//copy public params
	tmp->A = (unsigned char *)malloc(RRE);
	memcpy(tmp->A, par->A, RRE);
	tmp->A2 = (unsigned char *)malloc(RRE);
	memcpy(tmp->A2, par->A2, RRE);
	tmp->B2 = (unsigned char *)malloc(RRE);
	memcpy(tmp->B2, par->B2, RRE);

	*state = (void *)tmp; //recast and return
}

//vpar unused, but generally it MAY be used
void __tscibi_chagen(const unsigned char *cmt, void **state, unsigned char **cha){
	struct __tscibi_verst *tmp = (struct __tscibi_verst *)(*state); //parse state

	tmp->U = (unsigned char *)malloc(RRE);
	tmp->V = (unsigned char *)malloc(RRE);
	tmp->W = (unsigned char *)malloc(RRE);

	//parse commit
	skipcopy( tmp->U, cmt, 0, 	RRE);
	skipcopy( tmp->V, cmt, RRE, 	RRE);
	skipcopy( tmp->W, cmt, 2*RRE, 	RRE);

	//generate challenge
	//commit = U', V = vB where v is nonce
	tmp->c = (unsigned char *)malloc(RRS);
	*cha = (unsigned char *)malloc(TSCIBI_CHALEN);
	crypto_core_ristretto255_scalar_random(tmp->c);
	memcpy(*cha, tmp->c, RRS);

	*state = (void *)tmp; //recast and return
}

//main decision function for protocol
void __tscibi_protdc(const unsigned char *res, void *state, int *dec){
	struct __tscibi_verst *tmp = (struct __tscibi_verst *)(state); //parse state

	unsigned char rhs[RRE]; unsigned char lhs[RRE]; unsigned char tbuf[RRS];
	__tscibi_hashexec(tmp->mbuf, tmp->mlen, tmp->U, tmp->V, tmp->A, tmp->A2, tbuf);

	// yB = T + c( U' - xP1 )
	*dec += crypto_scalarmult_ristretto255_base(lhs, res); // yB
	*dec = crypto_scalarmult_ristretto255( rhs, tbuf, tmp->A); // xP1
	*dec += crypto_core_ristretto255_sub( rhs, tmp->U, rhs); // U' - xP1
	*dec += crypto_scalarmult_ristretto255( rhs, tmp->c, rhs); // c( U' - xP1 )
	*dec += crypto_core_ristretto255_add( rhs, tmp->W, rhs);// T + c(U' - xP1)

	__tscibi_verstfree(state);
	*dec += crypto_verify_32(lhs, rhs);
}

size_t __tscibi_skserial(void *in, unsigned char **out){
	size_t rs;
	struct __tscibi_sk *ri = (struct __tscibi_sk *)in;//recast the key
	//set size and allocate
	*out = (unsigned char *)malloc( TSCIBI_SKLEN );
	//a, A
	rs = copyskip( *out, ri->a, 		0, 	RRS);
	rs = copyskip( *out, ri->pub->A, 	rs, 	RRE);
	rs = copyskip( *out, ri->pub->A2, 	rs, 	RRE);
	rs = copyskip( *out, ri->pub->B2, 	rs, 	RRE);
	return rs;
}

size_t __tscibi_pkserial(void *in, unsigned char **out){
	size_t rs;
	struct __tscibi_pk *ri = (struct __tscibi_pk *)in;//recast the key
	//set size and allocate
	*out = (unsigned char *)malloc( TSCIBI_PKLEN );
	// A
	rs = copyskip( *out, ri->A, 	0, 	RRE);
	rs = copyskip( *out, ri->A2, 	rs, 	RRE);
	rs = copyskip( *out, ri->B2, 	rs, 	RRE);
	return rs;
}

size_t __tscibi_sgserial(void *in, unsigned char **out){
	size_t rs;
	struct __tscibi_sg *ri = (struct __tscibi_sg *)in;//recast the obj
	//set size and allocate
	*out = (unsigned char *)malloc( TSCIBI_SGLEN );
	//s, x, U
	rs = copyskip( *out, ri->s, 	0, 	RRS);
	rs = copyskip( *out, ri->x, 	rs, 	RRS);
	rs = copyskip( *out, ri->U, 	rs, 	RRE);
	rs = copyskip( *out, ri->V, 	rs, 	RRE);
	return rs;
}

size_t __tscibi_skconstr(const unsigned char *in, void **out){
	size_t rs;
	struct __tscibi_sk *tmp;
	//allocate memory for seckey
	tmp = __tscibi_skinit();
	// a, A, A2
	rs = skipcopy( tmp->a,		in, 0, 	RRS);
	rs = skipcopy( tmp->pub->A,	in, rs, RRE);
	rs = skipcopy( tmp->pub->A2,	in, rs, RRE);
	rs = skipcopy( tmp->pub->B2,	in, rs, RRE);
	*out = (void *) tmp;
	return rs;
}

size_t __tscibi_pkconstr(const unsigned char *in, void **out){
	size_t rs;
	struct __tscibi_pk *tmp;
	//allocate memory for seckey
	tmp = __tscibi_pkinit();
	// A, A2, B2
	rs = skipcopy( tmp->A,		in, 0, 	RRE);
	rs = skipcopy( tmp->A2,		in, rs,	RRE);
	rs = skipcopy( tmp->B2,		in, rs,	RRE);
	*out = (void *) tmp;
	return rs;
}

size_t __tscibi_sgconstr(const unsigned char *in, void **out){
	size_t rs;
	struct __tscibi_sg *tmp;
	//allocate memory for seckey
	tmp = __tscibi_sginit();
	// s, x, U
	rs = skipcopy( tmp->s,		in, 0, 	RRS);
	rs = skipcopy( tmp->x,		in, rs, RRS);
	rs = skipcopy( tmp->U,		in, rs, RRE);
	rs = skipcopy( tmp->V,		in, rs, RRE);
	*out = (void *) tmp;
	return rs;
}

const struct __ibi tscibi = {
	.init = __sodium_init,
	.keygen = __tscibi_randkeygen,
	.pkext = __tscibi_getpubkey,
	.siggen = __tscibi_signatgen,
	.sigvrf = __tscibi_signatchk,
	.skfree = __tscibi_skfree,
	.pkfree = __tscibi_pkfree,
	.sgfree = __tscibi_sgfree,
	.skprint = __tscibi_skprint,
	.pkprint = __tscibi_pkprint,
	.sgprint = __tscibi_sgprint,
	.prvinit = __tscibi_prvinit,
	.cmtgen = __tscibi_cmtgen,
	.resgen = __tscibi_resgen,
	.verinit = __tscibi_verinit,
	.chagen = __tscibi_chagen,
	.protdc = __tscibi_protdc,
	.sklen = TSCIBI_SKLEN,
	.pklen = TSCIBI_PKLEN,
	.sglen = TSCIBI_SGLEN,
	.cmtlen = TSCIBI_CMTLEN,
	.chalen = TSCIBI_CHALEN,
	.reslen = TSCIBI_RESLEN,
	.skserial = __tscibi_skserial,
	.pkserial = __tscibi_pkserial,
	.sgserial = __tscibi_sgserial,
	.skconstr = __tscibi_skconstr,
	.pkconstr = __tscibi_pkconstr,
	.sgconstr = __tscibi_sgconstr,
};
