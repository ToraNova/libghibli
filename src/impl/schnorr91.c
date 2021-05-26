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
#include "ds.h"
#include "schnorr91.h"

// memory allocation
struct __schnorr91_pk *__schnorr91_pkinit(void){
	struct __schnorr91_pk *out;
	out = (struct __schnorr91_pk *)malloc( sizeof(struct __schnorr91_pk) );
	out->A = (uint8_t *)malloc( RRE );
	return out;
}
struct __schnorr91_sk *__schnorr91_skinit(void){
	struct __schnorr91_sk *out;
	out = (struct __schnorr91_sk *)malloc( sizeof(struct __schnorr91_sk) );
	out->a = (uint8_t *)sodium_malloc( RRS );
	out->pub = __schnorr91_pkinit();
	return out;
}
struct __schnorr91_sg *__schnorr91_sginit(void){
	struct __schnorr91_sg *out;
	out = (struct __schnorr91_sg *)malloc( sizeof( struct __schnorr91_sg) );
	out->s = (uint8_t *)sodium_malloc( RRS );
	out->x = (uint8_t *)sodium_malloc( RRS );
	out->U = (uint8_t *)sodium_malloc( RRE );
	return out;
}

//memory free
void __schnorr91_pkfree(void *in){
	//key recast
	struct __schnorr91_pk *ri = (struct __schnorr91_pk *)in;
	//free up memory
	free(ri->A);
	free(ri);
}
void __schnorr91_skfree(void *in){
	//key recast
	struct __schnorr91_sk *ri = (struct __schnorr91_sk *)in;
	//zero out the secret component
	//sodium_memzero(ri->a, RRS); //sodium_free already does this

	//free memory
	sodium_free(ri->a);
	__schnorr91_pkfree(ri->pub);
	free(ri);
}
void __schnorr91_sgfree(void *in){
	//key recast
	struct __schnorr91_sg *ri = (struct __schnorr91_sg *)in;
	//clear the components
	//sodium_memzero(ri->s, RRS);
	//sodium_memzero(ri->x, RRS);
	//sodium_memzero(ri->U, RRE);
	//free memory
	sodium_free(ri->s);
	sodium_free(ri->x);
	//free(ri->x);
	sodium_free(ri->U);
	free(ri);
}

void __schnorr91_skgen(void **out){
	int rc;
	//declare and allocate memory for key
	struct __schnorr91_sk *tmp = __schnorr91_skinit();
	uint8_t neg[RRS];

	//sample secret a
	crypto_core_ristretto255_scalar_random( tmp->a );

	crypto_core_ristretto255_scalar_negate(neg , tmp->a);
	rc = crypto_scalarmult_ristretto255_base(tmp->pub->A, neg); // A = -aB

	memset(neg, 0, RRS); // zero memory
	assert(rc == 0);

	//recast and return
	*out = (void *) tmp;
}

void __schnorr91_pkext(void *vkey, void **out){
	//key recast
	struct __schnorr91_sk *key = ((struct __schnorr91_sk *)vkey);
	//allocate for pk
	struct __schnorr91_pk *tmp = __schnorr91_pkinit();
	memcpy(tmp->A, key->pub->A, RRE);
	*out = (void *)tmp;
}

void __schnorr91_siggen(
	void *vkey,
	const uint8_t *mbuf, size_t mlen,
	void **out
){
	int rc;
 	//key recast
	struct __schnorr91_sk *key = (struct __schnorr91_sk *)vkey;
	//declare and allocate for signature struct
	struct __schnorr91_sg *tmp = __schnorr91_sginit();

	//--------------------------TODO START
	//nonce, r and hash
	uint8_t nonce[RRS];

	//sample r (MUST RANDOMIZE, else secret key a will be exposed)
	crypto_core_ristretto255_scalar_random(nonce);

	rc = crypto_scalarmult_ristretto255_base(
			tmp->U,
			nonce
			); // U = rB
	assert(rc == 0);

	__sodium_2rinhashexec(mbuf, mlen, tmp->U, key->pub->A, tmp->x);

	// s = r + xa
	crypto_core_ristretto255_scalar_mul( tmp->s , tmp->x, key->a );
	crypto_core_ristretto255_scalar_add( tmp->s, tmp->s, nonce );
	memset(nonce, 0, RRS);
	//--------------------------TODO END

	*out = (void *) tmp;
}

void __schnorr91_sigvrf(
	void *vpar,
	void *vsig,
	const uint8_t *mbuf, size_t mlen,
	int *res
){
	//key recast
	uint8_t xp[RRS];
	struct __schnorr91_pk *par = (struct __schnorr91_pk *)vpar;
	struct __schnorr91_sg *sig = (struct __schnorr91_sg *)vsig;

	//--------------------------TODO START
	uint8_t tmp1[RRE]; //tmp array
	uint8_t tmp2[RRE]; //tmp array

	// U' = sB - xA
	*res = crypto_scalarmult_ristretto255_base( tmp1, sig->s);
	*res += crypto_scalarmult_ristretto255( tmp2, sig->x, par->A);
	*res += crypto_core_ristretto255_add( tmp1, tmp1, tmp2 );

	__sodium_2rinhashexec(mbuf, mlen, tmp1, par->A, xp);

	//check if hash is equal to x from vsig
	*res += crypto_verify_32( xp, sig->x );
	//--------------------------TODO END
}

//debugging use only
void __schnorr91_pkprint(void *in){
	struct __schnorr91_pk *ri = (struct __schnorr91_pk *)in;
	printf("A :"); ucbprint(ri->A, RRE); printf("\n");
}

void __schnorr91_skprint(void *in){
	struct __schnorr91_sk *ri = (struct __schnorr91_sk *)in;
	printf("a :"); ucbprint(ri->a, RRS); printf("\n");
	__schnorr91_pkprint((void *)ri->pub);
}

void __schnorr91_sgprint(void *in){
	struct __schnorr91_sg *ri = (struct __schnorr91_sg *)in;
	printf("s :"); ucbprint(ri->s, RRS); printf("\n");
	printf("x :"); ucbprint(ri->x, RRS); printf("\n");
	printf("U :"); ucbprint(ri->U, RRE); printf("\n");
}

size_t __schnorr91_pkserial(void *in, uint8_t *out){
	size_t rs;
	struct __schnorr91_pk *ri = (struct __schnorr91_pk *)in;//recast the key
	//set size and allocate
	//*out = (uint8_t *)malloc( SCHNORR91_PKLEN );
	// A
	rs = copyskip( out, ri->A, 	0, 	RRE);
	return rs;
}

size_t __schnorr91_skserial(void *in, uint8_t *out){
	size_t rs;
	struct __schnorr91_sk *ri = (struct __schnorr91_sk *)in;//recast the key
	//set size and allocate
	//*out = (uint8_t *)malloc( SCHNORR91_SKLEN );
	//a, A
	rs = copyskip( out, ri->a, 		0, 	RRS);
	rs = copyskip( out, ri->pub->A, 	rs, 	RRE);
	return rs;
}

size_t __schnorr91_sgserial(void *in, uint8_t *out){
	size_t rs;
	struct __schnorr91_sg *ri = (struct __schnorr91_sg *)in;//recast the obj
	//set size and allocate
	//*out = (uint8_t *)malloc( SCHNORR91_SGLEN );
	//s, x, U
	rs = copyskip( out, ri->s, 	0, 	RRS);
	rs = copyskip( out, ri->x, 	rs, 	RRS);
	rs = copyskip( out, ri->U, 	rs, 	RRE);
	return rs;
}

size_t __schnorr91_pkconstr(const uint8_t *in, void **out){
	size_t rs;
	struct __schnorr91_pk *tmp;
	//allocate memory for seckey
	tmp = __schnorr91_pkinit();
	// A
	rs = skipcopy( tmp->A,		in, 0, 	RRE);
	*out = (void *) tmp;
	return rs;
}

size_t __schnorr91_skconstr(const uint8_t *in, void **out){
	size_t rs;
	struct __schnorr91_sk *tmp;
	//allocate memory for seckey
	tmp = __schnorr91_skinit();
	// a, A
	rs = skipcopy( tmp->a,		in, 0, 	RRS);
	rs = skipcopy( tmp->pub->A,	in, rs, RRE);
	*out = (void *) tmp;
	return rs;
}

size_t __schnorr91_sgconstr(const uint8_t *in, void **out){
	size_t rs;
	struct __schnorr91_sg *tmp;
	//allocate memory for seckey
	tmp = __schnorr91_sginit();
	// s, x, U
	rs = skipcopy( tmp->s,		in, 0, 	RRS);
	rs = skipcopy( tmp->x,		in, rs, RRS);
	rs = skipcopy( tmp->U,		in, rs, RRE);
	*out = (void *) tmp;
	return rs;
}

const ds_t schnorr91 = {
	.hier = 0, //non hierarchical
	.skgen = __schnorr91_skgen,
	.pkext = __schnorr91_pkext,
	.siggen = __schnorr91_siggen,
	.sigvrf = __schnorr91_sigvrf,
	.skfree = __schnorr91_skfree,
	.pkfree = __schnorr91_pkfree,
	.sgfree = __schnorr91_sgfree,
	.skprint = __schnorr91_skprint,
	.pkprint = __schnorr91_pkprint,
	.sgprint = __schnorr91_sgprint,
	.skserial = __schnorr91_skserial,
	.pkserial = __schnorr91_pkserial,
	.sgserial = __schnorr91_sgserial,
	.skconstr = __schnorr91_skconstr,
	.pkconstr = __schnorr91_pkconstr,
	.sgconstr = __schnorr91_sgconstr,
	.sklen = SCHNORR91_SKLEN,
	.pklen = SCHNORR91_PKLEN,
	.sglen = SCHNORR91_SGLEN,
};
