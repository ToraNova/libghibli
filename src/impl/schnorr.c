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
#include "ds.h"


// memory allocation
struct __schnorr_pk *__schnorr_pkinit(void){
	struct __schnorr_pk *out;
	out = (struct __schnorr_pk *)malloc( sizeof(struct __schnorr_pk) );
	out->A = (unsigned char *)malloc( RRE );
	return out;
}
struct __schnorr_sk *__schnorr_skinit(void){
	struct __schnorr_sk *out;
	out = (struct __schnorr_sk *)sodium_malloc( sizeof(struct __schnorr_sk) );
	out->a = (unsigned char *)sodium_malloc( RRS );
	out->pub = __schnorr_pkinit();
	return out;
}
struct __schnorr_sg *__schnorr_sginit(void){
	struct __schnorr_sg *out;
	out = (struct __schnorr_sg *)sodium_malloc( sizeof( struct __schnorr_sg) );
	out->s = (unsigned char *)sodium_malloc( RRS );
	out->x = (unsigned char *)sodium_malloc( RRS );
	out->U = (unsigned char *)sodium_malloc( RRE );
	return out;
}

//memory free
void __schnorr_pkfree(void *in){
	//key recast
	struct __schnorr_pk *ri = (struct __schnorr_pk *)in;
	//free up memory
	free(ri->A);
	free(ri);
}
void __schnorr_skfree(void *in){
	//key recast
	struct __schnorr_sk *ri = (struct __schnorr_sk *)in;
	//zero out the secret component
	sodium_memzero(ri->a, RRS);

	//free memory
	sodium_free(ri->a);
	__schnorr_pkfree(ri->pub);
	sodium_free(ri);
}
void __schnorr_sgfree(void *in){
	//key recast
	struct __schnorr_sg *ri = (struct __schnorr_sg *)in;
	//clear the components
	//sodium_memzero(ri->s, RRS);
	//sodium_memzero(ri->x, RRS);
	//sodium_memzero(ri->U, RRE);
	//free memory
	sodium_free(ri->s);
	sodium_free(ri->x);
	//free(ri->x);
	sodium_free(ri->U);
	sodium_free(ri);
}

void __schnorr_randkeygen(void **out){
	int rc;
	//declare and allocate memory for key
	struct __schnorr_sk *tmp = __schnorr_skinit();
	unsigned char neg[RRS];

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

void __schnorr_getpubkey(void *vkey, void **out){
	//key recast
	struct __schnorr_sk *key = ((struct __schnorr_sk *)vkey);
	//allocate for pk
	struct __schnorr_pk *tmp = __schnorr_pkinit();
	copyskip(tmp->A, key->pub->A, 0, RRE);
	*out = (void *)tmp;
}

//assumes arr is alloc with RRS
void __schnorr_hashexec(
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

void __schnorr_signatgen(
	void *vkey,
	const unsigned char *mbuf, size_t mlen,
	void **out
){
	int rc;
 	//key recast
	struct __schnorr_sk *key = (struct __schnorr_sk *)vkey;
	//declare and allocate for signature struct
	struct __schnorr_sg *tmp = __schnorr_sginit();

	//--------------------------TODO START
	//nonce, r and hash
	unsigned char nonce[RRS];

	//sample r (MUST RANDOMIZE, else secret key a will be exposed)
	crypto_core_ristretto255_scalar_random(nonce);

	rc = crypto_scalarmult_ristretto255_base(
			tmp->U,
			nonce
			); // U = rB
	assert(rc == 0);

	__schnorr_hashexec(mbuf, mlen, tmp->U, key->pub->A, tmp->x);

	// s = r + xa
	crypto_core_ristretto255_scalar_mul( tmp->s , tmp->x, key->a );
	crypto_core_ristretto255_scalar_add( tmp->s, tmp->s, nonce );
	//--------------------------TODO END

	*out = (void *) tmp;
}

void __schnorr_signatchk(
	void *vpar,
	void *vsig,
	const unsigned char *mbuf, size_t mlen,
	int *res
){
	//key recast
	unsigned char xp[RRS];
	struct __schnorr_pk *par = (struct __schnorr_pk *)vpar;
	struct __schnorr_sg *sig = (struct __schnorr_sg *)vsig;

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

	__schnorr_hashexec(mbuf, mlen, tmp1, par->A, xp);

	//check if hash is equal to x from vsig
	*res += crypto_verify_32( xp, sig->x );
	//--------------------------TODO END
}

//debugging use only
void __schnorr_pkprint(void *in){
	struct __schnorr_pk *ri = (struct __schnorr_pk *)in;
	printf("A :"); ucbprint(ri->A, RRE); printf("\n");
}

void __schnorr_skprint(void *in){
	struct __schnorr_sk *ri = (struct __schnorr_sk *)in;
	printf("a :"); ucbprint(ri->a, RRS); printf("\n");
	__schnorr_pkprint((void *)ri->pub);
}

void __schnorr_sgprint(void *in){
	struct __schnorr_sg *ri = (struct __schnorr_sg *)in;
	printf("s :"); ucbprint(ri->s, RRS); printf("\n");
	printf("x :"); ucbprint(ri->x, RRS); printf("\n");
	printf("U :"); ucbprint(ri->U, RRE); printf("\n");
}

size_t __schnorr_skserial(void *in, unsigned char **out){
	size_t rs;
	struct __schnorr_sk *ri = (struct __schnorr_sk *)in;//recast the key
	//set size and allocate
	*out = (unsigned char *)malloc( SCHNORR_SKLEN );
	//a, A
	rs = copyskip( *out, ri->a, 		0, 	RRS);
	rs = copyskip( *out, ri->pub->A, 	rs, 	RRE);
	return rs;
}

size_t __schnorr_pkserial(void *in, unsigned char **out){
	size_t rs;
	struct __schnorr_pk *ri = (struct __schnorr_pk *)in;//recast the key
	//set size and allocate
	*out = (unsigned char *)malloc( SCHNORR_PKLEN );
	// A
	rs = copyskip( *out, ri->A, 	0, 	RRE);
	return rs;
}

size_t __schnorr_sgserial(void *in, unsigned char **out){
	size_t rs;
	struct __schnorr_sg *ri = (struct __schnorr_sg *)in;//recast the obj
	//set size and allocate
	*out = (unsigned char *)malloc( SCHNORR_SGLEN );
	//s, x, U
	rs = copyskip( *out, ri->s, 	0, 	RRS);
	rs = copyskip( *out, ri->x, 	rs, 	RRS);
	rs = copyskip( *out, ri->U, 	rs, 	RRE);
	return rs;
}

size_t __schnorr_skconstr(const unsigned char *in, void **out){
	size_t rs;
	struct __schnorr_sk *tmp;
	//allocate memory for seckey
	tmp = __schnorr_skinit();
	// a, A
	rs = skipcopy( tmp->a,		in, 0, 	RRS);
	rs = skipcopy( tmp->pub->A,	in, rs, RRE);
	*out = (void *) tmp;
	return rs;
}

size_t __schnorr_pkconstr(const unsigned char *in, void **out){
	size_t rs;
	struct __schnorr_pk *tmp;
	//allocate memory for seckey
	tmp = __schnorr_pkinit();
	// A
	rs = skipcopy( tmp->A,		in, 0, 	RRE);
	*out = (void *) tmp;
	return rs;
}

size_t __schnorr_sgconstr(const unsigned char *in, void **out){
	size_t rs;
	struct __schnorr_sg *tmp;
	//allocate memory for seckey
	tmp = __schnorr_sginit();
	// s, x, U
	rs = skipcopy( tmp->s,		in, 0, 	RRS);
	rs = skipcopy( tmp->x,		in, rs, RRS);
	rs = skipcopy( tmp->U,		in, rs, RRE);
	*out = (void *) tmp;
	return rs;
}

const struct __dss schnorr = {
	.init = __sodium_init,
	.keygen = __schnorr_randkeygen,
	.pkext = __schnorr_getpubkey,
	.siggen = __schnorr_signatgen,
	.sigvrf = __schnorr_signatchk,
	.skfree = __schnorr_skfree,
	.pkfree = __schnorr_pkfree,
	.sgfree = __schnorr_sgfree,
	.skprint = __schnorr_skprint,
	.pkprint = __schnorr_pkprint,
	.sgprint = __schnorr_sgprint,
	.sklen = SCHNORR_SKLEN,
	.pklen = SCHNORR_PKLEN,
	.sglen = SCHNORR_SGLEN,
	.skserial = __schnorr_skserial,
	.pkserial = __schnorr_pkserial,
	.sgserial = __schnorr_sgserial,
	.skconstr = __schnorr_skconstr,
	.pkconstr = __schnorr_pkconstr,
	.sgconstr = __schnorr_sgconstr,
};
