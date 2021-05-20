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
#include "sodium_macro.h"
#include "gibi.h"

#define __ANCYGIBI_CMTLEN 3*RRE
#define __ANCYGIBI_CHALEN RRS
#define __ANCYGIBI_RESLEN RRS

struct __ancygibi_pk {
	unsigned char *A; //y = aB
	unsigned char *A2; //y2 = aB2
	unsigned char *B2; //second base
};

struct __ancygibi_sk {
	struct __ancygibi_pk *pub;
	unsigned char *a;
};

struct __ancygibi_sg {
	unsigned char *s;
	unsigned char *x;
	unsigned char *U; //precomputation
	unsigned char *V; //precomputation
};

void __ancygibi_gmemkeyder(void *vpar, void **out){
	struct __ancygibi_pk *par = (struct __ancygibi_pk *)vpar;

	int rc; struct __ancygibi_sk *tmp;
	tmp = (struct __ancygibi_sk *)malloc( sizeof(struct __ancygibi_sk) );
	tmp->pub = (struct __ancygibi_pk *)malloc( sizeof(struct __ancygibi_pk) );
	unsigned char neg[RRS];

	tmp->a = (unsigned char *)sodium_malloc( RRS );
	tmp->pub->A = (unsigned char *)malloc( RRE );
	tmp->pub->A2 = (unsigned char *)malloc( RRE );
	tmp->pub->B2 = (unsigned char *)malloc( RRE );

	memcpy( tmp->pub->B2, par->B2, RRE); //copy the second base

	//sample secret a
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

//assumes arr is alloc with RRS
void __ancygibi_hashexec(
	const unsigned char *mbuf, size_t mlen,
	unsigned char *ubuf,
	unsigned char *vbuf,
	unsigned char *wbuf,
	unsigned char *xbuf,
	unsigned char *ybuf,
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
	crypto_hash_sha512_update( &state, ybuf, RRE);
	crypto_hash_sha512_final( &state, tbuf);
	crypto_core_ristretto255_scalar_reduce(
		oarr, (const unsigned char *)tbuf
	);
}

void __ancygibi_gidreqgen(void *vgusk, const unsigned char *mbuf, size_t mlen, void **out){
	struct __ancygibi_sk *key = (struct __ancygibi_sk *)vgusk; //group member key
	int rc; struct __ancygibi_sg *tmp;
	tmp = (struct __ancygibi_sg *)malloc( sizeof( struct __ancygibi_sg) );

	//--------------------------TODO START
	//nonce, r and hash
	unsigned char nonce[RRS];

	//allocate for components
	tmp->s = (unsigned char *)sodium_malloc( RRS );
	tmp->x = (unsigned char *)sodium_malloc( RRS );
	tmp->U = (unsigned char *)malloc( RRE );
	tmp->V = (unsigned char *)malloc( RRE );

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

	__ancygibi_hashexec(mbuf, mlen, tmp->U, tmp->V, key->pub->A, key->pub->A2, key->pub->B2, tmp->x);

	// s = r + xa
	crypto_core_ristretto255_scalar_mul( tmp->s , tmp->x, key->a );
	crypto_core_ristretto255_scalar_add( tmp->s, tmp->s, nonce );
	//--------------------------TODO END

	*out = (void *) tmp;
}

void __ancygibi_gidreqchk(
	void *vgupk,
	void *vsig,
	const unsigned char *mbuf, size_t mlen,
	int *res
){
	unsigned char xp[RRS];
	struct __ancygibi_pk *pub = (struct __ancygibi_pk *)vgupk; //group member key
	struct __ancygibi_sg *sig = (struct __ancygibi_sg *)vsig;

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
			pub->A
			);
	*res += crypto_core_ristretto255_add( tmp3, tmp1, tmp2 ); //tmp3 U'

	// V' = sP1 - xP2
	*res += crypto_scalarmult_ristretto255(
			tmp1,
			sig->s,
			pub->B2
			);
	*res += crypto_scalarmult_ristretto255(
			tmp2,
			sig->x,
			pub->A2
			);
	*res += crypto_core_ristretto255_add( tmp2, tmp1, tmp2 ); //tmp4 V'

	__ancygibi_hashexec(mbuf, mlen, tmp3, tmp2, pub->A, pub->A2, pub->B2, xp);

	//check if tmp is equal to x from obuffer
	*res += crypto_verify_32( xp, sig->x );
	//--------------------------TODO END
}

extern void __tscibi_randkeygen();
extern void __tscibi_getpubkey();
extern void __tscibi_signatgen();
extern void __tscibi_signatchk();
extern void __tscibi_skfree();
extern void __tscibi_pkfree();
extern void __tscibi_sgfree();
extern void __tscibi_skprint();
extern void __tscibi_pkprint();
extern void __tscibi_sgprint();
extern void __tscibi_prvinit();
extern void __tscibi_cmtgen();
extern void __tscibi_resgen();
extern void __tscibi_verinit();
extern void __tscibi_chagen();
extern void __tscibi_protdc();

const struct __gibi ancygibi = {
	.randkeygen = __tscibi_randkeygen,
	.getpubkey = __tscibi_getpubkey,
	.signatgen = __tscibi_signatgen,
	.signatchk = __tscibi_signatchk,
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
	.cmtlen = __ANCYGIBI_CMTLEN,
	.chalen = __ANCYGIBI_CHALEN,
	.reslen = __ANCYGIBI_RESLEN,
	.gmemkeyder = __ancygibi_gmemkeyder,
	.gidreqgen = __ancygibi_gidreqgen,
	.gidreqchk = __ancygibi_gidreqchk,
};
