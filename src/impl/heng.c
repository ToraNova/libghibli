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
#include "ibi.h"
#include "schnorr.h"

#define HENG_CMTLEN (2*RRE)
#define HENG_CHALEN RRS
#define HENG_RESLEN RRS

//prover and verifier protocol states
struct __schibi_prvst {
	uint8_t *s;
	uint8_t *U; //precomputation
	uint8_t *nonce;
	uint8_t *mbuf;
	size_t mlen;
};

struct __schibi_verst {
	uint8_t *A;
	uint8_t *c;
	uint8_t *U; //precompute
	uint8_t *V; //nonceB
	uint8_t *mbuf;
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

void __schibi_prvinit(void *vusk, const uint8_t *mbuf, size_t mlen, void **state){
	struct __schnorr_sg *usk = (struct __schnorr_sg *)vusk;
	struct __schibi_prvst *tmp;
	tmp = (struct __schibi_prvst *)malloc(sizeof(struct __schibi_prvst));

	//allocate and copy for mbuf
	tmp->mbuf = (uint8_t *)malloc(mlen);
	tmp->mlen = mlen;
	memcpy(tmp->mbuf, mbuf, mlen);

	//copy secrets, vusk no longer needed
	tmp->s = (uint8_t *)sodium_malloc(RRS);
	memcpy( tmp->s, usk->s, RRS);
	tmp->U = (uint8_t *)malloc(RRE);
	memcpy( tmp->U, usk->U, RRE); //x is not copied as it is not needed

	*state = (void *)tmp; //recast and return
}

//mbuf and mlen unused in this case, but generally it could be used
void __schibi_cmtgen(void **state, uint8_t *cmt){
	struct __schibi_prvst *tmp = (struct __schibi_prvst *)(*state); //parse state

	uint8_t tbuf[RRE]; int rc;
	tmp->nonce = (uint8_t *)sodium_malloc(RRS); //allocate nonce

	crypto_core_ristretto255_scalar_random(tmp->nonce); //sample nonce and compute cmt
	rc = crypto_scalarmult_ristretto255_base(tbuf , tmp->nonce);
	//create commit message
	//*cmt = (uint8_t *)malloc(HENG_CMTLEN); // leave it up to user to allocate
	//commit = U, V = vB where v is nonce
	copyskip( cmt, tmp->U, 	0, 	RRE);
	copyskip( cmt, tbuf, 		RRE, 	RRE);
	*state = (void *)tmp; //recast and return
}

void __schibi_resgen(const uint8_t *cha, void *state, uint8_t *res){
	struct __schibi_prvst *tmp = (struct __schibi_prvst *)state; //parse state
	//allocate mem for response
	//*res = (uint8_t *)malloc(HENG_RESLEN); //leave it up to user to allocate

	//compute response : y=t+cs where t is nonce
	crypto_core_ristretto255_scalar_mul( res, cha, tmp->s ); //
	crypto_core_ristretto255_scalar_add( res, res, tmp->nonce );
	__schibi_prvstfree(state); //critical, PLEASE FREE BEFORE RETURNING
}

void __schibi_verinit(void *vpar, const uint8_t *mbuf, size_t mlen, void **state){
	struct __schnorr_pk *par = (struct __schnorr_pk *)vpar; //parse mpk
	struct __schibi_verst *tmp;
	//allocate
	tmp = (struct __schibi_verst *)malloc(sizeof(struct __schibi_verst));

	//copy mbuf
	tmp->mbuf = (uint8_t *)malloc(mlen);
	memcpy(tmp->mbuf, mbuf, mlen);
	tmp->mlen = mlen;

	//copy public params
	tmp->A = (uint8_t *)malloc(RRE);
	memcpy(tmp->A, par->A, RRE);

	*state = (void *)tmp; //recast and return
}

//vpar unused, but generally it MAY be used
void __schibi_chagen(const uint8_t *cmt, void **state, uint8_t *cha){
	struct __schibi_verst *tmp = (struct __schibi_verst *)(*state); //parse state

	tmp->U = (uint8_t *)malloc(RRE);
	tmp->V = (uint8_t *)malloc(RRE);

	//parse commit
	skipcopy( tmp->U, cmt, 0, 	RRE);
	skipcopy( tmp->V, cmt, RRE, 	RRE);

	//generate challenge
	//commit = U', V = vB where v is nonce
	tmp->c = (uint8_t *)malloc(RRS);
	//*cha = (uint8_t *)malloc(HENG_CHALEN); //leave it up to user to allocate
	crypto_core_ristretto255_scalar_random(tmp->c);
	memcpy(cha, tmp->c, RRS);

	*state = (void *)tmp; //recast and return
}

//main decision function for protocol
void __schibi_protdc(const uint8_t *res, void *state, int *dec){
	struct __schibi_verst *tmp = (struct __schibi_verst *)(state); //parse state

	uint8_t rhs[RRE]; uint8_t lhs[RRE]; uint8_t tbuf[RRS];
	__schnorr_hashexec(tmp->mbuf, tmp->mlen, tmp->U, tmp->A, tbuf);

	// yB = T + c( U' - xP1 )
	*dec = crypto_scalarmult_ristretto255_base(lhs, res); // yB
	*dec += crypto_scalarmult_ristretto255( rhs, tbuf, tmp->A); // xA
	*dec += crypto_core_ristretto255_sub( rhs, tmp->U, rhs); // U' - xA
	*dec += crypto_scalarmult_ristretto255( rhs, tmp->c, rhs); // c( U' - xA )
	*dec += crypto_core_ristretto255_add(rhs, tmp->V, rhs);// T + c(U' - xA)

	__schibi_verstfree(state);
	*dec += crypto_verify_32(lhs, rhs);
}

const struct __ibi heng = {
	.ds = (ds_t *)&schnorr,
	.prvinit = __schibi_prvinit, //proto
	.cmtgen = __schibi_cmtgen,
	.resgen = __schibi_resgen,
	.verinit = __schibi_verinit,
	.chagen = __schibi_chagen,
	.protdc = __schibi_protdc,
	.cmtlen = HENG_CMTLEN,
	.chalen = HENG_CHALEN,
	.reslen = HENG_RESLEN,
};
