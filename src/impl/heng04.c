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
#include "schnorr91.h"

#define HENG04_CMTLEN (2*RRE)
#define HENG04_CHALEN RRS
#define HENG04_RESLEN RRS

//prover and verifier protocol states
struct __heng04_prvst {
	uint8_t *s;
	uint8_t *U; //precomputation
	uint8_t *nonce;
	uint8_t *mbuf;
	size_t mlen;
};

struct __heng04_verst {
	uint8_t *A;
	uint8_t *c; //challenge
	uint8_t *U; //precompute
	uint8_t *NE; //commit nonce group element
	uint8_t *mbuf;
	size_t mlen;
};

void __heng04_prvstfree(void *state){
	struct __heng04_prvst *tmp = (struct __heng04_prvst *)state; //parse state
	sodium_free(tmp->s);
	sodium_free(tmp->nonce);
	memset(tmp->U, 0, RRE);//clear and free
	free(tmp->U);
	free(tmp->mbuf);
	free(tmp);
}

void __heng04_verstfree(void *state){
	struct __heng04_verst *tmp = (struct __heng04_verst *)state; //parse state
	free(tmp->A);
	free(tmp->c);
	free(tmp->U);
	free(tmp->NE);
	free(tmp->mbuf);
	free(tmp);
}

void __heng04_prvinit(void *vusk, const uint8_t *mbuf, size_t mlen, void **state){
	struct __schnorr91_sg *usk = (struct __schnorr91_sg *)vusk;
	struct __heng04_prvst *tmp;
	tmp = (struct __heng04_prvst *)malloc(sizeof(struct __heng04_prvst));

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
void __heng04_cmtgen(void **state, uint8_t *cmt){
	struct __heng04_prvst *tmp = (struct __heng04_prvst *)(*state); //parse state

	uint8_t tbuf[RRE]; int rc;
	tmp->nonce = (uint8_t *)sodium_malloc(RRS); //allocate nonce

	crypto_core_ristretto255_scalar_random(tmp->nonce); //sample nonce and compute cmt
	rc = crypto_scalarmult_ristretto255_base(tbuf , tmp->nonce);
	//create commit message
	//*cmt = (uint8_t *)malloc(HENG04_CMTLEN); // leave it up to user to allocate
	//commit = U, V = vB where v is nonce
	copyskip( cmt, tmp->U, 	0, 	RRE);
	copyskip( cmt, tbuf, 		RRE, 	RRE);
	*state = (void *)tmp; //recast and return
}

void __heng04_resgen(const uint8_t *cha, void *state, uint8_t *res){
	struct __heng04_prvst *tmp = (struct __heng04_prvst *)state; //parse state
	//allocate mem for response
	//*res = (uint8_t *)malloc(HENG04_RESLEN); //leave it up to user to allocate

	//compute response : y=t+cs where t is nonce
	crypto_core_ristretto255_scalar_mul( res, cha, tmp->s ); //
	crypto_core_ristretto255_scalar_add( res, res, tmp->nonce );
	__heng04_prvstfree(state); //critical, PLEASE FREE BEFORE RETURNING
}

void __heng04_verinit(void *vpar, const uint8_t *mbuf, size_t mlen, void **state){
	struct __schnorr91_pk *par = (struct __schnorr91_pk *)vpar; //parse mpk
	struct __heng04_verst *tmp;
	//allocate
	tmp = (struct __heng04_verst *)malloc(sizeof(struct __heng04_verst));

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
void __heng04_chagen(const uint8_t *cmt, void **state, uint8_t *cha){
	struct __heng04_verst *tmp = (struct __heng04_verst *)(*state); //parse state

	tmp->U = (uint8_t *)malloc(RRE);
	tmp->NE = (uint8_t *)malloc(RRE);

	//parse commit
	skipcopy( tmp->U, cmt, 0, 	RRE);
	skipcopy( tmp->NE, cmt, RRE, 	RRE);

	//generate challenge
	//commit = U', V = vB where v is nonce
	tmp->c = (uint8_t *)malloc(RRS);
	//*cha = (uint8_t *)malloc(HENG04_CHALEN); //leave it up to user to allocate
	crypto_core_ristretto255_scalar_random(tmp->c);
	memcpy(cha, tmp->c, RRS);

	*state = (void *)tmp; //recast and return
}

//main decision function for protocol
void __heng04_protdc(const uint8_t *res, void *state, int *dec){
	struct __heng04_verst *tmp = (struct __heng04_verst *)(state); //parse state

	uint8_t rhs[RRE]; uint8_t lhs[RRE]; uint8_t tbuf[RRS];
	__sodium_2rinhashexec(tmp->mbuf, tmp->mlen, tmp->U, tmp->A, tbuf);

	// yB = T + c( U' - xP1 )
	*dec = crypto_scalarmult_ristretto255_base(lhs, res); // yB
	*dec += crypto_scalarmult_ristretto255( rhs, tbuf, tmp->A); // xA
	*dec += crypto_core_ristretto255_sub( rhs, tmp->U, rhs); // U' - xA
	*dec += crypto_scalarmult_ristretto255( rhs, tmp->c, rhs); // c( U' - xA )
	*dec += crypto_core_ristretto255_add(rhs, tmp->NE, rhs);// T + c(U' - xA)

	__heng04_verstfree(state);
	*dec += crypto_verify_32(lhs, rhs);
}

const ibi_t heng04 = {
	.ds = (ds_t *)&schnorr91,
	.prvinit = __heng04_prvinit, //proto
	.cmtgen = __heng04_cmtgen,
	.resgen = __heng04_resgen,
	.verinit = __heng04_verinit,
	.chagen = __heng04_chagen,
	.protdc = __heng04_protdc,
	.cmtlen = HENG04_CMTLEN,
	.chalen = HENG04_CHALEN,
	.reslen = HENG04_RESLEN,
};
