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

#include "ibi.h"
#include "../utils/debug.h"
#include "../utils/bufhelp.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

ibi_t *get_ibi_impl(uint8_t an){
	switch(an){
		case 0:
			return (ibi_t *) &heng04;
		case 1:
			return (ibi_t *) &chin15;
		case 2:
			return (ibi_t *) &vangujar19;
		default:
			assert(0); //error
			return (ibi_t *) &heng04;
	}
}

int __ibi_ishier(uint8_t an){
	ds_t *impl = get_ibi_impl(an)->ds;
	return impl->hier;
}

ibi_u_t *__ibi_uinit(uint8_t an, size_t mlen){
	ibi_u_t *out = (ibi_u_t *)malloc(sizeof(ibi_u_t));
	out->an = an;
	out->mlen = mlen;
	out->m = (uint8_t *)malloc(mlen);
	return out;
}

void __ibi_ufree(void *in){
	ibi_u_t *ri = (ibi_u_t *)in;
	ds_t *impl = get_ibi_impl(ri->an)->ds;
	impl->sgfree(ri->k);
	free(ri->m);
	free(ri);
}

uint8_t __ibi_uaread(void *in){
	ibi_u_t *ri = (ibi_u_t *)in;
	return ri->an;
}

void __ibi_uiread(void *in, uint8_t **out, size_t *len){
	ibi_u_t *ri = (ibi_u_t *)in;
	*len = ri->mlen;
	*out = (uint8_t *)malloc( (*len) + 1 );
	memcpy(*out, ri->m, *len);
	(*out)[*len] = 0; //null char
}

// base length of a user key (not including length of signature
size_t __ibi_ukbslen(uint8_t an){
	ds_t *impl = get_ibi_impl(an)->ds;
	return (impl->sglen + 1);
}

void __ibi_ukgen(
	void *vkey,
	const uint8_t *mbuf, size_t mlen,
	void **out
){
	ds_k_t *sk = (ds_k_t *)vkey; //recast key
	// init key
	ibi_u_t *uk = __ibi_uinit(sk->an, mlen);
	// get implementation
	ds_t *impl = get_ibi_impl(sk->an)->ds;
	// sign using the implementation
	impl->siggen(sk->k, mbuf, mlen, &(uk->k));
	// copy user id to the key
	memcpy(uk->m, mbuf, mlen);
	*out = (void *)uk;
}

void __ibi_ukvrf(void *vpar, void *vusk, int *res){
	ds_k_t *pk = (ds_k_t *)vpar;
	ibi_u_t *uk = (ibi_u_t *)vusk;
	if(uk->an != pk->an){ *res = 1; return; }
	ds_t *impl = get_ibi_impl(pk->an)->ds;
	impl->sigvrf(pk->k, uk->k, uk->m, uk->mlen, res);
}

void __ibi_uprint(void *in){
	ibi_u_t *ri = (ibi_u_t *)in;
	ds_t *impl = get_ibi_impl(ri->an)->ds;
	printf("m :%s\n", ri->m);
	impl->sgprint(ri->k);
}

size_t __ibi_userial(void *in, uint8_t *out, size_t mblen){
	ibi_u_t *ri = (ibi_u_t *)in; //recast key
	ds_t *impl = get_ibi_impl(ri->an)->ds; //get ds impl
	assert( mblen >= (__ibi_ukbslen(ri->an) + ri->mlen) ); //ensure enough buffer space
	out[0] = ri->an;
	size_t rs = 1; //skip first byte
	rs += impl->sgserial(ri->k, out+rs);
	rs = copyskip(out, ri->m, rs, ri->mlen);
	return rs;
}

size_t __ibi_uconstr(const uint8_t *in, size_t len, void **out){
	size_t ul = (len - __ibi_ukbslen(in[0]));
	ul = __ibi_ishier(in[0]) ? ul/2 : ul;

	ibi_u_t *ri = __ibi_uinit(in[0], ul);
	ds_t *impl = get_ibi_impl(ri->an)->ds; //get ds impl
	size_t rs = 1; //first byte read
	rs += impl->sgconstr(in+rs, &(ri->k));
	rs = skipcopy(ri->m, in, rs, ri->mlen);
	*out = (void *)ri;
	return rs;
}

void __ibi_prvinit(void *vuk, void **state){
	ibi_u_t *uk = (ibi_u_t *)vuk;
	ibi_t *impl = get_ibi_impl(uk->an);
	ibi_protst_t *tmp = (ibi_protst_t *)malloc(sizeof(ibi_protst_t *));
	tmp->an = uk->an; //set algo type
	impl->prvinit(uk->k, uk->m, uk->mlen, &(tmp->st));
	*state = (void *)tmp;
}

void __ibi_cmtgen(void **state, uint8_t *cmt){
	ibi_protst_t *tmp = (ibi_protst_t *)(*state);
	ibi_t *impl = get_ibi_impl(tmp->an);
	impl->cmtgen( &(tmp->st), cmt );
	*state = (void *)tmp;
}

void __ibi_resgen(const uint8_t *cha, void *state, uint8_t *res){
	ibi_protst_t *tmp = (ibi_protst_t *)(state);
	ibi_t *impl = get_ibi_impl(tmp->an);
	impl->resgen(cha, (tmp->st), res);
	free(tmp);
}

void __ibi_verinit(void *vpa, const uint8_t *mbuf, size_t mlen, void **state){
	ds_k_t *pk = (ds_k_t *)vpa;
	ibi_t *impl = get_ibi_impl(pk->an);
	ibi_protst_t *tmp = (ibi_protst_t *)malloc(sizeof(ibi_protst_t *));
	tmp->an = pk->an;
	impl->verinit(pk->k, mbuf, mlen, &(tmp->st));
	*state = (void *)tmp;
}

void __ibi_chagen(const uint8_t *cmt, void **state, uint8_t *cha){
	ibi_protst_t *tmp = (ibi_protst_t *)(*state);
	ibi_t *impl = get_ibi_impl(tmp->an);
	impl->chagen(cmt, &(tmp->st), cha);
	*state = (void *)tmp;
}

void __ibi_protdc(const uint8_t *res, void *state, int *d){
	ibi_protst_t *tmp = (ibi_protst_t *)(state);
	ibi_t *impl = get_ibi_impl(tmp->an);
	impl->protdc(res, tmp->st, d);
	free(tmp);
}

size_t __ibi_cmtlen(uint8_t an){
	ibi_t *impl = get_ibi_impl(an); //get algorithm
	return impl->cmtlen;
}

size_t __ibi_chalen(uint8_t an){
	ibi_t *impl = get_ibi_impl(an); //get algorithm
	return impl->chalen;
}

size_t __ibi_reslen(uint8_t an){
	ibi_t *impl = get_ibi_impl(an); //get algorithm
	return impl->reslen;
}

void __ibi_keygen(uint8_t an, void **skout, void **pkout){
	ds_k_t *sk = __ds_kinit(an,0); //secret key
	ds_k_t *pk = __ds_kinit(an,1); //public key
	ds_t *impl = get_ibi_impl(an)->ds; //get algorithm
	impl->skgen(&(sk->k));
	impl->pkext(sk->k, &(pk->k));
	*skout = (void *)sk;
	*pkout = (void *)pk;
}

size_t __ibi_sklen(uint8_t an){
	ds_t *impl = get_ibi_impl(an)->ds; //get algorithm
	return (impl->sklen + 2);
}

size_t __ibi_pklen(uint8_t an){
	ds_t *impl = get_ibi_impl(an)->ds; //get algorithm
	return (impl->pklen + 2);
}

size_t __ibi_kserial(void *in, uint8_t *out, size_t mblen){
	ds_k_t *tmp = (ds_k_t *)in;
	ds_t *impl = get_ibi_impl(tmp->an)->ds; //get algorithm
	out[0] = tmp->an;
	out[1] = tmp->t;
	size_t rs = 2;
	if(tmp->t){
		assert( mblen >= __ibi_sklen(tmp->an) ); //ensure enough buffer space
		rs += impl->pkserial(tmp->k, out+rs);
	}else{
		assert( mblen >= __ibi_sklen(tmp->an) ); //ensure enough buffer space
		rs += impl->skserial(tmp->k, out+rs);
	}
	return rs;
}

void __ibi_kfree(void *in){
	ds_k_t *tmp = (ds_k_t *)in;
	ds_t *impl = get_ibi_impl(tmp->an)->ds; //get algorithm
	if(tmp->t){
		//public key
		impl->pkfree(tmp->k);
	}else{
		//secret key
		impl->skfree(tmp->k);
	}
	free(tmp);
}

size_t __ibi_kconstr(const uint8_t *in, void **out){
	ds_k_t *tmp = __ds_kinit(in[0], in[1]);
	ds_t *impl = get_ibi_impl(in[0])->ds; //get algorithm
	size_t rs = 2; //2 bytes read (an and k)
	if(in[1]){
		rs += impl->pkconstr(in+rs, &(tmp->k));
	}else{
		rs += impl->skconstr(in+rs, &(tmp->k));
	}
	*out = (void *)tmp;
	return rs;
}

void __ibi_kprint(void *in){
	ds_k_t *tmp = (ds_k_t *)in;
	ds_t *impl = get_ibi_impl(tmp->an)->ds; //get algorithm
	if(tmp->t){
		printf("public key, an: %02X\n",tmp->an);
		impl->pkprint(tmp->k);
	}else{
		printf("private key, an: %02X\n",tmp->an);
		impl->skprint(tmp->k);
	}
}

size_t __ibi_fqnread(void *in, uint8_t **fqn){
	ds_s_t *tmp = (ds_s_t *)in;
	ds_t *impl = get_ibi_impl(tmp->an)->ds;
	if( impl->fqnread ){
		return impl->fqnread(tmp->s, fqn);
	}
	// not implemented
	*fqn = NULL;
	return 0;
}

const ibi_if_t ibi = {
	.setup = __ibi_keygen,
	.issue = __ibi_ukgen,
	.validate = __ibi_ukvrf,

	.prvinit = __ibi_prvinit,
	.cmtgen = __ibi_cmtgen,
	.chagen = __ibi_chagen,
	.verinit = __ibi_verinit,
	.resgen = __ibi_resgen,
	.protdc = __ibi_protdc,

	.kfree = __ibi_kfree,
	.ufree = __ibi_ufree,
	.karead = __ds_karead,
	.ktread = __ds_ktread,
	.uaread = __ibi_uaread,
	.uiread = __ibi_uiread,
	.kserial = __ibi_kserial,
	.userial = __ibi_userial,
	.kconstr = __ibi_kconstr,
	.uconstr = __ibi_uconstr,

	.cmtlen = __ibi_cmtlen,
	.chalen = __ibi_chalen,
	.reslen = __ibi_reslen,
	.pklen = __ibi_pklen,
	.sklen = __ibi_sklen,
	.ukbslen = __ibi_ukbslen,
	.kprint = __ibi_kprint,
	.uprint = __ibi_uprint,
	.fqnread = __ibi_fqnread,
	.ishier = __ibi_ishier,
};
