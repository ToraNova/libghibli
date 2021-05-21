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

#include "ds.h"
#include "../utils/debug.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

ds_t *get_ds_impl(uint8_t an){
	switch(an){
		case 0:
			return (ds_t *)&schnorr;
		default:
			return (ds_t *)&schnorr;
	}
}

size_t __ds_sklen(uint8_t an){
	ds_t *impl = get_ds_impl(an); //get algorithm
	return (impl->sklen + 2);
}

size_t __ds_pklen(uint8_t an){
	ds_t *impl = get_ds_impl(an); //get algorithm
	return (impl->pklen + 2);
}

size_t __ds_sglen(uint8_t an){
	ds_t *impl = get_ds_impl(an); //get algorithm
	return (impl->sglen + 1);
}

ds_k_t *__ds_kinit(uint8_t an, uint8_t t){
	ds_k_t *out = (ds_k_t*) malloc(sizeof(ds_k_t));
	out-> an = an;
	out-> t = t;
	return out;
}

ds_s_t *__ds_sinit(uint8_t an){
	ds_s_t *out = (ds_s_t*) malloc(sizeof(ds_s_t));
	out-> an = an;
	return out;
}

void __ds_keygen(uint8_t an, void **skout, void **pkout){
	ds_k_t *sk = __ds_kinit(an,0); //secret key
	ds_k_t *pk = __ds_kinit(an,1); //public key
	ds_t *impl = get_ds_impl(an); //get algorithm
	impl->skgen(&(sk->k));
	impl->pkext(sk->k, &(pk->k));
	*skout = (void *)sk;
	*pkout = (void *)pk;
}

void __ds_kfree(void *in){
	ds_k_t *tmp = (ds_k_t *)in;
	ds_t *impl = get_ds_impl(tmp->an); //get algorithm
	if(tmp->t){
		//public key
		impl->pkfree(tmp->k);
	}else{
		//secret key
		impl->skfree(tmp->k);
	}
	free(tmp);
}

void __ds_rfree(void *in){
	ds_s_t *tmp = (ds_s_t *)in;
	ds_t *impl = get_ds_impl(tmp->an); //get algorithm
	impl->sgfree(tmp->s);
	free(tmp);
}

uint8_t __ds_ktread(void *in){
	ds_k_t *tmp = (ds_k_t *)in;
	return tmp->t;
}

uint8_t __ds_karead(void *in){
	ds_k_t *tmp = (ds_k_t *)in;
	return tmp->an;
}

uint8_t __ds_raread(void *in){
	ds_s_t *tmp = (ds_s_t *)in;
	return tmp->an;
}

size_t __ds_kserial(void *in, uint8_t *out){
	ds_k_t *tmp = (ds_k_t *)in;
	ds_t *impl = get_ds_impl(tmp->an); //get algorithm
	out[0] = tmp->an;
	out[1] = tmp->t;
	size_t rs = 2;
	if(tmp->t){
		rs += impl->pkserial(tmp->k, out+rs);
	}else{
		rs += impl->skserial(tmp->k, out+rs);
	}
	return rs;
}

size_t __ds_rserial(void *in, uint8_t *out){
	ds_s_t *tmp = (ds_s_t *)in;
	ds_t *impl = get_ds_impl(tmp->an); //get algorithm
	out[0] = tmp->an;
	size_t rs = 1;
	rs += impl->sgserial(tmp->s, out+rs);
	return rs;
}

size_t __ds_kconstr(const uint8_t *in, void **out){
	ds_k_t *tmp = __ds_kinit(in[0], in[1]);
	ds_t *impl = get_ds_impl(in[0]); //get algorithm
	size_t rs = 2; //2 bytes read (an and k)
	if(in[1]){
		rs += impl->pkconstr(in+rs, &(tmp->k));
	}else{
		rs += impl->skconstr(in+rs, &(tmp->k));
	}
	*out = (void *)tmp;
	return rs;
}

size_t __ds_rconstr(const uint8_t *in, void **out){
	ds_s_t *tmp = __ds_sinit(in[0]);
	ds_t *impl = get_ds_impl(in[0]); //get algorithm
	size_t rs = 1;
	rs += impl->sgconstr(in+rs, &(tmp->s));
	*out = (void *)tmp;
	return rs;
}

void __ds_sign(void *vkey, const uint8_t *mbuf, size_t mlen, void **out){
	ds_k_t *tmp = (ds_k_t *)vkey;
	ds_t *impl = get_ds_impl(tmp->an); //get algorithm
	ds_s_t *sg = __ds_sinit(tmp->an); //intialize sig structure
	impl->siggen(tmp->k, mbuf, mlen, &(sg->s)); //sign using the implementation
	*out = (void *)sg;
}

void __ds_verify(void *vpar, void *vsig, const uint8_t *mbuf, size_t mlen, int *res){
	ds_k_t *pk = (ds_k_t *)vpar;
	ds_s_t *sg  = (ds_s_t *)vsig;
	if(pk->an != sg->an){ *res = 1; return; }
	ds_t *impl = get_ds_impl(pk->an); //get algorithm
	impl->sigvrf(pk->k, sg->s, mbuf, mlen, res);
}

void __ds_kprint(void *in){
	ds_k_t *tmp = (ds_k_t *)in;
	ds_t *impl = get_ds_impl(tmp->an); //get algorithm
	if(tmp->t){
		printf("public key, an: %02X\n",tmp->an);
		impl->pkprint(tmp->k);
	}else{
		printf("private key, an: %02X\n",tmp->an);
		impl->skprint(tmp->k);
	}
}

void __ds_rprint(void *in){
	ds_s_t *tmp = (ds_s_t *)in;
	ds_t *impl = get_ds_impl(tmp->an); //get algorithm
	printf("an:%02X\n",tmp->an);
	impl->sgprint(tmp->s);
}

const ds_if_t ds = {
	.keygen = __ds_keygen,
	.kfree = __ds_kfree,
	.ktread = __ds_ktread, //read key type (public/private)
	.karead = __ds_karead, //read key algo
	.raread = __ds_raread, //read sign algo
	.kserial = __ds_kserial,
	.rserial = __ds_rserial,
	.kconstr = __ds_kconstr,
	.rconstr = __ds_rconstr,
	.sign = __ds_sign,
	.verify = __ds_verify,
	.sklen = __ds_sklen,
	.pklen = __ds_pklen,
	.sglen = __ds_sglen,
	.kprint = __ds_kprint,
	.rprint = __ds_rprint,
	.rfree = __ds_rfree,
};
