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

#ifndef __DS_H__
#define __DS_H__

#include <stddef.h>
#include <stdint.h>

typedef struct __ds_k {
	uint8_t an; //algo
	uint8_t t; //key type
	void *k; //key pointer
} ds_k_t;

// signature type
typedef struct __ds_s {
	uint8_t an; //algo
	void *s; //key pointer
} ds_s_t;

// raw implementation
typedef struct __ds {
	void (*skgen)(void **); //generate secret key
	void (*pkext)(void *, void **); //obtain pubkey from secret
	void (*siggen)(void *, const uint8_t *, size_t, void **);
	void (*sigvrf)(void *,void *, const uint8_t *, size_t, int *);
	void (*skfree)(void *);
	void (*pkfree)(void *);
	void (*sgfree)(void *);
	void (*skprint)(void *);
	void (*pkprint)(void *);
	void (*sgprint)(void *);
	size_t (*skserial)(void *, uint8_t *);
	size_t (*pkserial)(void *, uint8_t *);
	size_t (*sgserial)(void *, uint8_t *);
	size_t (*skconstr)(const uint8_t *, void **);
	size_t (*pkconstr)(const uint8_t *, void **);
	size_t (*sgconstr)(const uint8_t *, void **);
	const size_t sklen;
	const size_t pklen;
	const size_t sglen;
} ds_t;

// ds implemented
extern const ds_t schnorr;

// interfaces
typedef struct __ds_if {
	void (*keygen)(uint8_t, void **, void **); //generate a ds_k_t sk and pk
	void (*sign)(void *, const uint8_t *, size_t , void **); //sign msg
	void (*verify)(void *, void *, const uint8_t *, size_t , int *); //verify msg

	void (*kfree)(void *); //free a ds_k_t key
	void (*rfree)(void *); //free a signature
	uint8_t (*ktread)(void *); //read the key type
	uint8_t (*karead)(void *); //read the key algo
	uint8_t (*raread)(void *); //read the sign algo
	size_t (*kserial)(void *, uint8_t *); //serialize key
	size_t (*rserial)(void *, uint8_t *); //serialize signature
	size_t (*kconstr)(const uint8_t *, void **); //constrct key from serialization
	size_t (*rconstr)(const uint8_t *, void **); //construct signature from serialization

	size_t (*sklen)(uint8_t); //length of sk based on algo
	size_t (*pklen)(uint8_t); //length of pk based on algo
	size_t (*sglen)(uint8_t); //length of sg based on algo
	void (*kprint)(void *); //debugging use (print keys)
	void (*rprint)(void *);
} ds_if_t;

extern const ds_if_t ds;

ds_t *get_ds_impl(uint8_t an);

// for internal usage
size_t __ds_sklen(uint8_t an);
size_t __ds_pklen(uint8_t an);
size_t __ds_sglen(uint8_t an);
ds_k_t *__ds_kinit(uint8_t an, uint8_t t);
ds_s_t *__ds_sinit(uint8_t an);
void __ds_keygen(uint8_t an, void **skout, void **pkout);
void __ds_kfree(void *in);
void __ds_rfree(void *in);
uint8_t __ds_ktread(void *in);
uint8_t __ds_karead(void *in);
uint8_t __ds_raread(void *in);
size_t __ds_kserial(void *in, uint8_t *out);
size_t __ds_rserial(void *in, uint8_t *out);
size_t __ds_kconstr(const uint8_t *in, void **out);
size_t __ds_rconstr(const uint8_t *in, void **out);
void __ds_sign(void *vkey, const uint8_t *mbuf, size_t mlen, void **out);
void __ds_verify(void *vpar, void *vsig, const uint8_t *mbuf, size_t mlen, int *res);
void __ds_kprint(void *in);
void __ds_rprint(void *in);

#endif
