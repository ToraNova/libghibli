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

#ifndef __IBI_H__
#define __IBI_H__

#include "ds.h"
#include <stddef.h>
#include <stdint.h>

typedef struct __ibi_u {
	uint8_t an; //algo type
	void *k; //key pointer
	size_t mlen;
	uint8_t *m; //user id
} ibi_u_t;

typedef struct __ibi_protst {
	uint8_t an; //algo type
	void *st; //protocol state
} ibi_protst_t;

// ibi from kurosawa-heng transforms (DS+HVZK)
typedef struct __ibi {
	ds_t *ds;
	//used by prover
	//generates a state information
	void (*prvinit)(void *vusk, const uint8_t *mbuf, size_t mlen, void **state);
	void (*cmtgen)(void **, uint8_t *);
	void (*resgen)(const uint8_t *, void *, uint8_t *);

	//used by verifier
	void (*verinit)(void *, const uint8_t *, size_t, void **);
	void (*chagen)(const uint8_t *, void **, uint8_t *);
	void (*protdc)(const uint8_t *, void *, int *);

	const size_t cmtlen;
	const size_t chalen;
	const size_t reslen;
} ibi_t;

extern const ibi_t heng04;
extern const ibi_t chin15;
extern const ibi_t vangujar19;

typedef struct __ibi_if {
	void (*setup)(uint8_t, void **, void **); //generate a ds_k_t sk and pk (setup)
	void (*issue)( void *, const uint8_t *, size_t, void ** ); //issue new user key
	void (*validate)(void *, void *, int *); //validate user key

	//generates a state information
	void (*prvinit)(void *, void **);
	void (*cmtgen)(void **, uint8_t *);
	void (*resgen)(const uint8_t *, void *, uint8_t *);
	//used by verifier
	void (*verinit)(void *, const uint8_t *, size_t, void **);
	void (*chagen)(const uint8_t *, void **, uint8_t *);
	void (*protdc)(const uint8_t *, void *, int *);

	void (*kfree)(void *); //free a sk/pk
	void (*ufree)(void *); //free a user key
	uint8_t (*karead)(void *);
	uint8_t (*ktread)(void *);
	uint8_t (*uaread)(void *);
	void (*uiread)(void *, uint8_t **, size_t *);
	size_t (*kserial)(void *, uint8_t *, size_t);
	size_t (*userial)(void *, uint8_t *, size_t);
	size_t (*kconstr)(const uint8_t *, void **);
	size_t (*uconstr)(const uint8_t *, size_t, void **);

	size_t (*pklen)(uint8_t);
	size_t (*sklen)(uint8_t);
	size_t (*ukbslen)(uint8_t);
	void (*kprint)(void *); //debugging
	void (*uprint)(void *);
	size_t (*cmtlen)(uint8_t);
	size_t (*chalen)(uint8_t);
	size_t (*reslen)(uint8_t);
} ibi_if_t;

extern const ibi_if_t ibi;

ibi_t *get_ibi_impl(uint8_t an);
#endif
