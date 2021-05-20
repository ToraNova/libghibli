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

#include <stddef.h>

struct __ibi_uk {
	void *k;
	size_t mlen;
	unsigned char *m;
};

struct __ibi {
	int (*init)(void); //crypto initialization
	void (*keygen)(void **); //generate a random key
	void (*pkext)(void *, void **); //obtain pubkey from secret
	void (*skfree)(void *);
	void (*pkfree)(void *);
	void (*skprint)(void *);
	void (*pkprint)(void *);
	const size_t sklen;
	const size_t pklen;
	const size_t ukbaselen;
	size_t (*skserial)(void *, unsigned char **);
	size_t (*pkserial)(void *, unsigned char **);
	size_t (*skconstr)(const unsigned char *, void **);
	size_t (*pkconstr)(const unsigned char *, void **);

	void (*issue)( void *, const unsigned char *, size_t, void ** );
	void (*validate)(void *, void *, int *);
	size_t (*idext)(void *, unsigned char **);
	void (*ukfree)(void *);
	void (*ukprint)(void *);
	size_t (*ukserial)(void *, unsigned char **);
	size_t (*ukconstr)(const unsigned char *, size_t, void **);

	//used by prover
	//generates a state information
	void (*prvinit)(void *, void **);
	void (*cmtgen)(void **, unsigned char **);
	void (*resgen)(const unsigned char *, void *, unsigned char **);

	//used by verifier
	void (*verinit)(void *, const unsigned char *, size_t, void **);
	void (*chagen)(const unsigned char *, void **, unsigned char **);
	void (*protdc)(const unsigned char *, void *, int *);

	const size_t cmtlen;
	const size_t chalen;
	const size_t reslen;
};

struct __ibi_uk *__ibi_ukinit(size_t);

extern const struct __ibi schnorr_ibi;
//extern const struct __ibi tscibi;

extern const struct __ibi *ibi_impls[];

#endif
