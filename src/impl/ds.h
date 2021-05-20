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

struct __dss {
	int (*init)(void); //crypto initialization
	void (*keygen)(void **); //generate a random key
	void (*pkext)(void *, void **); //obtain pubkey from secret
	void (*siggen)( void *, const unsigned char *, size_t, void ** );
	void (*sigvrf)(void *,void *, const unsigned char *, size_t, int *);
	void (*skfree)(void *);
	void (*pkfree)(void *);
	void (*sgfree)(void *);
	void (*skprint)(void *);
	void (*pkprint)(void *);
	void (*sgprint)(void *);

	const size_t sklen;
	const size_t pklen;
	const size_t sglen;

	size_t (*skserial)(void *, unsigned char **);
	size_t (*pkserial)(void *, unsigned char **);
	size_t (*sgserial)(void *, unsigned char **);

	size_t (*skconstr)(const unsigned char *, void **);
	size_t (*pkconstr)(const unsigned char *, void **);
	size_t (*sgconstr)(const unsigned char *, void **);
};

extern const struct __dss schnorr;

extern const struct __dss *dss_impls[];

#endif
