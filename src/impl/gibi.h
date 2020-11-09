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

#ifndef __GIBI_H_
#define __GIBI_H_

#include <stddef.h>

struct __gibi {

	void (*randkeygen)(void **); //generate a random key
	void (*getpubkey)(void *, void **); //obtain pubkey from secret
	void (*signatgen)( void *, const unsigned char *, size_t, void ** );
	void (*signatchk)(void *,void *, const unsigned char *, size_t, int *);
	void (*skfree)(void *);
	void (*pkfree)(void *);
	void (*sgfree)(void *);
	void (*skprint)(void *);
	void (*pkprint)(void *);
	void (*sgprint)(void *);

	//group manager key derive (group public and group secret)
	void (*gmemkeyder)( void *, void **); //e:phase 2
	void (*gidreqgen)(void *, const unsigned char *, size_t, void **); //i:phase 1
	void (*gidreqchk)(void *, void *, const unsigned char *, size_t, int *); //i:phase 2

	//used by prover
	//generates a state information
	void (*prvinit)(void *, const unsigned char *, size_t, void **);
	void (*cmtgen)(void **, unsigned char **);
	void (*resgen)(const unsigned char *, void *, unsigned char **);

	//used by verifier
	void (*verinit)(void *, const unsigned char *, size_t, void **);
	void (*chagen)(const unsigned char *, void **, unsigned char **);
	void (*protdc)(const unsigned char *, void *, int *);

	const size_t cmtlen;
	const size_t chalen;
	const size_t reslen;

	//TODO: DER encoding? base64? find a good way to serialize
	//size_t (*secserial)(void *, unsigned char **, size_t *);
	//size_t (*pubserial)(void *, unsigned char **, size_t *);
	//size_t (*sigserial)(void *, unsigned char **, size_t *);
	//void (*secstruct)(const unsigned char *, size_t, void **);
	//void (*pubstruct)(const unsigned char *, size_t, void **);
	//void (*sigstruct)(const unsigned char *, size_t, void **);
};

extern const struct __gibi ancygibi;

extern const struct __gibi *gibi_impls[];

#endif
