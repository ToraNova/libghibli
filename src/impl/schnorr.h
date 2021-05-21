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

#ifndef __SCHNORR_H__
#define __SCHNORR_H__

#define SCHNORR_PKLEN RRE
#define SCHNORR_SKLEN RRS+SCHNORR_PKLEN
#define SCHNORR_SGLEN (2*RRS+RRE)

struct __schnorr_pk {
	unsigned char *A;
};

struct __schnorr_sk {
	struct __schnorr_pk *pub;
	unsigned char *a;
};

struct __schnorr_sg {
	unsigned char *s;
	unsigned char *x;
	unsigned char *U; //precomputation
};

void __schnorr_hashexec(
	const uint8_t *mbuf, size_t mlen,
	uint8_t *ubuf,
	uint8_t *vbuf,
	uint8_t *oarr
);
#endif
