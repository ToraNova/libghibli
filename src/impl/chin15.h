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

#ifndef __CHIN15_H__
#define __CHIN15_H__

#define CHIN15_PKLEN (2*RRE)
#define CHIN15_SKLEN (2*RRS+CHIN15_PKLEN)
#define CHIN15_SGLEN (3*RRS+2*RRE)

struct __chin15_pk {
	unsigned char *A;
	unsigned char *B2; //second base
};

struct __chin15_sk {
	unsigned char hf;
	struct __chin15_pk *pub;
	unsigned char *a1;
	unsigned char *a2;
};

struct __chin15_sg {
	unsigned char *s1;
	unsigned char *s2;
	unsigned char *x;
	unsigned char *U; //precomputation
	unsigned char *B2; //second base
};

struct __chin15_prvst {
	uint8_t *s1;
	uint8_t *s2;
	uint8_t *U; //precomputation
	uint8_t *B2;
	uint8_t *nonce1;
	uint8_t *nonce2;
	uint8_t *mbuf;
	size_t mlen;
};

struct __chin15_verst {
	uint8_t *A;
	uint8_t *B2;
	uint8_t *c; //challenge
	uint8_t *U; //precompute
	uint8_t *NE; //commit nonce group element
	uint8_t *mbuf;
	size_t mlen;
};

#define CHIN15_CMTLEN (2*RRE)
#define CHIN15_CHALEN RRS
#define CHIN15_RESLEN (2*RRS)

#define VANGUJAR19_SGBSLEN  (CHIN15_SGLEN + RRE + 2 + 1)
struct __vangujar19_sg {
	uint8_t hf;
	uint8_t hl; //hier level: 0-root
	size_t hnlen; //hier name length
	uint8_t *A; //public stored here as well
	uint8_t *hn; //hier name
	void *d; //key (chin15 design)
};

#endif
