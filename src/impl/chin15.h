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
#endif
