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

#ifndef __GHIBLI_H__
#define __GHIBLI_H__

//PLEASE call cryptoinit() before using the library

#include "core.h"

#define GHIBC_FAIL     -1   // indicate a general failure
#define GHIBC_NO_ERR   0    // indicate ok
#define GHIBC_FILE_ERR 0x01 // unable to open file for reading
#define GHIBC_BUFF_ERR 0x02 // buffer error (memory/overflow)
#define GHIBC_SOCK_ERR 0x04 // socket creation/configuration error
#define GHIBC_CONN_ERR 0x08 // connection cannot be established

#define GHIBC_FLAG_VERBOSE 0x02 // verbosity flag

struct __ghibli_file {
	int (*setup)(char *, char *, int, int);
	int (*issue)(char *, char *, char *, int);
	int (*keycheck)(char *, char *, char **, size_t *, int);
	int (*agent)(char *, int);
	int (*pingver)(char *, char *, size_t, char *, size_t, int);
};

extern const struct __ghibli_file ghibfile;

#endif
