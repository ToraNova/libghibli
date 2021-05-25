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

#include <string.h>
#include <assert.h>
#include <sodium.h>
#include "../utils/bufhelp.h"
#include "../utils/debug.h"
#include "__crypto.h"
#include "ibi.h"
#include "chin15.h"

/*
const ibi_t vangujar19 = {
	.ds = (ds_t *)&__vangujar19,
	.prvinit = chin15.prvinit, //proto
	.cmtgen = chin15.cmtgen,
	.resgen = chin15.resgen,
	.verinit = chin15.verinit,
	.chagen = chin15.chagen,
	.protdc = chin15.protdc,
	.cmtlen = CHIN15_CMTLEN,
	.chalen = CHIN15_CHALEN,
	.reslen = CHIN15_RESLEN,
};
*/
