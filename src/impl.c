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

#include "impl.h"

const struct __ibi *ibi_impls[] = {
	&schibi,
	&tscibi,
	NULL,
};

//initialize the "default ibi"
struct __ibi init_ibi_impl(int an){
	struct __ibi ftable = {
	.keygen = ibi_impls[an]->keygen,
	.pkext = ibi_impls[an]->pkext,
	.siggen = ibi_impls[an]->siggen,
	.sigvrf = ibi_impls[an]->sigvrf,
	.skfree = ibi_impls[an]->skfree,
	.pkfree = ibi_impls[an]->pkfree,
	.sgfree = ibi_impls[an]->sgfree,
	.skprint = ibi_impls[an]->skprint,
	.pkprint = ibi_impls[an]->pkprint,
	.sgprint = ibi_impls[an]->sgprint,
	.prvinit = ibi_impls[an]->prvinit,
	.cmtgen = ibi_impls[an]->cmtgen,
	.resgen = ibi_impls[an]->resgen,
	.verinit = ibi_impls[an]->verinit,
	.chagen = ibi_impls[an]->chagen,
	.protdc = ibi_impls[an]->protdc,
	.cmtlen = ibi_impls[an]->cmtlen,
	.chalen = ibi_impls[an]->chalen,
	.reslen = ibi_impls[an]->reslen,
	};
}
