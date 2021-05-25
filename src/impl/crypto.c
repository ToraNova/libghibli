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

#include <sodium.h>
#include "__crypto.h"
#include "utils/debug.h"

int __sodium_init(){
	//2020 Nov 09, using libsodium
	int rc = sodium_init();
	if(rc == 0 | rc == 1){
		// no error 0
		// already initialized 1
		return 0;
	}
	lerror("unable to initialize libsodium secure memory!\n");
	return 1;
}

//assumes arr is alloc with RRS
void __sodium_2rinhashexec(
	const uint8_t *mbuf, size_t mlen,
	uint8_t *ubuf,
	uint8_t *vbuf,
	uint8_t *oarr
){
	crypto_hash_sha512_state state;
	uint8_t tbuf[RRH]; //hash
	//compute hash
	crypto_hash_sha512_init( &state );
	crypto_hash_sha512_update( &state, mbuf, mlen);
	crypto_hash_sha512_update( &state, ubuf, RRE);
	crypto_hash_sha512_update( &state, vbuf, RRE);
	crypto_hash_sha512_final( &state, tbuf);
	crypto_core_ristretto255_scalar_reduce(
		oarr, (const uint8_t *)tbuf
	);
}
