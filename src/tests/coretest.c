/*
 * Test code for core functions
 */

#include "../core.h"
#include "../utils/bufhelp.h"
#include <stdio.h>

int main(int argc, char *argv[]){

	unsigned char buf[64];

	ghibc_init();
	gc.randbytes(buf, 64);
	ucbprint(buf, 64); printf("\n");
}
