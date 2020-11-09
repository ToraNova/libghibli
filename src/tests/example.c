#include "ghibli.h"
#include "utils/bufhelp.h"

int main(int argc, char *argv[]){
	unsigned char buf[64];
	ghibcore.randombytes(buf, 64);
	ucbprint(buf, 64);
}
