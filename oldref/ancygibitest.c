/*
 * Test code for ibi functions
 */

#include "../core.h"
#include "../utils/bufhelp.h"
//#include "../impl/ibi.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>

//linux
long long rdtsc(){
	unsigned int lo,hi;
	__asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
	return ((long long)hi << 32) | lo;
}

#define rnc 100
#define MEASUREMODE CLOCK_REALTIME
//#define MEASUREMODE CLOCK_PROCESS_CPUTIME_ID

int main(int argc, char *argv[]){

	int gmc = atoi(argv[1]);

	void *msk;
	void *mpk;
	void *gsk;
	void *greq;
	void **gusk; //assume 5 members
	void **gupk;
	int rc;
	unsigned char msg[64];
	unsigned char msg2[64];
	unsigned char *cmt, *cha, *res;
	void *pst, *vst;
	int dec;

	printf("running ancy group-ibi test\n");
	ancygibi.init();

	struct timespec swal, ewal;
	struct timespec sclk, eclk;
	unsigned long long scycle, ecycle; //cpu cycles

	double cputime_setup[rnc];
	double walltime_setup[rnc];
	unsigned long long cycles_setup[rnc];

	double cputime_e1[rnc];
	double walltime_e1[rnc];
	unsigned long long cycles_e1[rnc];

	double cputime_e2[rnc];
	double walltime_e2[rnc];
	unsigned long long cycles_e2[rnc];

	double cputime_i1[rnc];
	double walltime_i1[rnc];
	unsigned long long cycles_i1[rnc];

	double cputime_i2[rnc];
	double walltime_i2[rnc];
	unsigned long long cycles_i2[rnc];

	double cputime_i3[rnc];
	double walltime_i3[rnc];
	unsigned long long cycles_i3[rnc];

	long tsec, tnan;

	for(int i=0;i<rnc;i++){
		ghibcore.randombytes(msg, 64);
		ghibcore.randombytes(msg2, 64);

		//ta keygen
		clock_gettime(CLOCK_REALTIME, &swal);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &sclk);
		scycle = rdtsc();
		ancygibi.keygen(&msk);
		ancygibi.pkext(msk, &mpk);
		ecycle = rdtsc();
		clock_gettime(CLOCK_REALTIME, &ewal);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &eclk);

		tsec = ewal.tv_sec - swal.tv_sec;
    		tnan = ewal.tv_nsec - swal.tv_nsec;
		walltime_setup[i] = tsec + tnan*1e-9;
		tsec = eclk.tv_sec - sclk.tv_sec;
    		tnan = eclk.tv_nsec - sclk.tv_nsec;
		cputime_setup[i] = tsec + tnan*1e-9;
		cycles_setup[i] = ecycle - scycle;

		//group secret gen to group master
		clock_gettime(CLOCK_REALTIME, &swal);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &sclk);
		scycle = rdtsc();
		ancygibi.siggen(msk, msg, strlen(msg), &gsk);
		ecycle = rdtsc();
		clock_gettime(CLOCK_REALTIME, &ewal);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &eclk);
		//ancygibi.sigvrf(mpk, gsk, msg, strlen(msg), &rc);
		//assert(rc==0); //assure valid group key

		tsec = ewal.tv_sec - swal.tv_sec;
    		tnan = ewal.tv_nsec - swal.tv_nsec;
		walltime_e1[i] = tsec + tnan*1e-9;
		tsec = eclk.tv_sec - sclk.tv_sec;
    		tnan = eclk.tv_nsec - sclk.tv_nsec;
		cputime_e1[i] = tsec + tnan*1e-9;
		cycles_e1[i] = ecycle - scycle;

		//derive member keys
		gusk = (void **) malloc( gmc*sizeof(void *) );
		gupk = (void **) malloc( gmc*sizeof(void *) );

		clock_gettime(CLOCK_REALTIME, &swal);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &sclk);
		scycle = rdtsc();
		for(int j=0;j<gmc;j++){
			ancygibi.gmemkeyder(mpk, &(gusk[j]));
			ancygibi.pkext(gusk[j], &(gupk[j]));
		}
		ecycle = rdtsc();
		clock_gettime(CLOCK_REALTIME, &ewal);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &eclk);

		tsec = ewal.tv_sec - swal.tv_sec;
    		tnan = ewal.tv_nsec - swal.tv_nsec;
		walltime_e2[i] = tsec + tnan*1e-9;
		tsec = eclk.tv_sec - sclk.tv_sec;
    		tnan = eclk.tv_nsec - sclk.tv_nsec;
		cputime_e2[i] = tsec + tnan*1e-9;
		cycles_e2[i] = ecycle - scycle;

		//simulate, member 0 desire identification. gen signature

		clock_gettime(CLOCK_REALTIME, &swal);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &sclk);
		scycle = rdtsc();
		ancygibi.gidreqgen( gusk[0], msg2, strlen(msg2), &greq );
		ecycle = rdtsc();
		clock_gettime(CLOCK_REALTIME, &ewal);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &eclk);

		tsec = ewal.tv_sec - swal.tv_sec;
    		tnan = ewal.tv_nsec - swal.tv_nsec;
		walltime_i1[i] = tsec + tnan*1e-9;
		tsec = eclk.tv_sec - sclk.tv_sec;
    		tnan = eclk.tv_nsec - sclk.tv_nsec;
		cputime_i1[i] = tsec + tnan*1e-9;
		cycles_i1[i] = ecycle - scycle;

		clock_gettime(CLOCK_REALTIME, &swal);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &sclk);
		scycle = rdtsc();
		ancygibi.gidreqvrf( gupk[0], greq, msg2, strlen(msg2), &rc);
		ancygibi.sgfree(greq);
		assert(rc == 0);
		for(int j=1;j<gmc;j++){
			ancygibi.gidreqgen( gusk[j], msg2, strlen(msg2), &greq );
			ancygibi.gidreqvrf( gupk[j], greq, msg2, strlen(msg2), &rc);
			assert(rc==0);
			ancygibi.sgfree(greq);
		}
		ecycle = rdtsc();
		clock_gettime(CLOCK_REALTIME, &ewal);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &eclk);

		tsec = ewal.tv_sec - swal.tv_sec;
    		tnan = ewal.tv_nsec - swal.tv_nsec;
		walltime_i2[i] = tsec + tnan*1e-9;
		tsec = eclk.tv_sec - sclk.tv_sec;
    		tnan = eclk.tv_nsec - sclk.tv_nsec;
		cputime_i2[i] = tsec + tnan*1e-9;
		cycles_i2[i] = ecycle - scycle;

		clock_gettime(CLOCK_REALTIME, &swal);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &sclk);
		scycle = rdtsc();
		ancygibi.prvinit(gsk, msg, strlen(msg), &pst);
		ancygibi.cmtgen(&pst, &cmt);
		ancygibi.verinit(mpk, msg, strlen(msg), &vst);
		ancygibi.chagen(cmt, &vst, &cha);
		ancygibi.resgen(cha, pst, &res);
		ancygibi.protdc(res, vst, &dec);
		assert(dec==0);
		ecycle = rdtsc();
		clock_gettime(CLOCK_REALTIME, &ewal);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &eclk);

		tsec = ewal.tv_sec - swal.tv_sec;
    		tnan = ewal.tv_nsec - swal.tv_nsec;
		walltime_i3[i] = tsec + tnan*1e-9;
		tsec = eclk.tv_sec - sclk.tv_sec;
    		tnan = eclk.tv_nsec - sclk.tv_nsec;
		cputime_i3[i] = tsec + tnan*1e-9;
		cycles_i3[i] = ecycle - scycle;

		free(cmt);
		free(cha);
		free(res);
		ancygibi.skfree(msk);
		ancygibi.pkfree(mpk);
		ancygibi.sgfree(gsk);
		for(int j=0;j<gmc;j++){
			ancygibi.skfree(gusk[j]);
			ancygibi.pkfree(gupk[j]);
		}
		free(gusk);
		free(gupk);
	}

	for(int i=1;i<rnc;i++){
		cputime_setup[0] += cputime_setup[i];
		cputime_e1[0] += cputime_e1[i];
		cputime_e2[0] += cputime_e2[i];
		cputime_i1[0] += cputime_i1[i];
		cputime_i2[0] += cputime_i2[i];
		cputime_i3[0] += cputime_i3[i];

		walltime_setup[0] += walltime_setup[i];
		walltime_e1[0] += walltime_e1[i];
		walltime_e2[0] += walltime_e2[i];
		walltime_i1[0] += walltime_i1[i];
		walltime_i2[0] += walltime_i2[i];
		walltime_i3[0] += walltime_i3[i];

		cycles_setup[0] += cycles_setup[i];
		cycles_e1[0] += cycles_e1[i];
		cycles_e2[0] += cycles_e2[i];
		cycles_i1[0] += cycles_i1[i];
		cycles_i2[0] += cycles_i2[i];
		cycles_i3[0] += cycles_i3[i];
	}
	//uncomment to measure in seconds
	//cputime_setup[0] /= rnc;
	//cputime_e1[0] /= rnc;
	//cputime_e2[0] /= rnc;
	//cputime_i1[0] /= rnc;
	//cputime_i2[0] /= rnc;
	//cputime_i3[0] /= rnc;

	//walltime_setup[0] /= rnc;
	//walltime_e1[0] /= rnc;
	//walltime_e2[0] /= rnc;
	//walltime_i1[0] /= rnc;
	//walltime_i2[0] /= rnc;
	//walltime_i3[0] /= rnc;

	//cycles_setup[0] /= rnc;
	//cycles_e1[0] /= rnc;
	//cycles_e2[0] /= rnc;
	//cycles_i1[0] /= rnc;
	//cycles_i2[0] /= rnc;
	//cycles_i3[0] /= rnc;

	//printf("TOTAL ROUNDS: %d, TOTAL GROUP MEMBERS: %d\n",rnc,gmc);
	//printf("SETUP\n");
	//printf("CPUTIME: %fms\n",cputime_setup[0]);
	//printf("WALLTIME: %fms\n",walltime_setup[0]);
	//printf("CPUCYCLES: %llu\n",cycles_setup[0]);
	//printf("\n");

	//printf("EXTRACT PHASE 1\n");
	//printf("CPUTIME: %fms\n",cputime_e1[0]);
	//printf("WALLTIME: %fms\n",walltime_e1[0]);
	//printf("CPUCYCLES: %llu\n",cycles_e1[0]);
	//printf("\n");

	//printf("EXTRACT PHASE 2\n");
	//printf("CPUTIME: %fms\n",cputime_e2[0]);
	//printf("WALLTIME: %fms\n",walltime_e2[0]);
	//printf("CPUCYCLES: %llu\n",cycles_e2[0]);
	//printf("\n");

	//printf("IDENT PHASE 1\n");
	//printf("CPUTIME: %fms\n",cputime_i1[0]);
	//printf("WALLTIME: %fms\n",walltime_i1[0]);
	//printf("CPUCYCLES: %llu\n",cycles_i1[0]);
	//printf("\n");

	//printf("IDENT PHASE 2\n");
	//printf("CPUTIME: %fms\n",cputime_i2[0]);
	//printf("WALLTIME: %fms\n",walltime_i2[0]);
	//printf("CPUCYCLES: %llu\n",cycles_i2[0]);
	//printf("\n");

	//printf("IDENT PHASE 3\n");
	//printf("CPUTIME: %fms\n",cputime_i3[0]);
	//printf("WALLTIME: %fms\n",walltime_i3[0]);
	//printf("CPUCYCLES: %llu\n",cycles_i3[0]);
	//printf("\n");

	printf("TOTAL ROUNDS: %d, TOTAL GROUP MEMBERS: %d\n",rnc,gmc);
	printf("%f, %f, %llu,",cputime_setup[0], walltime_setup[0], cycles_setup[0]);
	printf("%f, %f, %llu,",cputime_e1[0],walltime_e1[0],cycles_e1[0]);
	printf("%f, %f, %llu,",cputime_e2[0],walltime_e2[0],cycles_e2[0]);
	printf("%f, %f, %llu,",cputime_i1[0],walltime_i1[0],cycles_i1[0]);
	printf("%f, %f, %llu,",cputime_i2[0],walltime_i2[0],cycles_i2[0]);
	printf("%f, %f, %llu,",cputime_i3[0],walltime_i3[0],cycles_i3[0]);
	printf("\n");
}

