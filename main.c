#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sched.h>
#include <pthread.h>

typedef struct TD{
	unsigned char *plain;
	unsigned char *keys;
	int count;
	int cpuid;
	int loopcount;
}ThreadData_t;

pthread_cond_t cpu_cond_mutex;
pthread_cond_t *out_cond = NULL;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int KeyFilesize;
char cpu_avail = 0;
int current_thread_count;
int NoOfProcessors;

void print_error(FILE *std,const char *fmt,...)
{
	va_list ap;
	va_start(ap,fmt);
	vfprintf(std,fmt,ap);
	va_end(ap);
}


void usage(){
	print_error(stderr,"%s","<Usage> :  encryptUtil [-n #][-k keyfile]\n");
	print_error(stderr,"%s","\t\t-n # Number of threads to create\n");
	print_error(stderr,"%s","\t\t-k keyfile Path to file containing key\n");
	print_error(stderr,"%s","<Example> : ./enryptUtil -n 4 -k keyfile\n");
}

void shiftkeys(char *Keys)
{
	unsigned char first_bit = Keys[0] & 0x80;
	for(int i=0;i<KeyFilesize;i++){
		Keys[i] = (Keys[i] << 1) |((i!= KeyFilesize -1) ?  ((Keys[i+1] & 0x80) >> 7) : (first_bit>>7));
		printf("key:%x \n",Keys[i]);
	}
}
void* XorEncrypt(void *arg)
{

	ThreadData_t *tdata = (ThreadData_t *)arg;
	printf("Count:%d\n cpuid:%d",tdata->count,tdata->cpuid);

	for(tdata->loopcount = 0;tdata->loopcount < KeyFilesize;tdata->loopcount++){
		tdata->plain[tdata->loopcount] = tdata->plain[tdata->loopcount] ^ tdata->keys[tdata->loopcount];
	}

	if(tdata->count != current_thread_count)
	{
		pthread_cond_wait(&out_cond[tdata->count],&mutex);
	}


	pthread_mutex_lock(&mutex);
	cpu_avail |= (1 << tdata->cpuid);
	if(++current_thread_count == NoOfProcessors){ 
        current_thread_count =0;
        }
	pthread_cond_signal(&out_cond[current_thread_count]);
	pthread_cond_signal(&cpu_cond_mutex);
	pthread_mutex_unlock(&mutex);
}

int main(int argc,char *argv[]){

	int opt,n;
	char *KeyFilename;
	unsigned char *Keys;
	if(argc < 5){
		usage();       
		exit(0);
	}
	while((opt = getopt(argc,argv,"n:k:")) != -1){
		switch(opt){
			case 'n':
				n = atoi(optarg);
				break;
			case 'k':
				{
					int len = strlen(optarg);
					KeyFilename = (char*)malloc(len+1);
					if(KeyFilename != NULL){
						memcpy(KeyFilename,optarg,len);
						KeyFilename[len] = '\0';
					}else{
						print_error(stderr,"Unable to allocate memory for KeyFilename:%s\n",optarg);
					}
					break;
				}
			case '?':
				usage();
				exit(0);
		}
	}
	printf("n:%d KeyFilename:%s\n",n,KeyFilename);
	if(KeyFilename != NULL){
		struct stat st;
		FILE *key_fp = fopen(KeyFilename,"rb");
		if(key_fp != NULL){
			if(stat(KeyFilename,&st) == 0){
				KeyFilesize = st.st_size;
			}else{
				print_error(stderr,"Could not determine File Size for File:%s",KeyFilename);
			}
			Keys = (unsigned char *)malloc(sizeof(char) * KeyFilesize);
			fread(Keys,sizeof(char),KeyFilesize,key_fp);

			fclose(key_fp);
		}else{
			print_error(stderr,"Could not open :%s\n",KeyFilename);
		}       

	}
	NoOfProcessors = sysconf(_SC_NPROCESSORS_ONLN);
	printf("No processors:%d \n",NoOfProcessors);
	for(int i=0;i<NoOfProcessors;i++){
		cpu_avail |= (1<<i);
	}
	pthread_t *tid = (pthread_t*)malloc(sizeof(pthread_t)*NoOfProcessors);
	pthread_attr_t *attr = (pthread_attr_t*)malloc(sizeof(pthread_attr_t) * NoOfProcessors);
	ThreadData_t *Tdata= (ThreadData_t*)malloc(sizeof(ThreadData_t)*NoOfProcessors);       
        out_cond = (pthread_cond_t*)malloc(sizeof(pthread_cond_t) * NoOfProcessors);
	//     cpu_set_t *cpus = (cpu_set_t*)malloc(sizeof(cpu_set_t) *NoOfProcessors);

	int current_core;
	int thread_count =0;
	while(!feof(stdin)){
		//fread(plain,sizeof(char),KeyFilesize,stdin);
		while(1){
			for(current_core=0;current_core<NoOfProcessors;current_core++){
				if(cpu_avail & (1<<current_core)){
					break;
				}
			} 
			if(cpu_avail)
				break;

			pthread_cond_wait(&cpu_cond_mutex,&mutex);
		}
		Tdata[current_core].plain = (unsigned char*)malloc(sizeof(char)*KeyFilesize);
		fread(Tdata[current_core].plain,sizeof(char),KeyFilesize,stdin);
		Tdata[current_core].keys = (unsigned char*)malloc(sizeof(char)*KeyFilesize); 
		memcpy(Tdata[current_core].keys,Keys,KeyFilesize);

		Tdata[current_core].count = thread_count;
		thread_count++;
		Tdata[current_core].cpuid = current_core;
		/* 
		   CPU_ZERO(&cpus[current_core]);
		   CPU_SET(current_core,&cpus[current_core] );
		   pthread_attr_setaffinity_np(&attr[current_core],sizeof(cpu_set_t),&cpus[current_core] );
		 */        
		pthread_mutex_lock(&mutex);
		cpu_avail = (cpu_avail &  ~(1 << current_core));
		pthread_mutex_unlock(&mutex);
		pthread_create(&tid[current_core],NULL,XorEncrypt,&Tdata[current_core]);              

	}

}
