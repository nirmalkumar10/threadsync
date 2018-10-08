#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sched.h>
#include <pthread.h>
#include <semaphore.h>

#define HASH_ELEMS 5
#define CORE0  0

typedef struct HmOutData{
	int DataId;
	int DataValid;
	unsigned char *Encrypted;
	struct HmOutData *next;
}HmOutData_t;

HmOutData_t *HmOutElem[HASH_ELEMS];

typedef struct TD{
	unsigned char *plain;
	unsigned char *keys;
	int index;
	int loopcount;
	int buffer_count;
	HmOutData_t *trav;
	sem_t read_sem;         /* Read semaphore used by helper threads waiting on main thread to provide plaintext data*/
	sem_t write_sem;        /* Write semaphore used by main thread to overwrite new data when helper threads complete encryption*/
}ThreadData_t;


pthread_cond_t cpu_cond_mutex;
pthread_cond_t *out_cond = NULL;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int KeyFilesize;
static char cpu_avail = 0;
static int current_thread_count;
static int NoOfProcessors;

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
	}
}
void* XorEncrypt(void *arg)
{

	ThreadData_t *tdata = (ThreadData_t *)arg;
	printf("running on CPU:%3d\n",sched_getcpu());
	while(1){	
		sem_wait(&tdata->read_sem);
		tdata->index = (tdata->buffer_count / 10); 
		tdata->trav = HmOutElem[tdata->index];
		for(int i=0;i<(tdata->buffer_count %10);i++){
			tdata->trav = tdata->trav->next;
		}
		for(tdata->loopcount = 0;tdata->loopcount < KeyFilesize;tdata->loopcount++){
			tdata->trav->Encrypted[tdata->loopcount] = tdata->plain[tdata->loopcount] ^ tdata->keys[tdata->loopcount];   
			//printf("Xor:%d\t",tdata->trav->Encrypted[tdata->loopcount]);
		}
		tdata->trav->DataValid =1;
		printf("\n");
		sem_post(&tdata->write_sem);
	}
}

void* OutputData(void *arg)
{

	int buffer_read_count=0;
	while(1){
		int index = (buffer_read_count /10);
		int offset = (buffer_read_count %10);
		HmOutData_t *trav = HmOutElem[index];
		printf("index:%d offset:%d\n",index,offset);
		for(int i=0;i<offset;i++){
			trav = trav->next;
		}
		while(1){
			if(trav!= NULL && trav->DataValid){

				for(int i=0;i<KeyFilesize;i++){
					printf("XOREncr:%d",trav->Encrypted[i]);

				}
				buffer_read_count++;
				break;
			}
		}
	}
}

void Create_HashOutData(){

	HmOutData_t *trav;

	for(int i=0;i<HASH_ELEMS;i++){
		HmOutElem[i] = (HmOutData_t*)calloc(sizeof(HmOutData_t),1);
		trav = HmOutElem[i];
		trav->DataId = 0;                
		trav->Encrypted = (unsigned char*)malloc(sizeof(char)*KeyFilesize);
		for(int i=1;i<10;i++){

			HmOutData_t *temp = (HmOutData_t*)calloc(sizeof(HmOutData_t),1);
			temp->DataId =i;
			temp->Encrypted = (unsigned char*)malloc(sizeof(char)*KeyFilesize);
			trav->next=temp;
			trav = trav->next;
		}

	}
}

int main(int argc,char *argv[]){

	int opt,NumThreads;
	char *KeyFilename;
	void *ret;
	unsigned char *Keys;
	if(argc < 5){
		usage();       
		exit(0);
	}
	while((opt = getopt(argc,argv,"n:k:")) != -1){  /* Get Options for Number of threads and keyfile name*/
		switch(opt){
			case 'n':
				NumThreads = atoi(optarg);
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
                                                exit(0);
					}
					break;
				}
			case '?':
				usage();
				exit(0);
		}
	}
	if(KeyFilename != NULL){              /* Open KeyFile ,read the size and store the key */
		struct stat st;
		FILE *key_fp = fopen(KeyFilename,"rb");
		if(key_fp != NULL){
			if(stat(KeyFilename,&st) == 0){
				KeyFilesize = st.st_size;
			}else{
				print_error(stderr,"Could not determine File Size for File:%s",KeyFilename);
                                exit(0);
			}
			Keys = (unsigned char *)malloc(sizeof(char) * KeyFilesize);
			fread(Keys,sizeof(char),KeyFilesize,key_fp);

			fclose(key_fp);
		}else{
			print_error(stderr,"Could not open :%s\n",KeyFilename);
                        exit(0);
		}       

	}

	NoOfProcessors = sysconf(_SC_NPROCESSORS_ONLN);       

	pthread_t *tid = (pthread_t*)malloc(sizeof(pthread_t)*NumThreads);
	pthread_t out_id;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	ThreadData_t *Tdata= (ThreadData_t*)malloc(sizeof(ThreadData_t)*NumThreads);       
	cpu_set_t cpus;

	int current_core =1;
	int current_buffer_write_count =0;

	CPU_ZERO(&cpus);
	CPU_SET(CORE0,&cpus);
	sched_setaffinity(0,sizeof(cpu_set_t),&cpus);  /* Set Main thread to run from CORE 0 */

	Create_HashOutData();                        /* Initialise datastructure for storing encrypted data */
	printf("Main process CPU:%3d\n",sched_getcpu());
	for(int threadcount = 0;threadcount <NumThreads;threadcount++){
		Tdata[threadcount].plain = (unsigned char*)malloc(sizeof(char)*KeyFilesize);
		Tdata[threadcount].keys = (unsigned char*)malloc(sizeof(char)*KeyFilesize);
		sem_init(&Tdata[threadcount].read_sem,1,0);
		sem_init(&Tdata[threadcount].write_sem,1,1);  

		CPU_ZERO(&cpus);
		CPU_SET(current_core,&cpus);
		pthread_attr_setaffinity_np(&attr,sizeof(cpu_set_t),&cpus);
		pthread_create(&tid[threadcount],&attr,XorEncrypt,&Tdata[threadcount]);  /* Create threads with different CPU affinity */
		current_core++;
		if((current_core) == NoOfProcessors){
			current_core =1;
		}

	}

	CPU_ZERO(&cpus);
	CPU_SET(CORE0,&cpus);
	pthread_attr_setaffinity_np(&attr,sizeof(cpu_set_t),&cpus); 
	pthread_create(&out_id,&attr,OutputData,NULL); /* Separate thread running from CORE0 to output encrypted data */

	while(!feof(stdin)){

		for(int threadcount =0;threadcount<NumThreads;threadcount++){

			if(sem_wait(&Tdata[threadcount].write_sem) == 0){
				fread(Tdata[threadcount].plain,sizeof(char),KeyFilesize,stdin);
				memcpy(Tdata[threadcount].keys,Keys,KeyFilesize);
				Tdata[threadcount].buffer_count = current_buffer_write_count;
				current_buffer_write_count++;
				sem_post(&Tdata[threadcount].read_sem);
				shiftkeys(Keys);              /* Shift encryption key after one block */
			}else{
				continue;
			}

		}
	}
	pthread_join(out_id,&ret);

}
