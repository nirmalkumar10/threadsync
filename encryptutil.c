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

#define HASH_ELEMS 20
#define HASH_LENGTH 10
#define MAIN_CORE  0
#define OUTPUT_CORE  1 

typedef struct HmOutData{
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


static int KeyFilesize;
static int NoOfProcessors;
static int bytes_read ;
static int buffer_read_count=0;
static int current_buffer_write_count =0;

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
	while(1){
		sem_wait(&tdata->read_sem);
		tdata->index = (tdata->buffer_count / HASH_LENGTH); 
		tdata->trav = HmOutElem[tdata->index];
		for(int i=0;i<(tdata->buffer_count % HASH_LENGTH);i++){
			tdata->trav = tdata->trav->next;
		}
		for(tdata->loopcount = 0;tdata->loopcount < KeyFilesize;tdata->loopcount++){
			tdata->trav->Encrypted[tdata->loopcount] = tdata->plain[tdata->loopcount] ^ tdata->keys[tdata->loopcount];   
		}
		tdata->trav->DataValid =1;
		sem_post(&tdata->write_sem);
		if(bytes_read == -1){
			pthread_exit((void*)arg);
		}
	}
}

/*

   Thread runs from CORE 0 along with main thread
   Outputs encrypted data created by helper threads to stdout
 */

void* OutputData(void *arg)
{
	while(1){
		int index = (buffer_read_count /HASH_LENGTH);
		int offset = (buffer_read_count %HASH_LENGTH);
		HmOutData_t *trav = HmOutElem[index];
		for(int i=0;i<offset;i++){
			trav = trav->next;
		}
		while(1){
			if((trav!= NULL) && (trav->DataValid ==1)){
				for(int i=0;i<KeyFilesize;i++){
					fwrite(&trav->Encrypted[i],sizeof(char),1,stdout);
					trav->DataValid =0;
				}
				fflush(stdout);
				buffer_read_count++;
				if(buffer_read_count == (HASH_ELEMS * HASH_LENGTH)) {
					buffer_read_count =0;
				}
			}
			break;
		}
		if((buffer_read_count == current_buffer_write_count) && (bytes_read ==-1) ) {
			pthread_exit((void*)arg); 
		}
	}
}

void Create_HashOutData(){

	HmOutData_t *trav;

	for(int i=0;i<HASH_ELEMS;i++){
		HmOutElem[i] = (HmOutData_t*)calloc(sizeof(HmOutData_t),1);
		trav = HmOutElem[i];
		trav->Encrypted = (unsigned char*)malloc(sizeof(char)*KeyFilesize);
		for(int i=1;i<HASH_LENGTH;i++){

			HmOutData_t *temp = (HmOutData_t*)calloc(sizeof(HmOutData_t),1);
			temp->Encrypted = (unsigned char*)malloc(sizeof(char)*KeyFilesize);
			trav->next=temp;
			trav = trav->next;
		}

	}
}

void Delete_HashOutData()
{

	HmOutData_t *trav,*temp;;
	for(int i=0;i<HASH_ELEMS;i++){
		temp = trav = HmOutElem[i];
		while(trav != NULL){
			trav = trav->next;
			free(temp->Encrypted);
			free(temp);
			temp = trav;
		}
	}
}

int main(int argc,char *argv[]){

	int opt,NumThreads,keys_read;
	char *KeyFilename;
	unsigned char *Keys;
	if(argc < 5){
		usage();       
		exit(0);
	}
	while((opt = getopt(argc,argv,"n:k:")) != -1){  /* Get Options for Number of threads and keyfile name*/
		switch(opt){
			case 'n':{
					 NumThreads = atoi(optarg);
					 if(NumThreads == 0) {
						 NumThreads =1;
					 }
					 if(NumThreads < 0){
						 print_error(stderr,"Invalid Number of Threads :%d specified\n",NumThreads);
						 usage();
						 exit(0);
					 }
					 break;
				 }
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
			if(Keys != NULL){
				keys_read = fread(Keys,sizeof(char),KeyFilesize,key_fp);
			}
			if((Keys == NULL ) || (keys_read != KeyFilesize)){
				print_error(stderr,"Reading from %s failed",KeyFilename);
			}
			free(KeyFilename);
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
	if(tid == NULL || Tdata ==  NULL){
		print_error(stderr,"%s","Malloc failed for pthreads");
		exit(0);
	}
	int current_core =2;
	int diff =0;
	CPU_ZERO(&cpus);
	CPU_SET(MAIN_CORE,&cpus);
	sched_setaffinity(0,sizeof(cpu_set_t),&cpus);  /* Set Main thread to run from CORE 0 - Reads input data from stdin */

	Create_HashOutData();                        /* Initialise datastructure for storing encrypted data */
	for(int threadcount = 0;threadcount <NumThreads;threadcount++){
		Tdata[threadcount].plain = (unsigned char*)malloc(sizeof(char)*KeyFilesize);
		Tdata[threadcount].keys = (unsigned char*)malloc(sizeof(char)*KeyFilesize);
		sem_init(&Tdata[threadcount].read_sem,1,0);
		sem_init(&Tdata[threadcount].write_sem,1,1);  

		CPU_ZERO(&cpus);
		CPU_SET(current_core,&cpus);
		pthread_attr_setaffinity_np(&attr,sizeof(cpu_set_t),&cpus);
		pthread_create(&tid[threadcount],&attr,XorEncrypt,&Tdata[threadcount]);/* Create Encryptor threads with different CPU affinity */
		current_core++;
		if((current_core) == NoOfProcessors){
			current_core =2;
		}

	}

	CPU_ZERO(&cpus);
	CPU_SET(OUTPUT_CORE,&cpus);
	pthread_attr_setaffinity_np(&attr,sizeof(cpu_set_t),&cpus); 
	pthread_create(&out_id,&attr,OutputData,NULL); /* Separate thread running from CORE 1 to output encrypted data */

	while(!feof(stdin)){

		for(int threadcount =0;threadcount<NumThreads;threadcount++){
			diff =buffer_read_count - current_buffer_write_count;
			if((diff < 50) && ( diff > 0 ) ) {
				break; 
			}
			fflush(stdout);
			if(sem_wait(&Tdata[threadcount].write_sem) == 0){
				bytes_read = fread(Tdata[threadcount].plain,sizeof(char),KeyFilesize,stdin);
				if(bytes_read != KeyFilesize){
					break;
				}

				memcpy(Tdata[threadcount].keys,Keys,KeyFilesize);
				Tdata[threadcount].buffer_count = current_buffer_write_count;
				current_buffer_write_count++;
				if(current_buffer_write_count == (HASH_ELEMS * HASH_LENGTH)){
					current_buffer_write_count =0;
				}
				sem_post(&Tdata[threadcount].read_sem);
				shiftkeys(Keys);              /* Shift encryption key after one block */
			}else{
				continue;
			}
		}
	}
	bytes_read =-1;
	for(int threadcount=0;threadcount<NumThreads;threadcount++){
		sem_post(&Tdata[threadcount].read_sem);
		pthread_join(tid[threadcount],NULL);
	}
	pthread_join(out_id,NULL);
	Delete_HashOutData();
	for(int i=0;i<NumThreads;i++){
		free(Tdata[i].plain);
		free(Tdata[i].keys);
	}
	free(Tdata);
	free(Keys);
	free(tid);
}
