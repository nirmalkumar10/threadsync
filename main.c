#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

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
int main(int argc,char *argv[]){

	int opt,n;
	char *KeyFilename;
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
		int KeyFilesize;
		char *Keys;
		FILE *key_fp = fopen(KeyFilename,"rb");
		if(key_fp != NULL){
			if(stat(KeyFilename,&st) == 0){
				KeyFilesize = st.st_size;
			}else{
				print_error(stderr,"Could not determine File Size for File:%s",KeyFilename);
			}
			Keys = (char *)malloc(sizeof(char) * KeyFilesize);
			for(int i=0;i<KeyFilesize;i++) {
				fread(&Keys[i],sizeof(char),1,key_fp);
			}                
			fclose(key_fp);
		}else{
                    print_error(stderr,"Could not open :%s\n",KeyFilename);
                   }       

	}



}
