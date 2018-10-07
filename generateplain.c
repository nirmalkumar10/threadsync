#include <stdio.h>
#include <stdlib.h>

#define PLAINSIZE 40

int main()
{

FILE *fp = fopen("plaintext","wb");

char plain = 0;

if(fp != NULL){

for(char i=0;i<PLAINSIZE;i++){
plain +=i;
fwrite(&plain,sizeof(plain),1,fp);
plain=0;
}

fclose(fp);
}


}
