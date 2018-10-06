#include <stdio.h>
#include <stdlib.h>

int main()
{

char key_array[] = {0xf0,0xf1,0xf3,0x12};

FILE *fp = fopen("keyfile","wb");

if(fp!= NULL){

fwrite(key_array,sizeof(key_array),1,fp);

fclose(fp);
}

}
