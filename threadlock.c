
#include <pthread.h>
#include <stdio.h>

int sharedResource = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t *cond = NULL;

void* fooAPI(void* param)
{
    pthread_mutex_lock(&mutex);
    printf("Changing the shared resource now.\n");
sleep(2);
pthread_cond_wait(cond,&mutex);
    sharedResource = 42;
    pthread_mutex_unlock(&mutex);
    return 0;
}

int main()
{
    pthread_t thread;
cond = (pthread_cond_t*)malloc(sizeof(pthread_cond_t)*1);
    // Really not locking for any reason other than to make the point.
    pthread_mutex_lock(&mutex);
    pthread_create(&thread, NULL, fooAPI, NULL);
    sleep(1);
	printf("sharedResouce:%d\n",sharedResource);
//pthread_cond_signal(cond);
    pthread_mutex_unlock(&mutex);

    // Now we need to lock to use the shared resource.
    pthread_mutex_lock(&mutex);
    printf("%d\n", sharedResource);
    pthread_mutex_unlock(&mutex);
}
