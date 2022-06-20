#include <unistd.h>

void* smalloc(size_t size)
{
    if(size == 0 || size > 1e8)
	{
		return NULL;
	}
	
	void* prev_pgbrk = sbrk(0);
	void* ret = sbrk(size);
	
	if(ret != prev_pgbrk)
	{
		return NULL;
	}
	
	return prev_pgbrk;
}