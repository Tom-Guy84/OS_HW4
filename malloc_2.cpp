#include <unistd.h>
#include <string.h>

#define TRUE 1
#define FALSE 0

typedef struct MalocMetadata* MMData;
struct MalocMetadata
{
	size_t size;
	int is_free;
	MMData next;
	MMData prev;
};

MMData global_data = NULL;

void* init_data(size_t size)
{
	void* prev_pgbrk = sbrk(0);
	void* res = sbrk(sizeof(*global_data) + size);
	
	if(prev_pgbrk != res)
		return NULL;
	
	MMData new_data = (MMData) res;
	new_data->size = size;
	new_data->is_free = FALSE;
	new_data->next = NULL;
	new_data->prev = NULL;
	
	return res;
}

void insert_sorted (MMData new_val)
{
	MMData temp = global_data;
	
	if(temp > new_val)
	{
		new_val->next = temp;
		new_val->prev = NULL;
		temp->prev = new_val;
		
		global_data = new_val;
		
		return;
	}
	while(temp->next != NULL && temp->next < new_val)
	{
		temp = temp->next;
	}
	
	new_val->next = temp->next;
	temp->next = new_val;
	new_val->prev = temp;
	
	if (new_val->next != NULL)
	{
		new_val->next->prev = new_val;
	}
}

MMData first_free(size_t size)
{
	MMData temp = global_data;
	

	while(temp != NULL)
	{
		if(temp->size >= size && temp->is_free)
			return temp;
		temp = temp->next;
	}
	return NULL;
}

void* smalloc(size_t size)
{
    if(size == 0 || size > 1e8)
	{
		return NULL;
	}
			
	MMData trying_with_freed = first_free(size);
	
	void* ret = NULL;
	
	if(trying_with_freed == NULL)
	{
		ret = init_data(size);
		if(ret == NULL) return NULL;
		
		if(global_data == NULL)
		{
			global_data = (MMData) ret;
		}
		else
		{
			MMData ret_data = (MMData) ret;
			insert_sorted(ret_data);
		}
	}
	else
	{
		trying_with_freed->is_free = FALSE;
		ret = trying_with_freed;
	}
	return ((char*)ret) + sizeof(*global_data);
}


void* scalloc(size_t num, size_t size)
{
	void* p_arr = smalloc(num * size);
	
	if(p_arr == NULL)
		return NULL;
	
	memset(p_arr, 0, size * num);
	
	return p_arr;
}

void sfree(void* p)
{
	if (p == NULL) return;
	MMData p_data = (MMData) (((char*)p) - sizeof(*global_data));
	p_data->is_free = TRUE;
}

void* srealloc(void* oldp, size_t size)
{
	if(size == 0)
		return NULL;
	
	if(oldp == NULL)
		return smalloc(size);
	
	MMData old_data = (MMData) (((char*)oldp) - sizeof(*global_data));
	if(old_data->size >= size) // size is sufficient
		return oldp;
		
	void* newp = smalloc(size);
	if(newp == NULL) //sbrk failed
	{
		return NULL; // do not free oldp, of course
	}
	memmove(newp, oldp, old_data->size); // assume it didnt fail
	
	sfree(oldp);
	return newp;
}

size_t _size_meta_data()
{
	return sizeof(*global_data);
}

size_t _num_free_blocks()
{
	MMData temp = global_data;
	
	size_t count = 0;
	while(temp != NULL)
	{
		count += temp->is_free;
		temp = temp->next;
	}
	return count;
}

size_t _num_free_bytes()
{
	MMData temp = global_data;
	
	size_t count = 0;
	while(temp != NULL)
	{
		count += temp->is_free * (temp->size );
		temp = temp->next;
	}
	return count;
}

size_t _num_allocated_blocks()
{
	MMData temp = global_data;
	
	size_t count = 0;
	while(temp != NULL)
	{
		count++;
		temp = temp->next;
	}
	return count;
}

size_t _num_allocated_bytes()
{
	MMData temp = global_data;
	
	size_t count = 0;
	while(temp != NULL)
	{
		count += temp->size;
		temp = temp->next;
	}
	return count;
}

size_t _num_meta_data_bytes()
{
	return _num_allocated_blocks() * _size_meta_data();
}

