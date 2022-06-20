#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

#define TRUE 1
#define FALSE 0
#define _128KB (131072)
#define ALIGN 8

typedef struct MallocMetadata* MMData;
struct MallocMetadata
{
	size_t size;
	int is_free;
	MMData next;
	MMData prev;
    void* to_free;
};

MMData global_data = NULL;
MMData global_m_data = NULL;

void* init_data(size_t size)
{
	void* prev_pgbrk = sbrk(0);
	void* res = sbrk(ALIGN + sizeof(*global_data) + size);
	
	if(prev_pgbrk != res)
		return NULL;

    void* aligned_res = ((char*) res) + (8 - (((char*) res) % 8));
	MMData new_data = (MMData) aligned_res;
	new_data->size = size;
	new_data->is_free = FALSE;
	new_data->next = NULL;
	new_data->prev = NULL;
    new_data->to_free = res;
	
	return aligned_res;
}

void insert_sorted (MMData new_val, MMData& list)
{
	MMData temp = list;

    if(list == NULL)
    {
        list = new_val;
        return;
    }
	
	if(temp->size > new_val->size || (temp->size == new_val->size && temp > new_val))
	{
		new_val->next = temp;
		new_val->prev = NULL;
		temp->prev = new_val;
		
		list = new_val;
		
		return;
	}
	
	while(temp->next != NULL && temp->next->size < new_val->size)
	{
		temp = temp->next;
	}
	
	while(temp->next != NULL && (temp->next->size == new_val->size && temp->next < new_val))
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

void remove_sorted(MMData del_val, MMData& list)
{
	//Notice: not freeing on purpose
	
	MMData temp = list;
	if (temp == del_val)
	{
		list = temp->next;
		return;
	}
	while(temp != del_val)
	{
		temp = temp->next;
	}
	
	if(temp == NULL) return;
	temp->prev->next = temp->next;
	if(temp->next != NULL)
	{
		temp->next->prev = temp->prev;
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

void join_free(MMData freed)
{
    MMData join_with_l = NULL;
    MMData join_with_r = NULL;
    int changed = 0;

    MMData temp = global_data;
    while(temp != NULL)
    {
        if(freed + sizeof(*global_data) + freed->size == temp->to_free && temp->is_free) // next block in yamin
        {
            join_with_r = temp;
        }
        else if(temp + sizeof(*global_data) + temp->size == freed->to_free && temp->is_free) // next to block in smol
        {
            join_with_l = temp;
        }
        temp = temp->next;
    }

	if(join_with_r != NULL)
    { //join with next
        freed->size += join_with_r->size + ALIGN + sizeof(*global_data);
        remove_sorted(join_with_r, global_data);
        changed = 1;
    }
    if(join_with_l != NULL)
    {
        join_with_l->size += freed->size + ALIGN + sizeof(*global_data);
        MMData temp = join_with_l;
        join_with_l = freed;
        freed = temp;
        remove_sorted(join_with_l, global_data);
        changed = 1;
    }
    if(changed == 1)
    {
        remove_sorted(freed, global_data);
        insert_sorted(freed, global_data);
    }
}

void* find_wilderness()
{
    void* curr_pgbrk = sbrk(0); //get the highest location in the heap

    //explore the list and check if there's free wilderness there..
    MMData temp = global_data;
    size_t mm_size = sizeof(*global_data);
    while(temp != NULL && ((char*) temp->to_free) + mm_size + temp->size + ALIGN != curr_pgbrk )
    {
        temp = temp->next;
    }

    if(temp == NULL || !temp->is_free) return NULL;

    return temp;
}

MMData apply_wilderness(size_t size)
{
	//should get here only if first_free failed

    MMData temp = (MMData) find_wilderness();

	if(temp == NULL) return NULL;

	size_t remaining_size = size - temp->size;

	void* validate = sbrk(remaining_size);
	if(validate != curr_pgbrk) return NULL;

	remove_sorted(temp, global_data);
	temp->size += remaining_size;
	insert_sorted(temp, global_data);

	return temp;
}

void split_free(void* allocated, size_t size)
{
	MMData data = (MMData) allocated;
	
	if(data->size >= size + sizeof(*global_data) + 128 + ALIGN)
	{
		remove_sorted(data, global_data);
		//Remember to recover, please
		
		size_t temp_size = data->size;
		data->size = size;
		
		void* new_ptr = data->to_free + sizeof(*global_data) + size + ALIGN;

        void* aligned_new_ptr = ((char*) new_ptr) + (8 - (((char*) new_ptr) % 8));

		MMData new_data = (MMData) aligned_new_ptr;
		new_data->size = temp_size - size - sizeof(*global_data) - ALIGN;
		new_data->is_free = TRUE;
        new_data->next = NULL;
        new_data->prev = NULL;
        new_data->to_free = new_ptr;
		
		insert_sorted(new_data, global_data);
		insert_sorted(data, global_data);
	}
}	

void* smalloc(size_t size)
{
    if(size == 0 || size > 1e8)
	{
		return NULL;
	}
    void* ret = NULL;

    if(size >= _128KB)
    {
        //mmap and so on
        ret = mmap(NULL, size + sizeof(*global_m_data) + ALIGN, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0);
        if (ret == MAP_FAILED)
        {
            // TODO should validate the error ^^
            return NULL;
        }
        void* aligned_ret = ((char*) ret) + (8 - (((char*) ret) % 8));
        MMData ret_data = (MMData) aligned_ret;
        ret_data->size = size;
        ret_data->is_free = FALSE;
        ret_data->next = ret_data->prev = NULL;
        ret_data->to_free = ret;

        insert_sorted(ret_data, global_m_data);

        return ((char*)aligned_ret) + sizeof(*global_m_data);
    }
			
	MMData trying_with_freed = first_free(size);

	void* prev_pgbrk = sbrk(0);
	
	if(trying_with_freed == NULL)
	{
        //try using wilderness:
		MMData wild_try = apply_wilderness(size);

		if(wild_try != NULL)
		{
			wild_try->is_free = FALSE;
			//wild_try is already placed in the list
			ret = wild_try;
		}
		else
		{
			ret = init_data(size);
			if(ret == NULL) return NULL;

            insert_sorted((MMData) ret, global_data);
		}
	}
	else
	{
		trying_with_freed->is_free = FALSE;
		ret = trying_with_freed;
		split_free(ret, size);
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

    if(p_data->size >= _128KB)
    {
        remove_sorted(p_data, global_m_data);
        munmap(p_data->to_free, p_data->size + sizeof(*global_m_data) + ALIGN);
        return;
    }
    p_data->is_free = TRUE;
    join_free(p_data);
}

void* srealloc(void* oldp, size_t size)
{
	if(size == 0)
		return NULL;
	
	if(oldp == NULL)
		return smalloc(size);
	
	MMData old_data = (MMData) (((char*)oldp) - sizeof(*global_data));
	if(old_data->size >= size) // size is sufficient
		return oldp; // in fact, have to split - but we assume that it won't be necessary

    MMData join_with_l = NULL;
    MMData join_with_r = NULL;
    MMData temp = global_data;

    void* curr_pgbrk = sbrk(0);

    while(temp != NULL && size < _128KB)
    {
        if(old_data + sizeof(*global_data) + old_data->size == temp->to_free) // next block in yamin
        {
            join_with_r = temp;
        }
        else if(temp + sizeof(*global_data) + temp->size == old_data->to_free) // next to block in smol
        {
            join_with_l = temp;
        }
        temp = temp->next;
    }

    if(join_with_l != NULL && join_with_l->is_free)
    {
        if (join_with_l->size + old_data->size + sizeof(*global_data) + ALIGN >= size
           || find_wilderness() == old_data)
        {

            if(join_with_l->size + old_data->size + sizeof(*global_data) + ALIGN >= size)
            {
                join_with_l->size += old_data->size + sizeof(*global_data) + ALIGN;
            }
            else
            {
                void* validate = sbrk(size - old_data->size - (join_with_l->size + sizeof(*global_data) + ALIGN));
                if(validate != curr_pgbrk) return NULL;
                join_with_l->size = size;
            }
            //only lower enough
            join_with_l->is_free = FALSE;
            remove_sorted(old_data);
            remove_sorted(join_with_l);
            insert_sorted(join_with_l);

            split_free(join_with_l, size);
            return join_with_l;
        }
    }

    if(find_wilderness() == old_data)
    {
        void* validate = sbrk(size - old_data->size);
        if(validate != curr_pgbrk) return NULL;
        old_data->size = size;
        remove_sorted(old_data);
        insert_sorted(old_data);
        return old_data;
        //no need to split because we're the correct size
    }

    if(join_with_r != NULL && join_with_r->is_free &&
            (join_with_r->size + old_data->size + sizeof(*global_data) + ALIGN >= size))
    {
        old_data->size += join_with_r->size + sizeof(*global_data) + ALIGN;
        //only higher enough
        remove_sorted(old_data);
        remove_sorted(join_with_r);
        insert_sorted(old_data);

        split_free(old_data, size);
        return old_data;
    }

    if(join_with_r != NULL && join_with_r->is_free && join_with_l && join_with_l->is_free)
    {
        if(old_data->size + join_with_l->size + join_with_r->size + 2 * sizeof(*global_data) + 2 * ALIGN >= size)
        {
            join_free(old_data);
            join_with_l->is_free = FALSE;
            return join_with_l;
        }
    }


    if(join_with_r != NULL && join_with_r->is_free)
    {
        //join if size
        if(find_wilderness() == join_with_r)
        {
            old_data->size += join_with_r->size + sizeof(*global_data) + ALIGN;
            remove_sorted(old_data);
            remove_sorted(join_with_r);
            insert_sorted(old_data);

            if(join_with_l != NULL && join_with_l->is_free)
            {
                join_with_l->size += old_data->size + sizeof(*global_data) + ALIGN;
                join_with_l->is_free = FALSE;
                remove_sorted(old_data);
                remove_sorted(join_with_l);
                insert_sorted(join_with_l);

                old_data = join_with_l; // we want to work with old_data
            }

            void* validate = sbrk(size - old_data->size);
            if(validate != curr_pgbrk) return NULL;
            old_data->size = size;

            remove_sorted(old_data);
            insert_sorted(old_data);

            return old_data;
        }
    }

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
	return sizeof(*global_data) + ALIGN;
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
		count += temp->is_free * (temp->size);
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
    temp = global_m_data;
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

    temp = global_m_data;
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

