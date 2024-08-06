#include <unistd.h>
#include <cstring.h>
#include "BlocksList.h"

#define MAX_SIZE 100000000

//TODO: add global list pointer (and initialize it?)
MallocMetadata* metadata_head = nullptr;

void* smalloc(size_t size) {
    
}

void* scalloc(size_t num, size_t size) {
    
}

void sfree(void* p) {
    if(!p) {    //if p is NULL, simply return
        return;
    }
    //calculate the pointer to the metadata struct of the block pointed by p
    MallocMetadata* block_metadata = (MallocMetadata*)(p - sizeof(MallocMetadata));
    if(block_metadata->is_free) {   //if the block is already released, simply return
        return;
    }
    block_metadata->is_free = true;
}

void* srealloc(void* oldp, size_t size) {
    if(size == 0 || size > MAX_SIZE) {
        return nullptr;
    }
    size_t old_size;
    if(oldp) {  //if oldp in not NULL, check size validity
        //calculate the pointer to the metadata struct of the block pointed by oldp
        MallocMetadata* block_metadata = (MallocMetadata*)(oldp - sizeof(MallocMetadata));
        if(size <= block_metadata->size) {
            return oldp;
        }
        old_size = block_metadata->size;
    }
    void* newp = smalloc(size);
    if(newp) {  //if newp is not NULL that means that the allocation was successful
        if(oldp) {  //if oldp is not NULL, copy the content of oldp to the new allocated space and free oldp
            memmove(newp, (const void*)(oldp), old_size);
            sfree(oldp);
        }
    }
    return newp;
}

size_t _num_free_blocks() {
    MallocMetadata* current = metadata_head;
    int result = 0;
    while(current != nullptr) {
        if(current->is_free) {
            result++;
        }
        current = current->next;
    }
    return result;
}

size_t _num_free_bytes() {
    MallocMetadata* current = metadata_head;
    int result = 0;
    while(current != nullptr) {
        if(current->is_free) {
            result += current->size;
        }
        current = current->next;
    }
    return result;
}

size_t _num_allocated_blocks() {
    MallocMetadata* current = metadata_head;
    int result = 0;
    while(current != nullptr) {
        result++;
        current = current->next;
    }
    return result;
}

size_t _num_allocated_bytes() {
    MallocMetadata* current = metadata_head;
    int result = 0;
    while(current != nullptr) {
        result += current->size;
        current = current->next;
    }
    return result;
}

size_t _num_meta_data_bytes() {
    return (_num_allocated_blocks() * sizeof(MallocMetadata));
}

size_t _size_meta_data() {
    return sizeof(MallocMetadata);
}