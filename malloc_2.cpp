#include <stdio.h> // for size_t
#include <cmath> // for pow
#include <unistd.h>
#include <cstring.h>
#include "BlocksList.h"

#define MAX_SIZE 100000000

//TODO: add global list pointer (and initialize it?)
MallocMetadata* metadata_head = nullptr;

// Function to append metadata to the list
void append_metadata (MallocMetadata* new_metadata) {
    if (!metadata_head) {
        metadata_head = new_metadata;
    } else {
        MallocMetadata* current = metadata_head;
        while (current->next) {
            current = current->next;
        }
        current->next = new_metadata;
        new_metadata->next = NULL;
        new_metadata->prev = current;
    }
}

void* smalloc(size_t size) {
    // Check for invalid size
    if (size == 0 || size > pow(10, 8)) {
        return NULL;
    }
    // Search for a free block
    MallocMetadata* current = metadata_head;
    while (current) {
        if (current->is_free && current->size >= size) {
            current->is_free = false;
            return (char*)current + sizeof(MallocMetadata); // Skip metadata
        }
        current = current->next;
    }
    // Allocate new block if no free block is found
    void* result = sbrk(size + sizeof(MallocMetadata));
    if (result == (void*)(-1)) {
        return NULL;
    }
    MallocMetadata* new_metadata = (MallocMetadata*)result;
    new_metadata->size = size;
    new_metadata->is_free = false;
    new_metadata->next = nullptr;
    new_metadata->prev = nullptr;
    append_metadata(new_metadata);
    return (char*)result + sizeof(MallocMetadata); // Skip metadata
}

void* scalloc(size_t num, size_t size) {
    size_t total_size = num * size;
    void* ptr = smalloc(total_size);
    if (ptr) {
        std::memset(ptr, 0, total_size);
    }
    return ptr;
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