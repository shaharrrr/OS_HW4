#include <stdio.h> // for size_t
#include <unistd.h>
#include <cstring>

#define MAX_SIZE 1e8

// Macro to perform sbrk() system call safely
#define DO_SBRK(res, size)           \
    do {                             \
        res = sbrk(size);            \
        if (res == (void *)-1)       \
            return nullptr;          \
    } while (0)

/**
 * MemoryBlocksManager Class:
 * Manages memory allocation using a buddy system allocator.
 * It handles small allocations internally and delegates large allocations to mmap().
 */
class MemoryBlocksManager {
private:
    /**
     * MallocMetadata Struct:
     * Contains metadata for each memory block.
     */
    typedef struct MallocMetadata {
        size_t size; // Size of the memory block
        bool is_free; // Flag indicating if the block is free
        MallocMetadata* next; // Pointer to the next block in the linked list
        MallocMetadata* prev; // Pointer to the previous block in the linked list

        // Constructor to initialize metadata
        MallocMetadata()
                : size(0), is_free(false), next(nullptr), prev(nullptr) {}
    } *mallocMetadata;

    size_t freeBlocks; // Number of free blocks
    size_t freeBytes; // Total free bytes
    size_t totalBlocks; // Total number of blocks
    size_t totalBytes; // Total allocated bytes
    MallocMetadata metadataList; // Array of linked lists for different block sizes (buddy system)

    // Helper Functions:

    /**
     * Retrieves the metadata pointer from the allocation pointer.
     * @param m - Allocation pointer
     * @return Metadata pointer
     */
    mallocMetadata get_metadata(void* p);

    /**
     * Retrieves the allocation pointer from the metadata pointer.
     * @param m - Pointer to MallocMetadata
     * @return Allocation pointer
     */
    void* get_allocPtr(MallocMetadata* m);

    /**
     * Performs allocation to a block of size at least equal to 'size'
     * @param size - Size of the allocation
     * @return Allocation pointer
     */
    void* alloc_to_free_block(size_t size);

    /**
     * Adds a block to the linked list in an ordered manner based on address.
     * @param block - Pointer to the block to add
     */
    void add_to_list(mallocMetadata block);

    /**
     * Removes a block from the linked list.
     * @param block - Pointer to the block to remove
     */
    void remove_from_list(MallocMetadata* block);

    // Private Constructor for Singleton Pattern
    MemoryBlocksManager();

public:
    /**
     * Retrieves the singleton instance of MemoryBlocksManager.
     * @return Reference to MemoryBlocksManager instance
     */
    static MemoryBlocksManager& getInstance() {
        static MemoryBlocksManager instance;
        return instance;
    }

    /**
     * Allocates a memory block of the specified size.
     * @param size - Desired allocation size
     * @return Pointer to the allocated memory or nullptr on failure
     */
    void* alloc_block(size_t size);

    /**
     * Free a memory block pointed by p.
     * @param p - Pointer to the memory block
     * @return void
     */
    void free_block(void* p);

    /**
     * Returns the size of MallocMetadata struct
     * @return size of MallocMetadata struct
     */
    size_t get_metadata_size();

    /**
     * Returns the size of the block pointed by p
     * @param p - Pointer to the memory block
     * @return Pointer to the allocated memory or nullptr on failure
     */
    size_t get_size(void* p);

    /**
     * Returns the total number of blocks allocated now
     * @return size of MallocMetadata struct
     */
    size_t get_totalBlocks();

    /**
     * Returns the total number of bytes allocated now
     * @return size of MallocMetadata struct
     */
    size_t get_totalBytes();

    /**
     * Returns the total number of free blocks
     * @return size of MallocMetadata struct
     */
    size_t get_freeBlocks();

    /**
     * Returns the total number of free bytes allocated now
     * @return size of MallocMetadata struct
     */
    size_t get_freeBytes();
};

// Constructor initializes member variables
MemoryBlocksManager::MemoryBlocksManager()
        : freeBlocks(0), freeBytes(0), totalBlocks(0), totalBytes(0), metadataList() {}

/**
 * Adds a block to the linked list in an ordered manner based on memory address.
 */
void MemoryBlocksManager::add_to_list(mallocMetadata block) {
    mallocMetadata next_metadata = metadataList.next;
    mallocMetadata prev_metadata = &metadataList;

    while (next_metadata) {
        if ((void*)next_metadata > (void*)block) {
            // Insert block between prev_meta and next_meta
            block->next = next_metadata;
            block->prev = prev_metadata;
            next_metadata->prev = block;
            prev_metadata->next = block;
            return;
        }
        prev_metadata = next_metadata;
        next_metadata = next_metadata->next;
    }

    // Insert at the end
    block->next = nullptr;
    block->prev = prev_metadata;
    prev_metadata->next = block;
}

/**
 * Removes a block from the linked list.
 */
void MemoryBlocksManager::remove_from_list(MallocMetadata* block) {
    block->prev->next = block->next;
    if (block->next)
        block->next->prev = block->prev;
    block->prev = nullptr;
    block->next = nullptr;
}

/**
 * Performs allocation to a block of size at least equal to 'size'
 */
void* MemoryBlocksManager::alloc_to_free_block(size_t size){
    mallocMetadata current = &metadataList;
    while(current){     //traversing the linked list of free blocks
        if(current->is_free && current->size >= size){
            //Update metadata and statistics
            current->is_free = false;
            freeBlocks--;
            freeBytes-=current->size;
            remove_from_list(current);
            return get_allocPtr(current);
            }
        current=current->next;
    }
    return (void*)-1;
}

/**
 * Retrieves the allocation pointer from the metadata pointer.
 */
void* MemoryBlocksManager::get_allocPtr(MallocMetadata* m) {
    return (void*)((intptr_t)m + sizeof(MallocMetadata));
}

/**
 * Allocates a memory block of the specified size.
 */
void* MemoryBlocksManager::alloc_block(size_t size) {
    void* result = alloc_to_free_block(size);
    if(result != (void*)-1){    //if successfully allocated a free block that satisfies request, return the allocation pointer
        return result;
    }
    //otherwise, allocate a new block
    DO_SBRK(result, size+sizeof(struct MallocMetadata));
    mallocMetadata new_metadata = (mallocMetadata)result;
    //Update statistics and metadata
    totalBytes += size;
    totalBlocks++;
    new_metadata->is_free = false;
    new_metadata->size = size;
    return get_allocPtr(new_metadata);
}

/**
 * Free a memory block pointed by p.
 */
void MemoryBlocksManager::free_block(void *p) {
    if(!p) {    //if p is NULL, simply return
        return;
    }
    mallocMetadata block_metadata = get_metadata(p);
    if(block_metadata->is_free) {   //if the block is already released, simply return
        return;
    }
    //Update metadata and add to the free blocks list
    block_metadata->is_free = true;
    freeBlocks++;
    freeBytes += block_metadata->size;
    add_to_list(block_metadata);
}

size_t MemoryBlocksManager::get_metadata_size(){
    return sizeof(struct MallocMetadata);
}

size_t MemoryBlocksManager::get_size(void* p){
    return get_metadata(p)->size;
}

size_t MemoryBlocksManager::get_totalBlocks(){
    return totalBlocks;
}

size_t MemoryBlocksManager::get_totalBytes(){
    return totalBytes;
}

size_t MemoryBlocksManager::get_freeBlocks(){
    return freeBlocks;
}

size_t MemoryBlocksManager::get_freeBytes(){
    return freeBytes;
}

MemoryBlocksManager::mallocMetadata MemoryBlocksManager::get_metadata(void* p){
    if (!p) return nullptr;
    return (mallocMetadata)((intptr_t)p - sizeof(struct MallocMetadata));
}

void* smalloc(size_t size) {
    if (size > MAX_SIZE || size == 0) {
        return nullptr; // Invalid size or initialization failure

    }
    return MemoryBlocksManager::getInstance().alloc_block(size); // Buddy system allocation
}

void* scalloc(size_t num, size_t size) {
    size_t total_size = num * size;
    void* ptr = smalloc(total_size);
    if (!ptr) {
        return nullptr;
    }
    std::memset(ptr, 0, total_size);
    return ptr;
}

void sfree(void* p) {
    MemoryBlocksManager::getInstance().free_block(p);
}

void* srealloc(void* oldp, size_t size) {
    if (size > MAX_SIZE || size == 0) {
        return nullptr;
    }
    if (!oldp) { //If ‘oldp’ is NULL, allocates space for ‘size’ bytes and returns a pointer to it.
        return smalloc(size);
    }
    void *result;
    if(size <= MemoryBlocksManager::getInstance().get_size(oldp)) {
        return oldp;
    }
    else{
        result = smalloc(size);
        if(!result){
            return nullptr;
        }
    }
    std::memmove(result,oldp,MemoryBlocksManager::getInstance().get_size(oldp));
    sfree(oldp);
    return result;
}

size_t _num_free_blocks() {
    return MemoryBlocksManager::getInstance().get_freeBlocks();
}

size_t _num_free_bytes() {
    return MemoryBlocksManager::getInstance().get_freeBytes();
}

size_t _num_allocated_blocks() {
    return MemoryBlocksManager::getInstance().get_totalBlocks();
}

size_t _num_allocated_bytes() {
    return MemoryBlocksManager::getInstance().get_totalBytes();
}

size_t _num_meta_data_bytes() {
    return (_num_allocated_blocks() * MemoryBlocksManager::getInstance().get_metadata_size());
}

size_t _size_meta_data() {
    return MemoryBlocksManager::getInstance().get_metadata_size();
}