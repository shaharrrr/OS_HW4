#include <stdio.h> // for size_t
#include <unistd.h>
#include <cstring.h>

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
    struct MallocMetadata {
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
     * Pops (removes and returns) the first block from the linked list.
     * @return Pointer to the popped block
     */
    MallocMetadata* pop();

    /**
     * Adds a block to the linked list in an ordered manner based on address.
     * @param block - Pointer to the block to add
     */
    void add_to_list(MallocMetadata* block);

    /**
     * Removes a block from the linked list.
     * @param block - Pointer to the block to remove
     */
    void remove_from_list(MallocMetadata* block);

    /**
     * Checks if the linked list is empty.
     * @param list - Reference to the list's head metadata
     * @return True if empty, else False
     */
    bool isEmpty(MallocMetadata& list);

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
     * Reallocates a memory block pointed by p to a new memory block of specified size.
     * @param oldp - Pointer to the memory block
     * @param size - New size of the memory block
     * @return Pointer to the allocated memory or nullptr on failure
     */
    void* realloc_block(void* oldp, size_t size);

    /**
     * Returns the size of MallocMetadata struct
     * @return size of MallocMetadata struct
     */
    static size_t get_metadata_size();

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
 * Checks if a linked list is empty.
 */
bool MemoryBlocksManager::isEmpty(MallocMetadata& list) {
    return list.next == nullptr;
}

/**
 * Adds a block to the linked list in an ordered manner based on memory address.
 */
void MemoryBlocksManager::add_to_list(MallocMetadata* block) {
    MallocMetadata* next_metadata = metadataList.next;
    MallocMetadata* prev_metadata = &metadataList;

    while (next_metadata) {
        if ((uintptr_t)next_metadata > (uintptr_t)block) {
            // Insert block between prev_meta and next_meta
            block->next = next_meta;
            block->prev = prev_meta;
            next_meta->prev = block;
            prev_meta->next = block;
            return;
        }
        prev_meta = next_meta;
        next_meta = next_meta->next;
    }

    // Insert at the end
    block->next = nullptr;
    block->prev = prev_meta;
    prev_meta->next = block;
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
 * Pops the first block from the linked list.
 */
MemoryBlocksManager::MallocMetadata* MemoryBlocksManager::pop() {
    if (!isEmpty(metadataList)) {
        MallocMetadata* res = metadataList.next;
        remove_from_list(res);
        return res;
    }
    return nullptr; // List is empty
}

/**
 * Allocates a memory block of the specified size.
 */
void* MemoryBlocksManager::alloc_block(size_t size) {
    // Search for a free block
    MallocMetadata* current = metadataList;
    while (current) {
        if (current->is_free && current->size >= size) {
            current->is_free = false;

            //Update statistics
            freeBlocks--;
            freeBytes -= current->size;

            return get_allocPtr(current);
        }
        current = current->next;
    }
    // Allocate new block if no free block is found
    void* result;
    DO_SBRK(result, (size + sizeof(MallocMetadata)));

    MallocMetadata* new_metadata = (MallocMetadata*)result;
    new_metadata->size = size;
    new_metadata->is_free = false;
    new_metadata->next = nullptr;
    new_metadata->prev = nullptr;
    add_to_list(new_metadata);

    //update statistics
    totalBlocks++;
    totalBytes += size;

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
    block_metadata->is_free = true;
    freeBlocks++;
    freeBytes += block_metadata->size;
}

void* MemoryBlocksManager::realloc_block(void* oldp, size_t size){
    mallocMetadata oldMetadata = get_metadata(oldp);
    if(size <= oldMetadata->size) {
        return oldp;
    }
    return alloc_block(size);
}

static MemoryBlocksManager::size_t get_metadata_size(){
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
    return (mallocMetadata)((uintptr_t)p - sizeof(struct MallocMetadata));
}

void* smalloc(size_t size) {
    if (!MemoryBlocksManager::getInstance() || size > MAX_SIZE || size == 0) {
        return nullptr; // Invalid size or initialization failure

    }
    return MemoryBlocksManager::getInstance().alloc_block(size); // Buddy system allocation
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
    MemoryBlocksManager::getInstance().free_block(p);
}

void* srealloc(void* oldp, size_t size) {
    if (!MemoryBlocksManager::getInstance() || size > MAX_SIZE || size == 0) {
        return nullptr;
    }
    if (!oldp) { //If ‘oldp’ is NULL, allocates space for ‘size’ bytes and returns a pointer to it.
        return smalloc(size);
    }
    void *result;
    result = MemoryBlocksManager::getInstance().realloc_block(oldp, size);

    if (!result) {   //if result is NULL, allocation failed. Return NULL
        return nullptr;
    }
    if (result == oldp) {    //if result is oldp it means that size was smaller than or equal to oldp size, no allocation is performed
        return oldp;
    }

    size_t old_size = MemoryBlocksManager::getInstance().get_size(oldp);
    std::memmove(result, oldp, old_size);
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
    return (_num_allocated_blocks() * MemoryBlocksManager::get_metadata_size());
}

size_t _size_meta_data() {
    return MemoryBlocksManager::get_metadata_size();
}