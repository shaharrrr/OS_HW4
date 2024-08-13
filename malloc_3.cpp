#include <unistd.h> // For sbrk() and sysconf()
#include <cstring> // For memset() and memmove()
#include <iostream>
#include <sys/mman.h> // For mmap() and munmap()

// Maximum order for block sizes (i.e., 2^MAX_ORDER)
#define MAX_ORDER 10
#define KB 1024 // Define Kilobyte

/**
 * BlockManager Class:
 * Manages memory allocation using a buddy system allocator.
 * It handles small allocations internally and delegates large allocations to mmap().
 */
class BlockManager {
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

    uintptr_t offset; // Base address offset for the memory pool
    size_t freeBlocks; // Number of free blocks
    size_t freeBytes; // Total free bytes
    size_t totBlocks; // Total number of blocks
    size_t totBytes; // Total allocated bytes
    bool init_pool_flag; // Flag to check if the memory pool is initialized
    MallocMetadata metaChain[MAX_ORDER + 1]; // Array of linked lists for different block sizes (buddy system)

    const int BLOCKS_SET_SIZE = 128; // Base block size in KB
    const int BLOCKS_SET_NUM = 32; // Number of blocks to initialize in the memory pool

    // Private Constructor for Singleton Pattern
    BlockManager();
};
