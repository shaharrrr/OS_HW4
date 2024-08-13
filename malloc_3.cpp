#include <unistd.h> // For sbrk() and sysconf()
#include <cstring> // For memset() and memmove()
#include <iostream>
#include <sys/mman.h> // For mmap() and munmap()

// Maximum order for block sizes (i.e., 2^MAX_ORDER)
#define MAX_ORDER 10
#define KB 1024 // Define Kilobyte
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

    uintptr_t offset; // Koren: base address offset for the memory pool
    size_t freeBlocks; // Number of free blocks
    size_t freeBytes; // Total free bytes
    size_t totalBlocks; // Total number of blocks
    size_t totalBytes; // Total allocated bytes
    bool init_pool_flag; // Flag to check if the memory pool is initialized
    MallocMetadata metadataList[MAX_ORDER + 1]; // Array of linked lists for different block sizes (buddy system)

    const int BLOCKS_SET_SIZE = 128; // Base block size in KB
    const int BLOCKS_SET_NUM = 32; // Number of blocks to initialize in the memory pool

    // Helper Functions:

    /**
     * Retrieves the allocation pointer from the metadata pointer.
     * @param m - Pointer to MallocMetadata
     * @return Allocation pointer
     */
    void* get_allocPtr(MallocMetadata* m);

    /**
     * Splits a given memory block into two halves.
     * @param m - Pointer to the block to split
     * @return Pointer to the new split block
     */
    MallocMetadata* split(MallocMetadata* m);

    /**
     * Pops (removes and returns) the first block from a specified linked list.
     * @param list_index - Index of the linked list (based on block size)
     * @return Pointer to the popped block
     */
    MallocMetadata* pop(int list_index);

    /**
     * Adds a block to a specified linked list in an ordered manner based on address.
     * @param list_index - Index of the linked list
     * @param block - Pointer to the block to add
     */
    void add_to_list(int list_index, MallocMetadata* block);

    /**
     * Removes a block from its linked list.
     * @param block - Pointer to the block to remove
     */
    void remove_from_list(MallocMetadata* block);

    /**
     * Checks if a linked list is empty.
     * @param list - Reference to the list's head metadata
     * @return True if empty, else False
     */
    bool isEmpty(MallocMetadata& list);

    /**
     * Calculates the order (log base 2) for a given size based on the buddy system.
     * @param size - Desired size
     * @return Order index or -1 if size exceeds maximum
     */
    int get_order(size_t size);

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
     * Allocates a large memory block using mmap().
     * @param size - Desired allocation size
     * @return Pointer to the allocated memory
     */
    void* lalloc_block(size_t size);

    /**
     * Initializes the memory pool lazily on first allocation.
     * @return Void pointer (unused)
     */
    void* lazy_init();

    /**
     * Checks if a given size qualifies as a large allocation.
     * @param size - Size to check
     * @return True if large, else False
     */
    bool isLargeAlloc(size_t size);
};

// Constructor initializes member variables
MemoryBlocksManager::MemoryBlocksManager()
    : offset(0), freeBlocks(0), freeBytes(0), totalBlocks(0), totalBytes(0), init_pool_flag(true), metadataList() {}

/**
 * Lazy Initialization:
 * Initializes the memory pool by allocating a large contiguous block using sbrk().
 * Divides this block into smaller blocks managed by the buddy system.
 */
void* MemoryBlocksManager::lazy_init() {
    if (!init_pool_flag)
        return (void*)-1; // Already initialized

    void* ptr;
    // Allocate BLOCKS_SET_NUM blocks, each of BLOCKS_SET_SIZE KB
    DO_SBRK(ptr, BLOCKS_SET_NUM * BLOCKS_SET_SIZE * KB);
    offset = (uintptr_t)ptr; // Koren: set base offset

    // Initialize each block and add it to the appropriate linked list
    for (int i = 0; i < BLOCKS_SET_NUM; i++) {
        uintptr_t block_addr = (uintptr_t)ptr + i * (BLOCKS_SET_SIZE * KB);
        MallocMetadata* block = (MallocMetadata*)block_addr;
        block->size = BLOCKS_SET_SIZE * KB - sizeof(MallocMetadata);
        block->is_free = true;
        block->next = nullptr;
        block->prev = nullptr;
        add_to_list(MAX_ORDER, block); // Add to the largest block size list
    }

    // Update metrics
    freeBlocks = BLOCKS_SET_NUM;
    freeBytes = BLOCKS_SET_NUM * (BLOCKS_SET_SIZE * KB - sizeof(MallocMetadata));
    totalBlocks = freeBlocks;
    totalBytes = freeBytes;
    init_pool_flag = false; // Mark as initialized
    return (void*)-1; // Return unused pointer
}

/**
 * Checks if a linked list is empty.
 */
bool MemoryBlocksManager::isEmpty(MallocMetadata& list) {
    return list.next == nullptr;
}

/**
 * Adds a block to a linked list in an ordered manner based on memory address.
 * This ordering helps in identifying buddies during merging.
 */
void MemoryBlocksManager::add_to_list(int list_index, MallocMetadata* block) {
    MallocMetadata* next_meta = metadataList[list_index].next;
    MallocMetadata* prev_meta = &metadataList[list_index];

    while (next_meta) {
        if ((uintptr_t)next_meta > (uintptr_t)block) {
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
 * Removes a block from its linked list.
 */
void MemoryBlocksManager::remove_from_list(MallocMetadata* block) {
    block->prev->next = block->next;
    if (block->next)
        block->next->prev = block->prev;
    block->prev = nullptr;
    block->next = nullptr;
}

/**
 * Pops the first block from the specified linked list.
 */
MemoryBlocksManager::MallocMetadata* MemoryBlocksManager::pop(int list_index) {
    if (!isEmpty(metadataList[list_index])) {
        MallocMetadata* res = metadataList[list_index].next;
        remove_from_list(res);
        return res;
    }
    return nullptr; // List is empty
}

/**
 * Splits a block into two equal halves and returns the new block.
 * Updates metadata and metrics accordingly.
 */
MemoryBlocksManager::MallocMetadata* MemoryBlocksManager::split(MallocMetadata* m) {
    size_t half_of_block = (m->size + sizeof(MallocMetadata)) / 2;
    MallocMetadata* res = (MallocMetadata*)((uintptr_t)m + half_of_block);
    
    // Update metrics
    freeBlocks++;
    totalBlocks++;
    freeBytes -= sizeof(MallocMetadata);
    totalBytes -= sizeof(MallocMetadata);

    // Update sizes
    m->size = half_of_block - sizeof(MallocMetadata);
    res->size = m->size;
    res->is_free = true;
    res->next = nullptr;
    res->prev = nullptr;
    return res;
}

/**
 * Allocates a memory block of the specified size using the buddy system.
 */
void* MemoryBlocksManager::alloc_block(size_t size) {
    // Determine the appropriate order for the block size.
    // The order is determined based on the size of the block.
    // This helps in grouping blocks of similar sizes together for efficient allocation.
    int dest_ord = get_order(size);
    
    // If the size is too large and no suitable order is found, return nullptr.
    if(dest_ord == -1)
        return nullptr;

    // Try to find a block that can satisfy the allocation request.
    // Start from the order calculated and go up to the maximum order.
    for(int src_ord = dest_ord; src_ord <= MAX_ORDER; src_ord++) {
        // If the current order list is empty, continue to the next larger order.
        if(isEmpty(metadataList[src_ord]))
            continue;
        
        // If we found a block in the current order list, try to split it down to the desired order.
        // This loop continues until we have split the block down to the desired size.
        while(src_ord >= dest_ord) {
            // Pop the first available block from the list at the current order.
            mallocMetadata buff = pop(src_ord);
            
            // If we have reached the desired order, allocate the block.
            if(src_ord == dest_ord) {
                // Mark the block as not free.
                buff->is_free = false;
                
                // Update the number of free blocks and free bytes.
                freeBlocks--;
                freeBytes -= buff->size;
                
                // Return the pointer to the allocated block's memory.
                return get_allocPtr(buff);
            } else {
                // If the block is larger than needed, split it into two smaller blocks.
                // Decrease the order to move closer to the desired block size.
                src_ord--;
                
                // Split the block into two smaller blocks.
                // One block is added back to the current order list,
                // and the other will be further split or used depending on the remaining loop iterations.
                add_to_list(src_ord, split(buff));
                add_to_list(src_ord, buff);
            }
        }
        break; // If we have found and allocated a block, exit the loop.
    }
    
    // If no suitable block was found or could be split, return nullptr.
    return nullptr;
}

/**
 * Allocates a large memory block using mmap().
 * mmap() maps a file or device into memory, providing a way to allocate memory.
 * Here, it's used to allocate anonymous memory not backed by any file.
 */
void* MemoryBlocksManager::lalloc_block(size_t size) {
    // mmap() parameters:
    // - addr: nullptr (let the system choose the address)
    // - length: size + metadata size
    // - prot: PROT_READ | PROT_WRITE (read and write permissions)
    // - flags: MAP_PRIVATE | MAP_ANONYMOUS (private mapping, not backed by any file)
    // - fd: -1 (ignored because of MAP_ANONYMOUS)
    // - offset: 0
    MallocMetadata* block = (MallocMetadata*)mmap(nullptr, size + sizeof(MallocMetadata),
                                                  PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    block->is_free = false;
    block->next = nullptr;
    block->prev = nullptr;
    block->size = size;

    // Update metrics
    totalBlocks++;
    totalBytes += size;
    return get_allocPtr(block);
}

/**
 * Calculates the order (log base 2) for a given size based on the buddy system.
 */
int MemoryBlocksManager::get_order(size_t size) {
    int res = 0;
    for (size_t bytes = BLOCKS_SET_SIZE; res <= MAX_ORDER; bytes *= 2, res++) {
        if (size <= bytes - sizeof(MallocMetadata))
            return res;
    }
    return -1; // Size exceeds maximum manageable block size
}

/**
 * Retrieves the allocation pointer from the metadata pointer.
 */
void* MemoryBlocksManager::get_allocPtr(MallocMetadata* m) {
    return (void*)((uintptr_t)m + sizeof(MallocMetadata));
}

/**
 * Checks if a given size qualifies as a large allocation (i.e., larger than the maximum block size in the buddy system).
 */
bool MemoryBlocksManager::isLargeAlloc(size_t size) {
    return size > BLOCKS_SET_SIZE * KB - sizeof(MallocMetadata);
}

/**
 * Allocates a memory block of the specified size.
 * Delegates to lalloc_block() if size is large; otherwise, uses alloc_block().
 */
void* smalloc(size_t size) {
    // Initialize the memory pool lazily
    if (!MemoryBlocksManager::getInstance().lazy_init() || size > MAX_SIZE || size == 0)
        return nullptr; // Invalid size or initialization failure

    if (MemoryBlocksManager::getInstance().isLargeAlloc(size))
        return MemoryBlocksManager::getInstance().lalloc_block(size); // Large allocation
    return MemoryBlocksManager::getInstance().alloc_block(size); // Buddy system allocation
}

/**
 * Allocates and zero-initializes an array.
 * Uses smalloc() for allocation and memset() to zero-initialize.
 */
void* scalloc(size_t num, size_t size) {
    void* res = smalloc(num * size);
    if (!res)
        return nullptr; // Allocation failed

    // memset() sets the allocated memory to zero
    std::memset(res, 0, num * size);
    return res;
}
