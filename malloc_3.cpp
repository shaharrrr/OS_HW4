#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sys/mman.h>

#define MAX_ORDER 10
#define KB 1024

class BlockManager {
private:
    struct MallocMetadata {
        size_t size;
        bool is_free; 
        MallocMetadata* next;
        MallocMetadata* prev;

        MallocMetadata() 
            : size(0), is_free(false), next(nullptr), prev(nullptr) {}
    } *mallocMetadata;

    uintptr_t offset;
    size_t freeBlocks;
    size_t freeBytes;
    size_t totBlocks;
    size_t totBytes;
    bool init_pool_flag; 
    MallocMetadata metaChain[MAX_ORDER + 1];

    const int BLOCKS_SET_SIZE = 128;
    const int BLOCKS_SET_NUM = 32;

    BlockManager();
};
