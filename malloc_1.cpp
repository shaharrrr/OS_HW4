#include <unistd.h>

#define MAX_SIZE 100000000

void* smalloc(size_t size) {
    if(size == 0 || size > MAX_SIZE) {  //verify value of size is legal (0 < size < MAX_SIZE)
        return nullptr;
    }
    //TODO: verify size value is non-negative? referring the note in part 1
    void* result = sbrk(size);
    if(result == (void*)(-1)) {
        return nullptr;
    }
    return result;

}