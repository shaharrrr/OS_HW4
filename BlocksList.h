#ifndef BLOCKSLIST_H
#define BLOCKSLIST_H

struct MallocMetadata {
    size_t size;                //the size of the block as was allocated
    bool is_free;               //indicates if the block is used or free
    MallocMetadata* next;       //pointer to the next metadata struct
    MallocMetadata* prev;       //pointer to the previous metadata struct
};

class BlocksList {
    MallocMetadata* head;
    size_t length;

public:
    // Default constructor
    BlocksList();

    // Function to insert a node at the end of the linked list.
    void insertBlock(MallocMetadata* newBlock);

    // Function to print the linked list.
    //void printList();

    // Function to delete the node at given position
    //void deleteBlock(MallocMetadata* block);
};

#endif //BLOCKSLIST_H
