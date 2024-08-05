// #include "BlocksList.h"

// BlocksList::BlocksList() {
//     head = NULL;
//     length = 0;
// }

// // Function to delete the block at given position
// //void BlocksList::deleteBlock(MallocMetadata* block)
// //{
// //    MallocMetadata *temp1 = head, *temp2 = NULL;
// //    int ListLen = 0;
// //
// //    if (head == NULL) {
// //        cout << "List empty." << endl;
// //        return;
// //    }
// //
// //    // Declare temp1
// //    temp1 = head;
// //
// //    // Deleting the head.
// //    if (nodeOffset == 1) {
// //
// //        // Update head
// //        head = head->next;
// //        //delete temp1;
// //        return;
// //    }
// //
// //    // Traverse the list to
// //    // find the node to be deleted.
// //    while (nodeOffset-- > 1) {
// //
// //        // Update temp2
// //        temp2 = temp1;
// //
// //        // Update temp1
// //        temp1 = temp1->next;
// //    }
// //
// //    // Change the next pointer
// //    // of the previous node.
// //    temp2->next = temp1->next;
// //
// //    // Delete the node
// //    //delete temp1;
// //}

// // Function to insert a new node.
// void BlocksList::insertBlock(MallocMetadata* newBlock)
// {
//     // Create the new Node.
//     Node* newNode = new Node(data);

//     // Assign to head
//     if (head == NULL) {
//         head = newNode;
//         return;
//     }

//     // Traverse till end of list
//     Node* temp = head;
//     while (temp->next != NULL) {

//         // Update temp
//         temp = temp->next;
//     }

//     // Insert at the last.
//     temp->next = newNode;
// }

// // Function to print the
// // nodes of the linked list.
// void BlocksList::printList()
// {
//     Node* temp = head;

//     // Check for empty list.
//     if (head == NULL) {
//         cout << "List empty" << endl;
//         return;
//     }

//     // Traverse the list.
//     while (temp != NULL) {
//         cout << temp->data << " ";
//         temp = temp->next;
//     }
// }
