#ifndef NODELIST_H_
#define NODELIST_H_

typedef struct node{
	int value;
	struct node *next;
} NODE;

NODE* insertNode(NODE *ptr, int value);
NODE* deleteNode(NODE *ptr, int value);
NODE* findNode(NODE *ptr, int value);
void deleteList(NODE *head);
void print(NODE *ptr);

#endif /* NODELIST_H_ */
