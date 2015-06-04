#ifndef NODELIST_H_
#define NODELIST_H_

typedef struct node{
	int value;
	int port;
	struct sockaddr_in *serveraddr;
	struct node *next;
} NODE;

NODE* insertNode(NODE *ptr, int value);
NODE* deleteNode(NODE *ptr, int value);
NODE* findNode(NODE *ptr, int value);
void print(NODE *ptr);
void deleteList(NODE *head);

#endif /* NODELIST_H_ */
