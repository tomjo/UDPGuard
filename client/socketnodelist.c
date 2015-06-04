#include <stdio.h>      // NULL
#include <stdlib.h>		//malloc
#include "socketnodelist.h"

NODE* insertNode(NODE *ptr, int value) {
	NODE *newNode = (NODE *) malloc(sizeof(NODE));
	newNode->value = value;
	newNode->next = ptr;
	newNode->port = 0;
	return newNode;
}

NODE* deleteNode(NODE *ptr, int value) {
	NODE *tmp = NULL;
	if (ptr == NULL)
		return NULL;
	if (ptr->value == value) {
		tmp = ptr->next;
		free(ptr);
		return tmp;
	}
	ptr->next = deleteNode(ptr->next, value);
	return ptr;
}

NODE* findNode(NODE *ptr, int value) {
	while (ptr != NULL) {
		if (ptr->value == value)
			return ptr;
		ptr = ptr->next;
	}
	return NULL;
}

void print(NODE *ptr) {
	NODE *last, *current;

	last = NULL;

	while (ptr != last) {
		current = ptr;
		printf("%d  ", current->value);
		print(current->next);
		last = current;
	}
}

void deleteList(NODE *head) {
	NODE *next, *deleteMe;
	deleteMe = head;
	while (deleteMe) {
		next = deleteMe->next;
		free(deleteMe);
		deleteMe = next;
	}
}
