#include <stdio.h>

typedef enum {
	a = 0,
	b = 1,
	c = 2
} oi;

void aiai(oi yes) {
	if (yes >= b) {
		printf("yes\n");
	}
}

void main(int argc, char **argv) {
	printf("heyo\n");
	aiai(c);
}