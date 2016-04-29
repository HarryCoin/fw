#include <stdio.h>
#include <stdlib.h>
       #include <sys/socket.h>
       #include <netinet/in.h>

void main(int argc, char **argv) {
	struct in_addr getaddr;
	inet_pton(AF_INET, "10.0.1.1", &getaddr); // saves in big endian

	int shit = 0;
	char *hey = "1 2 3";
	char oi = 'z';
	char yes[20];
	snprintf(yes, 20, "%d", 0);
	printf("%s\n", yes);

	char bla1,bla2, bla3;
	//sscanf(hey, "%s %s %s", &bla1, &bla2, &bla3);

	printf("hey %d\n", getaddr.s_addr);
}

