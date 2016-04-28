#include <stdio.h>
#include <stdlib.h>
       #include <sys/socket.h>
       #include <netinet/in.h>

void main(int argc, char **argv) {
	struct in_addr getaddr;
	inet_pton(AF_INET, "127.0.0.1", &getaddr); # saves in big endian

	printf("hey %d\n", getaddr.s_addr);
}

