/*
 * Userspace Interface Implementation
 * ##################################
 *
 * Lets the user see # of packets passed and blocked,
 * and also reset the counters.
 *
*/


#include <stdio.h>
#include <stdlib.h>


void main(int argc, char **argv) {
	int reset_flag = 0;

	// Check args and parse input
	if (argc > 2) {
		printf("Error: Invalid number of args: only one argument permitted. Quitting.\n");
		return;
	}
	if (argc == 2) {
		if (strcmp("0",argv[1]) == 0) {
			reset_flag = 1;
		} else {
			printf("Error: Parameter can't be different from \"0\". Quitting.\n");
			return;
		}
	}


	char* filename = "/sys/class/firewall_class/firewall_packet_counters/sysfs_att";
	FILE* f;

	if (reset_flag == 1) {
		// Reset values
		f = fopen(filename, "w");
		if (f == NULL) {
			printf("Error opening file. Quitting.\n");
			return;
		}

		if (fprintf(f, "%u %u", 0, 0) != 3) {
			printf("%d\n",res);
			printf("Error writing to file. Quitting.\n");
			close(f);
			return;
		}
	}

	else {
		// Print values
		f = fopen(filename, "r");
		if (f == NULL) {
			printf("Error opening file. Quitting.\n");
			return;
		}

		int accepted,blocked;

		if (fscanf(f, "%u %u", &accepted, &blocked) != 2) {
			printf("Error reading file. Quitting.\n");
			close(f);
			return;
		}

		printf("Firewall Packets Summary:\n");
		printf("Number of accepted packets: %u\n", accepted);
		printf("Number of dropped packets: %u\n", blocked);
		printf("Total number of packets: %u\n", accepted + blocked);
	}

	close(f);
}