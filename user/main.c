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
#include <string.h>
 #include <arpa/inet.h>

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]


#define write_to_buf(format, what) buf_pos = buf_pos + snprintf(buf + buf_pos, 4096 - buf_pos, format, what);

int get_rules_size() {
	char* filename = "/sys/class/fw/fw_rules/rules_size";
	FILE* f;

	f = fopen(filename, "r");
	if (f == NULL) {
		printf("Error opening file. Quitting.\n");
		return;
	}

	int size;

	if (fscanf(f, "%d", &size) != 1) {
		printf("Error reading file. Quitting.\n");
		close(f);
		return;
	}

	return size;
}


void load_rules_from_file() {
	char *filename = "a.txt";
	char buf[4096] = {0};
	int buf_pos = 2;
	buf[0] = *"5"; buf[1] = *"5";
	FILE *f; int ip;
	f = fopen(filename, "r");
			struct in_addr address;


	char rule_name[20], direction[10], src_ip[25], dst_ip[25], protocol[10], src_port[7], dst_port[7], ack[7], action[10];

	if (fscanf(f, "%s %s %s %s %s %s %s %s %s\n", \
			rule_name, direction, src_ip, dst_ip, protocol, src_port, dst_port, ack, action) < 0) {
		printf("error");
		return;
	}

	write_to_buf("%s ", rule_name);

	char dir[2] = "0";
	if (strcmp("in",direction) == 0)
		dir[0] = (char) 1;
	else if (strcmp("out",direction) == 0)
		dir[0] = (char) 2;
	else if (strcmp("any",direction) == 0)
		dir[0] = (char) 3;
	write_to_buf("%s ", dir);

	if (strstr(src_ip,"/") != NULL) {
		printf("\n\nwhat\n\n");
		// Divide
	} else {
		//don't divide? :\
		printf("\n\n\nassaf \n");
		//ip = in_aton(src_ip);
		//printf("\n%s %d\n",src_ip, address.s_addr);
		//write_to_buf("%d ", ip);

	}
	printf("%s\n", buf);
	//printf("%s %s %s %s %s %s %s %s %s\n", rule_name, direction, src_ip, dst_ip, protocol, src_port, dst_port, ack, action);
	close(f);
}

int print_rules() {
	int rules_len = get_rules_size();

	char* filename2 = "/sys/class/fw/fw_rules/rules";
	FILE* f2;
	f2 = fopen(filename2, "r");
	if (f2 == NULL) {
		printf("Error opening file. Quitting.\n");
		return;
	}
	load_rules_from_file();
	char buf[200];
	char rule_name[20];
	int direction, src_ip, src_nps, dst_ip, dst_nps, protocol, src_port, dst_port, ack, action;
	int i;

	printf("\n#################\n");
	printf("## Rules Table ##\n");
	printf("#################\n\n");
	for (i = 0; i < rules_len; i++) {
		if (fscanf(f2, "%s %d %d/%d %d/%d %d %d %d %d %d\n", \
				rule_name, &direction, &src_ip, &src_nps, &dst_ip, &dst_nps, &protocol, &src_port, &dst_port, &ack, &action) < 0) {
			printf("Error reading file. Quitting.\n");
			close(f2);
			return;
		}
		printf("%s ", rule_name);

		if (direction == 1)
			printf("in ");
		else if (direction == 2)
			printf("out ");
		else
			printf("any ");

		if (src_ip == 0)
			printf("any ");
		else
			printf("%d.%d.%d.%d/%d ", NIPQUAD(src_ip), src_nps);

		if (dst_ip == 0)
			printf("any ");
		else
			printf("%d.%d.%d.%d/%d ", NIPQUAD(dst_ip), dst_nps);

		if (protocol == 143)
			printf("any ");
		else if (protocol == 6)
			printf("tcp ");
		else if (protocol == 17)
			printf("udp ");
		else if (protocol == 1)
			printf("icmp ");
		else if (protocol == 255)
			printf("other ");

		src_port = ntohs(src_port);
		if (src_port == 0)
			printf("any ");
		else if (src_port == 1023)
			printf(">1023 ");
		else
			printf("%d ",src_port);

		dst_port = ntohs(dst_port);
		if (dst_port == 0)
			printf("any ");
		else if (dst_port == 1023)
			printf(">1023 ");
		else
			printf("%d ",(dst_port));

		if (ack == 1)
			printf("no ");
		else if (ack == 2)
			printf("yes ");
		else
			printf("any ");

		if (action == 0)
			printf("drop");
		else if (action == 1)
			printf("accept");

		printf("\n");

		//printf("%s %d %d/%d %d/%d %d %d %d %d %d\n", \
		//		rule_name, direction, src_ip, src_nps, dst_ip, dst_nps, protocol, src_port, dst_port, ack, action);
	}
	printf("\n");
	close(f2);
}

int clear_rules() {
	char* filename = "/sys/class/fw/fw_rules/clear_rules";
	FILE* f;

	f = fopen(filename, "w");
	if (f == NULL) {
		printf("Error opening file. Quitting.\n");
		return -1;
	}

	if (fprintf(f, "1", 1) < 0) {
		printf("Error writing to file. Quitting.\n");
		close(f);
		return -1;
	}

	return 1;
}

void main(int argc, char **argv) {
	int reset_flag = 0;

	// Check args and parse input
	if (argc > 2) {
		printf("Error: Invalid number of args: only one argument permitted. Quitting.\n");
		return;
	}
	if (argc == 2) {
		if (strcmp("0",argv[1]) == 0) {
			if (clear_rules() < 0)
				return;
		} else if (strcmp("1",argv[1]) == 0) {
			if (print_rules() < 0)
				return;
		} 
		else {
			printf("Error: Parameter can't be different from \"0\". Quitting.\n");
			return;
		}
	}
	

	
}