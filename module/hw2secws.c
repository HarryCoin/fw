/*
 * #######################################################
 * ##  Workshop in Information Security - Assignment 3  ##
 * #######################################################
 *
 * Presented by Assaf Oren , assaforen , 301750956
 * assafo@gmail.com
 *
*/

#include <linux/module.h> // For all modules
#include <linux/kernel.h> // For KERN_INFO and Macros
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]

#include "fw.h"
#include "shared_vars.h"
#include "sysfs_dev.c"

rule_t rules[50];
int rules_len = 0;


void load_rules(void) {


}

void init_rules(void) {
	rules[0].src_ip = in_aton("10.0.2.0");
	printk(KERN_INFO "addr %d\n", rules[0].src_ip);
	rules[0].src_prefix_mask = in_aton("255.255.255.0");
	printk(KERN_INFO "addr %d\n", rules[0].src_prefix_mask);
	rules[1].src_ip = in_aton("10.0.1.0");
	printk(KERN_INFO "addr %d\n", rules[0].src_ip);
	rules[1].src_prefix_mask = in_aton("255.255.255.0");
	printk(KERN_INFO "addr %d\n", rules[0].src_prefix_mask);
	rules_len = 2;
}


int check_packet_against_rules(rule_t packet) {
	int i;

	for (i = 0; i < rules_len; i++) {
		// Match against all fields
		// Check direction - wtf

		// Check source IP
		if (rules[i].src_ip != 0) {
			unsigned int ip_after_mask = packet.src_ip & rules[i].src_prefix_mask;
			if (ip_after_mask != rules[i].src_ip)
				continue;
		}

		// Check dest IP
		if (rules[i].dst_ip != 0) {
			unsigned int ip_after_mask = packet.dst_ip & rules[i].dst_prefix_mask;
			if (ip_after_mask != rules[i].dst_ip)
				continue;
		}

		// Check protocol
		if (rules[i].protocol != PROT_ANY) {
			if (packet.protocol != rules[i].protocol)
				continue;
		}

		// Check ports
		if (rules[i].protocol == PROT_TCP || rules[i].protocol == PROT_UDP) {
			if (rules[i].src_port != 0) {
				if (packet.src_port != rules[i].src_port)
					continue;
			}

		}

		// If reached here - rules fits. return it
		printk(KERN_INFO "we have a fit for rule %d", i);

		// Log to file
		// Return accept
	}
}



void rule_to_string(rule_t rule, char *buffer) {
	char temp[50];
	//bla = in_ntoa(rule.src_ip);
	snprintf(temp, 200, "%d.%d.%d.%d", NIPQUAD(rule.src_ip));
	strcat(buffer,temp);
	snprintf(temp, 200, " : %d.%d.%d.%d", NIPQUAD(rule.dst_ip));
	strcat(buffer,temp);
	snprintf(temp, 200, " || %u : %u", ntohs(rule.src_port), ntohs(rule.dst_port));
	strcat(buffer,temp);
	snprintf(temp, 200, " || %d || %d", rule.protocol, rule.ack);
	strcat(buffer,temp);
}


void packet_to_rule_format(struct sk_buff *skb, rule_t *packet_as_rule) {
	struct iphdr *packet_iphdr;
	struct tcphdr *packet_tcph;
	struct udphdr *packet_udph;

	packet_iphdr = ip_hdr(skb);
	packet_as_rule->protocol = packet_iphdr->protocol;
	packet_as_rule-> ack = 0;

	if (packet_iphdr->protocol == PROT_TCP) {
		packet_tcph = (struct tcphdr *)(skb_transport_header(skb)+20);
		packet_as_rule-> src_port = packet_tcph->source;
		packet_as_rule-> dst_port = packet_tcph->dest;
		packet_as_rule-> ack = packet_tcph->ack ? ACK_YES : ACK_NO;
	}

	else if (packet_iphdr->protocol == PROT_UDP) {
		//packet_udph = udp_hdr(skb);
		packet_udph = (struct udphdr *)(skb_transport_header(skb)+20);
		packet_as_rule-> src_port = packet_udph->source;
		packet_as_rule-> dst_port = packet_udph->dest;

	} else { // ICMP
		packet_as_rule-> src_port = PORT_ANY;
		packet_as_rule-> dst_port = PORT_ANY;
	}

	packet_as_rule-> src_ip = packet_iphdr->saddr;
	packet_as_rule-> src_prefix_mask = 0;
	packet_as_rule-> src_prefix_size = 0;
	packet_as_rule-> dst_ip = packet_iphdr->daddr;
	packet_as_rule-> dst_prefix_mask = 0;
	packet_as_rule-> dst_prefix_size = 0;

}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Assaf Oren");



/* !------------ Packet counters -------------! */
unsigned int counter_packets_passed = 0;
unsigned int counter_packets_blocked = 0;
/* !------------ /Packet counters ------------! */



/* !------------ Hooks -------------! */
struct nf_hook_ops nf_hook_in;
struct nf_hook_ops nf_hook_forward;
struct nf_hook_ops nf_hook_out;
/* !------------ /Hooks ------------! */



/* !------------ Hook functions -------------! */
unsigned int hook_func_accept (
        unsigned int hooknum, 
        struct sk_buff *skb,          
        const struct net_device *in, 
        const struct net_device *out,         
        int (*okfn)(struct sk_buff *)) {
	char buff[200] = {0};

	counter_packets_passed++;
	// Analyze packet
	rule_t packet;
	packet_to_rule_format(skb, &packet);

	// printk(KERN_INFO "ip %u\n", packet.src_ip);

	rule_to_string(packet, buff);
	printk(KERN_INFO "oi: %s", buff);
	check_packet_against_rules(packet);
	printk(KERN_INFO "*** packet passed ***\n");
	return NF_ACCEPT;
}

unsigned int hook_func_drop (
        unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *)) {

	counter_packets_blocked++;
	printk(KERN_INFO "*** packet blocked ***\n");
	return NF_DROP;
}
/* !------------ /Hook functions ------------! */


static int __init load_module(void) {
	printk(KERN_INFO "###########################################################\n");
	printk(KERN_INFO "###########################################################\n");
	printk(KERN_INFO "###########################################################\n");

	init_rules();

	counter_packets_passed = 0;
	counter_packets_blocked = 0;

	// Init IN hook
	nf_hook_in.hook = hook_func_accept;
	nf_hook_in.hooknum = NF_INET_PRE_ROUTING;
	nf_hook_in.pf = PF_INET;
	nf_hook_in.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nf_hook_in);


	// Init Sysfs device
	fw_sysfs_init();

	return 0;
}


static void __exit unload_module(void) {
	nf_unregister_hook(&nf_hook_in);

	fw_sysfs_exit();
}


module_init(load_module);
module_exit(unload_module);

