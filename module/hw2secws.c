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
	unsigned int addr = in_aton("127.0.0.1");
	printk(KERN_INFO "addr %d\n", addr);
	rules[0].src_ip = addr;
	printk(KERN_INFO "addr %d\n", rules[0].src_ip);

}



void rule_to_string(rule_t rule, char *buffer) {
	char temp[50];
	//bla = in_ntoa(rule.src_ip);
	snprintf(temp, 200, "%d.%d.%d.%d", NIPQUAD(rule.src_ip));
	strcat(buffer,temp);
	snprintf(temp, 200, " : %d.%d.%d.%d", NIPQUAD(rule.dst_ip));
	strcat(buffer,temp);
	snprintf(temp, 200, " || %u : %u", (rule.src_port), (rule.dst_port));
	strcat(buffer,temp);
	snprintf(temp, 200, " || %d", rule.protocol);
	strcat(buffer,temp);
}


void packet_to_rule_format(struct sk_buff *skb, rule_t *packet_as_rule) {
	struct iphdr *packet_iphdr;
	struct tcphdr *packet_tcph;
	struct udphdr *packet_udph;

	packet_iphdr = ip_hdr(skb);
	packet_as_rule->protocol = packet_iphdr->protocol;

	if (packet_iphdr->protocol == PROT_TCP) {
		packet_tcph = tcp_hdr(skb);
		printk(KERN_INFO "port %d\n", (u_short) ntohs(packet_tcph-> dest));
		packet_as_rule-> src_port = packet_tcph->source;
		packet_as_rule-> dst_port = packet_tcph->dest;
		packet_as_rule-> ack = packet_tcph->ack ? ACK_YES : ACK_NO;
	}
	else if (packet_iphdr->protocol == PROT_UDP) {
		packet_udph = udp_hdr(skb);
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
	printk(KERN_INFO "%d\n", (int) &rules[0]);
	printk(KERN_INFO "%d\n", (int) &rules[1]);
	printk(KERN_INFO "%d\n", (int) &rules[3]);
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

