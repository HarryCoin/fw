/*
 * #######################################################
 * ##  Workshop in Information Security - Assignment 2  ##
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

#include "shared_vars.h"
#include "sysfs_dev.c"



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

	counter_packets_passed++;
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
	counter_packets_passed = 0;
	counter_packets_blocked = 0;

	// Init IN hook
	nf_hook_in.hook = hook_func_accept;
	nf_hook_in.hooknum = NF_INET_LOCAL_IN;
	nf_hook_in.pf = PF_INET;
	nf_hook_in.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nf_hook_in);

	// Init OUT hook
	nf_hook_out.hook = hook_func_accept;
	nf_hook_out.hooknum = NF_INET_LOCAL_OUT;
	nf_hook_out.pf = PF_INET;
	nf_hook_out.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nf_hook_out);

	// Init FORWARD hook
	nf_hook_forward.hook = hook_func_drop;
	nf_hook_forward.hooknum = NF_INET_FORWARD;
	nf_hook_forward.pf = PF_INET;
	nf_hook_forward.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nf_hook_forward);

	// Init Sysfs device
	fw_sysfs_init();

	return 0;
}


static void __exit unload_module(void) {
	nf_unregister_hook(&nf_hook_in);
	nf_unregister_hook(&nf_hook_out);
	nf_unregister_hook(&nf_hook_forward);

	fw_sysfs_exit();
}


module_init(load_module);
module_exit(unload_module);

