/*
 * #######################################################
 * ##  Workshop in Information Security - Assignment 1  ##
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


MODULE_LICENSE("GPL"); // To remove kernel taint message



/* !------------ Hooks ------------! */
struct nf_hook_ops nf_hook_in;
struct nf_hook_ops nf_hook_forward;
struct nf_hook_ops nf_hook_out;
/* !------------ /Hooks ------------! */



/* !------------ Hook functions ------------! */
unsigned int hook_func_accept (
        unsigned int hooknum, 
        struct sk_buff *skb,          
        const struct net_device *in, 
        const struct net_device *out,         
        int (*okfn)(struct sk_buff *)) {

	printk(KERN_INFO "*** packet passed ***\n");
	return NF_ACCEPT;
}

unsigned int hook_func_drop (
        unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *)) {

	printk(KERN_INFO "*** packet blocked ***\n");
	return NF_DROP;
}
/* !------------ /Hook functions ------------! */


static int __init load_module(void) {
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

	return 0;
}


static void __exit unload_module(void) {
	nf_unregister_hook(&nf_hook_in);
	nf_unregister_hook(&nf_hook_out);
	nf_unregister_hook(&nf_hook_forward);
}


module_init(load_module);
module_exit(unload_module);

