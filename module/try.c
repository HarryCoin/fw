#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>

MODULE_LICENSE("GPL");

static void trying(void) {
	printk(KERN_INFO "*** trying ***\n");
}

