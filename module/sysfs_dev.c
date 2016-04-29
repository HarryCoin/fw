/*
 * Sysfs Device Implementation
 * ###########################
 *
 * For communicating with userspace.
 * Saves in sysfs_att number of packets passed and packets blocked
 * in format: "%u %u" (respectively).
 *
 * Based on Reuven's example.
 *
*/


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>

#include "shared_vars.h"


/* !------------ Device IDs and name ----------------------! */
static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

static char* CHAR_DEVICE_NAME = "fw_dev";
static char* FW_CLASS_NAME = "fw";
static char* SYSFS_DEVICE_NAME = "fw_rules";
static char* ATTR_RULES_SIZE = "rules_size";
/* !------------ /Device IDs and name ----------------------! */



/* !------------ Device implementation -----------------------! */
static struct file_operations fops = {
	.owner = THIS_MODULE
};


void rule_to_string_for_sysfs(rule_t rule, char *buffer) {
	char temp[50];
	buffer[0] = 0;
	//bla = in_ntoa(rule.src_ip);
	snprintf(temp, 200, "%s %d %d/%d %d/%d %d %d %d %d %d\n", \
		rule.rule_name, rule.direction, \
		rule.src_ip, rule.src_prefix_size, \
		rule.dst_ip, rule.dst_prefix_size, \
		rule.protocol, rule.src_port, rule.dst_port, rule.ack, rule.action);
	strcat(buffer,temp);
}



ssize_t get_rules(struct device *dev, struct device_attribute *attr, char *buf)	// sysfs show implementation
{
	int i = 0;
	int pos = 0;
	char rule_str[200];
	char temp[1000];
	temp[0] = 0;
	for (i = 0; i < rules_len; i++) {
		rule_to_string_for_sysfs(rules[i], rule_str);
		printk(KERN_INFO "sysfs %s", rule_str);
		pos = pos + scnprintf(buf + pos, PAGE_SIZE, "%s", rule_str);
	}

	//return 1;
	return pos;
}

ssize_t display_rules_size(struct device *dev, struct device_attribute *attr, char *buf)	// sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", rules_len);
}

ssize_t store_do_nothing(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	// sysfs store implementation
{
	/*int temp, temp2;
	if (sscanf(buf, "%u %u", &temp, &temp2) == 2) {
		counter_packets_passed = temp;
		counter_packets_blocked = temp2;
	}*/
	//rules_len--;

	return count;	
}

ssize_t store_clear_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	// sysfs store implementation
{
	rules_len = 0;
	return count;	
}

ssize_t display_do_nothing(struct device *dev, struct device_attribute *attr, char *buf)	// sysfs show implementation
{
	return 0;
}

static DEVICE_ATTR(rules_size, S_IRWXO , display_rules_size, store_do_nothing);
static DEVICE_ATTR(rules, S_IRWXO , get_rules, store_do_nothing);
static DEVICE_ATTR(clear_rules, S_IRWXO , display_do_nothing, store_clear_rules);





/* !------------ /Device implementation ----------------------! */



/* !------------ Exit function ------------------------! */
typedef enum {
	stage_chardev = 0,
	stage_class = 1,
	stage_sysfs_dev = 2,
	stage_attr1 = 3,
	stage_attr2 = 4,
	stage_attr3 = 5,
	all = 100
} sysfs_stages;

// Receives as input the latest stage that succeeded,
// And cleans up all stages up to including that stage.
// e.g. in: stage_class, out: destroys the sysfs class and then unregisters the chardev
void exitProperly(sysfs_stages stage) {
	if (stage >= stage_attr3) {
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_clear_rules.attr);
	}
	if (stage >= stage_attr2) {
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules.attr);
	}
	if (stage >= stage_attr1) {
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
	}
	if (stage >= stage_sysfs_dev) {
		device_destroy(sysfs_class, MKDEV(major_number, 0));
	}
	if (stage >= stage_class) {
		class_destroy(sysfs_class);
	}
	if (stage >= stage_chardev) {
		unregister_chrdev(major_number, CHAR_DEVICE_NAME);
	}
}
/* !------------ /Exit function -----------------------! */




 // Initialize  (called when module is initialized)
static int fw_sysfs_init(void)
{
	// Create char device
	major_number = register_chrdev(0, CHAR_DEVICE_NAME, &fops);
	if (major_number < 0)
		return -1;
		
	// Create sysfs class
	sysfs_class = class_create(THIS_MODULE, FW_CLASS_NAME);
	if (IS_ERR(sysfs_class))
	{
		exitProperly(stage_chardev);
		return -1;
	}
	
	// Create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, SYSFS_DEVICE_NAME);	
	if (IS_ERR(sysfs_device))
	{
		exitProperly(stage_class);
		return -1;
	}
	
	// Create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules_size.attr))
	{
		exitProperly(stage_sysfs_dev);
		return -1;
	}

	// Create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules.attr))
	{
		exitProperly(stage_attr1);
		return -1;
	}

	// Create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_clear_rules.attr))
	{
		exitProperly(stage_attr2);
		return -1;
	}
	
	return 0;
}


// Called when module is removed
static void fw_sysfs_exit(void)
{
	exitProperly(all);
}
