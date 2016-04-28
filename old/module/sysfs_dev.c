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

static char* CHAR_DEVICE_NAME = "firewall_device";
static char* COUNTERS_CLASS_NAME = "firewall_class";
static char* SYSFS_DEVICE_NAME = "firewall_packet_counters";
/* !------------ /Device IDs and name ----------------------! */



/* !------------ Device implementation -----------------------! */
static struct file_operations fops = {
	.owner = THIS_MODULE
};

ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)	// sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u %u\n", counter_packets_passed, counter_packets_blocked);
}

ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	// sysfs store implementation
{
	int temp, temp2;
	if (sscanf(buf, "%u %u", &temp, &temp2) == 2) {
		counter_packets_passed = temp;
		counter_packets_blocked = temp2;
	}

	return count;	
}

static DEVICE_ATTR(sysfs_att, S_IRWXO , display, modify);
/* !------------ /Device implementation ----------------------! */



/* !------------ Exit function ------------------------! */
typedef enum {
	stage_chardev = 0,
	stage_class = 1,
	stage_sysfs_dev = 2,
	stage_attr = 3
} sysfs_stages;

// Receives as input the latest stage that succeeded,
// And cleans up all stages up to including that stage.
// e.g. in: stage_class, out: destroys the sysfs class and then unregisters the chardev
void exitProperly(sysfs_stages stage) {
	if (stage >= stage_attr) {
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr);
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
	sysfs_class = class_create(THIS_MODULE, COUNTERS_CLASS_NAME);
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
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr))
	{
		exitProperly(stage_sysfs_dev);
		return -1;
	}
	
	return 0;
}


// Called when module is removed
static void fw_sysfs_exit(void)
{
	exitProperly(stage_attr);
}
