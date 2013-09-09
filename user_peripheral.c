/*
 * Thin layer to provide access to user peripherals in the FPGA fabric.
 *
 * Copyright (c) 2013 Communications Engineering Lab (CEL)
 * Karlsruhe Institute of Technology (KIT), Karlsruhe, Germany
 *
 * Author: Moritz Fischer <moritz.fischer@student.kit.edu>
*/

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/interrupt.h>
#include <linux/poll.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/wait.h>

#include <asm/page.h>

#define PAGE_ORDER 10

struct user_peripheral_drvdata {
	struct platform_device *pdev;
	struct miscdevice mdev;

	unsigned long regs_phys_addr;
	size_t regs_len;

	unsigned int irq;
	atomic_t irq_happened;

	struct page *xx_buf;
	unsigned long xx_phys_addr;
	size_t xx_len;

	wait_queue_head_t wait;

	atomic_t in_use;
};

/* Sets p to 1, if not set, otherwise nothing.
 * Returns zero if it was not one, non-zero else
 * */
#define test_and_set(p) !atomic_add_unless(p, 1, 1)

#define to_drvdata(p) container_of(p, struct user_peripheral_drvdata, mdev)

static ssize_t user_peripheral_get_regs_phys_addr(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct user_peripheral_drvdata *d = platform_get_drvdata(pdev);
	return sprintf(buf, "%lu\n", d->regs_phys_addr);
}

static ssize_t user_peripheral_get_xx_phys_addr(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct user_peripheral_drvdata *d = platform_get_drvdata(pdev);
	return sprintf(buf, "%lu\n", d->xx_phys_addr);
}

static ssize_t user_peripheral_get_regs_len(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct user_peripheral_drvdata *d = platform_get_drvdata(pdev);
	return sprintf(buf, "%lu\n", d->regs_len);
}

static ssize_t user_peripheral_get_xx_buf_len(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct user_peripheral_drvdata *d = platform_get_drvdata(pdev);
	return sprintf(buf, "%lu\n", d->xx_len);
}

static DEVICE_ATTR(regs_phys_addr, S_IRUGO, user_peripheral_get_regs_phys_addr, NULL);
static DEVICE_ATTR(regs_len, S_IRUGO, user_peripheral_get_regs_len, NULL);

static DEVICE_ATTR(xx_phys_addr, S_IRUGO, user_peripheral_get_xx_phys_addr, NULL);
static DEVICE_ATTR(xx_buf_len, S_IRUGO, user_peripheral_get_xx_buf_len, NULL);

static struct attribute *user_peripheral_sysfs_entries[] = {
	&dev_attr_regs_phys_addr.attr,
	&dev_attr_xx_phys_addr.attr,
	&dev_attr_regs_len.attr,
	&dev_attr_xx_buf_len.attr,
	NULL
};

static struct attribute_group user_peripheral_attribute_group = {
		.name = NULL,
		.attrs = user_peripheral_sysfs_entries,
};

static irqreturn_t user_peripheral_irq_handler(int irq, void *pdata)
{
	struct user_peripheral_drvdata *d = pdata;
	//dev_info(&d->pdev->dev, "Received IRQ -1 updated\n");

	atomic_set(&d->irq_happened, 1);
	wake_up_interruptible(&d->wait);

	return IRQ_HANDLED;
}


static int user_peripheral_open(struct inode *inode, struct file *filp)
{
	int ret;
	struct user_peripheral_drvdata *d = to_drvdata(filp->private_data);
	/*dev_info(&d->pdev->dev, "in user_peripheral_open()\n");*/

	if (test_and_set(&d->in_use))
	    return -EBUSY;

	ret = devm_request_irq(&d->pdev->dev, d->irq,
		user_peripheral_irq_handler, 0, "user_peripheral", d);
	if (ret) {
		dev_err(&d->pdev->dev, "Could not request IRQ %d\n", d->irq);
		return -EBUSY;
	} else
		atomic_set(&d->irq_happened, 0);

	return 0;
}

static int user_peripheral_release(struct inode *inode, struct file *filp)
{
	struct user_peripheral_drvdata *d = to_drvdata(filp->private_data);
	/*dev_info(&d->pdev->dev, "in user_peripheral_release()\n");*/

	devm_free_irq(&d->pdev->dev, d->irq, d);
	atomic_set(&d->in_use, 0);
	return 0;
}

/* Not that those to translate to offsets of N * PAGE_SIZE in
 * the userland mmap call */
#define MMAP_REGS 0x1
#define MMAP_BUFFS 0x2

static int user_peripheral_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct user_peripheral_drvdata *d = to_drvdata(filp->private_data);

	/*dev_info(&d->pdev->dev, "in user_peripheral_mmap(), trying to map 0x%lx bytes, offset %lx\n",*/
		/*vma->vm_end - vma->vm_start, vma->vm_pgoff);*/

	if (vma->vm_pgoff == MMAP_REGS) {
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

		if (remap_pfn_range(vma, vma->vm_start, d->regs_phys_addr >> PAGE_SHIFT,
			d->regs_len, vma->vm_page_prot))
			return -EIO;
		return 0;
	} else if (vma->vm_pgoff == MMAP_BUFFS) {
		if (remap_pfn_range(vma, vma->vm_start, page_to_pfn(d->xx_buf),
			d->xx_len, vma->vm_page_prot))
			return -EIO;
		return 0;
	}
	return -EINVAL;
}

static unsigned int user_peripheral_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask;
	struct user_peripheral_drvdata *d = to_drvdata(filp->private_data);

	poll_wait(filp, &d->wait, wait);

	if (atomic_read(&d->irq_happened) == 1)
		mask |= POLLIN | POLLRDNORM;

	return mask;

}

static ssize_t user_peripheral_read(struct file *filp, char *buf, size_t count,
				loff_t *ppos)
{
	struct user_peripheral_drvdata *d = to_drvdata(filp->private_data);

	if (!atomic_read(&d->irq_happened) &&
		filp->f_flags & O_NONBLOCK)
	    return -EAGAIN;

	wait_event_interruptible(d->wait, atomic_read(&d->irq_happened));
	atomic_set(&d->irq_happened, 0);
	return 0;
}


static const struct file_operations user_peripheral_fops = {
	.owner		=	THIS_MODULE,
	.open		=	user_peripheral_open,
	.mmap		=	user_peripheral_mmap,
	.poll		=	user_peripheral_poll,
	.read		=	user_peripheral_read,
	.release	=	user_peripheral_release,
};

static int user_peripheral_probe(struct platform_device *pdev)
{
	struct user_peripheral_drvdata *d;
	struct resource *regs, *irq;
	int ret;

	/*dev_info(&pdev->dev, "In user_peripheral_probe\n");*/

	d = devm_kzalloc(&pdev->dev, sizeof(struct user_peripheral_drvdata), GFP_KERNEL);
	if (!d)
		return -ENOMEM;
	d->pdev = pdev;
	dev_set_drvdata(&pdev->dev, d);

	regs = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!regs) {
		dev_err(&pdev->dev, "Error getting regs resource from devicetree\n");
		return -EIO;
	}

	if (!devm_request_mem_region(&pdev->dev, regs->start, resource_size(regs), "user_peripheral")) {
		dev_err(&pdev->dev, "Error requesting MEM region\n");
		return -EIO;
	}

	irq = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (!irq) {
		dev_err(&pdev->dev, "Error getting IRQ resource from devicetree\n");
		return -EIO;
	}
	d->irq = irq->start;
	init_waitqueue_head(&d->wait);

	/* Remember where we have our regs */
	d->regs_phys_addr = regs->start;
	d->regs_len = resource_size(regs);

	/* Try to allocate some pages for buffers */
	d->xx_buf = alloc_pages(GFP_ATOMIC, PAGE_ORDER);
	if (!d->xx_buf) {
		dev_err(&pdev->dev, "Error allocating buffer\n");
		return -ENOMEM;
	}

	d->xx_phys_addr = page_to_phys(d->xx_buf);
	d->xx_len = (1 << PAGE_ORDER) * PAGE_SIZE;

	dev_info(&pdev->dev, "Buffer @ %p, Regs @ %p + 0x%lx, IRQ %u\n",
		d->xx_phys_addr, d->regs_phys_addr, d->regs_len, d->irq);

	/* Initialize misc device */
	d->mdev.name = "user_peripheral";
	d->mdev.fops = &user_peripheral_fops,
	d->mdev.minor = MISC_DYNAMIC_MINOR;

	ret = misc_register(&(d->mdev));

	if (ret)
		dev_err(&pdev->dev, "Failed to register miscdevice\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &user_peripheral_attribute_group);

	if (ret)
		dev_err(&pdev->dev, "Failed to register sysfs attribute group\n");

	atomic_set(&d->in_use, 0);
	atomic_set(&d->irq_happened, 0);

	return 0;
}

static int user_peripheral_remove(struct platform_device *pdev)
{
	struct user_peripheral_drvdata *d;
	dev_info(&pdev->dev, "In user_peripheral_remove()\n");

	d = dev_get_drvdata(&pdev->dev);

	sysfs_remove_group(&d->pdev->dev.kobj, &user_peripheral_attribute_group);

	misc_deregister(&d->mdev);

	__free_pages(d->xx_buf, PAGE_ORDER);

	devm_kfree(&pdev->dev, d);

	return 0;
}

static const struct of_device_id user_peripheral_of_ids[] = {
	{ .compatible = "gnuradio,user_peripheral" },
	{ }
};

static struct platform_driver user_peripheral_driver = {
	.driver = {
		.name = "user_peripheral",
		.of_match_table = user_peripheral_of_ids,
		.owner = THIS_MODULE,
	},
	.probe = user_peripheral_probe,
	.remove = user_peripheral_remove,
};

static int __init user_peripheral_init(void)
{
	pr_debug("Loading user_peripheral module ...\n");
	return platform_driver_register(&user_peripheral_driver);
}

static void __exit user_peripheral_exit(void)
{
	pr_debug("Removing user_peripheral module ...\n");
	platform_driver_unregister(&user_peripheral_driver);
}

module_init(user_peripheral_init);
module_exit(user_peripheral_exit);

MODULE_AUTHOR("Moritz Fischer <moritz.fischer@student.kit.edu>");
MODULE_DESCRIPTION("Allows userland access to user peripherals in the FPGA fabric.");
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(of, user_peripheral_of_ids);
