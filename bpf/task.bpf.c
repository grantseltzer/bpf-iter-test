#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "types.h"

SEC("iter/task")
int ps(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	if (task == NULL) {
		return 0;
	}
	if (task->group_leader != task) {
		return 0;
	}

	info_t info = {
		.pid = task->tgid,
		.ppid = task->parent->tgid,
		.uid = task->cred->uid.val,
		.gid = task->cred->gid.val,
	};

	long err = bpf_probe_read_kernel_str(info.comm, sizeof(info.comm), (void *)task->comm);
	if (err < 0) {
		bpf_printk("could not read kernel str comm: %ld", err);
		return 0;
	}
	err = bpf_seq_write(seq, &info, sizeof(info));
	if (err < 0) {
		bpf_printk("could not seq write: %ld", err);
		return 0;
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
