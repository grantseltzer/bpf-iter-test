#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "types.h"

extern char* bpf_sha256(const char *data, int size) __ksym;

#define PAGE_SIZE_C 4096

struct scratch_buffer {
	char buf[PAGE_SIZE_C];
};

// Per-CPU map to store scratch buffer (avoids allocation failures)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch_buffer);
} scratch_map SEC(".maps");

// Context structure for bpf_loop callback
struct loop_ctx {
	struct task_struct    *task;
	void                  *mem;
	struct scratch_buffer *scratch;
	struct seq_file       *seq;
	unsigned long         vma_start;
	unsigned long         vma_end;
	unsigned long         vma_flags;
	unsigned long         pid;
	char                  filepath[64];
};

// Callback function for bpf_loop - processes one page at a time
static long process_page(u64 index, void *ctx)
{
	struct loop_ctx *loop_ctx = (struct loop_ctx *)ctx;
	long err;
	
	// Calculate the start and end addresses for this specific page
	unsigned long page_start = loop_ctx->vma_start + (index * PAGE_SIZE_C);
	unsigned long page_end = page_start + PAGE_SIZE_C;

	bpf_printk("Page start: %lx, Page end: %lx", page_start, page_end);

	// Copy the page data from user space	
	err = bpf_copy_from_user_task(
		(void*)loop_ctx->scratch->buf,
		PAGE_SIZE_C,
		(void *)page_start,
		loop_ctx->task,
		0
	);
	if (err < 0) {
		bpf_printk("could not copy from user task: %ld", err);
		return 1; 
	}
	
	// Hash the current page
	char *hash = bpf_sha256(loop_ctx->scratch->buf, PAGE_SIZE_C);
	
	// Create page-specific info structure
	vma_info_t page_info = {
		.pid = loop_ctx->pid,
		.start = page_start,
		.end = page_end,
		.flags = loop_ctx->vma_flags,
	};
	
	// Copy the hash and filepath
	bpf_probe_read_kernel((void*)page_info.hash, sizeof(page_info.hash), (void *)hash);
	bpf_probe_read_kernel((void*)page_info.filepath, sizeof(page_info.filepath), loop_ctx->filepath);
	
	// Output this page's information
	err = bpf_seq_write(loop_ctx->seq, &page_info, sizeof(page_info));
	if (err < 0) {
		bpf_printk("could not seq write: %ld", err);
		return 0;
	}
	return 0;
}

SEC("iter.s/task_vma")
int collect_vmas(struct bpf_iter__task_vma *ctx)
{
	struct vm_area_struct *vma = ctx->vma;
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	if (task == NULL) {
		bpf_printk("task is NULL");
		return 0;
	}
	if (vma == NULL) {
		bpf_printk("vma is NULL");
		return 0;
	}
	if (seq == NULL) {
		bpf_printk("seq is NULL");
		return 0;
	}
	if (!(vma->vm_flags & 0x00000004)) {
		return 0;
	}
	bpf_printk("Entered for vma of task %d", task->tgid);
	long unsigned int brk = task->mm->brk;
	long unsigned int start_brk = task->mm->start_brk;
	long unsigned int stack_start = task->mm->start_stack;
	long err;
	if (vma->vm_start == 0 || vma->vm_end == 0 || vma->vm_end < vma->vm_start) {
		bpf_printk("Invalid vma range: start=%lx end=%lx", vma->vm_start, vma->vm_end);
		return 0;
	}
	
	unsigned long sizeOfVMA = vma->vm_end - vma->vm_start;
	__u32 numberOfPagesInVMA = sizeOfVMA / PAGE_SIZE_C;

	// Use per-CPU map instead of bpf_obj_new
	__u32 key = 0;
	struct scratch_buffer *scratch = bpf_map_lookup_elem(&scratch_map, &key);
	if (!scratch) {
		bpf_printk("Failed to get scratch buffer for task->tgid: %d", task->tgid);
		return 0;
	}

	// Prepare filepath for the context
	char filepath[64] = {0};
	bpf_probe_read_kernel_str(filepath, sizeof(filepath), vma->vm_file->f_path.dentry->d_name.name);

	struct loop_ctx loop_ctx = {
		.task = task,
		.mem = (void *)vma->vm_start,
		.scratch = scratch,
		.seq = seq,
		.vma_start = vma->vm_start,
		.vma_end = vma->vm_end,
		.vma_flags = vma->vm_flags,
		.pid = task->tgid, 
	};

	bpf_probe_read_kernel((void*)loop_ctx.filepath, sizeof(loop_ctx.filepath), filepath);
	bpf_printk("Number of pages: %d", numberOfPagesInVMA);
	long loops_performed = bpf_loop(numberOfPagesInVMA, process_page, &loop_ctx, 0);
	if (loops_performed < 0) {
		bpf_printk("bpf_loop failed: %ld", loops_performed);
		return 0;
	}
	bpf_printk("Finished vma for task %d", task->tgid);
	return 0;
}

char _license[] SEC("license") = "GPL";
