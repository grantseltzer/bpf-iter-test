typedef struct vma_info {
    unsigned long pid;
    unsigned long start;
    unsigned long end;
    unsigned long flags;
    char hash[32];
    char filepath[64];
} vma_info_t;

