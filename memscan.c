#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>

// 新版 iOS SDK 不再支持直接 include mach_vm.h，这里手动声明需要的函数
kern_return_t mach_vm_region(
    vm_map_t target_task,
    mach_vm_address_t *address,
    mach_vm_size_t *size,
    vm_region_flavor_t flavor,
    vm_region_info_t info,
    mach_msg_type_number_t *infoCnt,
    mach_port_t *object_name);

kern_return_t mach_vm_read(
    vm_map_t target_task,
    mach_vm_address_t address,
    mach_vm_size_t size,
    vm_offset_t *data,
    mach_msg_type_number_t *dataCnt);

#define CHUNK_SIZE 0x4000ULL

void search_string_in_task(mach_port_t task, const char *str) {
    size_t str_len = strlen(str);
    if (str_len == 0) return;

    mach_vm_address_t addr = 0;
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    kern_return_t kr;
    int total_found = 0;

    printf("开始扫描字符串: \"%s\" (长度 %zu)\n", str, str_len);

    while (1) {
        kr = mach_vm_region(task, &addr, &region_size, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &info_count, NULL);
        if (kr != KERN_SUCCESS) {
            break;
        }

        if ((info.protection & VM_PROT_READ) != 0) {
            mach_vm_address_t current = addr;
            while (current < addr + region_size) {
                mach_vm_size_t to_read = (addr + region_size - current > CHUNK_SIZE) ? 
                                         CHUNK_SIZE : (addr + region_size - current);
                
                vm_offset_t data_ptr = 0;
                mach_msg_type_number_t data_size = 0;
                kr = mach_vm_read(task, current, to_read, &data_ptr, &data_size);
                if (kr == KERN_SUCCESS && data_size > 0) {
                    char *base = (char *)data_ptr;
                    size_t remaining = data_size;
                    char *match = (char *)memmem(base, remaining, str, str_len);
                    while (match != NULL) {
                        mach_vm_address_t found_addr = current + (match - base);
                        printf("  [找到] 0x%016llx\n", (unsigned long long)found_addr);
                        total_found++;
                        size_t offset = (match - base) + str_len;
                        if (offset >= remaining) break;
                        match = (char *)memmem(base + offset, remaining - offset, str, str_len);
                    }
                    vm_deallocate(mach_task_self(), data_ptr, data_size);
                }
                current += to_read;
            }
        }
        addr += region_size;
        if (addr == 0 || addr > 0x7fffffffffffffffULL) break;
    }

    printf("扫描完成，共找到 %d 处匹配\n\n", total_found);
}

pid_t get_pid_by_name(const char *name) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t size = 0;

    if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0) {
        return 0;
    }

    struct kinfo_proc *procs = (struct kinfo_proc *)malloc(size);
    if (!procs) return 0;

    if (sysctl(mib, 4, procs, &size, NULL, 0) != 0) {
        free(procs);
        return 0;
    }

    int nproc = size / sizeof(struct kinfo_proc);
    pid_t found_pid = 0;
    for (int i = 0; i < nproc; i++) {
        if (strcmp(procs[i].kp_proc.p_comm, name) == 0) {
            found_pid = procs[i].kp_proc.p_pid;
            break;
        }
    }
    free(procs);
    return found_pid;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("用法: %s <进程名> <要搜索的字符串>\n", argv[0]);
        printf("示例: %s client dm65_scene_prop_76\n", argv[0]);
        printf("示例: %s client dm65_survivor_m_bo\n", argv[0]);
        return 1;
    }

    const char *proc_name = argv[1];
    const char *search_str = argv[2];

    printf("正在查找进程: %s\n", proc_name);
    pid_t pid = get_pid_by_name(proc_name);
    if (pid == 0) {
        printf("错误: 找不到名为 '%s' 的进程\n", proc_name);
        printf("提示: 用 'ps aux' 查看实际进程名\n");
        return 1;
    }
    printf("找到 PID: %d\n", pid);

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        printf("task_for_pid 失败: %s (错误码 0x%x)\n", mach_error_string(kr), kr);
        printf("请确认二进制已用 task_for_pid-allow 权限签名 (ldid -Sents.plist)\n");
        return 1;
    }
    printf("成功获取任务端口\n\n");

    search_string_in_task(task, search_str);

    mach_port_deallocate(mach_task_self(), task);
    return 0;
}
