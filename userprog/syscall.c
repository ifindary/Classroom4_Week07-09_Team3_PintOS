#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "../include/threads/init.h"
#include "../include/lib/kernel/stdio.h"
#include "../include/lib/user/syscall.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <string.h>
#include "threads/palloc.h"
#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

//user memory access
void check_address(void *addr);

//fdt
int process_add_file(struct file *f);
struct file *process_get_file(int fd);
void process_close_file(int fd);

// system call function
void halt(void);
void exit(int status);
int write(int fd, const void *buffer, unsigned size);
pid_t fork(const char *thread_name);
int exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
            ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
            FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
    lock_init(&filesys_lock);
}

static struct intr_frame *frame;
/* The main system call interface */
void syscall_handler (struct intr_frame *f UNUSED) {
    // TODO: Your implementation goes here.
    int syscall = f->R.rax;
    
    frame = f;
    
    switch (syscall){
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit(f->R.rdi);
            break;
        case SYS_FORK:
            f->R.rax = fork(f->R.rdi);
            break;
        case SYS_EXEC:
            f->R.rax = exec(f->R.rdi);
            break;
        case SYS_WAIT:
            f->R.rax = wait(f->R.rdi);
            break;
        case SYS_CREATE:
            f->R.rax = create(f->R.rdi, f->R.rsi);
            break;
        case SYS_REMOVE:
            f->R.rax = remove(f->R.rdi);
            break;
        case SYS_OPEN:
            f->R.rax = open(f->R.rdi);
            break;
        case SYS_FILESIZE:
            f->R.rax = filesize(f->R.rdi);
            break;
        case SYS_READ:
            f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
            f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_SEEK:
            seek(f->R.rdi, f->R.rsi);
            break;
        case SYS_TELL:
            f->R.rax = tell(f->R.rdi);
            break;
        case SYS_CLOSE:
            close(f->R.rdi);
            break;

        default:
            thread_exit();
            break;
    }
    // printf ("system call!\n");

    // thread_exit ();
}

 
void check_address(void *addr){
    if(!is_user_vaddr(addr) || addr == NULL){
        exit(-1);
    }
    if(pml4_get_page(thread_current()->pml4,addr) == NULL){
        exit(-1);
    }
}

// 핀토스 종료 함수
void halt(void){
    power_off();
}

//현재 유저 프로그램 종료 후 커널로 상태 반환하는 함수
void exit(int status){
    struct thread *t = thread_current();
    t->exit_status = status;
    printf ("%s: exit(%d)\n", t->name, status);

    thread_exit();
}

bool create(const char *file, unsigned initial_size){
    check_address(file);

    return filesys_create(file,initial_size);
}

bool remove(const char *file){
    check_address(file);

    return filesys_remove(file);
}
// 파일을 여는 함수
int open(const char *file){
    check_address(file);
    struct file *f = filesys_open(file);
    if(f == NULL){
        return -1;
    }
    int result = process_add_file(f);
    if(result == -1){
        file_close(f);
    }
    return result;
}

//열려있는 파일의 크기 반환하는 함수
int filesize(int fd){
    struct file *f = process_get_file(fd);

    if(f == NULL){
        return -1;
    }
    return file_length(f);
}

int read(int fd, void *buffer, unsigned size){
	check_address(buffer);
    int result = 0;

    if(fd == 0){
        *(char *)buffer = input_getc();
		result = size;
    }else if(fd < 2){
		return -1;
	}else{
    	struct file *f = process_get_file(fd);
		if(f == NULL){
			return -1;
		}
		result = file_read(f,buffer,size);
	}
	return result;
}

int write(int fd, const void *buffer, unsigned size){
	check_address(buffer);
	struct file *f = process_get_file(fd);
	int result;

	if(fd == 1){
		putbuf(buffer,size);
		result = size;
	}else if(fd < 2){
		return -1;
	}else{
		if(f == NULL){
			return -1;
		}
		result = file_write(f,buffer,size);
	}

	return result;
}

//다음으로 읽거나 쓸 위치를 position으로 변경하는 함수
void seek(int fd, unsigned position){
    // struct file *f = process_get_file(fd);
	// if(f == NULL){
	// 	return;
	// }
	
    file_seek(fd,position);
}

// 다음으로 읽거나 쓸 위치 반환 함수
unsigned tell(int fd){
    // struct file *f = process_get_file(fd);
	// if(f == NULL){
	// 	return -1;
	// }

    return file_tell(fd);    
}
// 열린 파일 닫는 함수
void close(int fd){
    struct file *f = process_get_file(fd);

	if(f == NULL){
		return;
	}
    file_close(f);

    process_close_file(fd);
}

pid_t fork(const char *thread_name){
	return process_fork(thread_name, frame);
}

int exec(const char *cmd_line){
	check_address(cmd_line);
	char *cpy_cmd_line =  palloc_get_page(0);
	if(cpy_cmd_line == NULL){
		exit(-1);
	}
	strlcpy(cpy_cmd_line,cmd_line,PGSIZE);

    if(process_exec(cpy_cmd_line) == -1){
        exit(-1);
    }
}
int wait(pid_t pid){
    return process_wait(pid);
}

// function for fdt(1. process_add_file 2. process_get_file 3. process_close_file)
int process_add_file(struct file *f){
    struct thread *t = thread_current();
    struct file **fdt = t->fdt;

    while(t->next_fd < FDT_COUNT_LIMIT && fdt[t->next_fd]){
        t->next_fd++;
    }
    if(t->next_fd >= FDT_COUNT_LIMIT){
        return -1;
    }
    fdt[t->next_fd] = f;

    return t->next_fd;
}

struct file *process_get_file(int fd){
    struct thread *t = thread_current();
    struct file **fdt = t->fdt;

    if(fd < 2 || fd >= FDT_COUNT_LIMIT){
        return NULL;
    }
    return fdt[fd];
}

void process_close_file(int fd){
    struct thread *t = thread_current();
    struct file **fdt = t->fdt;

    if(fd < 2 || fd >= FDT_COUNT_LIMIT){
        return NULL;
    }
    fdt[fd] = NULL; 
}
