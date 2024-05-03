#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "userprog/process.h"
typedef int mapid_t;
int sys_halt(void);
int sys_exit(int status);
int sys_exec(const char* ufile);
int sys_wait(pid_t child);
int sys_create(const char* ufile, unsigned initial_size);
int sys_remove(const char* ufile);
int sys_open(const char* ufile);
int sys_filesize(int handle);
int sys_read(int handle, void* udst_, unsigned size);
int sys_write(int handle, void* usrc_, unsigned size);
int sys_seek(int handle, unsigned position);
int sys_tell(int handle);
int sys_close(int handle);
int sys_practice(int input);
int sys_compute_e(int n);
int sys_inumber(int fd);

void syscall_init(void);
void safe_file_close(struct file* file);

tid_t sys_get_tid(void);
bool sys_sema_up(char* sema);
bool sys_sema_down(char* sema);
bool sys_sema_init(char* sema, int val);
bool sys_lock_release(char* lock);
bool sys_lock_acquire(char* lock);
bool sys_lock_init(char* lock);
tid_t sys_pthread_join(tid_t tid);
void sys_pthread_exit(void);
tid_t sys_pthread_create(stub_fun sfun, pthread_fun tfun, const void* arg);

/* Project 3 and optionally project 4. */
mapid_t sys_mmap(int fd, void* addr);
void sys_munmap(mapid_t);

bool sys_chdir(const char* dir);
bool sys_mkdir(const char* dir);
bool sys_readdir(int fd, char* name);
bool sys_isdir(int fd);
int sys_inumber(int fd);

int sys_bc_stats(int sel);
void sys_bc_clear();
#endif /* userprog/syscall.h */
