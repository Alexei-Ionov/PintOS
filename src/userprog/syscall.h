#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "lib/kernel/list.h"
#include <stdlib.h>
#include "filesys/file.h"

/* Process identifier. */
typedef int pid_t;

struct file_info {
  struct list_elem elem;
  int fd;         //fd of the file
  struct file* f; //ptr to the actual file in the file description table
};

void destroy_fd_table(void);
int practice(int i);

void halt(void);

void exit(int status);

pid_t exec(const char* file);

int wait(pid_t pid);

bool create(const char* file, unsigned initial_size);
bool remove(const char* file);

int open(const char* filename);

int read(int fd, void* buffer, unsigned size);

struct file* getFile(int fd);

int write(int fd, const void* buffer, unsigned size);
void housekeep_metadata_list(void);
int exepected_num_args(int sys_val);
bool isFileSys(int sys_val);
bool isValidSys(int sys_val);
struct file_info* getInfo(int fd);
void syscall_init(void);
void halt(void);
void exit(int status);
pid_t exec(const char* file);
int wait(pid_t);
bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void* buffer, unsigned length);
int write(int fd, const void* buffer, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
int practice(int i);
// double compute_e(int n);
// tid_t sys_pthread_create(stub_fun sfun, pthread_fun tfun, const void* arg);
// void sys_pthread_exit(void) NO_RETURN;
// tid_t sys_pthread_join(tid_t tid);

// bool lock_init(lock_t* lock);
// void lock_acquire(lock_t* lock);
// void lock_release(lock_t* lock);
// bool sema_init(sema_t* sema, int val);
// void sema_down(sema_t* sema);
// void sema_up(sema_t* sema);
// tid_t get_tid(void);
#endif /* userprog/syscall.h */
