#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "lib/kernel/list.h"
#include <stdlib.h>
#include "filesys/file.h"

struct file_info {
  struct list_elem elem;
  int fd;            //fd of the file
  struct file* file; //ptr to the actual file in the file description table
};
void destroy_table(void);

void syscall_init(void);

bool create(const char* file, unsigned initial_size);

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

#endif /* userprog/syscall.h */
