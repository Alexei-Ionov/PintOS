#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>
#include "filesys/file.h"

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

struct process_create_args {
  const char* file_name;
  struct process_metadata* metadata;
};
struct process_metadata {
  pid_t
      pid; //pid could be the pid of the process that owns this struct or the pid of the child, depending on the context
  struct semaphore sema;
  int exit_status; //exit status of the child
  int ref_cnt;
  bool waiting;
  struct lock metadata_lock;
  bool load_successful;
  struct list_elem elem;
};
/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */
  int fd_counter;             // counter for fd
  struct list* file_list;     // pointer to list of FD table
  struct list* children_list;
  struct process_metadata* own_metadata;
};

void userprog_init(void);

struct process_metadata* process_execute(const char* file_name);
int process_wait(struct process_metadata*);
void process_exit(int status);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
