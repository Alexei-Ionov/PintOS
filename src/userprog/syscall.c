#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>

#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

//allows us to use file struct operations
#include "filesys/file.h"
// addded this here to get putbuf
#include "lib/kernel/console.h"
//to perform create & remove
#include "filesys/filesys.h"
//allows us to malloc file_info structs
//allows us to work with list
#include "lib/kernel/list.h"
#include "devices/input.h"
//used for checking args
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h" //for halt()

static void syscall_handler(struct intr_frame*);

struct lock file_sys_lock;

void syscall_init(void) {
  lock_init(&file_sys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

int practice(int i) { return i + 1; }

/*
iterates through the processes children list, decremeting ref cnt by 1

in the case where ref cnt becomes zero then we can remove and free it from our list
*/
void housekeep_metadata_list(void) {
  struct list* metadata_list = thread_current()->pcb->children_list;
  struct list_elem* ptr = list_begin(metadata_list);
  /*
  idear here is to iterate through shared metadata for children list 

  upon decrementing the ref cnt (after acquiring lock), 

  if the ref cnt == 0, then we will first remove the node from our list & free the memory associated with the struct
  */
  while (ptr != list_end(metadata_list)) {
    struct process_metadata* shared_data = list_entry(ptr, struct process_metadata, elem);
    struct list_elem* next_ptr = list_next(ptr);
    /*
    concept check: is this pattern for locking and releasing fine?     
    */
    lock_acquire(&(shared_data->metadata_lock));
    shared_data->ref_cnt -= 1;

    if (shared_data->ref_cnt == 0) {
      list_remove(&(shared_data->elem));
      free(shared_data);
    } else {
      lock_release(&(shared_data->metadata_lock));
    }
    ptr = next_ptr;
  }
  free(metadata_list); //at the end, free the entire list
}

/*
moved all the actual housekeeping for fd table & children list into process exit

therefore, ALL exits (including when kernel kills our process) will be able to approriately free all memory

*/
void exit(int status) {

  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  process_exit(status);
}
void halt(void) { shutdown_power_off(); }

pid_t exec(const char* file) {

  struct process_metadata* shared_data = process_execute(file);

  sema_down(&(shared_data->sema)); //waits for child to get to loading
  if (!shared_data->load_successful) {
    free(shared_data);
    free(file); //free the command line args?
    exit(-1);
  }
  //other wise load is successful
  struct list* c_list = thread_current()->pcb->children_list;
  list_push_back(c_list, &(shared_data->elem));
  return shared_data->pid;
}

int wait(pid_t pid) {

  struct list* metadata_list = thread_current()->pcb->children_list;
  struct list_elem* ptr;
  /*
  iterate thru metadata list to find metadata that matches our child pid
  */
  struct process_metadata* shared_data = NULL;
  for (ptr = list_begin(metadata_list); ptr != list_end(metadata_list); ptr = list_next(ptr)) {
    struct process_metadata* metadata = list_entry(ptr, struct process_metadata, elem);
    if (metadata->pid == pid) {
      shared_data = metadata;
      break;
    }
  }
  /*
  if child pid doesn't exist in our childrens list 
  OR 
  if parent has already called wait on this child, 

  then return -1
  */
  if (shared_data == NULL || (shared_data != NULL && shared_data->waiting == true)) {
    return -1;
  }
  /*
  now we need to check whether the child has already finished executing via ref counter

  if it has finished alr, then we don't need to wait 

  note: not sure if we need to acquire and release lock. doing it JUST IN CASE. 

  
  */
  shared_data->waiting = true; //allows our child to know that we are waiting for them
  lock_acquire(&(shared_data->metadata_lock));
  if (shared_data->ref_cnt == 1) {
    int ret = shared_data->exit_status;
    lock_release(&(shared_data->metadata_lock));
    return ret; //child alr exited
  }
  lock_release(&(shared_data->metadata_lock));
  //if child hasn't yet exited we need to wait for it to up the sema
  sema_down(&(shared_data->sema));
  /*
  once we get here we know our child exited and has the exit status in the shared metadata
  */

  return shared_data->exit_status;
}

bool create(const char* file, unsigned initial_size) { return filesys_create(file, initial_size); }

bool remove(const char* file) { return filesys_remove(file); }

int open(const char* filename) {
  struct file* file = filesys_open(filename);
  if (file == NULL) { //failed to open file
    return -1;
  }
  struct file_info* info = malloc(sizeof(struct file_info));
  if (info == NULL) {
    return -1;
  }
  info->f = file;
  /*
  IMPORTANT: for later, might need to change implementation FOR LOCKING. for now, we assume fine since we use global lock for all file syscalls
  */
  info->fd = thread_current()->pcb->fd_counter;
  thread_current()->pcb->fd_counter += 1;

  struct list* fd_list = thread_current()->pcb->file_list;
  list_push_back(fd_list, &info->elem);
  return info->fd;
}

int filesize(int fd) {
  struct file_info* info = getInfo(fd);
  if (info == NULL) {
    return -1;
  }
  return file_length(info->f);
}

// /*

// IMPORTANT:

// need to fix the below read() function. not sure if this is correct imlpementation since input_getc() just waits for input

// */
int read(int fd, void* buffer, unsigned size) {
  if (fd == 0) { //READING FROM STDIN
    unsigned cnt = 0;
    while (cnt != size) {
      char c = (char)input_getc();
      ((char*)buffer)[cnt] = c;
      cnt += 1;
    }
    return cnt;
  } else {
    struct file_info* info = getInfo(fd);
    if (info == NULL) {
      return -1;
    }
    return file_read(info->f, buffer, size);
  }
}

struct file_info* getInfo(int fd) {
  struct list* fd_list = thread_current()->pcb->file_list;
  struct list_elem* ptr;
  for (ptr = list_begin(fd_list); ptr != list_end(fd_list); ptr = list_next(ptr)) {
    struct file_info* info = list_entry(ptr, struct file_info, elem);
    if (info->fd == fd) {
      return info;
    }
  }
  return NULL;
}

int write(int fd, const void* buffer, unsigned size) {
  if (fd == 1) { //WRITING TO STDOUT!
    int cnt = 0;
    while (size >= 200) {
      putbuf(buffer + cnt, 200);
      size -= 200;
      cnt += 200;
    }
    putbuf(buffer + cnt, size);
    cnt += size; // in the final iteration we read the final size bytes
    return cnt;
  } else {
    struct file_info* info = getInfo(fd);
    if (info == NULL) {
      return -1;
    }
    struct file* file = info->f;
    if (file == NULL) {
      return -1;
    }
    off_t written = file_write(file, buffer, size);
    return written;
  }
}

void seek(int fd, unsigned position) {
  struct file_info* info = getInfo(fd);
  if (info != NULL) {
    file_seek(info->f, position);
  }
}

unsigned tell(int fd) {
  struct file_info* info = getInfo(fd);
  if (info == NULL) {
    exit(-1);
  }
  return file_tell(info->f);
}
bool isFileSys(int sys_val) {
  return (sys_val == SYS_WRITE || sys_val == SYS_READ || sys_val == SYS_OPEN ||
          sys_val == SYS_FILESIZE || sys_val == SYS_TELL || sys_val == SYS_CLOSE ||
          sys_val == SYS_CREATE || sys_val == SYS_SEEK);
}
int exepected_num_args(int sys_val) {
  if (sys_val == SYS_HALT || sys_val == SYS_PT_EXIT || sys_val == SYS_GET_TID) {
    return 0;
  } else if (sys_val == SYS_COMPUTE_E || sys_val == SYS_PRACTICE || sys_val == SYS_EXIT ||
             sys_val == SYS_EXEC || sys_val == SYS_WAIT || sys_val == SYS_REMOVE ||
             sys_val == SYS_OPEN || sys_val == SYS_FILESIZE || sys_val == SYS_TELL ||
             sys_val == SYS_CLOSE || sys_val == SYS_MUNMAP || sys_val == SYS_CHDIR ||
             sys_val == SYS_MKDIR || sys_val == SYS_ISDIR || sys_val == SYS_INUMBER ||
             sys_val == SYS_PT_JOIN || sys_val == SYS_LOCK_INIT || sys_val == SYS_LOCK_ACQUIRE ||
             sys_val == SYS_LOCK_RELEASE || sys_val == SYS_SEMA_DOWN || sys_val == SYS_SEMA_UP) {
    return 1;
  } else if (sys_val == SYS_CREATE || sys_val == SYS_SEEK || sys_val == SYS_MMAP ||
             sys_val == SYS_READDIR || sys_val == SYS_SEMA_INIT) {
    return 2;
  } else {
    return 3;
  }
}

void close(int fd) {
  struct file_info* info = getInfo(fd);
  if (info == NULL) {
    exit(-1);
  }
  file_close(info->f);
  list_remove(&(info->elem)); // removes fd from list
  free(info);
}

void destroy_fd_table(void) {
  struct list* fd_list = thread_current()->pcb->file_list;
  while (!list_empty(fd_list)) {
    struct list_elem* ptr = list_back(fd_list);
    struct file_info* info = list_entry(ptr, struct file_info, elem);
    file_close(info->f);
    list_remove(&(info->elem));
    free(info);
  }
  free(fd_list); // free the entire list at the end
}

void isValidPointer(void* ptr) {

  if (!(ptr != NULL && is_user_vaddr((const void*)ptr))) {
    exit(-1);
  }
  /*
  go thru all of the bytes pointed to by pointer to make sure none lie on page boundary
  */
  uint32_t* pd = active_pd();
  for (int i = 0; i < 4; i++) {
    /*
    cast to char pointer to be able to use pointer arithmetic to get individual byte increments
    */
    char* offset_ptr = (char*)ptr + i;
    if (pagedir_get_page(pd, (const void*)offset_ptr) == NULL) {
      exit(-1);
    }
  }
}
static void syscall_handler(struct intr_frame* f UNUSED) {
  /*
  first we check to see if the esp itself is valid
  */
  isValidPointer((void*)f->esp);
  uint32_t* args = ((uint32_t*)f->esp);
  int sys_val = args[0];

  /*
  ARGUMENT VALIDATION: 
  1.) check if ptrs are not NULL
  2.) check if ptrs lie in USER SPAxCE
  3.) PAGE BOUNDARY naunces

  */
  //note actually safe yet lol. real checking happens below with the pointers
  uint32_t*
      safe_args[3]; //note actually safe yet lol. real checking happens below with the pointers
  int argc = 1 + exepected_num_args(sys_val);
  int index = 1;
  safe_args[0] = (uint32_t*)args[1];
  safe_args[1] = (uint32_t*)args[2];
  safe_args[2] = (uint32_t*)args[3];
  // while (index <= argc) {
  //   if (args[index] == NULL) {
  //     exit(-1);
  //   }
  //   safe_args[index - 1] = args[index];
  //   index += 1;
  // }

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  if (isFileSys(sys_val)) {
    lock_acquire(&file_sys_lock);
    if (sys_val == SYS_WRITE) {
      isValidPointer((void*)safe_args[1]);
      f->eax = write((int)safe_args[0], (const void*)safe_args[1], (unsigned int)safe_args[2]);
    } else if (sys_val == SYS_REMOVE) {
      isValidPointer((void*)safe_args[0]);
      f->eax = remove((const char*)safe_args[0]);

    } else if (sys_val == SYS_OPEN) {
      isValidPointer((void*)safe_args[0]);
      f->eax = open((const char*)safe_args[0]);

    } else if (sys_val == SYS_FILESIZE) {

      f->eax = filesize((int)safe_args[0]);

    } else if (sys_val == SYS_CLOSE) {
      int fd = (int)safe_args[0];
      close(fd);

    } else if (sys_val == SYS_TELL) {
      int fd = (int)safe_args[0];
      f->eax = tell(fd);

    } else if (sys_val == SYS_CREATE) {
      isValidPointer((void*)safe_args[0]);

      const char* filename = (const char*)safe_args[0];
      unsigned int size = (unsigned int)safe_args[1];
      f->eax = create(filename, size);

    } else if (sys_val == SYS_SEEK) {
      int fd = (int)safe_args[0];
      unsigned int pos = (unsigned int)safe_args[1];
      seek(fd, pos);

    } else if (sys_val == SYS_READ) {
      isValidPointer((void*)safe_args[1]);
      int fd = (int)safe_args[0];
      const void* buffer = (const void*)safe_args[1];
      unsigned int size = (unsigned int)safe_args[2];
      f->eax = read(fd, buffer, size);
    }
    lock_release(&file_sys_lock);
  }

  if (sys_val == SYS_EXIT) {
    f->eax = safe_args[0];
    exit((int)safe_args[0]);
  } else if (sys_val == SYS_PRACTICE) {
    f->eax = practice((int)safe_args[0]);
  } else if (sys_val == SYS_HALT) {
    halt();
  } else if (sys_val == SYS_EXEC) {
    isValidPointer((void*)safe_args[0]);
    f->eax = exec((const char*)safe_args[0]);
  } else if (sys_val == SYS_WAIT) {
    f->eax = wait((pid_t)safe_args[0]);
  }
}
