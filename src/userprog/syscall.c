#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>

#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

//allows us to use file_info struct
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

static void syscall_handler(struct intr_frame*);

struct lock file_sys_lock;

void syscall_init(void) {
  lock_init(&file_sys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

int practice(int i) { return i + 1; }

// void halt(void) { return; }

/*
IMPORTANT: need to check up on exit. not sure if f-eax matters in certain cases
*/
// void exit(int status) {
//   //destroy_table()
//   printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
//   process_exit();
// }

pid_t exec(const char* file) {
  /*
  structure: 

  1.) add metadata node to childrens list
  2.) run process execute
  */
  struct list* c_list = t->pcb->children_list;
  struct process_metadata* metadata = malloc(sizeof(process_metadata));
  sema_init(&(metadata->sema));
  metadata->ref_cnt = 2;
  metadata->waiting = false;
  metadata->load_successful = false;
  lock_init(&(metadata->metadata_lock));
  list_push_back(c_list, &info->elem);
  tid_t child_id = process_execute(file, metadata);
  metadata->child_id = child_id;
  sema_down(&(metadata->sema)); //waits for child to get to loading
  if (!metadata->load_successful) {
    free(metadata);
    exit(-1);
  }
  return child_id;
}

// int wait(pid_t pid) { return 0; }

// bool create(const char* file, unsigned initial_size) { return filesys_create(file, initial_size); }

// bool remove(const char* file) { return filesys_remove(file); }

// int open(const char* filename) {
//   struct file* file = filesys_open(filename);
//   if (file == NULL) { //failed to open file
//     return -1;
//   }
//   struct file_info* info = malloc(sizeof(struct file_info));
//   if (info == NULL) {
//     perror("malloc failed while creating file_info struct");
//     return -1;
//   }
//   info->file = file;
//   /*
//   IMPORTANT: for later, might need to change implementation FOR LOCKING. for now, we assume fine since we use global lock for all file syscalls
//   */
//   info->fd = thread_current()->pcb->fd_counter;
//   thread_current()->pcb->fd_counter += 1;

//   struct list* fd_list = thread_current()->pcb->file_list;
//   list_push_back(fd_list, &info->elem);
//   return info->fd;
// }

// int filesize(int fd) {
//   struct file_info* info = getInfo(fd);
//   if (info == NULL) {
//     perror("no matching fd");
//     return -1;
//   }
//   return info->file->inode.inode_disk.length;
// }

// /*

// IMPORTANT:

// need to fix the below read() function. not sure if this is correct imlpementation since input_getc() just waits for input

// */
// int read(int fd, void* buffer, unsigned size) {
//   if (fd == 0) { //READING FROM STDIN
//     int cnt = 0;
//     while (cnt != size) {
//       char c = (char)input_getc();
//       buffer[cnt] = c;
//       cnt += 1;
//     }
//     return cnt;

//   } else {
//     struct info_file* info = getInfo(fd);
//     if (info == NULL) {
//       perror("no matching fd");
//       return -1;
//     }

//     return file_read(info->file, buffer, size);
//   }
// }

// struct file_info* getInfo(int fd) {
//   struct list* fd_list = thread_current()->pcb->file_list;
//   struct list_elem* ptr;
//   for (ptr = list_begin(fd_list); ptr != list_end(fd_list); ptr = list_next(ptr)) {
//     struct file_info* info = list_entry(ptr, struct file_info, elem);
//     if (info->fd == fd) {
//       return info;
//     }
//   }
//   return NULL;
// }

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
  }
  return -1;
}

//   } else {
//     struct file_info* info = getInfo(fd);
//     if (info == NULL) {
//       // perror("no matching fd");
//       return -1;
//     }
//     struct file* file = info->file;
//     if (file == NULL) {
//       return -1;
//     }
//     off_t written = file_write(file, buffer, size);
//     return written;
//   }
//   return -1;
// }

// void seek(int fd, unsigned position) {
//   struct file_info* info = getInfo(fd);
//   if (info != NULL) {
//     file_seek(info->file, position);
//   }
// }

// unsigned tell(int fd) {
//   struct file_info* info = getInfo(fd);
//   if (info == NULL) {
//     perror("fd not found");
//     exit(-1);
//   }
//   return file_tell(info->file);
// }
bool isFileSys(int sys_val) {
  return (sys_val == SYS_WRITE || sys_val == SYS_READ || sys_val == SYS_OPEN ||
          sys_val == SYS_FILESIZE || sys_val == SYS_TELL || sys_val == SYS_CLOSE ||
          sys_val == SYS_CREATE || sys_val == SYS_SEEK);
}
bool isValidSys(int sys_val) {
  return (sys_val == SYS_WRITE || sys_val == SYS_READ || sys_val == SYS_OPEN ||
          sys_val == SYS_FILESIZE || sys_val == SYS_TELL || sys_val == SYS_CLOSE ||
          sys_val == SYS_CREATE || sys_val == SYS_SEEK || sys_val == SYS_HALT ||
          sys_val == SYS_EXIT || sys_val == SYS_EXEC || sys_val == SYS_WAIT ||
          sys_val == SYS_PRACTICE || sys_val == SYS_COMPUTE_E || sys_val == SYS_PT_CREATE ||
          sys_val == SYS_PT_EXIT || sys_val == SYS_PT_JOIN || sys_val == SYS_LOCK_ACQUIRE ||
          sys_val == SYS_LOCK_INIT || sys_val == SYS_PT_JOIN || sys_val == SYS_LOCK_RELEASE ||
          sys_val == SYS_SEMA_DOWN || sys_val == SYS_SEMA_UP || sys_val == SYS_GET_TID ||
          sys_val == SYS_MMAP || sys_val == SYS_MUNMAP || sys_val == SYS_CHDIR ||
          sys_val == SYS_MKDIR || sys_val == SYS_READDIR || sys_val == SYS_ISDIR ||
          sys_val == SYS_INUMBER);
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

// void close(int fd) {
//   struct file_info* info = getInfo(fd);
//   if (info == NULL) {
//     perror("no matching fd");
//     exit(-1);
//   }
//   file_close(info->file);
//   list_remove(&(info->elem)); // removes fd from list
//   free(info);
// }
// void destroy_table(void) {
//   struct list* fd_list = thread_current()->pcb->file_list;
//   while (!list_empty(fd_list)) {
//     struct list_elem* ptr = list_back(fd_list);
//     struct file_info* info = list_entry(ptr, struct file_info, elem);
//     close(info->fd);
//   }
//   free(fd_list); // free the entire list at the end
// }
static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  /*
  first we make sure the syscall number is actually valid. i dont think this is actally necessary but will have to double check. 
  */
  if (!isValidSys(args[0])) {
    /*
    TODO: figure out how to gracefully handle invalid arg
    */
  }
  int sys_val = args[0];

  /*
  ARGUMENT VALIDATION: 
  1.) check if ptrs are not NULL
  2.) check if ptrs lie in USER SPACE
  3.) PAGE BOUNDARY naunces

  */
  //idea is to iterate until we hit a NULL value since we know it MUST BE here. we know we reach a premature NULL if argc != exepected num args for that sys call
  uint32_t* pd = active_pd();
  uint32_t* safe_args[3];
  int argc = exepected_num_args(sys_val);
  safe_args[0] = args[1];
  safe_args[1] = args[2];
  safe_args[2] = args[3];
  int index = 1;
  // while (index <= argc && args[index] != NULL) {
  //   //need to fix: for now just putting this here to check on valid args
  //   safe_args[index - 1] = args[index];
  //   if (is_user_vaddr((const void *) args[index]) && pagedir_get_page(pd, (const void *) args[index]) != NULL) {
  //     index += 1;
  //   } else {
  //     index += 1;
  //      /*
  //     TODO: figure out how to gracefully handle invalid arg
  //     */
  //   }
  // }
  if (exepected_num_args(sys_val) != index - 1) {
    /*
    TODO: figure out how to gracefully handle invalid arg
    this can be caused in a case where say write takes 3 args but only 2 are given. 
    */
  }
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
      f->eax = write((int)safe_args[0], (const void*)safe_args[1], (unsigned int)safe_args[2]);
    }
    // } else if (sys_val == SYS_REMOVE) {
    //   const char* filename = (const char*) args[1];
    //   f->eax = remove(filename);

    // } else if (sys_val == SYS_OPEN) {
    //   const char* filename = (const char*) args[1];
    //   f->eax = open(filename);

    // } else if (sys_val == SYS_FILESIZE) {
    //   int fd = args[1];
    //   f->eax = filesize(fd);

    // } else if (sys_val == SYS_CLOSE) {
    //   int fd = args[1];
    //   close(fd);

    // } else if (sys_val == SYS_TELL) {
    //   int fd = args[1];
    //   f->eax = tell(fd);

    // } else if (sys_val == SYS_CREATE) {
    //   const char* filename = (const char*) args[1];
    //   unsigned int size = args[2];
    //   f->eax = create(filename, size);

    // } else if (sys_val == SYS_SEEK) {
    //   int fd = args[1];
    //   unsigned int pos = args[2];
    //   seek(fd, pos);

    // } else if (sys_val == SYS_READ) {
    //   int fd = args[1];
    //   const void* buffer = (const void*)args[2];
    //   unsigned int size = args[3];
    //   f->eax = read(fd, buffer, size);
    //   //aqiure lcok
    // }
    lock_release(&file_sys_lock);
  }

  if (sys_val == SYS_EXIT) {
    // destroy_table();
    f->eax = safe_args[0];
    // exit((int) safe_args[1]);
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, (int)safe_args[0]);
    process_exit();
  } else if (sys_val == SYS_PRACTICE) {
    f->eax = practice((int)safe_args[0]);
  }
}
