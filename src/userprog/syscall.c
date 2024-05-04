#include "userprog/syscall.h"
#include <stdio.h>
#include <float.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

#include "filesys/inode.h"
#define READDIR_MAX_LEN 14
static void syscall_handler(struct intr_frame*);
static void copy_in(void*, const void*, size_t);

/* Serializes file system operations. */
static struct lock fs_lock;

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&fs_lock);
}

/* System call handler. */
static void syscall_handler(struct intr_frame* f) {
  typedef int syscall_function(int, int, int);

  /* A system call. */
  struct syscall {
    size_t arg_cnt;         /* Number of arguments. */
    syscall_function* func; /* Implementation. */
  };

  /* Table of system calls. */
  // static const struct syscall syscall_table[] = {
  //     {0, (syscall_function*)sys_halt},      {1, (syscall_function*)sys_exit},
  //     {1, (syscall_function*)sys_exec},      {1, (syscall_function*)sys_wait},
  //     {2, (syscall_function*)sys_create},    {1, (syscall_function*)sys_remove},
  //     {1, (syscall_function*)sys_open},      {1, (syscall_function*)sys_filesize},
  //     {3, (syscall_function*)sys_read},      {3, (syscall_function*)sys_write},
  //     {2, (syscall_function*)sys_seek},      {1, (syscall_function*)sys_tell},
  //     {1, (syscall_function*)sys_close},     {1, (syscall_function*)sys_practice},
  //     {1, (syscall_function*)sys_compute_e}, {1, (syscall_function*)sys_inumber},
  //     {1, (syscall_function*)sys_chdir},     {1, (syscall_function*)sys_mkdir},
  //     {2, (syscall_function*)sys_readdir},   {1, (syscall_function*)sys_isdir},
  //     };
  /* Table of system calls. */

  static const struct syscall syscall_table[] = {
      {0, (syscall_function*)sys_halt},         {1, (syscall_function*)sys_exit},
      {1, (syscall_function*)sys_exec},         {1, (syscall_function*)sys_wait},
      {2, (syscall_function*)sys_create},       {1, (syscall_function*)sys_remove},
      {1, (syscall_function*)sys_open},         {1, (syscall_function*)sys_filesize},
      {3, (syscall_function*)sys_read},         {3, (syscall_function*)sys_write},
      {2, (syscall_function*)sys_seek},         {1, (syscall_function*)sys_tell},
      {1, (syscall_function*)sys_close},        {1, (syscall_function*)sys_practice},
      {1, (syscall_function*)sys_compute_e},    {3, (syscall_function*)sys_pthread_create},
      {0, (syscall_function*)sys_pthread_exit}, {1, (syscall_function*)sys_pthread_join},
      {1, (syscall_function*)sys_lock_init},    {1, (syscall_function*)sys_lock_acquire},
      {1, (syscall_function*)sys_lock_release}, {2, (syscall_function*)sys_sema_init},
      {1, (syscall_function*)sys_sema_down},    {1, (syscall_function*)sys_sema_up},
      {1, (syscall_function*)sys_get_tid},

      {2, (syscall_function*)sys_mmap},         {1, (syscall_function*)sys_munmap},

      {1, (syscall_function*)sys_chdir},        {1, (syscall_function*)sys_mkdir},
      {2, (syscall_function*)sys_readdir},      {1, (syscall_function*)sys_isdir},
      {1, (syscall_function*)sys_inumber},      {1, (syscall_function*)sys_bc_stats},
      {0, (syscall_function*)sys_bc_clear}};
  const struct syscall* sc;
  unsigned call_nr;
  int args[3];

  /* Get the system call. */
  copy_in(&call_nr, f->esp, sizeof call_nr);
  if (call_nr >= sizeof syscall_table / sizeof *syscall_table)
    process_exit();
  sc = syscall_table + call_nr;

  if (sc->func == NULL)
    process_exit();

  /* Get the system call arguments. */
  ASSERT(sc->arg_cnt <= sizeof args / sizeof *args);
  memset(args, 0, sizeof args);
  copy_in(args, (uint32_t*)f->esp + 1, sizeof *args * sc->arg_cnt);

  /* Execute the system call,
     and set the return value. */
  f->eax = sc->func(args[0], args[1], args[2]);
}

/* Closes a file safely */
void safe_file_close(struct file* file) {
  lock_acquire(&fs_lock);
  file_close(file);
  lock_release(&fs_lock);
}

/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool verify_user(const void* uaddr) {
  return (uaddr < PHYS_BASE && pagedir_get_page(thread_current()->pcb->pagedir, uaddr) != NULL);
}

/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool get_user(uint8_t* dst, const uint8_t* usrc) {
  int eax;
  asm("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:" : "=m"(*dst), "=&a"(eax) : "m"(*usrc));
  return eax != 0;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool put_user(uint8_t* udst, uint8_t byte) {
  int eax;
  asm("movl $1f, %%eax; movb %b2, %0; 1:" : "=m"(*udst), "=&a"(eax) : "q"(byte));
  return eax != 0;
}

/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call process_exit() if any of the user accesses are invalid. */
static void copy_in(void* dst_, const void* usrc_, size_t size) {
  uint8_t* dst = dst_;
  const uint8_t* usrc = usrc_;

  for (; size > 0; size--, dst++, usrc++)
    if (usrc >= (uint8_t*)PHYS_BASE || !get_user(dst, usrc))
      process_exit();
}

/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call process_exit() if any of the user accesses are invalid. */
static char* copy_in_string(const char* us) {
  char* ks;
  size_t length;

  ks = palloc_get_page(0);
  if (ks == NULL)
    process_exit();

  for (length = 0; length < PGSIZE; length++) {
    if (us >= (char*)PHYS_BASE || !get_user(ks + length, us++)) {
      palloc_free_page(ks);
      process_exit();
    }

    if (ks[length] == '\0')
      return ks;
  }
  ks[PGSIZE - 1] = '\0';
  return ks;
}

/* Halt system call. */
int sys_halt(void) { shutdown_power_off(); }

/* Exit system call. */
int sys_exit(int exit_code) {
  thread_current()->pcb->wait_status->exit_code = exit_code;
  process_exit();
  NOT_REACHED();
}

/* Exec system call. */
int sys_exec(const char* ufile) {
  pid_t tid;
  char* kfile = copy_in_string(ufile);

  lock_acquire(&fs_lock);
  tid = process_execute(kfile);
  lock_release(&fs_lock);

  palloc_free_page(kfile);

  return tid;
}

/* Wait system call. */
int sys_wait(pid_t child) { return process_wait(child); }

/* Create system call. */
int sys_create(const char* ufile, unsigned initial_size) {
  char* kfile = copy_in_string(ufile);
  bool ok;

  lock_acquire(&fs_lock);
  ok = filesys_create(kfile, initial_size);
  lock_release(&fs_lock);

  palloc_free_page(kfile);

  return ok;
}

/* Remove system call. */
int sys_remove(const char* ufile) {
  char* kfile = copy_in_string(ufile);
  bool ok;

  lock_acquire(&fs_lock);
  ok = filesys_remove(kfile);
  lock_release(&fs_lock);

  palloc_free_page(kfile);

  return ok;
}

/* Open system call. */
int sys_open(const char* ufile) {
  char* kfile = copy_in_string(ufile);
  struct file_descriptor* fd;
  int handle = -1;

  fd = malloc(sizeof *fd);
  if (fd != NULL) {
    lock_acquire(&fs_lock);
    fd->file = filesys_open(kfile);
    if (fd->file != NULL) {
      struct thread* cur = thread_current();
      handle = fd->handle = cur->pcb->next_handle++;
      fd->dir_pos = 0;
      list_push_front(&cur->pcb->fds, &fd->elem);
    } else
      free(fd);
    lock_release(&fs_lock);
  }

  palloc_free_page(kfile);
  return handle;
}

/* Returns the file descriptor associated with the given handle.
   Terminates the process if HANDLE is not associated with an
   open file. */
static struct file_descriptor* lookup_fd(int handle) {
  struct thread* cur = thread_current();
  struct list_elem* e;

  for (e = list_begin(&cur->pcb->fds); e != list_end(&cur->pcb->fds); e = list_next(e)) {
    struct file_descriptor* fd;
    fd = list_entry(e, struct file_descriptor, elem);
    if (fd->handle == handle)
      return fd;
  }

  process_exit();
  NOT_REACHED();
}

/* Filesize system call. */
int sys_filesize(int handle) {
  struct file_descriptor* fd = lookup_fd(handle);
  int size;

  lock_acquire(&fs_lock);
  size = file_length(fd->file);
  lock_release(&fs_lock);

  return size;
}

/* Read system call. */
int sys_read(int handle, void* udst_, unsigned size) {
  uint8_t* udst = udst_;
  struct file_descriptor* fd;
  int bytes_read = 0;

  /* Handle keyboard reads. */
  if (handle == STDIN_FILENO) {
    for (bytes_read = 0; (size_t)bytes_read < size; bytes_read++)
      if (udst >= (uint8_t*)PHYS_BASE || !put_user(udst++, input_getc()))
        process_exit();
    return bytes_read;
  }

  /* Handle all other reads. */
  fd = lookup_fd(handle);
  /* NOTE: not sure whether i should jsut return 0 or proces_exit(-1)*/
  if (sys_isdir(handle)) {
    return -1;
  }
  lock_acquire(&fs_lock);
  while (size > 0) {
    /* How much to read into this page? */
    size_t page_left = PGSIZE - pg_ofs(udst);
    size_t read_amt = size < page_left ? size : page_left;
    off_t retval;

    /* Check that touching this page is okay. */
    if (!verify_user(udst)) {
      lock_release(&fs_lock);
      process_exit();
    }

    /* Read from file into page. */
    retval = file_read(fd->file, udst, read_amt);
    if (retval < 0) {
      if (bytes_read == 0)
        bytes_read = -1;
      break;
    }
    bytes_read += retval;

    /* If it was a short read we're done. */
    if (retval != (off_t)read_amt)
      break;

    /* Advance. */
    udst += retval;
    size -= retval;
  }
  lock_release(&fs_lock);

  return bytes_read;
}

/* Write system call. */
int sys_write(int handle, void* usrc_, unsigned size) {
  uint8_t* usrc = usrc_;
  struct file_descriptor* fd = NULL;
  int bytes_written = 0;

  /* Lookup up file descriptor. */
  if (handle != STDOUT_FILENO) {
    fd = lookup_fd(handle);
    if (sys_isdir(handle)) {
      return -1;
    }
  }

  lock_acquire(&fs_lock);
  while (size > 0) {
    /* How much bytes to write to this page? */
    size_t page_left = PGSIZE - pg_ofs(usrc);
    size_t write_amt = size < page_left ? size : page_left;
    off_t retval;

    /* Check that we can touch this user page. */
    if (!verify_user(usrc)) {
      lock_release(&fs_lock);
      process_exit();
    }

    /* Do the write. */
    if (handle == STDOUT_FILENO) {
      putbuf(usrc, write_amt);
      retval = write_amt;
    } else
      retval = file_write(fd->file, usrc, write_amt);
    if (retval < 0) {
      if (bytes_written == 0)
        bytes_written = -1;
      break;
    }
    bytes_written += retval;

    /* If it was a short write we're done. */
    if (retval != (off_t)write_amt)
      break;

    /* Advance. */
    usrc += retval;
    size -= retval;
  }
  lock_release(&fs_lock);

  return bytes_written;
}

/* Seek system call. */
int sys_seek(int handle, unsigned position) {
  struct file_descriptor* fd = lookup_fd(handle);

  lock_acquire(&fs_lock);
  if ((off_t)position >= 0)
    file_seek(fd->file, position);
  lock_release(&fs_lock);

  return 0;
}

/* Tell system call. */
int sys_tell(int handle) {
  struct file_descriptor* fd = lookup_fd(handle);
  unsigned position;

  lock_acquire(&fs_lock);
  position = file_tell(fd->file);
  lock_release(&fs_lock);

  return position;
}

/* Close system call. */
int sys_close(int handle) {
  struct file_descriptor* fd = lookup_fd(handle);
  safe_file_close(fd->file);
  list_remove(&fd->elem);
  free(fd);
  return 0;
}

int sys_inumber(int fd) {
  struct file_descriptor* file_desc = lookup_fd(fd);
  if (!file_desc || !file_desc->file) {
    return -1;
  } else {
    struct inode* inode = file_get_inode(file_desc->file);
    return inode_get_inumber(inode);
  }
}

/* Practice system call. */
int sys_practice(int input) { return input + 1; }

/* Compute e and return a float cast to an int */
int sys_compute_e(int n) { return sys_sum_to_e(n); }

block_sector_t get_cwd_sector(void) {
  if (!thread_current()->pcb->cwd) {
    return NULL;
  }
  return inode_get_inumber(dir_get_inode(thread_current()->pcb->cwd));
}
void delete_cwd(void) { thread_current()->pcb->cwd = NULL; }

struct dir* get_dir_no_create(const char* dir, bool is_chdir) {
  /* ASSUMES A VALID DIR PATH IS GIVEN */
  struct dir* dir_head;
  /* if we have an absolute path */
  if (dir[0] == '/') {
    dir_head = dir_open_root();
  } else { /* else relative path!! */
    if (get_cwd_sector() == NULL) {
      return NULL;
    }
    dir_head = dir_open(inode_open(inode_get_inumber(dir_get_inode(thread_current()->pcb->cwd))));
  }

  if (strcmp(dir, "/") == 0) {
    return dir_head;
  }
  char buf[15];
  memset(&buf, 0, 15);
  int ret;
  const char** src = &dir;
  struct dir* prev_dir = NULL;
  struct inode* next;

  while (1) {
    ret = get_next_part(buf, src);
    /* too long of a filename part */
    if (ret == -1) {
      dir_close(dir_head);
      return NULL;
    }
    /* end of dir path */
    if (ret == 0) {
      /* in the case where we are cd'ing into a directory, we want to cd into the last part of the path.*/
      if (is_chdir) {
        dir_close(prev_dir);
        return dir_head;
      }
      /* case where we want the directory right before the last part. this is the case with fileopen, fileremove */
      dir_close(dir_head);
      return prev_dir;
    }
    if (prev_dir) {
      dir_close(prev_dir);
    }
    /* in the case where we have a faulty path */
    if (!dir_lookup(dir_head, &buf, &next)) {
      dir_close(dir_head);
      return NULL;
    }
    prev_dir = dir_head;
    dir_head = dir_open(next);
    memset(&buf, 0, 15);
  }
}
struct dir* get_dir_create(const char* dir) {

  struct dir* dir_head;
  /* if we have an absolute path */
  if (dir[0] == '/') {
    dir_head = dir_open_root();
  } else { /* else relative path!! */

    if (get_cwd_sector() == NULL) {
      return NULL;
    }
    dir_head = dir_open(inode_open(inode_get_inumber(dir_get_inode(thread_current()->pcb->cwd))));
  }

  char buf[15];
  memset(&buf, 0, 15);
  int ret;
  const char** src = &dir;
  struct dir* temp_dir = NULL;
  struct inode* next;
  while (1) {
    ret = get_next_part(buf, src);
    /* too long of a filename part */
    if (ret == -1) {
      dir_close(dir_head);
      return NULL;
    }
    /* end of dir path means that the file/dir already exists! */
    if (ret == 0) {
      dir_close(dir_head);
      return NULL;
    }
    /* in the case where we have a faulty path OR in the case of last part for mkdir/filesyscreate*/
    if (!dir_lookup(dir_head, &buf, &next)) {
      /* invalid path */
      if (get_next_part(buf, src) != 0) {
        dir_close(dir_head);
        return NULL;
      }
      return dir_head;
    }
    temp_dir = dir_head;
    dir_head = dir_open(next);
    dir_close(temp_dir);
    memset(&buf, 0, 15);
  }
}

void get_last_part(char* name, char* res) {
  char buf[15];
  memset(&buf, 0, 15);
  int ret;
  const char** src = &name;
  int len = 0;
  while (ret = get_next_part(buf, src)) {
    len = strlen(&buf);
    memcpy(res, &buf, len);
    memset(&buf, 0, 15);
  }
  res[len] = '\0';
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
int get_next_part(char part[READDIR_MAX_LEN + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + READDIR_MAX_LEN)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}
bool sys_chdir(const char* dir) {
  if (!dir || strlen(dir) == 0) {
    return false;
  }
  struct dir* cwd = get_dir_no_create(dir, true);
  if (cwd == NULL) {
    return false;
  }
  //close the cwd as we will not be needing it anymore
  dir_close(thread_current()->pcb->cwd);
  /* update the cwd */
  thread_current()->pcb->cwd = cwd;
  return true;
}
bool sys_mkdir(const char* dir) {
  if (!dir || strlen(dir) == 0) {
    return false;
  }
  struct dir* d = get_dir_create(dir);
  if (d == NULL) {
    return false;
  }
  uint32_t sector;
  if (!free_map_allocate(1, &sector)) {
    dir_close(d);
    return false;
  }
  if (!dir_create(sector, 16, inode_get_inumber(dir_get_inode(d)))) {
    dir_close(d);
    free_map_release(sector, 1);
    return false;
  }

  char dir_name[15];
  get_last_part(dir, &dir_name);
  /* add dir entry for the newly created directory */
  if (!dir_add(d, &dir_name, sector)) {
    dir_close(d);
    free_map_release(sector, 1);
    return false;
  }
  dir_close(d);
  return true;
}
bool sys_readdir(int fd, char* name) {
  if (!sys_isdir(fd)) {
    return false;
  }
  struct file_descriptor* file_metadata = lookup_fd(fd);
  struct dir* dir = dir_open(inode_open(inode_get_inumber(file_get_inode(file_metadata->file))));
  if (dir == NULL)
    return false;
  bool found = false;
  dir_update_pos(dir, file_metadata->dir_pos);
  while (dir_readdir(dir, name)) {
    if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
      found = true;
      break;
    }
  }

  file_metadata->dir_pos = dir_get_pos(dir);
  dir_close(dir);
  return found;
}

bool sys_isdir(int fd) {
  struct file_descriptor* file_metadata = lookup_fd(fd);
  struct inode_disk data;
  read_helper(&data, inode_get_inumber(file_get_inode(file_metadata->file)), BLOCK_SECTOR_SIZE, 0);
  return data.is_dir;
}

tid_t sys_pthread_create(stub_fun sfun, pthread_fun tfun, const void* arg) {
  return pthread_execute(sfun, tfun, arg);
}

void sys_pthread_exit(void) { pthread_exit(); }

tid_t sys_pthread_join(tid_t tid) {}

bool sys_lock_init(char* lock) {
  lock_acquire(&fs_lock);
  // bool verified = verify_user(lock);
  lock_release(&fs_lock);
  // if (!verified) {
  //   return false;
  // }
  // if (lock == NULL) {
  //   return false;
  // }
  // struct lock_metadata* new_lock = malloc(sizeof(struct lock_metadata));
  // if (new_lock == NULL) {
  //   return false;
  // }
  // // struct lock kernel_lock;

  // struct lock* kernel_lock = malloc(sizeof(struct lock));
  // if (kernel_lock == NULL) {
  //   free(new_lock);
  //   return false;
  // }
  // new_lock->id = lock;
  // lock_init(kernel_lock);
  // new_lock->kernel_lock = kernel_lock;
  // lock_acquire(&thread_current()->pcb->lock_for_lock_list);
  // list_push_back(&thread_current()->pcb->lock_list, &new_lock->elem);
  // lock_release(&thread_current()->pcb->lock_for_lock_list);
  // return true;
  return true;
}

struct lock_metadata* get_lock_metadata(char* lock) {
  //   lock_acquire(&thread_current()->pcb->lock_for_lock_list);
  //   struct list_elem* e;
  //   struct list* lock_list = &thread_current()->pcb->lock_list;
  //   struct lock_metadata* res = NULL;
  //   for (e = list_begin(lock_list); e != list_end(lock_list); e = list_next(e)) {
  //     struct lock_metadata* l = list_entry(e, struct lock_metadata, elem);
  //     if (l->id == lock) {
  //       res = l;
  //       break;
  //     }
  //   }
  //   lock_release(&thread_current()->pcb->lock_for_lock_list);
  //   return res;
  // }
}
bool sys_lock_acquire(char* lock) {
  //   struct lock_metadata* l = get_lock_metadata(lock);
  //   if (l == NULL) {
  //     return false;
  //   }
  //   //can't acquire the same lock twice with the same thread.
  //   if (l->kernel_lock->holder && l->kernel_lock->holder->tid == thread_current()->tid) {
  //     return false;
  //   }
  //   lock_acquire(l->kernel_lock);
  return true;
}

bool sys_lock_release(char* lock) {
  // struct lock_metadata* l = get_lock_metadata(lock);
  // if (l == NULL) {
  //   return false;
  // }
  // //can't release lock not held by this thread...
  // if (!l->kernel_lock->holder || l->kernel_lock->holder->tid != thread_current()->tid) {
  //   return false;
  // }
  // lock_release(l->kernel_lock);
  return true;
}

bool sys_sema_init(char* sema, int val) {
  lock_acquire(&fs_lock);
  // bool verified = verify_user(sema);
  lock_release(&fs_lock);
  // if (!verified) {
  //   return false;
  // }
  // if (val < 0) {
  //   return false;
  // }
  // struct sema_metadata* new_sema = malloc(sizeof(struct sema_metadata));
  // if (new_sema == NULL) {
  //   return false;
  // }
  // new_sema->id = sema;

  // struct semaphore* kernel_sema = malloc(sizeof(struct semaphore));
  // if (kernel_sema == NULL) {
  //   free(new_sema);
  //   return false;
  // }
  // sema_init(kernel_sema, val);
  // new_sema->kernel_sema = kernel_sema;
  // lock_acquire(&thread_current()->pcb->lock_for_sema_list);
  // list_push_back(&thread_current()->pcb->sema_list, &new_sema->elem);
  // lock_release(&thread_current()->pcb->lock_for_sema_list);
  return true;
}
struct sema_metadata* get_sema_metadata(char* sema) {
  // lock_acquire(&thread_current()->pcb->lock_for_sema_list);
  // struct list_elem* e;
  // struct list* sema_list = &thread_current()->pcb->sema_list;
  // struct sema_metadata* res = NULL;
  // for (e = list_begin(sema_list); e != list_end(sema_list); e = list_next(e)) {
  //   struct sema_metadata* s = list_entry(e, struct sema_metadata, elem);
  //   if (s->id == sema) {
  //     res = s;
  //     break;
  //   }
  // }
  // lock_release(&thread_current()->pcb->lock_for_sema_list);
  // return res;
}
bool sys_sema_down(char* sema) {
  lock_acquire(&fs_lock);
  // bool verified = verify_user(sema);
  lock_release(&fs_lock);
  // if (!verified) {
  //   return false;
  // }
  // struct sema_metadata* s = get_sema_metadata(sema);
  // if (s == NULL) {
  //   return false;
  // }
  // sema_down(s->kernel_sema);
  return true;
}

bool sys_sema_up(char* sema) {
  lock_acquire(&fs_lock);
  // bool verified = verify_user(sema);
  lock_release(&fs_lock);
  // if (!verified) {
  //   return false;
  // }
  // struct sema_metadata* s = get_sema_metadata(sema);
  // if (s == NULL) {
  //   return false;
  // }
  // sema_up(s->kernel_sema);
  return true;
}
tid_t sys_get_tid(void) { return thread_current()->tid; }

mapid_t sys_mmap(int fd, void* addr) {}
void sys_munmap(mapid_t) {}

int sys_bc_stats(int sel) {
  if (sel == 0) {
    return get_cache_misses();
  } else if (sel == 1) {
    return get_cache_hits();
  } else if (sel == 2) {
    return get_write_cnt();
  }
}

void sys_bc_clear() { evict_cache(); }
