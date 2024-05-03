#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/block.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);
struct lock free_map_lock;

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();
  lock_init(&free_map_lock);

  if (format)
    do_format();

  // free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
  evict_cache();
  free_map_close();
}
/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  /* in case where cwd has been removed already. we should not be able to create any files inisde of it*/

  struct dir* dir = get_dir_create(name);
  /* faulty file path */
  if (dir == NULL) {
    return false;
  }
  block_sector_t inode_sector;
  /* extract the actual file name */
  char file_name[15];
  get_last_part(name, &file_name);

  // lock_acquire(&free_map_lock);
  /* NOTE MIGHT NEED TO ADD LOCK FOR FREE MAP HERE!!! */
  bool success =
      (free_map_allocate(1, &inode_sector) && inode_create(inode_sector, initial_size, 0) &&
       dir_add(dir, &file_name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  /* found matching directory up to the last part */
  if (strcmp(name, "/") == 0) {
    return file_open(inode_open(ROOT_DIR_SECTOR));
  }
  if ((strcmp(name, ".") == 0 || strcmp(name, "..") == 0) && get_cwd_sector() == NULL) {
    return NULL;
  }
  // if (strcmp(name, ".") == 0) {
  //   return file_open(inode_open(get_cwd_sector()));
  // }

  struct dir* dir = get_dir_no_create(name, false);
  if (dir == NULL)
    return NULL;
  struct inode* inode = NULL;

  char file_name[15];
  get_last_part(name, &file_name);
  /* checking to make sure the file/directory we are opening is actually valid (i.e. there is a directory entry for it in dir)*/
  if (!dir_lookup(dir, &file_name, &inode)) {
    dir_close(dir);
    return NULL;
  }
  dir_close(dir);
  return file_open(inode);
}

bool is_dir_empty(struct dir* dir) {
  char name[15];
  while (dir_readdir(dir, name)) {
    if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
      return false;
    }
  }
  return true;
}
/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  /* dir is the directory that contains the file/dir we want to remove */
  struct dir* dir = get_dir_no_create(name, false);
  if (dir == NULL)
    return false;
  if (strcmp(name, "/") == 0) {
    dir_close(dir);
    return false;
  }

  //can be either file or directory!!!
  char file_name[15];
  get_last_part(name, &file_name);
  struct inode* file_inode;
  /* in the case where file/dirextory doesnt exist within dir*/
  if (!dir_lookup(dir, &file_name, &file_inode)) {
    dir_close(dir);
    return false;
  }
  struct inode_disk data;
  read_helper((void*)&data, file_inode->sector, BLOCK_SECTOR_SIZE, 0);
  if (data.is_dir) {
    struct dir* dir_to_remove = dir_open(file_inode);
    if (!is_dir_empty(dir_to_remove)) {
      dir_close(dir_to_remove);
      dir_close(dir);
      return false;
    }
    /* if we are removing the directory we are currenlty on, also set our t->pcb->cwd to NULL !*/
    if (inode_get_inumber(file_inode) == get_cwd_sector()) {
      delete_cwd();
    }
    dir_close(dir_to_remove);
  }

  bool success = dir_remove(dir, &file_name);
  dir_close(dir);
  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  // free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16, ROOT_DIR_SECTOR))
    PANIC("root directory creation failed");
  // free_map_close();
  printf("done.\n");
}