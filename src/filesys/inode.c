#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define NUM_DIRECT 12
#define NUM_POINTER 128

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  off_t length;   /* File size in bytes. */
  unsigned magic; /* Magic number. */
  block_sector_t direct[12];
  block_sector_t doubly_indirect;
  uint32_t permissions;
  uint32_t num_links;
  int is_dir;
  uint32_t unused[110]; /* Not used. */
};

int max_inumber;

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem; /* Element in inode list. */
  block_sector_t sector; /* Sector number of disk location. */
  int open_cnt;          /* Number of openers. */
  bool removed;          /* True if deleted, false otherwise. */
  int deny_write_cnt;    /* 0: writes ok, >0: deny writes. */
  //struct inode_disk data; /* Inode content. */
};

/* Returns the physical block sector number of sequential index i in the inode
   by performing pointer tree traversal. */
static block_sector_t sector_of_index(struct inode* inode, int sector_index) {
  block_sector_t sector;
  struct inode_disk inode_block;
  block_read(fs_device, inode->sector, &inode_block);
  //read_helper(&inode_block, inode->sector, BLOCK_SECTOR_SIZE, 0);
  if (sector_index < NUM_DIRECT) {
    // Return direct pointer
    return inode_block.direct[sector_index];
    //read_helper(sector, &inode_block->direct[sector_index], BLOCK_SECTOR_SIZE, 0);
  } else {
    // Traverse doubly indirect pointer
    sector_index = sector_index - NUM_DIRECT;
    block_sector_t doubly_indirect[NUM_POINTER];
    block_sector_t singly_indirect[NUM_POINTER];
    block_read(fs_device, &inode_block.doubly_indirect, &doubly_indirect);
    block_read(fs_device, doubly_indirect[sector_index / NUM_POINTER], &singly_indirect);
    return singly_indirect[sector_index % NUM_POINTER];
    //read_helper(doubly_indirect, &inode_block->doubly_indirect, BLOCK_SECTOR_SIZE, 0);
    //read_helper(singly_indirect, doubly_indirect[sector_index / NUM_POINTER], BLOCK_SECTOR_SIZE, 0);
    //read_helper(sector, singly_indirect[sector_index % NUM_POINTER], BLOCK_SECTOR_SIZE, 0);
  }
  return sector;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  if (pos < inode_length(inode)) {
    return sector_of_index(inode, pos / BLOCK_SECTOR_SIZE);
  } else {
    return -1;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = (struct inode_disk*)calloc(1, sizeof *disk_inode);
  disk_inode->length = 0;
  disk_inode->magic = INODE_MAGIC;

  success = inode_resize(disk_inode, length);

  block_write(fs_device, sector, disk_inode);
  //write_helper(disk_inode, sector, BLOCK_SECTOR_SIZE, 0);

  free(disk_inode);

  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    struct inode_disk inode_block;
    block_read(fs_device, inode->sector, &inode_block);
    //read_helper(inode_block, inode->sector, BLOCK_SECTOR_SIZE, 0);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      inode_resize(&inode_block, 0);
      free_map_release(inode->sector, 1);
    }
    // if (inode->removed) {
    //   free_map_release(inode->sector, 1);
    //   free_map_release(inode_block.start, bytes_to_sectors(inode_block.length));
    // }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read(fs_device, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

  return bytes_read;
}

int free_singly_indirect_buffer(struct inode* inode, block_sector_t b) { return 0; }

/* Extends or shrinks inode by allocating or freeing pointers as neccesary.
   Inspiration from discussion 9. Returns 1 if success and 0 otherwise. */
int inode_resize(struct inode_disk* inode, off_t final_size) {

  // TODO: Need to implement roll back, failure likely due to free_map_allocate.
  //struct inode_disk* inode_block;
  //block_read(fs_device, inode->sector, inode_block);
  //read_helper(inode_block, inode->sector, BLOCK_SECTOR_SIZE, 0);

  block_sector_t zero_block = calloc(NUM_POINTER, sizeof(block_sector_t));
  /* Handle direct pointers */
  for (int i = 0; i < NUM_DIRECT; i++) {
    if (final_size <= BLOCK_SECTOR_SIZE * i && inode->direct[i] != 0) {
      /* Shrink */
      free_map_release(inode->direct[i], 1);
      inode->direct[i] = 0;
    } else if (final_size > BLOCK_SECTOR_SIZE * i && inode->direct[i] == 0) {
      /* Grow */
      free_map_allocate(1, &inode->direct[i]);
      block_write(fs_device, inode->direct[i], zero_block);
      //write_helper
    }
  }

  /* Allocate doubly indirect as needed */
  if (inode->doubly_indirect == 0 && final_size <= BLOCK_SECTOR_SIZE * NUM_DIRECT) {
    inode->length = final_size; // do not change length in resize function
    return 1;
  }

  /* We need to modify the doubly indirect block, 
     so prepare buffer to allocate or load it. */
  block_sector_t* doubly_indirect_buffer = calloc(NUM_POINTER, sizeof(block_sector_t));
  if (inode->doubly_indirect == 0) {
    free_map_allocate(1, &inode->doubly_indirect);
  } else {
    block_read(fs_device, inode->doubly_indirect, doubly_indirect_buffer);
    //read_helper
  }

  /* Iterate through the pointers in the doubly indirect block. */
  for (int i = 0; i < NUM_POINTER; i++) {
    block_sector_t* singly_indirect_buffer = calloc(NUM_POINTER, sizeof(block_sector_t));
    if (doubly_indirect_buffer[i] != 0 && final_size > (12 + i * NUM_POINTER) * BLOCK_SECTOR_SIZE) {
      // if allocated and new size is greater, then read into buffer
      block_read(fs_device, doubly_indirect_buffer[i], singly_indirect_buffer);
      //read_helper
    } else if (doubly_indirect_buffer[i] != 0 &&
               final_size <= (12 + i * NUM_POINTER) * BLOCK_SECTOR_SIZE) {
      // if allocated and new size is smaller, still read in but free in following for loop
      block_read(fs_device, doubly_indirect_buffer[i], singly_indirect_buffer);
      //read_helper
    } else if (doubly_indirect_buffer[i] == 0 &&
               final_size > (12 + i * NUM_POINTER) * BLOCK_SECTOR_SIZE) {
      // if unallocated and new size is greater, then allocate block
      free_map_allocate(1, &doubly_indirect_buffer[i]);
    } else if (doubly_indirect_buffer[i] == 0 &&
               final_size <= (12 + i * NUM_POINTER) * BLOCK_SECTOR_SIZE) {
      // if unallocated and new size is smaller, then break from loop
      break;
    }

    /* Process the singly indirect block. */
    for (int j = 0; j < NUM_POINTER; j++) {
      if (singly_indirect_buffer[j] != 0 &&
          final_size <= (12 + i * NUM_POINTER + j) * BLOCK_SECTOR_SIZE) {
        /* Shrink */
        free_map_release(singly_indirect_buffer[j], 1);
        singly_indirect_buffer[j] = 0;
      } else if (singly_indirect_buffer[j] == 0 &&
                 final_size > (12 + i * NUM_POINTER + j) * BLOCK_SECTOR_SIZE) {
        /* Grow */
        free_map_allocate(1, &singly_indirect_buffer[j]);
        block_write(fs_device, singly_indirect_buffer[j], zero_block);
      }
    }

    /* If size does not reach the current singly indirect block, 
       then free the current singly indirect block. */
    if (final_size <= (12 + i * NUM_POINTER) * BLOCK_SECTOR_SIZE) {
      free_map_release(doubly_indirect_buffer[i], 1);
      doubly_indirect_buffer[i] = 0;
    } else {
      block_write(fs_device, doubly_indirect_buffer[i], singly_indirect_buffer);
      free(singly_indirect_buffer);
    }
  }

  /* If size does not require a doubly indirect pointer, then remove it. */
  if (final_size <= 12 * BLOCK_SECTOR_SIZE) {
    free_map_release(inode->doubly_indirect, 1);
    inode->doubly_indirect = 0;
  } else {
    block_write(fs_device, inode->doubly_indirect, doubly_indirect_buffer);
  }
  free(doubly_indirect_buffer);
  free(zero_block);
  inode->length = final_size; // do not change length in resize function

  return 1;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  // Allocate / dellocate blocks as necessary
  struct inode_disk inode_block;
  block_read(fs_device, inode->sector, &inode_block);
  //read_helper(inode_block, inode->sector, BLOCK_SECTOR_SIZE, 0);
  if (inode_block.length < size + offset) {
    int success = inode_resize(&inode_block, size + offset);
  }

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    block_write(fs_device, sector_idx, buffer_);
    //write_helper(buffer_, sector_idx, size, offset);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }

  free(bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) {
  struct inode_disk inode_block;
  block_read(fs_device, inode->sector, &inode_block);
  //read_helper(inode_block, inode->sector, BLOCK_SECTOR_SIZE, 0);
  return inode_block.length;
}
