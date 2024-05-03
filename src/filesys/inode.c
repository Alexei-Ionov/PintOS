#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

#include "threads/synch.h"
/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define NUM_DIRECT 12
#define NUM_POINTER 128
#define FREE 0
int max_inumber;
static struct lock write_lock;

struct cache_metadata cache[64];
// global cache lock - obtain when reading/writing to cache
struct lock cache_lock;
int clock_pointer;
int cache_hits;
int cache_misses;

/* Returns the number of sectors to allofcate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* Returns the physical block sector number of sequential index i in the inode
   by performing pointer tree traversal. */
static block_sector_t sector_of_index(struct inode* inode, int sector_index) {
  block_sector_t sector;
  struct inode_disk inode_block;
  // block_read(fs_device, inode->sector, &inode_block);
  read_helper(&inode_block, inode->sector, BLOCK_SECTOR_SIZE, 0);
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
    // block_read(fs_device, inode_block.doubly_indirect, &doubly_indirect);
    // block_read(fs_device, doubly_indirect[sector_index / NUM_POINTER], &singly_indirect);
    read_helper(&doubly_indirect, inode_block.doubly_indirect, BLOCK_SECTOR_SIZE, 0);
    read_helper(&singly_indirect, doubly_indirect[sector_index / NUM_POINTER], BLOCK_SECTOR_SIZE,
                0);
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
void inode_init(void) {
  list_init(&open_inodes);
  lock_init(&write_lock);
  lock_init(&cache_lock);
  init_cache();
}

void init_cache(void) {
  clock_pointer = 0;
  cache_hits = 0;
  cache_misses = 0;
  for (int i = 0; i < 64; i++) {
    cache[i].valid = 0;
    cache[i].dirty = 0;
    cache[i].use = 0;
    lock_init(&(cache[i].cache_index_lock));
  }
}
/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, int is_dir) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = (struct inode_disk*)calloc(1, sizeof *disk_inode);
  if (disk_inode == NULL)
    return false;
  disk_inode->length = 0;
  disk_inode->magic = INODE_MAGIC;
  disk_inode->is_dir = is_dir;
  // for (int i = 0; i < NUM_DIRECT; i++) {
  //   disk_inode->direct[i] = FREE;
  // }
  success = inode_resize(disk_inode, length);
  if (!success)
    return false;
  // block_write(fs_device, sector, disk_inode);
  write_helper(disk_inode, sector, BLOCK_SECTOR_SIZE, 0);
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
    // block_read(fs_device, inode->sector, &inode_block);
    read_helper(&inode_block, inode->sector, BLOCK_SECTOR_SIZE, 0);
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

// clock algorithm
// 1) check current. if 0, use.
// 2) if 1, update to 0, then next.
void update_clock(void) {
  while (1) {
    // printf("inf looping");
    if (cache[clock_pointer].use == 0) {
      return;
    }
    cache[clock_pointer].use = 0;
    clock_pointer = (clock_pointer + 1) % 64;
  }
}

// push everything in cache to buffer
void evict_cache(void) {
  for (int i = 0; i < 64; i++) {
    if (cache[i].valid && cache[i].dirty) {
      block_write(fs_device, cache[i].sector_index, cache[i].data);
    }
  }
}

/* 
Overlap of global lock and index lock happens when we are evicting an index because we need to update the metadata before releasing the 
global lock. We need to tell the other threads "hey! we are going to bring this value in in the future, so just wait on us to bring it in". 
We release the global lock only after we acquire the index lock of the replaced page. 
  |-------------------------------------> time
          |______| <- index lock time
    |_______| <- global lock time
          |_| <- overlap is where we update our metadata. we update saying "this WILL come". then we release the global lock so we aren't blocking
*/
void read_helper(void* buffer, block_sector_t sector_idx, size_t size, int offset) {
  // instead of calling block_read, we call this function, which checks our cache to see if we have sector_idx in our cache.
  // if it's in our cache, we just read it into buffer, else we bring in the sector index into the cache and bring it from the cache then.
  lock_acquire(&cache_lock);
  for (int i = 0; i < 64; i++) {
    // if we have found the sector index, then we memcpy and set use bit to 1
    if (cache[i].sector_index == sector_idx) {
      lock_acquire(&cache[i].cache_index_lock);
      cache[i].use = 1; // page has been used recently
      cache_hits++;
      lock_release(&cache_lock);
      memcpy(buffer, cache[i].data + offset, size);
      lock_release(&cache[i].cache_index_lock);
      return;
    }
  }
  cache_misses++;
  // we did NOT hit in our cache, so we use clock and find next page
  update_clock();
  struct cache_metadata* cur_cache = &cache[clock_pointer];
  // acquire the lock of the valid index
  lock_acquire(&cur_cache->cache_index_lock); // release data after updates
  cur_cache->old_sector_index = cur_cache->sector_index;
  // update metadata
  cur_cache->sector_index = sector_idx;
  cur_cache->valid = 1;
  cur_cache->use = 1;
  clock_pointer = (clock_pointer + 1) % 64;
  lock_release(&cache_lock); // release cache global lock here, before you edit the actual data.
  if (cur_cache->dirty) {
    block_write(fs_device, cur_cache->old_sector_index, cur_cache->data);
    cur_cache->dirty = 0;
  }
  block_read(fs_device, sector_idx, cur_cache->data); // read in the sector into this place in cache
  memcpy(buffer, cur_cache->data + offset, size);
  lock_release(&cur_cache->cache_index_lock); // release data after updates
  return;
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
      // block_read(fs_device, sector_idx, buffer + bytes_read);
      read_helper(buffer + bytes_read, sector_idx, BLOCK_SECTOR_SIZE, 0);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      // if (bounce == NULL) {
      //   bounce = malloc(BLOCK_SECTOR_SIZE);
      //   if (bounce == NULL)
      //     break;
      // }
      // block_read(fs_device, sector_idx, bounce);
      // memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
      read_helper(buffer + bytes_read, sector_idx, chunk_size, sector_ofs);
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
  // lock_acquire(&write_lock);
  block_sector_t zero_block = calloc(NUM_POINTER, sizeof(block_sector_t));
  /* Handle direct pointers */
  for (int i = 0; i < NUM_DIRECT; i++) {
    if ((final_size <= (BLOCK_SECTOR_SIZE * i)) && inode->direct[i] != FREE) {
      /* Shrink */
      free_map_release(inode->direct[i], 1);
      inode->direct[i] = FREE;
    } else if ((final_size > (BLOCK_SECTOR_SIZE * i)) && inode->direct[i] == FREE) {
      /* Grow */
      free_map_allocate(1, &inode->direct[i]);
      //write_helper
    }
  }

  /* Allocate doubly indirect as needed */
  if (inode->doubly_indirect == 0 && final_size <= BLOCK_SECTOR_SIZE * NUM_DIRECT) {
    inode->length = final_size; // do not change length in resize function
    // lock_release(&write_lock);
    return 1;
  }

  /* We need to modify the doubly indirect block, 
     so prepare buffer to allocate or load it. */
  block_sector_t* doubly_indirect_buffer = calloc(NUM_POINTER, sizeof(block_sector_t));
  if (inode->doubly_indirect == 0) {
    free_map_allocate(1, &inode->doubly_indirect);
  } else {
    // block_read(fs_device, inode->doubly_indirect, doubly_indirect_buffer);
    read_helper(doubly_indirect_buffer, inode->doubly_indirect,
                NUM_POINTER * sizeof(block_sector_t), 0);
    //read_helper
  }

  /* Iterate through the pointers in the doubly indirect block. */
  for (int i = 0; i < NUM_POINTER; i++) {
    block_sector_t* singly_indirect_buffer = calloc(NUM_POINTER, sizeof(block_sector_t));
    if (doubly_indirect_buffer[i] != 0 && final_size > (12 + i * NUM_POINTER) * BLOCK_SECTOR_SIZE) {
      // if allocated and new size is greater, then read into buffer
      // block_read(fs_device, doubly_indirect_buffer[i], singly_indirect_buffer);
      read_helper(singly_indirect_buffer, doubly_indirect_buffer[i],
                  sizeof(block_sector_t) * NUM_POINTER, 0);
      //read_helper
    } else if (doubly_indirect_buffer[i] != 0 &&
               final_size <= (12 + i * NUM_POINTER) * BLOCK_SECTOR_SIZE) {
      // if allocated and new size is smaller, still read in but free in following for loop
      // block_read(fs_device, doubly_indirect_buffer[i], singly_indirect_buffer);
      read_helper(singly_indirect_buffer, doubly_indirect_buffer[i],
                  sizeof(block_sector_t) * NUM_POINTER, 0);
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
        // block_write(fs_device, singly_indirect_buffer[j], zero_block);
        write_helper(zero_block, singly_indirect_buffer[j], sizeof(block_sector_t) * NUM_POINTER,
                     0);
      }
    }

    /* If size does not reach the current singly indirect block, 
       then free the current singly indirect block. */
    if (final_size <= (12 + i * NUM_POINTER) * BLOCK_SECTOR_SIZE) {
      free_map_release(doubly_indirect_buffer[i], 1);
      doubly_indirect_buffer[i] = 0;
    } else {
      // block_write(fs_device, doubly_indirect_buffer[i], singly_indirect_buffer);
      write_helper(singly_indirect_buffer, doubly_indirect_buffer[i],
                   NUM_POINTER * sizeof(block_sector_t), 0);
      free(singly_indirect_buffer);
    }
  }

  /* If size does not require a doubly indirect pointer, then remove it. */
  if (final_size <= 12 * BLOCK_SECTOR_SIZE) {
    free_map_release(inode->doubly_indirect, 1);
    inode->doubly_indirect = 0;
  } else {
    // block_write(fs_device, inode->doubly_indirect, doubly_indirect_buffer);
    write_helper(doubly_indirect_buffer, inode->doubly_indirect,
                 sizeof(block_sector_t) * NUM_POINTER, 0);
  }
  free(doubly_indirect_buffer);
  free(zero_block);
  inode->length = final_size; // do not change length in resize function
  // lock_release(&write_lock);
  return 1;
}

void write_helper(const void* buffer, block_sector_t sector_idx, size_t size, int offset) {
  // instead of calling block_write, we call this function, which checks our cache to see if we have sector_idx in our cache.
  // if it's in our cache, we just write to it from the buffer, else we bring in the sector index into the cache and write to it
  lock_acquire(&cache_lock);
  for (int i = 0; i < 64; i++) {
    // if we have found the sector index, then we memcpy and set use bit to 1
    if (cache[i].sector_index == sector_idx) {
      lock_acquire(&cache[i].cache_index_lock);
      cache[i].use = 1;   // page has been used recently
      cache[i].dirty = 1; // set dirty bit
      cache_hits++;
      lock_release(&cache_lock);
      memcpy(cache[i].data + offset, buffer, size);
      lock_release(&cache[i].cache_index_lock);
      return;
    }
  }
  // we did NOT hit in our cache, so we use clock and find next page
  cache_misses++;
  update_clock();
  struct cache_metadata* cur_cache = &cache[clock_pointer];
  // acquire the lock of the valid index
  lock_acquire(&cur_cache->cache_index_lock); // release data after updates
  cur_cache->old_sector_index = cur_cache->sector_index;
  // update metadata
  cur_cache->sector_index = sector_idx;
  cur_cache->valid = 1;
  cur_cache->use = 1;
  clock_pointer = (clock_pointer + 1) % 64;
  lock_release(&cache_lock); // release cache global lock here, before you edit the actual data.
  if (cur_cache->dirty) {
    block_write(fs_device, cur_cache->old_sector_index, cur_cache->data);
    cur_cache->dirty = 0;
  }
  block_read(fs_device, sector_idx, cur_cache->data); // read in the sector into this place in cache
  memcpy(cur_cache->data + offset, buffer, size);
  cur_cache->dirty = 1;
  lock_release(&cur_cache->cache_index_lock); // release data after updates
  return;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  // lock_acquire(&write_lock);
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;

  if (inode->deny_write_cnt) {
    // lock_release(&write_lock);
    return 0;
  }

  // Allocate / dellocate blocks as necessary
  struct inode_disk inode_block;
  // block_read(fs_device, inode->sector, &inode_block);
  read_helper(&inode_block, inode->sector, BLOCK_SECTOR_SIZE, 0);
  int success;
  //read_helper(inode_block, inode->sector, BLOCK_SECTOR_SIZE, 0);
  if (inode_block.length < size + offset) {
    success = inode_resize(&inode_block, size + offset);
    // block_write(fs_device, inode->sector, &inode_block);
    write_helper(&inode_block, inode->sector, BLOCK_SECTOR_SIZE, 0);
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

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      // block_write(fs_device, sector_idx, buffer + bytes_written);
      write_helper(buffer + bytes_written, sector_idx, BLOCK_SECTOR_SIZE, 0);
      //write_helper(buffer_, sector_idx, size, offset);
    } else {
      // uint8_t* sector_buf = malloc(BLOCK_SECTOR_SIZE);
      // block_read(fs_device, sector_idx, sector_buf);
      // memcpy(sector_buf + sector_ofs, buffer + bytes_written, chunk_size);
      // block_write(fs_device, sector_idx, sector_buf);
      // free(sector_buf);
      write_helper(buffer + bytes_written, sector_idx, chunk_size, sector_ofs);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }

  free(bounce);
  // lock_release(&write_lock);
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
  // block_read(fs_device, inode->sector, &inode_block);
  read_helper(&inode_block, inode->sector, BLOCK_SECTOR_SIZE, 0);
  //read_helper(inode_block, inode->sector, BLOCK_SECTOR_SIZE, 0);
  return inode_block.length;
}

int get_cache_misses() { return cache_misses; }
int get_cache_hits() { return cache_hits; }