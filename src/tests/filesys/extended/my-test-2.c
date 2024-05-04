#include <syscall.h>
#include <random.h>
#include <stdlib.h>
#include "tests/lib.h"
#include "tests/main.h"
#define BLOCK_SIZE 512
#define NUM_BLOCKS 128
#define TOTAL_SIZE 2 << 16 // 64KiB

static char byte = 'x'; // Write this byte 64Ki times

void test_main(void) {
  int fd;
  int i;
  random_init(0);
  CHECK(create("a", 0), "create \"a\"");
  CHECK((fd = open("a")) > 1, "open \"a\"");

  int old_total_write = bc_stats(2);

  msg("write 64 KiB to \"a\" byte-by-byte");
  for (i = 0; i < TOTAL_SIZE; i++) {
    write(fd, &byte, 1);
  }

  int new_total_write = bc_stats(2);

  msg("read 64 KiB from \"a\" byte-by-byte");

  /*
  char buffer;
    for (i = 0; i < TOTAL_SIZE; i++) {
        read(fd, &buffer, 1);
    }
    */

  close(fd);
  remove("a");
  msg("close \"a\"");

  int diff = new_total_write - old_total_write;
  if (diff > 120 && diff < 200) {
    msg("Total writes is close to 128");
  }
}