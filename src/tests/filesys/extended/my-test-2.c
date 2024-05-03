#include <syscall.h>
#include <random.h>
#include <stdlib.h>
#include "tests/lib.h"
#include "tests/main.h"
#define BLOCK_SIZE 512
#define NUM_BLOCKS 128
static char buf_a[BLOCK_SIZE];

void test_main(void) {
  int fd;
  random_init(0);
  random_bytes(buf_a, sizeof buf_a);
  CHECK(create("a", 0), "create \"a\"");
  CHECK((fd = open("a")) > 1, "open \"a\"");

  msg("write 64 KiB to \"a\"");
  for (int b = 0; b < NUM_BLOCKS; b++) {
    write(fd, buf_a, BLOCK_SIZE);
  }

  int total_write = bc_stats(0) + bc_stats(1);

  close(fd);
  remove("a");
  msg("close \"a\"");
}