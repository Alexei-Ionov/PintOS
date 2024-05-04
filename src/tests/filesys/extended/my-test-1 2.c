#include <syscall.h>
#include <random.h>
#include <stdlib.h>
#include "tests/lib.h"
#include "tests/main.h"
#define BLOCK_SIZE 512
#define NUM_BLOCKS 64
static char buf_a[BLOCK_SIZE];

void test_main(void) {
  int fd_a;
  random_init(0);
  random_bytes(buf_a, sizeof buf_a);
  CHECK(create("a", 0), "create \"a\"");
  CHECK((fd_a = open("a")) > 1, "open \"a\"");

  msg("writing content into \"a\"");
  for (int b = 0; b < NUM_BLOCKS; b++) {
    write(fd_a, buf_a, BLOCK_SIZE);
  }

  msg("close \"a\"");
  close(fd_a);

  msg("write to file complete, resetting");
  bc_clear();

  CHECK((fd_a = open("a")) > 1, "open \"a\"");
  msg("reading \"a\" for the first time");
  for (int b = 0; b < NUM_BLOCKS; b++) {
    read(fd_a, buf_a, BLOCK_SIZE);
  }
  close(fd_a);
  msg("close \"a\"");

  int old_hit = bc_stats(1);
  int old_total = bc_stats(0) + old_hit;
  int old_hit_rate = (100 * old_hit) / old_total;

  CHECK((fd_a = open("a")) > 1, "open \"a\"");
  msg("reading \"a\" for the second time");
  for (int b = 0; b < NUM_BLOCKS; b++) {
    read(fd_a, buf_a, BLOCK_SIZE);
  }
  close(fd_a);
  msg("close \"a\"");

  remove("a");

  int new_hit = bc_stats(1);
  int new_total = bc_stats(0) + new_hit;
  int new_hit_rate = 100 * (new_hit - old_hit) / (new_total - old_total);

  if (new_hit_rate > old_hit_rate) {
    msg("hit rate improved");
  }
}