# -*- perl -*-
use strict;
use warnings;
use tests::tests;
use tests::random;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(my-test-2) begin
(my-test-2) create "a"
(my-test-2) open "a"
(my-test-2) write 64 KiB to "a" byte-by-byte
(my-test-2) read 64 KiB from "a" byte-by-byte
(my-test-2) close "a"
(my-test-2) total writes is close to 128
(my-test-2) end
EOF
pass;