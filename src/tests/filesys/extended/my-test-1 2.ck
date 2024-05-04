# -*- perl -*-
use strict;
use warnings;
use tests::tests;
use tests::random;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(my-test-1) begin
(my-test-1) create "a"
(my-test-1) open "a"
(my-test-1) writing content into "a"
(my-test-1) close "a"
(my-test-1) write to file complete, resetting
(my-test-1) open "a"
(my-test-1) reading "a" for the first time
(my-test-1) close "a"
(my-test-1) open "a"
(my-test-1) reading "a" for the second time
(my-test-1) close "a"
(my-test-1) hit rate improved
(my-test-1) end
EOF
pass;