# bg3-ach-enabler build
#
#   make          build the library:            build/libbg3ach.so
#   make test     check it against the game:    bin/bg3 by default, or GAME=/path/to/bg3
#   make debug    build the test with memory/undefined-behaviour checks (ASan + UBSan)
#   make clean    delete build/
#   make help     show this list

CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
LDFLAGS ?=
LDLIBS  ?=

BUILD   := build
LIB     := $(BUILD)/libbg3ach.so
TEST    := $(BUILD)/test_offline

# The native Linux game executable that `make test` checks against.
# Example: make test GAME="$HOME/.local/share/Steam/steamapps/common/Baldurs Gate 3/bin/bg3"
GAME    ?= bin/bg3

.PHONY: all test debug clean help

all: $(LIB)

# The library. -fvisibility=hidden keeps all of its functions private; it only needs to run
# its start-up code when loaded.
$(LIB): src/bg3ach.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -shared -fPIC -fvisibility=hidden $(LDFLAGS) -o $@ $< $(LDLIBS)

# The offline test. It #includes src/bg3ach.c directly, so only that file is compiled.
$(TEST): tests/test_offline.c src/bg3ach.c | $(BUILD)
	$(CC) $(CPPFLAGS) -Isrc $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

test: $(TEST)
	@if [ ! -f "$(GAME)" ]; then \
		echo "Can't find the game at '$(GAME)'."; \
		echo "Run: make test GAME=/path/to/bg3   (the native Linux executable)"; \
		exit 1; \
	fi
	./$(TEST) "$(GAME)"

debug: CFLAGS := -std=c11 -O0 -g -Wall -Wextra -Wpedantic -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean $(TEST)

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD)

help:
	@sed -n '3,7s/^# *//p' $(firstword $(MAKEFILE_LIST))
