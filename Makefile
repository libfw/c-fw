PREFIX ?= /usr/local
CFLAGS ?= -O2 -Wall -Wextra -pedantic
HCL_DIR := third_party/c-hcl

# AddressSanitizer is opt-in (SANITIZE=address). Coverage uses llvm-profdata/
# llvm-cov; on macOS without pkgx: make cover LLVM_COV='xcrun llvm-cov' ...
SANITIZE ?=
LLVM_PROFDATA ?= llvm-profdata
LLVM_COV ?= llvm-cov
TEST_CFLAGS := -I. -I$(HCL_DIR) -O0 -g -Wall -Wextra -DACL_FAULT_INJECT -DCT_FAULT_INJECT
ifneq ($(strip $(SANITIZE)),)
TEST_CFLAGS += -fsanitize=$(SANITIZE)
endif
COVER_CFLAGS = $(TEST_CFLAGS) -fprofile-instr-generate -fcoverage-mapping

all: libcfw.a

acl.o: acl.c acl.h json.h cfw_alloc.h
	$(CC) $(CFLAGS) -c acl.c -o $@
json.o: json.c json.h cfw_alloc.h
	$(CC) $(CFLAGS) -c json.c -o $@
conntrack.o: conntrack.c conntrack.h
	$(CC) $(CFLAGS) -c conntrack.c -o $@
acl_hcl.o: acl_hcl.c acl_hcl.h acl.h $(HCL_DIR)/hcl.h
	$(CC) $(CFLAGS) -I$(HCL_DIR) -c acl_hcl.c -o $@
hcl.o: $(HCL_DIR)/hcl.c $(HCL_DIR)/hcl.h
	$(CC) $(CFLAGS) -I$(HCL_DIR) -c $(HCL_DIR)/hcl.c -o $@
ast.o: $(HCL_DIR)/ast.c $(HCL_DIR)/hcl.h
	$(CC) $(CFLAGS) -I$(HCL_DIR) -c $(HCL_DIR)/ast.c -o $@

libcfw.a: acl.o json.o conntrack.o acl_hcl.o hcl.o ast.o
	$(AR) rcs $@ $^

.PHONY: fmt
fmt:
	clang-format -i acl.c acl.h json.c json.h conntrack.c conntrack.h acl_hcl.c acl_hcl.h test/*.c

.PHONY: test
test:
	$(CC) $(TEST_CFLAGS) acl.c json.c test/acl_test.c -o test/acl_test && ./test/acl_test
	$(CC) $(TEST_CFLAGS) conntrack.c test/conntrack_test.c -o test/conntrack_test && ./test/conntrack_test
	$(CC) $(TEST_CFLAGS) acl.c json.c acl_hcl.c $(HCL_DIR)/hcl.c $(HCL_DIR)/ast.c test/acl_hcl_test.c -o test/acl_hcl_test && ./test/acl_hcl_test

.PHONY: cover
cover:
	rm -f *.profraw *.profdata
	$(CC) $(COVER_CFLAGS) acl.c json.c test/acl_test.c -o test/acl_test
	LLVM_PROFILE_FILE=acl.profraw ./test/acl_test >/dev/null
	$(CC) $(COVER_CFLAGS) conntrack.c test/conntrack_test.c -o test/conntrack_test
	LLVM_PROFILE_FILE=conntrack.profraw ./test/conntrack_test >/dev/null
	$(CC) $(COVER_CFLAGS) acl.c json.c acl_hcl.c $(HCL_DIR)/hcl.c $(HCL_DIR)/ast.c test/acl_hcl_test.c -o test/acl_hcl_test
	LLVM_PROFILE_FILE=aclhcl.profraw ./test/acl_hcl_test >/dev/null
	$(LLVM_PROFDATA) merge -sparse acl.profraw -o acl.profdata
	$(LLVM_COV) report ./test/acl_test -instr-profile=acl.profdata acl.c json.c
	$(LLVM_PROFDATA) merge -sparse conntrack.profraw -o conntrack.profdata
	$(LLVM_COV) report ./test/conntrack_test -instr-profile=conntrack.profdata conntrack.c
	$(LLVM_PROFDATA) merge -sparse aclhcl.profraw -o aclhcl.profdata
	$(LLVM_COV) report ./test/acl_hcl_test -instr-profile=aclhcl.profdata acl_hcl.c

install: libcfw.a
	install -d "$(DESTDIR)$(PREFIX)/lib" "$(DESTDIR)$(PREFIX)/include/cfw"
	install -m644 libcfw.a "$(DESTDIR)$(PREFIX)/lib/"
	install -m644 acl.h conntrack.h acl_hcl.h "$(DESTDIR)$(PREFIX)/include/cfw/"

.PHONY: clean
clean:
	rm -f *.o *.a test/acl_test test/conntrack_test test/acl_hcl_test *.profraw *.profdata
	rm -rf *.dSYM test/*.dSYM
