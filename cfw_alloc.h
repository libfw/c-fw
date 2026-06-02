#ifndef C_FW_ALLOC_H
#define C_FW_ALLOC_H

/* Test-only allocation fault injection, shared by acl.c and json.c so a single
 * budget sweep can reach every defensive out-of-memory branch across both.
 * acl_alloc_budget < 0 disables; otherwise the (budget+1)-th allocation fails
 * once. The storage for acl_alloc_budget is defined in acl.c. */
#ifdef ACL_FAULT_INJECT
#include <stdbool.h>
#include <stdlib.h>

extern int acl_alloc_budget;

static inline bool acl__should_fail(void) {
  if (acl_alloc_budget < 0)
    return false;
  if (acl_alloc_budget == 0) {
    acl_alloc_budget = -1;
    return true;
  }
  acl_alloc_budget--;
  return false;
}
static inline void *acl__malloc(size_t n) { return acl__should_fail() ? NULL : malloc(n); }
static inline void *acl__calloc(size_t a, size_t b) {
  return acl__should_fail() ? NULL : calloc(a, b);
}
static inline void *acl__realloc(void *p, size_t n) {
  return acl__should_fail() ? NULL : realloc(p, n);
}
#define malloc acl__malloc
#define calloc acl__calloc
#define realloc acl__realloc
#endif /* ACL_FAULT_INJECT */

#endif /* C_FW_ALLOC_H */
