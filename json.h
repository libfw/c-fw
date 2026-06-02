#ifndef C_FW_JSON_H
#define C_FW_JSON_H

#include <stdbool.h>
#include <stddef.h>

/* A minimal JSON parser (objects, arrays, strings, numbers, booleans, null;
 * standard escapes + \uXXXX). Dependency-free; used by acl.c to load rulesets. */
typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } jtype;

typedef struct jnode {
  jtype type;
  bool b;
  double num;
  char *str;           /* J_STR value (owned) */
  struct jnode **vals; /* J_ARR / J_OBJ children (owned) */
  char **keys;         /* J_OBJ keys (owned), parallel to vals; NULL for arrays */
  size_t n;
} jnode;

/* Parse a JSON document. Returns NULL on malformed input. */
jnode *json_parse(const char *src, size_t len);
void jfree(jnode *v);
/* First value for `key` in an object node, or NULL. */
const jnode *jget(const jnode *obj, const char *key);

#endif /* C_FW_JSON_H */
