#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cfw_alloc.h"
#include "json.h"

typedef struct {
  const char *p;
  const char *end;
} jcur;

void jfree(jnode *v) {
  if (v == NULL)
    return;
  free(v->str);
  for (size_t i = 0; i < v->n; i++) {
    jfree(v->vals[i]);
    if (v->keys != NULL)
      free(v->keys[i]);
  }
  free(v->vals);
  free(v->keys);
  free(v);
}

static void jskip_ws(jcur *c) {
  while (c->p < c->end && isspace((unsigned char)*c->p))
    c->p++;
}

static jnode *jparse_value(jcur *c);

static void jutf8_encode(uint32_t cp, char **out) {
  if (cp < 0x80) {
    *(*out)++ = (char)cp;
  } else if (cp < 0x800) {
    *(*out)++ = (char)(0xC0 | (cp >> 6));
    *(*out)++ = (char)(0x80 | (cp & 0x3F));
  } else {
    *(*out)++ = (char)(0xE0 | (cp >> 12));
    *(*out)++ = (char)(0x80 | ((cp >> 6) & 0x3F));
    *(*out)++ = (char)(0x80 | (cp & 0x3F));
  }
}

/* Parse a JSON string starting at the opening quote. Returns a malloc'd C
 * string, or NULL on error. */
static char *jparse_string_raw(jcur *c) {
  if (c->p >= c->end || *c->p != '"')
    return NULL;
  c->p++;
  /* The decoded string is never longer than the encoded one. */
  char *out = malloc((size_t)(c->end - c->p) + 1);
  if (out == NULL)
    return NULL;
  char *w = out;
  while (c->p < c->end && *c->p != '"') {
    char ch = *c->p++;
    if (ch != '\\') {
      *w++ = ch;
      continue;
    }
    if (c->p >= c->end)
      goto err;
    char esc = *c->p++;
    switch (esc) {
    case '"':
      *w++ = '"';
      break;
    case '\\':
      *w++ = '\\';
      break;
    case '/':
      *w++ = '/';
      break;
    case 'b':
      *w++ = '\b';
      break;
    case 'f':
      *w++ = '\f';
      break;
    case 'n':
      *w++ = '\n';
      break;
    case 'r':
      *w++ = '\r';
      break;
    case 't':
      *w++ = '\t';
      break;
    case 'u': {
      if (c->end - c->p < 4)
        goto err;
      uint32_t cp = 0;
      for (int i = 0; i < 4; i++) {
        char h = *c->p++;
        cp <<= 4;
        if (h >= '0' && h <= '9')
          cp |= (uint32_t)(h - '0');
        else if (h >= 'a' && h <= 'f')
          cp |= (uint32_t)(h - 'a' + 10);
        else if (h >= 'A' && h <= 'F')
          cp |= (uint32_t)(h - 'A' + 10);
        else
          goto err;
      }
      jutf8_encode(cp, &w);
      break;
    }
    default:
      goto err;
    }
  }
  if (c->p >= c->end || *c->p != '"')
    goto err;
  c->p++; /* closing quote */
  *w = '\0';
  return out;
err:
  free(out);
  return NULL;
}

static jnode *jparse_string(jcur *c) {
  char *s = jparse_string_raw(c);
  if (s == NULL)
    return NULL;
  jnode *v = calloc(1, sizeof(*v));
  if (v == NULL) {
    free(s);
    return NULL;
  }
  v->type = J_STR;
  v->str = s;
  return v;
}

static jnode *jparse_number(jcur *c) {
  char *endp = NULL;
  errno = 0;
  double d = strtod(c->p, &endp);
  if (endp == c->p || endp > c->end)
    return NULL;
  c->p = endp;
  jnode *v = calloc(1, sizeof(*v));
  if (v == NULL)
    return NULL;
  v->type = J_NUM;
  v->num = d;
  return v;
}

static jnode *jparse_literal(jcur *c, const char *lit, jtype type, bool bval) {
  size_t len = strlen(lit);
  if ((size_t)(c->end - c->p) < len || strncmp(c->p, lit, len) != 0)
    return NULL;
  c->p += len;
  jnode *v = calloc(1, sizeof(*v));
  if (v == NULL)
    return NULL;
  v->type = type;
  v->b = bval;
  return v;
}

static bool jpush(jnode *parent, char *key, jnode *child) {
  jnode **nv = realloc(parent->vals, sizeof(*nv) * (parent->n + 1));
  if (nv == NULL)
    return false;
  parent->vals = nv;
  if (key != NULL) {
    char **nk = realloc(parent->keys, sizeof(*nk) * (parent->n + 1));
    if (nk == NULL)
      return false;
    parent->keys = nk;
    parent->keys[parent->n] = key;
  }
  parent->vals[parent->n] = child;
  parent->n++;
  return true;
}

static jnode *jparse_array(jcur *c) {
  c->p++; /* '[' */
  jnode *v = calloc(1, sizeof(*v));
  if (v == NULL)
    return NULL;
  v->type = J_ARR;
  jskip_ws(c);
  if (c->p < c->end && *c->p == ']') {
    c->p++;
    return v;
  }
  for (;;) {
    jskip_ws(c);
    jnode *item = jparse_value(c);
    if (item == NULL)
      goto err;
    if (!jpush(v, NULL, item)) {
      jfree(item);
      goto err;
    }
    jskip_ws(c);
    if (c->p >= c->end)
      goto err;
    if (*c->p == ',') {
      c->p++;
      continue;
    }
    if (*c->p == ']') {
      c->p++;
      return v;
    }
    goto err;
  }
err:
  jfree(v);
  return NULL;
}

static jnode *jparse_object(jcur *c) {
  c->p++; /* '{' */
  jnode *v = calloc(1, sizeof(*v));
  if (v == NULL)
    return NULL;
  v->type = J_OBJ;
  jskip_ws(c);
  if (c->p < c->end && *c->p == '}') {
    c->p++;
    return v;
  }
  for (;;) {
    jskip_ws(c);
    char *key = jparse_string_raw(c);
    if (key == NULL)
      goto err;
    jskip_ws(c);
    if (c->p >= c->end || *c->p != ':') {
      free(key);
      goto err;
    }
    c->p++;
    jskip_ws(c);
    jnode *val = jparse_value(c);
    if (val == NULL) {
      free(key);
      goto err;
    }
    if (!jpush(v, key, val)) {
      free(key);
      jfree(val);
      goto err;
    }
    jskip_ws(c);
    if (c->p >= c->end)
      goto err;
    if (*c->p == ',') {
      c->p++;
      continue;
    }
    if (*c->p == '}') {
      c->p++;
      return v;
    }
    goto err;
  }
err:
  jfree(v);
  return NULL;
}

static jnode *jparse_value(jcur *c) {
  jskip_ws(c);
  if (c->p >= c->end)
    return NULL;
  switch (*c->p) {
  case '{':
    return jparse_object(c);
  case '[':
    return jparse_array(c);
  case '"':
    return jparse_string(c);
  case 't':
    return jparse_literal(c, "true", J_BOOL, true);
  case 'f':
    return jparse_literal(c, "false", J_BOOL, false);
  case 'n':
    return jparse_literal(c, "null", J_NULL, false);
  default:
    return jparse_number(c);
  }
}

const jnode *jget(const jnode *obj, const char *key) {
  if (obj == NULL || obj->type != J_OBJ)
    return NULL;
  for (size_t i = 0; i < obj->n; i++) {
    if (strcmp(obj->keys[i], key) == 0)
      return obj->vals[i];
  }
  return NULL;
}

/* Parse a whole document. */
jnode *json_parse(const char *src, size_t len) {
  jcur c = {.p = src, .end = src + len};
  return jparse_value(&c);
}
