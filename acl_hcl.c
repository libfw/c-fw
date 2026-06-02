#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acl.h"
#include "acl_hcl.h"
#include "hcl.h" /* libhcl/c-hcl */
#include "log.h"

/* Growable JSON output buffer. */
struct sbuf {
  char *p;
  size_t len, cap;
  bool oom;
};
static void sb_putn(struct sbuf *s, const char *d, size_t n) {
  if (s->oom)
    return;
  if (s->len + n + 1 > s->cap) {
    size_t cap = s->cap ? s->cap * 2 : 256;
    while (cap < s->len + n + 1)
      cap *= 2;
    char *np = realloc(s->p, cap);
    if (np == NULL) {
      s->oom = true;
      return;
    }
    s->p = np;
    s->cap = cap;
  }
  memcpy(s->p + s->len, d, n);
  s->len += n;
  s->p[s->len] = '\0';
}
static void sb_puts(struct sbuf *s, const char *str) { sb_putn(s, str, strlen(str)); }

/* Emit an HCL value as JSON. Strings are emitted quoted (ACL values -- MACs,
 * CIDRs, keywords -- contain no characters needing JSON escaping). */
static void emit_value(struct sbuf *s, const hcl_value *v) {
  double num;
  bool b;
  switch (hcl_value_kind(v)) {
  case HCL_STRING:
    sb_puts(s, "\"");
    sb_puts(s, hcl_value_string(v));
    sb_puts(s, "\"");
    break;
  case HCL_NUMBER: {
    hcl_value_number(v, &num);
    char buf[32];
    snprintf(buf, sizeof(buf), "%g", num);
    sb_puts(s, buf);
    break;
  }
  case HCL_BOOL:
    hcl_value_bool(v, &b);
    sb_puts(s, b ? "true" : "false");
    break;
  case HCL_NULL:
    sb_puts(s, "null");
    break;
  case HCL_LIST:
    sb_puts(s, "[");
    for (size_t i = 0; i < hcl_value_list_count(v); i++) {
      if (i)
        sb_puts(s, ",");
      emit_value(s, hcl_value_list_at(v, i));
    }
    sb_puts(s, "]");
    break;
  }
}

static const char *RULE_KEYS[] = {"action", "direction", "src_cidr", "dst_cidr",
                                  "proto",  "src_port",  "dst_port"};

/* Emit one rule object from a `rule {}` body, with optional direction / MAC
 * overrides applied (used when expanding a group over its members). */
static bool emit_rule(struct sbuf *s, bool *first, const hcl_body *rb, const char *dir,
                      const char *src_mac, const char *dst_mac) {
  if (hcl_body_attr(rb, "action") == NULL) {
    ERROR("acl_hcl: rule is missing \"action\"");
    return false;
  }
  if (!*first)
    sb_puts(s, ",");
  *first = false;
  sb_puts(s, "{");
  bool f2 = true;

  /* direction: override wins, else the rule's own attr. */
  if (dir != NULL) {
    sb_puts(s, "\"direction\":\"");
    sb_puts(s, dir);
    sb_puts(s, "\"");
    f2 = false;
  } else {
    const hcl_value *dv = hcl_body_attr(rb, "direction");
    if (dv != NULL) {
      sb_puts(s, "\"direction\":");
      emit_value(s, dv);
      f2 = false;
    }
  }
  /* src_mac / dst_mac: override wins, else the rule's own attr. */
  const struct {
    const char *key, *override;
  } macs[] = {
      {"src_mac", src_mac},
      {"dst_mac", dst_mac}
  };
  for (size_t i = 0; i < 2; i++) {
    const char *ov = macs[i].override;
    const hcl_value *av = hcl_body_attr(rb, macs[i].key);
    if (ov == NULL && av == NULL)
      continue;
    if (!f2)
      sb_puts(s, ",");
    f2 = false;
    sb_puts(s, "\"");
    sb_puts(s, macs[i].key);
    sb_puts(s, "\":");
    if (ov != NULL) {
      sb_puts(s, "\"");
      sb_puts(s, ov);
      sb_puts(s, "\"");
    } else {
      emit_value(s, av);
    }
  }
  /* remaining scalar fields straight from the rule body. */
  for (size_t i = 0; i < sizeof(RULE_KEYS) / sizeof(RULE_KEYS[0]); i++) {
    const hcl_value *av = hcl_body_attr(rb, RULE_KEYS[i]);
    if (av == NULL)
      continue;
    if (!f2)
      sb_puts(s, ",");
    f2 = false;
    sb_puts(s, "\"");
    sb_puts(s, RULE_KEYS[i]);
    sb_puts(s, "\":");
    emit_value(s, av);
  }
  sb_puts(s, "}");
  return true;
}

static bool emit_group(struct sbuf *s, bool *first, const hcl_block *g) {
  const hcl_body *gb = hcl_block_body(g);
  const hcl_value *members = hcl_body_attr(gb, "member_mac");
  size_t nmember = hcl_value_list_count(members);
  if (nmember == 0) {
    ERROR("acl_hcl: group has no member_mac");
    return false;
  }
  for (size_t r = 0; r < hcl_body_block_count(gb, "rule"); r++) {
    const hcl_body *rb = hcl_block_body(hcl_body_block_at(gb, "rule", r));
    const hcl_value *dv = hcl_body_attr(rb, "direction");
    const char *dir = dv ? hcl_value_string(dv) : NULL;
    bool any = (dir == NULL) || strcmp(dir, "any") == 0;
    bool egress = any || strcmp(dir, "egress") == 0;
    bool ingress = any || strcmp(dir, "ingress") == 0;
    for (size_t m = 0; m < nmember; m++) {
      const char *mac = hcl_value_string(hcl_value_list_at(members, m));
      if (mac == NULL) {
        ERROR("acl_hcl: member_mac entries must be strings");
        return false;
      }
      if (egress && !emit_rule(s, first, rb, "egress", mac, NULL))
        return false;
      if (ingress && !emit_rule(s, first, rb, "ingress", NULL, mac))
        return false;
    }
  }
  return true;
}

struct acl *acl_parse_hcl(const char *src, size_t len) {
  char err[256];
  hcl_doc *doc = hcl_parse(src, len, err, sizeof(err));
  if (doc == NULL) {
    ERRORF("acl_hcl: %s", err);
    return NULL;
  }
  const hcl_body *root = hcl_doc_root(doc);

  struct sbuf s = {0};
  bool first = true, ok = true;
  sb_puts(&s, "{\"rules\":[");
  /* top-level rules */
  for (size_t i = 0; ok && i < hcl_body_block_count(root, "rule"); i++) {
    const hcl_body *rb = hcl_block_body(hcl_body_block_at(root, "rule", i));
    ok = emit_rule(&s, &first, rb, NULL, NULL, NULL);
  }
  /* groups */
  for (size_t i = 0; ok && i < hcl_body_block_count(root, "group"); i++) {
    ok = emit_group(&s, &first, hcl_body_block_at(root, "group", i));
  }
  sb_puts(&s, "]");
  const hcl_value *def = hcl_body_attr(root, "default_action");
  if (def != NULL && hcl_value_string(def) != NULL) {
    sb_puts(&s, ",\"default_action\":\"");
    sb_puts(&s, hcl_value_string(def));
    sb_puts(&s, "\"");
  }
  sb_puts(&s, "}");
  hcl_free(doc);

  if (!ok || s.oom) {
    free(s.p);
    return NULL;
  }
  struct acl *acl = acl_parse(s.p, s.len);
  free(s.p);
  return acl;
}

struct acl *acl_load_hcl(const char *path) {
  FILE *fp = fopen(path, "rb");
  if (fp == NULL) {
    ERRORF("acl_hcl: cannot open \"%s\": %s", path, strerror(errno));
    return NULL;
  }
  if (fseek(fp, 0, SEEK_END) != 0 || ftell(fp) < 0) {
    ERRORN("acl_hcl: seek");
    fclose(fp);
    return NULL;
  }
  long size = ftell(fp);
  rewind(fp);
  char *data = malloc((size_t)size + 1);
  if (data == NULL) {
    ERRORN("acl_hcl: malloc");
    fclose(fp);
    return NULL;
  }
  size_t got = fread(data, 1, (size_t)size, fp);
  fclose(fp);
  data[got] = '\0';
  struct acl *acl = acl_parse_hcl(data, got);
  free(data);
  if (acl == NULL)
    ERRORF("acl_hcl: failed to compile \"%s\"", path);
  return acl;
}
