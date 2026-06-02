/* Unit test for the HCL front-end (acl_hcl.c, via libhcl/c-hcl).
 *   clang -I.. -I../third_party/c-hcl -O0 -g \
 *       ../acl.c ../acl_hcl.c ../third_party/c-hcl/hcl.c acl_hcl_test.c -o acl_hcl_test
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acl.h"
#include "acl_hcl.h"

bool debug = false; /* referenced by log.h */

static int failures = 0;
static void check(const char *name, bool ok) {
  if (!ok) {
    fprintf(stderr, "FAIL: %s\n", name);
    failures++;
  } else {
    fprintf(stderr, "ok:   %s\n", name);
  }
}

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))
static const uint8_t MAC1[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
static const uint8_t MAC2[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x02};

static size_t tcp(uint8_t *buf, const uint8_t smac[6], uint16_t dport) {
  static const uint8_t dmac[6] = {0x02, 0, 0, 0, 0, 0x99};
  memcpy(buf, dmac, 6);
  memcpy(buf + 6, smac, 6);
  buf[12] = 0x08;
  buf[13] = 0x00;
  uint8_t *ip = buf + 14;
  memset(ip, 0, 20);
  ip[0] = 0x45;
  ip[9] = 6;
  uint32_t s = IP(192, 168, 1, 5), d = IP(8, 8, 8, 8);
  ip[12] = s >> 24;
  ip[13] = s >> 16;
  ip[14] = s >> 8;
  ip[15] = s;
  ip[16] = d >> 24;
  ip[17] = d >> 16;
  ip[18] = d >> 8;
  ip[19] = d;
  uint8_t *l4 = ip + 20;
  l4[0] = 0x30;
  l4[1] = 0x39;
  l4[2] = (uint8_t)(dport >> 8);
  l4[3] = (uint8_t)dport;
  return 14 + 20 + 4;
}

static struct acl *p(const char *hcl) { return acl_parse_hcl(hcl, strlen(hcl)); }

int main(void) {
  /* Behavioral: group egress rule binds src MAC; top-level rule is global. */
  {
    struct acl *a = p("# policy\n"
                      "default_action = \"allow\"\n"
                      "group \"db\" {\n"
                      "  member_mac = [\"de:ad:be:ef:00:01\"]\n"
                      "  rule { action = \"deny\" direction = \"egress\" proto = \"tcp\" "
                      "dst_port = 22 }\n"
                      "}\n"
                      "rule { action = \"deny\" direction = \"egress\" proto = \"tcp\" "
                      "dst_port = 25 }\n");
    check("hcl policy compiles", a != NULL);
    uint8_t f[64];
    size_t n = tcp(f, MAC1, 22);
    check("member tcp/22 egress denied", !acl_allows(a, ACL_EGRESS, f, n));
    n = tcp(f, MAC2, 22);
    check("non-member tcp/22 allowed", acl_allows(a, ACL_EGRESS, f, n));
    n = tcp(f, MAC2, 25);
    check("global tcp/25 egress denied", !acl_allows(a, ACL_EGRESS, f, n));
    n = tcp(f, MAC1, 80);
    check("tcp/80 allowed", acl_allows(a, ACL_EGRESS, f, n));
    acl_destroy(a);
  }

  /* Group ingress rule binds dst MAC + port range. */
  {
    struct acl *a = p("group \"web\" {\n"
                      "  member_mac = [\"de:ad:be:ef:00:01\", \"de:ad:be:ef:00:02\"]\n"
                      "  rule { action = \"allow\" direction = \"ingress\" proto = \"tcp\" "
                      "dst_port = [80, 443] }\n"
                      "}\n");
    check("group ingress compiles", a != NULL);
    acl_destroy(a);
  }

  /* acl_load_hcl from a file. */
  {
    FILE *fp = fopen("/tmp/cfw_test.hcl", "wb");
    if (fp) {
      fputs("default_action = \"deny\"\nrule { action = \"allow\" proto = \"icmp\" }\n", fp);
      fclose(fp);
    }
    struct acl *a = acl_load_hcl("/tmp/cfw_test.hcl");
    check("acl_load_hcl reads file", a != NULL);
    acl_destroy(a);
    check("acl_load_hcl missing file", acl_load_hcl("/tmp/no/such.hcl") == NULL);
  }

  /* Errors. */
  check("err: HCL syntax", p("group \"g\" {") == NULL);
  check("err: group without members", p("group \"g\" { rule { action = \"deny\" } }") == NULL);
  check("err: rule without action", p("rule { proto = \"tcp\" }") == NULL);

  if (failures == 0) {
    fprintf(stderr, "\nAll acl_hcl tests passed.\n");
    return 0;
  }
  fprintf(stderr, "\n%d acl_hcl test(s) FAILED.\n", failures);
  return 1;
}
