#ifndef SOCKET_VMNET_ACL_H
#define SOCKET_VMNET_ACL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// A stateless L3/L4 access-control list, loaded from the compact JSON emitted
// by the `hcl2acl` helper. Rules are evaluated first-match-wins; if no rule
// matches, the list's default action applies.
//
// This is intentionally stateless: there is no connection tracking, so a rule
// that allows egress does not implicitly allow the return traffic. Stateful
// security groups (conntrack) are a planned follow-up.
struct acl;

// Direction of a frame relative to a guest:
//   ACL_EGRESS  - a frame a guest is sending (socket -> vmnet / other guests)
//   ACL_INGRESS - a frame being delivered to guests (vmnet -> socket)
enum acl_dir {
  ACL_EGRESS,
  ACL_INGRESS,
};

// Load and compile an ACL from a JSON file. Returns NULL on error (logged).
struct acl *acl_load(const char *path);

// Parse and compile an ACL from an in-memory JSON buffer (no filesystem
// access). Returns NULL on error (logged). Used by acl_load and by tests.
struct acl *acl_parse(const char *json, size_t len);

// Return true if `frame` (a full ethernet frame of `len` bytes) is permitted in
// the given direction. Non-IPv4 frames (e.g. ARP, IPv6) are always allowed in
// this first version; see ACL.md.
bool acl_allows(const struct acl *acl, enum acl_dir dir, const uint8_t *frame, size_t len);

// Like acl_allows, but also reports which rule decided the verdict: *matched is
// set to the 0-based rule index, or -1 if no rule matched and the list's
// default action applied (also -1 for a NULL acl or a non-IP passthrough).
// acl_check additionally maintains the observability counters below.
bool acl_check(const struct acl *acl, enum acl_dir dir, const uint8_t *frame, size_t len,
               int *matched);

// Cumulative match/verdict counters, indexed by direction ([ACL_EGRESS],
// [ACL_INGRESS]). `nonip` counts non-IPv4 frames passed through unconditionally
// (they are also included in the `allow`/`bytes_allow` totals).
struct acl_stats {
  uint64_t allow[2];
  uint64_t deny[2];
  uint64_t bytes_allow[2];
  uint64_t bytes_deny[2];
  uint64_t nonip[2];
};

// Parsed L3/L4 view of a frame, for describing events in a UI. `sport`/`dport`
// are -1 when not applicable (non-TCP/UDP or truncated).
struct acl_l3l4 {
  int family; // 4 or 6
  uint8_t src[16], dst[16];
  int proto;
  int sport, dport;
};

// Classify a frame's L3/L4 tuple. Returns false for non-IP / runt / truncated
// frames (the same ones acl_allows passes through unconditionally).
bool acl_classify(const uint8_t *frame, size_t len, struct acl_l3l4 *out);

// Number of rules in the list.
size_t acl_rule_count(const struct acl *acl);

// Per-rule cumulative match count (0 if idx is out of range).
uint64_t acl_rule_hits(const struct acl *acl, size_t idx);

// Copy the aggregate counters into *out (zeroed if acl is NULL).
void acl_get_stats(const struct acl *acl, struct acl_stats *out);

// Zero all counters (aggregate + per-rule).
void acl_reset_stats(struct acl *acl);

// Named acl_destroy (not acl_free) to avoid clashing with the POSIX
// acl_free(void *) declared in <sys/acl.h>.
void acl_destroy(struct acl *acl);

#endif /* SOCKET_VMNET_ACL_H */
