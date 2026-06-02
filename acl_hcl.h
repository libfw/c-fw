#ifndef C_FW_ACL_HCL_H
#define C_FW_ACL_HCL_H

#include <stddef.h>

// HCL front-end for the ACL: parse a policy written in HCL (via libhcl/c-hcl)
// and compile it to an ACL. Groups are expanded over their member MACs (egress
// rules bind to the member's source MAC, ingress rules to the destination MAC).
//
//   default_action = "deny"
//   group "web" {
//     member_mac = ["de:ad:be:ef:00:01"]
//     rule { action = "allow" direction = "ingress" proto = "tcp" dst_port = 443 }
//   }
//   rule { action = "deny" direction = "egress" proto = "tcp" dst_port = 25 }
struct acl;

// Compile an in-memory HCL policy. Returns NULL on error (logged).
struct acl *acl_parse_hcl(const char *src, size_t len);

// Read and compile an HCL policy file. Returns NULL on error (logged).
struct acl *acl_load_hcl(const char *path);

#endif /* C_FW_ACL_HCL_H */
