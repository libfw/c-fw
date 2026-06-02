# c-fw

A small, embeddable **stateful L3/L4 packet filter** for C. It matches and
tracks raw ethernet frames (`const uint8_t *frame, size_t len`), so it has no
dependency on any particular packet source — use it with vmnet, TUN/TAP, pcap,
a userspace proxy, etc.

It is the firewall core extracted from
[socket_vmnet](https://github.com/lima-vm/socket_vmnet)'s ACL work.

## What's inside

- **`acl.{c,h}`** — a stateless access-control list: first-match-wins rules over
  ethernet / IPv4 / IPv6 / TCP / UDP / ICMP, matching on source/dest MAC, source/
  dest CIDR (v4 or v6), protocol, port (single or range) and direction
  (egress / ingress). Loaded from a compact JSON ruleset (a tiny built-in JSON
  parser; zero third-party code).
- **`conntrack.{c,h}`** — stateful flow tracking by normalized TCP/UDP 5-tuple,
  with per-protocol idle timeouts and LRU eviction. Lets the return traffic of an
  allowed flow pass without an explicit reverse rule. Time is caller-supplied, so
  it is deterministic and unit-testable.
- **`acl_hcl.{c,h}`** — optional HCL front-end: author policies in HCL and compile
  them to an ACL, via [libhcl/c-hcl](https://github.com/libhcl/c-hcl) (a git
  submodule). Groups are expanded over their member MACs.

```c
#include "acl.h"
#include "acl_hcl.h"
#include "conntrack.h"

struct acl *acl = acl_load_hcl("policy.hcl");          // or acl_load("policy.json")
struct conntrack *ct = conntrack_new(4096, 120, 30);   // tcp/udp idle timeouts

uint64_t now = time(NULL);
bool ok = conntrack_established(ct, frame, len, now) ||
          acl_allows(acl, ACL_EGRESS, frame, len);
if (ok) conntrack_record(ct, frame, len, now);
```

## HCL note

The HCL front-end uses **c-hcl**, which parses only the **declarative subset** of
HCL native syntax (attributes, labeled blocks, scalar/list values). It is **not
HCL2-compatible**: no expressions, interpolation, functions, or heredocs. That is
intentional — policies are configuration, not programs.

## Rule schema

JSON (the daemon-facing form) and the equivalent HCL:

```json
{ "default_action": "allow",
  "rules": [ { "action":"deny", "direction":"egress", "proto":"tcp",
               "src_mac":"de:ad:be:ef:00:01", "dst_cidr":"10.0.0.0/8",
               "dst_port":[1000,2000] } ] }
```

```hcl
default_action = "allow"
group "web" {
  member_mac = ["de:ad:be:ef:00:01"]
  rule { action = "allow" direction = "ingress" proto = "tcp" dst_port = 443 }
}
rule { action = "deny" direction = "egress" proto = "tcp" dst_port = 25 }
```

Stateless by default; combine with conntrack for stateful behavior. ICMP is not
tracked. See the headers for the full API.

## Build & test

```sh
git clone --recursive https://github.com/libfw/c-fw   # pulls the c-hcl submodule
make            # builds libcfw.a
make test       # unit tests (add SANITIZE=address on a system clang)
make cover      # llvm-cov report
```

Already cloned without `--recursive`? `git submodule update --init`.
No toolchain? With [pkgx](https://pkgx.sh): `dev` (reads pkgx.yaml) or `./taskw test`.

All modules are unit-tested (ASan + allocation fault injection); coverage is 100%
of functions and ~97–99% of lines (the remainder being defensive NULL/I-O guards).

## License

BSD-3-Clause. See [LICENSE](LICENSE).
