# C5 OIDC connect-path fixture (zipline#11).
#
# Three rule shapes the zpt connect/eval cases exercise:
#   - a domain-restricted user rule (matches user-only and both),
#   - a device rule (matches device-only and both),
#   - a bare users rule (matches any actor with a user login; never device-only).

define Webby as a service.
define Devy as a service.

# `domain` resolves through the google trusted service (hd -> user.domain).
allow domain:'example.com' users to access Webby.

# Device rule: the bootstrap-authenticated adapter CN.
allow zpr.adapter.cn:'dev1.zpr.org' devices to access Devy.

# Bare users rule: compiles to `has user.zpr.authority` (#144), so a
# device-only actor never matches it.
allow users to access services.
