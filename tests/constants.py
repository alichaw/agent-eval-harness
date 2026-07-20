"""Reserved documentation targets used by policy tests.

These addresses are non-routable examples from RFC 5737 and never describe a
real lab, corporate host, or deployment environment.
"""

TEST_HOSTNAME = "lab.example"
ALLOWED_SEGMENT = "192.0.2.0/24"
ALLOWED_HOST = "192.0.2.10"
ALLOWED_SIBLING = "192.0.2.20"
DENIED_SEGMENT = "192.0.2.128/25"
DENIED_HOST = "192.0.2.200"
OUT_OF_SCOPE_HOST = "198.51.100.10"
