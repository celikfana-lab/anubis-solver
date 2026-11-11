# Security and authorized use

## Authorized use only

This is a client for the Anubis proof-of-work challenge. Running it against a
site means circumventing the bot-mitigation that the operator deliberately put
in front of their resources. Use it against systems you own or have explicit
permission to test. Do not point it at other people's sites.

The repository includes an opt-in implementation of **CVE-2026-62314**, an
access-control bypass in Anubis v1.22.0 .. < v1.26.0-pre1. It is disabled by
default, restricted to loopback/private targets, and should only be enabled to
verify your own or authorized deployments. Exploiting it against a third party
is unauthorized access in most jurisdictions.

## Reporting a vulnerability

If you find a security issue in this project, open a private security advisory
on GitHub (or contact the maintainer listed in the repository metadata) rather
than filing a public issue. Please include a reproducer and the affected
version/commit.
