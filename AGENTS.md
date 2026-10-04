# AGENTS.md

## The Rust toolchain pin does not move

SCREAMING: DO NOT MOVE ANYTHING. The repo pins `rust-toolchain.toml` to
`1.96.0` and that pin is load-bearing, not hygiene. macOS XProtect scans
every freshly linked executable on first exec, one at a time, through
syspolicyd; the Developer Tools privilege exempts binaries whose parent app
chain is granted, and that exemption holds only while the toolchain home
never moves. A routine bump, a channel switch, or a `rustup update`
relocates every build binary and re-triggers the whole scan tax
(15-59 seconds per fresh test binary; roughly twenty minutes of scanning
per full suite for under a minute of test execution). A toolchain move is
an operator ruling; agents never bump it, and `rustup update` is never run
on a working checkout. Sibling repos in the lua-lunet family pin the
same channel so the family shares one non-moving toolchain home.

## Release tags

Release tags are `YYYY.MM.DD-${sha}`: the date the tag is cut (UTC) and the
short sha of the tagged commit, separated by a hyphen — for example
`2026.09.25-a5edfd3`. The sha in the name is always the sha the tag points
at, so the name identifies the exact commit without dereferencing.

- Tags are annotated and are cut on `main` commits only; a release tag
  names a commit that is on `main`.
- The legacy `v0.17.9-lunet.*` series predates this convention and remains
  as published; no new tags follow it.
