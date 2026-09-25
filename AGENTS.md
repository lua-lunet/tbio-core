# AGENTS.md

## Release tags

Release tags are `YYYY.MM.DD-${sha}`: the date the tag is cut (UTC) and the
short sha of the tagged commit, separated by a hyphen — for example
`2026.09.25-a5edfd3`. The sha in the name is always the sha the tag points
at, so the name identifies the exact commit without dereferencing.

- Tags are annotated and are cut on `main` commits only; a release tag
  names a commit that is on `main`.
- The legacy `v0.17.9-lunet.*` series predates this convention and remains
  as published; no new tags follow it.
