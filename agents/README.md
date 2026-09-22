# agents/

Working files for coding agents: notes, analyses, plans, and prompts that belong to the
repository rather than to one session.

`AGENTS.md` at the package root is the entry point an agent reads first, and it stays short
enough to read in full. This directory is for everything too long or too specific to live
there: a design note for a subsystem, an analysis of a tricky class, a prompt an agent reuses.

Scratch files that should not be committed go in `/local/`, which is ignored.

`.gitattributes` keeps this directory out of the distributed package.
