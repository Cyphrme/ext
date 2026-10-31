# Incrementality Rationale

This document explains the rationale behind the Incrementality section of the
[README](../README.md).

Skipping by metadata is a performance heuristic, not an integrity guarantee:
an adversary able to write a file and control its metadata can evade it.
Integrity audits use `ext check --full`.
