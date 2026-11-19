# Interpreting hook-detect output

## Status meanings

- `passed`: the requested MCP pipeline finished and post-scan identity checks succeeded. It does not mean every phase had full coverage.
- Module `completed`: requested phases finished without an unexplained comparison gap.
- Module `partial`: some requested evidence was unknown, outside budget, or otherwise not fully comparable.
- Module `gap`: the disk baseline, mapped headers, requested tables, or reads could not be established.
- `target_stable=false`: process sequence or selected module identity changed; do not compare results across that boundary.

## Inline

Patches are discovered by comparing the intersection of disk executable sections and current executable image pages. `inline_candidate` means a complete decoded jump begins at a trusted patch boundary. `entry_return_patch` means a return semantic appears where the disk bytes do not provide it. Ordinary `patch` evidence must not be described as a hook.

`executable_bytes_gap` and `runtime_exec_without_disk_exec` are part of coverage. Never say “no finding” while either indicates unexamined bytes.

## EAT

`equal` covers directory fields, function slots, name-to-index mappings, and forwarder strings that were successfully read. `absent` requires a reliable absent directory. Any damaged, partial, or one-sided directory remains a finding/gap.

## IAT

IAT compares the runtime pointer with an expected address derived from trusted disk imports/exports, target module bases, and resolved forwarders. It is not a raw disk-vs-memory byte diff.

`unresolved_library_or_apiset` and `missing_or_ambiguous_export` are unknown states. The current unique-direct-export fallback is non-authoritative and is labeled `resolved_unique_export`; it cannot turn the phase into full IAT coverage. `iat_pointer_mismatch` is the only direct IAT redirection finding.

## Safety

Reports contain module/path hashes, addresses, sizes, statuses, and instruction summaries—not raw memory. Do not send a report to another host or invoke remediation unless the user explicitly asks for that separate action.
