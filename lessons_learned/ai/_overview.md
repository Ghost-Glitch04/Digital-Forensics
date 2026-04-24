# AI Subject Files — Overview

Router for structured-recall lookups. Identify the relevant topic file
by keyword, then read the 1-2 targeted files for actionable When/Rule
content.

## How to use

1. `grep -i "{keyword}" _overview.md` — find candidate topic files
2. Read the matched file(s); scan `### Rule Title` headings
3. For each candidate rule, read `**When:**` / `**Not when:**` / `**Rule:**`
   in isolation
4. Apply the rule if the trigger matches your current task; skip if a
   Not-when condition matches

## AI Subject Files

| File | Rules | Topics / keywords |
|---|---|---|
| [powershell.md](powershell.md) | 6 | powershell, string-escape, byte-scan, performance, parse-check, array-indexof, hex-escape, interpreted-loop, file-encoding, bom, dotnet-version, ps51 |
| [forensic_triage.md](forensic_triage.md) | 4 | false-positive, keyword-list, immutability, copy-then-analyze, fixture-pairing, contract-in-log, ooxml, cfbf, xmlns, encrypted-package, silent-wrong-answer |
| [process.md](process.md) | 5 | prove-first, plan-mode, askuserquestion, benchmark-first, plan-first, discriminator-questions, switch-design, cli-ergonomics, retry, call-site-audit, idempotency |

## Cross-file conventions

- Primary rule lives in the file whose primary technology / concern
  matches the rule. Cross-cutting rules appear as one-line See references
  in secondary files under `## See Also`.
- `Companions:` links are mutual (if A → B, then B → A).
- `*Source:*` pointers use `{phase_id}:{entry_N}` format.
