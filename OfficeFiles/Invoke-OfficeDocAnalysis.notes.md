# Invoke-OfficeDocAnalysis — Development Notes

Session-resumption anchor. Read this **before** modifying the script.
Captures failures, edge cases, and load-bearing design decisions that
aren't obvious from the current code. Entries are append-only.

Schema (per scripting-standards-v5.3 troubleshooting.md):

```
### [YYYY-MM-DD] Attempt N — Brief description
Tried : Specific approach (reproducible)
Result: FAILED | SUCCESS
Reason: Root cause, not symptom
Next  : What changes (for FAILED only)
```

---

## Development Notes

### [2026-04-24] Attempt 1 — v1 → v2 full rewrite to standards template
Tried : Replace 768-line v1 (partially broken) with standards-compliant
        rewrite: phased template, source-immutability contract via temp
        copy + SHA-256 re-verification, JSON findings output, RTF path,
        XLM macro detection, OOXML template-injection detection.
Result: SUCCESS
Reason: Prove-first check on UTF-16LE byte encoding (30 seconds) confirmed
        the byte-pattern scan approach before the full unit was built.
        End-to-end verification against three real OOXML files, one real
        CFBF MSI, and one synthetic CFBF VBA-needle fragment. Source hash
        unchanged across all runs; immutability assertion in log on every
        exit path.

### [2026-04-24] Attempt 2 — Initial OOXML keyword scan was over-eager
Tried : Treat URL schemes (http://, https://, ftp://) as plain-substring
        SuspiciousKeyword hits the same way as VBA/LOLBin keywords.
Result: FAILED — benign .docx scored SUSPICIOUS with 12 findings.
Reason: Every clean OOXML file contains the xmlns namespace declaration
        `xmlns="http://schemas.openxmlformats.org/..."` in at least every
        .xml part. Plain-substring match produced one false positive per
        XML file per URL scheme. This is *exactly* the SentinelOne false-
        positive problem the script was built to disprove.
Next  : Moved URL schemes to a separate $Script:UrlSchemes list. In the
        OOXML path, URLs are only flagged when matched inside value
        attributes (Target=, src=, Source=) of .rels files or in specific
        content parts (word/document.xml, xl/sharedStrings.xml). In the
        CFBF path, URL schemes remain plain-substring because that format
        has no xmlns namespace problem and VBA-embedded URLs are a real IOC.

### [2026-04-24] Attempt 3 — Find-BytePattern naive PS loop too slow on MSIs
Tried : Pure-PowerShell nested-for-loop byte scan (i=0..len-needle,
        j=0..needle) to find UTF-16LE stream-name needles in CFBF bodies.
Result: FAILED (performance) — 5.4MB MSI took 11.2s in the Analysis phase
        alone (OLEStream + AutoExec + XLMMacros units combined).
Reason: Interpreted PS loops iterate ~1M bytes/sec. With ~25 needle scans
        per CFBF analysis pass (6 OLE + 16 auto-exec ASCII+UTF16 + 8 XLM
        indicators), the naive O(n·m) scan compounds into double-digit
        seconds for modestly-sized files. Unacceptable for a triage tool.
Next  : Replaced inner scan with [Array]::IndexOf($Haystack, $first, $pos)
        to jump to candidate first-byte positions, then verify remaining
        bytes in a short loop. Prove-first benchmark on 5MB buffer:
          Naive PS loop:        1.152s
          Latin-1 IndexOf:      0.042s  (27× faster)
          Array.IndexOf+verify: 0.017s  (68× faster) ← selected
        Post-fix MSI total: 1.118s (down from 12.015s, 10.7× faster).
        Correctness re-verified on synthetic VBA-needle: offset=0x1010 match.

### [2026-04-24] Attempt 4 — PowerShell 5.1 compatibility test (CF-5)
Tried : Run the 4-fixture verification suite (parse + benign .docx + benign .xlsx
        + 5.4MB CFBF MSI + synthetic CFBF VBA-needle) under `powershell.exe`
        (Windows inbox PS 5.1.26100) instead of `pwsh.exe` (7.6.0) which was
        the only runtime used in v2 development.
Result: FAILED on first attempt, surfaced TWO distinct PS 5.1 incompatibilities:
        (1) Parser emitted 20 cascading errors starting at line 496 despite
            clean parse on PS 7. Root cause: script was written without a
            UTF-8 BOM. PS 5.1 reads .ps1 files as Windows-1252 when no BOM
            is present; the 50 em-dashes (U+2014, 3 UTF-8 bytes) in the
            script's comments and log messages were mis-decoded as 3-character
            garbage sequences, corrupting the token stream. PS 7 reads UTF-8
            by default so it parsed cleanly.
        (2) After BOM fix, CFBF Extract-CFBFBinary unit failed at line 603
            with "The property 'Latin1' cannot be found on this object."
            Root cause: [System.Text.Encoding]::Latin1 static property was
            added in .NET Core 5+. PS 5.1 runs on .NET Framework 4.x where
            the equivalent is [System.Text.Encoding]::GetEncoding(28591)
            (ISO-8859-1 code page). PS 7 runs on .NET 8 where ::Latin1 works.
Reason: v2 was developed entirely on PS 7 / .NET 8. Neither trap surfaces
        until the script runs on the Windows-default PS 5.1. Both are silent
        in the author's environment.
Next  : (completed) Added UTF-8 BOM via `[System.IO.File]::WriteAllText` with
        UTF8Encoding(true). Replaced ::Latin1 with ::GetEncoding(28591).
        Re-verified all 4 fixtures on BOTH runtimes:
          PS 5.1: T1/T2 CLEAN, T3 SUSPICIOUS, T4 MALICIOUS (VBA@0x1010)
          PS 7.6: T1/T2 CLEAN, T3 SUSPICIOUS, T4 MALICIOUS (VBA@0x1010)
        Performance: MSI analysis 9.2s on PS 5.1 vs 1.0s on PS 7 — acceptable
        for triage; .NET Framework 4.x Array methods are ~9× slower than .NET 8.

### [2026-04-24] Attempt 5 — Copy-Item retry wrapper partial fix (CF-7)
Tried : Wrap the single `Copy-Item` call in `Copy-SourceSafely` with
        Invoke-WithRetry (3 attempts, 2s base backoff). Build a locked-
        source harness that holds exclusive read-write lock for 5 seconds.
Result: FAILED first run. Script exited 20 at `Compute-SourceHashes`
        (line 494) BEFORE reaching the wrapped Copy-Item.
Reason: `Compute-SourceHashes` runs earlier in Preflight and does three
        Get-FileHash reads against the original source. A locked source
        fails there too. CF-7 as originally scoped ("retry on Copy-Item")
        was a partial fix; the real requirement is "retry on any source
        read during Preflight".
Next  : (completed) Wrapped Compute-SourceHashes hash block in
        Invoke-WithRetry as well. Get-FileHash is idempotent-read, safe
        to retry. All source-reading sites now retry: Compute-SourceHashes
        (3 hashes in one retry block), Copy-SourceSafely (1 copy).
        Assert-SourceUnchanged at script end already had catch-and-WARN
        demotion so it's acceptable without retry. Locked-source harness
        post-fix: script retries at t=0/2/6s, succeeds on attempt 3 at
        ~7s total. Verified on BOTH PS 5.1 and pwsh 7.6.

### [2026-04-24] Attempt 6 — EncryptedPackage detection (CF-8)
Tried : Add new `Detect-EncryptedPackage` unit to CFBF analysis path,
        running BEFORE expensive keyword/OLE scans. Uses Find-BytePattern
        to search raw bytes for UTF-16LE stream names: EncryptedPackage,
        EncryptionInfo, DataSpaces. Emits SUSPICIOUS finding + escalation
        note on hit.
Result: SUCCESS on first try (prove-first paid off: understood the CFBF
        container encapsulation ahead of implementation).
Reason: Password-protected OOXML is wrapped in a CFBF outer container
        with an EncryptedPackage stream — so magic bytes D0-CF-11-E0
        route it to CFBF analysis, not OOXML. Without detection, downstream
        scans find nothing in ciphertext → falsely CLEAN verdict on a
        document that may contain arbitrary hostile content. New unit
        closes this silent-wrong-answer path.
Next  : (none — landed clean) Test fixture: synthetic CFBF header +
        pad + UTF-16LE 'EncryptedPackage' bytes + fake ciphertext.
        Verdict on fixture: SUSPICIOUS with [EncryptedPackage] finding.
        Real password-protected .docx / .doc corpus fixture deferred
        to Phase 7 test scaffolding (CF-1).

---

## Edge cases discovered during testing

- **.msi files are CFBF** — the D0-CF-11-E0 magic byte matches MSI in
  addition to .doc/.xls/.ppt. Including .msi in the CFBF `expectedExtensions`
  list prevents a spurious extension-mismatch warning for Windows Installer
  packages. MSIs don't contain VBA/Workbook streams; OLEStream unit
  legitimately returns zero findings for them.

- **MSIs frequently contain http://, https://, Shell, Decode** as plain
  binary content (product page URLs, installer UI strings, Windows Shell
  API references). Current CFBF keyword list will produce SUSPICIOUS
  verdicts on most MSIs. Acceptable because MSIs outside a known-safe
  source are worth a second look anyway, but if triage fatigue becomes
  a problem, consider gating the CFBF keyword scan behind a `-Strict`
  flag or excluding .msi files at the format-detect stage.

- **RTF with .doc extension** — real-world phishing pattern. Script
  correctly routes to RTF analysis path via magic bytes (not extension)
  and flags extension-format mismatch as VERIFY_WARN.

- **Source LastWriteTime drift** — AV scanners may touch the file's
  metadata timestamp without modifying bytes. Immutability check treats
  LastWriteTime drift as WARN (not FATAL) since the SHA-256 comparison
  is the authoritative bytes-unchanged check.

- **$env:COMPUTERNAME not set on non-Windows PowerShell** — the script
  falls back to [System.Net.Dns]::GetHostName() (cross-platform pattern
  from scripting-standards-v5.3 powershell.md line 238). Matters if the
  script is ever run on Linux/macOS pwsh.

---

## Design invariants (do not break without an entry in this file)

1. **Source file is never opened with write/delete intent.** Every read
   is either Get-FileHash (read-only) or via the temp copy. Violation of
   this invariant defeats the script's entire premise.

2. **Immutability assertion runs on every exit path** — success, phase
   gate, and unhandled catch. Remove it and the contract becomes
   unprovable from the log.

3. **Magic-byte detection is ground truth, extension is decoration.** Do
   not bypass Detect-FileFormat to dispatch on $FilePath.Extension —
   attackers rename files; bytes don't lie.

4. **Findings list is an in-memory accumulator.** Do not flush to disk
   mid-Analysis; Write-JsonReport is the only consumer, and it runs after
   Build-FindingsSummary has computed the verdict.

5. **Workspace cleanup is best-effort, never blocking.** A cleanup
   failure should not mask a successful analysis. It's WARN, not FATAL.

6. **The script must survive on read-only input.** Copy-Item copies a
   read-only source fine; don't add operations that would fail on files
   marked Read-Only or on shares with DENY write.

---

## Known scope boundaries (escalate rather than extend)

The script is a **triage** tool. It does not attempt:

- VBA decompression / deobfuscation (escalate to `olevba` from oletools)
- RTF OLE object extraction (escalate to `rtfobj`)
- XLM macro decoding (escalate to `XLMMacroDeobfuscator`)
- Sandbox execution or dynamic analysis (use FLARE VM or a proper sandbox)
- Reputation lookup / VT API calls (the hashes are logged; analyst can
  paste into VT manually or script their own lookup)
- Deep PE analysis on embedded executables (the MZ header detection is
  a tripwire, not a disassembler — escalate to PE-bear / CFF Explorer)
