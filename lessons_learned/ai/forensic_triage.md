# Forensic Triage — False-Positive Reduction and Safety Invariants

Rules for building tools that triage EDR/AV false positives without
mutating the analyzed artifact. Apply when designing or modifying static
analysis scripts, log parsers, or artifact inspectors in the DFIR
toolkit.

---

### Regression-test every detection keyword against a known-clean file per target format
<!-- tags: false-positive, keyword-list, ooxml, cfbf, xmlns -->

**When:** Writing or editing a detector whose purpose is to **reduce**
false positives from existing tooling (EDR, AV, SIEM), especially any
detector that uses plain-substring keyword matching against file
content.

**Not when:** The tool's purpose is purely forward detection (new IOC
feeds, threat intel matching) where over-firing is acceptable — those
tools operate in a different tradeoff regime.

**Rule:** For every keyword in the detector's list, test against at
least one representative **known-clean** file of each target format
before the tool is declared ready. A false-positive-reduction tool
that reproduces the false-positive class it exists to fight is worse
than no tool — it invalidates the premise and damages analyst trust.

Pay specific attention to:
- **OOXML xmlns namespaces** — every .docx/.xlsx/.pptx contains
  `xmlns="http://..."` declarations in most XML parts. Plain `http://`
  substring match triggers in every benign file.
- **OOXML schema URIs** — similarly `xmlns:r="http://schemas.openxmlformats.org/..."`
  in .rels files.
- **Standard VBA identifiers** — benign VBA code legitimately
  references `Shell`, `Environ`, `CreateObject` for non-malicious
  automation.
- **Standard CFBF stream names** — `WordDocument`, `Workbook`,
  `PowerPoint Document` appear in every respective format; match with
  severity INFO, not ALERT.

```powershell
# WRONG — plain substring match on URL schemes
if ($content -match 'http://|https://') { Add-Finding SUSPICIOUS ... }

# RIGHT — gate to value-attribute context in files known to hold URLs
if ($relPath -like '*.rels' -or $relPath -like '*document.xml') {
    foreach ($scheme in $Script:UrlSchemes) {
        $pattern = '(?:Target|src|Source)\s*=\s*"([^"]*' + [regex]::Escape($scheme) + '[^"]*)"'
        if ($content -match $pattern) { Add-Finding SUSPICIOUS ExternalUrl ... }
    }
}
```

**Why:** Invoke-OfficeDocAnalysis v2 shipped an initial draft where
`http://` was a plain-substring keyword. First real-file test against
a benign `.docx` produced 12 false positives — one per .xml part — and
a SUSPICIOUS verdict on a clean file. This is exactly the
false-positive class the tool exists to disprove; shipping it would
have invalidated the tool's premise. Caught in manual test pre-ship;
the regression-test discipline prevents the class.

**Companions:** forensic_triage.md → "Prove source immutability via hash round-trip in the log", process.md → "Pair real-world + synthetic fixtures when testing pattern detectors"

*Source: phase01:6*

---

### Prove source immutability via hash round-trip in the log
<!-- tags: immutability, copy-then-analyze, contract-in-log -->

**When:** Writing any script whose contract is "will not modify input
file X" and that script will be run on business-critical files.

**Not when:** The script's job is explicitly to transform or annotate
the source (e.g., a renamer, a metadata stripper). Those have
mutation-in-place as part of their contract.

**Rule:** Capture SHA-256 of the source file at script start. Re-hash
the source at every exit path — success, phase gate, outer catch.
Emit a log line that cites the captured value: `VERIFY_OK: Source file
immutability confirmed — SHA-256 unchanged from script start to end
({hash})`. On mismatch, emit FATAL with both hashes and exit 99.

Additionally, route ALL downstream reads through a verified **copy**
of the source in a temp workspace, not the source itself. The copy
pattern makes the immutability contract mechanical (the source handle
is only opened once, for hashing) rather than policy-driven (every
read site audited for write intent).

```powershell
# At Preflight:
$Script:SourceHashSha256Start = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash
# ... copy source to $env:TEMP\workspace\, re-hash copy, verify equality ...

# At SCRIPT_COMPLETE / PHASE_GATE / outer catch:
function Assert-SourceUnchanged {
    $hashNow = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash
    if ($hashNow -ne $Script:SourceHashSha256Start) {
        Write-Log "SOURCE_MUTATED: start=$Script:SourceHashSha256Start | end=$hashNow | ExitCode=99" 'FATAL'
        exit 99
    }
    Write-Log "VERIFY_OK: Source file immutability confirmed — SHA-256 unchanged from script start to end ($hashNow)"
}
```

**Why:** An analyst reading the log should be able to verify the
contract was honored without reading the code. Safety contracts proved
only by inspection are one auditor-turnover away from being silently
broken; contracts proved in every run's log are evidence that travels.
Invoke-OfficeDocAnalysis v2 verified this across 5 end-to-end runs —
every run emitted the confirmation line, hash-before always equaled
hash-after.

**Companions:** forensic_triage.md → "Regression-test every detection keyword against a known-clean file per target format"

*Source: phase01:3, phase01:10*

---

### Pair real-world + synthetic fixtures when testing pattern detectors
<!-- tags: fixture-pairing, false-positive -->

**When:** Testing a pattern-based detector (byte-pattern, keyword,
structural scan) before shipping.

**Not when:** The test subject is purely deterministic and data-
independent (e.g., a pure function over fixed inputs).

**Rule:** Always test against **both**:
1. A **real-world file** of realistic size — catches performance
   regressions, environmental quirks, false-positive surfaces.
2. A **synthetic positive** with the needle at a known location —
   proves the match code path works end-to-end.

Neither alone is sufficient. Real files rarely contain the specific
needle the detector targets (so correctness goes untested). Synthetic
fixtures are too small to stress perf and too clean to surface
false-positive sources.

**Why:** Invoke-OfficeDocAnalysis v2 tested against (a) a real 5.4MB
CFBF MSI and (b) a 5KB synthetic CFBF fragment with a UTF-16LE `VBA`
needle at offset 4096. The MSI revealed the 11-second performance
regression — no synthetic file of that size would have surfaced it.
The synthetic file proved the byte-pattern fix detects at offset 0x1010
— the MSI has no VBA stream, so its correctness path would have been
untested. Either test alone would have shipped broken.

**Companions:** forensic_triage.md → "Regression-test every detection keyword against a known-clean file per target format", process.md → "Prove-first with a 30-second one-liner"

*Source: phase01:4*

---

### Detect encrypted Office packages before claiming CLEAN
<!-- tags: false-positive, encrypted-package, cfbf, ooxml, silent-wrong-answer -->

**When:** Building a static Office document analyzer that returns a
verdict (CLEAN / SUSPICIOUS / MALICIOUS) to a human triager.

**Not when:** The tool is explicitly documented as "valid-plaintext-only"
and refuses encrypted inputs up front. Then no detection is needed —
the tool simply doesn't accept the input class.

**Rule:** Check for encrypted-package stream names FIRST in any CFBF
analysis path, before running expensive keyword or OLE-structure scans.
Password-protected OOXML (.docx / .xlsx / .pptx) is wrapped in a CFBF
outer container, so magic bytes `D0-CF-11-E0` route encrypted OOXML
to the CFBF path, not the OOXML path. Legacy `.doc` / `.xls` with
password use the same stream names. Without this detection, encrypted
ciphertext produces zero findings in every downstream scan and the
tool returns a falsely CLEAN verdict on a password-protected document
that might contain arbitrary hostile content.

Stream names to match (UTF-16LE byte patterns in raw CFBF body):
- `EncryptedPackage` — primary; ECMA-376 Agile Encryption
- `EncryptionInfo` — encryption metadata stream (always present when encrypted)
- `DataSpaces` — protection-scheme registry; DRM/encryption indicator

```powershell
$Script:EncryptedStreamNames = @('EncryptedPackage','EncryptionInfo','DataSpaces')
foreach ($name in $Script:EncryptedStreamNames) {
    $utf16Needle = [System.Text.Encoding]::Unicode.GetBytes($name)
    $offset = Find-BytePattern -Haystack $Script:RawBytes -Needle $utf16Needle
    if ($offset -ge 0) {
        Add-Finding 'SUSPICIOUS' 'EncryptedPackage' "Password-protected — static content analysis not possible" ("offset=0x{0:X}" -f $offset)
        # Escalation: olevba / MSOFFCRYPTO-tool with password
    }
}
```

Verdict floor on hit: **SUSPICIOUS**, not CLEAN. Analyst needs the
password to scan body content; encrypted ciphertext is opaque to all
static tools.

**Why:** `Invoke-OfficeDocAnalysis` originally had no encrypted-package
detection. A password-protected .docx routes to the CFBF analysis path
via magic bytes; OLE-stream / keyword scans find nothing in ciphertext
body; Verdict = CLEAN. This is the exact silent-wrong-answer pattern
that erodes analyst trust — the one .docx a SentinelOne alert flags
might be exactly the one someone encrypted to hide a payload. The
fix is two lines of data (stream name list) plus one new analysis
unit that runs before the expensive scans.

**Companions:** forensic_triage.md → "Regression-test every detection keyword against a known-clean file per target format", forensic_triage.md → "Prove source immutability via hash round-trip in the log"

*Source: phase01:14*
