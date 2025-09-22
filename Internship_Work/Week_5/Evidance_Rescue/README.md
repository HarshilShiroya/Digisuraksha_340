# EvidenceRescue (Prototype)

CLI tool for:
- File carving (signature-based)
- Entropy scanning
- Filesystem parsing (optional, needs pytsk3)
- Report generation

## Quick Start
```bash
python3 evidence_rescue.py make-test-blob --output test_blob.bin
python3 evidence_rescue.py analyze test_blob.bin --output-dir out_scan
python3 evidence_rescue.py carve test_blob.bin --output-dir out_carved
python3 evidence_rescue.py list-carved out_carved/index.json
python3 evidence_rescue.py entropy-scan test_blob.bin --output-dir out_entropy
python3 evidence_rescue.py detect-encrypted out_carved/index.json
python3 evidence_rescue.py report out_carved/index.json --format json --output report_case1
