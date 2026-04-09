# CloneGuard Demo Recordings

Scripts for recording asciinema demos. Each demo has a setup script that
creates a temporary scenario and a recording script.

## Prerequisites

```bash
brew install asciinema
pip install "cloneguard[mini]"
```

## Recording

Each demo has two scripts:
- `setup-*.sh` — creates the scenario (temp repo with attack payload)
- `record-*.sh` — records the asciinema session

Run setup first, then record. Review the recording, then upload:

```bash
asciinema upload demo-a-clinerules.cast
```

## Demos

1. **Demo A: .clinerules Attack** — malicious instruction file detected on scan
2. **Demo B: Behavioral Sequence** — multi-step exfil caught by SEQ-001
3. **Demo C: Package Hallucination** — non-existent package flagged before install
