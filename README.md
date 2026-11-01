# Reproducing CVE-GENIE — NT521.R11.ANTN

Course project (Secure Programming & Software Vulnerability Exploitation) reproducing the
paper **CVE-GENIE** — *"From CVE Entries to Verifiable Exploits: An Automated Multi-Agent
Framework for Reproducing CVEs"* (arXiv:2509.01835). The paper ships public code
(github.com/BUseclab/cve-genie), so this is the *paper-with-code* track.

**Team:** Dang Minh Tu (24520033), Vo Quang Vu (24522045), Le Tri Duc (24520009) — UIT, VNU-HCM.

Everything here runs **without any paid API**, on a personal machine (RTX 3050 6 GB, Docker).

## What's inside
| Path | What |
|------|------|
| `report/` | Detailed report (IEEE/RIVF 2-column LaTeX) → `report/report.pdf` |
| `repro/` | Reproduction: `artifacts/` (replay published exploit+verifier in Docker), `processor/` (live Data Processor), `manual/` (our own exploit+verifier) |
| `experiments/` | Local-LLM agent runs + `corpus_analysis.py` (aggregate verification over 429 artifacts) |
| `local_agent/` | Minimal Exploiter agent (Qwen2.5-3B/7B, in-process llama.cpp) |
| `demo/` | `run_demo.sh` — interactive end-to-end demo |
| `docs/` | Method notes, reproduction notes, analysis |
| `cve-genie/` | The authors' cloned repo (code + 429 reproduced-CVE artifacts) |

## Quick start (one command each)
```bash
make corpus     # recompute the paper's $2.77/CVE and CWE/language spread from 429 artifacts
make replay     # replay published exploit+verifier in Docker (3 CVEs print the flag)
make manual     # our hand-written exploit+verifier + the patched-version control
make report     # build report/report.pdf
make demo       # interactive demo for the presentation
```
Local-LLM extra-credit experiments:
```bash
make agent-3b CVE=CVE-2024-4340      # Qwen2.5-3B
make agent-7b CVE=CVE-2024-4340      # Qwen2.5-7B (partial GPU offload)
```

## Key results
- **Replay:** 3/4 CVEs reproduce end-to-end to the flag in isolated Docker; the 4th fails at
  *build*, matching the paper's dominant failure mode.
- **Corpus verification:** our recomputed mean cost is **$2.767/CVE**, matching the paper's
  reported **$2.77** almost exactly (across 429 artifacts, 125 CWEs, 10 languages).
- **Local-LLM study:** a small open model produces well-formed tool calls but fails the
  security *reasoning*; a single shared "improved" prompt helps one CWE class and breaks
  another — reinforcing CVE-GENIE's per-module engineered prompts.

## Prerequisites
- Docker running; the `./env` virtualenv (Python deps + Playwright Chromium already installed).
- `make corpus`/`replay`/`manual`/`report` are fully offline after images are cached once.
- `make processor` needs `cve-genie/src/.env` with a free `GITHUB_TOKEN`.
- `make agent-*` needs the GGUF model(s) under `local_agent/models/`.
- Report build needs `lualatex`; `report/build.sh` sets `TEXMFHOME=~/texmf`.
