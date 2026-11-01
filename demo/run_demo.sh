#!/usr/bin/env bash
# =============================================================================
# DEMO CVE-GENIE — tái hiện CVE-2024-4340 (sqlparse DoS) end-to-end, KHÔNG API trả phí.
# Các giai đoạn:
#   (A) Processor LIVE  : trích xuất dữ liệu CVE thật từ cvelistV5 + GitHub
#   (B) Replay artifact : chạy exploit+verifier CVE-GENIE công bố -> ra flag
#   (C) Manual          : exploit+verifier tự viết (+ control bản vá) -> ra flag
#   (D) Agent local     : (tùy chọn) LLM 3B tự thử sinh exploit
# =============================================================================
set -u
ROOT="/home/team/NT521.R11.ANTN"
PY="$ROOT/env/bin/python"
CVE="CVE-2024-4340"
pause(){ echo; read -rp "  [Enter] để chạy giai đoạn tiếp theo..." _; echo; }
hr(){ printf '\n========== %s ==========\n' "$1"; }

hr "DEMO: Tái hiện $CVE (sqlparse <0.5.0, DoS đệ quy — CWE-674)"
echo "Máy: Docker + venv. Không dùng API trả phí."

# ---------------------------------------------------------------------------
pause; hr "(A) PROCESSOR LIVE — trích xuất dữ liệu CVE thật"
if [ -f "$ROOT/cve-genie/src/.env" ]; then
  ( cd "$ROOT/cve-genie/src" && \
    "$PY" ./data/scripts/cve_data.py --cve_id "$CVE" \
      --output_path "$ROOT/repro/processor/${CVE}.json" 2>/dev/null \
      | grep -aE 'saved|required|Optional|Ready|Missing' )
  echo "  -> dữ liệu lưu ở repro/processor/${CVE}.json"
else
  echo "  (bỏ qua: chưa có cve-genie/src/.env với GITHUB_TOKEN)"
fi

# ---------------------------------------------------------------------------
pause; hr "(B) REPLAY ARTIFACT — exploit + verifier CVE-GENIE công bố (Docker)"
docker build -q -t cve-2024-4340 "$ROOT/repro/artifacts/CVE-2024-4340" >/dev/null
echo "  Chạy verifier (kỳ vọng: in flag 3xploit66full, thoát 0):"
echo -n "  FLAG = "; docker run --rm cve-2024-4340; echo "  (exit=$?)"

# ---------------------------------------------------------------------------
pause; hr "(C) MANUAL — exploit + verifier TỰ VIẾT, có control bản vá"
docker build -q -t cve-2024-4340-manual "$ROOT/repro/manual/CVE-2024-4340" >/dev/null
echo "  [bản LỖI 0.4.4]   kỳ vọng ra FLAG, exit 0:"
echo -n "  -> "; docker run --rm cve-2024-4340-manual; echo "     (exit=$?)"
echo "  [bản VÁ 0.5.0]    kỳ vọng KHÔNG flag, exit 1 (chống false-positive):"
docker build -q -t cve-2024-4340-patched "$ROOT/repro/manual/CVE-2024-4340" -f - >/dev/null <<'DF'
FROM python:3.11-slim
RUN pip install --no-cache-dir "sqlparse==0.5.0"
WORKDIR /cve
COPY poc.py verifier.py ./
CMD ["python3","verifier.py"]
DF
docker run --rm cve-2024-4340-patched >/dev/null 2>&1; echo "  -> bản vá bị loại đúng (exit=$?)"

# ---------------------------------------------------------------------------
pause; hr "(D) AGENT LOCAL (tùy chọn) — LLM 3B tự thử sinh exploit"
if [ -f "$ROOT/local_agent/models/Qwen2.5-3B-Instruct-Q4_K_M.gguf" ]; then
  read -rp "  Chạy agent local? (nạp model lên GPU ~15s) [y/N] " ans
  if [ "${ans:-N}" = "y" ]; then
    timeout 600 "$PY" "$ROOT/local_agent/agent.py" --cve "$CVE" --tag demo 2>/dev/null | grep -aE '^\[CVE|CRITIC'
  else echo "  (bỏ qua)"; fi
else
  echo "  (bỏ qua: chưa có model local)"
fi

hr "KẾT THÚC DEMO"
echo "Chi tiết: docs/*.md | Báo cáo: report/report.pdf"
