# PLAN — Reproduce "CVE-GENIE" (NT521.R11.ANTN đồ án)

## 0. Bài báo

- **Tên:** *From CVE Entries to Verifiable Exploits: An Automated Multi-Agent Framework for Reproducing CVEs* (CVE-GENIE).
- **arXiv:** 2509.01835v2 (12 Feb 2026). **Code công khai:** https://github.com/BUseclab/cve-genie (Apache-2.0).
- **Tóm tắt 1 câu:** CVE-GENIE nhận 1 CVE ID → tự động thu thập dữ liệu, dựng lại môi trường bị lỗi, sinh exploit/PoC và một verifier để xác nhận, dùng kiến trúc đa tác tử (multi-agent) chạy trên nhiều LLM.
- **Con số chính của paper:** tái hiện ~51% (428/841) CVE 2024–2025, chi phí TB **$2.77/CVE**.

### Kiến trúc (4 module, mỗi module có cặp developer + critic theo vòng ReAct)
1. **Processor** — Data Processor (lấy source code + dữ liệu CVE từ cvelistV5/GitHub) + Knowledge Builder (LLM tóm tắt thành knowledge base). *Phần Data Processor KHÔNG cần LLM.*
2. **Builder** — Pre-Requisite Dev + Setup Dev + Setup Critic: dựng lại môi trường dễ bị tấn công.
3. **Exploiter** — Exploit Dev + Exploit Critic: sinh exploit/PoC.
4. **CTF Verifier** — Verifier Dev + Flag Checker + Verifier Critic: sinh verifier kiểm tra exploit (mô hình "flag" kiểu CTF).
- **EAGER** = Exploit · Assessment · Generalization · End-to-end · Rebuild.
- Ví dụ chạy xuyên suốt trong paper: **CVE-2024-4340** (sqlparse < 0.5.0, DoS do RecursionError — CWE-674).

## 1. Ràng buộc & quyết định (đã chốt với user 2026-10-29)

- **Không có API trả phí.** Chỉ dùng model local/miễn phí.
- **Phần cứng:** RTX 3050 **6GB**, RAM 7.6GB, Docker OK, Internet OK, vLLM 0.18 có sẵn, disk 894GB.
  → GPU chỉ tải nổi model ~3–4B quantized. Paper đã cho thấy open-model yếu ở tác vụ agentic này.
- **Hệ quả thiết kế:** *Lõi tái hiện KHÔNG phụ thuộc GPU/API.* Ta tái hiện thí nghiệm bằng **artifacts + full logs tác giả đã công bố** và chạy lại các **script exploit/verifier đã lưu trong Docker**; chạy **live các giai đoạn tất định** (Data Processor, chỉ cần GITHUB_TOKEN free). Phần **local-model = thí nghiệm điểm cộng** để đo đúng "khoảng trống" open-model mà paper nêu.
- **Mục tiêu:** Đạt yêu cầu + điểm cộng xuất sắc (kịch bản/dữ liệu mới + cải tiến).
- **Sản phẩm:** (a) Slide thuyết trình, (b) Báo cáo chi tiết, (c) Demo chạy được, (d) Mã nguồn thực nghiệm.
- **Nhân lực:** cá nhân → các phase chạy tuần tự; trong 1 phase các task độc lập file nên có thể làm song song nếu muốn.

## 2. Phạm vi "tái hiện" (rõ ràng, trung thực)

| Mức | Nội dung | Cần gì |
|-----|----------|--------|
| A. Tái hiện kết quả | Chạy lại exploit+verifier đã công bố cho 3–5 CVE trong Docker, xác nhận flag | Docker (free) |
| B. Chạy live pipeline tất định | Data Processor trích xuất CVE thật | GITHUB_TOKEN (free) |
| C. Hiện thực thủ công | Tự code lại exploit+verifier CVE-2024-4340 (+1 CVE khác) từ đầu | Không cần gì |
| D. Điểm cộng | Agent loop tối giản chạy model local trên CVE dễ **và 1 CVE MỚI** (ngoài tập paper); đo độ tin cậy, so với paper | GPU 6GB / CPU |

## 3. Phases

- **Phase 0 — Nền tảng:** clone repo + dữ liệu, dựng env, đọc hiểu sâu method. (T0.1, T0.2)
- **Phase 1 — Tái hiện thí nghiệm (không API):** replay artifacts (T1.1), Processor live (T1.2), hiện thực thủ công (T1.3).
- **Phase 2 — Điểm cộng:** dựng endpoint model local + agent loop tối giản (T2.1), chạy trên CVE dễ + CVE MỚI, phân tích (T2.2).
- **Phase 3 — Sản phẩm:** báo cáo (T3.1), slide (T3.2), gói demo (T3.3).

Mỗi phase xong: cập nhật mục Status, dọn môi trường, có thể `/clear` trước phase sau (PLAN.md giữ trạng thái).

## 4. Giao diện/quy ước chung (khóa trước khi chia việc)

- Thư mục làm việc:
  - `cve-genie/` — clone upstream (read-only, không sửa trực tiếp; nếu cần sửa thì fork trong `local_agent/`).
  - `repro/artifacts/`, `repro/processor/`, `repro/manual/` — kết quả Phase 1.
  - `local_agent/`, `experiments/` — Phase 2.
  - `report/`, `slides/`, `demo/` — Phase 3.
  - `docs/*.md` — ghi chú kỹ thuật từng task (nguồn sự thật, không chỉ trong chat).
- CVE "dễ" chuẩn để xuyên suốt demo: **CVE-2024-4340** (sqlparse). CVE dự phòng dễ khác sẽ chọn ở T1.1 từ `results/` của repo.
- Mọi lệnh chạy exploit/verifier phải trong Docker container cô lập, KHÔNG chạy exploit trực tiếp trên host.
- Secrets (GITHUB_TOKEN) để trong `cve-genie/src/.env`, không commit.

## 5. Status

| Task | Mô tả | Trạng thái |
|------|-------|-----------|
| T0.1 | Clone repo + dữ liệu + env + kiểm kê artifacts | ✅ xong → docs/setup.md |
| T0.2 | Ghi chú phương pháp chi tiết | ✅ xong → docs/method-notes.md |
| T1.1 | Replay artifacts 3–5 CVE trong Docker | ✅ 3/4 chạy ra flag → docs/repro-artifacts.md |
| T1.2 | Data Processor live | ✅ 2 Ready + 1 Missing (đã vá tay) → docs/repro-processor.md |
| T1.3 | Hiện thực thủ công exploit/verifier | ✅ xong + phát hiện weak-verifier → docs/repro-manual.md |
| T2.1 | Endpoint local + agent loop tối giản | ✅ Qwen2.5-3B in-process trên GPU; agent chạy → local_agent/ |
| T2.2 | Thí nghiệm CVE mới + phân tích điểm cộng | ✅ ma trận 6 run + cải tiến + ưu/nhược → docs/bonus-analysis.md |
| T3.1 | Báo cáo chi tiết (LaTeX) | ✅ report/report.pdf (6 trang) + report.tex + build.sh |
| T3.2 | Slide thuyết trình | ⏭️ hoãn theo yêu cầu user |
| T3.3 | Gói demo chạy được | ✅ demo/run_demo.sh + README (đã test A/B/C) |

## 5b. Ghi chú Phase 0 (đã hoàn thành 2026-10-29)

- Repo clone 425MB. **results/reproduced_cves/ có 429 CVE** tái hiện đủ (exploit.py + verifier.py + cve_info.json + toàn bộ hội thoại agent) → nền tái hiện offline rất mạnh, KHÔNG cần API.
- Mỗi run: `scripts/{exploit,verifier}.py` + `conversations/*` (cve_info.json = knowledge base). Flag mẫu thực tế: `3xploit66full`.
- **Dữ liệu:** không clone cvelistV5 (>300k file); seed từng JSON vào `src/data/cvelistV5/cves/YYYY/Nxxx/`. Processor đọc cục bộ OK, chỉ cần GITHUB_TOKEN cho GitHub API (user cấp ở T1.2).
- Env: `/home/team/NT521.R11.ANTN/env` (đã cài requirements). Playwright browsers chưa cài (chỉ cần khi scrape advisory).
- **5 CVE ứng viên Phase 1:** CVE-2024-4340 (sqlparse/Python/recursion), CVE-2024-4032 (CPython ipaddress), CVE-2024-45390 (Node code-inj), CVE-2024-21535 (Node XSS), CVE-2024-47068 (Rollup — cần xác nhận DOM). Chi tiết: docs/setup.md.
- Cấu hình model tối ưu của paper: KnowledgeBuilder/Builder-dev = o4-mini; Exploiter/Verifier-dev = o3. Baseline 1-agent o3 **không** tái hiện nổi 1 CVE → kiến trúc mô-đun là cốt lõi.

## 5c. Ghi chú Phase 1 (hoàn thành 2026-10-29)

- **T1.1:** 3/4 CVE replay ra flag `3xploit66full` trong Docker (sqlparse, CPython-ipaddress, @blakeembrey/template). CVE-2024-21535 fail ở build toolchain (babel/microbundle) — minh chứng điểm yếu "dựng môi trường". Script: `repro/artifacts/run_all.sh`.
- **T1.3:** tự viết poc+verifier CVE-2024-4340; **phát hiện & sửa lỗi verifier-yếu** (bản vá 0.5.0 chained-exception làm false-positive → sửa bằng xét ngoại lệ cuối). Đúng vấn đề Verifier Critic của paper. Có control bản vá (exit 1).
- **T1.2:** Processor chạy live (token + Chromium). CVE-2024-4340/4032 → Ready; CVE-2024-45390 → Missing data (version dạng dải, không tra được tag) → vá tay theo PROCESSING.md → Ready. Live-extract khớp chính xác knowledge base tác giả.
- Lưu ý: token nằm ở `cve-genie/src/.env` (gitignored). Playwright Chromium đã cài.

## 5d. Ghi chú Phase 2 (hoàn thành 2026-10-29)

- Runtime: `llama-cpp-python` build CUDA, model **Qwen2.5-3B Q4** nạp **in-process** trên GPU (HTTP server llama.cpp bị lỗi uvicorn "Errno -2" trên WSL → bỏ, dùng in-process). Chi phí $0.
- Phát hiện: model 3B **gọi tool đúng format** (valid=steps, malformed=0) — sắc thái khác paper; **thành công** CVE-2024-4032 (logic bug, 4 bước) nhưng **thất bại** CVE-2024-4340 (recursion DoS cần payload khéo), 3 kiểu lỗi: chạy sai (không dùng python3), payload sai (không lồng), không thích nghi (kẹt lặp).
- Cải tiến prompt: vá được 2/3 lỗi trên 4340 (dùng python3 + payload lồng) nhưng chưa thành công (lộ lỗi tool `||` + vẫn lặp); và **phản tác dụng trên 4032** (hint recursion áp sai cho logic bug) → chứng minh vì sao CVE-GENIE cần prompt riêng theo module + model mạnh.
- Dữ liệu: `experiments/*/*.json` (6 run). GPU chỉ bận lúc chạy, VRAM giải phóng sau mỗi lần.

## 5e. Ghi chú Phase 3 (2026-10-29)

- **Báo cáo LaTeX:** biên dịch bằng **lualatex + fontspec + font DejaVu** (tiếng Việt chuẩn, copy-paste được). pdflatex+T5 bị rớt glyph, utf8x vỡ ở section title → chọn lualatex. Phải cài thủ công vào `~/texmf`: luaotfload, lualibs, lua-uni-algos (+ t5enc.def không dùng nữa). Chạy lại: `report/build.sh` (tự set TEXMFHOME=~/texmf).
- **Demo:** `demo/run_demo.sh` 4 giai đoạn (Processor live / replay / manual+control bản vá / agent local tùy chọn). Đã test A/B/C chạy đúng, có pause thuyết trình + phương án offline.
- **Slide (T3.2):** hoãn theo yêu cầu; nội dung đã sẵn trong report + docs nếu cần làm sau.

## 6. Rủi ro & phương án dự phòng

- **Model local quá yếu để làm agent** (nhiều khả năng): vẫn OK — đó chính là phát hiện của thí nghiệm T2.2; lõi điểm (Phase 1) không phụ thuộc nó. Dự phòng: chạy module nhẹ nhất (Knowledge Builder) hoặc single-step prompt thay vì vòng ReAct đầy đủ.
- **cvelistV5 rất lớn:** dùng shallow/sparse clone hoặc tải trực tiếp JSON của CVE cần qua GitHub raw (ghi rõ ở T0.1).
- **DevContainer upstream crash với CVE nhiều service:** chỉ chọn CVE single-process cho mọi phần chạy live.
- **RAM 7.6GB chật:** chạy model qua CPU/quantized nhỏ, hoặc llama.cpp GGUF 3–4B; không chạy song song model + Docker nặng.
