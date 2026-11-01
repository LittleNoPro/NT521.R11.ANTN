# docs/setup.md — T0.1 Setup & kiểm kê artifacts

## 1. Môi trường đã dựng

| Thành phần | Giá trị |
|---|---|
| Repo clone | `cve-genie/` (`git clone --depth 1`, 425 MB, 6200 files) |
| Python venv | `/home/team/NT521.R11.ANTN/env` (Python 3.12) |
| Deps đã cài | `cve-genie/src/data/requirements.txt` (requests, python-dotenv, playwright, python-slugify, …) — import OK |
| Playwright browsers | **CHƯA cài** (`playwright install`) — chỉ cần cho việc scrape advisory; để sau, không chặn phần offline |
| Docker | 29.8.0, chạy OK (dùng cho T1.1/T1.3) |
| GPU | RTX 3050 6GB (chỉ cho T2.x) |

## 2. Cấu trúc repo upstream

```
cve-genie/
├── README.md                     # cách chạy (A: extract data, B: run, C: visualize)
├── Dockerfile, .devcontainer/    # môi trường chạy agent
├── src/
│   ├── main.py                   # điểm vào pipeline (cần OPENAI_API_KEY — ta KHÔNG dùng)
│   ├── agents/  agentlib/  prompts/  toolbox/   # cài đặt multi-agent + prompt
│   ├── simulation_environments/
│   └── data/
│       ├── scripts/cve_data.py        # trích xuất dữ liệu 1 CVE  <-- Processor (tất định)
│       ├── scripts/cve_processor.py   # helper: đọc cvelistV5 + gọi GitHub API + scrape
│       ├── PROCESSING.md              # cách bổ sung dữ liệu thiếu thủ công
│       └── example/, ablation/, large_scale/, baseline/
├── results/
│   ├── CVE-2024-4340/             # run mẫu trong paper (Figure 2)
│   ├── reproduced_cves/           # 429 CVE tái hiện thành công (Section 4.4)  <-- MỎ VÀNG offline
│   ├── RESULTS.md, analysis_stats.ipynb, project_types.json
├── visualizer/                   # web app xem lại 1 run (serve.py)
└── vm_library/                   # cách chạy trong VM
```

Kết quả Section 3.5 & 4 đầy đủ (critics_evals, baseline, design_ablation, robustness, large_scale) nằm trên OSF: https://osf.io/dcej4/?view_only=81309bbc7e8c489abb9fb7e40bd1c0fb

## 3. Cấu trúc 1 "artifact run" (mỗi CVE trong results/)

```
<CVE>/
├── scripts/
│   ├── exploit.py        # PoC chạy được
│   └── verifier.py       # verifier kiểu CTF: chạy exploit, nếu đúng lỗi → in FLAG, exit 0
├── log.txt               # log tổng
└── conversations/
    ├── cve_info.json           # KNOWLEDGE BASE: description, cwe, patch_commits, sw_version, sw_version_wget, sec_adv, dir_tree, repo_path
    ├── knowledge_builder.txt   # tóm tắt của Knowledge Builder agent
    ├── repo_builder.json / repo_builder_setup_logs.txt / repo_critic.json   # module Builder
    ├── pre_req_builder.json                                                  # Pre-Requisite agent
    ├── exploiter.json / exploiter_logs.txt / exploit_critic.json             # module Exploiter
    └── ctf_verifier.json / verifier_critic.json                             # module CTF Verifier
```
→ Mỗi CVE thành công có **đủ exploit + verifier + toàn bộ hội thoại agent**. Đây là nền để tái hiện **không cần API** (T1.1) và để phân tích hành vi agent (báo cáo).

**Lưu ý flag thực tế:** script dùng `FLAG = "3xploit66full"` (Figure 2 trong paper in thiếu chữ, "3xploit66ful").

## 4. Chiến lược dữ liệu CVE (không clone cvelistV5 khổng lồ)

- `cve_processor.get_cve_by_id` đọc **file cục bộ** tại:
  `cve-genie/src/data/cvelistV5/cves/<YYYY>/<Nxxx>/<CVE>.json`
  (ví dụ `.../cves/2024/4xxx/CVE-2024-4340.json`).
- cvelistV5 đầy đủ có >300k file → **không clone**. Thay vào đó tải đúng JSON cần qua GitHub raw:
  ```bash
  curl -s -o cve-genie/src/data/cvelistV5/cves/2024/4xxx/CVE-2024-4340.json \
    https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/4xxx/CVE-2024-4340.json
  ```
- Sau khi có file: `cve_data.py` còn gọi **GitHub API** (lấy tag phiên bản + nội dung patch) và **Playwright** (scrape advisory) → cần `GITHUB_TOKEN` trong `cve-genie/src/.env`.
- **Smoke test đã làm:** sau khi seed file, chạy `cve_data.py CVE-2024-4340` đọc được mô tả/CWE và chỉ dừng ở `'GITHUB_TOKEN'` (KeyError) → đường dữ liệu cục bộ hoạt động; chỉ thiếu token (user cấp ở T1.2). PAT read-only `public_repo` là đủ.

## 5. CVE ứng viên cho Phase 1 (single-process, đa dạng ngôn ngữ/CWE)

Đã lọc từ 429 CVE theo heuristic: exploit ngắn, không server/db/socket.

| # | CVE | Dự án / phiên bản | Ngôn ngữ | CWE | Cách dựng | Độ chắc |
|---|-----|-------------------|----------|-----|-----------|---------|
| 1 | **CVE-2024-4340** | sqlparse < 0.5.0 (v0.4.4) | Python | CWE-674 Uncontrolled Recursion (DoS) | `pip install sqlparse==0.4.4` | ⭐ gold, là ví dụ của paper |
| 2 | **CVE-2024-4032** | CPython `ipaddress` ≤3.8.19 | Python (stdlib) | IP is_private/is_global sai | docker `python:3.8` | cao, không cần pip |
| 3 | **CVE-2024-45390** | @blakeembrey/template < 1.2.0 | Node/JS | CWE-94 Code Injection | `npm i` + `node -e` | cao, single-process |
| 4 | **CVE-2024-21535** | markdown-to-jsx < 7.4.0 | Node/JS | CWE-79 XSS | `npm i markdown-to-jsx react-dom` | cao |
| 5 | **CVE-2024-47068** | Rollup < 4.22.4 | Node/JS | CWE-79 DOM Clobbering | exploit in HTML | ⚠️ cần kiểm tra verifier có cần DOM/trình duyệt không (xác nhận ở T1.1) |

**Pool dự phòng** (toàn `import sys`, ngắn, nếu 1 trong 5 fail): CVE-2025-27417, CVE-2024-54152, CVE-2025-1716, CVE-2024-10718, CVE-2024-8572.

> T1.1 sẽ xác nhận cái nào thực sự chạy end-to-end trong Docker; mục tiêu ≥3 CVE (bắt buộc có CVE-2024-4340).

## 6. Việc user cần làm
- Tạo **GitHub Personal Access Token** (classic, scope `public_repo` hoặc fine-grained read-only), đặt vào `cve-genie/src/.env`:
  ```
  GITHUB_TOKEN=ghp_xxx
  ```
  (chỉ cần cho T1.2 chạy Processor live; phần replay artifacts T1.1 KHÔNG cần.)
