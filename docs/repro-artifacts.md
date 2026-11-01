# docs/repro-artifacts.md — T1.1 Tái hiện kết quả từ artifacts đã công bố (Docker, không API)

**Mục tiêu:** Chứng minh exploit + verifier mà CVE-GENIE công bố thực sự chạy được: dựng lại đúng phiên bản phần mềm bị lỗi trong Docker, chạy exploit, verifier in đúng **flag `3xploit66full`** và exit 0. Hoàn toàn **không cần LLM/API** — chỉ dùng các artifact tác giả đã release.

## Kết quả

| # | CVE | Dự án / phiên bản | Ngôn ngữ | CWE | Dựng env | Verifier ra flag? | Khớp paper? |
|---|-----|-------------------|----------|-----|:---:|:---:|:---:|
| 1 | CVE-2024-4340 | sqlparse 0.4.4 | Python | CWE-674 Recursion DoS | ✅ | ✅ `3xploit66full` exit 0 | ✅ |
| 2 | CVE-2024-4032 | CPython 3.8.19 `ipaddress` | Python | IP is_private/is_global | ✅ | ✅ `3xploit66full` exit 0 | ✅ |
| 3 | CVE-2024-45390 | @blakeembrey/template 1.1.0 | Node/JS | CWE-94 Code Injection | ✅ | ✅ `3xploit66full` exit 0 | ✅ |
| 4 | CVE-2024-21535 | markdown-to-jsx 7.3.2 | Node/JS | CWE-79 XSS | ❌ build fail | — | — (xem bên dưới) |

→ **3/4 CVE tái hiện end-to-end thành công**, phủ 2 ngôn ngữ (Python, Node) và 3 lớp lỗi khác nhau (DoS đệ quy, lỗi logic phân loại IP, code injection). CVE-2024-4340 (ví dụ của paper) nằm trong số thành công.

## Cách tái lập

```bash
cd repro/artifacts
./run_all.sh          # build + chạy 3 CVE thành công, in flag mỗi cái
```
Hoặc từng cái:
```bash
docker build -t cve-2024-4340 repro/artifacts/CVE-2024-4340
docker run --rm cve-2024-4340      # -> 3xploit66full
```

Mỗi thư mục `repro/artifacts/<CVE>/` gồm: `Dockerfile`, `exploit.py` + `verifier.py` (copy nguyên từ `cve-genie/results/.../scripts/`), và `verifier_output.log` (kết quả chạy).

## Chi tiết từng CVE

### 1. CVE-2024-4340 — sqlparse (CWE-674)
- Lỗi: đưa chuỗi `[`×N + `]`×N vào `sqlparse.parse()` → đệ quy không kiểm soát tại `TokenList.flatten()` (`sqlparse/sql.py`) → `RecursionError` (DoS).
- Env: `python:3.11-slim` + `pip install sqlparse==0.4.4`.
- Verifier: import exploit, chạy in-process với depth 10 000; chỉ coi là thành công khi (a) đúng `RecursionError` VÀ (b) traceback có `sqlparse/sql.py` → tránh false-positive. In flag, exit 0. ✅

### 2. CVE-2024-4032 — CPython ipaddress
- Lỗi: `192.0.0.9` bị phân loại sai `is_private=False, is_global=True` trên CPython ≤3.8.19 (sửa ở 3.8.20).
- Env: `python:3.8.19-slim`; verifier hardcode interpreter `./python` → ta `ln -s $(which python3) ./python`.
- Sanity: `./python exploit.py 192.0.0.9` → `False True` (đúng hành vi lỗi). Verifier chấp nhận đúng 2 token `("False","True")` → flag, exit 0. ✅

### 3. CVE-2024-45390 — @blakeembrey/template (CWE-94)
- Lỗi: `displayName` không được khử nên code JS chèn vào chạy khi gọi `template()`.
- Env: `node:20-slim` + python3; tải source v1.1.0 từ GitHub, `npm install && npm run build` (ts-scripts) → `dist/`.
- Verifier: chạy exploit với payload chứa sentinel `PWNED_VERIFIER_123456`; thấy sentinel trong output → flag, exit 0. ✅

### 4. CVE-2024-21535 — markdown-to-jsx (CWE-79) — **build thất bại (có chủ đích ghi nhận)**
- Lỗi: thuộc tính `src="javascript:..."` không bị khử → XSS.
- Vấn đề: `npm run build` của v7.3.2 dùng `microbundle` + babel; trên Node 18 lẫn 20, babel báo `SyntaxError: index.cjs.tsx: Missing semicolon (3:23)` khi parse TSX (toolchain cũ không tương thích môi trường npm hiện tại). Log: `CVE-2024-21535/build_failure.log`.
- **Ý nghĩa:** đây đúng là **nguyên nhân thất bại số 1 mà paper nêu** — *dựng lại môi trường* khó hơn sinh exploit (paper: ~41% thất bại kẹt ở bước build; ~49% CVE thiếu dữ liệu setup). Tác giả chạy trong DevContainer có pin toolchain; ngoài môi trường đó, build dễ vỡ. → Minh chứng thực nghiệm tốt cho phần "nhược điểm" (độ bền môi trường, khó tái lập).

## Nhận xét rút ra (đưa vào báo cáo)
- Verifier kiểu CTF của CVE-GENIE **có chất lượng**: không chỉ bắt "có crash", mà kiểm tra đúng loại lỗi + đúng vị trí (4340 kiểm tra traceback chứa `sqlparse/sql.py`; 4032 so khớp chính xác output). Đây là điểm mạnh "Assessment" trong EAGER.
- Artifact công bố **tái lập được** ngoài hạ tầng tác giả cho các CVE đơn giản/thuần ngôn ngữ, nhưng **phụ thuộc toolchain build** cho dự án có bước biên dịch (Node/TS) → củng cố nhận định về độ bền môi trường.
