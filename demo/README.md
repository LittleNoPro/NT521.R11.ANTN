# Demo CVE-GENIE — bấm là chạy

Tái hiện **CVE-2024-4340** (sqlparse < 0.5.0, DoS do đệ quy không kiểm soát, CWE-674)
end-to-end, **không dùng API trả phí**.

## Chạy
```bash
bash demo/run_demo.sh
```
Script dừng chờ `Enter` giữa các giai đoạn để tiện thuyết trình.

## Các giai đoạn & thời lượng ước tính

| GĐ | Nội dung | Kỳ vọng | Thời lượng |
|----|----------|---------|-----------|
| **A** | Processor LIVE trích dữ liệu CVE thật (cvelistV5 + GitHub API) | `✅ Ready to reproduce!!` | ~5–15s |
| **B** | Chạy exploit+verifier **CVE-GENIE công bố** trong Docker | in flag `3xploit66full`, exit 0 | ~5s (sau build) |
| **C** | exploit+verifier **tự viết**; chạy cả bản lỗi và bản vá | bản lỗi: `FLAG{...}` exit 0; bản vá: **bị loại** exit 1 | ~5s |
| **D** | (tùy chọn) agent **LLM 3B local** tự thử sinh exploit | thường thất bại (minh hoạ giới hạn open-model) | ~20–60s + nạp model |

Lần đầu mỗi image Docker cần build (tải base image + cài gói): thêm ~30–60s/giai đoạn.

## Điều kiện tiên quyết
- **Docker** đang chạy.
- **venv** tại `/home/team/NT521.R11.ANTN/env` (đã cài sẵn).
- Giai đoạn **A** cần `cve-genie/src/.env` chứa `GITHUB_TOKEN` + Playwright Chromium (đã cài). Nếu thiếu, GĐ A tự bỏ qua.
- Giai đoạn **D** cần model `local_agent/models/Qwen2.5-3B-Instruct-Q4_K_M.gguf` (đã tải). Nếu thiếu, tự bỏ qua.

## Phương án OFFLINE (mất mạng / không có token)
- Bỏ qua GĐ A (cần mạng). GĐ **B** và **C** chạy offline hoàn toàn *sau khi* các image Docker đã build sẵn một lần (base image `python:3.11-slim` đã có trong cache).
- Dữ liệu Processor đã lưu sẵn ở `repro/processor/CVE-2024-4340.json` để trình bày mà không cần chạy lại GĐ A.

## Thông điệp chính khi demo
1. **B** chứng minh exploit+verifier của CVE-GENIE **thật sự chạy được** (không chỉ là file tĩnh).
2. **C** cho thấy ta **hiểu lỗ hổng** và verifier **chống bypass** (phân biệt đúng bản lỗi vs bản vá) —
   đúng vai trò *Verifier Critic* của paper.
3. **A** cho thấy giai đoạn tất định của pipeline tái lập được, trích đúng dữ liệu tác giả dùng.
4. **D** minh hoạ **vì sao cần model mạnh**: open-model 3B gọi tool được nhưng suy luận yếu.
