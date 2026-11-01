# docs/repro-processor.md — T1.2 Chạy LIVE giai đoạn Data Processor

**Mục tiêu:** Chạy thật phần tất định (không LLM) của pipeline — `cve_data.py` trích xuất dữ liệu CVE từ cvelistV5 + GitHub API + scrape advisory — để chứng minh Processor hoạt động và xử lý được dữ liệu thiếu.

## Thiết lập
- Token: `cve-genie/src/.env` → `GITHUB_TOKEN` (đã gitignore, `git check-ignore` xác nhận).
- Dữ liệu: seed từng JSON CVE vào `src/data/cvelistV5/cves/<year>/<bucket>xxx/` (không clone full cvelistV5).
- Playwright: đã cài Chromium headless (`python -m playwright install chromium`, ~111 MB) để scrape advisory. **Không cài thì `scrape()` lỗi** `BrowserType.launch: Executable doesn't exist` → đây là một prerequisite quan trọng.
- Output lưu ở `repro/processor/<CVE>.json`.

## Cách Processor làm việc (quan sát thực tế)
1. `get_cve_by_id` đọc file cvelistV5 cục bộ → lấy **description + CWE**.
2. Với mỗi **patch commit** trong references: gọi GitHub API lấy nội dung patch (⇒ `software_code_provided`).
3. Nếu CVE có **version_data**: tra GitHub API xem tag phiên bản bị lỗi có tồn tại không (⇒ `software_version_available`), dựng URL tải source `.../archive/refs/tags/<tag>.zip`.
4. Lọc **other_urls** theo keyword (`security/advisory/bounty/issue…`), dùng Playwright **scrape** nội dung advisory.
5. Verdict `✅ Ready to reproduce` khi đủ 3 trường bắt buộc: patch commits + version provided + version available on GitHub.

## Kết quả chạy live

| CVE | code (patch) | version provided | version on GitHub | advisory | Verdict |
|-----|:---:|:---:|:---:|:---:|---|
| CVE-2024-4340 | ✅ | ✅ | ✅ | ✅ | **✅ Ready to reproduce** |
| CVE-2024-4032 | ✅ | ✅ | ✅ | ✅ | **✅ Ready to reproduce** |
| CVE-2024-45390 | ✅ | ✅ | ❌ | ✅ | ⚠️ Missing required data |

## Kiểm chứng chéo (độ tin cậy của Processor)
Dữ liệu **live** của CVE-2024-4340 khớp **chính xác** knowledge base tác giả công bố:

| Trường | Live trích | Authors' cve_info.json |
|---|---|---|
| sw_version | `0.4.4` | `0.4.4` |
| #patch_commits | 1 | 1 |
| #sec_adv | 1 | 1 |
| CWE | CWE-674 Uncontrolled Recursion | (khớp) |

→ Giai đoạn Processor tái lập được, cho ra đúng dữ liệu tác giả dùng.

## Xử lý dữ liệu THIẾU (robustness — paper §4.3)
CVE-2024-45390 bị `⚠️ Missing required data`: trường affected ghi dạng dải `< 1.2.0`, không có **tag phiên bản bị lỗi** cụ thể nên GitHub API trả 404 (`v< 1.2.0 does not exist as a tag`) → `software_version_available = False`.

Theo **PROCESSING.md**, ta bổ sung thủ công 2 trường bắt buộc còn thiếu:
```json
"sw_version": "v1.1.0",
"sw_version_wget": "https://github.com/blakeembrey/js-template/archive/refs/tags/v1.1.0.zip"
```
(Nguồn phiên bản đúng: v1.1.0 — khớp artifact tác giả.) Sau khi vá: đủ trường bắt buộc ⇒ **Ready to reproduce**, và URL source trả **HTTP 200** (tải được). → Minh họa đúng cơ chế *"Robustness to Incomplete Data"*: khi CVE thiếu thông tin, con người (hoặc agent phân tích patch/source) bổ sung để tiếp tục tái hiện.

## Tái lập
```bash
# token đã ở cve-genie/src/.env
cd cve-genie/src
/home/team/NT521.R11.ANTN/env/bin/python ./data/scripts/cve_data.py \
  --cve_id CVE-2024-4340 --output_path /home/team/NT521.R11.ANTN/repro/processor/CVE-2024-4340.json
```

## Nhận xét (đưa vào báo cáo)
- Processor (phần tất định) **đáng tin & tái lập được**; là nền dữ liệu cho mọi module LLM phía sau.
- Điểm dễ vỡ thực tế: (1) phụ thuộc chất lượng record cvelistV5 (version dạng dải → không tra được tag); (2) cần token GitHub + trình duyệt Playwright; (3) scrape advisory phụ thuộc web ngoài. → Phù hợp nhận định của paper rằng ~49% CVE thiếu PoC/dữ liệu và dữ liệu thiếu làm giảm thành công.
