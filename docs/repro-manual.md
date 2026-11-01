# docs/repro-manual.md — T1.3 Hiện thực THỦ CÔNG exploit + verifier

**Mục tiêu:** Tự tay viết lại PoC + verifier cho CVE-2024-4340 (không copy từ CVE-GENIE), chạy trong Docker, để (a) chứng minh hiểu rõ lỗ hổng độc lập với pipeline, (b) đối chiếu với artifact của tác giả. File: `repro/manual/CVE-2024-4340/{poc.py,verifier.py,Dockerfile}`.

## Lỗ hổng (nhắc lại)
sqlparse < 0.5.0 phân tích biểu thức lồng nhau bằng **đệ quy** (`TokenList.flatten` trong `sqlparse/sql.py`). Input `[`×N + `]`×N đủ sâu → vượt giới hạn đệ quy Python → `RecursionError` không được bắt → **DoS** (CWE-674).

## Cách chạy & kết quả
```bash
cd repro/manual/CVE-2024-4340
docker build -t cve-2024-4340-manual .
docker run --rm cve-2024-4340-manual     # -> FLAG{cve-2024-4340_sqlparse_uncontrolled_recursion}, exit 0
```

| Phiên bản | Kỳ vọng | Kết quả |
|---|---|---|
| sqlparse **0.4.4** (lỗi) | in flag, exit 0 | ✅ `FLAG{...}` exit 0 |
| sqlparse **0.5.0** (vá) — control | KHÔNG flag, exit 1 | ✅ exit 1 |

## Phát hiện quan trọng: verifier YẾU bị false-positive (và cách khắc phục)

Phiên bản verifier **đầu tiên** của tôi kiểm tra kiểu: `"RecursionError" in stderr AND "sqlparse/sql.py" in stderr AND returncode != 0`.
→ Khi test trên bản **đã vá 0.5.0**, verifier **vẫn in flag** (false-positive!).

**Nguyên nhân:** bản vá 0.5.0 không bỏ lỗi mà **bắt `RecursionError` rồi raise lại `SQLParseError('Maximum recursion depth exceeded')`** (sql.py:220, `... from err`). Vì là *chained exception*, traceback bản vá **vẫn chứa** chuỗi `RecursionError` và `sqlparse/sql.py` → điều kiện substring lỏng lẻo bị qua mặt.

**Khắc phục (chống bypass):** xét **ngoại lệ CUỐI CÙNG** thực sự thoát ra, không xét substring:
- Bản lỗi → ngoại lệ cuối = `RecursionError` (DoS không kiểm soát) ⇒ thành công.
- Bản vá → ngoại lệ cuối = `sqlparse.exceptions.SQLParseError` (có kiểm soát, không phải DoS) ⇒ loại.

Sau khi sửa: bản lỗi ✅ ra flag, bản vá ✅ bị loại (exit 1). Đây là một **phân biệt lỗi/vá** đúng nghĩa.

### Ý nghĩa cho đồ án
Đây chính xác là vấn đề **"verifier yếu / bypassable"** mà **Verifier Critic** trong CVE-GENIE sinh ra để bắt (paper §3.4.3, Figure 4: verifier yếu bị sửa nhờ critic feedback). Tôi đã **tự mình gặp và tự sửa** đúng lớp lỗi đó → minh chứng sống động rằng vòng developer↔critic của paper giải quyết vấn đề có thật, không phải trang trí.

## So sánh bản thủ công vs bản CVE-GENIE

| Khía cạnh | Bản tác giả (CVE-GENIE) | Bản thủ công của tôi |
|---|---|---|
| PoC payload | `[`×N + `]`×N (giống) | `[`×N + `]`×N (giống) |
| Cách verifier chạy exploit | **in-process** (import module, bắt exception trực tiếp) | **subprocess** (cô lập tiến trình, đọc stderr) |
| Tiêu chí thành công | RecursionError + traceback chứa `sqlparse/sql.py` | ngoại lệ **cuối** = RecursionError + từ `sqlparse/sql.py` + **loại SQLParseError** |
| Chống bypass bản vá | có (kiểm vị trí lỗi) | có (kiểm **loại ngoại lệ cuối**) — chặt hơn ở ca bản vá chained-exception |
| Flag | `3xploit66full` | `FLAG{cve-2024-4340_...}` |

→ Hai cách thiết kế verifier khác nhau (in-process vs subprocess) nhưng cùng tinh thần EAGER-Assessment. Bản tác giả dùng in-process nên nếu test trên 0.5.0 sẽ bắt được `SQLParseError` (khác type) ngay — cũng không bị false-positive; cách của tôi đạt cùng mục tiêu qua đường subprocess.

## (Tùy chọn, chưa làm) CVE thứ hai
Có thể lặp cho CVE-2024-4032 (logic bug, rất nhanh) nếu cần thêm; hiện ưu tiên chất lượng ca 4340 với phát hiện weak-verifier ở trên.
