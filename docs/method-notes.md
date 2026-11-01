# docs/method-notes.md — T0.2 Ghi chú phương pháp CVE-GENIE

> Nguồn: `paper.pdf` (arXiv 2509.01835v2) + mã nguồn `cve-genie/`. Trích dẫn trang ghi dạng (p.N).
> Mục nào chưa chắc đánh dấu **[cần kiểm chứng]**.

## 1. Bối cảnh & vấn đề (p.1–2)

- **Bài toán:** Dataset lỗ hổng chất lượng cao (có exploit kiểm chứng được) rất cần cho nghiên cứu bảo mật (đánh giá fuzzer, vá lỗi, đo năng lực bảo mật của AI), nhưng **khan hiếm** vì tạo ra đòi hỏi công sức thủ công + chuyên môn sâu. Ví dụ: Mu et al. tốn **3.600 giờ, 43 chuyên gia** để tái hiện chỉ 368 lỗ hổng bộ nhớ Linux (p.1).
- **Vì sao khó:** NVD/CVE có hàng trăm nghìn mục nhưng **thiếu** mã nguồn bị lỗi, cách dựng môi trường, exploit, bước xác thực — vì mục đích chính của advisory là cảnh báo admin, và exploit thường được giữ kín vì lý do đạo đức (p.1).
- **Vai trò (role) của hệ thống:** nhận 1 CVE ID → tự động tạo ra một "instance tái hiện được" gồm: môi trường bị lỗi đã dựng lại + exploit/PoC + verifier.

## 2. Công trình liên quan & khoảng trống (p.2–3, Table 1–2)

- Các hướng cũ: **annotation thủ công** (SARD, SVEN, Devign), **chèn bug** (VulChecker), **mining heuristic / SA tool** (Draper, D2A, VUDENC), **tự động từ fuzzer** (ARVO).
- Hạn chế: phạm vi hẹp, nhãn sai, dữ liệu cũ nhanh (DARPA CGC 2016), ARVO chỉ C/C++ memory bug từ OSS-Fuzz.
- **LLM-agent** gần đây mạnh ở SWE/security (PatchPilot, PatchAgent, DARPA AIxCC) → động lực dùng multi-agent cho tái hiện CVE.

## 3. EAGER — 5 tiêu chí của hệ tái hiện lý tưởng (p.3, Table 2)

| Chữ | Tiêu chí | Ý nghĩa |
|---|---|---|
| **E** | Exploit Generation | Tạo exploit/PoC kích hoạt tin cậy lỗ hổng |
| **A** | Assessment | Có "verifier/sanitizer" tự đánh giá exploit có thành công không |
| **G** | Generalization | Tổng quát qua nhiều CWE, ngôn ngữ, loại dự án |
| **E** | End-to-end Automation | Tự động hoàn toàn mọi giai đoạn |
| **R** | Rebuild project | Dựng lại môi trường bị lỗi gốc |

→ Không phương pháp cũ nào thỏa cả 5 (thủ công không scale; ARVO hẹp). CVE-GENIE là hệ **duy nhất** thỏa toàn bộ EAGER (p.3).

## 4. Kiến trúc: 4 module, mỗi module cặp developer↔critic kiểu ReAct (p.3–8, Figure 2)

3 nguyên tắc thiết kế (p.3–4): (1) **Phân rã mô-đun** (LLM kém với context/task dài); (2) **Bền với dữ liệu thiếu** (thiếu trường CVE giảm thành công tới 44% → dựa vào patch/source khi thiếu advisory/PoC); (3) **Tin cậy nhờ tự phê bình** (mỗi module có cặp developer + critic lặp refine).

### 4.1 Processor (p.4–5)
- **Data Processor** (tất định, KHÔNG LLM): tìm repo source qua URL trong cvelist → xác định phiên bản bị lỗi (vd sqlparse v0.4.4) → tải source qua GitHub API. Trích 4 trường từ cvelist nếu có: (1) mô tả CVE, (2) CWE, (3) patch commit (giúp định vị root cause), (4) advisory/PoC (lọc URL theo keyword "security/advisory/bounty…" rồi scrape).
  - *Mã thực tế:* `src/data/scripts/cve_data.py` + `cve_processor.py`. `get_cve_by_id` đọc file cục bộ `cvelistV5/cves/YYYY/Nxxx/CVE.json`; dùng GitHub API lấy tag phiên bản + nội dung patch; Playwright `scrape()` advisory. Điều kiện "✅ Ready to reproduce": có patch_commits + version_data + version tồn tại trên GitHub.
- **Knowledge Builder** (LLM nhẹ = **o4-mini**): chưng cất raw → **knowledge base** có cấu trúc (summary, root-cause, PoC/exploit details, patch). Đây là **long-term memory** cho các agent, chỉ nạp thông tin cốt lõi để tránh tràn context. Nếu advisory không có exploit → agent tự phác thảo exploit sẽ ra sao.
- **Output:** source phiên bản lỗi + cây thư mục + knowledge base.

### 4.2 Builder — dựng lại môi trường (p.5–6)
- **Pre-Requisite Developer** (tool read-only): phân tích & lập kế hoạch setup (phát hiện README sai/thiếu — vd lunary chỉ sai đường .env). Không có agent này, LLM hay bỏ sót chi tiết → setup fail.
- **Setup Developer** (có tool exec): thực thi kế hoạch, cấu hình môi trường.
- **Setup Critic**: đọc log setup, đánh giá, phản hồi để sửa.
- Model thắng (từ DS): **developer = o4-mini** (dựng được 32/60, ~20 tool-call/CVE). claude-3.5-sonnet hay "bỏ cuộc"; gemini-flash & open-model không tin cậy (Qwen mô tả bước mà không gọi tool; gemini-flash lỗi cú pháp tool-call) (p.8).

### 4.3 Exploiter — sinh exploit (p.6–7)
- **Exploit Developer** + **Exploit Critic** vòng ReAct, có tool exec/read/write trong môi trường đã dựng.
- Model thắng (từ 32 setup đúng): **developer = o3** (16 exploit hợp lệ, 3 sửa nhờ critic); **critic = o4-mini** (cân bằng recall/specificity). Chỉ dùng **closed-source làm developer** vì open-model không ổn định (p.11).
- **Output:** `exploit.py`.

### 4.4 CTF Verifier — sinh verifier kiểu CTF (p.7–8)
- **Verifier Developer** (tool read-only — không cho exec, mọi kiểm chứng qua Flag Checker + Critic): sinh script xác minh exploit.
- **Flag Checker** (tất định): chạy verifier + exploit, kiểm tra chạy không lỗi và **in đúng flag** (vd `3xploit66full`). Nếu lỗi/thiếu flag → phản hồi Verifier Developer, lặp tối đa **5 lần**.
- **Verifier Critic** (= **o3**, một mình bắt được lỗi tinh vi): phát hiện verifier **yếu/bypass được** (vd chỉ bắt RecursionError bất kỳ thay vì đúng ở `sqlparse/sql.py`), yêu cầu siết lại.
- **Output:** `verifier.py`. Nếu qua Critic → đánh dấu **reproduced**, lưu VM snapshot + exploit + verifier + metadata (cost, time, toàn bộ hội thoại agent).
- Mô hình "flag": verifier đóng vai challenge CTF — exploit thành công ⇒ in flag bí mật ⇒ exit 0.

## 5. Chọn LLM & kỹ thuật prompt (p.8–12, Table 3)

- Nghiên cứu 10 LLM (o3, o4-mini, Claude 3.7/3.5 Sonnet, Gemini 2.5 Pro/Flash, Llama-4 Maverick, Qwen3, DeepSeek V3/R1) trên **DS = 60 CVE** (sau knowledge-cutoff, 44 CWE, 18 ngôn ngữ, 56 dự án).
- Quy trình 5 bước/module: chọn ứng viên → chấm developer thủ công → thiết kế prompt critic từ lỗi hay gặp → chấm critic → chốt cấu hình.
- **Cấu hình tối ưu:** Knowledge Builder = o4-mini; Builder dev = o4-mini; Exploiter dev = o3, critic = o4-mini; Verifier dev = o3, critic = o3.
- **Phát hiện quan trọng cho đồ án của ta:** open-source LLM (Qwen3, DeepSeek, Llama-4) **không tin cậy ở tác vụ agentic tool-calling** → bị loại khỏi vai developer. (Đây chính là điều T2.x sẽ đo lại trên máy local.)

## 6. Thiết lập đánh giá & kết quả (p.8–17)

- **Baseline (Section 4.1):** gộp tất cả agent thành **1 agent o3 đơn khối** → **không tái hiện nổi dù chỉ 1 CVE** EAGER-style → chứng minh kiến trúc mô-đun là thiết yếu (p.1, p.16–17).
- **Robustness DR (Section 4.3):** bỏ bớt context trên CVE "dễ" (15 CVE, 3 lần/CVE): bỏ advisory → 11/15 (73%); bỏ patch commit → 10/15 (67%); chỉ còn description → 9/15 (60%). Patch commit cho tín hiệu định vị mạnh nhất. Ví dụ 4340 chỉ-mô-tả: 20 phút, $4.50 qua 2 lần chạy (p.13).
- **Large-scale DL (Section 4.4):** 841 CVE (6/2024–5/2025, 186 CWE, 29 ngôn ngữ, 440 dự án; ~49% không có PoC). **Tái hiện 428/841 (~51%)**, phủ 141 CWE, 22 ngôn ngữ, 267 dự án.
  - Theo loại dự án: Library/Framework 72.8%, AI/ML 57.9%, Web/Backend 44.6%; kém nhất Desktop 17.6%, Blockchain 7.7% (binary-heavy khó).
  - **Chi phí TB $2.77/CVE.** Thất bại: ~198 ca do quá-giờ/quá-chi-phí, ~80% là vượt chi phí (kẹt lúc build ~41%, lúc sinh exploit ~59%).
- Chạy mỗi CVE **3 lần lặp** (iteratively) để tăng cơ hội thành công.

## 7. Case study (p.4–8, Appendix H)

- **CVE-2024-4340 (chạy xuyên suốt):** sqlparse < 0.5.0, DoS do đệ quy không kiểm soát (CWE-674). PoC: chuỗi `[`×N + `]`×N đưa vào `sqlparse.parse()` → RecursionError tại `TokenList.flatten()` trong `sqlparse/sql.py`. Verifier in flag `3xploit66full`. Ideal run: **~5 phút, $0.27** (Figure 2).
- **CVE-2024-5129 (Appendix H):** lỗi logic missing-authorization trong lunary-ai — minh họa khả năng xử lý lỗ hổng logic (không chỉ memory bug).

## 8. Điểm mơ hồ cần làm rõ khi thực nghiệm

- Cơ chế "VM snapshot" lưu môi trường — repo công bố scripts + logs, **[cần kiểm chứng]** snapshot ảnh VM có kèm không (RESULTS chỉ nêu scripts/conversations).
- Prompt chính xác từng agent: đọc trong `src/prompts/` khi làm T2.1 để mô phỏng trung thực.
- Con số flag/thời gian trong Figure 2 có sai lệch OCR nhỏ (`3xploit66ful` vs `3xploit66full`).

## 9. Ưu/nhược sơ bộ (sẽ củng cố bằng thực nghiệm ở T2.2)

- **Ưu:** thỏa đủ EAGER; phân rã mô-đun + critic tăng độ tin cậy; verifier chống bypass; tổng quát nhiều CWE/ngôn ngữ; bền với dữ liệu thiếu; chi phí/CVE thấp so với thủ công.
- **Nhược:** phụ thuộc LLM mạnh closed-source (o3/o4-mini) → tốn tiền, khó tái lập nếu không có API; open-model thất bại ở agentic → rào cản cho người ít tài nguyên; DevContainer dễ crash với app nhiều service; ~49% CVE thiếu PoC làm giảm thành công; rủi ro LLM "bịa"/verifier yếu cần critic kiểm soát; kém ở domain binary-heavy (desktop, blockchain).
