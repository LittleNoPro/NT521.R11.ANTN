# docs/bonus-analysis.md — T2.2 Thí nghiệm model LOCAL + cải tiến + biện luận (điểm cộng)

**Mục tiêu:** Dùng agent tối giản (T2.1) chạy trên LLM **local, miễn phí** để kiểm chứng lại phát hiện của paper rằng open-model yếu ở tác vụ agentic, đo định lượng các kiểu lỗi, thử một **cải tiến phương pháp** (prompt engineering) và đo trước/sau trên dữ liệu có sẵn → thỏa "điểm cộng xuất sắc" nhánh *cải tiến phương pháp + thực nghiệm*.

## 1. Thiết lập (free, $0)
- **Model:** Qwen2.5-3B-Instruct (GGUF Q4_K_M, ~1.9GB) — open-weight từ HuggingFace.
- **Runtime:** `llama-cpp-python` build CUDA, nạp **in-process**, offload 37/37 layer lên GPU RTX 3050 6GB (CUDA buffer ~1.8GB). Không HTTP server (tránh lỗi uvicorn trên WSL).
- **Agent:** `local_agent/agent.py` — 1 module Exploiter (developer ReAct + 1 critic), tool chạy trong Docker cô lập (`--network none`, 1GB RAM). Oracle chấm điểm độc lập.
- **Chi phí:** $0 (so với $2.77/CVE của paper với o3/o4-mini). GPU chỉ bận ~6–14s mỗi lần chạy, giải phóng VRAM ngay sau đó.

## 2. Kết quả (ma trận thí nghiệm)

| CVE | Lớp lỗi | variant | success | steps | valid tool-call | malformed | tool_errors | llm_s |
|-----|---------|---------|:---:|:---:|:---:|:---:|:---:|:---:|
| CVE-2024-4032 | logic (IP) | baseline | ✅ **True** | 4 | 4 | 0 | 0 | 6.4 |
| CVE-2024-4032 | logic (IP) | improved | ❌ False | 4 | 4 | 0 | 2 | 12.0 |
| CVE-2024-4340 | recursion DoS | baseline (x3) | ❌ False | 12 | 12 | 0 | 5 | ~13 |
| CVE-2024-4340 | recursion DoS | improved (x2) | ❌ False | 12 | 12 | 0 | 6 | ~14 |

## 3. Phân tích kiểu lỗi (bằng chứng từ transcript)

**Format tool-call: HOÀN HẢO.** Mọi lần chạy đều **valid=steps, malformed=0** → model 3B bám đúng giao thức ReAct text (THOUGHT/ACTION/INPUT). → Đây là **sắc thái bổ sung** cho paper: với giao thức text được ép chặt, open-model nhỏ *gọi tool được* (paper quan sát Qwen "mô tả mà không gọi tool" — khác biệt có thể do họ dùng function-calling chuẩn, còn ta dùng ReAct text đơn giản hơn).

**Nhưng thất bại ở suy luận — 3 kiểu lỗi quan sát ở CVE-2024-4340 baseline:**
1. **Suy luận môi trường sai:** chạy `/work/exploit.py` như shell script → `Permission denied` → `syntax error`; không tự suy ra phải dùng `python3`.
2. **Suy luận bảo mật sai:** payload là `parse(' '*10000)` (khoảng trắng) thay vì **lồng** `[`×N+`]`×N → về bản chất không thể gây đệ quy, dù KB đã nói "deeply nested".
3. **Không thích nghi:** lặp y hệt write+run 4–5 lần theo lỗi, không đổi chiến lược → kẹt tới hết budget (12 bước).

**Ngược lại, CVE-2024-4032 (logic bug đơn giản) baseline THÀNH CÔNG (4 bước):** model viết đúng `ipaddress.ip_address('192.0.0.9').is_private/.is_global`, chạy `./file` lỗi rồi **tự sửa sang `python3`** → ra `False True` → oracle True. (Thú vị: ghi chú `finish` của model tự nói "không exploit được" dù thực tế đã thành công — model không tự đánh giá đúng kết quả của mình.)
→ **Kết luận 1:** model nhỏ *có thể* tái hiện lỗ hổng **tầm thường** (một lời gọi API, không cần payload khéo), nhưng **thất bại** khi cần payload được chế tác + suy luận nhiều bước (recursion DoS).

## 4. Cải tiến phương pháp & đo trước/sau

**Cải tiến (prompt engineering):** thêm 3 chỉ dẫn nhắm đúng 3 lỗi: (a) "chạy file Python bằng `python3 <path>`, đừng chạy trực tiếp", (b) "lỗi recursion cần delimiter LỒNG sâu, không phải khoảng trắng", (c) "nếu lỗi thì đừng lặp lại lệnh cũ".

**Tác động trên CVE-2024-4340 (đo từ transcript improved):**
- ✅ Sửa được lỗi (1): giờ model dùng `python3 /work/exploit.py`.
- ✅ Sửa được khái niệm lỗi (2): model chuyển sang sinh ngoặc lồng (`for i in range(8000): print('[')…`).
- ❌ Vẫn **không thành công** vì (i) lỗi MỚI lộ ra: model nhầm ký tự phân tách `||` của tool `write_file` thành dấu xuống dòng → file Python hỏng cú pháp; (ii) vẫn **lặp không thích nghi** (lỗi 3 chưa khắc phục được chỉ bằng chỉ dẫn).

**Tác động NGƯỢC trên CVE-2024-4032:** baseline ✅ → improved ❌. Chỉ dẫn "payload lồng sâu" vốn dành cho recursion đã **khiến model áp dụng sai** cho một logic bug: nó viết `[192.0.0.9][[[]]][]…` (vô nghĩa) thay vì gọi `ipaddress`. → Prompt cải tiến generic làm **tổng quát kém qua các lớp CWE**.

→ **Kết luận 2 (rất quan trọng):** một prompt "cải tiến" dùng chung cho mọi loại lỗ hổng **lợi bất cập hại** — vá được lỗi lớp này nhưng phá lớp khác. Điều này **giải thích & củng cố trực tiếp lựa chọn thiết kế của CVE-GENIE**: dùng **prompt kỹ-thuật-hoá riêng theo từng module/tác vụ** (§3.5) thay vì một prompt chung, và chọn model mạnh cho từng vai.

## 5. So sánh với paper
| Khía cạnh | Paper (o3/o4-mini) | Thí nghiệm của ta (Qwen2.5-3B local) |
|---|---|---|
| Tái hiện EAGER đầy đủ | 428/841 (51%) | 1 lớp lỗi đơn giản (4032); thất bại ở DoS cần payload (4340) |
| Open-model agentic | "không tin cậy", loại khỏi vai developer | gọi tool được, nhưng suy luận bảo mật/môi trường yếu, không thích nghi |
| Chi phí | $2.77/CVE | $0 |
| Vai trò critic | critic sửa được lỗi developer | thiếu vòng critic-điều-khiển-sửa-lỗi → agent kẹt lặp (khớp: cần critic) |
| Prompt | kỹ-thuật-hoá theo module | prompt generic tổng quát kém qua CWE (khớp: cần prompt riêng) |

## 6. Biện luận ƯU / NHƯỢC điểm của CVE-GENIE (có dẫn chứng thực nghiệm)

**Ưu điểm:**
- **Thỏa đủ EAGER** — là framework duy nhất (Table 2). Verifier kiểu CTF chặt (T1.1/T1.3 cho thấy nó phân biệt được lỗi/vá).
- **Phân rã mô-đun + cặp developer↔critic** là thiết yếu: thí nghiệm của ta cho thấy khi THIẾU vòng critic điều khiển sửa lỗi, agent nhỏ kẹt lặp (lỗi 3) — đúng vấn đề critic giải quyết; và baseline 1-agent o3 của paper không tái hiện nổi 1 CVE.
- **Prompt riêng theo tác vụ** có cơ sở: §4 của ta chứng minh prompt generic phản tác dụng xuyên CWE.
- **Tổng quát** nhiều CWE/ngôn ngữ; **bền** với dữ liệu thiếu (T1.2 cho thấy cơ chế bổ sung dữ liệu).
- **Rẻ hơn thủ công** nhiều bậc ($2.77 vs 3.600 giờ chuyên gia của Mu et al.).

**Nhược điểm:**
- **Phụ thuộc LLM mạnh, closed-source (o3/o4-mini) → tốn tiền, khó tái lập** nếu không có API. Thí nghiệm của ta xác nhận: thay bằng open-model nhỏ miễn phí thì năng lực sụp đổ ở các lỗ hổng không tầm thường.
- **Dựng môi trường là điểm yếu nhất** (T1.1: build markdown-to-jsx fail; paper: ~41% thất bại kẹt ở build). DevContainer dễ crash với app nhiều service.
- **Rủi ro "ảo giác"/đánh giá sai:** model 3B tự nhận "không exploit được" dù đã thành công (và ngược lại) → cần Flag Checker + Verifier Critic để không tin lời tự thuật của developer.
- **~49% CVE thiếu PoC** làm giảm thành công; phụ thuộc chất lượng record cvelistV5 (T1.2: version dạng dải không tra được tag).
- **Kém ở domain binary-heavy** (desktop 17.6%, blockchain 7.7%).

## 7. Giới hạn của thí nghiệm này (trung thực)
- Chỉ 1 module (Exploiter) + 1 model nhỏ + 2 CVE + context 4096 → không phải đánh giá quy mô như paper; nhằm *minh hoạ & kiểm chứng định tính*, không phủ nhận/khẳng định con số 51%.
- Môi trường bị lỗi được dựng sẵn (bỏ qua module Builder) để cô lập năng lực sinh exploit.
- Oracle là heuristic theo từng CVE, không tổng quát.
