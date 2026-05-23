# Báo Cáo Tiến Độ Đồ Án - Tuần 3 & 4 (02/04 - 13/04)

**Dự án:** Phát hiện Phishing Đa phương thức (Multimodal Phishing Detection)  
**Giai đoạn:** Refactor API production, chuẩn hoá dataset Benign, bổ sung feature nâng cao cho URL module.

---

## 1. Ổn định API & Tích hợp Production (Backend/API)
**File:** `src/api/main.py`, `extension/popup.js`

- **Khắc phục lỗi thiếu dependency**:
  - Fix lỗi `ModuleNotFoundError: No module named 'slowapi'` khi chạy `uvicorn`.
  - Cài `slowapi` đúng vào virtualenv để tránh bị cài nhầm vào user site-packages.

- **Fix lỗi API trả 422 từ Chrome Extension**:
  - Nguyên nhân: Extension có thể gửi URL nội bộ dạng `chrome://...`, `chrome-extension://...` → Pydantic `HttpUrl` chỉ nhận `http/https` → trả `422 Unprocessable Entity`.
  - Giải pháp:
    - **Frontend**: chặn sớm, không gọi API nếu URL không phải `http(s)`.
    - **Backend**: đổi `url` trong schema từ `HttpUrl` sang `str` + validator để trả thông báo rõ ràng “Only http:// and https:// URLs are supported”.

## 2. Chuẩn hoá tập Benign URL (Data Collection) — khớp phân phối thực tế
**File:** `src/data_collection/collect_benign.py`

- **Vấn đề phát hiện**:
  - Tập benign cũ bị “đơn điệu” (đa phần là root domain, thiên về `http://`), không giống thói quen truy cập thực tế (đa số là HTTPS, có path/subdomain).
  - Hệ quả: Model học shortcut (ví dụ phụ thuộc mạnh vào `path_length`) và có thể **false positive** với site benign thực (ví dụ `talosintelligence.com`).

- **Viết lại collector Benign (v3)** theo hướng *đảm bảo số lượng và đa dạng ngay cả khi API bên ngoài fail*:
  - Nguồn **offline** dựa trên Tranco (đảm bảo luôn chạy được):
    - `tranco_root`: domain gốc (mix scheme + www)
    - `tranco_paths`: domain + common subpages (about/contact/login/docs/search/…)
    - `tranco_subdomains`: domain + subdomain phổ biến (`mail.`, `docs.`, `blog.`, `api.`, `app.`, …) + path
  - Nguồn **bonus online**:
    - CommonCrawl CDX và Wayback CDX (có cơ chế **probe** và **fail-fast** để tránh treo hàng giờ khi bị block/rate-limit).
  - Thêm **curated safe URLs** (các URL hợp lệ nhưng phức tạp, gồm cả security sites, SaaS, VN sites) để tăng tính đại diện.

- **Cân bằng số lượng benign/phishing**:
  - Trim và chuẩn hoá để **benign = 15,000 URLs**, khớp với **phishing = 15,000 URLs**.
  - Sampling giữ tỷ lệ các nguồn (fair-share) để tránh lệch phân phối.

## 3. Bổ sung Feature URL nâng cao (Feature Engineering) — giảm FP ngoài tập test
**File:** `src/features/extract_url_features.py`

- **Mở rộng bộ feature URL** từ **69 → 84 features** (thêm 15 features):
  - **TLD reputation**: đánh điểm TLD theo mức độ “hay bị abuse” (ví dụ `.tk`, `.xyz`, `.cfd`…)
  - **Brand impersonation**: phát hiện hostname chứa keyword brand nhưng registered domain không khớp domain thật
  - **Domain linguistic signals**: vowel/consonant ratio, digit/letter ratio, consecutive char ratio, domain_looks_random…
  - **Path structure**: `path_depth`, `path_has_extension`, `path_has_double_ext`
- Mục tiêu: giảm hiện tượng model dựa quá mạnh vào 1-2 feature dạng “shortcut”, tăng khả năng tổng quát hoá với benign URLs thực tế.

---

**Kết quả đạt được (Tuần 3-4):**
- API chạy ổn định với Extension, trả lỗi rõ ràng cho URL không hợp lệ và không còn 422 khó debug.
- Tập benign được nâng cấp cả về **số lượng (15k)** lẫn **đa dạng (HTTPS/path/subdomain)**, giảm lệch phân phối so với thực tế.
- Feature set URL được tăng cường để giảm false positive trên các website benign ngoài tập test.
