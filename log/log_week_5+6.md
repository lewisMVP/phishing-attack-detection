# Báo Cáo Tiến Độ Đồ Án - Tuần 5 & 6 (14/04 - 21/04)

**Dự án:** Phát hiện Phishing Đa phương thức (Multimodal Phishing Detection)  
**Giai đoạn:** Tái cân bằng dataset URL theo phân phối thực tế, tăng độ chống chịu XGBoost, tối ưu threshold theo ngân sách FPR < 5%.

---

## 1. Tái cân bằng dataset URL (Benign >> Phishing) để giảm False Positive
**File:** `notebook/train_url.ipynb`

- **Vấn đề phát hiện**:
  - Dataset URL đang cân bằng cứng **15k benign / 15k phishing** → không giống thực tế (benign chiếm đa số).
  - Khi train theo phân phối cân bằng, model dễ “nhạy” quá mức với pattern giống phishing → tăng FP khi deploy.

- **Giải pháp triển khai**:
  - **Downsample phishing**: giảm từ 15,000 xuống **10,000** (giảm tác động nhiễu/độ trùng và tránh overfit vào nguồn phishing chiếm đa số như PhishTank).
  - **Tăng benign theo hướng “hard negatives”**:
    - Mở rộng danh sách **hard safe URLs** (URL hợp lệ nhưng phức tạp, có subdomain/path/query dài, chứa keyword kiểu `login/secure/verify/account`, payment/checkout, SaaS console, cloud console, shortener phổ biến…).
    - **Oversample hard safe URLs** (nhân bản nhiều lần) để tăng trọng số học cho các benign “trông đáng ngờ”.
    - Tự động lọc trong benign gốc các URL chứa keyword nhạy (`login|secure|verify|account|signin|auth|password|wallet`) và **boost** (nhân bản) để giảm lỗi FP do keyword.

- **Kết quả mong đợi**:
  - Phân phối mới gần thực tế hơn: **benign > phishing** → FPR giảm ổn định hơn ngoài tập test.
  - Model học rõ ràng hơn rằng: “URL dài + nhiều query + keyword đăng nhập” vẫn có thể là benign.

## 2. Tăng độ chống chịu cho XGBoost (regularization + stochastic training)
**File:** `notebook/train_url.ipynb`

- **Mục tiêu**: giảm overfitting, tăng khả năng tổng quát hoá khi benign pool lớn và đa dạng hơn.

- **Thay đổi chính trong cấu hình XGBoost**:
  - **Giảm độ phức tạp cây**: `max_depth` thấp hơn, thêm `min_child_weight`, `gamma > 0` để tránh split theo nhiễu.
  - **Stochastic boosting**: bật `subsample`, `colsample_bytree`, `colsample_bylevel`, `colsample_bynode` (< 1.0) để giảm variance.
  - **Regularization mạnh hơn**: tăng `reg_alpha` (L1) và `reg_lambda` (L2).
  - **Early stopping “kiên nhẫn” hơn**: tăng `early_stopping_rounds`, giảm `learning_rate` và tăng `n_estimators` để học ổn định.
  - **Xử lý mất cân bằng theo ratio mới**:
    - `scale_pos_weight` không dùng tỉ lệ thô `neg/pos`, mà dùng dạng **dampened** (ví dụ sqrt) để tránh kéo model quá mạnh về lớp phishing (gây tăng FP).

## 3. Tối ưu threshold theo ngân sách FPR < 5% (không “peek” test)
**File:** `notebook/train_url.ipynb`


- **Thay đổi mục tiêu vận hành**:
  - Trước đây notebook đặt target FPR chặt (ví dụ 1%), nay đổi theo yêu cầu vận hành: **FPR < 5%** là chấp nhận được.

- **Quy trình threshold đúng chuẩn đánh giá**:
  - **Chọn threshold trên Validation set** để thoả **FPR ≤ 5%** và tối đa hoá **Recall/TPR**.
  - **Cố định threshold** đó và đánh giá lại trên **Test set** để có ước lượng FPR/TPR “unbiased”.

## 4. Thiết kế lại UI Chrome Extension (tối ưu trải nghiệm & tính “production-ready”)
**File:** (UI Extension) `extension/popup.html`, `extension/popup.css`, `extension/popup.js` *(tuỳ cấu trúc repo)*

- **Vấn đề với UI cũ**:
  - Layout và style còn “prototype”, độ nhất quán thị giác chưa cao (spacing, border-radius, typography).
  - CTA (nút “Scan Website”) chưa thật sự nổi bật, cảm giác tin cậy/“AI powered” chưa rõ ràng.
  - Trải nghiệm hiển thị URL hiện tại chưa tối ưu (dễ bị dài/tràn, khó đọc nhanh).

- **Thay đổi trong UI mới** (theo bản mockup cập nhật):
  - Thiết kế theo hướng **clean + modern**, tăng độ tương phản và phân cấp thông tin rõ ràng.
  - Khối **CURRENT URL** được “card hoá” và làm nổi bật hơn, dễ đọc và gọn gàng hơn.
  - Trung tâm là trạng thái **READY TO SCAN** với icon/check rõ ràng → tăng cảm giác tin cậy.
  - CTA “Scan Website” được làm lớn, dễ bấm, màu sắc đồng bộ với nhận diện extension.
  - Badge **AI POWERED** được thể hiện nhất quán, tăng mức độ “production feel”.
  - Footer versioning “Protected by AI • v2.0” giúp thể hiện vòng đời sản phẩm và tracking release.

---

**Kết quả đạt được (Tuần 5-6):**
- Dataset URL được tái cân bằng theo hướng **benign chiếm đa số**, phù hợp thực tế và giảm rủi ro FP khi deploy.
- XGBoost được tăng cường regularization + subsampling để **chống overfit** và ổn định hơn với dữ liệu đa dạng.
- Threshold tuning được chuẩn hoá theo pipeline **Validation → Test**, với ngân sách **FPR < 5%** như yêu cầu vận hành.
- UI extension được nâng cấp theo hướng **tối giản – hiện đại – dễ dùng**, sẵn sàng cho demo/triển khai thực tế.