# Báo Cáo Tiến Độ Đồ Án - Tuần 1 & 2 (18/03 - 01/04)

**Dự án:** Phát hiện Phishing Đa phương thức (Multimodal Phishing Detection)
**Giai đoạn:** Xây dựng Pipeline Dữ liệu, Trích xuất Đặc trưng và Huấn luyện Mô hình XGBoost cho URL.

---

## 1. Thu thập & Chuẩn bị Dữ liệu (Data Collection Pipeline)
**Thư mục:** `src/data_collection/`

- **Tập Phishing (Phishing Aggregator):**
  - Tích hợp 3 nguồn cấp dữ liệu chính: **PhishTank**, **OpenPhish**, và **PhishStats**.
  - Xử lý vấn đề chặn bot (Cloudflare 403/429) trên PhishTank bằng cách chuyển sang bắt dữ liệu gián tiếp hoặc sử dụng định dạng CSV. Thêm cơ chế tải thủ công dự phòng khi API bị lỗi.
  - Sử dụng chung Headers (User-Agent) và Retry-logic để đảm bảo ổn định mạng.

- **Tập An toàn (Benign Aggregator):**
  - Gộp dữ liệu từ **Tranco List** (danh sách domain top phổ biến) và **Common Crawl** (Sử dụng module `cdx_toolkit`).
  - Lấy mẫu công bằng (Fair-share sampling) để đảm bảo dataset cân bằng với tập Phishing nhằm tránh bias.

## 2. Trích xuất Đặc trưng URL (Feature Engineering)
**File:** `src/features/extract_url_features.py`

- Nâng cấp bộ đặc trưng từ **17 đặc trưng cơ bản lên 69 đặc trưng nâng cao** nhằm phục vụ cho XGBoost. Thêm các tính năng phát hiện sâu:
  - **Domain Entropy (Shannon Entropy):** Đánh giá độ hỗn loạn của domain để phát hiện các tên miền sinh ra ngẫu nhiên (DGA).
  - **Phân rã URL sâu:** Thay vì đếm chung chung, thuật toán kiểm tra từ khoá nhạy cảm (bank, login, secure) tách biệt giữa **Domain** và **Path** để giảm thiểu False Positives (Ví dụ: `tuoitre.vn/bank` là bình thường, nhưng `bank.xyz.com` là mờ ám).
  - **Phân tích Cấu trúc & Tỷ lệ:** Đếm số lượng Subdomain, phát hiện TLD ẩn trong đường dẫn, tỷ lệ độ dài hostname/path.
  - Tích hợp module phát hiện dịch vụ rút gọn URL (Shortening Services).
- **Tối ưu Hiệu năng:** Refactor lại toàn bộ code cũ (bỏ các vòng lặp `iterrows` chậm chạp), chuyển sang dùng **Vectorized operations** của Pandas và `.apply()`. Tốc độ xử lý tăng ~50x (26.000+ URL được trích xuất trong 1.5 giây).

## 3. Huấn luyện Mô hình Tối ưu (Model Training & Optimization)
**File:** `notebook/train_url.ipynb`

- **Nâng cấp thuật toán:** Thay thế thuật toán `RandomForestClassifier` cũ bằng **`xgboost.XGBClassifier`** (với `tree_method='hist'`, `n_estimators=1000`).
- **Phòng chống Overfitting:** Áp dụng cơ chế **Early Stopping** (dừng sớm ở vòng 50 nếu không cải thiện) bằng cách theo dõi tập Validation (chia tách dữ liệu thành Train/Val/Test với tỷ lệ 64/16/20).
- **Tối ưu FPR (False Positive Rate):**
  - Mục tiêu cao nhất là tránh nhận diện nhầm web sạch thành lừa đảo.
  - Thay vì dùng hàm `predict()` với ngưỡng mặc định (Threshold = 0.5), chuyển sang dùng hàm tự viết `find_optimal_threshold()` dựa trên `predict_proba()`.
  - Tự động dò tìm ngưỡng quyết định (Threshold) khắt khe nhất để ép chỉ số FPR xuống mức mục tiêu (<1%), từ đó cân bằng được F1-Score, Recall và Accuracy (Accuracy tổng đạt trên 72%, AUC đạt ~99.5%).
- Bổ sung biểu đồ trực quan mạnh mẽ: Thuyết minh hiệu quả mô hình bằng Confusion Matrix (đã tối ưu hóa), ROC Curve, Precision-Recall Curve và tính trực quan `Feature Importance` dựa trên trọng số của XGBoost.

## 4. Tích hợp API Đưa vào Sử dụng (Production Integration)
**File:** `src/api/main.py`

- Thay thế hàm lấy đặc trưng rút gọn nội bộ trong file API bằng cách gộp chung module `extract_url_features_for_api` (69 features) từ thư mục gốc, đảm bảo tính đồng nhất giữa môi trường Train và Production.
- Nâng cấp logic Inference (Dự đoán):
  - Chỉnh sửa cơ chế nạp (load) mô hình: Đọc file `url_xgboost.pkl`.
  - Không chỉ đọc model, API giờ đây đọc trực tiếp **`optimal_threshold`** lưu kèm trong file `.pkl` để dùng làm cutoff linh động thay vì set cứng ngưỡng 0.6 như hệ thống cũ.
- Tinh chỉnh các dòng Log và Score Override cho phù hợp với sức mạnh mới của mô hình XGBoost.

---
**Các vấn đề đã giải quyết:**
- Fix cấu hình sai của môi trường ảo (venv) trên Git Bash không nhận lệnh `pip install` (Cài đặt thêm các package cho Jupyter Kernel: `xgboost`, `matplotlib`, `seaborn`).
- Sửa lỗi thứ tự bị lặp lộn trong biểu đồ phân bổ Labels (`value_counts` bị sai lệch).
- Fix lỗi cấu trúc khai báo Early Stopping cho XGBModel version.
