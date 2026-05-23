# Báo Cáo Tiến Độ Đồ Án - Tuần 9 & 10 (22/04 - 13/05)

**Dự án:** Phát hiện Phishing Đa phương thức (Multimodal Phishing Detection)  
**Giai đoạn:** Nâng cấp Computer Vision (YOLO26), Chuyển đổi mô hình NLP (XLM-RoBERTa), và Tối ưu hoá Backend Inference.

---

## 1. Nâng cấp mô hình Computer Vision (YOLO26 Logo Detection)
**File:** `notebook/train_yolo26.ipynb`, `src/api/main.py`

- **Chuyển đổi sang YOLO26**:
  - Cập nhật kiến trúc mô hình từ YOLOv8 lên **YOLO26** (phiên bản mới nhất năm 2026) để tối ưu hoá tốc độ inference trên thiết bị edge và tăng độ chính xác nhận diện logo.
  - Sử dụng **MuSGD optimizer** giúp mô hình hội tụ nhanh và ổn định hơn.

- **Thiết kế Notebook Training chuyên sâu (`train_yolo26.ipynb`)**:
  - Tích hợp các kỹ thuật **chống overfitting** mạnh mẽ:
    - **Early Stopping**: `patience=40` để tránh học vẹt.
    - **Data Augmentation**: Mosaic (1.0), MixUp (0.15), Copy-Paste, HSV jittering, và Random Erasing.
    - **Regularization**: Weight decay (0.0005), Label Smoothing (0.05), và Dropout (0.1).
  - Tự động hoá quy trình sửa lỗi đường dẫn dataset từ Roboflow (fix lỗi `valid` vs `val` path).
  - Bổ sung bộ công cụ trực quan hoá: Confusion Matrix (Count/Normalized), F1/P/R/PR Curves, và sample inference kết quả.

## 2. Thay thế mô hình NLP (XLM-RoBERTa thay cho BERT)
**File:** `src/api/main.py`

- **Lý do thay đổi**:
  - Mô hình **XLM-RoBERTa** (`xlmr_phishing`) mang lại khả năng hiểu ngôn ngữ đa quốc gia (cross-lingual) tốt hơn so với BERT cơ bản, đặc biệt quan trọng khi phân tích nội dung các trang web phishing tại thị trường Việt Nam.
  
- **Triển khai kỹ thuật**:
  - Cập nhật API sử dụng `AutoTokenizer` và `AutoModelForSequenceClassification` để tương thích linh hoạt với nhiều dòng model transformer.
  - Thay đổi đường dẫn load model và cập nhật lại log/debug message trong luồng inference để phản ánh đúng mô hình đang sử dụng (`[XLM-R]` thay cho `[BERT]`).

## 3. Tối ưu hoá luồng Inference & Debugging (Backend/API)
**File:** `src/api/main.py`

- **Cải thiện Logging**:
  - Thêm các dòng debug in ra thông tin chi tiết về độ dài HTML, trạng thái load của từng model (XGB, XLM-R, YOLO) ngay khi nhận request.
  - Cập nhật thông báo hệ thống để phân biệt rõ ràng các module đang chạy (`URL`, `TEXT`, `IMAGE`).

- **Đồng bộ hoá định danh**:
  - Thống nhất tên gọi **YOLO26** xuyên suốt từ notebook training đến hệ thống load model trong API.
  - Giữ nguyên cấu trúc key trong dictionary `models` để đảm bảo tính tương thích ngược với logic voting hiện tại mà không cần refactor quá nhiều code xử lý điểm số.

---

**Kết quả đạt được (Tuần 9-10):**
- Hoàn thành bộ khung training hiện đại cho YOLO26 với đầy đủ công cụ đánh giá và chống overfit.
- Nâng cấp thành công lõi NLP sang **XLM-RoBERTa**, tăng cường khả năng phát hiện dựa trên nội dung văn bản.
- Backend API được chuẩn hoá, hỗ trợ debug tốt hơn và sẵn sàng cho việc tích hợp các phiên bản model mới nhất.
- Khắc phục triệt để các lỗi về đường dẫn dữ liệu và lỗi thuộc tính thư viện (`total_memory`, `list.get`) trong môi trường Colab.
