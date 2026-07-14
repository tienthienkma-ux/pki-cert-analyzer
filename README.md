# PKI Certificate Analyzer & Validator

PKI Certificate Analyzer là một công cụ phân tích và thẩm định chứng chỉ số X.509 toàn diện được viết bằng Python. Chương trình không chỉ bóc tách các trường thông tin tĩnh mà còn thực hiện kiểm tra trạng thái thu hồi thời gian thực (Live Revocation Checking) thông qua giao thức CRL và xác thực chuỗi tin cậy (Chain of Trust) theo tiêu chuẩn bảo mật quốc tế RFC 5280.

# 1. Lý Thuyết Nền Tảng (PKI Core Concepts)
Để hiểu cách công cụ này hoạt động, chúng ta cần nắm rõ 3 trụ cột cốt lõi của Hạ tầng khóa công khai (PKI):

**A. Chứng chỉ X.509 là gì?**

Chứng chỉ X.509 giống như một "Căn cước công dân kỹ thuật số" trên Internet. Nó liên kết một Khóa công khai (Public Key) với một Thực thể (Subject) và được xác nhận bởi một Bên thứ ba đáng tin cậy gọi là Nhà cấp phát chứng thực (Certificate Authority - CA).

**B. Cơ chế kiểm tra thu hồi qua CRL (Certificate Revocation List)**

Một chứng chỉ dù còn hạn dùng (Validity) vẫn có thể bị vô hiệu hóa bất kỳ lúc nào nếu khóa bí mật bị lộ (Key Compromise) hoặc thông tin thay đổi.

CRL (Danh sách thu hồi chứng chỉ): Là một "danh sách đen" chứa số Serial của các chứng chỉ đã bị CA hủy bỏ trước thời hạn. File CRL này được CA ký số bảo mật và phân phối định kỳ dưới dạng nhị phân DER.

Nghịch lý "Con gà và Quả trứng" (The Chicken-and-Egg Problem): Tại sao các đường dẫn tải CRL (CDP) trong chứng chỉ luôn dùng giao thức không bảo mật http:// thay vì https://?

Giải thích: Nếu link CRL dùng https://, trình duyệt lại phải thiết lập kết nối TLS bảo mật với máy chủ CRL. Để thiết lập TLS, nó cần tải CRL về để kiểm tra xem chứng chỉ của máy chủ CRL đó có bị thu hồi hay không. Đây là một vòng lặp vô hạn không có lối thoát. Do đó, RFC 5280 quy định tải CRL qua http://, tính toàn vẹn của file CRL sẽ được bảo vệ bằng chính chữ ký số của CA nằm trong file đó chứ không phụ thuộc vào đường truyền.

**C. Chuỗi tin cậy (Chain of Trust) & Xác thực chữ ký số**

Trình duyệt không thể tự nhiên tin tưởng chứng chỉ của một trang web (như *.google.com). Nó phải xác thực theo một chuỗi phân cấp:

| Cấp bậc  | Loại chứng chỉ | Vai trò|
| --- | --- | --- | 
| Cấp 3 | End-Entity Cert (ví dụ: *.google.com)	| Chứng chỉ cuối cùng cấp cho máy chủ/người dùng.|
| Cấp 2 |	Intermediate Cert (ví dụ: WE2) |	CA trung gian được ủy quyền ký cấp cho chứng chỉ cuối.
| Cấp 1	| Root Cert (ví dụ: GTS Root R1)	| CA gốc, nằm sẵn trong kho thiết bị tin cậy (Trust Store).

**Cơ chế xác thực:** Công cụ sẽ lấy Khóa công khai (Public Key) từ file chứng chỉ của CA trung gian (google_issuer.crt), sau đó dùng thuật toán mật mã học để giải mã chữ ký số (Signature) trên chứng chỉ cuối (google_sample.crt). Nếu khớp, chứng chỉ cuối hoàn toàn hợp lệ và nguyên vẹn.

# 2. Các Tính Năng Đã Hoàn Thành
 X.509 Metadata Parser: Trích xuất chi tiết Subject DN, Issuer DN, Serial Number, Thuật toán ký, Thời hạn hiệu lực (Not Before / Not After).

 Live CRL Revocation Verifier: * Tự động trích xuất các điểm phân phối CRL (CRL Distribution Points - CDP) từ extension của chứng chỉ.

 --> Tải trực tiếp file danh sách đen dạng DER từ các máy chủ CA thời gian thực.

 --> Phân tích tệp tin CRL và tra cứu lý do thu hồi (Revocation Reason) theo chuẩn RFC 5280.

 --> Đánh giá điều kiện an toàn và danh sách miền bảo vệ, đánh giá cấu hình SAN.

 Cryptographic Chain Validator: Thực hiện xác minh chữ ký số toán học giữa chứng chỉ thực thể và chứng chỉ CA phát hành để phát hiện chứng chỉ giả mạo.

 HTML Report Generator: Xuất báo cáo đồ họa trực quan dưới dạng trang web tĩnh report.html để phục vụ công tác giám sát an toàn thông tin.

 # 3. Cấu trúc mã nguồn

```text
pki-analyzer/
│
├── certs/                      
│   ├── google_issuer.crt       
│   └── google_sample.crt        
│
├── src/                        
│   ├── __init__.py
│   ├── parser.py    
|   ├── main.py           
│   ├── validator.py 
|   └── reporter.py        
│
├── .gitignore     
├── requiements.txt
├── report.html                                
└── README.md
```
# 4. Hướng Dẫn Khởi Chạy
**Yêu cầu hệ thống**

Python 3.8 trở lên.

Kết nối Internet ổn định (để tải CRL từ máy chủ CA của Google).

**Các bước thiết lập nhanh**

Clone dự án về máy: 

git clone https://github.com/ten-cua-ban/pki-analyzer.git

cd pki-analyzer

**Khởi tạo môi trường ảo:**

python -m venv .venv

Kích hoạt trên Windows:
.venv\Scripts\activate

Kích hoạt trên Linux/macOS:
source .venv/bin/activate

**Cài đặt thư viện:**

pip install cryptography requests

pip install -r requirements.txt
(File requirements.txt gồm: cryptography>=41.0.0 và requests>=2.31.0)

**Chạy ứng dụng phân tích:**

python main.py

**Công nghệ sử dụng**

Python 3

Cryptography: Thư viện xử lý mật mã học và chứng chỉ X.509 chuyên sâu.

Requests: Gửi yêu cầu HTTP tải các tệp tin CRL từ máy chủ CA.

# 5. Kết Quả Chạy Chương Trình Thực Tế
Khi chạy ứng dụng, log phân tích chi tiết sẽ được hiển thị ngay trên Terminal:


 PKI CERTIFICATE ANALYZER

Phiên bản cấu trúc : X.509 v3

Subject DN         : CN=*.google.com

Issuer DN          : CN=WE2,O=Google Trust Services,C=US

     Tên miền chính (CN): *.google.com

     Đơn vị cấp phát (CA): WE2

--------------------------------------------------
Có hiệu lực từ (UTC): 2026-06-22 08:35:30+00:00

Hết hiệu lực vào (UTC): 2026-09-14 08:35:29+00:00

[TRẠNG THÁI] : Chứng chỉ HỢP LỆ (Còn lại 62 ngày)

Thuật toán khóa : ECDSA (Elliptic Curve)

    -> Tên đường cong: secp256r1

    -> Độ dài khóa   : 256 bits

==================================================

Chứng chỉ của : *.google.com

--------------------------------------------------
Thuộc tính Critical: BẮT BUỘC (True)

Các mục đích được phép sử dụng:
    -> digital_signature

[Đánh giá cấp bậc chứng chỉ]:

Đây là chứng chỉ cuối (End-Entity Cert) - Không có quyền hạ cấp/ký cert khác

Phù hợp cho các tác vụ thiết lập kênh truyền bảo mật (TLS Handshake)

 Thuộc tính Critical: KHÔNG (False)

 Danh sách mục đích ứng dụng được cấp phép (EKU):

    -> Tên: serverAuth         | OID: 1.3.6.1.5.5.7.3.1

[Đánh giá an toàn]:

Đủ điều kiện: Chứng chỉ được phép cấu hình làm Web Server TLS

Thuộc tính Critical: KHÔNG (False)

Số lượng tên miền đăng ký bảo vệ: 65

    -> [DNS] : *.google.com
    -> [DNS] : *.appengine.google.com
    -> [DNS] : *.bdn.dev
    -> [DNS] : *.origin-test.bdn.dev
    -> [DNS] : *.cloud.google.com
    -> [DNS] : *.crowdsource.google.com
    -> [DNS] : *.datacompute.google.com
    -> [DNS] : *.google.ca
    -> [DNS] : *.google.cl
    -> [DNS] : *.google.co.in
    -> [DNS] : *.google.co.jp
    -> [DNS] : *.google.co.uk
    -> [DNS] : *.google.com.ar
    -> [DNS] : *.google.com.au
    -> [DNS] : *.google.com.br
    -> [DNS] : *.google.com.co
    -> [DNS] : *.google.com.mx
    -> [DNS] : *.google.com.tr
    -> [DNS] : *.google.com.vn
    -> [DNS] : *.google.de
    -> [DNS] : *.google.es
    -> [DNS] : *.google.fr
    -> [DNS] : *.google.hu
    -> [DNS] : *.google.it
    -> [DNS] : *.google.nl
    -> [DNS] : *.google.pl
    -> [DNS] : *.google.pt
    -> [DNS] : *.gemini.cloud.google.com
    -> [DNS] : *.gstatic.com
    -> [DNS] : *.metric.gstatic.com
    -> [DNS] : *.gvt1.com
    -> [DNS] : *.gcpcdn.gvt1.com
    -> [DNS] : *.gvt2.com
    -> [DNS] : *.gcp.gvt2.com
    -> [DNS] : *.url.google.com
    -> [DNS] : *.youtube-nocookie.com
    -> [DNS] : *.ytimg.com
    -> [DNS] : ai.android
    -> [DNS] : android.com
    -> [DNS] : *.android.com
    -> [DNS] : *.flash.android.com
    -> [DNS] : g.co
    -> [DNS] : *.g.co
    -> [DNS] : goo.gl
    -> [DNS] : www.goo.gl
    -> [DNS] : google-analytics.com
    -> [DNS] : *.google-analytics.com
    -> [DNS] : google.com
    -> [DNS] : googlecommerce.com
    -> [DNS] : *.googlecommerce.com
    -> [DNS] : urchin.com
    -> [DNS] : *.urchin.com
    -> [DNS] : youtu.be
    -> [DNS] : youtube.com
    -> [DNS] : *.youtube.com
    -> [DNS] : music.youtube.com
    -> [DNS] : *.music.youtube.com
    -> [DNS] : youtubeeducation.com
    -> [DNS] : *.youtubeeducation.com
    -> [DNS] : youtubekids.com
    -> [DNS] : *.youtubekids.com
    -> [DNS] : yt.be
    -> [DNS] : *.yt.be
    -> [DNS] : android.clients.google.com
    -> [DNS] : *.aistudio.google.com


[Đánh giá cấu hình SAN]:

 Hệ thống sử dụng chứng chỉ Wildcard (*).

    -> Ưu điểm: Tiết kiệm chi phí, dễ quản lý cho nhiều subdomain
    -> Rủi ro: Nếu khóa bí mật (Private Key) bị lộ, các subdomain đều bị ảnh hưởng

 Cấu hình chuẩn: Tên miền gốc (CN) khớp chính xác với bản ghi trong SAN.

Kiểm tra thực thể *.google.com

Điểm phân phối CRL tìm thấy (1):

    -> http://c.pki.goog/we2/xuzt3PU9F_w.crl
-----------------------------------------------------------
BẮT ĐẦU KIỂM TRA TRẠNG THÁI THU HỒI LIVE:

    [i] Đang kết nối tải CRL từ: http://c.pki.goog/we2/xuzt3PU9F_w.crl ...

[KẾT QUẢ]:  HỢP LỆ

Chứng chỉ con (Subject): *.google.com

Chứng chỉ cha (Issuer) : WE2

------------------------------------------------------------

[KT1]: Chứng chỉ cha có thuộc tính cA=True hợp lệ

[KT2]: Chữ ký số HỢP LỆ

   -> Kết luận: Chứng chỉ con được ký chính xác bởi Khóa bí mật của CA này.

    [i] Đang kết nối tải CRL từ: http://c.pki.goog/we2/xuzt3PU9F_w.crl ...

 Đã xuất HTML tại: report.html

------------------------------------------------------------
HOÀN THÀNH: Bạn hãy mở file 'report.html' bằng trình duyệt






