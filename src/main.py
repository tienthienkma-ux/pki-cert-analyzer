import sys
import os
import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from parser import CertParser
from validator import CertValidator
from reporter import HTMLReporter

def main():
    sample_cert = "certs/google_sample.crt"
    issuer_cert = "certs/google_issuer.crt"
    output_report = "report.html"
    
    print("  PKI CERTIFICATE ANALYZER")
    print("="*50)
    
    try:
        parser = CertParser(sample_cert)
        
        # Metadata 
        print(f"Phiên bản cấu trúc : {parser.get_version()}")
        print(f"Subject DN         : {parser.get_subject_dn()}")
        print(f"Issuer DN          : {parser.get_issuer_dn()}")

        cns = parser.get_common_name()
        print(f"     Tên miền chính (CN): {cns['subject_cn']}")
        print(f"     Đơn vị cấp phát (CA): {cns['issuer_cn']}")
        print("-" * 50)
        
        # Validity
        validity = parser.get_validity()
        print(f" Có hiệu lực từ (UTC): {validity['not_before']}")
        print(f"Hết hiệu lực vào (UTC): {validity['not_after']}")
        
        # tính toán trạng thái
        now = datetime.datetime.now(datetime.timezone.utc)
        if now < validity['not_before']:
            print("[TRẠNG THÁI] : Chứng chỉ CHƯA ĐẾN HẠN kích hoạt")
        elif now > validity['not_after']:
            print("[TRẠNG THÁI] : Chứng chỉ ĐÃ HẾT HẠN sử dụng")
        else:
            time_left = validity['not_after'] - now
            print(f"[TRẠNG THÁI] : Chứng chỉ HỢP LỆ (Còn lại {time_left.days} ngày)")
            
        # Public Key Info 
        pub_key_info = parser.get_public_key_info()
        algo = pub_key_info["algorithm"]
        details = pub_key_info["details"]
        
        print(f"Thuật toán khóa : {algo}")
        
        if algo == "RSA":
            print(f"    -> Độ dài khóa  : {details['key_size_bits']} bits")
            print(f"    -> Số mũ Exponent: {details['exponent']}")
            
            # Đánh giá bảo mật dựa trên độ dài khóa
            if details['key_size_bits'] < 2048:
                print("Khóa RSA quá yếu (< 2048 bits), nguy cơ bị bẻ khóa")
            else:
                print("Độ dài khóa RSA đạt tiêu chuẩn an toàn")
                
        elif algo == "ECDSA (Elliptic Curve)":
            print(f"    -> Tên đường cong: {details['curve_name']}")
            print(f"    -> Độ dài khóa   : {details['key_size_bits']} bits")
            
        else:
            print(f"    -> Chi tiết      : {details}")
    except Exception as e:
        print(f" [LỖI]: {e}")
    print("="*50)
    try:
        parser = CertParser(sample_cert)
        cns = parser.get_common_name()
        print(f"[*] Chứng chỉ của : {cns['subject_cn']}")
        print("-" * 50)
        
        # Key Usage 
        ku = parser.get_key_usage()
        
        if not ku["present"]:
            print("Key Usage không tồn tại trong chứng chỉ này")
        else:
            print(f"Thuộc tính Critical: {'BẮT BUỘC (True)' if ku['critical'] else 'KHÔNG (False)'}")
            print(f"Các mục đích được phép sử dụng:")
            
            for usage in ku["active_usages"]:
                print(f"    -> {usage}")
                
            # AUDIT 
            print("\n[Đánh giá cấp bậc chứng chỉ]:")
            raw = ku["raw_flags"]
            
            if raw.get("key_cert_sign"):
                print(" Đây là chứng chỉ CA (Có quyền cấp phát chứng chỉ khác)")
                if not ku["critical"]:
                    print(" CẢNH BÁO: Theo RFC 5280, Key Usage của CA nên được đánh dấu là Critical")
            else:
                print("Đây là chứng chỉ cuối (End-Entity Cert) - Không có quyền hạ cấp/ký cert khác")
                
            if raw.get("digital_signature") or raw.get("key_encipherment"):
                print("Phù hợp cho các tác vụ thiết lập kênh truyền bảo mật (TLS Handshake)")
        # Extended Key Usage 
        eku = parser.get_extended_key_usage()
        
        if not eku["present"]:
            print("Trường Extended Key Usage (EKU) không tồn tại")
        else:
            print(f" Thuộc tính Critical: {'BẮT BUỘC (True)' if eku['critical'] else 'KHÔNG (False)'}")
            print(f" Danh sách mục đích ứng dụng được cấp phép (EKU):")
            
            # tạo một danh sách chỉ chứa tên để kiểm tra nhanh
            list_of_names = [u["name"] for u in eku["usages"]]
            
            for usage in eku["usages"]:
                print(f"    -> Tên: {usage['name']:<18} | OID: {usage['oid']}")
            
            # SECURITY AUDIT
            print("\n[Đánh giá an toàn]:")
            
            # Kiểm tra tiêu chuẩn cho Web Server HTTPS
            if "serverAuth" in list_of_names:
                print("Đủ điều kiện: Chứng chỉ được phép cấu hình làm Web Server TLS")
            else:
                print("CẢNH BÁO: Chứng chỉ này KHÔNG ĐƯỢC PHÉP dùng làm Web Server TLS")
                
            if "clientAuth" in list_of_names:
                print("Mở rộng: Chứng chỉ hỗ trợ mTLS (Xác thực hai chiều từ phía Client)")
                
            if "codeSigning" in list_of_names:
                print("CẢNH BÁO: Chứng chỉ này chứa quyền Ký số phần mềm. Hãy quản lý Private Key cực kỳ cẩn thận")

        
        # Subject Alternative Name
        san = parser.get_subject_alternative_name()
        
        if not san["present"]:
            print("CẢNH BÁO :")
            print("    Chứng chỉ không cấu hình trường SAN (Subject Alternative Name).")
            print("    Các trình duyệt hiện đại (Chrome/Firefox) sẽ chặn trang web này")
        else:
            print(f" Thuộc tính Critical: {'BẮT BUỘC (True)' if san['critical'] else 'KHÔNG (False)'}")
            
            # danh sách DNS Tên miền
            print(f" Số lượng tên miền đăng ký bảo vệ: {len(san['dns_names'])}")
            for dns in san["dns_names"]:
                print(f"    -> [DNS] : {dns}")
                
            # danh sách IP (Nếu có)
            if san["ip_addresses"]:
                print(f" Danh sách IP được bảo vệ trực tiếp:")
                for ip in san["ip_addresses"]:
                    print(f"    -> [IP]  : {ip}")
                    
            # AUDIT
            print("\n[Đánh giá cấu hình SAN]:")
            
            # Kiểm tra xem có chứa tên miền Wildcard không (ví dụ: *.google.com)
            has_wildcard = any(dns.startswith("*.") for dns in san["dns_names"])
            if has_wildcard:
                print(" Hệ thống sử dụng chứng chỉ Wildcard (*).")
                print("    -> Ưu điểm: Tiết kiệm chi phí, dễ quản lý cho nhiều subdomain")
                print("    -> Rủi ro: Nếu khóa bí mật (Private Key) bị lộ, các subdomain đều bị ảnh hưởng")
            else:
                print(" Hệ thống sử dụng chứng chỉ định danh tường minh (Single/Multi-domain), kiểm soát rủi ro tốt")
                
            # Kiểm tra quy chuẩn đồng bộ giữa CN và SAN
            if cns['subject_cn'] not in san['dns_names'] and f"*.{cns['subject_cn']}" not in san['dns_names']:
                print(" Cảnh báo cấu hình: Trường CN không nằm trong danh sách SAN. Hãy kiểm tra lại sự đồng bộ")
            else:
                print(" Cấu hình chuẩn: Tên miền gốc (CN) khớp chính xác với bản ghi trong SAN.")
    except Exception as e:
        print(f" [LỖI]: {e}")
    
    try:
        # Validator trạng thái thu hồi
        # Parser đọc thông tin
        parser = CertParser(sample_cert)
        cns = parser.get_common_name()
        print(f"Kiểm tra thực thể {cns['subject_cn']}")
        
        # Validator kiểm tra trạng thái mạng
        validator = CertValidator(parser)
        
        # Lấy danh sách URL để in ra màn hình trước
        crl_urls = validator.get_crl_distribution_points()
        print(f" Điểm phân phối CRL tìm thấy ({len(crl_urls)}):")
        for url in crl_urls:
            print(f"    -> {url}")
            
        print("-" * 60)
        print(" BẮT ĐẦU KIỂM TRA TRẠNG THÁI THU HỒI LIVE:")
        
        # Chạy bộ máy kiểm tra CRL
        result = validator.check_revocation_via_crl()
        print(f"[KẾT QUẢ]: {result['message']}")

    except Exception as e:
        print(f" [LỖI]: {e}")
    
    try:
        # chứng chỉ con và chứng chỉ cha (Issuer)
        # chứng chỉ Con
        leaf_parser = CertParser(sample_cert)
        leaf_validator = CertValidator(leaf_parser)
        print(f"Chứng chỉ con (Subject): {leaf_parser.get_common_name()['subject_cn']}")
        
        # chứng chỉ Cha
        issuer_parser = CertParser(issuer_cert)
        issuer_validator = CertValidator(issuer_parser)
        print(f"Chứng chỉ cha (Issuer) : {issuer_parser.get_common_name()['subject_cn']}")
        print("-" * 60)
        
        #Kiểm tra quyền CA của chứng chỉ cha
        parent_constraints = issuer_validator.check_basic_constraints()
        if parent_constraints["is_ca"]:
            print("[KT1]: Chứng chỉ cha có thuộc tính cA=True hợp lệ")
        else:
            print("[KT1 Failed]: Chứng chỉ cha không có quyền cấp phát (cA=False)")
            
        # Xác thực chữ ký số bằng mật mã học
        # Truyền đối tượng cert thuần của cha vào hàm verify của con
        is_signature_valid = leaf_validator.verify_cert_signature(issuer_parser.cert)
        
        if is_signature_valid:
            print("[KT2]: Chữ ký số HỢP LỆ")
            print("   -> Kết luận: Chứng chỉ con được ký chính xác bởi Khóa bí mật của CA này.")
        else:
            print("[KT2 Failed]: Chữ ký số không hợp lệ hoặc bị giả mạo")

    except Exception as e:
        print(f" [LỖI HỆ THỐNG]: {e}")
    try:
        parser = CertParser(sample_cert)
        validator = CertValidator(parser)
        reporter = HTMLReporter(parser, validator)
        reporter.generate_report(output_report)
        
        print("-" * 60)
        print(f" HOÀN THÀNH: Bạn hãy mở file '{output_report}' bằng trình duyệt")


    except Exception as e:
        print(f" [LỖI HỆ THỐNG]: {e}")
    print("="*60)
if __name__ == "__main__":
    main()