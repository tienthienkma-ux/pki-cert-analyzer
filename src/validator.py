import requests
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa

class CertValidator:
    def __init__(self, parser_obj):
        """
        Nhận CertParser
        """
        self.parser = parser_obj
        self.cert = parser_obj.cert

    def get_crl_distribution_points(self) -> list:
        """
        RFC 5280 trích xuất các URL của điểm phân phối CRL (CDP) từ trường mở rộng
        """
        try:
            ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            crl_urls = []
            
            for point in ext.value:
                if point.full_name:
                    for name in point.full_name:
                        # Kiểm tra nếu định dạng tên là một đường dẫn URL (URI)
                        if isinstance(name, x509.UniformResourceIdentifier):
                            crl_urls.append(name.value)
            return crl_urls
            
        except x509.ExtensionNotFound:
            return []

    def check_revocation_via_crl(self) -> dict:
        """
        Tải file CRL từ Internet và đối chiếu Serial Number để kiểm tra trạng thái thu hồi
        """
        urls = self.get_crl_distribution_points()
        if not urls:
            return {"status": "UNKNOWN", "message": "Không tìm thấy điểm phân phối CRL trong chứng chỉ"}
        
        serial_number = self.cert.serial_number
        
        for url in urls:
            if url.startswith("http"):
                try:
                    print(f"    [i] Đang kết nối tải CRL từ: {url} ...")
                    response = requests.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        crl = x509.load_der_x509_crl(response.content)
                        revoked_record = crl.get_revoked_certificate_by_serial_number(serial_number)
                        
                        if revoked_record:
                            # lý do thu hồi từ Extensions (RFC 5280)
                            reason = "Không nêu rõ lý do"
                            try:
                                reason_ext = revoked_record.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_REASON)
                                reason = reason_ext.value.reason.value # 'keyCompromise', 'cACompromise',...
                            except Exception:
                                pass

                            return {
                                "status": "REVOKED",
                                "message": f" BỊ THU HỒI | Lý do: {reason} | Ngày thu hồi: {revoked_record.revocation_date_utc}"
                            }
                        
                        return {
                            "status": "GOOD",
                            "message": " HỢP LỆ"
                        }
                    else:
                        # nếu Server phản hồi nhưng trả về lỗi HTTP (Ví dụ: 404, 502)
                        print(f"    [!] Máy chủ CRL phản hồi mã lỗi HTTP: {response.status_code}")
                        continue

                except Exception as e:
                    print(f"    [DEBUG lỗi gốc]: {e}")
                    continue
                    
        return {"status": "ERROR", "message": "Mất kết nối mạng hoặc không thể tải file CRL từ các máy chủ CA"}
    def check_basic_constraints(self) -> dict:
        """
        Kiểm tra chứng chỉ có phải là CA (Có quyền ký chứng chỉ khác) hay không
        """
        try:
            ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            bc = ext.value
            return {
                "is_ca": bc.ca,
                "path_length": bc.path_length
            }
        except x509.ExtensionNotFound:
            return {"is_ca": False, "path_length": None}

    def verify_cert_signature(self, issuer_cert_obj: x509.Certificate) -> bool:
        """
        dùng Public Key của chứng chỉ cha (Issuer) để xác thực chữ ký số trên chứng chỉ hiện tại
        """
        issuer_public_key = issuer_cert_obj.public_key()
        
        try:
            # xđ thuật toán mã hóa để áp dụng thuật toán verify tương ứng
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    self.cert.signature,
                    self.cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    self.cert.signature_hash_algorithm
                )
            elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(
                    self.cert.signature,
                    self.cert.tbs_certificate_bytes,
                    ec.ECDSA(self.cert.signature_hash_algorithm)
                )
            else:
                # Ed25519 không cần truyền Hash/Padding tách biệt
                issuer_public_key.verify(
                    self.cert.signature,
                    self.cert.tbs_certificate_bytes
                )
            return True  # trùng khớp và hợp lệ
        except Exception:
            return False # giả mạo hoặc không do khóa này ký ra