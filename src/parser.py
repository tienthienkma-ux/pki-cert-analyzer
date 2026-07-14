import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

class CertParser:
    def __init__(self, cert_path: str):
        if not os.path.exists(cert_path):
            raise FileNotFoundError(f"Không tìm thấy file chứng chỉ tại {cert_path}")
            
        self.cert_path = cert_path
        self.cert = self.load_certificate()

    def load_certificate(self):
        with open(self.cert_path, "rb") as f:
            cert_data = f.read()
        return x509.load_pem_x509_certificate(cert_data)

    def get_version(self) -> str:
        """
        Version trả về dạng Enum/Integer (0=v1, 1=v2, 2=v3).
        """
        version_enum = self.cert.version
        return f"X.509 v{version_enum.value + 1}"  # Cộng 1 để ra phiên bản thực tế (v3)

    def get_subject_dn(self) -> str:
        """
        trả về chuỗi Distinguished Name (DN) đầy đủ của Subject theo chuẩn RFC 4514
        """
        return self.cert.subject.rfc4514_string()

    def get_issuer_dn(self) -> str:
        """
        trả về chuỗi Distinguished Name (DN) đầy đủ của Issuer (CA ký chứng chỉ)
        """
        return self.cert.issuer.rfc4514_string()

    def get_common_name(self) -> dict:
        """
        bóc tách riêng trường Common Name (CN) của cả Subject và Issuer để hiển thị gọn gàng.
        """
        def extract_cn(name_object):
            cns = name_object.get_attributes_for_oid(NameOID.COMMON_NAME)
            return cns[0].value if cns else "N/A"

        return {
            "subject_cn": extract_cn(self.cert.subject),
            "issuer_cn": extract_cn(self.cert.issuer)
        }
    def get_validity(self) -> dict:
        """
        trích xuất khoảng thời gian hiệu lực (notBefore và notAfter) dưới dạng UTC datetime
        """
        # Thư viện cryptography trả về đối tượng datetime có sẵn timezone UTC
        not_before = self.cert.not_valid_before_utc
        not_after = self.cert.not_valid_after_utc
        
        return {
            "not_before": not_before,
            "not_after": not_after
        }
    def get_public_key_info(self) -> dict:
        """
        RFC 5280 trích xuất thuật toán và các tham số kỹ thuật của Public Key.
        """
        pub_key = self.cert.public_key()
        key_info = {
            "algorithm": "Unknown",
            "details": {}
        }

        # Khóa RSA
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_info["algorithm"] = "RSA"
            key_info["details"] = {
                "key_size_bits": pub_key.key_size,
                "exponent": pub_key.public_numbers().e
            }
            
        # Khóa Elliptic Curve (ECDSA)
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_info["algorithm"] = "ECDSA (Elliptic Curve)"
            key_info["details"] = {
                "curve_name": pub_key.curve.name,
                "key_size_bits": pub_key.key_size
            }
            
        # Khóa Ed25519 
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            key_info["algorithm"] = "Ed25519"
            key_info["details"] = {"key_size_bits": 256}

        return key_info
    def get_key_usage(self) -> dict:
        """
        RFC 5280 trích xuất trạng thái Critical và các cờ giới hạn mục đích sử dụng khóa.
        """
        try:
            # Lấy extension Key Usage bằng OID 
            ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku_value = ext.value
            
            # các flag được định nghĩa trong RFC 5280
            flags = {
                "digital_signature": ku_value.digital_signature,
                "content_commitment": ku_value.content_commitment, #  nonRepudiation
                "key_encipherment": ku_value.key_encipherment,
                "data_encipherment": ku_value.data_encipherment,
                "key_agreement": ku_value.key_agreement,
                "key_cert_sign": ku_value.key_cert_sign,
                "crl_sign": ku_value.crl_sign,
                "encipher_only": ku_value.encipher_only if ku_value.key_agreement else False,
                "decipher_only": ku_value.decipher_only if ku_value.key_agreement else False,
            }
            
            # danh sách các tính năng được "Bật" (True) để hiển thị cho gọn
            active_usages = [k for k, v in flags.items() if v]

            return {
                "present": True,
                "critical": ext.critical,
                "active_usages": active_usages,
                "raw_flags": flags
            }
            
        except x509.ExtensionNotFound:
            # Chứng chỉ cũ (v1) hoặc không định nghĩa trường này
            return {
                "present": False,
                "critical": False,
                "active_usages": [],
                "raw_flags": {}
            }
    def get_extended_key_usage(self) -> dict:
        """
        trích xuất các OID định nghĩa mục đích sử dụng ở tầng ứng dụng (EKU)
        """
        try:
            # Lấy extension Extended Key Usage bằng OID chuẩn
            ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            eku_value = ext.value
            
            usages = []
            for oid in eku_value:
                # thường trả về chuỗi dễ đọc như 'serverAuth', 'clientAuth'
                # nếu không có chuỗi dễ đọc ta lấy chuỗi OID thuần (chuỗi số)
                friendly_name = getattr(oid, "_name", oid.dotted_string)
                usages.append({
                    "name": friendly_name,
                    "oid": oid.dotted_string
                })

            return {
                "present": True,
                "critical": ext.critical,
                "usages": usages
            }
            
        except x509.ExtensionNotFound:
            return {
                "present": False,
                "critical": False,
                "usages": []
            }
    def get_subject_alternative_name(self) -> dict:
        """
        RFC 5280 trích xuất danh sách các định danh thay thế (DNS, IP) trong trường SAN
        """
        try:
            # extension SAN bằng OID
            ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_value = ext.value
            
            # các bản ghi tên miền (DNSName)
            dns_names = san_value.get_values_for_type(x509.DNSName)
            
            # các bản ghi IP (IPAddress) --> về chuỗi ký tự (str)
            ip_addresses = [str(ip) for ip in san_value.get_values_for_type(x509.IPAddress)]
            
            return {
                "present": True,
                "critical": ext.critical,
                "dns_names": dns_names,
                "ip_addresses": ip_addresses
            }
            
        except x509.ExtensionNotFound:
            return {
                "present": False,
                "critical": False,
                "dns_names": [],
                "ip_addresses": []
            }    