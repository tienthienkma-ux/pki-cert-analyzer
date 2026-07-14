import os

class HTMLReporter:
    def __init__(self, parser_obj, validator_obj):
        self.parser = parser_obj
        self.validator = validator_obj

    def generate_report(self, output_path: str = "report.html"):
        """
        Tổng hợp dữ liệu.
        """
        # lấy các dữ liệu đã thư thập được
        cns = self.parser.get_common_name()
        version = self.parser.get_version()
        subject_dn = self.parser.get_subject_dn()
        issuer_dn = self.parser.get_issuer_dn()
        validity = self.parser.get_validity()
        pub_key = self.parser.get_public_key_info()
        key_usage = self.parser.get_key_usage()
        eku = self.parser.get_extended_key_usage()
        san = self.parser.get_subject_alternative_name()
        crl_result = self.validator.check_revocation_via_crl()
        
        # Tô màu cho trạng thái 
        status_color = "#2ec4b6" # (An toàn)
        status_text = "HỢP LỆ & AN TOÀN"
        
        if crl_result["status"] == "REVOKED":
            status_color = "#e63946" # (Bị thu hồi)
            status_text = "CẢNH BÁO: CHỨNG CHỈ BỊ THU HỒI!"
        elif pub_key["algorithm"] == "RSA" and pub_key["details"].get("key_size_bits", 0) < 2048:
            status_color = "#ffb703" # (Cảnh báo yếu)
            status_text = "CẢNH BÁO: MẬT MÃ YẾU"

        # xây dưng HTML template
        html_template = f"""
        <!DOCTYPE html>
        <html lang="vi">
        <head>
            <meta charset="UTF-8">
            <title>PKI Certificate Audit Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }}
                .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .header {{ border-bottom: 3px solid {status_color}; padding-bottom: 15px; margin-bottom: 25px; }}
                h1 {{ margin: 0; color: #1d3557; font-size: 24px; }}
                .status-badge {{ display: inline-block; padding: 6px 12px; background-color: {status_color}; color: white; font-weight: bold; border-radius: 4px; margin-top: 10px; }}
                .section {{ margin-bottom: 25px; }}
                .section-title {{ font-size: 18px; color: #457b9d; border-left: 5px solid #457b9d; padding-left: 10px; margin-bottom: 15px; font-weight: 6px; }}
                table {{ width: 100%; border-collapse: collapse; margin-bottom: 10px; }}
                table, th, td {{ border: 1px solid #ddd; }}
                th, td {{ padding: 12px; text-align: left; }}
                th {{ background-color: #f8f9fa; width: 30%; font-weight: 600; }}
                .badge {{ background: #e1edd6; color: #5f8d3e; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; display: inline-block; margin: 2px; }}
                .badge-critical {{ background: #fce8e6; color: #c53929; }}
                .list-item {{ margin: 5px 0; font-family: monospace; background: #f8f9fa; padding: 4px 8px; border-radius: 4px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>BÁO CÁO THẨM ĐỊNH CHỨNG CHỈ SỐ (X.509)</h1>
                    <small>Công cụ phân tích: PKI Cert Analyzer Engine (RFC 5280)</small><br>
                    <div class="status-badge">{status_text}</div>
                </div>

                <div class="section">
                    <div class="section-title">1. Thông tin định danh cốt lõi (Metadata)</div>
                    <table>
                        <tr><th>Tên miền chính (Common Name)</th><td><strong>{cns['subject_cn']}</strong></td></tr>
                        <tr><th>Phiên bản cấu trúc</th><td>{version}</td></tr>
                        <tr><th>Subject DN</th><td><code>{subject_dn}</code></td></tr>
                        <tr><th>Issuer DN (Đơn vị cấp)</th><td><code>{issuer_dn}</code></td></tr>
                    </table>
                </div>

                <div class="section">
                    <div class="section-title">2. Thời gian hiệu lực (Validity)</div>
                    <table>
                        <tr><th>Có hiệu lực từ (UTC)</th><td>{validity['not_before']}</td></tr>
                        <tr><th>Hết hiệu lực vào (UTC)</th><td>{validity['not_after']}</td></tr>
                    </table>
                </div>

                <div class="section">
                    <div class="section-title">3. Thông tin mật mã (Public Key Info)</div>
                    <table>
                        <tr><th>Thuật toán sử dụng</th><td>{pub_key['algorithm']}</td></tr>
                        <tr><th>Chi tiết kỹ thuật khóa</th><td><code>{pub_key['details']}</code></td></tr>
                    </table>
                </div>

                <div class="section">
                    <div class="section-title">4. Mục đích sử dụng mở rộng (Extensions)</div>
                    <table>
                        <tr>
                            <th>Key Usage</th>
                            <td>
                                {'<span class="badge badge-critical">Critical</span>' if key_usage.get('critical') else ''}
                                {''.join(f'<span class="badge">{u}</span>' for u in key_usage.get('active_usages', []))}
                            </td>
                        </tr>
                        <tr>
                            <th>Extended Key Usage (EKU)</th>
                            <td>
                                {'<span class="badge badge-critical">Critical</span>' if eku.get('critical') else ''}
                                {''.join(f'<span class="badge">{u["name"]}</span>' for u in eku.get('usages', []))}
                            </td>
                        </tr>
                    </table>
                </div>

                <div class="section">
                    <div class="section-title">5. Hệ sinh thái tên miền bảo vệ (SAN)</div>
                    <div>
                        {''.join(f'<div class="list-item">[DNS] {name}</div>' for name in san.get('dns_names', []))}
                        {''.join(f'<div class="list-item">[IP] {ip}</div>' for ip in san.get('ip_addresses', []))}
                    </div>
                </div>

                <div class="section">
                    <div class="section-title">6. Trạng thái thu hồi Live (Revocation Check)</div>
                    <table>
                        <tr><th>Kết quả đối chiếu CRL</th><td><strong>{crl_result['message']}</strong></td></tr>
                    </table>
                </div>
            </div>
        </body>
        </html>
        """
        
        # ghi html ra file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_template)
        print(f" Đã xuất HTML tại: {output_path}")