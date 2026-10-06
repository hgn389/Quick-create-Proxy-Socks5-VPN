# Nền tảng v1.0.0 beta

| Hệ điều hành | Kiến trúc có payload | Ghi chú |
| --- | --- | --- |
| Ubuntu 20.04 | amd64, arm64 | 3proxy tĩnh musl build từ source 0.9.9.0; cần nguồn cập nhật bảo mật Ubuntu/ESM phù hợp. |
| Ubuntu 22.04, 24.04, 26.04 | amd64, arm64 | Dùng executable từ package DEB 3proxy 0.9.9.0. |
| Debian 12, 13 | amd64, arm64 | Dùng executable từ package DEB 3proxy 0.9.9.0. |
| AlmaLinux 8, 9, 10 | amd64, arm64 | Dùng executable từ package RPM theo major version. |
| CentOS Stream 9, 10 | amd64, arm64 | CentOS Linux 7/8 và Stream 8 không trong phạm vi. |

Đây là **ma trận có payload và được bộ cài nhận diện**, chưa phải ma trận đã thử nghiệm trên máy thật. Bản beta đã kiểm tra build amd64/arm64 và preflight trên Ubuntu 22.04 amd64. Trước khi dùng sản xuất cần chạy thử trên từng OS, đặc biệt ARM board và các bản mới. Orange Pi cần ảnh OS 64 bit tương ứng, systemd, kernel có WireGuard và kho gói hoạt động. Board ARM 32 bit không được hỗ trợ.

`./install.sh --check` kiểm tra hệ điều hành, kiến trúc, systemd, tài nguyên, cổng panel, binary và thư viện 3proxy trên host. Nó không thay đổi hệ thống. Khi kernel không có WireGuard hoặc không cài được tools, panel và proxy vẫn có thể hoạt động; chức năng VPN sẽ báo lỗi khi khởi tạo.

Panel dùng HTTPS trên TCP 22689 với chứng chỉ tự ký cho IPv4 đã phát hiện; địa chỉ đăng nhập và dấu vân tay chứng chỉ được in khi cài. Bộ cài thêm một rule có định danh riêng vào UFW, firewalld hoặc iptables đang hoạt động trên máy, rồi gỡ đúng rule đó khi uninstall. Firewall/security group của nhà cung cấp VPS vẫn phải được mở riêng. Bộ cài không sửa webserver, port 80/443, các rule không thuộc QCP hay kernel. Cấu hình WireGuard dùng IPv4 NAT trong bảng nft riêng. Rule firewall hiện hữu vẫn có thể chặn UDP/FORWARD của WireGuard; cần mở thủ công theo chính sách của VPS.
