# Phụ thuộc và nguồn phát hành

- `qcp`: Go 1.27, biên dịch tĩnh cho Linux amd64/arm64 (`CGO_ENABLED=0`). Metadata dùng bbolt, không có tiến trình database riêng.
- `3proxy`: 0.9.9.0. Gói DEB/RPM chính thức được tải theo phiên bản cố định; `vendor-3proxy.sh` xác minh manifest checksum ký bằng khóa upstream có fingerprint `FC12214499FCC7BA1CFF6CDC0312384E3A73940B`, rồi chỉ lấy binary 3proxy. Không chạy postinstall script của package upstream.
- Ubuntu 20.04: binary 3proxy tĩnh build từ Git commit `da99424eac4092e3722f1a5b1844cfe80478f580` của tag 0.9.9.0 bằng Zig 0.13.0. Không dùng package DEB mới vì yêu cầu glibc/OpenSSL cao hơn. Mã nguồn được kiểm tra commit cố định, nhưng tag upstream không có chữ ký Git được xác minh; cần xem đây là giới hạn provenance của bản beta.
- WireGuard: dùng `wireguard-tools` và kernel của hệ điều hành. `nftables` phục vụ IPv4 NAT. Bộ cài thử cài tools từ kho OS đã cấu hình, không thêm EPEL hay kho khác.
- Firewall panel: dùng UFW hoặc firewalld khi dịch vụ tương ứng đang hoạt động, nếu không sẽ dùng lệnh `iptables` hiện có. Rule TCP 22689 được lưu trong state của QCP để có thể áp dụng lại và gỡ đúng rule do QCP tạo.

Gói phát hành chỉ chứa binary, script, unit, tài liệu và giấy phép. Không chứa compiler, dữ liệu vận hành hay bí mật. Manifest SHA256 của Go binary và 3proxy được kiểm tra trước khi cài.

Tham khảo: [3proxy releases](https://github.com/3proxy/3proxy/releases), [3proxy security](https://github.com/3proxy/3proxy/blob/master/SECURITY.md), [WireGuard tools](https://www.wireguard.com/install/).
