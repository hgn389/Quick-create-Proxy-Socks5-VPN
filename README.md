# Quick Create Proxy SOCKS5 VPN — v1.0.0-beta.4

Bản beta chạy bằng Go + 3proxy + WireGuard trên Linux/systemd, không cần Docker, database server hay webserver riêng. Panel dùng HTTPS trên cổng TCP `22689`, không chiếm cổng 80/443 của website.

## Cài nhanh bằng một lệnh

Đăng nhập VPS bằng SSH, sao chép nguyên lệnh sau và dán vào terminal:

```sh
curl -fsSL https://raw.githubusercontent.com/hgn389/Quick-create-Proxy-Socks5-VPN/v1.0.0-beta.4/install-online.sh | sudo bash
```

Lệnh này tải đúng GitHub Release `v1.0.0-beta.4`, kiểm tra SHA256, chọn binary `amd64` hoặc `arm64`, rồi hiển thị kế hoạch cài đặt để xác nhận. Nếu đang đăng nhập trực tiếp bằng `root` và máy không có `sudo`, dùng `| bash` ở cuối lệnh. Sau khi hoàn tất, terminal hiển thị URL webpanel cùng tài khoản ban đầu `admin` / `12345687`.

> Lệnh cài nhanh chỉ hoạt động sau khi tag và GitHub Release tương ứng đã được xuất bản. Trước thời điểm đó, dùng gói phát hành cục bộ theo phần cài đặt thủ công bên dưới.

## Tình trạng chức năng

- Panel một tài khoản quản trị mặc định `admin` / `12345687`, buộc đổi mật khẩu ngay sau lần đăng nhập đầu tiên, giới hạn thử đăng nhập, phiên và CSRF. Bộ cài tạo chứng chỉ HTTPS riêng cho IP panel.
- Tạo, bật, tắt, xóa SOCKS5 và HTTP proxy có `CONNECT` cho HTTPS. Mỗi proxy có user/mật khẩu riêng, port riêng, quyền đọc file riêng. Mặc định chỉ nghe trên localhost; muốn truy cập từ bên ngoài phải nhập IPv4 CIDR nguồn khi tạo.
- Khởi tạo WireGuard, tạo peer iPhone, QR/cấu hình hiện một lần, bật/tắt/thu hồi peer, xem handshake và byte nhận/gửi hiện tại. Peer chỉ lưu khóa công khai. Có full tunnel và split tunnel chỉ tới mạng WireGuard nội bộ; full tunnel đưa IPv6 vào tunnel nhưng chưa có NAT/routing IPv6 ra Internet.
- Cài/nâng cấp tại chỗ có bản sao của binary, unit và admin hash cũ; tự khôi phục các file đó nếu giai đoạn thay thế thất bại. Gỡ cài đặt giữ lại cấu hình và dữ liệu nhạy cảm trên VPS.
- Footer có `Check Update`: tra cứu GitHub Release của dự án. Khi có bản mới, nút cập nhật tải gói, kiểm tra SHA256 do GitHub công bố, rồi chạy bộ cài trong một systemd unit riêng.

Đây là beta. Chưa có quota, băng thông, hết hạn tài khoản, TOTP, phân trang, biểu đồ theo ngày/tháng, sao lưu/khôi phục qua panel hay kiểm thử tích hợp trên mọi bản phân phối. Không nên dùng làm dịch vụ proxy công cộng.

## Cài đặt từ gói phát hành

Giải nén gói `qcp-v1.0.0-beta.4-linux-amd64-arm64.tar.gz` trên VPS rồi chạy:

```sh
cd qcp-v1.0.0-beta.4
./install.sh --check
sudo ./install.sh --install
```

Bộ cài sẽ hiện kế hoạch thay đổi và yêu cầu xác nhận. Dùng `--yes` nếu chạy tự động. Sau khi cài, terminal in địa chỉ `https://IP_VPS:22689`, tài khoản `admin`, mật khẩu ban đầu `12345687` và dấu vân tay SHA256 của chứng chỉ. Ứng dụng chỉ lưu bcrypt hash; panel bắt buộc đặt mật khẩu khác trước khi dùng các chức năng quản trị. Sau đó có thể đổi mật khẩu từ footer hoặc tạo mật khẩu ngẫu nhiên bằng `sudo qcp admin rotate`.

Mở đúng URL HTTPS được in ra. Chứng chỉ được tạo riêng trên VPS nên trình duyệt sẽ cảnh báo lần đầu; đối chiếu dấu vân tay với terminal trước khi chấp nhận. Bộ cài tự thêm rule TCP 22689 vào UFW, firewalld hoặc iptables đang dùng trên máy và chỉ gỡ rule do QCP tạo. Security group/firewall ngoài VPS của nhà cung cấp vẫn cần cho phép cổng này. Nếu VPS có nhiều IP hoặc không tự phát hiện đúng IP public, đặt `QCP_PANEL_IP` lúc cài:

```sh
sudo QCP_PANEL_IP=203.0.113.10 ./install.sh --install
```

Có thể dùng SSH tunnel nếu muốn giới hạn truy cập qua SSH: `ssh -L 22689:127.0.0.1:22689 user@IP_VPS`, rồi mở `https://127.0.0.1:22689`.

Muốn kết nối proxy từ xa, nhập IPv4 CIDR nguồn cụ thể, ví dụ `203.0.113.4/32`, và mở đúng cổng TCP ở firewall VPS/nhà cung cấp. Để trống sẽ chỉ cho localhost. Không dùng `0.0.0.0/0` trừ khi thật sự cần và đã tự kiểm soát truy cập.

SOCKS5 và HTTP proxy cơ bản gửi thông tin xác thực theo dạng có thể đọc trên đường truyền. Với mạng không tin cậy, hãy dùng proxy qua WireGuard/SSH hoặc một lớp TLS do bạn cấu hình riêng.

Muốn dùng WireGuard, kernel phải có module WireGuard. Bộ cài thử cài `wireguard-tools` và `nftables` từ kho OS khi thiếu. Panel cần IP public/tên miền và cổng UDP; cổng đó phải được mở ở firewall VPS/nhà cung cấp. QCP chỉ tạo bảng NAT riêng `ip qcp_wg_nat`, không thay đổi firewall hiện hữu. Nếu host có quy tắc chặn FORWARD, quản trị viên cần cho phép lưu lượng `qcp-wg0` thủ công. Subnet beta cố định là `10.77.93.0/24`; khởi tạo sẽ dừng nếu phát hiện xung đột interface. QR chứa khóa riêng của thiết bị, hãy quét và rời trang sau khi lưu an toàn.

## Nâng cấp và gỡ

Trong panel, bấm `Check Update` ở footer. Chỉ các GitHub Release đã xuất bản, có tag dạng `vX.Y.Z` hoặc `vX.Y.Z-beta.N` và có asset tên `qcp-<tag>-linux-amd64-arm64.tar.gz` kèm SHA256 digest mới được đề xuất. Quá trình cập nhật có thể tạm ngắt panel và proxy; xem trạng thái sau khi tải lại trang. Trước khi có Release đầu tiên trên GitHub, trang sẽ báo chưa có bản phát hành.

```sh
sudo ./install.sh --install
sudo ./install.sh --uninstall
```

Gỡ cài đặt dừng các dịch vụ QCP, gỡ rule TCP 22689 do QCP tạo và xóa binary/unit; `/etc/qcp`, `/etc/wireguard/qcp-wg0.conf` và `/var/lib/qcp` vẫn ở VPS để không mất khóa hoặc metadata. Nếu cần xóa hoàn toàn, hãy tự sao lưu rồi xóa các thư mục này sau khi xác nhận không còn dùng tunnel. Tránh đưa các file đó vào GitHub hoặc gói phát hành.

## Xây dựng gói trên máy phát triển

`./scripts/build.sh` cần Go 1.27, tạo Go binary tĩnh cho amd64/arm64. `./scripts/vendor-3proxy.sh` cần `curl`, `gpg`, `dpkg-deb`, `rpm2cpio`, `cpio` và tải các package 3proxy 0.9.9.0 với manifest chữ ký được kiểm tra. `./scripts/build-3proxy-ubuntu20.sh` cần Zig 0.13.0, Git, Make để tạo 3proxy tĩnh tương thích Ubuntu 20.04 cho hai kiến trúc. Cuối cùng chạy `./scripts/package.sh`.

Mã nguồn không chứa mật khẩu, khóa VPN, file `.env`, state DB hay QR phát hành. Toàn bộ ảnh mockup được giữ cục bộ, không thêm vào Git, vì có IP minh họa và một ảnh chứa QR chưa được xác minh.

Xem [nền tảng hỗ trợ](docs/PLATFORM-SUPPORT.md), [phụ thuộc](docs/DEPENDENCIES.md) và [đặc tả gốc](docs/PROJECT-SPEC.md).
