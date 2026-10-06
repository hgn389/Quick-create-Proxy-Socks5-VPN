# Quick create Proxy Socks5 VPN

> Bản đặc tả gốc. Theo yêu cầu bổ sung sau đó, panel bản beta dùng HTTPS trên cổng 22689, tự mở cổng ở firewall máy chủ và in URL IP:port khi cài. Tài khoản ban đầu là `admin` / `12345687` và buộc đổi mật khẩu sau lần đăng nhập đầu tiên; xem README để biết hành vi hiện tại.

## 1. Tổng quan

**Quick create Proxy Socks5 VPN** là hệ thống cài đặt và quản trị tập trung các dịch vụ truy cập mạng cá nhân trên VPS Linux. Hệ thống cho phép quản trị viên tạo nhanh tài khoản **SOCKS5**, **HTTP/HTTPS proxy** và thiết bị **WireGuard VPN**, quản lý toàn bộ bằng Web Panel, đồng thời vẫn giữ các website và webserver đang chạy trên VPS hoạt động ổn định.

Mục tiêu chính của dự án là biến các thao tác vốn phải thực hiện thủ công bằng dòng lệnh thành một quy trình đơn giản, có kiểm soát và có thể hoàn tác:

- Cài đặt nhanh trên VPS mới hoặc VPS đang chạy website.
- Tạo proxy/VPN trong vài thao tác, không cần sửa cấu hình hệ thống bằng tay.
- Dùng ứng dụng WireGuard trên iPhone để quét QR và kết nối.
- Quản lý người dùng, cổng, trạng thái, lưu lượng và nhật ký từ Web Panel.
- Chống dò mật khẩu, thử đăng nhập liên tục và truy cập trái phép.
- Bật, tắt, khởi động lại hoặc xóa từng dịch vụ độc lập.
- Gỡ cài đặt sạch, có lựa chọn giữ hoặc xóa bản sao lưu cấu hình.
- Không chiếm cổng, sửa virtual host hoặc làm gián đoạn webserver hiện hữu.

> **Lưu ý thuật ngữ:** SOCKS5 và HTTP/HTTPS là dịch vụ proxy; WireGuard là VPN. Dự án quản lý cả hai nhóm trong cùng một giao diện nhưng không xem SOCKS5 là một giao thức VPN.

## 2. Phạm vi và đối tượng sử dụng

### 2.1. Đối tượng sử dụng

- Cá nhân cần đưa lưu lượng iPhone, máy tính hoặc ứng dụng qua IP công cộng của VPS.
- Quản trị viên cần cấp nhanh nhiều tài khoản proxy hoặc nhiều cấu hình WireGuard.
- Đơn vị đang có website trên VPS và muốn bổ sung proxy/VPN mà không thay đổi hệ thống web hiện tại.

### 2.2. Phạm vi phiên bản đầu tiên

- Hệ điều hành mục tiêu: Ubuntu Server LTS, ưu tiên Ubuntu 22.04 và 24.04.
- Quản lý WireGuard, SOCKS5, HTTP proxy và HTTP CONNECT cho lưu lượng HTTPS.
- Web Panel có giao diện responsive để dùng trên điện thoại và máy tính.
- Chạy dưới dạng các service systemd độc lập.
- Lưu metadata và cấu hình quản trị trong SQLite hoặc kho dữ liệu nhẹ tương đương.
- Hỗ trợ cài đặt, nâng cấp, sao lưu, khôi phục và gỡ cài đặt.

### 2.3. Ngoài phạm vi mặc định

- Không giải mã nội dung HTTPS và không thực hiện MITM TLS.
- Không tự ý thay đổi DNS, virtual host, chứng chỉ hoặc mã nguồn website.
- Không bảo đảm ẩn danh tuyệt đối; IP đích vẫn là IP công cộng của VPS.
- Không cung cấp proxy mở, relay thư rác hoặc cơ chế né tránh quy định của nhà cung cấp VPS.

## 3. Kiến trúc tổng thể

```text
Trình duyệt quản trị
        |
        | HTTPS
        v
Web Panel + API quản trị
        |
        +----------------------+----------------------+
        |                      |                      |
        v                      v                      v
WireGuard Manager       Proxy Manager          Audit/Backup
        |                      |
        v                      +-----------+-----------+
WireGuard interface                 |           |
                              SOCKS5 service  HTTP proxy service

Website hiện hữu
        |
        +--> Nginx/Apache/Caddy trên cổng 80/443, độc lập với các service trên
```

### 3.1. Các thành phần đề xuất

1. **Web Panel**
   - Giao diện quản trị responsive.
   - Đăng nhập, phân quyền, quản lý phiên và hiển thị trạng thái hệ thống.
   - Không trực tiếp chạy lệnh shell tùy ý từ dữ liệu người dùng.

2. **Backend/API**
   - Có thể phát triển bằng Go để đóng gói thành một binary duy nhất.
   - Kiểm tra hợp lệ mọi cổng, IP, tên người dùng và tham số cấu hình.
   - Chỉ gọi các tác vụ quản trị đã định nghĩa trước, theo nguyên tắc quyền tối thiểu.

3. **WireGuard Manager**
   - Quản lý khóa server, peer, địa chỉ mạng nội bộ, thời hạn và trạng thái peer.
   - Sinh file cấu hình và QR phù hợp với ứng dụng WireGuard.
   - Ghi nhận lưu lượng vào/ra và thời điểm handshake gần nhất.

4. **Proxy Manager**
   - Tạo và quản lý SOCKS5, HTTP proxy và HTTP CONNECT.
   - Hỗ trợ xác thực user/password, giới hạn IP nguồn, thời hạn và lưu lượng.
   - Mỗi instance hoặc nhóm instance có cấu hình rõ ràng, không dùng cổng hệ thống đã có.

5. **Data store**
   - SQLite phù hợp cho một VPS và quy mô nhỏ/trung bình.
   - Chứa metadata, trạng thái, chính sách, audit log và thông tin phiên.
   - Mật khẩu không được lưu dạng rõ; khóa WireGuard và bí mật nhạy cảm phải được bảo vệ bằng quyền file chặt chẽ, và nên mã hóa khi lưu trữ nếu mô hình vận hành cho phép.

6. **Service supervisor**
   - systemd quản lý Web Panel, backend và các proxy engine.
   - Tự khởi động sau khi VPS reboot, tự phục hồi có giới hạn khi tiến trình lỗi.

7. **Firewall manager**
   - Quản lý các rule do dự án sở hữu bằng chain/table riêng hoặc marker rõ ràng.
   - Không flush toàn bộ firewall và không xóa rule của website, Docker hoặc dịch vụ khác.

## 4. Nguyên tắc không ảnh hưởng website đang chạy

Đây là yêu cầu bắt buộc của hệ thống và phải được kiểm tra trước, trong và sau khi cài đặt.

### 4.1. Cổng riêng

- Không chiếm cổng `80` và `443` nếu webserver đang sử dụng.
- Web Panel mặc định bind vào `127.0.0.1` trên một cổng quản trị riêng, ví dụ `127.0.0.1:9080`.
- Nếu cần truy cập Web Panel từ Internet, ưu tiên:
  - reverse proxy qua một subdomain riêng trên webserver hiện hữu; hoặc
  - bind trên một cổng HTTPS quản trị riêng và giới hạn IP nguồn bằng firewall.
- Dải cổng proxy phải cấu hình được, ví dụ `10000-19999`, nhưng installer phải kiểm tra cổng đang lắng nghe trước khi cấp.
- WireGuard dùng một cổng UDP riêng, ví dụ `51820/udp`, và phải cho phép thay đổi.
- Không giả định một cổng là trống chỉ vì chưa có trong file cấu hình của dự án.

### 4.2. Service riêng

- Sử dụng tên systemd riêng, ví dụ:
  - `qcp-panel.service`
  - `qcp-api.service`
  - `qcp-proxy@.service`
  - `wg-quick@qcp-wg0.service`
- Không sửa hoặc restart Nginx, Apache, Caddy, PHP-FPM, database hay ứng dụng website nếu không thật sự cần thiết.
- Nếu người dùng chọn tích hợp reverse proxy, hệ thống chỉ tạo một file cấu hình riêng, kiểm tra cú pháp trước khi reload và có bản sao để rollback.

### 4.3. Firewall và định tuyến an toàn

- Chỉ thêm rule cần thiết cho cổng quản trị, proxy và WireGuard.
- Rule NAT/forwarding của WireGuard phải có phạm vi interface/subnet cụ thể.
- Không xóa hoặc thay thế toàn bộ cấu hình `nftables`, `iptables` hay UFW hiện có.
- Trước khi áp dụng rule, phải kiểm tra đường truy cập SSH hiện tại để tránh tự khóa quản trị viên khỏi VPS.
- Khi gỡ cài đặt, chỉ xóa các rule có ID, comment, chain hoặc table thuộc dự án.

### 4.4. Kiểm tra tương thích trước cài đặt

Installer phải thu thập và báo cáo ít nhất:

- Cổng TCP/UDP đang sử dụng.
- Webserver và container đang chạy.
- Trạng thái UFW/nftables/iptables.
- Interface mạng mặc định và IP public dự kiến.
- Trạng thái IP forwarding.
- Phiên bản hệ điều hành và kiến trúc CPU.
- Dung lượng đĩa, bộ nhớ và quyền quản trị.

Nếu phát hiện xung đột, installer phải dừng trước khi thay đổi hệ thống và đưa ra lựa chọn cổng khác; không tự động ghi đè.

## 5. Tính năng chi tiết

### 5.1. Web Panel

- Dashboard hiển thị:
  - trạng thái các service;
  - IP public của VPS;
  - tổng số WireGuard peer và proxy;
  - số kết nối đang hoạt động;
  - lưu lượng theo ngày/tháng;
  - cảnh báo lỗi, cổng xung đột hoặc chứng chỉ sắp hết hạn.
- Danh sách proxy/VPN với tìm kiếm, lọc và phân trang.
- Tạo, sửa, bật, tắt, khởi động lại và xóa cấu hình.
- Sao chép endpoint và thông tin kết nối có kiểm soát.
- Sinh QR WireGuard, tải file `.conf` và thu hồi peer.
- Whitelist IP nguồn cho Web Panel hoặc từng proxy.
- Đặt ngày hết hạn, quota lưu lượng, giới hạn kết nối và băng thông nếu proxy engine hỗ trợ.
- Xem log hoạt động và lịch sử thay đổi.
- Hiển thị bí mật một lần khi tạo; không đưa mật khẩu/khóa riêng vào danh sách hoặc log.
- Hỗ trợ đăng xuất mọi phiên và thu hồi phiên quản trị.

### 5.2. WireGuard cho iPhone

Quy trình sử dụng dự kiến:

1. Quản trị viên tạo một peer mới và đặt tên thiết bị, ví dụ `iphone-an`.
2. Backend sinh cặp khóa và cấp địa chỉ IP nội bộ không trùng lặp.
3. Web Panel hiển thị QR của cấu hình client.
4. Trên iPhone, người dùng mở ứng dụng **WireGuard** → chọn thêm tunnel → quét QR.
5. Người dùng bật tunnel để kết nối qua VPS.
6. Quản trị viên có thể xem handshake/lưu lượng, tắt peer hoặc thu hồi khóa.

Hai chế độ định tuyến nên được hỗ trợ:

- **Full tunnel:** toàn bộ lưu lượng Internet của iPhone đi qua VPS.
- **Split tunnel:** chỉ các subnet/địa chỉ được chỉ định đi qua WireGuard.

Yêu cầu bảo mật QR:

- QR chứa khóa riêng của client, vì vậy phải được xem là dữ liệu bí mật.
- Không cache QR công khai, không ghi QR hoặc cấu hình client vào access log.
- QR nên chỉ hiển thị sau khi xác thực lại hoặc trong thời gian ngắn.
- Cho phép xóa bản cấu hình client phía server sau khi người dùng tải/quét; server chỉ cần thông tin peer cần thiết để xác thực kết nối.
- Khi nghi ngờ lộ QR, phải thu hồi peer và tạo peer mới, không tái sử dụng khóa cũ.

### 5.3. SOCKS5 proxy

- Tạo nhanh endpoint theo mẫu `IP_VPS:PORT`.
- Xác thực username/password riêng cho từng tài khoản.
- Tùy chọn chỉ cho phép một hoặc nhiều IP nguồn.
- Bật/tắt độc lập, đổi mật khẩu, đặt ngày hết hạn và xóa tài khoản.
- Theo dõi lưu lượng, kết nối đang hoạt động và lỗi xác thực.
- Không cho phép chế độ anonymous/open proxy theo mặc định.
- Có chính sách giới hạn số kết nối, tốc độ và số lần xác thực thất bại.

### 5.4. HTTP và HTTPS proxy

- Hỗ trợ HTTP forward proxy.
- Hỗ trợ phương thức `CONNECT` để chuyển tiếp kết nối HTTPS mà không giải mã TLS.
- Có xác thực, whitelist, quota và giới hạn kết nối tương tự SOCKS5.
- Chặn các đích/range nhạy cảm theo mặc định nếu có nguy cơ SSRF hoặc truy cập mạng nội bộ không mong muốn, ví dụ metadata endpoint của nhà cung cấp cloud.
- Không quảng bá là “HTTPS proxy” theo nghĩa giải mã HTTPS; hệ thống chỉ tạo đường hầm CONNECT trừ khi có một tính năng TLS proxy riêng được thiết kế và kiểm toán.

### 5.5. Tạo nhanh proxy/VPN

Web Panel cung cấp wizard ngắn:

1. Chọn loại: WireGuard, SOCKS5 hoặc HTTP/HTTPS proxy.
2. Chọn/tự động cấp cổng trống trong dải cho phép.
3. Nhập tên, chính sách truy cập, ngày hết hạn và giới hạn tài nguyên.
4. Sinh thông tin xác thực mạnh tự động hoặc cho phép nhập theo chính sách.
5. Kiểm tra xung đột và hiển thị bản xem trước.
6. Áp dụng cấu hình theo giao dịch: nếu service không khởi động hoặc health check thất bại, tự rollback.
7. Trả về endpoint, QR hoặc file cấu hình phù hợp.

Hệ thống cũng có thể hỗ trợ tạo hàng loạt từ mẫu, nhưng phải có giới hạn số lượng, kiểm tra dải cổng và màn hình xác nhận trước khi áp dụng.

## 6. Bảo mật

### 6.1. Bảo vệ đăng nhập Web Panel

- Chỉ cho phép HTTPS khi truy cập từ xa.
- Mật khẩu phải được băm bằng Argon2id hoặc bcrypt với tham số phù hợp; không mã hóa hai chiều thay cho hashing.
- Khuyến nghị hỗ trợ TOTP 2FA và recovery code dùng một lần.
- Cookie phiên phải có `Secure`, `HttpOnly` và `SameSite` phù hợp.
- Đổi session ID sau khi đăng nhập; hết hạn phiên khi không hoạt động và có thời hạn tối đa.
- Bảo vệ CSRF cho thao tác thay đổi trạng thái.
- Thiết lập CSP, chống clickjacking, kiểm tra Origin/Host và escape dữ liệu hiển thị.
- Không đưa token, password, private key vào URL, log hoặc thông báo lỗi.

### 6.2. Chống brute-force và thử đăng nhập nhiều lần

Cơ chế nên kết hợp nhiều lớp:

- Rate limit theo IP và theo tài khoản.
- Backoff tăng dần sau mỗi lần thất bại.
- Khóa tạm thời tài khoản sau ngưỡng cấu hình được, ví dụ 5 lần thất bại trong 15 phút.
- Không khóa vĩnh viễn chỉ bằng lưu lượng từ bên ngoài để tránh bị lợi dụng gây từ chối dịch vụ.
- Thông báo đăng nhập thất bại dùng nội dung chung, không tiết lộ tài khoản có tồn tại hay không.
- Ghi audit event cho login thành công/thất bại, khóa tạm, mở khóa và đổi mật khẩu.
- Có thể tích hợp Fail2ban hoặc cơ chế firewall động cho IP tấn công lặp lại.
- CAPTCHA chỉ nên là lớp bổ sung sau dấu hiệu bất thường, không thay thế rate limiting/2FA.
- Cảnh báo quản trị viên khi có số lần thất bại bất thường hoặc đăng nhập từ IP mới.

Chính sách tương tự phải áp dụng cho xác thực proxy: giới hạn thử sai, theo dõi nguồn tấn công và chặn tạm thời mà không làm gián đoạn người dùng hợp lệ.

### 6.3. Quyền hệ thống và bí mật

- Web process chạy bằng user hệ thống riêng, không chạy thường trực bằng root.
- Tác vụ cần quyền cao đi qua helper có danh sách lệnh cố định hoặc policy sudo tối thiểu.
- File cấu hình chứa bí mật có owner/group cụ thể và quyền tối đa `0600` khi phù hợp.
- Không truyền bí mật qua tham số dòng lệnh có thể bị lộ trong danh sách process.
- Mã hóa backup chứa khóa/bí mật và tách khóa mã hóa khỏi file backup.
- Có quy trình xoay vòng mật khẩu quản trị, thông tin xác thực proxy và khóa WireGuard.

### 6.4. Bảo vệ API

- API quản trị không mở công khai nếu không cần thiết.
- Mọi endpoint thay đổi trạng thái đều yêu cầu xác thực và kiểm tra quyền.
- Áp dụng schema validation, giới hạn kích thước request và timeout.
- Không cho phép người dùng đưa trực tiếp shell command, đường dẫn tùy ý hoặc template systemd tùy ý.
- Dùng request ID cho truy vết nhưng không chứa dữ liệu nhạy cảm.
- Các thao tác nguy hiểm như xóa toàn bộ, khôi phục backup hoặc đổi network cần xác nhận lại.

## 7. Firewall và chính sách mạng

### 7.1. Nguyên tắc

- Mặc định deny cho cổng quản trị từ Internet, sau đó chỉ mở theo allowlist hoặc cơ chế truy cập đã chọn.
- Chỉ mở các cổng proxy thực sự đang bật.
- Mở cổng WireGuard bằng UDP, không mở TCP cùng số cổng nếu không cần.
- Hỗ trợ IPv4 và IPv6 có chủ đích; không để IPv6 trở thành đường vòng ngoài chính sách IPv4.
- Chặn truy cập không cần thiết từ proxy đến mạng loopback, link-local, metadata cloud và subnet quản trị.
- Bật IP forwarding chỉ khi WireGuard/routing cần và ghi nhận giá trị ban đầu để khôi phục khi gỡ cài đặt.

### 7.2. Tính tương thích

- Phát hiện hệ thống đang dùng UFW, nftables, iptables hoặc firewall do nhà cung cấp quản lý.
- Không trộn nhiều backend firewall một cách mù quáng.
- Nếu Docker đang chạy, phải kiểm tra tương tác với chain của Docker trước khi áp dụng.
- Mọi thay đổi firewall phải có bản xem trước, health check và đường rollback.

## 8. systemd và vận hành service

Mỗi service cần có unit riêng, với các nguyên tắc:

- `Restart=on-failure` và giới hạn tần suất restart để tránh vòng lặp.
- Chạy bằng user/group riêng nếu service không bắt buộc root.
- Khai báo dependency mạng phù hợp.
- Sử dụng hardening của systemd khi tương thích, như giới hạn filesystem, capability và syscall.
- Không ghi file vào thư mục mã nguồn; tách binary, config, state và log.
- Kiểm tra cấu hình trước khi restart.
- Khi nâng cấp, thực hiện theo thứ tự: backup → kiểm tra → thay binary/config → restart → health check → rollback nếu lỗi.

Trạng thái service trên Web Panel phải phản ánh trạng thái thực tế từ systemd/health check, không chỉ dựa trên cờ lưu trong database.

## 9. Logging và audit

### 9.1. Operational log

Ghi lại sự kiện vận hành phục vụ chẩn đoán:

- Service start/stop/restart và lỗi cấu hình.
- Kết nối, ngắt kết nối và lỗi mạng ở mức cần thiết.
- Tình trạng health check, cổng xung đột và lỗi firewall.
- Mức log cấu hình được; production không bật debug kéo dài.

### 9.2. Audit log

Ghi lại hành động quản trị theo cấu trúc bất biến ở mức ứng dụng:

- Ai thực hiện, thời gian, IP nguồn, action và đối tượng bị tác động.
- Tạo/sửa/bật/tắt/xóa proxy hoặc peer.
- Đăng nhập, đăng xuất, thất bại xác thực, đổi mật khẩu và thay đổi quyền.
- Thay đổi firewall, cài đặt, nâng cấp, restore và uninstall.
- Kết quả thành công/thất bại và request ID.

Audit log không được chứa mật khẩu, token, private key, QR payload hoặc toàn bộ file WireGuard client.

### 9.3. Lưu giữ và xoay log

- Tích hợp journald hoặc logrotate.
- Có giới hạn dung lượng và thời gian giữ log để tránh đầy ổ đĩa.
- Cho phép xuất audit log để lưu trữ ngoài VPS.
- Đồng bộ thời gian bằng NTP để timestamp đáng tin cậy.

## 10. Sao lưu và khôi phục cấu hình

### 10.1. Nội dung backup

- Database/metadata của Web Panel.
- Cấu hình WireGuard server và peer cần thiết.
- Cấu hình proxy.
- Cấu hình tích hợp reverse proxy do dự án tạo.
- Manifest phiên bản, checksum, danh sách service và firewall rule thuộc dự án.
- Không mặc định sao lưu log traffic dung lượng lớn.

### 10.2. Yêu cầu backup

- Backup phải nhất quán; khóa ghi hoặc dùng cơ chế snapshot an toàn với database.
- File backup có checksum, phiên bản schema và ngày tạo.
- Backup chứa bí mật phải được mã hóa.
- Quyền truy cập file backup phải hạn chế.
- Có chính sách giữ nhiều phiên bản và dọn bản cũ.
- Khuyến nghị lưu thêm một bản ngoài VPS.

### 10.3. Khôi phục

- Kiểm tra checksum, phiên bản và dung lượng trước khi restore.
- Tạo backup hiện trạng trước khi ghi đè.
- Hỗ trợ chế độ dry-run để báo xung đột cổng/interface.
- Sau restore phải kiểm tra service, firewall, WireGuard handshake và endpoint proxy.
- Tự rollback về trạng thái trước restore nếu bước kiểm tra quan trọng thất bại.

## 11. Cấu trúc thư mục đề xuất

```text
/usr/local/bin/
└── qcp                         # CLI/backend binary

/etc/qcp/
├── qcp.yaml                    # Cấu hình chung, không chứa password dạng rõ
├── panel.yaml                  # Cấu hình Web Panel/API
├── proxies/                    # Cấu hình từng proxy hoặc nhóm proxy
└── secrets/                    # Bí mật, quyền truy cập chặt chẽ

/etc/wireguard/
└── qcp-wg0.conf                # Interface WireGuard do dự án quản lý

/var/lib/qcp/
├── qcp.db                      # Database trạng thái/metadata
├── backups/                    # Backup cục bộ đã mã hóa
└── runtime/                    # Dữ liệu runtime

/var/log/qcp/                   # Chỉ dùng nếu không ghi hoàn toàn vào journald

/etc/systemd/system/
├── qcp-panel.service
├── qcp-api.service
└── qcp-proxy@.service
```

Tên và đường dẫn thực tế có thể thay đổi, nhưng mỗi thư mục phải có owner, quyền truy cập, vòng đời và trách nhiệm rõ ràng.

## 12. Quy trình cài đặt đề xuất

### Giai đoạn 1: Preflight chỉ đọc

1. Xác nhận hệ điều hành, kiến trúc và quyền quản trị.
2. Phát hiện webserver, container, firewall, cổng và interface đang hoạt động.
3. Kiểm tra DNS/subdomain quản trị nếu người dùng chọn tích hợp HTTPS.
4. Kiểm tra khả năng giữ nguyên SSH và website.
5. Hiển thị kế hoạch thay đổi đầy đủ trước khi áp dụng.

### Giai đoạn 2: Backup và chuẩn bị

1. Sao lưu các file hệ thống sẽ được chỉnh sửa.
2. Tạo user/group hệ thống và cấu trúc thư mục.
3. Cài binary/package với checksum hoặc chữ ký đã xác minh.
4. Sinh secret ban đầu bằng nguồn ngẫu nhiên mật mã.

### Giai đoạn 3: Cấu hình dịch vụ

1. Cấu hình Web Panel trên loopback hoặc cổng riêng.
2. Tạo unit systemd và bật service cần thiết.
3. Thiết lập WireGuard interface nếu được chọn.
4. Thêm firewall rule có định danh riêng.
5. Chỉ tạo cấu hình reverse proxy sau khi người dùng đồng ý.

### Giai đoạn 4: Kiểm tra sau cài đặt

1. Kiểm tra website hiện hữu qua HTTP/HTTPS.
2. Kiểm tra webserver và các service website không bị restart ngoài kế hoạch.
3. Kiểm tra Web Panel, xác thực và TLS.
4. Kiểm tra SOCKS5/HTTP proxy bằng tài khoản thử.
5. Kiểm tra WireGuard handshake, DNS và IP egress.
6. Kiểm tra reboot persistence của systemd ở thời điểm bảo trì phù hợp.
7. Xuất báo cáo cài đặt, cổng đã dùng và vị trí backup.

Installer cần idempotent: chạy lại không tạo trùng cấu hình, rule hoặc user; mọi thay đổi phải có thể xác định nguồn gốc.

## 13. Bật, tắt và xóa tài nguyên

### 13.1. Bật/tắt

- Bật/tắt từng proxy hoặc WireGuard peer độc lập.
- Tắt peer bằng cách loại peer khỏi cấu hình runtime nhưng vẫn giữ metadata để có thể bật lại.
- Tắt proxy phải đóng cổng tương ứng và xác nhận không còn listener.
- Bật lại phải kiểm tra cổng và chính sách trước khi khởi động.
- Mọi thao tác đều có audit log và trạng thái kết quả.

### 13.2. Xóa

- Xóa một proxy phải dừng service, xóa cấu hình liên quan và gỡ đúng firewall rule của proxy đó.
- Xóa WireGuard peer phải thu hồi quyền truy cập ngay và xóa dữ liệu client nhạy cảm còn lưu.
- Không tái sử dụng credential hoặc khóa đã thu hồi.
- Có xác nhận cho thao tác xóa và tùy chọn thời gian khôi phục mềm trước khi xóa vĩnh viễn metadata không nhạy cảm.

## 14. Quy trình gỡ cài đặt sạch

Uninstaller phải cung cấp ít nhất hai chế độ:

- **Gỡ ứng dụng, giữ backup:** xóa service/binary/runtime nhưng giữ một backup đã mã hóa và hướng dẫn khôi phục.
- **Gỡ hoàn toàn:** xóa toàn bộ thành phần thuộc dự án sau khi xác nhận rõ ràng.

Trình tự đề xuất:

1. Kiểm tra và hiển thị chính xác thành phần sẽ bị xóa.
2. Tùy chọn tạo backup cuối cùng.
3. Dừng và disable các service thuộc dự án.
4. Thu hồi peer, đóng listener và gỡ các firewall/NAT rule có định danh của dự án.
5. Gỡ unit systemd, binary và file cấu hình thuộc dự án.
6. Khôi phục các sysctl mà dự án đã thay đổi nếu không còn dịch vụ khác cần chúng.
7. Gỡ file reverse proxy riêng của dự án; kiểm tra cú pháp trước khi reload webserver.
8. Xóa user/group hệ thống khi không còn file/process sở hữu.
9. Tùy lựa chọn, giữ hoặc xóa database, backup và log.
10. Xác nhận website, SSH, firewall và webserver vẫn hoạt động.
11. Xuất báo cáo những gì đã xóa, những gì được giữ và vị trí backup.

Uninstaller tuyệt đối không được:

- Flush toàn bộ firewall.
- Xóa cấu hình webserver không do dự án tạo.
- Xóa interface, route, package hoặc sysctl đang được dịch vụ khác sử dụng.
- Xóa dữ liệu bằng glob hoặc đường dẫn chưa được kiểm tra.

## 15. CLI đề xuất

Ngoài Web Panel, một CLI tối thiểu giúp khôi phục khi giao diện web không truy cập được:

```text
qcp status
qcp doctor
qcp proxy list
qcp proxy create
qcp proxy enable <id>
qcp proxy disable <id>
qcp proxy remove <id>
qcp wireguard peer list
qcp wireguard peer create
qcp wireguard peer revoke <id>
qcp backup create
qcp backup verify <file>
qcp restore <file> --dry-run
qcp uninstall
```

CLI phải dùng cùng lớp kiểm tra hợp lệ và audit với Web Panel; không tạo một đường quản trị yếu hơn.

## 16. Health check và quan sát hệ thống

- Kiểm tra process và trạng thái systemd.
- Kiểm tra listener đúng IP/cổng.
- Kiểm tra API nội bộ và database.
- Kiểm tra WireGuard interface, route và handshake.
- Kiểm tra proxy authentication bằng tài khoản health-check giới hạn.
- Theo dõi CPU, RAM, disk, file descriptor và bandwidth.
- Cảnh báo khi disk gần đầy, service restart lặp lại, lỗi xác thực tăng đột biến hoặc cổng bị chiếm.
- Không gửi credential hoặc dữ liệu traffic nhạy cảm sang hệ thống telemetry mặc định.

## 17. Tiêu chí triển khai an toàn

Một bản triển khai chỉ được xem là đạt yêu cầu khi thỏa tất cả tiêu chí sau:

### 17.1. Trước triển khai

- Có danh sách đầy đủ các cổng và service hiện hữu.
- Có backup các file sẽ thay đổi và đã kiểm tra khả năng đọc backup.
- Không có xung đột cổng/interface/subnet.
- Có đường truy cập SSH dự phòng hoặc console của nhà cung cấp VPS.
- Xác định rõ firewall backend và cách rollback.
- Đã chọn cơ chế TLS cho Web Panel.

### 17.2. Sau triển khai

- Website hiện hữu trả về nội dung và chứng chỉ đúng như trước.
- Nginx/Apache/Caddy và ứng dụng website không phát sinh lỗi mới.
- Web Panel không mở bằng HTTP công khai.
- Tài khoản mặc định đã bị vô hiệu hóa hoặc buộc đổi mật khẩu khi đăng nhập đầu tiên.
- Rate limit, khóa tạm và audit login hoạt động.
- Không có open proxy; truy cập sai credential bị từ chối.
- Cổng chỉ mở đúng theo cấu hình.
- QR/private key không xuất hiện trong log.
- WireGuard full tunnel không làm rò DNS theo chính sách đã chọn.
- Service tự khởi động đúng sau reboot và không rơi vào restart loop.
- Backup có thể verify; quy trình restore đã được thử nghiệm trên môi trường kiểm tra.
- Quy trình uninstall dry-run xác định đúng tài nguyên của dự án.

### 17.3. Kiểm thử bảo mật tối thiểu

- Thử brute-force có kiểm soát để xác nhận rate limit/temporary lock.
- Kiểm tra session fixation, CSRF và quyền truy cập API.
- Kiểm tra input injection đối với tên, cổng, IP và tham số cấu hình.
- Kiểm tra không thể đọc file bí mật bằng user dịch vụ không liên quan.
- Kiểm tra proxy không truy cập được endpoint metadata cloud theo chính sách.
- Kiểm tra IPv6 không bypass firewall hoặc định tuyến.
- Quét cổng từ bên ngoài trước và sau cài đặt để so sánh.
- Kiểm tra rollback khi service, firewall hoặc health check thất bại.

## 18. Đề xuất công nghệ

- **Backend/API:** Go.
- **Web UI:** HTML template + JavaScript nhẹ hoặc một frontend SPA nhỏ, tùy quy mô.
- **Database:** SQLite cho một VPS; có thể hỗ trợ PostgreSQL nếu triển khai nhiều node sau này.
- **VPN:** WireGuard và `wg`/netlink API.
- **Proxy engine:** chọn engine đã được duy trì, hỗ trợ xác thực và thống kê; bọc bằng adapter để có thể thay thế.
- **Service manager:** systemd.
- **Firewall:** nftables là hướng ưu tiên trên hệ thống mới, nhưng phải tương thích với firewall hiện hữu.
- **TLS:** dùng reverse proxy hiện hữu hoặc ACME client có phạm vi cấu hình rõ ràng.
- **Logging:** structured JSON kết hợp journald và audit store.

Việc chọn proxy engine cụ thể cần dựa trên khả năng bảo trì, giấy phép, hỗ trợ IPv6, xác thực, giới hạn tài nguyên và mức độ dễ cô lập; không nên tự viết giao thức proxy từ đầu nếu không có yêu cầu đặc biệt.

## 19. Lộ trình phát triển đề xuất

### Giai đoạn 1 — Nền tảng an toàn

- Preflight, cấu trúc thư mục, database và systemd.
- Đăng nhập Web Panel, 2FA, rate limit và audit.
- Quản lý một WireGuard interface và peer/QR.
- Quản lý SOCKS5/HTTP proxy cơ bản.
- Backup, health check và uninstall có dry-run.

### Giai đoạn 2 — Quản trị nâng cao

- Quota, giới hạn băng thông/kết nối và ngày hết hạn.
- Tạo hàng loạt, template và tìm kiếm/lọc.
- Cảnh báo, thống kê và export audit.
- IPv6 và nhiều interface/public IP.

### Giai đoạn 3 — Quy mô lớn

- Quản lý nhiều VPS từ một control plane.
- Tách control plane và agent.
- RBAC nhiều quản trị viên.
- PostgreSQL, hàng đợi tác vụ và centralized observability.
- Rolling update và policy đồng bộ giữa các node.

## 20. Tiêu chí hoàn thành phiên bản đầu tiên

Phiên bản đầu tiên được xem là hoàn thành khi quản trị viên có thể:

1. Cài đặt dự án trên Ubuntu LTS đang chạy website mà website không gián đoạn ngoài cửa sổ reload đã được chấp thuận.
2. Đăng nhập Web Panel qua HTTPS với cơ chế chống brute-force hoạt động.
3. Tạo WireGuard peer, quét QR bằng iPhone và truy cập Internet qua IP VPS.
4. Tạo SOCKS5 và HTTP/HTTPS CONNECT proxy có xác thực, sau đó bật/tắt/xóa độc lập.
5. Xem trạng thái, lưu lượng cơ bản và audit log mà không làm lộ bí mật.
6. Sao lưu, xác minh và khôi phục cấu hình trên môi trường thử nghiệm.
7. Gỡ cài đặt sạch chỉ các tài nguyên thuộc dự án, giữ nguyên SSH, firewall ngoài phạm vi và webserver/website hiện hữu.

---

Tài liệu này là đặc tả tổng quan ban đầu. Trước khi triển khai production cần bổ sung thiết kế chi tiết cho schema dữ liệu, API, quyền RBAC, proxy engine được chọn, mô hình firewall theo từng hệ điều hành và bộ kiểm thử rollback/uninstall tự động.
