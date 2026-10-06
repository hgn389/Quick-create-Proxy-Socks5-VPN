# Chuẩn bị xuất bản lên GitHub

Repository đích: `https://github.com/hgn389/Quick-create-Proxy-Socks5-VPN` (nhánh `main`). Thư mục beta đã gắn `origin` và fetch lịch sử hiện có. Chưa push, chưa tạo tag hay GitHub Release.

## Quy ước để nút Check Update hoạt động

- Tag của phiên bản này: `v1.0.0-beta.3`; các bản sau dùng `vMAJOR.MINOR.PATCH` hoặc `vMAJOR.MINOR.PATCH-beta.N`.
- File `VERSION` và hằng `version` trong `cmd/qcp/main.go` phải khớp tag sau khi bỏ chữ `v`.
- GitHub Release phải chứa asset `qcp-<tag>-linux-amd64-arm64.tar.gz`, ví dụ `qcp-v1.0.0-beta.3-linux-amd64-arm64.tar.gz`.
- Phải đính kèm `dist/release/SHA256SUMS` với đúng tên asset `SHA256SUMS`; lệnh cài nhanh dùng file này để xác minh archive. Auto updater yêu cầu thêm trường `digest: sha256:...` trong GitHub Release API và so sánh với file tải về. GitHub chưa có Release thì panel báo chưa có bản cập nhật.
- Bản beta phát hành bằng Release đánh dấu `prerelease`; auto updater vẫn thấy các bản beta mới hơn.

## Nội dung Git

`.gitignore` loại `dist/`, file `.env`, khóa `.key`/`.pem`, `.conf`, `.db`, log, backup, thư mục secrets/data và toàn bộ mockup. Gói Release được build cục bộ, không đưa binary hay bí mật vận hành vào commit Git. Không commit `/etc/qcp`, `/etc/wireguard`, `/var/lib/qcp` hoặc token GitHub.

## Trình tự sau khi chủ dự án xác nhận xuất bản

1. Kiểm tra danh sách file sẽ commit và diff đã stage; kiểm tra lại không có khóa, QR hoặc IP vận hành.
2. Commit mã nguồn trên nhánh `main`, tạo tag đúng phiên bản và đẩy lên `origin`.
3. Tạo GitHub Release với archive trong `dist/release/` và asset `SHA256SUMS`. Đánh dấu prerelease cho bản beta.
4. Đọc lại Release API để xác nhận asset có SHA256 digest, sau đó kiểm tra `Check Update` từ một bản cài thử.

Các bước ghi lên GitHub ở trên chưa được thực hiện.
