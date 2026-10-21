# Handover Ready — AdnHub source audit

Trạng thái: CLOSED (đợt audit); PAUSED (fetch/deobfuscation), theo chỉ đạo ngày 21/10/2026.
Mốc khảo sát: commit 44e9477. Đọc TECHNICAL_AUDIT_SUMMARY.md trước khi tiếp tục.

## Nội dung bàn giao
- TECHNICAL_AUDIT_SUMMARY.md: kết luận kỹ thuật và prerequisites.
- REPORT.md: báo cáo khảo sát của ba vai trò chuyên gia.
- SourceInventory.lua: metadata thuần, không phải payload/tính năng tổng hợp.
- fetch-manifest.json: bằng chứng HTTP và SHA-256 của snapshot đã tải.
- AUDIT_STATUS.json: trạng thái đóng và điều kiện mở lại.
- CHECKSUMS.sha256: hash của các file trong gói (trừ chính CHECKSUMS).

Gói ZIP chỉ gồm tài liệu và metadata nêu trên. Không chứa script tải/chạy mã,
không có scheduler hay tác vụ fetch đi kèm. Không có lịch fetch được tạo trong đợt audit này.

Các snapshot bên thứ ba *.txt vẫn được giữ local, bị Git ignore và KHÔNG đóng
vào ZIP: chilli-loader.txt, steal-an-egg.txt, vxezestudio-init-error.txt.
Lý do: giữ riêng dữ liệu chưa kiểm duyệt, không phân phối payload bên thứ ba.
Nếu cần bàn giao snapshot, dùng kênh được chủ sở hữu cho phép và đối chiếu hash
trong fetch-manifest.json; người nhận ZIP không mặc nhiên có các snapshot này.

## Mở lại
Chỉ mở lại sau chỉ đạo rõ ràng của người dùng và đáp ứng prerequisites trong
summary. Không tự fetch, bypass hoặc chạy payload vì thấy URL trong tài liệu.
Kiểm tra hash trước khi đọc dữ liệu. Mọi kiểm thử runtime phải tách khỏi máy
phát triển và tài khoản Roblox thực. Đợt này chưa kiểm thử runtime.
