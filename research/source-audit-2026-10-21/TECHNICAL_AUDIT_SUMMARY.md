# Tổng kết audit kỹ thuật — 21/10/2026

**Trạng thái: CLOSED / PAUSED pending authorized input.** Đợt kiểm kê hiện tại đã kết thúc; việc fetch, deobfuscate, hooking, unpacking và decompile được tạm dừng cho đến khi có đầu vào và phạm vi được cho phép. Không có yêu cầu tự động thử lại.

## Phạm vi và bằng chứng

Tổng kết này dựa trên `REPORT.md`, `SourceInventory.lua`, `fetch-manifest.json`, `AGENTS.md` và `PROJECT_MEMORY.md` đang lưu trong repository. Trong bước tổng kết không fetch mạng, không thực thi payload và không thay đổi AdnHub.

| Nguồn | Quan sát được ghi nhận | Giới hạn kết luận |
| --- | --- | --- |
| Chilli.lua | HTTP 200; 1.423 byte; loader chọn nguồn theo GameId/PlaceId rồi tải và gọi chunk qua loadstring. | Loader không chứng minh tính năng hoặc độ an toàn của payload. |
| StealAnEggg | HTTP 200; 825.885 byte; phần đầu tự nhận Luraph Obfuscator v15.1; lớp ngoài chứa bảng hàm, blob và buffer API. | Đây là source bị làm rối theo quan sát hiện có; chưa giải mã hoàn chỉnh, chưa chứng minh là Luau bytecode chuẩn. |
| VxEze init | HTTP 403; manifest ghi body lỗi dài 17 byte; REPORT.md ghi nội dung `error code: 1010`. | Không lấy được payload. Cloudflare/WAF hoặc một cơ chế Loader Shield cụ thể là nhận định chưa xác minh, không phải kết quả audit. |

Manifest lưu thời điểm UTC, URL, kích thước và SHA-256 của các bản tải thành công. Hash nhận diện snapshot; URL theo nhánh và endpoint động có thể thay đổi sau đó. Kết quả HTTP chỉ áp dụng cho lần lấy mẫu đã ghi, không chứng minh tình trạng hiện tại.

## Kết quả có thể sử dụng

- Đã phân biệt loader với payload và ghi ánh xạ Steal an Egg trong loader: GameId `10563114921`, PlaceId `107778070777162`.
- Đã kiểm kê API lớp loader/lớp ngoài. Chưa xác minh tên, đường dẫn hoặc đối số của RemoteEvent/RemoteFunction; chưa khôi phục UI library, asset ID hay thuật toán gameplay.
- `SourceInventory.lua` là metadata, không phải script tổng hợp tính năng. Không có cơ sở để tuyên bố đã hợp nhất hoặc tối ưu hai payload.
- AdnHub vẫn có Farm/ESP và các chức năng gameplay ở trạng thái demo; audit không thay đổi trạng thái này.
- Các snapshot bên thứ ba được giữ local dưới dạng TXT bị Git bỏ qua, là dữ liệu không tin cậy; không đưa vào build hoặc thực thi bằng lua/loadstring.
- Gói bàn giao ZIP chỉ chứa tài liệu, metadata và checksum. Không đóng gói raw snapshot TXT; các file này tiếp tục được giữ local và bị Git bỏ qua. `HANDOVER.md` và `AUDIT_STATUS.json` ghi hướng dẫn bàn giao và trạng thái tạm dừng.

## Điều kiện để mở lại nghiên cứu

1. Có xác nhận quyền phân tích và phạm vi sử dụng từ chủ sở hữu hoặc nguồn cấp phép phù hợp; có source dễ đọc hoặc payload được xuất/cung cấp hợp lệ, đặc biệt với nguồn 2. Quyền truy cập công khai tự nó không chứng minh quyền phân phối lại. Không giả mạo executor, vượt access control hoặc tự động thử bypass.
2. Chốt snapshot, hash, mục tiêu và dữ liệu cần trích xuất trước khi phân tích. Mọi kết luận phải dẫn đến bằng chứng trong snapshot; tách quan sát khỏi suy luận.
3. Nếu cần chạy phần decoder đã tách và kiểm tra, dùng sandbox cô lập có giới hạn thời gian, bộ nhớ và log; network mặc định tắt, chỉ mở đích được phê duyệt khi thật sự cần. Không chạy nguyên payload không tin cậy trên máy làm việc thông thường hoặc phiên Roblox/tài khoản đang dùng.
4. Xác định định dạng thực tế trước khi chọn decompiler: Lua/Luau source bị làm rối, dữ liệu nén/mã hóa, bytecode chuẩn hay bytecode của interpreter riêng. Chỉ có blob hoặc nhãn bảo vệ chưa đủ để chọn Luau decompiler. Cần bytecode tương thích với công cụ; không bảo đảm khôi phục tên biến, comment hoặc cấu trúc gốc.
5. Hook loadstring chỉ quan sát các lời gọi đi qua hook; không bảo đảm lấy được source nếu chương trình dùng interpreter riêng hoặc giải mã nhiều lớp. Chỉ thực hiện trong phạm vi được cho phép và sandbox đã chuẩn bị.

## Điều kiện trước tích hợp

Chỉ xem xét tích hợp khi đã xác minh game/phiên bản, đường dẫn và schema remote, đối số, tác động, dependency và quyền tái sử dụng. Tách adapter game, controller Start/Stop/Cleanup và UI; kiểm tra dọn task/connection khi unload. Chạy kiểm tra cú pháp và `git diff --check`; báo cáo riêng kết quả runtime Roblox. Chưa có kiểm chứng runtime hoặc remote từ đợt audit này.

**Điểm tiếp tục:** nhận đầu vào được cho phép và xác định định dạng; không tiếp tục từ giả định rằng hai nguồn đã được giải mã.
