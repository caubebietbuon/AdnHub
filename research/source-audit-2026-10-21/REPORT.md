# Báo cáo bước 1 — kiểm kê nguồn và phân tích tĩnh

Ngày: 21/10/2026. Ba chuyên gia được giao việc độc lập; Tech Lead đối chiếu kết quả với bản tải trực tiếp. Chưa thực thi bất kỳ payload nào.

## 1. Reverse Engineer
- Nhãn URL nguồn 1 và URL đích khác nhau. Chilli.lua là loader; StealAnEggg là payload đích.
- Payload trả HTTP 200, 825885 byte; header tự nhận Luraph Obfuscator v15.1.
- Quan sát: bảng hàm đánh số, blob LPH~, buffer API, wrapper setmetatable. Đây là Lua source đã làm rối, chưa có bằng chứng là Luau bytecode chuẩn.
- Chưa giải mã blob, chưa khôi phục control flow hoặc tên biến. Không thể khẳng định mã an toàn chỉ từ lớp ngoài.
- Nguồn 2 trả HTTP 403, body `error code: 1010`. Phản hồi này không cung cấp payload. Chưa xác định cơ chế bảo vệ thực tế; không suy diễn từ mã lỗi.

## 2. Roblox Lua Developer
Loader đọc game.GameId và game.PlaceId, chọn một trong sáu URL, tải bằng game.HttpGet, biên dịch loadstring rồi gọi chunk. Có tối đa ba lần thử tải với khoảng nghỉ 0.5 giây. Nhánh Steal an Egg ánh xạ GameId 10563114921 và PlaceId 107778070777162.

Trong loader, lỗi biên dịch không được báo; lỗi thực thi chunk không được pcall bắt. Chưa xác minh hành vi game phía sau payload.

| Thành phần | Kết quả kiểm chứng |
| --- | --- |
| API loader | game.GameId, game.PlaceId, game.HttpGet, pcall, loadstring, task.wait |
| API lớp ngoài payload | setmetatable, buffer.create/read/write, table/string helpers, loadstring |
| UI library / asset ID | Chưa khôi phục được |
| RemoteEvent / RemoteFunction và arguments | Chưa xác định; không đồng nghĩa chương trình không có remote |
| Farm / ESP / thao tác với trứng | Chưa có bằng chứng đủ để mô tả thuật toán |
| Nguồn 2 | Không có payload để phân tích |

## 3. Code Architect
Chưa đủ dữ liệu để so sánh tính năng hai payload hay tạo script chức năng tổng hợp. SourceInventory.lua chỉ chứa dữ liệu kiểm chứng và trạng thái; không tải/chạy mã từ xa và không được tích hợp vào AdnHub.

Tách riêng ba lớp khi có thêm nguồn: adapter game (đường dẫn và schema remote), controller tính năng (Start/Stop/Cleanup), UI. Chỉ tích hợp phần có bằng chứng về đối số, tác động, vòng đời và quyền tái sử dụng.

## 4. Bằng chứng và tái lập
fetch-manifest.json chứa URL đầy đủ, thời điểm UTC, HTTP status, kích thước và SHA-256. Bản gốc *.txt được giữ local và loại khỏi Git; chúng là dữ liệu không tin cậy. Không chạy bằng lua/loadstring. Không đưa source bên thứ ba vào bản build.

Các URL GitHub trỏ nhánh có thể thay đổi; SHA-256 giúp nhận diện đúng snapshot. Endpoint động có thể trả kết quả khác vào thời điểm khác.

## 5. Điều kiện để tiếp tục reverse
Cần payload nguồn 2 hoặc bản xuất từ môi trường mà chủ sở hữu cho phép phân tích; hoặc source không obfuscate do tác giả cung cấp. Với nguồn 1, bước tiếp theo là lập bản đồ decoder/dispatcher từ snapshot, rồi chỉ chạy các hàm giải mã đã tách và kiểm tra trong môi trường cô lập.

Hook loadstring không đảm bảo thu được source: chương trình có thể chạy qua interpreter riêng. Chưa có bytecode thì chưa thể chọn decompiler hay tuyên bố đã decompile. Không giả mạo executor hoặc vượt access control để lấy nội dung bị chặn.

## 6. Kiểm tra
Đối chiếu chéo kết quả của reverse engineer, Lua developer và architect. Kiểm tra cú pháp module inventory bằng luac; kiểm tra git diff --check. Chưa chạy Roblox, chưa kiểm chứng remote, chưa deobfuscate hoàn chỉnh.
