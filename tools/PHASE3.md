# Phase 3 — Reader discovery và khung tracer

## Kết quả hiện tại
Chỉ phân tích snapshot local; không fetch hai nguồn, không chạy g hoặc decoder.
Python đã xác nhận các anchor trong g có SHA-256 cố định. 19 test Python đạt.
Các file Luau qua kiểm tra cú pháp Lua 5.1 cho phần cú pháp chung; đó KHÔNG phải
kiểm thử Luau runtime. Máy chưa có Luau CLI/Docker; mới chuẩn bị bundle demo.

Entropy gần 8 bit/byte không tự chứng minh dữ liệu mã hóa/nén hay bắt buộc phải
chạy payload. Có thể tiếp tục dịch tĩnh reader khi đã hiểu phép biến đổi.

## Bước 1: chạy công cụ tìm reader

```powershell
python tools/decryption_finder.py
```

Đầu vào mặc định: output/stage1-vm-source.lua.txt.
Đầu ra local: output/phase3/decryption-findings.json và mask-tables.json.
Báo cáo metadata được lưu tại research/reader-discovery-2026-10-21/.
Mask tables là bản dịch đại số của TW, không phải constant table đã giải mã.

### Các hàm Python
- find: giới hạn kích thước, kiểm tra hash, tokenize và lấy vùng hàm ứng viên
  bằng analyzer. Tìm tham chiếu reader/biến trạng thái và số literal, rồi kiểm
  tra 8 đoạn anchor đã được rà soát. Không eval/exec/loadstring mã đầu vào.
- mask_tables: dịch bốn bước modulo 256 trong TW sang Python cho seed 0..255.
  Chỉ dựng bảng mask; không tự áp nó lên toàn bộ d.
- main: xử lý đường dẫn và xuất báo cáo; lỗi hash/anchor thì dừng.

### Đường khởi tạo đã lần theo từ mã
CW gọi MW, nhận loop=true và state=33. CW điều phối các hàm theo state;
MW không trực tiếp gọi sW. Trong nhánh đầu:
1. xW tại state33 tạo counter chứa bước 1, điểm đầu -1, điểm cuối 255;
   đồng thời trả các giá trị 61,123 vào các biến state của CW.
2. aW ở state6 tăng counter; khi còn trong 0..255 thì chuyển state22.
3. TW ở state22 dùng multiplier=61, increment=123 để dựng OW và VW.

Với seed s:

```text
a=(123+61*s)%256
b=(123+61*a)%256
c=(123+61*b)%256
d=(123+61*c)%256
OW[s]=a + b*256 + c*65536 + d*16777216
VW[s]=d
```

OW[0]=0xe49dca7b; VW[0]=228. Đây là hệ số của recurrence quan sát được,
không phải một key cố định áp dụng cho toàn bộ file.

### Bằng chứng reader/XOR
Offset là byte ASCII zero-based trong g đã giải nén:

| Offset | Bằng chứng | Mức kết luận |
| --- | --- | --- |
| 73244 | MW khởi tạo state33 | Quan sát trực tiếp |
| 180885 | nhánh xW trả 61,123 | Quan sát; vai trò suy ra từ các phép gán CW/TW |
| 183446 | aW đọc bộ đếm | Quan sát trực tiếp |
| 110535 / 110640 | TW recurrence và đóng gói OW/VW | Dịch đại số, có test |
| 112548 | zW XOR OW[index], mask khác và word đọc từ buffer | Quan sát; index/mask phụ thuộc state |
| 112684 | zW cập nhật modulo256 rồi XOR khi ghi byte | Quan sát; chưa biết record/offset nào của d |
| 206006 | sW gọi v rồi gọi ngay closure được trả về | Cần chặn trước lời gọi closure |

Alias [46]=readu8, [8]=readu32, [20]=bxor, [69]=writeu32, [74]=writeu8;
[104] là vị trí cursor thấy trong loader, U nhận varargs; OW/VW là bảng mask.
v còn có các __index decoder lười. Hằng số 83,187,1397969747 và các literal
khác được ghi trong report với trạng thái quan sát, không tự coi là global key.

Chưa xác lập được schema các record d, tag constant/prototype, kích thước lệnh
hay vị trí đầy đủ của bảng hằng số. Mọi phép dump trước dispatch có thể thiếu
những mục chỉ được giải mã khi __index được truy cập trong lúc chạy.

## Bước 2: các phần của tracer

### sandbox_tracer.luau
Đây là harness nhận source của adapter decoder đã rà soát và DATA dạng chuỗi.
Nó không đọc file/network và không tự nạp g. Host gọi loadstring một lần để biên
dịch adapter, sau đó hostSetfenv đặt environment allowlist đã freeze.

- libraryCopy: chỉ đưa các hàm dữ liệu cần thiết vào bản sao thư viện bất biến.
  Không đưa require, io, os, debug, coroutine, game, request, filesystem hay
  pcall/xpcall vào adapter. Thiếu API thì adapter lỗi, không tạo stub Roblox.
- encode: snapshot bằng next (không kích hoạt __index/__pairs), có xử lý vòng
  tham chiếu, key không phải string, buffer và số không hữu hạn. Snapshot tối đa
  độ sâu 6, 64 entry/table, budget1024 node; chuỗi512 byte, buffer64 byte preview.
  Trường truncated/length giữ rõ giới hạn; không tuyên bố dump đầy đủ.
- emit: xuất JSON từng dòng ra stdout, tối đa256 sự kiện. Byte không ASCII được
  escape để JSON luôn hợp lệ. Luau không cần quyền ghi file.
- traceCall: ghi arguments, gọi hàm, ghi kết quả hoặc lỗi. Các buffer wrapper dùng
  hàm này; allocation giới hạn 1MiB. Không tự log mọi phép tính/local trong VM.
- getfenv: trả environment allowlist, không trả environment caller/host.
- setfenv: ghi sự kiện rồi từ chối thay environment. _ENV chỉ là một tên biến
  được đặt bằng environment, không có ngữ nghĩa scope Lua5.2 trong Luau.
- load/loadstring của adapter: ghi preview source rồi chặn biên dịch tiếp. Chúng
  không thể bắt những chuỗi giải mã chỉ tồn tại trong local hoặc interpreter riêng.
- trace.before_dispatch(candidate,metadata): ghi snapshot rồi ném STOP_BEFORE_DISPATCH.
  Vị trí checkpoint do adapter đã rà soát chỉ định; harness không tự chứng minh
  candidate là bảng hằng số hay tự xác định ranh giới của toàn VM.

Định nghĩa các hook trong environment adapter thay vì sửa global của host.
JSON chỉ chứa snapshot có giới hạn; tuyệt đối không tự duyệt metatable để ép
lazy decode. Việc đó có thể gọi interpreter chưa được kiểm duyệt.

### decoder_adapter_template.luau
Template hiện dừng ngay với DECODER_ADAPTER_NOT_REVIEWED. Chưa có adapter trích
riêng từ g được xác minh. Không thay bằng nguyên g: khởi tạo bảng g có dependency
Roblox và sW có thể gọi closure VM ngay. Adapter thực cần chỉ chứa reader đã hiểu,
kiểm tra bounds, chuyển đổi dữ liệu và checkpoint có bằng chứng.

### tracer_demo_adapter.luau
Fixture tổng hợp: dựng OW/VW theo công thức đã biết, tạo bảng giả có tham chiếu
vòng và gọi checkpoint. Không nhận d thật, không chứa mã ứng dụng/payload. Dữ liệu
snapshot của demo luôn mang nhãn synthetic, không phải constant đã thu hồi.

## Chuẩn bị và vận hành

Chế độ mặc định chỉ chuẩn bị file, không chạy bất kỳ adapter nào:

```powershell
python tools/run_tracer.py --demo
```

Bundle entry.luau + bundle-manifest.json nằm trong một thư mục run riêng dưới
output/tracer. Dữ liệu được nhúng bằng decimal escape ba chữ số để tránh chèn
mã nguồn khi đóng gói. Input và output dump bị Git ignore.

Để chạy demo sau khi đã có image Linux cục bộ chứa Luau tại /usr/local/bin/luau:

```powershell
python tools/run_tracer.py --demo --run-isolated --image-id "sha256:<64-hex-cua-image-local>"
```

Chuỗi trong dấu <> là placeholder, phải thay bằng image ID đầy đủ đã kiểm tra.
Runner không tải image, không cài công cụ, không fallback sang chạy trực tiếp.
Image tag latest/tên remote bị từ chối; Docker context TCP/SSH cũng bị từ chối.
Nên đặt toàn bộ bước chạy trong VM dùng một lần đã ngắt NIC, không mount thư
mục cá nhân/tài khoản. Chuẩn bị Luau/image offline trước khi đưa dữ liệu vào.

Với adapter thực đã rà soát, có hash ghi nhận và data hợp lệ:

```powershell
$adapterDigest = (Get-FileHash -Algorithm SHA256 tools/my_reviewed_adapter.luau).Hash.ToLower()
python tools/run_tracer.py --adapter tools/my_reviewed_adapter.luau --reviewed-adapter-sha256 $adapterDigest --data output/stage1-vm-data.bin
```

Lệnh này vẫn chỉ chuẩn bị. Chỉ thêm --run-isolated --image-id sau khi adapter và
checkpoint được xác minh. Việc cung cấp hash giữ nguyên bản đã review, không tự
chứng minh code an toàn. Template hiện tại chưa đáp ứng điều kiện đó.

### Lớp host và đầu ra
run_tracer.py dùng Docker --network=none, --pull=never, --read-only, user không
root, cap-drop ALL, no-new-privileges, memory256MiB, swap tổng256MiB, CPU1,
pids32. Chỉ mount bundle mới readonly; stdin đóng; không mount repo/socket Docker.
Không có đường ghi trực tiếp vào host từ adapter. Host thu stdout tối đa4MiB,
timeout10s (tối đa30s), rồi xóa container theo tên riêng kể cả khi timeout.

Các file sau chỉ xuất hiện nếu thực sự chạy: trace.stdout.log, trace-events.json,
run-result.json, và constant-candidate-snapshot.json khi có sự kiện checkpoint.
File snapshot mang trạng thái bounded_adapter_checkpoint_not_verified_complete_constants.
Không có checkpoint thì không tạo file snapshot. Mỗi run dùng thư mục mới để
không lẫn file của lần trước. run-result lưu exit code và lý do dừng.

Đây là containment blueprint có giới hạn, KHÔNG phải cam kết an toàn tuyệt đối
hoặc air gap vật lý đã được thiết lập. Hook Lua không tắt network ở OS; network
none chỉ tắt networking của container. Kernel/engine/image và máy host vẫn là
phần tin cậy. Snapshot không chứng minh truy xuất được toàn bộ RAM hay constants.
Nếu engine không sẵn sàng, tool dừng và báo chưa chạy; không giảm mức cô lập.

## Kiểm tra

```powershell
python -m unittest discover -s tools -p "test_*.py" -v
```

19 test kiểm tra parser/analyzer, mask recurrence, anchor snapshot, hash lỗi,
đóng gói literal, chế độ prepare không gọi process, giới hạn adapter và flags
container/local endpoint. Chưa kiểm thử Docker/Luau runtime hoặc giải mã d.

## Tài liệu chính thức
- https://luau.org/sandbox/ : loại bỏ I/O/load trong runtime, thách thức của
  environment APIs, tài nguyên và cô lập VM.
- https://luau.org/library/ : API thư viện và environment.

Các đường dẫn này là tài liệu tham khảo; runner không truy cập chúng.
