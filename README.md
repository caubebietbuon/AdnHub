# 🥚 Adonis Hub (Adn Hub) - Steal an Egg

> **Futuristic Dark Glass UI Script Menu** dành cho trò chơi Roblox **Steal an Egg**.

> **Trạng thái:** Farm, Auto Steal, Base Return, Vacuum, bộ lọc trứng và ESP hiện là demo giao diện, chưa có logic game. Boost FPS tắt bóng và hiệu ứng hiện có, khôi phục khi tắt hoặc unload.
>
> Hướng dẫn bảo trì và lịch sử lỗi: [PROJECT_MEMORY.md](PROJECT_MEMORY.md).

---

## ✨ Điểm Nổi Bật Trong Thiết Kế

- **Futuristic Dark Glass:** Nền kính mờ tối màu sâu, kết hợp hiệu ứng viền phát sáng gradient xoay động giữa dải màu **Neon Cyan** & **Electric Purple**. Cả 4 góc đều được bo tròn mềm mại và đồng nhất.
- **Header Sang Trọng:** Tên hiệu **ADONIS HUB** với chữ kim loại chuyển sắc (Metallic Gradient), biểu tượng quả trứng neon và các nút điều khiển thu nhỏ (`—`), đóng (`✕`) có micro-interactions mượt mà.
- **Floating Pill Mode:** Khi thu nhỏ, cửa sổ tự động biến thành nút hình viên thuốc (*Floating Pill*) nhỏ gọn `🥚 ADN HUB`, tự do kéo thả bất kỳ đâu trên màn hình để mở lại.
- **Sidebar Navigation Tinh Gọn:**
  - 📬 **Contact:** Thông tin hệ thống, tối ưu FPS & Boost Lag, liên kết hỗ trợ cộng đồng / Discord.
  - 🥚 **Farm:** Tự động cướp trứng (Auto Steal), vận chuyển về Base, hút trứng từ xa (Silent Vacuum), thanh trượt cự ly (Egg Steal Range 0-100 studs), bộ lọc loại trứng, ESP hào quang trứng.
  - ⚙️ **Cài đặt:** Phím tắt đóng/mở menu mặc định (`Right Control`), gỡ hoàn toàn script (`Unload UI`), khôi phục vị trí mặc định.
- **Hệ thống Notification Tích Hợp:** Khung thông báo trượt động với thanh trạng thái phát sáng tương ứng theo ngữ cảnh (Success, Info, Warning, Error).

---

## 🚀 Cách Chạy Script

Dán đoạn mã dưới đây vào bất kỳ Roblox Executor nào (Delta, Fluxus, Wave, Solara, Synapse Z, Hydrogen, Arceus X,...):

```lua
loadstring(game:HttpGet("https://raw.githubusercontent.com/caubebietbuon/AdnHub/main/AdnHub.lua", true))()
```

Hoặc chạy file `Loader.lua`:

```lua
loadstring(game:HttpGet("https://raw.githubusercontent.com/caubebietbuon/AdnHub/main/Loader.lua", true))()
```

---

## ⌨️ Phím Tắt Mặc Định

| Phím Tắt | Chức Năng |
| :--- | :--- |
| `Right Control` | Ẩn / Hiện toàn bộ Menu Adn Hub |

---

## 🎨 Cấu Trúc Dự Án

```
AdnHub/
├── AdnHub.lua       # Toàn bộ mã nguồn UI Library + Script Steal an Egg
├── Loader.lua       # Script Loader siêu nhẹ tải từ GitHub Raw
└── README.md        # Tài liệu hướng dẫn sử dụng và giới thiệu
```

---

## 📜 Bản Quyền & Giấy Phép
Dự án được phát triển dưới giấy phép mã nguồn mở MIT. Vui lòng ghi nguồn khi tái sử dụng giao diện UI Library.
