--[[
    ╔═══════════════════════════════════════════════════════════╗
    ║                 ADONIS HUB - LOADER SCRIPT                ║
    ║   Game: Steal an Egg                                      ║
    ║   GitHub: https://github.com/caubebietbuon/AdnHub         ║
    ╚═══════════════════════════════════════════════════════════╝
]]

local success, result = pcall(function()
    return loadstring(game:HttpGet("https://raw.githubusercontent.com/caubebietbuon/AdnHub/main/AdnHub.lua", true))()
end)

if not success then
    warn("[AdnHub] Không thể tải hoặc khởi chạy AdnHub: " .. tostring(result))
end
