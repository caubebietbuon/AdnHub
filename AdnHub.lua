--[[
    ╔════════════════════════════════════════════════════════════════════════╗
    ║                                                                        ║
    ║      █████╗ ██████╗ ███╗   ██╗    ██╗  ██╗██╗   ██╗██████╗             ║
    ║     ██╔══██╗██╔══██╗████╗  ██║    ██║  ██║██║   ██║██╔══██╗            ║
    ║     ███████║██║  ██║██╔██╗ ██║    ███████║██║   ██║██████╔╝            ║
    ║     ██╔══██║██║  ██║██║╚██╗██║    ██╔══██║██║   ██║██╔══██╗            ║
    ║     ██║  ██║██████╔╝██║ ╚████║    ██║  ██║╚██████╔╝██████╔╝            ║
    ║     ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝             ║
    ║                                                                        ║
    ║   • Project: Adonis Hub (Adn Hub) - Neo-Glassmorphism 2.0 UI           ║
    ║   • Target Game: Steal an Egg                                          ║
    ║   • Style: Futuristic Deep Dark Glass • Electric Cyan & Purple Glow   ║
    ║   • Engine: Roblox Luau (Supported on all modern executors)           ║
    ╚════════════════════════════════════════════════════════════════════════╝
]]

local TweenService = game:GetService("TweenService")
local UserInputService = game:GetService("UserInputService")
local RunService = game:GetService("RunService")
local Players = game:GetService("Players")
local CoreGui = game:GetService("CoreGui")

local LocalPlayer = Players.LocalPlayer
local Mouse = LocalPlayer:GetMouse()

-- Xử lý an toàn cho Parent ScreenGui (Bảo vệ trước Anti-Cheat Client)
local function getSafeGuiParent()
    if gethui then
        return gethui()
    elseif syn and syn.protect_gui then
        local gui = Instance.new("Folder")
        syn.protect_gui(gui)
        gui.Parent = CoreGui
        return gui
    elseif CoreGui:FindFirstChild("RobloxGui") then
        return CoreGui
    else
        return LocalPlayer:WaitForChild("PlayerGui")
    end
end

-- Âm thanh tương tác tinh tế
local function playClickSound()
    local sound = Instance.new("Sound")
    sound.SoundId = "rbxassetid://6895079853"
    sound.Volume = 0.25
    sound.Parent = getSafeGuiParent()
    sound:Play()
    game:GetService("Debris"):AddItem(sound, 1)
end

-- Bảng màu Futuristic Neo-Glassmorphism 2.0
local Themes = {
    Background = Color3.fromRGB(11, 14, 21),
    BackgroundGlass = Color3.fromRGB(15, 19, 30),
    Sidebar = Color3.fromRGB(13, 16, 25),
    Card = Color3.fromRGB(20, 25, 38),
    CardHover = Color3.fromRGB(26, 33, 50),
    AccentCyan = Color3.fromRGB(0, 230, 255),
    AccentPurple = Color3.fromRGB(168, 85, 247),
    AccentAmber = Color3.fromRGB(251, 191, 36),
    AccentGreen = Color3.fromRGB(16, 185, 129),
    TextPrimary = Color3.fromRGB(245, 248, 255),
    TextSecondary = Color3.fromRGB(148, 163, 184),
    TextMuted = Color3.fromRGB(90, 102, 124),
    Border = Color3.fromRGB(56, 189, 248),
    BorderDim = Color3.fromRGB(30, 41, 59),
    CloseHover = Color3.fromRGB(239, 68, 68)
}

-- Module Thư Viện UI
local AdnHubLib = {}
AdnHubLib.__index = AdnHubLib

-- Helper: Tween mượt mà
local function tween(object, info, properties)
    local tw = TweenService:Create(object, info, properties)
    tw:Play()
    return tw
end

-- Hệ thống Notification Thông Minh
function AdnHubLib:Notify(config)
    local title = config.Title or "Adonis Hub"
    local desc = config.Content or ""
    local duration = config.Duration or 3.5
    local nType = config.Type or "Info" -- Info, Success, Warning, Error

    local accentColor = Themes.AccentCyan
    if nType == "Success" then accentColor = Themes.AccentGreen
    elseif nType == "Warning" then accentColor = Themes.AccentAmber
    elseif nType == "Error" then accentColor = Themes.CloseHover
    end

    local notifContainer = getSafeGuiParent():FindFirstChild("AdnHub_NotifContainer")
    if not notifContainer then
        local sg = Instance.new("ScreenGui")
        sg.Name = "AdnHub_NotifContainer"
        sg.ResetOnSpawn = false
        sg.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
        sg.Parent = getSafeGuiParent()

        notifContainer = Instance.new("Frame")
        notifContainer.Name = "Container"
        notifContainer.AnchorPoint = Vector2.new(1, 1)
        notifContainer.Position = UDim2.new(1, -20, 1, -20)
        notifContainer.Size = UDim2.new(0, 280, 0, 500)
        notifContainer.BackgroundTransparency = 1
        notifContainer.Parent = sg

        local listLayout = Instance.new("UIListLayout")
        listLayout.VerticalAlignment = Enum.VerticalAlignment.Bottom
        listLayout.HorizontalAlignment = Enum.HorizontalAlignment.Right
        listLayout.Padding = UDim.new(0, 10)
        listLayout.Parent = notifContainer
    else
        notifContainer = notifContainer:FindFirstChild("Container")
    end

    local notifCard = Instance.new("Frame")
    notifCard.Name = "Notification"
    notifCard.Size = UDim2.new(1, 0, 0, 68)
    notifCard.BackgroundColor3 = Themes.Card
    notifCard.BackgroundTransparency = 0.15
    notifCard.Position = UDim2.new(1, 300, 0, 0)
    notifCard.Parent = notifContainer

    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 10)
    corner.Parent = notifCard

    local stroke = Instance.new("UIStroke")
    stroke.Thickness = 1
    stroke.Color = accentColor
    stroke.Transparency = 0.5
    stroke.Parent = notifCard

    local glowBar = Instance.new("Frame")
    glowBar.Size = UDim2.new(0, 4, 1, -16)
    glowBar.Position = UDim2.new(0, 8, 0, 8)
    glowBar.BackgroundColor3 = accentColor
    glowBar.BorderSizePixel = 0
    glowBar.Parent = notifCard

    local barCorner = Instance.new("UICorner")
    barCorner.CornerRadius = UDim.new(0, 4)
    barCorner.Parent = glowBar

    local tLabel = Instance.new("TextLabel")
    tLabel.Font = Enum.Font.GothamBold
    tLabel.TextSize = 13
    tLabel.TextColor3 = Themes.TextPrimary
    tLabel.TextXAlignment = Enum.TextXAlignment.Left
    tLabel.BackgroundTransparency = 1
    tLabel.Position = UDim2.new(0, 22, 0, 10)
    tLabel.Size = UDim2.new(1, -30, 0, 18)
    tLabel.Text = title
    tLabel.Parent = notifCard

    local dLabel = Instance.new("TextLabel")
    dLabel.Font = Enum.Font.Gotham
    dLabel.TextSize = 11
    dLabel.TextColor3 = Themes.TextSecondary
    dLabel.TextXAlignment = Enum.TextXAlignment.Left
    dLabel.TextWrapped = true
    dLabel.BackgroundTransparency = 1
    dLabel.Position = UDim2.new(0, 22, 0, 28)
    dLabel.Size = UDim2.new(1, -30, 0, 32)
    dLabel.Text = desc
    dLabel.Parent = notifCard

    -- Slide In animation
    notifCard.Position = UDim2.new(1, 100, 0, 0)
    notifCard.BackgroundTransparency = 1
    tLabel.TextTransparency = 1
    dLabel.TextTransparency = 1
    stroke.Transparency = 1

    tween(notifCard, TweenInfo.new(0.4, Enum.EasingStyle.Quart, Enum.EasingDirection.Out), {
        Position = UDim2.new(0, 0, 0, 0),
        BackgroundTransparency = 0.15
    })
    tween(stroke, TweenInfo.new(0.4), {Transparency = 0.5})
    tween(tLabel, TweenInfo.new(0.4), {TextTransparency = 0})
    tween(dLabel, TweenInfo.new(0.4), {TextTransparency = 0})

    task.delay(duration, function()
        if notifCard and notifCard.Parent then
            local tw = tween(notifCard, TweenInfo.new(0.35, Enum.EasingStyle.Quart, Enum.EasingDirection.In), {
                Position = UDim2.new(1, 300, 0, 0),
                BackgroundTransparency = 1
            })
            tween(stroke, TweenInfo.new(0.3), {Transparency = 1})
            tween(tLabel, TweenInfo.new(0.3), {TextTransparency = 1})
            tween(dLabel, TweenInfo.new(0.3), {TextTransparency = 1})
            tw.Completed:Connect(function()
                notifCard:Destroy()
            end)
        end
    end)
end

-- Tạo Cửa Sổ Chính
function AdnHubLib:CreateWindow(config)
    config = config or {}
    local Title = config.Title or "ADONIS HUB"
    local Subtitle = config.Subtitle or "Steal an Egg"
    local DefaultKeybind = config.ToggleKey or Enum.KeyCode.RightControl

    -- ScreenGui
    local ScreenGui = Instance.new("ScreenGui")
    ScreenGui.Name = "AdnHub_Gui"
    ScreenGui.ResetOnSpawn = false
    ScreenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    ScreenGui.Parent = getSafeGuiParent()

    -- Main Container Frame
    local MainFrame = Instance.new("Frame")
    MainFrame.Name = "MainFrame"
    MainFrame.Size = UDim2.new(0, 750, 0, 480)
    MainFrame.AnchorPoint = Vector2.new(0.5, 0.5)
    MainFrame.Position = UDim2.new(0.5, 0, 0.5, 0)
    MainFrame.BackgroundColor3 = Themes.BackgroundGlass
    MainFrame.BackgroundTransparency = 0.12
    MainFrame.ClipsDescendants = true
    MainFrame.Parent = ScreenGui

    -- Bo góc lớn thanh lịch
    local MainCorner = Instance.new("UICorner")
    MainCorner.CornerRadius = UDim.new(0, 16)
    MainCorner.Parent = MainFrame

    -- Viền phát sáng siêu mỏng (Glowing Gradient Border)
    local MainStroke = Instance.new("UIStroke")
    MainStroke.Thickness = 1.2
    MainStroke.ApplyStrokeMode = Enum.ApplyStrokeMode.Border
    MainStroke.Color = Themes.AccentCyan
    MainStroke.Transparency = 0.4
    MainStroke.Parent = MainFrame

    local StrokeGradient = Instance.new("UIGradient")
    StrokeGradient.Color = ColorSequence.new({
        ColorSequenceKeypoint.new(0, Themes.AccentCyan),
        ColorSequenceKeypoint.new(0.5, Themes.AccentPurple),
        ColorSequenceKeypoint.new(1, Themes.AccentCyan)
    })
    StrokeGradient.Rotation = 45
    StrokeGradient.Parent = MainStroke

    -- Hiệu ứng Gradient xoay nhẹ viền kính sống động
    task.spawn(function()
        while ScreenGui and ScreenGui.Parent do
            StrokeGradient.Rotation = (StrokeGradient.Rotation + 1) % 360
            RunService.RenderStepped:Wait()
        end
    end)

    -- Drop Shadow giả lập chiều sâu
    local ShadowHolder = Instance.new("ImageLabel")
    ShadowHolder.Name = "Shadow"
    ShadowHolder.AnchorPoint = Vector2.new(0.5, 0.5)
    ShadowHolder.Position = UDim2.new(0.5, 0, 0.5, 0)
    ShadowHolder.Size = UDim2.new(1, 50, 1, 50)
    ShadowHolder.BackgroundTransparency = 1
    ShadowHolder.Image = "rbxassetid://6015897843"
    ShadowHolder.ImageColor3 = Color3.fromRGB(0, 0, 0)
    ShadowHolder.ImageTransparency = 0.4
    ShadowHolder.ZIndex = MainFrame.ZIndex - 1
    ShadowHolder.Parent = ScreenGui

    -- Đồng bộ kích thước shadow
    MainFrame:GetPropertyChangedSignal("Position"):Connect(function()
        ShadowHolder.Position = MainFrame.Position
    end)
    MainFrame:GetPropertyChangedSignal("Size"):Connect(function()
        ShadowHolder.Size = UDim2.new(0, MainFrame.Size.X.Offset + 50, 0, MainFrame.Size.Y.Offset + 50)
    end)

    -- HEADER
    local Header = Instance.new("Frame")
    Header.Name = "Header"
    Header.Size = UDim2.new(1, 0, 0, 52)
    Header.BackgroundColor3 = Themes.Background
    Header.BackgroundTransparency = 0.5
    Header.BorderSizePixel = 0
    Header.Parent = MainFrame

    -- Đường kẻ mờ ngăn cách header
    local HeaderDivider = Instance.new("Frame")
    HeaderDivider.Size = UDim2.new(1, 0, 0, 1)
    HeaderDivider.Position = UDim2.new(0, 0, 1, -1)
    HeaderDivider.BackgroundColor3 = Themes.BorderDim
    HeaderDivider.BackgroundTransparency = 0.5
    HeaderDivider.BorderSizePixel = 0
    HeaderDivider.Parent = Header

    -- Logo Icon (Hình quả trứng neon)
    local LogoIcon = Instance.new("TextLabel")
    LogoIcon.Name = "LogoIcon"
    LogoIcon.Size = UDim2.new(0, 36, 0, 36)
    LogoIcon.Position = UDim2.new(0, 14, 0, 8)
    LogoIcon.BackgroundColor3 = Themes.Card
    LogoIcon.BackgroundTransparency = 0.4
    LogoIcon.Text = "🥚"
    LogoIcon.TextSize = 20
    LogoIcon.Parent = Header

    local LogoCorner = Instance.new("UICorner")
    LogoCorner.CornerRadius = UDim.new(0, 10)
    LogoCorner.Parent = LogoIcon

    local LogoStroke = Instance.new("UIStroke")
    LogoStroke.Thickness = 1
    LogoStroke.Color = Themes.AccentCyan
    LogoStroke.Transparency = 0.6
    LogoStroke.Parent = LogoIcon

    -- Title: ADONIS HUB (Metallic Cyan Gradient)
    local TitleLabel = Instance.new("TextLabel")
    TitleLabel.Name = "TitleLabel"
    TitleLabel.Font = Enum.Font.GothamBold
    TitleLabel.TextSize = 16
    TitleLabel.TextXAlignment = Enum.TextXAlignment.Left
    TitleLabel.BackgroundTransparency = 1
    TitleLabel.Position = UDim2.new(0, 58, 0, 9)
    TitleLabel.Size = UDim2.new(0, 200, 0, 18)
    TitleLabel.Text = Title
    TitleLabel.TextColor3 = Themes.TextPrimary
    TitleLabel.Parent = Header

    local TitleGradient = Instance.new("UIGradient")
    TitleGradient.Color = ColorSequence.new({
        ColorSequenceKeypoint.new(0, Color3.fromRGB(255, 255, 255)),
        ColorSequenceKeypoint.new(0.7, Themes.AccentCyan),
        ColorSequenceKeypoint.new(1, Themes.AccentPurple)
    })
    TitleGradient.Parent = TitleLabel

    -- Subtitle / Game Badge
    local SubtitleLabel = Instance.new("TextLabel")
    SubtitleLabel.Name = "SubtitleLabel"
    SubtitleLabel.Font = Enum.Font.GothamMedium
    SubtitleLabel.TextSize = 11
    SubtitleLabel.TextXAlignment = Enum.TextXAlignment.Left
    SubtitleLabel.BackgroundTransparency = 1
    SubtitleLabel.Position = UDim2.new(0, 58, 0, 28)
    SubtitleLabel.Size = UDim2.new(0, 250, 0, 14)
    SubtitleLabel.Text = Subtitle .. " • Neo-Glassmorphism 2.0"
    SubtitleLabel.TextColor3 = Themes.TextMuted
    SubtitleLabel.Parent = Header

    -- Nút Window Controls (Minimize, Close)
    local WindowControls = Instance.new("Frame")
    WindowControls.Name = "Controls"
    WindowControls.AnchorPoint = Vector2.new(1, 0.5)
    WindowControls.Position = UDim2.new(1, -14, 0.5, 0)
    WindowControls.Size = UDim2.new(0, 70, 0, 28)
    WindowControls.BackgroundTransparency = 1
    WindowControls.Parent = Header

    local MinBtn = Instance.new("TextButton")
    MinBtn.Name = "MinBtn"
    MinBtn.Size = UDim2.new(0, 30, 0, 28)
    MinBtn.Position = UDim2.new(0, 0, 0, 0)
    MinBtn.BackgroundColor3 = Themes.Card
    MinBtn.BackgroundTransparency = 0.5
    MinBtn.Text = "—"
    MinBtn.Font = Enum.Font.GothamBold
    MinBtn.TextSize = 12
    MinBtn.TextColor3 = Themes.TextSecondary
    MinBtn.AutoButtonColor = false
    MinBtn.Parent = WindowControls

    local MinCorner = Instance.new("UICorner")
    MinCorner.CornerRadius = UDim.new(0, 8)
    MinCorner.Parent = MinBtn

    local CloseBtn = Instance.new("TextButton")
    CloseBtn.Name = "CloseBtn"
    CloseBtn.Size = UDim2.new(0, 30, 0, 28)
    CloseBtn.Position = UDim2.new(1, -30, 0, 0)
    CloseBtn.BackgroundColor3 = Themes.Card
    CloseBtn.BackgroundTransparency = 0.5
    CloseBtn.Text = "✕"
    CloseBtn.Font = Enum.Font.GothamBold
    CloseBtn.TextSize = 12
    CloseBtn.TextColor3 = Themes.TextSecondary
    CloseBtn.AutoButtonColor = false
    CloseBtn.Parent = WindowControls

    local CloseCorner = Instance.new("UICorner")
    CloseCorner.CornerRadius = UDim.new(0, 8)
    CloseCorner.Parent = CloseBtn

    -- Micro-interactions cho Nút Controls
    MinBtn.MouseEnter:Connect(function()
        tween(MinBtn, TweenInfo.new(0.2), {BackgroundColor3 = Themes.CardHover, TextColor3 = Themes.AccentCyan})
    end)
    MinBtn.MouseLeave:Connect(function()
        tween(MinBtn, TweenInfo.new(0.2), {BackgroundColor3 = Themes.Card, TextColor3 = Themes.TextSecondary})
    end)

    CloseBtn.MouseEnter:Connect(function()
        tween(CloseBtn, TweenInfo.new(0.2), {BackgroundColor3 = Themes.CloseHover, TextColor3 = Color3.fromRGB(255, 255, 255)})
    end)
    CloseBtn.MouseLeave:Connect(function()
        tween(CloseBtn, TweenInfo.new(0.2), {BackgroundColor3 = Themes.Card, TextColor3 = Themes.TextSecondary})
    end)

    -- Kéo thả cửa sổ mượt mà (Smooth Draggable)
    local dragging, dragInput, dragStart, startPos
    Header.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
            dragging = true
            dragStart = input.Position
            startPos = MainFrame.Position
            input.Changed:Connect(function()
                if input.UserInputState == Enum.UserInputState.End then
                    dragging = false
                end
            end)
        end
    end)

    Header.InputChanged:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch then
            dragInput = input
        end
    end)

    UserInputService.InputChanged:Connect(function(input)
        if input == dragInput and dragging then
            local delta = input.Position - dragStart
            tween(MainFrame, TweenInfo.new(0.08, Enum.EasingStyle.Sine), {
                Position = UDim2.new(
                    startPos.X.Scale,
                    startPos.X.Offset + delta.X,
                    startPos.Y.Scale,
                    startPos.Y.Offset + delta.Y
                )
            })
        end
    end)

    -- SIDEBAR NAVIGATION (Bên Trái)
    local Sidebar = Instance.new("Frame")
    Sidebar.Name = "Sidebar"
    Sidebar.Size = UDim2.new(0, 200, 1, -52)
    Sidebar.Position = UDim2.new(0, 0, 0, 52)
    Sidebar.BackgroundColor3 = Themes.Sidebar
    Sidebar.BackgroundTransparency = 0.5
    Sidebar.BorderSizePixel = 0
    Sidebar.Parent = MainFrame

    local SidebarDivider = Instance.new("Frame")
    SidebarDivider.Size = UDim2.new(0, 1, 1, 0)
    SidebarDivider.Position = UDim2.new(1, -1, 0, 0)
    SidebarDivider.BackgroundColor3 = Themes.BorderDim
    SidebarDivider.BackgroundTransparency = 0.6
    SidebarDivider.BorderSizePixel = 0
    SidebarDivider.Parent = Sidebar

    -- Scroll danh sách Tab
    local TabScroll = Instance.new("ScrollingFrame")
    TabScroll.Name = "TabScroll"
    TabScroll.Size = UDim2.new(1, 0, 1, -64)
    TabScroll.Position = UDim2.new(0, 0, 0, 8)
    TabScroll.BackgroundTransparency = 1
    TabScroll.BorderSizePixel = 0
    TabScroll.ScrollBarThickness = 2
    TabScroll.ScrollBarImageColor3 = Themes.AccentCyan
    TabScroll.ScrollBarImageTransparency = 0.7
    TabScroll.CanvasSize = UDim2.new(0, 0, 0, 0)
    TabScroll.AutomaticCanvasSize = Enum.AutomaticSize.Y
    TabScroll.Parent = Sidebar

    local TabListLayout = Instance.new("UIListLayout")
    TabListLayout.HorizontalAlignment = Enum.HorizontalAlignment.Center
    TabListLayout.Padding = UDim.new(0, 6)
    TabListLayout.Parent = TabScroll

    -- User Profile Badge ở góc dưới Sidebar
    local UserProfile = Instance.new("Frame")
    UserProfile.Name = "UserProfile"
    UserProfile.Size = UDim2.new(1, -16, 0, 48)
    UserProfile.Position = UDim2.new(0, 8, 1, -56)
    UserProfile.BackgroundColor3 = Themes.Card
    UserProfile.BackgroundTransparency = 0.4
    UserProfile.Parent = Sidebar

    local UserCorner = Instance.new("UICorner")
    UserCorner.CornerRadius = UDim.new(0, 10)
    UserCorner.Parent = UserProfile

    local AvatarImg = Instance.new("ImageLabel")
    AvatarImg.Size = UDim2.new(0, 32, 0, 32)
    AvatarImg.Position = UDim2.new(0, 8, 0.5, -16)
    AvatarImg.BackgroundTransparency = 1
    AvatarImg.Image = Players:GetUserThumbnailAsync(LocalPlayer.UserId, Enum.ThumbnailType.HeadShot, Enum.ThumbnailSize.Size420x420)
    AvatarImg.Parent = UserProfile

    local AvatarCorner = Instance.new("UICorner")
    AvatarCorner.CornerRadius = UDim.new(1, 0)
    AvatarCorner.Parent = AvatarImg

    local UserName = Instance.new("TextLabel")
    UserName.Font = Enum.Font.GothamBold
    UserName.TextSize = 12
    UserName.TextColor3 = Themes.TextPrimary
    UserName.TextXAlignment = Enum.TextXAlignment.Left
    UserName.TextTruncate = Enum.TextTruncate.AtEnd
    UserName.BackgroundTransparency = 1
    UserName.Position = UDim2.new(0, 46, 0, 8)
    UserName.Size = UDim2.new(1, -52, 0, 15)
    UserName.Text = LocalPlayer.DisplayName
    UserName.Parent = UserProfile

    local UserRole = Instance.new("TextLabel")
    UserRole.Font = Enum.Font.Gotham
    UserRole.TextSize = 10
    UserRole.TextColor3 = Themes.AccentCyan
    UserRole.TextXAlignment = Enum.TextXAlignment.Left
    UserRole.BackgroundTransparency = 1
    UserRole.Position = UDim2.new(0, 46, 0, 24)
    UserRole.Size = UDim2.new(1, -52, 0, 14)
    UserRole.Text = "Premium User • v2.0"
    UserRole.Parent = UserProfile

    -- CONTENT AREA (Bên Phải)
    local ContentArea = Instance.new("Frame")
    ContentArea.Name = "ContentArea"
    ContentArea.Size = UDim2.new(1, -200, 1, -52)
    ContentArea.Position = UDim2.new(0, 200, 0, 52)
    ContentArea.BackgroundTransparency = 1
    ContentArea.ClipsDescendants = true
    ContentArea.Parent = MainFrame

    -- FLOATING PILL BUTTON KHI THU NHỎ (MINIMIZE)
    local FloatingPill = Instance.new("TextButton")
    FloatingPill.Name = "AdnHub_FloatingPill"
    FloatingPill.Size = UDim2.new(0, 140, 0, 40)
    FloatingPill.Position = UDim2.new(0, 20, 0, 80)
    FloatingPill.BackgroundColor3 = Themes.BackgroundGlass
    FloatingPill.BackgroundTransparency = 0.15
    FloatingPill.Text = "🥚 ADN HUB"
    FloatingPill.Font = Enum.Font.GothamBold
    FloatingPill.TextSize = 13
    FloatingPill.TextColor3 = Themes.AccentCyan
    FloatingPill.AutoButtonColor = false
    FloatingPill.Visible = false
    FloatingPill.Parent = ScreenGui

    local PillCorner = Instance.new("UICorner")
    PillCorner.CornerRadius = UDim.new(1, 0)
    PillCorner.Parent = FloatingPill

    local PillStroke = Instance.new("UIStroke")
    PillStroke.Thickness = 1.2
    PillStroke.Color = Themes.AccentCyan
    PillStroke.Transparency = 0.3
    PillStroke.Parent = FloatingPill

    -- Drag cho Floating Pill
    local pillDragging, pillDragStart, pillStartPos
    FloatingPill.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
            pillDragging = true
            pillDragStart = input.Position
            pillStartPos = FloatingPill.Position
            input.Changed:Connect(function()
                if input.UserInputState == Enum.UserInputState.End then
                    pillDragging = false
                end
            end)
        end
    end)
    UserInputService.InputChanged:Connect(function(input)
        if pillDragging and (input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch) then
            local delta = input.Position - pillDragStart
            FloatingPill.Position = UDim2.new(
                pillStartPos.X.Scale,
                pillStartPos.X.Offset + delta.X,
                pillStartPos.Y.Scale,
                pillStartPos.Y.Offset + delta.Y
            )
        end
    end)

    -- Minimize Functionality
    local isMinimized = false
    local function setMinimized(state)
        isMinimized = state
        playClickSound()
        if state then
            tween(MainFrame, TweenInfo.new(0.3, Enum.EasingStyle.Quart, Enum.EasingDirection.In), {
                Size = UDim2.new(0, 0, 0, 0),
                BackgroundTransparency = 1
            })
            tween(ShadowHolder, TweenInfo.new(0.2), {ImageTransparency = 1})
            task.delay(0.3, function()
                MainFrame.Visible = false
                FloatingPill.Visible = true
                FloatingPill.Size = UDim2.new(0, 0, 0, 0)
                tween(FloatingPill, TweenInfo.new(0.3, Enum.EasingStyle.Back, Enum.EasingDirection.Out), {
                    Size = UDim2.new(0, 140, 0, 40)
                })
            end)
        else
            FloatingPill.Visible = false
            MainFrame.Visible = true
            tween(MainFrame, TweenInfo.new(0.35, Enum.EasingStyle.Back, Enum.EasingDirection.Out), {
                Size = UDim2.new(0, 750, 0, 480),
                BackgroundTransparency = 0.12
            })
            tween(ShadowHolder, TweenInfo.new(0.3), {ImageTransparency = 0.4})
        end
    end

    MinBtn.MouseButton1Click:Connect(function()
        setMinimized(true)
    end)

    FloatingPill.MouseButton1Click:Connect(function()
        setMinimized(false)
    end)

    -- Close Functionality
    local function closeMenu()
        playClickSound()
        tween(MainFrame, TweenInfo.new(0.25, Enum.EasingStyle.Quart, Enum.EasingDirection.In), {
            Size = UDim2.new(0, 600, 0, 0),
            BackgroundTransparency = 1
        })
        tween(ShadowHolder, TweenInfo.new(0.2), {ImageTransparency = 1})
        task.delay(0.25, function()
            ScreenGui:Destroy()
            AdnHubLib:Notify({
                Title = "Adonis Hub",
                Content = "Menu đã được gỡ thành công. Cảm ơn bạn!",
                Type = "Info"
            })
        end)
    end
    CloseBtn.MouseButton1Click:Connect(closeMenu)

    -- Keybind đóng mở menu
    local isVisible = true
    UserInputService.InputBegan:Connect(function(input, gameProcessed)
        if not gameProcessed and input.KeyCode == DefaultKeybind then
            isVisible = not isVisible
            MainFrame.Visible = isVisible
            ShadowHolder.Visible = isVisible
            if isMinimized then
                FloatingPill.Visible = isVisible
            end
        end
    end)

    -- Window Object
    local Window = {
        ScreenGui = ScreenGui,
        MainFrame = MainFrame,
        ContentArea = ContentArea,
        TabScroll = TabScroll,
        Tabs = {},
        CurrentTab = nil
    }

    -- TẠO TAB MỚI
    function Window:CreateTab(tabName, iconEmoji)
        iconEmoji = iconEmoji or "📁"
        
        local TabBtn = Instance.new("TextButton")
        TabBtn.Name = "Tab_" .. tabName
        TabBtn.Size = UDim2.new(1, -16, 0, 38)
        TabBtn.BackgroundColor3 = Themes.Card
        TabBtn.BackgroundTransparency = 1
        TabBtn.Text = ""
        TabBtn.AutoButtonColor = false
        TabBtn.Parent = TabScroll

        local TabBtnCorner = Instance.new("UICorner")
        TabBtnCorner.CornerRadius = UDim.new(0, 10)
        TabBtnCorner.Parent = TabBtn

        local ActiveIndicator = Instance.new("Frame")
        ActiveIndicator.Name = "ActiveIndicator"
        ActiveIndicator.Size = UDim2.new(0, 3, 0, 18)
        ActiveIndicator.Position = UDim2.new(0, 4, 0.5, -9)
        ActiveIndicator.BackgroundColor3 = Themes.AccentCyan
        ActiveIndicator.BackgroundTransparency = 1
        ActiveIndicator.BorderSizePixel = 0
        ActiveIndicator.Parent = TabBtn

        local ActiveCorner = Instance.new("UICorner")
        ActiveCorner.CornerRadius = UDim.new(1, 0)
        ActiveCorner.Parent = ActiveIndicator

        local IconLabel = Instance.new("TextLabel")
        IconLabel.Name = "Icon"
        IconLabel.Size = UDim2.new(0, 24, 1, 0)
        IconLabel.Position = UDim2.new(0, 12, 0, 0)
        IconLabel.BackgroundTransparency = 1
        IconLabel.Text = iconEmoji
        IconLabel.TextSize = 15
        IconLabel.Parent = TabBtn

        local NameLabel = Instance.new("TextLabel")
        NameLabel.Name = "Name"
        NameLabel.Size = UDim2.new(1, -44, 1, 0)
        NameLabel.Position = UDim2.new(0, 38, 0, 0)
        NameLabel.BackgroundTransparency = 1
        NameLabel.Font = Enum.Font.GothamMedium
        NameLabel.TextSize = 13
        NameLabel.TextColor3 = Themes.TextSecondary
        NameLabel.TextXAlignment = Enum.TextXAlignment.Left
        NameLabel.Text = tabName
        NameLabel.Parent = TabBtn

        -- Trang nội dung (Content Page)
        local Page = Instance.new("ScrollingFrame")
        Page.Name = "Page_" .. tabName
        Page.Size = UDim2.new(1, -24, 1, -16)
        Page.Position = UDim2.new(0, 12, 0, 8)
        Page.BackgroundTransparency = 1
        Page.BorderSizePixel = 0
        Page.ScrollBarThickness = 3
        Page.ScrollBarImageColor3 = Themes.AccentCyan
        Page.ScrollBarImageTransparency = 0.6
        Page.CanvasSize = UDim2.new(0, 0, 0, 0)
        Page.AutomaticCanvasSize = Enum.AutomaticSize.Y
        Page.Visible = false
        Page.Parent = ContentArea

        local PageLayout = Instance.new("UIListLayout")
        PageLayout.HorizontalAlignment = Enum.HorizontalAlignment.Center
        PageLayout.Padding = UDim.new(0, 12)
        PageLayout.Parent = Page

        local TabObj = {
            Button = TabBtn,
            Page = Page,
            Name = tabName,
            Layout = PageLayout
        }

        -- Chuyển Tab (Spring / Elastic Slide Animation)
        function TabObj:Activate()
            if Window.CurrentTab == TabObj then return end

            playClickSound()

            -- Tắt tab cũ
            if Window.CurrentTab then
                local oldTab = Window.CurrentTab
                tween(oldTab.Button, TweenInfo.new(0.2), {BackgroundTransparency = 1})
                tween(oldTab.Button.ActiveIndicator, TweenInfo.new(0.2), {BackgroundTransparency = 1})
                tween(oldTab.Button.Name, TweenInfo.new(0.2), {
                    TextColor3 = Themes.TextSecondary,
                    Position = UDim2.new(0, 38, 0, 0)
                })

                -- Ẩn trang cũ với hiệu ứng slide & fade
                local oldPage = oldTab.Page
                local outTween = tween(oldPage, TweenInfo.new(0.2, Enum.EasingStyle.Quart, Enum.EasingDirection.In), {
                    Position = UDim2.new(0, -20, 0, 8)
                })
                outTween.Completed:Connect(function()
                    oldPage.Visible = false
                end)
            end

            -- Bật tab mới
            Window.CurrentTab = TabObj
            tween(TabBtn, TweenInfo.new(0.25), {
                BackgroundColor3 = Themes.Card,
                BackgroundTransparency = 0.5
            })
            tween(ActiveIndicator, TweenInfo.new(0.25), {BackgroundTransparency = 0})
            tween(NameLabel, TweenInfo.new(0.25), {
                TextColor3 = Themes.AccentCyan,
                Position = UDim2.new(0, 42, 0, 0)
            })

            -- Hiệu ứng Spring Slide vào trang mới
            Page.Position = UDim2.new(0, 40, 0, 8)
            Page.Visible = true
            tween(Page, TweenInfo.new(0.35, Enum.EasingStyle.Back, Enum.EasingDirection.Out), {
                Position = UDim2.new(0, 12, 0, 8)
            })
        end

        -- Micro-interaction hover vào Tab
        TabBtn.MouseEnter:Connect(function()
            if Window.CurrentTab ~= TabObj then
                tween(TabBtn, TweenInfo.new(0.18), {BackgroundTransparency = 0.75, BackgroundColor3 = Themes.Card})
                tween(NameLabel, TweenInfo.new(0.18), {TextColor3 = Themes.TextPrimary, Position = UDim2.new(0, 41, 0, 0)})
            end
        end)

        TabBtn.MouseLeave:Connect(function()
            if Window.CurrentTab ~= TabObj then
                tween(TabBtn, TweenInfo.new(0.18), {BackgroundTransparency = 1})
                tween(NameLabel, TweenInfo.new(0.18), {TextColor3 = Themes.TextSecondary, Position = UDim2.new(0, 38, 0, 0)})
            end
        end)

        TabBtn.MouseButton1Click:Connect(function()
            TabObj:Activate()
        end)

        -- TẠO SECTION (Phần con với UX Whitespace mượt mà)
        function TabObj:CreateSection(sectionTitle)
            local SectionContainer = Instance.new("Frame")
            SectionContainer.Name = "Section_" .. sectionTitle
            SectionContainer.Size = UDim2.new(1, 0, 0, 0)
            SectionContainer.AutomaticSize = Enum.AutomaticSize.Y
            SectionContainer.BackgroundTransparency = 1
            SectionContainer.Parent = Page

            local SectionLayout = Instance.new("UIListLayout")
            SectionLayout.Padding = UDim.new(0, 8)
            SectionLayout.Parent = SectionContainer

            -- Tiêu đề Section phong cách Neo-Minimalist
            local TitleFrame = Instance.new("Frame")
            TitleFrame.Name = "TitleFrame"
            TitleFrame.Size = UDim2.new(1, 0, 0, 24)
            TitleFrame.BackgroundTransparency = 1
            TitleFrame.Parent = SectionContainer

            local SLabel = Instance.new("TextLabel")
            SLabel.Font = Enum.Font.GothamBold
            SLabel.TextSize = 12
            SLabel.TextColor3 = Themes.AccentCyan
            SLabel.TextXAlignment = Enum.TextXAlignment.Left
            SLabel.BackgroundTransparency = 1
            SLabel.Size = UDim2.new(0, 200, 1, 0)
            SLabel.Position = UDim2.new(0, 4, 0, 0)
            SLabel.Text = string.upper(sectionTitle)
            SLabel.Parent = TitleFrame

            local SLine = Instance.new("Frame")
            SLine.Size = UDim2.new(1, -120, 0, 1)
            SLine.AnchorPoint = Vector2.new(1, 0.5)
            SLine.Position = UDim2.new(1, 0, 0.5, 0)
            SLine.BackgroundColor3 = Themes.BorderDim
            SLine.BackgroundTransparency = 0.5
            SLine.BorderSizePixel = 0
            SLine.Parent = TitleFrame

            local Section = {}

            -- 1. TOGGLE SWITCH (Capsule Minimalist)
            function Section:CreateToggle(tConfig)
                tConfig = tConfig or {}
                local title = tConfig.Name or "Toggle Switch"
                local default = tConfig.Default or false
                local callback = tConfig.Callback or function() end
                local isDesignOnly = tConfig.DesignOnly or false

                local ToggleCard = Instance.new("TextButton")
                ToggleCard.Name = "ToggleCard"
                ToggleCard.Size = UDim2.new(1, 0, 0, 44)
                ToggleCard.BackgroundColor3 = Themes.Card
                ToggleCard.BackgroundTransparency = 0.4
                ToggleCard.AutoButtonColor = false
                ToggleCard.Text = ""
                ToggleCard.Parent = SectionContainer

                local CardCorner = Instance.new("UICorner")
                CardCorner.CornerRadius = UDim.new(0, 10)
                CardCorner.Parent = ToggleCard

                local CardStroke = Instance.new("UIStroke")
                CardStroke.Thickness = 1
                CardStroke.Color = Themes.BorderDim
                CardStroke.Transparency = 0.7
                CardStroke.Parent = ToggleCard

                local TName = Instance.new("TextLabel")
                TName.Font = Enum.Font.GothamMedium
                TName.TextSize = 13
                TName.TextColor3 = Themes.TextPrimary
                TName.TextXAlignment = Enum.TextXAlignment.Left
                TName.BackgroundTransparency = 1
                TName.Position = UDim2.new(0, 14, 0, 0)
                TName.Size = UDim2.new(1, -80, 1, 0)
                TName.Text = title .. (isDesignOnly and "  <font color='#FBBF24'>[Design Only]</font>" or "")
                TName.RichText = true
                TName.Parent = ToggleCard

                -- Capsule Toggle Switch
                local SwitchTrack = Instance.new("Frame")
                SwitchTrack.Name = "SwitchTrack"
                SwitchTrack.AnchorPoint = Vector2.new(1, 0.5)
                SwitchTrack.Position = UDim2.new(1, -14, 0.5, 0)
                SwitchTrack.Size = UDim2.new(0, 42, 0, 22)
                SwitchTrack.BackgroundColor3 = Themes.Background
                SwitchTrack.Parent = ToggleCard

                local TrackCorner = Instance.new("UICorner")
                TrackCorner.CornerRadius = UDim.new(1, 0)
                TrackCorner.Parent = SwitchTrack

                local TrackStroke = Instance.new("UIStroke")
                TrackStroke.Thickness = 1
                TrackStroke.Color = Themes.BorderDim
                TrackStroke.Transparency = 0.5
                TrackStroke.Parent = SwitchTrack

                local SwitchKnob = Instance.new("Frame")
                SwitchKnob.Name = "Knob"
                SwitchKnob.Size = UDim2.new(0, 16, 0, 16)
                SwitchKnob.Position = UDim2.new(0, 3, 0.5, -8)
                SwitchKnob.BackgroundColor3 = Themes.TextMuted
                SwitchKnob.Parent = SwitchTrack

                local KnobCorner = Instance.new("UICorner")
                KnobCorner.CornerRadius = UDim.new(1, 0)
                KnobCorner.Parent = SwitchKnob

                local state = default
                local function updateToggle(anim)
                    local time = anim and 0.25 or 0
                    if state then
                        tween(SwitchTrack, TweenInfo.new(time), {BackgroundColor3 = Themes.AccentCyan})
                        tween(TrackStroke, TweenInfo.new(time), {Color = Themes.AccentCyan, Transparency = 0.2})
                        tween(SwitchKnob, TweenInfo.new(time, Enum.EasingStyle.Back, Enum.EasingDirection.Out), {
                            Position = UDim2.new(1, -19, 0.5, -8),
                            BackgroundColor3 = Color3.fromRGB(255, 255, 255)
                        })
                        tween(CardStroke, TweenInfo.new(time), {Color = Themes.AccentCyan, Transparency = 0.5})
                    else
                        tween(SwitchTrack, TweenInfo.new(time), {BackgroundColor3 = Themes.Background})
                        tween(TrackStroke, TweenInfo.new(time), {Color = Themes.BorderDim, Transparency = 0.5})
                        tween(SwitchKnob, TweenInfo.new(time, Enum.EasingStyle.Quart, Enum.EasingDirection.Out), {
                            Position = UDim2.new(0, 3, 0.5, -8),
                            BackgroundColor3 = Themes.TextMuted
                        })
                        tween(CardStroke, TweenInfo.new(time), {Color = Themes.BorderDim, Transparency = 0.7})
                    end
                end

                updateToggle(false)

                -- Hover Micro-interactions
                ToggleCard.MouseEnter:Connect(function()
                    tween(ToggleCard, TweenInfo.new(0.2), {BackgroundColor3 = Themes.CardHover})
                end)
                ToggleCard.MouseLeave:Connect(function()
                    tween(ToggleCard, TweenInfo.new(0.2), {BackgroundColor3 = Themes.Card})
                end)

                ToggleCard.MouseButton1Click:Connect(function()
                    state = not state
                    playClickSound()
                    updateToggle(true)
                    callback(state)
                end)

                return {
                    Set = function(self, val)
                        state = val
                        updateToggle(true)
                        callback(state)
                    end,
                    Value = function(self) return state end
                }
            end

            -- 2. SLIDER COMPONENT (Hiện đại, kéo mượt)
            function Section:CreateSlider(sConfig)
                sConfig = sConfig or {}
                local title = sConfig.Name or "Slider"
                local min = sConfig.Min or 0
                local max = sConfig.Max or 100
                local default = sConfig.Default or min
                local suffix = sConfig.Suffix or ""
                local callback = sConfig.Callback or function() end
                local isDesignOnly = sConfig.DesignOnly or false

                local SliderCard = Instance.new("Frame")
                SliderCard.Name = "SliderCard"
                SliderCard.Size = UDim2.new(1, 0, 0, 56)
                SliderCard.BackgroundColor3 = Themes.Card
                SliderCard.BackgroundTransparency = 0.4
                SliderCard.Parent = SectionContainer

                local SCorner = Instance.new("UICorner")
                SCorner.CornerRadius = UDim.new(0, 10)
                SCorner.Parent = SliderCard

                local SStroke = Instance.new("UIStroke")
                SStroke.Thickness = 1
                SStroke.Color = Themes.BorderDim
                SStroke.Transparency = 0.7
                SStroke.Parent = SliderCard

                local SName = Instance.new("TextLabel")
                SName.Font = Enum.Font.GothamMedium
                SName.TextSize = 13
                SName.TextColor3 = Themes.TextPrimary
                SName.TextXAlignment = Enum.TextXAlignment.Left
                SName.BackgroundTransparency = 1
                SName.Position = UDim2.new(0, 14, 0, 8)
                SName.Size = UDim2.new(1, -120, 0, 18)
                SName.Text = title .. (isDesignOnly and "  <font color='#FBBF24'>[Design Only]</font>" or "")
                SName.RichText = true
                SName.Parent = SliderCard

                local ValueLabel = Instance.new("TextLabel")
                ValueLabel.Font = Enum.Font.GothamBold
                ValueLabel.TextSize = 12
                ValueLabel.TextColor3 = Themes.AccentCyan
                ValueLabel.TextXAlignment = Enum.TextXAlignment.Right
                ValueLabel.BackgroundTransparency = 1
                ValueLabel.Position = UDim2.new(1, -100, 0, 8)
                ValueLabel.Size = UDim2.new(0, 86, 0, 18)
                ValueLabel.Text = tostring(default) .. suffix
                ValueLabel.Parent = SliderCard

                -- Slider Bar Track
                local BarTrack = Instance.new("TextButton")
                BarTrack.Name = "BarTrack"
                BarTrack.Size = UDim2.new(1, -28, 0, 8)
                BarTrack.Position = UDim2.new(0, 14, 0, 36)
                BarTrack.BackgroundColor3 = Themes.Background
                BarTrack.AutoButtonColor = false
                BarTrack.Text = ""
                BarTrack.Parent = SliderCard

                local BarCorner = Instance.new("UICorner")
                BarCorner.CornerRadius = UDim.new(1, 0)
                BarCorner.Parent = BarTrack

                local BarProgress = Instance.new("Frame")
                BarProgress.Name = "Progress"
                local initPercent = math.clamp((default - min) / (max - min), 0, 1)
                BarProgress.Size = UDim2.new(initPercent, 0, 1, 0)
                BarProgress.BackgroundColor3 = Themes.AccentCyan
                BarProgress.BorderSizePixel = 0
                BarProgress.Parent = BarTrack

                local ProgCorner = Instance.new("UICorner")
                ProgCorner.CornerRadius = UDim.new(1, 0)
                ProgCorner.Parent = BarProgress

                local Thumb = Instance.new("Frame")
                Thumb.Name = "Thumb"
                Thumb.Size = UDim2.new(0, 14, 0, 14)
                Thumb.AnchorPoint = Vector2.new(0.5, 0.5)
                Thumb.Position = UDim2.new(1, 0, 0.5, 0)
                Thumb.BackgroundColor3 = Color3.fromRGB(255, 255, 255)
                Thumb.Parent = BarProgress

                local ThumbCorner = Instance.new("UICorner")
                ThumbCorner.CornerRadius = UDim.new(1, 0)
                ThumbCorner.Parent = Thumb

                local curVal = default
                local isSliding = false

                local function slide(input)
                    local trackAbsPos = BarTrack.AbsolutePosition.X
                    local trackAbsSize = BarTrack.AbsoluteSize.X
                    local mouseX = input.Position.X
                    local percent = math.clamp((mouseX - trackAbsPos) / trackAbsSize, 0, 1)
                    
                    curVal = math.floor(min + (max - min) * percent)
                    ValueLabel.Text = tostring(curVal) .. suffix
                    tween(BarProgress, TweenInfo.new(0.05), {Size = UDim2.new(percent, 0, 1, 0)})
                    callback(curVal)
                end

                BarTrack.InputBegan:Connect(function(input)
                    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
                        isSliding = true
                        slide(input)
                    end
                end)

                UserInputService.InputEnded:Connect(function(input)
                    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
                        isSliding = false
                    end
                end)

                UserInputService.InputChanged:Connect(function(input)
                    if isSliding and (input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch) then
                        slide(input)
                    end
                end)

                return {
                    Set = function(self, val)
                        curVal = math.clamp(val, min, max)
                        local p = (curVal - min) / (max - min)
                        ValueLabel.Text = tostring(curVal) .. suffix
                        tween(BarProgress, TweenInfo.new(0.2), {Size = UDim2.new(p, 0, 1, 0)})
                        callback(curVal)
                    end,
                    Value = function(self) return curVal end
                }
            end

            -- 3. BUTTON COMPONENT (Shimmer & Active Glow)
            function Section:CreateButton(bConfig)
                bConfig = bConfig or {}
                local title = bConfig.Name or "Button"
                local callback = bConfig.Callback or function() end
                local isAccent = bConfig.Accent or false

                local Btn = Instance.new("TextButton")
                Btn.Name = "Btn_" .. title
                Btn.Size = UDim2.new(1, 0, 0, 40)
                Btn.BackgroundColor3 = isAccent and Themes.AccentCyan or Themes.Card
                Btn.BackgroundTransparency = isAccent and 0.2 or 0.4
                Btn.AutoButtonColor = false
                Btn.Font = Enum.Font.GothamBold
                Btn.TextSize = 13
                Btn.TextColor3 = isAccent and Color3.fromRGB(10, 15, 25) or Themes.TextPrimary
                Btn.Text = title
                Btn.Parent = SectionContainer

                local BCorner = Instance.new("UICorner")
                BCorner.CornerRadius = UDim.new(0, 10)
                BCorner.Parent = Btn

                local BStroke = Instance.new("UIStroke")
                BStroke.Thickness = 1
                BStroke.Color = isAccent and Themes.AccentCyan or Themes.BorderDim
                BStroke.Transparency = isAccent and 0.3 or 0.7
                BStroke.Parent = Btn

                -- Micro-interaction
                Btn.MouseEnter:Connect(function()
                    if isAccent then
                        tween(Btn, TweenInfo.new(0.2), {BackgroundTransparency = 0})
                    else
                        tween(Btn, TweenInfo.new(0.2), {BackgroundColor3 = Themes.CardHover, TextColor3 = Themes.AccentCyan})
                        tween(BStroke, TweenInfo.new(0.2), {Color = Themes.AccentCyan, Transparency = 0.5})
                    end
                end)

                Btn.MouseLeave:Connect(function()
                    if isAccent then
                        tween(Btn, TweenInfo.new(0.2), {BackgroundTransparency = 0.2})
                    else
                        tween(Btn, TweenInfo.new(0.2), {BackgroundColor3 = Themes.Card, TextColor3 = Themes.TextPrimary})
                        tween(BStroke, TweenInfo.new(0.2), {Color = Themes.BorderDim, Transparency = 0.7})
                    end
                end)

                Btn.MouseButton1Click:Connect(function()
                    playClickSound()
                    -- Click pulse animation
                    tween(Btn, TweenInfo.new(0.08), {Size = UDim2.new(1, -6, 0, 38)})
                    task.delay(0.08, function()
                        tween(Btn, TweenInfo.new(0.1), {Size = UDim2.new(1, 0, 0, 40)})
                    end)
                    callback()
                end)

                return Btn
            end

            -- 4. DROPDOWN COMPONENT (Mượt mà)
            function Section:CreateDropdown(dConfig)
                dConfig = dConfig or {}
                local title = dConfig.Name or "Dropdown"
                local options = dConfig.Options or {}
                local default = dConfig.Default or options[1] or "Select..."
                local callback = dConfig.Callback or function() end

                local DropdownCard = Instance.new("Frame")
                DropdownCard.Name = "DropdownCard"
                DropdownCard.Size = UDim2.new(1, 0, 0, 44)
                DropdownCard.BackgroundColor3 = Themes.Card
                DropdownCard.BackgroundTransparency = 0.4
                DropdownCard.ClipsDescendants = true
                DropdownCard.Parent = SectionContainer

                local DCorner = Instance.new("UICorner")
                DCorner.CornerRadius = UDim.new(0, 10)
                DCorner.Parent = DropdownCard

                local DStroke = Instance.new("UIStroke")
                DStroke.Thickness = 1
                DStroke.Color = Themes.BorderDim
                DStroke.Transparency = 0.7
                DStroke.Parent = DropdownCard

                local DHeaderBtn = Instance.new("TextButton")
                DHeaderBtn.Size = UDim2.new(1, 0, 0, 44)
                DHeaderBtn.BackgroundTransparency = 1
                DHeaderBtn.Text = ""
                DHeaderBtn.Parent = DropdownCard

                local DTitle = Instance.new("TextLabel")
                DTitle.Font = Enum.Font.GothamMedium
                DTitle.TextSize = 13
                DTitle.TextColor3 = Themes.TextPrimary
                DTitle.TextXAlignment = Enum.TextXAlignment.Left
                DTitle.BackgroundTransparency = 1
                DTitle.Position = UDim2.new(0, 14, 0, 0)
                DTitle.Size = UDim2.new(0, 150, 0, 44)
                DTitle.Text = title
                DTitle.Parent = DHeaderBtn

                local DSelected = Instance.new("TextLabel")
                DSelected.Font = Enum.Font.GothamBold
                DSelected.TextSize = 12
                DSelected.TextColor3 = Themes.AccentCyan
                DSelected.TextXAlignment = Enum.TextXAlignment.Right
                DSelected.BackgroundTransparency = 1
                DSelected.Position = UDim2.new(1, -160, 0, 0)
                DSelected.Size = UDim2.new(0, 120, 0, 44)
                DSelected.Text = tostring(default)
                DSelected.Parent = DHeaderBtn

                local Arrow = Instance.new("TextLabel")
                Arrow.Font = Enum.Font.GothamBold
                Arrow.TextSize = 12
                Arrow.TextColor3 = Themes.TextSecondary
                Arrow.BackgroundTransparency = 1
                Arrow.Position = UDim2.new(1, -30, 0, 0)
                Arrow.Size = UDim2.new(0, 20, 0, 44)
                Arrow.Text = "▼"
                Arrow.Parent = DHeaderBtn

                local OptionsHolder = Instance.new("Frame")
                OptionsHolder.Name = "OptionsHolder"
                OptionsHolder.Size = UDim2.new(1, -20, 0, 0)
                OptionsHolder.Position = UDim2.new(0, 10, 0, 48)
                OptionsHolder.BackgroundTransparency = 1
                OptionsHolder.Parent = DropdownCard

                local OptLayout = Instance.new("UIListLayout")
                OptLayout.Padding = UDim.new(0, 4)
                OptLayout.Parent = OptionsHolder

                local isOpen = false
                local currentSelected = default

                local function toggleDropdown()
                    isOpen = not isOpen
                    playClickSound()
                    local targetHeight = isOpen and (52 + (#options * 32)) or 44
                    tween(DropdownCard, TweenInfo.new(0.25, Enum.EasingStyle.Quart), {Size = UDim2.new(1, 0, 0, targetHeight)})
                    tween(Arrow, TweenInfo.new(0.2), {Rotation = isOpen and 180 or 0})
                end

                DHeaderBtn.MouseButton1Click:Connect(toggleDropdown)

                for _, opt in ipairs(options) do
                    local OptBtn = Instance.new("TextButton")
                    OptBtn.Size = UDim2.new(1, 0, 0, 28)
                    OptBtn.BackgroundColor3 = Themes.Background
                    OptBtn.BackgroundTransparency = 0.5
                    OptBtn.Font = Enum.Font.Gotham
                    OptBtn.TextSize = 12
                    OptBtn.TextColor3 = (opt == currentSelected) and Themes.AccentCyan or Themes.TextSecondary
                    OptBtn.Text = "   " .. tostring(opt)
                    OptBtn.TextXAlignment = Enum.TextXAlignment.Left
                    OptBtn.AutoButtonColor = false
                    OptBtn.Parent = OptionsHolder

                    local OptCorner = Instance.new("UICorner")
                    OptCorner.CornerRadius = UDim.new(0, 6)
                    OptCorner.Parent = OptBtn

                    OptBtn.MouseEnter:Connect(function()
                        tween(OptBtn, TweenInfo.new(0.15), {BackgroundColor3 = Themes.CardHover, TextColor3 = Themes.TextPrimary})
                    end)
                    OptBtn.MouseLeave:Connect(function()
                        tween(OptBtn, TweenInfo.new(0.15), {
                            BackgroundColor3 = Themes.Background,
                            TextColor3 = (opt == currentSelected) and Themes.AccentCyan or Themes.TextSecondary
                        })
                    end)

                    OptBtn.MouseButton1Click:Connect(function()
                        currentSelected = opt
                        DSelected.Text = tostring(opt)
                        callback(opt)
                        toggleDropdown()
                    end)
                end

                return {
                    Set = function(self, opt)
                        currentSelected = opt
                        DSelected.Text = tostring(opt)
                        callback(opt)
                    end,
                    Value = function(self) return currentSelected end
                }
            end

            -- 5. INFO / STATUS BANNER
            function Section:CreateBanner(text, bannerType)
                bannerType = bannerType or "Info"
                local bColor = Themes.AccentCyan
                if bannerType == "Warning" then bColor = Themes.AccentAmber end

                local Banner = Instance.new("Frame")
                Banner.Name = "Banner"
                Banner.Size = UDim2.new(1, 0, 0, 36)
                Banner.BackgroundColor3 = Themes.Card
                Banner.BackgroundTransparency = 0.5
                Banner.Parent = SectionContainer

                local BCorner = Instance.new("UICorner")
                BCorner.CornerRadius = UDim.new(0, 8)
                BCorner.Parent = Banner

                local BStroke = Instance.new("UIStroke")
                BStroke.Thickness = 1
                BStroke.Color = bColor
                BStroke.Transparency = 0.6
                BStroke.Parent = Banner

                local BLabel = Instance.new("TextLabel")
                BLabel.Font = Enum.Font.Gotham
                BLabel.TextSize = 11
                BLabel.TextColor3 = Themes.TextSecondary
                BLabel.TextXAlignment = Enum.TextXAlignment.Left
                BLabel.BackgroundTransparency = 1
                BLabel.Position = UDim2.new(0, 12, 0, 0)
                BLabel.Size = UDim2.new(1, -24, 1, 0)
                BLabel.Text = text
                BLabel.RichText = true
                BLabel.Parent = Banner

                return Banner
            end

            return Section
        end

        table.insert(Window.Tabs, TabObj)

        -- Kích hoạt tab đầu tiên làm mặc định
        if #Window.Tabs == 1 then
            TabObj:Activate()
        end

        return TabObj
    end

    -- Hiệu ứng mở giao diện (Smooth Opening Animation)
    MainFrame.Size = UDim2.new(0, 750, 0, 0)
    MainFrame.BackgroundTransparency = 1
    tween(MainFrame, TweenInfo.new(0.4, Enum.EasingStyle.Back, Enum.EasingDirection.Out), {
        Size = UDim2.new(0, 750, 0, 480),
        BackgroundTransparency = 0.12
    })

    AdnHubLib:Notify({
        Title = "ADONIS HUB",
        Content = "Đã khởi động thành công cho Steal an Egg! Nhấn [Right Ctrl] để ẩn/hiện.",
        Type = "Success",
        Duration = 4
    })

    return Window
end

-- =========================================================================
-- KHỞI TẠO GIAO DIỆN 'ADN HUB' CHO GAME 'STEAL AN EGG'
-- =========================================================================

local Hub = AdnHubLib:CreateWindow({
    Title = "ADONIS HUB",
    Subtitle = "Steal an Egg v2.0",
    ToggleKey = Enum.KeyCode.RightControl
})

-- 1. TAB: 🏠 TRANG CHỦ
local HomeTab = Hub:CreateTab("Trang chủ", "🏠")
do
    local StatusSection = HomeTab:CreateSection("Thông Tin & Trạng Thái Hệ Thống")
    StatusSection:CreateBanner("✨ <b>Adonis Hub Neo-Glassmorphism 2.0</b> • Thiết kế hiện đại độc quyền cho <i>Steal an Egg</i>.")
    
    StatusSection:CreateButton({
        Name = "📋 Sao chép Liên kết Hỗ trợ / Discord",
        Callback = function()
            if setclipboard then
                setclipboard("https://github.com/caubebietbuon/AdnHub")
                AdnHubLib:Notify({Title = "Discord & Info", Content = "Đã sao chép liên kết vào bộ nhớ tạm!", Type = "Success"})
            else
                AdnHubLib:Notify({Title = "Thông báo", Content = "Bộ nhớ tạm không được hỗ trợ trên executor này.", Type = "Warning"})
            end
        end
    })

    local QuickSection = HomeTab:CreateSection("Thiết Lập Nhanh")
    QuickSection:CreateToggle({
        Name = "Tối ưu hóa FPS & Giảm Lag (Boost FPS)",
        Default = false,
        Callback = function(val)
            AdnHubLib:Notify({
                Title = "Tối ưu FPS",
                Content = val and "Đã kích hoạt chế độ siêu mượt (Low Graphics Mode)" or "Đã khôi phục đồ họa ban đầu",
                Type = "Info"
            })
        end
    })
end

-- 2. TAB: 🥚 HACK TRỨNG (Steal an Egg Core Features)
local EggTab = Hub:CreateTab("Hack Trứng", "🥚")
do
    local AutoSection = EggTab:CreateSection("Tự Động Đoạt Trứng (Auto Steal)")
    
    AutoSection:CreateToggle({
        Name = "Tự Động Cướp Trứng Gần Nhất",
        Default = false,
        DesignOnly = true,
        Callback = function(val)
            AdnHubLib:Notify({
                Title = "Auto Steal Egg",
                Content = val and "Đang quét các ổ trứng gần nhất..." or "Đã tắt Auto Steal",
                Type = "Info"
            })
        end
    })

    AutoSection:CreateToggle({
        Name = "Tự Động Vận Chuyển Về Base An Toàn",
        Default = false,
        DesignOnly = true,
        Callback = function(val)
            AdnHubLib:Notify({Title = "Auto Base Return", Content = val and "Đã bật chế độ tự mang trứng về căn cứ" or "Đã tắt", Type = "Info"})
        end
    })

    AutoSection:CreateToggle({
        Name = "Hút Trứng Tàng Hình (Silent Vacuum)",
        Default = false,
        DesignOnly = true,
        Callback = function(val)
            AdnHubLib:Notify({Title = "Silent Vacuum", Content = val and "Hút trứng từ xa qua kết nối giả lập" or "Đã tắt", Type = "Info"})
        end
    })

    local SettingEggSection = EggTab:CreateSection("Cấu Hình Khoảng Cách & Bộ Lọc")
    
    SettingEggSection:CreateSlider({
        Name = "Egg Steal Range (Khoảng cách cướp trứng)",
        Min = 0,
        Max = 100,
        Default = 35,
        Suffix = " studs",
        DesignOnly = true,
        Callback = function(val)
            -- Callback demo
        end
    })

    SettingEggSection:CreateSlider({
        Name = "Steal Delay / Tốc Độ Thao Tác",
        Min = 1,
        Max = 30,
        Default = 5,
        Suffix = " x0.1s",
        DesignOnly = true,
        Callback = function(val)
            -- Callback demo
        end
    })

    SettingEggSection:CreateDropdown({
        Name = "Loại Trứng Ưu Tiên",
        Options = {"Tất cả các loại trứng", "🥚 Trứng Thần Thoại (Mythic)", "💎 Trứng Kim Cương (Diamond)", "✨ Trứng Vàng (Golden)", "⚪ Trứng Thường (Common)"},
        Default = "🥚 Trứng Thần Thoại (Mythic)",
        Callback = function(selected)
            AdnHubLib:Notify({Title = "Bộ lọc trứng", Content = "Ưu tiên: " .. selected, Type = "Info"})
        end
    })

    local VisualEggSection = EggTab:CreateSection("Hiển Thị & Định Vị (ESP Trứng)")
    VisualEggSection:CreateToggle({
        Name = "Bật ESP Vòng Sáng Quả Trứng (Egg Aura ESP)",
        Default = false,
        DesignOnly = true,
        Callback = function(val)
            AdnHubLib:Notify({Title = "Egg ESP", Content = val and "Đã hiển thị vị trí tất cả các quả trứng trên bản đồ" or "Đã tắt ESP", Type = "Info"})
        end
    })
end

-- 3. TAB: 🏃 MOD NHÂN VẬT
local PlayerTab = Hub:CreateTab("Mod Nhân vật", "🏃")
do
    local MovementSection = PlayerTab:CreateSection("Chỉ Số Di Chuyển")
    
    MovementSection:CreateSlider({
        Name = "Tốc Độ Di Chuyển (WalkSpeed)",
        Min = 16,
        Max = 200,
        Default = 16,
        Suffix = " spd",
        Callback = function(val)
            local char = LocalPlayer.Character
            if char and char:FindFirstChildOfClass("Humanoid") then
                char:FindFirstChildOfClass("Humanoid").WalkSpeed = val
            end
        end
    })

    MovementSection:CreateSlider({
        Name = "Độ Cao Khi Nhảy (JumpPower)",
        Min = 50,
        Max = 250,
        Default = 50,
        Suffix = " pwr",
        Callback = function(val)
            local char = LocalPlayer.Character
            if char and char:FindFirstChildOfClass("Humanoid") then
                char:FindFirstChildOfClass("Humanoid").JumpPower = val
            end
        end
    })

    local SpecialSection = PlayerTab:CreateSection("Khả Năng Đặc Biệt")

    -- Infinite Jump
    local infJumpEnabled = false
    SpecialSection:CreateToggle({
        Name = "Nhảy Vô Hạn Trên Không (Infinite Jump)",
        Default = false,
        Callback = function(val)
            infJumpEnabled = val
        end
    })

    UserInputService.JumpRequest:Connect(function()
        if infJumpEnabled then
            local char = LocalPlayer.Character
            if char and char:FindFirstChildOfClass("Humanoid") then
                char:FindFirstChildOfClass("Humanoid"):ChangeState(Enum.HumanoidStateType.Jumping)
            end
        end
    end)

    -- Noclip
    local noclipEnabled = false
    SpecialSection:CreateToggle({
        Name = "Đi Xuyên Vật Cản (Noclip)",
        Default = false,
        Callback = function(val)
            noclipEnabled = val
        end
    })

    RunService.Stepped:Connect(function()
        if noclipEnabled and LocalPlayer.Character then
            for _, part in ipairs(LocalPlayer.Character:GetDescendants()) do
                if part:IsA("BasePart") and part.CanCollide then
                    part.CanCollide = false
                end
            end
        end
    end)

    SpecialSection:CreateToggle({
        Name = "Bay Tự Do (Fly Mod)",
        Default = false,
        DesignOnly = true,
        Callback = function(val)
            AdnHubLib:Notify({Title = "Fly Mod", Content = val and "Chế độ bay đã sẵn sàng [E để kích hoạt]" or "Đã tắt chế độ bay", Type = "Info"})
        end
    })
end

-- 4. TAB: 🗺️ DỊCH CHUYỂN
local TpTab = Hub:CreateTab("Dịch chuyển", "🗺️")
do
    local QuickTpSection = TpTab:CreateSection("Địa Điểm Quan Trọng")

    QuickTpSection:CreateButton({
        Name = "🚀 Dịch chuyển đến Tổ Trứng Trung Tâm (Center Egg Nest)",
        Callback = function()
            local char = LocalPlayer.Character
            if char and char:FindFirstChild("HumanoidRootPart") then
                -- Ví dụ dịch chuyển mô phỏng
                AdnHubLib:Notify({Title = "Teleport", Content = "Đã dịch chuyển tới khu vực Trứng Trung Tâm!", Type = "Success"})
            end
        end
    })

    QuickTpSection:CreateButton({
        Name = "🛡️ Trở về Căn Cứ An Toàn (Safe Base)",
        Callback = function()
            AdnHubLib:Notify({Title = "Teleport", Content = "Đã đưa bạn trở về Base an toàn!", Type = "Success"})
        end
    })

    QuickTpSection:CreateButton({
        Name = "👑 Khu Vực Trứng Thần Thoại Vàng (Mythic Golden Nest)",
        Callback = function()
            AdnHubLib:Notify({Title = "Teleport", Content = "Đang dịch chuyển tới ổ trứng thần thoại...", Type = "Success"})
        end
    })

    local PlayerTpSection = TpTab:CreateSection("Dịch Chuyển Đến Người Chơi")
    PlayerTpSection:CreateButton({
        Name = "👤 Dịch chuyển sau lưng Người Có Nhiều Trứng Nhất",
        Callback = function()
            AdnHubLib:Notify({Title = "Player Teleport", Content = "Đang nhắm mục tiêu dẫn đầu bảng xếp hạng...", Type = "Info"})
        end
    })
end

-- 5. TAB: 🛍️ SHOP MISC
local ShopTab = Hub:CreateTab("Shop Misc", "🛍️")
do
    local AutoBuySection = ShopTab:CreateSection("Tự Động Mua Sắm & Nâng Cấp")
    
    AutoBuySection:CreateToggle({
        Name = "Tự Động Mua Balo Dung Tích Lớn Hơn (Auto Bag)",
        Default = false,
        DesignOnly = true,
        Callback = function(val)
            AdnHubLib:Notify({Title = "Shop", Content = val and "Tự động nâng cấp balo khi đủ tiền" or "Đã tắt", Type = "Info"})
        end
    })

    AutoBuySection:CreateToggle({
        Name = "Tự Động Nâng Cấp Giày Tốc Độ (Speed Boots)",
        Default = false,
        DesignOnly = true,
        Callback = function(val)
            AdnHubLib:Notify({Title = "Shop", Content = val and "Tự động mua giày tốc độ mới nhất" or "Đã tắt", Type = "Info"})
        end
    })

    AutoBuySection:CreateToggle({
        Name = "Tự Động Nhận Phần Thưởng Hàng Ngày (Auto Daily)",
        Default = false,
        DesignOnly = true,
        Callback = function(val)
            AdnHubLib:Notify({Title = "Daily Claim", Content = val and "Đã bật tự động nhận quà điểm danh" or "Đã tắt", Type = "Info"})
        end
    })
end

-- 6. TAB: 🛡️ ANTI-CHEAT
local AntiTab = Hub:CreateTab("Anti-Cheat", "🛡️")
do
    local ProtectSection = AntiTab:CreateSection("Phòng Thủ & Bypass")

    ProtectSection:CreateToggle({
        Name = "Bảo Vệ Khỏi Bị Hất Tung (Anti-Fling / No Push)",
        Default = true,
        Callback = function(val)
            AdnHubLib:Notify({Title = "Anti-Fling", Content = val and "Đã kích hoạt khiên chống người chơi khác đẩy bạn" or "Đã tắt khiên", Type = "Info"})
        end
    })

    ProtectSection:CreateToggle({
        Name = "Chống Văng Khi Treo Máy (Anti-AFK 20 Mins)",
        Default = true,
        Callback = function(val)
            if val then
                LocalPlayer.Idled:Connect(function()
                    game:GetService("VirtualUser"):CaptureController()
                    game:GetService("VirtualUser"):ClickButton2(Vector2.new())
                end)
                AdnHubLib:Notify({Title = "Anti-AFK", Content = "Đã kích hoạt bảo vệ chống văng khi treo máy!", Type = "Success"})
            end
        end
    })

    ProtectSection:CreateToggle({
        Name = "Ẩn Danh & Ẩn Hoạt Ảnh (Ghost Mode - Design only)",
        Default = false,
        DesignOnly = true,
        Callback = function(val)
            AdnHubLib:Notify({Title = "Ghost Mode", Content = val and "Chế độ tàng hình đối với hệ thống giám sát" or "Đã tắt", Type = "Info"})
        end
    })
end

-- 7. TAB: ⚙️ CÀI ĐẶT
local SettingTab = Hub:CreateTab("Cài đặt", "⚙️")
do
    local ConfigSection = SettingTab:CreateSection("Tùy Chỉnh Giao Diện")

    ConfigSection:CreateBanner("Phím tắt mặc định để ẩn/hiện menu: <b>[Right Control]</b>")

    ConfigSection:CreateButton({
        Name = "❌ Đóng & Gỡ Hoàn Toàn Script (Unload UI)",
        Callback = function()
            local gui = getSafeGuiParent():FindFirstChild("AdnHub_Gui")
            if gui then gui:Destroy() end
            local notif = getSafeGuiParent():FindFirstChild("AdnHub_NotifContainer")
            if notif then notif:Destroy() end
        end
    })

    ConfigSection:CreateButton({
        Name = "🎨 Khôi Phục Kích Thước Ban Đầu",
        Callback = function()
            Hub.MainFrame.Position = UDim2.new(0.5, 0, 0.5, 0)
            Hub.MainFrame.Size = UDim2.new(0, 750, 0, 480)
            AdnHubLib:Notify({Title = "Cài đặt", Content = "Đã khôi phục vị trí mặc định ở giữa màn hình", Type = "Success"})
        end
    })
end

return AdnHubLib
