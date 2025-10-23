# Fynx crates.io 发布脚本 (PowerShell)
# 正确的发布顺序和依赖更新

$ErrorActionPreference = "Stop"

Write-Host "🚀 Fynx v0.1.0-alpha.1 发布脚本" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# 步骤 1: 运行测试
Write-Host "🧪 步骤 1/5: 运行所有测试..." -ForegroundColor Yellow
cargo test --all-features --workspace
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ 测试失败" -ForegroundColor Red
    exit 1
}
Write-Host "✅ 所有测试通过" -ForegroundColor Green
Write-Host ""

# 步骤 2: 发布 fynx-platform
Write-Host "📦 步骤 2/5: 发布 fynx-platform..." -ForegroundColor Yellow
Push-Location crates/platform

Write-Host "  检查打包内容..." -ForegroundColor Gray
cargo package --list

Write-Host "  发布到 crates.io..." -ForegroundColor Gray
cargo publish
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ fynx-platform 发布失败" -ForegroundColor Red
    Pop-Location
    exit 1
}

Write-Host "✅ fynx-platform 发布成功" -ForegroundColor Green
Pop-Location
Write-Host ""

# 步骤 3: 等待 crates.io 索引
Write-Host "⏳ 步骤 3/5: 等待 crates.io 索引 fynx-platform (60秒)..." -ForegroundColor Yellow
for ($i = 60; $i -gt 0; $i--) {
    Write-Host "`r  剩余 $i 秒..." -NoNewline -ForegroundColor Gray
    Start-Sleep -Seconds 1
}
Write-Host "`r✅ 等待完成                    " -ForegroundColor Green
Write-Host ""

# 步骤 4: 更新 fynx-proto 依赖并发布
Write-Host "📦 步骤 4/5: 发布 fynx-proto..." -ForegroundColor Yellow
Push-Location crates/proto

# 备份原始 Cargo.toml
Write-Host "  备份 Cargo.toml..." -ForegroundColor Gray
Copy-Item Cargo.toml Cargo.toml.backup

# 更新依赖为版本号
Write-Host "  更新 fynx-platform 依赖为版本号..." -ForegroundColor Gray
$cargoContent = Get-Content Cargo.toml -Raw
$cargoContent = $cargoContent -replace 'fynx-platform = \{ path = "\.\./platform" \}', 'fynx-platform = "0.1.0-alpha.1"'
Set-Content Cargo.toml $cargoContent

# 验证更改
Write-Host "  验证依赖更新..." -ForegroundColor Gray
Select-String -Path Cargo.toml -Pattern "fynx-platform"

# 检查打包
Write-Host "  检查打包内容..." -ForegroundColor Gray
cargo package --list | Select-Object -First 10

# 发布
Write-Host "  发布到 crates.io..." -ForegroundColor Gray
cargo publish
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ fynx-proto 发布失败" -ForegroundColor Red
    # 恢复备份
    Move-Item Cargo.toml.backup Cargo.toml -Force
    Pop-Location
    exit 1
}

Write-Host "✅ fynx-proto 发布成功" -ForegroundColor Green

# 恢复原始 Cargo.toml (保持本地开发使用路径依赖)
Write-Host "  恢复原始 Cargo.toml..." -ForegroundColor Gray
Move-Item Cargo.toml.backup Cargo.toml -Force

Pop-Location
Write-Host ""

# 步骤 5: 验证发布
Write-Host "✅ 步骤 5/5: 验证发布..." -ForegroundColor Yellow
Write-Host "  请访问以下链接验证:" -ForegroundColor Gray
Write-Host "  - https://crates.io/crates/fynx-platform/0.1.0-alpha.1" -ForegroundColor Cyan
Write-Host "  - https://crates.io/crates/fynx-proto/0.1.0-alpha.1" -ForegroundColor Cyan
Write-Host ""
Write-Host "  等待 docs.rs 构建文档 (约5-10分钟):" -ForegroundColor Gray
Write-Host "  - https://docs.rs/fynx-platform" -ForegroundColor Cyan
Write-Host "  - https://docs.rs/fynx-proto" -ForegroundColor Cyan
Write-Host ""

Write-Host "🎉 发布完成!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 后续步骤:" -ForegroundColor Yellow
Write-Host "1. 创建 Git 标签:" -ForegroundColor White
Write-Host '   git tag -a v0.1.0-alpha.1 -m "Release v0.1.0-alpha.1"' -ForegroundColor Gray
Write-Host "   git push origin v0.1.0-alpha.1" -ForegroundColor Gray
Write-Host ""
Write-Host "2. 在 GitHub 创建 Release:" -ForegroundColor White
Write-Host "   https://github.com/Rx947getrexp/fynx/releases/new" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. 测试安装:" -ForegroundColor White
Write-Host "   cargo new test-project" -ForegroundColor Gray
Write-Host "   cd test-project" -ForegroundColor Gray
Write-Host "   cargo add fynx-proto@0.1.0-alpha.1" -ForegroundColor Gray
Write-Host "   cargo build" -ForegroundColor Gray
