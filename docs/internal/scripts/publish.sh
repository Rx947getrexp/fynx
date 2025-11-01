#!/bin/bash
# Fynx crates.io 发布脚本
# 正确的发布顺序和依赖更新

set -e  # 遇到错误立即退出

echo "🚀 Fynx v0.1.0-alpha.1 发布脚本"
echo "================================"
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查是否已登录 crates.io
echo "📝 检查 cargo 登录状态..."
if ! cargo login --help &> /dev/null; then
    echo -e "${RED}❌ 请先登录 crates.io: cargo login <YOUR_API_TOKEN>${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Cargo 已安装${NC}"
echo ""

# 步骤 1: 运行测试
echo "🧪 步骤 1/5: 运行所有测试..."
cargo test --all-features --workspace
echo -e "${GREEN}✅ 所有测试通过${NC}"
echo ""

# 步骤 2: 发布 fynx-platform
echo "📦 步骤 2/5: 发布 fynx-platform..."
cd crates/platform

# 检查打包
echo "  检查打包内容..."
cargo package --list

# 发布
echo "  发布到 crates.io..."
cargo publish

echo -e "${GREEN}✅ fynx-platform 发布成功${NC}"
cd ../..
echo ""

# 步骤 3: 等待 crates.io 索引
echo "⏳ 步骤 3/5: 等待 crates.io 索引 fynx-platform (60秒)..."
for i in {60..1}; do
    echo -ne "  剩余 $i 秒...\r"
    sleep 1
done
echo -e "${GREEN}✅ 等待完成${NC}"
echo ""

# 步骤 4: 更新 fynx-proto 依赖并发布
echo "📦 步骤 4/5: 发布 fynx-proto..."
cd crates/proto

# 备份原始 Cargo.toml
cp Cargo.toml Cargo.toml.backup

# 更新依赖为版本号
echo "  更新 fynx-platform 依赖为版本号..."
sed -i 's|fynx-platform = { path = "../platform" }|fynx-platform = "0.1.0-alpha.1"|' Cargo.toml

# 验证更改
echo "  验证依赖更新..."
grep "fynx-platform" Cargo.toml

# 检查打包
echo "  检查打包内容..."
cargo package --list | head -10

# 发布
echo "  发布到 crates.io..."
cargo publish

echo -e "${GREEN}✅ fynx-proto 发布成功${NC}"

# 恢复原始 Cargo.toml (保持本地开发使用路径依赖)
echo "  恢复原始 Cargo.toml..."
mv Cargo.toml.backup Cargo.toml

cd ../..
echo ""

# 步骤 5: 验证发布
echo "✅ 步骤 5/5: 验证发布..."
echo "  请访问以下链接验证:"
echo "  - https://crates.io/crates/fynx-platform/0.1.0-alpha.1"
echo "  - https://crates.io/crates/fynx-proto/0.1.0-alpha.1"
echo ""
echo "  等待 docs.rs 构建文档 (约5-10分钟):"
echo "  - https://docs.rs/fynx-platform"
echo "  - https://docs.rs/fynx-proto"
echo ""

echo "🎉 发布完成!"
echo ""
echo "📋 后续步骤:"
echo "1. 创建 Git 标签:"
echo "   git tag -a v0.1.0-alpha.1 -m \"Release v0.1.0-alpha.1\""
echo "   git push origin v0.1.0-alpha.1"
echo ""
echo "2. 在 GitHub 创建 Release:"
echo "   https://github.com/Rx947getrexp/fynx/releases/new"
echo ""
echo "3. 测试安装:"
echo "   cargo new test-project"
echo "   cd test-project"
echo "   cargo add fynx-proto@0.1.0-alpha.1"
echo "   cargo build"
