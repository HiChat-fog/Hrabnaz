#!/bin/bash
# 勒索软件模拟脚本
# 模拟文件加密行为，触发 VFS 探针
# 注意: 仅在测试目录中运行！

echo "[模拟] 勒索软件加密行为"
TEST_DIR="/tmp/ks_ransomware_test"

mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

# 创建测试文件
for i in $(seq 1 10); do
    echo "test data $i" > "file_$i.txt"
done

# 模拟加密: 复制文件并添加 .encrypted 后缀
for f in *.txt; do
    cp "$f" "${f}.encrypted"
    echo "  加密: $f -> ${f}.encrypted"
done

# 模拟删除原文件
for f in *.txt; do
    if [[ ! "$f" == *.encrypted ]]; then
        rm "$f"
        echo "  删除: $f"
    fi
done

echo "[完成] 清理..."
rm -rf "$TEST_DIR"
