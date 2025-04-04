#!/bin/bash

# 检查是否提供了目标文件夹路径
if [ -z "$1" ]; then
    echo "用法: $0 <目标文件夹路径>"
    exit 1
fi

# 获取目标文件夹路径
TARGET_DIR="$1"

# 检查目标文件夹是否存在
if [ ! -d "$TARGET_DIR" ]; then
    echo "错误: 目标文件夹不存在: $TARGET_DIR"
    exit 1
fi

# 遍历目标文件夹中的所有 .cpp 文件
for file in "$TARGET_DIR"/*.cpp; do
    # 检查是否存在 .cpp 文件
    if [ -e "$file" ]; then
        # 获取文件的基名（不包括扩展名）
        base_name=$(basename "$file" .cpp)
        # 构造新的文件名
        new_file="$TARGET_DIR/$base_name.hpp"
        # 重命名文件
        mv "$file" "$new_file"
        echo "已重命名: $file -> $new_file"
    fi
done

echo "所有 .cpp 文件已重命名为 .hpp 文件。"
