#!/bin/bash

# 检查输入参数
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <num_parties> <port>"
    exit 1
fi

# 获取用户输入的参与方数量和端口号
NUM_PARTIES=$1
PORT=$2

# 项目目录
PROJECT_DIR="/Users/lvbao/Desktop/ScalableMixedModeMPC/bui/bin"

# 检查项目目录是否存在
if [ ! -d "$PROJECT_DIR" ]; then
    echo "Error: Project directory $PROJECT_DIR does not exist."
    exit 1
fi

# 切换到项目目录
cd "$PROJECT_DIR" || exit

# 随机生成每个参与方的输入并运行命令
echo "Generating random inputs for $NUM_PARTIES parties..."
for ((i=1; i<=NUM_PARTIES; i++)); do
    INPUT=$((RANDOM % (2**14))) # 随机生成一个 0 到 9999 的整数
    echo "Party $i input: $INPUT"
    ./test_lvt $i $PORT $NUM_PARTIES & # 在后台运行每个命令
done

# 等待所有后台任务完成
wait

echo "All commands have finished."