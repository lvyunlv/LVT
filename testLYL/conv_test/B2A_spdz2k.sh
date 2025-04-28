#!/bin/bash

proto="B2A_spdz2k"
base_port=12340
parties_list=(2 4 8 16 32)

output_file="../../testLYL/conv_test/B2A_spdz2k.txt"
# 清空输出文件
> "$output_file"

for parties in "${parties_list[@]}"; do
    # 启动第1方
    ./test_${proto} 1 $base_port $parties > tmp_output_1.txt 2>&1 &
    pid1=$!

    # 启动其他参与方
    for ((i=2; i<=parties; i++)); do
        ./test_${proto} $i $base_port $parties > /dev/null 2>&1 &
        pids[$i]=$!
    done

    wait $pid1
    for ((i=2; i<=parties; i++)); do
        wait ${pids[$i]}
    done

    echo -n "Party number: $parties\t" >> "$output_file"
    grep "Average time" tmp_output_1.txt >> "$output_file"
    rm -f tmp_output_1.txt

done