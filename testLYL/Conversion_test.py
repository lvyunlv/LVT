import os
import subprocess
import time
import sys
from concurrent.futures import ThreadPoolExecutor

# 设置基本参数
bin_dir = "../build/bin/"
bin_files = [
    "test_A2B_mascot",
    "test_A2L_mascot",
    "test_A2B_spdz2k",
    "test_B2A_mascot",
    "test_A2L_spdz2k",
    "test_L2A_mascot",
    "test_B2A_spdz2k",
    "test_L2A_spdz2k",
]
base_port = 22222   # 补上！！！

def save_output(party_id, output):
    filename = f"party_{party_id}_output.txt"
    with open(filename, "w") as f:
        f.write(output)

def run_program(bin_name, num_parties):
    bin_path = os.path.join(bin_dir, bin_name)

    if not os.path.exists(bin_path):
        print(f"[Error] Binary {bin_path} does not exist!")
        return ["BINARY_NOT_FOUND"] * num_parties

    processes = []

    for party_id in range(1, num_parties + 1):
        cmd = [bin_path, str(party_id), str(base_port), str(num_parties)]
        print(f"Starting party {party_id} cmd: {' '.join(cmd)}")  # 打印看看命令行
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        processes.append(proc)
        time.sleep(0.5)  # 防止一口气启动，冲突

    outputs = []
    for party_id, proc in enumerate(processes, 1):
        try:
            out, err = proc.communicate(timeout=120)  # 超时保护
            output = out.decode() + err.decode()
            save_output(party_id, output)  # 保存每个party的输出到文件
            outputs.append(output)
        except subprocess.TimeoutExpired:
            proc.kill()
            outputs.append("TIMEOUT")

    return outputs

def parse_output(output):
    if "Average time" in output and "Average communication" in output:
        try:
            time_part = output.split("Average time:")[1].split("ms")[0].strip()
            comm_part = output.split("Average communication:")[1].split("KB")[0].strip()
            return float(time_part), float(comm_part)
        except Exception as e:
            print(f"[ParseError] {e}")
            return None, None
    else:
        return None, None

def main():
    result_file = "Conversion_test_result.txt"
    with open(result_file, "w") as f:
        for bin_name in bin_files:
            for num_parties in [2, 4, 8, 16, 32]:
                print(f"Running {bin_name} with {num_parties} parties...")
                outputs = run_program(bin_name, num_parties)

                if outputs[0] == "BINARY_NOT_FOUND":
                    f.write(f"{bin_name} Parties: {num_parties}, BINARY_NOT_FOUND\n")
                    continue

                # 只解析第一个party的输出
                time_ms, comm_kb = parse_output(outputs[0])
                if time_ms is None or comm_kb is None:
                    print(f"[Warning] Cannot parse result for {bin_name} with {num_parties} parties!")
                    print(f"First party output:\n{outputs[0]}")
                    f.write(f"{bin_name} Parties: {num_parties}, ERROR\n")
                else:
                    f.write(f"{bin_name} Parties: {num_parties}, Time: {time_ms:.2f}ms, Comm: {comm_kb:.2f}KB\n")
    print(f"Finished! Results saved to {result_file}")

if __name__ == "__main__":
    main()
