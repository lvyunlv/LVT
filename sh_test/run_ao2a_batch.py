import subprocess
import time
import os

BIN_PATH = "../build/bin/test_ao2a"  # 可执行文件路径
RESULT_DIR = "results"
os.makedirs(RESULT_DIR, exist_ok=True)
OUT_FILE = os.path.join(RESULT_DIR, "ao2a")

PARTY_COUNTS = [2, 4, 6, 8, 16, 32]
RUNS = 3
BASE_PORT = 9000

def run_one_case(num_party):
    times = []
    comms = []
    for run in range(RUNS):
        procs = []
        outputs = [None] * num_party
        for i in range(num_party):
            party_id = i + 1
            port = BASE_PORT
            cmd = [BIN_PATH, str(party_id), str(port), str(num_party)]
            procs.append(subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        # 收集输出
        for i, proc in enumerate(procs):
            out, err = proc.communicate()
            outputs[i] = out
        # 只统计第一个party的输出
        for out in outputs:
            for line in out.splitlines():
                if "Communication:" in line and "Time:" in line:
                    parts = line.split(",")
                    comm = float(parts[0].split(":")[1].strip().split()[0])
                    t = float(parts[1].split(":")[1].strip().split()[0])
                    comms.append(comm)
                    times.append(t)
                    break
    avg_time = sum(times) / len(times)
    avg_comm = sum(comms) / len(comms)
    return avg_time, avg_comm

with open(OUT_FILE, "w") as fout:
    fout.write("party_num,avg_time(ms),avg_comm(KB)\n")
    for num_party in PARTY_COUNTS:
        print(f"Running for {num_party} parties...")
        avg_time, avg_comm = run_one_case(num_party)
        print(f"  [Summary] party_num={num_party}, avg_time={avg_time:.3f} ms, avg_comm={avg_comm:.3f} KB\n")
        fout.write(f"{num_party},{avg_time:.3f},{avg_comm:.3f}\n")
        fout.flush()
print("All done. Results saved to", OUT_FILE)