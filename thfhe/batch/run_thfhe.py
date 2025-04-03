import socket
import subprocess
import sys
from pathlib import Path


def get_local_ip():
    """返回本机内网 IP（非 127 开头的 IPv4 地址）"""
    hostname = socket.gethostname()
    ips = socket.gethostbyname_ex(hostname)[2]
    for ip in ips:
        if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172."):
            return ip
    raise RuntimeError("无法找到内网 IP")


def read_ip_list(path):
    """读取 ip.txt 并返回去除换行的 IP 列表"""
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def main():
    if len(sys.argv) != 2:
        print(f"用法: python {sys.argv[0]} <num_parties>")
        sys.exit(1)

    num_parties = sys.argv[1]
    ip_file = Path("./iplist/ip.txt")
    if not ip_file.exists():
        print(f"错误: {ip_file} 不存在")
        sys.exit(1)

    local_ip = get_local_ip()
    ip_list = read_ip_list(ip_file)

    try:
        party_id = ip_list.index(local_ip)
    except ValueError:
        print(f"错误: 本机 IP ({local_ip}) 不在 ip.txt 中")
        sys.exit(1)

    print(f"检测到本机 IP: {local_ip}")
    print(f"对应的 party_id: {party_id}")
    print(f"执行命令: ./target/release/examples/thfhe -n {num_parties} -i {party_id}")

    # 执行命令
    try:
        subprocess.run(
            ["./target/release/examples/thfhe", "-n", num_parties, "-i", str(party_id)],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print("程序执行失败：", e)


if __name__ == "__main__":
    main()
