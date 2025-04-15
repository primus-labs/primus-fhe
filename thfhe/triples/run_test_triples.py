import socket
import subprocess
import sys
from pathlib import Path


def get_local_ip():
    """return IP address"""
    hostname = socket.gethostname()
    ips = socket.gethostbyname_ex(hostname)[2]
    for ip in ips:
        if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172."):
            return ip
    raise RuntimeError("can't find inter IP")


def read_ip_list(path):

    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def main():
    if len(sys.argv) != 3:
        print(f"usage: python {sys.argv[0]} <parties_num> <base_port>")
        sys.exit(1)

    parties_num = sys.argv[1]
    base_port = sys.argv[2]
    ip_file = Path("../batch/iplist/ip.txt")

    if not ip_file.exists():
        print(f"erro: {ip_file} not exist")
        sys.exit(1)

    local_ip = get_local_ip()
    ip_list = read_ip_list(ip_file)

    try:
        party_id = ip_list.index(local_ip)
    except ValueError:
        print(f"erro: local IP ({local_ip}) not in ip.txt")
        sys.exit(1)

    print(f"check IP: {local_ip}")
    print(f"find party_id: {party_id}")
    print(f"excute: ./test_triples {parties_num} {party_id} {base_port}")

    try:
        subprocess.run(["./test_triples", parties_num, str(party_id), base_port], check=True)
    except subprocess.CalledProcessError as e:
        print("excute program failed", e)


if __name__ == "__main__":
    main()
