#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import signal
import sys

BINARY_PATH = "./target/release/examples/thfhe"
INTERFACE = "lo"
processes = []


def run_cmd(cmd):
    subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL)


def setup_tc_and_iptables(base_port, num_parties, bandwidth_mbps, delay_ms):
    print(f"set tc + iptables {bandwidth_mbps}Mbps, ping time {delay_ms}ms")

    run_cmd(f"tc qdisc del dev {INTERFACE} root")
    run_cmd(f"iptables -t mangle -F")

    run_cmd(f"tc qdisc add dev {INTERFACE} root handle 1: htb default 30")
    run_cmd(
        f"tc class add dev {INTERFACE} parent 1: classid 1:10 htb rate {bandwidth_mbps}mbit ceil {bandwidth_mbps}mbit"
    )
    run_cmd(
        f"tc qdisc add dev {INTERFACE} parent 1:10 handle 10: netem delay {delay_ms}ms"
    )
    run_cmd(
        f"tc filter add dev {INTERFACE} parent 1: protocol ip prio 1 u32 match mark 0x1 0xffffffff flowid 1:10"
    )

    for party_id in range(num_parties):
        port = base_port + party_id
        run_cmd(
            f"iptables -t mangle -A OUTPUT -p tcp --dport {port} -j MARK --set-mark 1"
        )


def cleanup_tc_and_iptables():
    print("clear tc and iptables")
    run_cmd(f"tc qdisc del dev {INTERFACE} root")
    run_cmd(f"iptables -t mangle -F")


def run_party(party_id, num_parties, base_port):
    proc = subprocess.Popen(
        [BINARY_PATH, "-n", str(num_parties), "-i", str(party_id)],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    return proc


def terminate_all():
    print("\n Terminating all processes...")
    for proc in processes:
        if proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
    cleanup_tc_and_iptables()


def signal_handler(sig, frame):
    terminate_all()
    sys.exit(0)


def main():
    if len(sys.argv) != 5:
        print(
            "usage: python3 multiprocess-run-fin.py <NUM_PARTIES> <BASE_PORT> <BANDWIDTH_MBPS> <DELAY_MS>"
        )
        sys.exit(1)

    num_parties = int(sys.argv[1])
    base_port = int(sys.argv[2])
    bandwidth_mbps = int(sys.argv[3])
    delay_ms = float(sys.argv[4])
    base_port = 20500
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    setup_tc_and_iptables(base_port, num_parties, bandwidth_mbps, delay_ms)

    try:
        for party_id in range(num_parties):
            proc = run_party(party_id, num_parties, base_port)
            print(
                f"Started party {party_id} (PID={proc.pid}) on port {base_port + party_id}"
            )
            processes.append(proc)

        for proc in processes:
            proc.wait()
            print(f"Process {proc.pid} exited with code {proc.returncode}")

    except KeyboardInterrupt:
        terminate_all()


if __name__ == "__main__":
    main()
