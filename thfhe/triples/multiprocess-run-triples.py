#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import subprocess
import signal

INTERFACE = "lo"
processes = []


def run_cmd(cmd):
    subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL)


def setup_tc_and_iptables(base_port, parties_num, bandwidth_mbps, delay_ms):
    print(f"set latency: {bandwidth_mbps}Mbps, ping time: {delay_ms}ms")

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

    port_range = parties_num * parties_num
    for port in range(base_port, base_port + port_range):
        run_cmd(
            f"iptables -t mangle -A OUTPUT -p tcp --dport {port} -j MARK --set-mark 1"
        )


def cleanup():
    print("clear tc and iptables")
    run_cmd(f"tc qdisc del dev {INTERFACE} root")
    run_cmd(f"iptables -t mangle -F")


def sigint_handler(signum, frame):
    print("\nCaught Ctrl+C, terminating all child processes...")
    for p in processes:
        if p.poll() is None:
            p.terminate()
    cleanup()
    sys.exit(0)


signal.signal(signal.SIGINT, sigint_handler)


def main():
    if len(sys.argv) != 5:
        print(
            "usage: python3 run_multiple.py <NUM_PARTIES> <BASE_PORT> <BANDWIDTH_MBPS> <DELAY_MS>"
        )
        sys.exit(1)

    parties_num = int(sys.argv[1])
    base_port = int(sys.argv[2])
    bandwidth_mbps = int(sys.argv[3])
    delay_ms = float(sys.argv[4])

    setup_tc_and_iptables(base_port, parties_num, bandwidth_mbps, delay_ms)

    try:
        for i in range(parties_num):
            cmd = f"./test_triples {parties_num} {i} {base_port}"
            print(f"Starting process: {cmd}")
            p = subprocess.Popen(cmd, shell=True)
            processes.append(p)

        for p in processes:
            p.wait()
            print(f"Process {p.pid} exited with code {p.returncode}")
    except KeyboardInterrupt:
        sigint_handler(None, None)
    finally:
        cleanup()


if __name__ == "__main__":
    main()
