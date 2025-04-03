import os
import argparse
import subprocess
import time
import signal
import sys


def run_triples(total_parties, base_port=20000):
    processes = []

    try:
        # Start processes for all parties
        for i in range(total_parties):
            cmd = ["./bin/test_triples", str(total_parties), str(i), str(base_port)]
            proc = subprocess.Popen(cmd, cwd=os.path.dirname(__file__))
            processes.append(proc)

        # Wait for all processes to complete
        for proc in processes:
            proc.wait()

    except KeyboardInterrupt:
        print("\nReceived interrupt, cleaning up...")
        for proc in processes:
            if proc.poll() is None:  # If process is still running
                proc.send_signal(signal.SIGINT)
        sys.exit(1)

    # Check if any process failed
    for i, proc in enumerate(processes):
        if proc.returncode != 0:
            print(f"Party {i} failed with return code {proc.returncode}")
            return False

    return True


def main():
    parser = argparse.ArgumentParser(description="Run triples generation test")
    parser.add_argument(
        "--parties", type=int, default=3, help="Number of parties (default: 3)"
    )
    parser.add_argument(
        "--port", type=int, default=20000, help="Base port number (default: 20000)"
    )

    args = parser.parse_args()

    if args.parties < 2:
        print("Number of parties must be at least 2")
        sys.exit(1)

    success = run_triples(args.parties, args.port)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
