#!/bin/bash

INTERFACE="lo"

reset_tc() {
    echo "Resetting tc configuration on $INTERFACE..."
    sudo tc qdisc del dev $INTERFACE root 2>/dev/null || true
    echo "Reset complete."
}

wait_for_htb() {
    for i in {1..10}; do
        if tc qdisc show dev "$INTERFACE" | grep -q "htb 1:"; then
            return 0
        fi
        sleep 0.1
    done
    echo "htb root qdisc not ready after waiting"
    exit 1
}

set_tc() {
    local delay=$1
    local rate=$2

    echo "Setting delay=${delay}, bandwidth=${rate} on $INTERFACE..."

    reset_tc

    sudo tc qdisc add dev $INTERFACE root handle 1: htb default 10 || {
        echo "Failed to add htb qdisc"
        exit 1
    }

    wait_for_htb

    sudo tc class add dev $INTERFACE parent 1: classid 1:10 htb rate $rate || {
        echo "Failed to add htb class"
        exit 1
    }

    sudo tc qdisc add dev $INTERFACE parent 1:10 handle 10: netem delay $delay || {
        echo "Failed to add netem qdisc"
        exit 1
    }

    echo "tc configuration applied successfully!"
}

set_delay_only() {
    local delay=$1

    echo "Setting delay=${delay} only (no bandwidth limit) on $INTERFACE..."

    reset_tc

    sudo tc qdisc add dev $INTERFACE root netem delay $delay || {
        echo "Failed to apply netem delay-only rule"
        exit 1
    }

    echo "Delay-only tc configuration applied successfully!"
}

show_current_tc() {
    echo "Current tc configuration on $INTERFACE:"
    sudo tc qdisc show dev $INTERFACE
}

# 菜单
echo "Please choose one of the following options:"
echo "1. Set 1ms delay and 1Gbit/s bandwidth"
echo "2. Set 100ms delay and 100Mbit/s bandwidth"
echo "3. Reset tc configuration (restore to default)"
echo "4. Show current tc configuration"
echo "5. Set only 1ms delay (no bandwidth limit)"
echo "6. Set only 100ms delay (no bandwidth limit)"
read -p "Enter your choice (1-6): " choice

case "$choice" in
    1) set_tc "1ms" "1gbit" ;;
    2) set_tc "100ms" "100mbit" ;;
    3) reset_tc ;;
    4) show_current_tc ;;
    5) set_delay_only "1ms" ;;
    6) set_delay_only "100ms" ;;
    *) echo "Invalid choice. Exiting." ;;
esac
