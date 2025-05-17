#!/bin/bash

# Function to start Unbound
start_unbound() {
    echo "Starting Unbound..."
    sudo unbound-control start &
}

# Function to stop Unbound
stop_unbound() {
    echo "Stopping Unbound..."
    sudo unbound-control stop
}

# Function to write a task to task_params.txt
write_task() {
    echo "$1" > task_params.txt
}

# Simulate sending Ctrl+C
send_ctrl_c() {
    echo "Sending Ctrl+C..."
    sudo pkill -2 unbound  # This sends SIGINT (Ctrl+C) to unbound process
}

# Array of tasks to execute
tasks=(
    "0 example.com 1"                       # Task 0: Set TTL to 1 second
    # "1 example.com 120"                      # Task 1: Set TTL to 120 seconds
    # "2 example.com 300"                      # Task 2: Set TTL to 300 seconds
    # "3 example.com 600"                      # Task 3: Set TTL to 600 seconds
    # "4 example.com A 192.0.2.1"                # Task 4: Create A record
    # "5 example.com AAAA 2001:0db8::1"          # Task 5: Create AAAA record
    # "6 www.example.com CNAME alias.example.com." # Task 6: Create CNAME record
    # "7 example.com NS ns1.example.com."        # Task 7: Create NS record
    # "8 example.com MX \"10 mail.example.com.\"" # Task 8: Create MX record
    # "9 example.com TXT \"Example text\""       # Task 9: Create TXT record
    # "10 example.com A 203.0.113.1"             # Task 10: Append A record
    # "11 example.com AAAA 2001:0db8::2"         # Task 11: Add AAAA record
    # "12 www.example.com CNAME alias2.example.com." # Task 12: Add CNAME record
    # "13 example.com NS ns2.example.com."       # Task 13: Add NS record
    # "14 example.com MX \"20 mail2.example.com.\"" # Task 14: Add MX record
    # "15 example.com TXT \"Another text\""      # Task 15: Add TXT record
    # "16 example.com A 198.51.100.1"            # Task 16: Change to A record
    # "17 example.com AAAA 2001:0db8::3"         # Task 17: Change to AAAA record
    # "18 www.example.com CNAME alias3.example.com." # Task 18: Change to CNAME record
    # "19 example.com NS ns3.example.com."       # Task 19: Change to NS record
    # "20 example.com MX \"30 mail3.example.com.\"" # Task 20: Change to MX record
    # "21 example.com TXT \"Yet another text\""  # Task 21: Change to TXT record
    # "22 example.com"                           # Task 22: Delete all RRs
    # "23 example.com"                           # Task 23: Change domain name to www.phishylink.com
    # "24 example.com"                           # Task 24: Change IP address to 192.168.0.1
    # "25 example.com"                           # Task 25: Append duplicate RR with IP 192.168.0.1
    # "26 example.com"                           # Task 26: Randomly modify optional fields
    # "27 example.com"                           # Task 27: Change delimiter formats in response
)

# Loop through the tasks
for task in "${tasks[@]}"; do
    # Write the task to the file
    echo "Writing task: $task"
    write_task "$task"

    # Start Unbound
    start_unbound

    # Wait for 1 minute (60 seconds)
    echo "Waiting for 1 minute..."
    sleep 600

    # Stop Unbound
    send_ctrl_c
    stop_unbound

    # Clear the task_params.txt file (optional)
    echo "Clearing task_params.txt"
    > task_params.txt
done

echo "All tasks completed."
