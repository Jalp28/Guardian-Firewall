# Guardian Firewall 
## 1. Overview
The Guardian Firewall GUI is a lightweight, user-friendly network security tool designed to monitor and filter network traffic in real-time. Built using Python and Tkinter, it offers an intuitive graphical interface for managing firewall rules and logging packets, with integration into Linux's iptables for rule enforcement.

## 2. Objectives
- Provide an accessible interface for managing network security rules.
- Enable real-time packet monitoring with customizable filtering.
- Simplify iptables rule application for non-technical users.
- Ensure persistent storage of rules and logs for ongoing use.

## 3. Features
- Real-time packet logging with color-coded actions (red for block, white for allow/no rule).
- Customizable rules for source/destination IP, port, protocol, and action.
- Persistent rule storage in `rules.json` and log in `log.txt`.
- iptables integration for traffic filtering.
- Responsive UI with scrollable sections, status bar, and rule management tools.

## 4. Installation
### Requirements
- Python 3 with required libraries:
  - Install Scapy: `pip install scapy`
  - Tkinter (typically included with Python).
- Linux environment (e.g., Kali).

### Steps
1. Clone or download the repository containing `gui.py`.
2. Navigate to the project folder: `cd /path/to/GuardianFirewall`.
3. Ensure dependencies are installed.

## 5. Usage
### Setup
1. Open `gui.py` and update `self.network_interface = "eth0"` to your active interface (e.g., `wlan0` or `lo`). Check interfaces with `ifconfig` or `ip link`.
2. Create `rules.json` if absent, with example content:
   ```json
   [
       {"action": "block", "src_ip": "192.168.1.100", "dst_ip": null, "port": null, "protocol": null},
       {"action": "allow", "src_ip": null, "dst_ip": null, "port": 80, "protocol": "TCP"}
   ]
   ```
3. Create an empty `log.txt` if not present.

### Running the GUI
1. Launch with: `sudo python3 gui.py` (sudo is required for iptables).
2. The interface includes:
   - **Live Packet Log**: Displays real-time traffic.
   - **Rule Management**: Add, change, or delete rules.
   - **Controls**: Start/stop sniffing, clear iptables, view/refresh logs.

### Operations
- **Start Sniffing**: Click "Start Sniffing" (status turns green).
- **Stop Sniffing**: Click "Stop Sniffing" (status turns red).
- **Add Rule**: Enter IP, port, protocol, and action, then click "Add Rule".
- **Change Rule**: Select a rule, update fields, and click "Change Rule".
- **Delete Rule**: Select a rule and click "Delete Rule".
- **Clear iptables**: Removes all rules.
- **View Log**: Opens a window with logged packets.
- **Refresh Log**: Updates the live log display.

### Example
- Block traffic from `192.168.1.100`: Set "Source IP" to `192.168.1.100`, "Action" to `block`, and add.
- Allow HTTP traffic: Set "Port" to `80`, "Protocol" to `TCP`, "Action" to `allow`, and add.

## 6. Benefits
- **Ease of Use**: Intuitive GUI reduces the learning curve.
- **Real-Time Monitoring**: Immediate feedback on network activity.
- **Ease of Use**: Intuitive GUI reduces the learning curve.
- **Flexibility**: Custom rules for specific IPs, ports, and protocols.
- **Security**: Integrates with iptables for robust traffic control.
- **Portability**: Runs on any Linux system with Python and iptables.
