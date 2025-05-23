# PacketSniffer: Cross-Platform Network Analyzer

**PacketSniffer** is a powerful, real-time network packet analyzer built in Python. It captures, decodes, and displays live packet data on **Windows** and **Linux**, supporting detailed inspection of **Ethernet**, **IPv4/IPv6**, **TCP**, **UDP**, and **ICMP/ICMPv6** traffic. Designed for network diagnostics, educational use, and traffic analysis, it offers filtering, saving, and protocol insights in a terminal-based interface.

---

## ✨ Features

* **Real-time Packet Capture**

  * Supports both **Windows** and **Linux**
  * Raw socket access to all incoming packets
* **Protocol Decoding**:

  * Ethernet
  * IPv4 / IPv6
  * TCP, UDP, ICMP, ICMPv6
* **Smart Details**:

  * Source/Destination IPs and Ports
  * Protocol Names and TCP Flags
  * Payload data in ASCII and HEX
* **Packet Saving Options**:

  * Save all packets in structured **JSON**
  * Generate a readable **Summary Report**
* **Filtering Support**:

  * Show only packets of a selected protocol (`--filter TCP`)
* **Safe Shutdown**:

  * Graceful exit with save prompt on Ctrl+C
* **Auto-detection** of active network interface (Windows)

---

## 🛠 Installation

### Requirements

* Python 3.8+
* Admin/root privileges (raw socket access)

### Dependencies

Install with pip:

```bash
pip install -r requirements.txt
```

#### `requirements.txt`:

```text
argparse
ipaddress
```

---

## 🚀 Running the Sniffer

### On **Linux**:

```bash
sudo python3 Sniffer.py
```

### On **Windows**:

Run Command Prompt or PowerShell as Administrator:

```bash
python Sniffer.py
```

### With Filtering:

```bash
python Sniffer.py --filter TCP
```

---

## 📦 How to Use

1. Launch the program.
2. Packet capture begins instantly.
3. View decoded information in the terminal:

   * Ethernet Header
   * IP/Port Information
   * Payload (decoded if possible)
4. Press `Ctrl+C` to stop.

When prompted:

* Choose to **save packets** to a `.json` file.
* A `_summary.txt` will also be created.

---

## 📁 Output Example

### JSON File:

* Timestamp, IP version
* Source/Destination
* Protocol, Ports
* Payload (HEX + ASCII)

### TXT Summary:

* Easy-to-read log of captured packets
* Protocol count, flags, and payload preview

---

## ⚠️ Permissions

* **Windows**: Must run as Administrator
* **Linux**: Must run with `sudo`
* Without proper permissions, raw sockets will not function.

---

## 🧠 Technical Overview

* **Raw Sockets** used to read low-level packets.
* Protocol headers are parsed using `struct.unpack`.
* Packet saving is handled via JSON serialization.
* Filtering uses protocol number mapping (e.g., TCP = 6).
* IP and MAC addresses are formatted for readability.

---



## 👨‍💻 Author

Developed by \[Neha Biju].

