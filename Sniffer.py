import socket
import struct
import textwrap
import sys
import os
import ipaddress
import binascii
from datetime import datetime
import json
import argparse

# Separator line
SEPARATOR = '='*80

TAB_1='\t'
TAB_2='\t\t'
TAB_3='\t\t\t'
TAB_4='\t\t\t\t'

DATA_TAB_1='\t'
DATA_TAB_2='\t\t'
DATA_TAB_3='\t\t\t'
DATA_TAB_4='\t\t\t\t'

# Protocol numbers
PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
    88: "EIGRP",
    89: "OSPF"
}

# Common ports and their services
PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-ALT"
}

def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def get_interface_ip():
    try:
        # Get the default interface IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def format_ipv4(addr):
    return '.'.join(map(str, addr))

def format_ipv6(addr):
    return ipaddress.IPv6Address(addr).exploded

def parse_ipv4(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ipv4(src), format_ipv4(target), data[header_length:]

def parse_ipv6(data):
    version_traffic = struct.unpack('! B', data[0:1])[0]
    version = version_traffic >> 4
    traffic_class = ((version_traffic & 0x0F) << 4) | (data[1] >> 4)
    flow_label = struct.unpack('! I', b'\x00' + data[1:4])[0] & 0x0FFFFF
    payload_length, next_header, hop_limit = struct.unpack('! H B B', data[4:8])
    src = data[8:24]
    dst = data[24:40]
    return (version, traffic_class, flow_label, payload_length, 
            next_header, hop_limit, format_ipv6(src), format_ipv6(dst), 
            data[40:])

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_packet(data):
    src_port, dst_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:10])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dst_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_packet(data):
    src_port, dst_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dst_port, size, data[8:]

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def print_packet_header(version):
    print(f"\n{SEPARATOR}")
    print(f"[{get_timestamp()}] New {version} Packet Detected")
    print(SEPARATOR)

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        # Try to decode as UTF-8 first
        try:
            decoded = string.decode('utf-8')
            # Check if it's printable text
            if all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in decoded):
                return '\n'.join([prefix + line for line in textwrap.wrap(decoded, size)])
        except:
            pass
        
        # If not UTF-8 or not printable, show hex
        hex_str = ' '.join(f'{b:02x}' for b in string)
        return '\n'.join([prefix + line for line in textwrap.wrap(hex_str, size)])
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def get_port_service(port):
    return PORTS.get(port, f"Unknown-{port}")

def save_packet_to_file(packet_info, filename):
    """Save packet information to a JSON file"""
    try:
        # Create a dictionary with packet information
        packet_data = {
            'timestamp': packet_info['timestamp'],
            'version': packet_info['version'],
            'source': packet_info['source'],
            'destination': packet_info['destination'],
            'protocol': packet_info['protocol'],
            'length': packet_info['length'],
            'details': packet_info['details']
        }
        
        # Convert bytes to hex string for JSON serialization
        if 'payload' in packet_data['details']:
            packet_data['details']['payload'] = binascii.hexlify(packet_data['details']['payload']).decode()
        
        # Append to file
        with open(filename, 'a') as f:
            json.dump(packet_data, f)
            f.write('\n')  # Add newline for each packet
    except Exception as e:
        print(f"Error saving packet: {e}")

def process_packet_data(proto, data, src_port=None, dst_port=None, save_file=None):
    protocol_name = PROTOCOLS.get(proto, f"Protocol {proto}")
    print(f'{TAB_2}{protocol_name} Packet:')
    
    # Create packet info dictionary
    packet_info = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        'version': 'IPv4' if proto in [1, 6, 17] else 'IPv6',
        'protocol': protocol_name,
        'details': {
            'protocol': proto,
            'protocol_name': protocol_name,
            'payload': data
        }
    }
    
    if proto == 1:  # ICMP
        icmp_type, code, checksum, data = icmp_packet(data)
        print(f'{TAB_3}Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
        packet_info['details'].update({
            'type': icmp_type,
            'code': code,
            'checksum': checksum
        })
        if data:
            print(f'{TAB_3}Data:')
            print(format_multi_line(DATA_TAB_3, data))
    
    elif proto == 6:  # TCP
        src_port, dst_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_packet(data)
        print(f'{TAB_3}Source Port: {src_port} ({get_port_service(src_port)})')
        print(f'{TAB_3}Destination Port: {dst_port} ({get_port_service(dst_port)})')
        print(f'{TAB_3}Sequence: {sequence}, Acknowledgement: {acknowledgement}')
        print(f'{TAB_3}Flags:')
        flags = []
        if flag_urg: flags.append("URG")
        if flag_ack: flags.append("ACK")
        if flag_psh: flags.append("PSH")
        if flag_rst: flags.append("RST")
        if flag_syn: flags.append("SYN")
        if flag_fin: flags.append("FIN")
        print(f'{TAB_4}{" ".join(flags)}')
        packet_info['details'].update({
            'src_port': src_port,
            'dst_port': dst_port,
            'sequence': sequence,
            'acknowledgement': acknowledgement,
            'flags': {
                'URG': flag_urg,
                'ACK': flag_ack,
                'PSH': flag_psh,
                'RST': flag_rst,
                'SYN': flag_syn,
                'FIN': flag_fin
            }
        })
        if data:
            print(f'{TAB_3}Data:')
            print(format_multi_line(DATA_TAB_3, data))
    
    elif proto == 17:  # UDP
        src_port, dst_port, size, data = udp_packet(data)
        print(f'{TAB_3}Source Port: {src_port} ({get_port_service(src_port)})')
        print(f'{TAB_3}Destination Port: {dst_port} ({get_port_service(dst_port)})')
        print(f'{TAB_3}Length: {size}')
        packet_info['details'].update({
            'src_port': src_port,
            'dst_port': dst_port,
            'length': size
        })
        if data:
            print(f'{TAB_3}Data:')
            print(format_multi_line(DATA_TAB_3, data))
    
    elif proto == 58:  # ICMPv6
        icmp_type, code, checksum, data = icmp_packet(data)
        print(f'{TAB_3}Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
        packet_info['details'].update({
            'type': icmp_type,
            'code': code,
            'checksum': checksum
        })
        if data:
            print(f'{TAB_3}Data:')
            print(format_multi_line(DATA_TAB_3, data))
    
    else:
        if data:
            print(f'{TAB_3}Data:')
            print(format_multi_line(DATA_TAB_3, data))
    
    # Save packet if save file is specified
    if save_file:
        save_packet_to_file(packet_info, save_file)

def save_packets_to_file(packets, filename):
    """Save captured packets to a nicely formatted JSON file"""
    try:
        # Create a structured dictionary for the capture
        capture_data = {
            "capture_info": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_packets": len(packets),
                "protocols": {},
                "ip_versions": {
                    "IPv4": 0,
                    "IPv6": 0
                }
            },
            "packets": []
        }

        # Count protocols and IP versions
        for packet in packets:
            # Count protocols
            protocol = packet['protocol']
            if protocol not in capture_data["capture_info"]["protocols"]:
                capture_data["capture_info"]["protocols"][protocol] = 0
            capture_data["capture_info"]["protocols"][protocol] += 1

            # Count IP versions
            capture_data["capture_info"]["ip_versions"][packet['version']] += 1

            # Create a clean packet entry
            packet_entry = {
                "timestamp": packet['timestamp'],
                "ip_version": packet['version'],
                "protocol": packet['protocol'],
                "source": packet['source'],
                "destination": packet['destination'],
                "length": packet['length'],
                "details": {}
            }

            # Add protocol-specific details
            details = packet['details']
            if 'src_port' in details:
                packet_entry["details"]["ports"] = {
                    "source": details['src_port'],
                    "destination": details['dst_port']
                }
                if 'length' in details:
                    packet_entry["details"]["length"] = details['length']

            if 'sequence' in details:
                packet_entry["details"]["sequence"] = details['sequence']
                packet_entry["details"]["acknowledgement"] = details['acknowledgement']

            if 'flags' in details:
                packet_entry["details"]["tcp_flags"] = {
                    flag: value for flag, value in details['flags'].items() if value
                }

            if 'type' in details:
                packet_entry["details"]["icmp"] = {
                    "type": details['type'],
                    "code": details['code'],
                    "checksum": details['checksum']
                }

            # Add payload as hex with ASCII representation
            if 'payload' in details:
                payload = details['payload']
                if isinstance(payload, bytes):
                    hex_payload = binascii.hexlify(payload).decode()
                    try:
                        ascii_payload = payload.decode('utf-8', errors='replace')
                        # Replace non-printable characters with dots
                        ascii_payload = ''.join(c if 32 <= ord(c) <= 126 else '.' for c in ascii_payload)
                    except:
                        ascii_payload = None
                    
                    packet_entry["details"]["payload"] = {
                        "hex": ' '.join(hex_payload[i:i+2] for i in range(0, len(hex_payload), 2)),
                        "ascii": ascii_payload if ascii_payload else None,
                        "length": len(payload)
                    }

            capture_data["packets"].append(packet_entry)

        # Save with nice formatting
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(capture_data, f, indent=2, ensure_ascii=False)
        
        # Create a summary file
        summary_filename = filename.rsplit('.', 1)[0] + '_summary.txt'
        with open(summary_filename, 'w', encoding='utf-8') as f:
            f.write("Packet Capture Summary\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Capture Time: {capture_data['capture_info']['timestamp']}\n")
            f.write(f"Total Packets: {capture_data['capture_info']['total_packets']}\n\n")
            
            f.write("IP Versions:\n")
            for version, count in capture_data['capture_info']['ip_versions'].items():
                f.write(f"  {version}: {count} packets\n")
            
            f.write("\nProtocols:\n")
            for protocol, count in capture_data['capture_info']['protocols'].items():
                f.write(f"  {protocol}: {count} packets\n")
            
            f.write("\nPacket Details:\n")
            f.write("-" * 50 + "\n")
            for i, packet in enumerate(capture_data['packets'], 1):
                f.write(f"\nPacket {i}:\n")
                f.write(f"  Time: {packet['timestamp']}\n")
                f.write(f"  Version: {packet['ip_version']}\n")
                f.write(f"  Protocol: {packet['protocol']}\n")
                f.write(f"  Source: {packet['source']}\n")
                f.write(f"  Destination: {packet['destination']}\n")
                f.write(f"  Length: {packet['length']} bytes\n")
                
                if 'ports' in packet['details']:
                    f.write(f"  Ports: {packet['details']['ports']['source']} -> {packet['details']['ports']['destination']}\n")
                
                if 'tcp_flags' in packet['details']:
                    f.write(f"  TCP Flags: {' '.join(packet['details']['tcp_flags'].keys())}\n")
                
                if 'icmp' in packet['details']:
                    f.write(f"  ICMP Type: {packet['details']['icmp']['type']}, Code: {packet['details']['icmp']['code']}\n")
                
                if 'payload' in packet['details']:
                    payload = packet['details']['payload']
                    f.write(f"  Payload Length: {payload['length']} bytes\n")
                    if payload['ascii']:
                        f.write(f"  Payload (ASCII): {payload['ascii']}\n")
                    f.write(f"  Payload (HEX): {payload['hex']}\n")

        print(f"\nSuccessfully saved capture to:")
        print(f"  - {filename} (Full JSON capture)")
        print(f"  - {summary_filename} (Human-readable summary)")
        return True
    except Exception as e:
        print(f"\nError saving packets: {e}")
        return False

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Network Packet Sniffer')
    parser.add_argument('-f', '--filter', help='Filter packets by protocol (TCP, UDP, ICMP, etc.)', metavar='PROTOCOL')
    args = parser.parse_args()

    if not is_admin():
        print("This program requires administrator privileges.")
        print("Please run as administrator (Windows) or with sudo (Linux)")
        sys.exit(1)

    # List to store captured packets
    captured_packets = []

    conn = None
    try:
        # Try Windows socket first
        if os.name == 'nt':  # Windows
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            local_ip = get_interface_ip()
            conn.bind((local_ip, 0))
            conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            print(f"Running in Windows mode on interface {local_ip}...")
        else:  # Linux/Unix
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            print("Running in Linux mode...")

        print("\nStarting packet capture... Press Ctrl+C to stop\n")
        print("Protocols being monitored:")
        for proto_num, proto_name in PROTOCOLS.items():
            print(f"{TAB_1}{proto_name} (Protocol {proto_num})")
        print("\nCommon ports being monitored:")
        for port, service in PORTS.items():
            print(f"{TAB_1}{service} (Port {port})")
        if args.filter:
            print(f"\nFiltering packets for protocol: {args.filter}")
        print()

        def process_and_store_packet(packet_info):
            if packet_info:
                captured_packets.append(packet_info)
                if args.filter and packet_info['protocol'] != args.filter:
                    return
                # Display packet information
                print_packet_header(packet_info['version'])
                print(f'{TAB_1}Version: {packet_info["details"]["version"]}')
                print(f'{TAB_1}Protocol: {packet_info["protocol"]}')
                print(f'{TAB_1}Source: {packet_info["source"]}, Target: {packet_info["destination"]}')
                process_packet_data(packet_info['details']['protocol'], packet_info['details']['payload'])

        while True:
            try:
                if os.name == 'nt':  # Windows
                    raw_data = conn.recvfrom(65565)[0]
                    version = (raw_data[0] >> 4)
                    if version == 4:
                        packet_info = process_ipv4_packet(raw_data)
                        process_and_store_packet(packet_info)
                    elif version == 6:
                        packet_info = process_ipv6_packet(raw_data)
                        process_and_store_packet(packet_info)
                    
                    if len(raw_data) >= 14:
                        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
                        if dest_mac and src_mac:
                            print(f'{TAB_1}Ethernet Frame:')
                            print(f'{TAB_2}Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')
                else:  # Linux
                    raw_data, addr = conn.recvfrom(65565)
                    if len(raw_data) >= 14:
                        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
                        if dest_mac and src_mac:
                            print(f'{TAB_1}Ethernet Frame:')
                            print(f'{TAB_2}Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')
                            if eth_proto == 8:  # IPv4
                                try:
                                    packet_info = process_ipv4_packet(data)
                                    process_and_store_packet(packet_info)
                                except:
                                    pass
                            elif eth_proto == 56710:  # IPv6
                                try:
                                    packet_info = process_ipv6_packet(data)
                                    process_and_store_packet(packet_info)
                                except:
                                    pass

            except KeyboardInterrupt:
                print("\nStopping packet capture...")
                if captured_packets:
                    while True:
                        save_choice = input("\nDo you want to save the captured packets? (yes/no): ").lower()
                        if save_choice in ['yes', 'y']:
                            filename = input("Enter filename to save (default: capture.json): ").strip()
                            if not filename:
                                filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                            if not filename.endswith('.json'):
                                filename += '.json'
                            
                            if save_packets_to_file(captured_packets, filename):
                                break
                        elif save_choice in ['no', 'n']:
                            print("\nDiscarding captured packets...")
                            break
                        else:
                            print("Please enter 'yes' or 'no'")
                break
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue

    except Exception as e:
        print(f"Error setting up socket: {e}")
        sys.exit(1)
    finally:
        if conn:
            try:
                if os.name == 'nt':
                    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                conn.close()
            except:
                pass

def process_ipv4_packet(data):
    try:
        version, header_length, ttl, proto, src_ip, target_ip, payload = parse_ipv4(data)
        protocol_name = PROTOCOLS.get(proto, f"Protocol {proto}")
        
        packet_info = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            'version': 'IPv4',
            'source': src_ip,
            'destination': target_ip,
            'protocol': protocol_name,
            'length': len(data),
            'details': {
                'version': version,
                'header_length': header_length,
                'ttl': ttl,
                'protocol': proto,
                'protocol_name': protocol_name,
                'source': src_ip,
                'destination': target_ip,
                'payload': payload
            }
        }
        
        if proto == 6:  # TCP
            src_port, dst_port, seq, ack, urg, ack_flag, psh, rst, syn, fin, data = tcp_packet(payload)
            packet_info['details'].update({
                'src_port': src_port,
                'dst_port': dst_port,
                'sequence': seq,
                'acknowledgement': ack,
                'flags': {
                    'URG': urg,
                    'ACK': ack_flag,
                    'PSH': psh,
                    'RST': rst,
                    'SYN': syn,
                    'FIN': fin
                }
            })
        elif proto == 17:  # UDP
            src_port, dst_port, size, data = udp_packet(payload)
            packet_info['details'].update({
                'src_port': src_port,
                'dst_port': dst_port,
                'length': size
            })
        
        return packet_info
    except:
        return None

def process_ipv6_packet(data):
    try:
        version, traffic_class, flow_label, payload_length, next_header, hop_limit, src_ip, target_ip, payload = parse_ipv6(data)
        protocol_name = PROTOCOLS.get(next_header, f"Protocol {next_header}")
        
        packet_info = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            'version': 'IPv6',
            'source': src_ip,
            'destination': target_ip,
            'protocol': protocol_name,
            'length': len(data),
            'details': {
                'version': version,
                'traffic_class': traffic_class,
                'flow_label': flow_label,
                'payload_length': payload_length,
                'next_header': next_header,
                'hop_limit': hop_limit,
                'protocol_name': protocol_name,
                'source': src_ip,
                'destination': target_ip,
                'payload': payload
            }
        }
        
        if next_header == 6:  # TCP
            src_port, dst_port, seq, ack, urg, ack_flag, psh, rst, syn, fin, data = tcp_packet(payload)
            packet_info['details'].update({
                'src_port': src_port,
                'dst_port': dst_port,
                'sequence': seq,
                'acknowledgement': ack,
                'flags': {
                    'URG': urg,
                    'ACK': ack_flag,
                    'PSH': psh,
                    'RST': rst,
                    'SYN': syn,
                    'FIN': fin
                }
            })
        elif next_header == 17:  # UDP
            src_port, dst_port, size, data = udp_packet(payload)
            packet_info['details'].update({
                'src_port': src_port,
                'dst_port': dst_port,
                'length': size
            })
        
        return packet_info
    except:
        return None

def ethernet_frame(data):
    try:
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.ntohs(proto), data[14:]
    except struct.error:
        return None, None, None, None

def get_mac_addr(bytes_addr):
    try:
        byte_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(byte_str).upper()
    except:
        return None
    

if __name__ == "__main__":
    main()