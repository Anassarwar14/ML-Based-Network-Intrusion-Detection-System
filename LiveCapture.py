import pyshark
from collections import defaultdict
import time
import socket
import json
import datetime
import os
import threading

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

connection_history = defaultdict(list)
host_history = defaultdict(int)

session_data = defaultdict(lambda: {
    'count': 0, 'srv_count': 0, 'serror_rate': 0, 'srv_serror_rate': 0,
    'rerror_rate': 0, 'srv_rerror_rate': 0, 'same_srv_rate': 0, 'diff_srv_rate': 0,
    'srv_diff_host_rate': 0, 'dst_host_count': 0, 'dst_host_srv_count': 0,
    'dst_host_same_srv_rate': 0, 'dst_host_diff_srv_rate': 0,
    'dst_host_same_src_port_rate': 0, 'dst_host_srv_diff_host_rate': 0,
    'dst_host_serror_rate': 0, 'dst_host_srv_serror_rate': 0,
    'dst_host_rerror_rate': 0, 'dst_host_srv_rerror_rate': 0
})

def get_flag_symbol(tcp_layer):
    if not tcp_layer:
        return 'OTH'
        
    try:
        flags = int(tcp_layer.flags, 16)
        
        if flags & 0x02 and not (flags & 0x10):
            return 'S0'
        elif flags & 0x02 and flags & 0x10:
            return 'SF'
        elif flags & 0x10 and not (flags & 0x02):
            return 'S1'
        elif flags & 0x04:
            return 'REJ'
        elif flags & 0x01:
            return 'S2'
        else:
            return 'OTH'
    except:
        return 'OTH'

def map_service(dst_port):
    common_services = {
        80: 'http',
        443: 'https',
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'domain',
        110: 'pop_3',
        143: 'imap',
        513: 'remote_job',
        514: 'private',
    }
    return common_services.get(dst_port, 'private')

def update_connection_history(src_ip, dst_ip, src_port, dst_port, protocol, service, flag):
    connection_key = (dst_ip, dst_port)
    src_key = (src_ip, src_port)
    
    connection_history[connection_key].append({
        'src_ip': src_ip,
        'src_port': src_port,
        'protocol': protocol,
        'service': service,
        'flag': flag,
        'timestamp': time.time()
    })
    
    if len(connection_history[connection_key]) > 100:
        connection_history[connection_key] = connection_history[connection_key][-100:]
    
    host_history[dst_ip] += 1
    if host_history[dst_ip] > 255:
        host_history[dst_ip] = 255

def compute_session_features(dst_ip, dst_port, src_ip, src_port, protocol, service, flag):
    connection_key = (dst_ip, dst_port)
    recent_connections = connection_history[connection_key]
    
    current_time = time.time()
    time_window = 2.0
    
    recent_connections = [conn for conn in recent_connections 
                         if current_time - conn['timestamp'] <= time_window]
    
    count = len(recent_connections)
    
    service_connections = [conn for conn in recent_connections 
                          if conn['service'] == service]
    srv_count = len(service_connections)
    
    serror_connections = [conn for conn in recent_connections 
                         if conn['flag'] in ['S0', 'S1', 'REJ']]
    rerror_connections = [conn for conn in recent_connections 
                         if conn['flag'] == 'REJ']
    
    serror_rate = len(serror_connections) / max(count, 1)
    rerror_rate = len(rerror_connections) / max(count, 1)
    
    srv_serror_connections = [conn for conn in service_connections 
                             if conn['flag'] in ['S0', 'S1', 'REJ']]
    srv_rerror_connections = [conn for conn in service_connections 
                             if conn['flag'] == 'REJ']
    
    srv_serror_rate = len(srv_serror_connections) / max(srv_count, 1)
    srv_rerror_rate = len(srv_rerror_connections) / max(srv_count, 1)
    
    same_srv_rate = srv_count / max(count, 1)
    diff_srv_rate = 1 - same_srv_rate
    
    diff_host_services = set()
    for conn in service_connections:
        if conn['src_ip'] != src_ip:
            diff_host_services.add(conn['src_ip'])
    
    srv_diff_host_rate = len(diff_host_services) / max(srv_count, 1)
    
    dst_host_connections = []
    for key, conns in connection_history.items():
        if key[0] == dst_ip:
            dst_host_connections.extend(conns)
    
    dst_host_count = min(len(dst_host_connections), 255)
    
    dst_host_srv_connections = [conn for conn in dst_host_connections 
                               if conn['service'] == service]
    dst_host_srv_count = len(dst_host_srv_connections)
    
    dst_host_same_srv_rate = dst_host_srv_count / max(dst_host_count, 1)
    dst_host_diff_srv_rate = 1 - dst_host_same_srv_rate
    
    dst_host_same_src_port_connections = [conn for conn in dst_host_connections 
                                         if conn['src_port'] == src_port]
    dst_host_same_src_port_rate = len(dst_host_same_src_port_connections) / max(dst_host_count, 1)
    
    dst_host_diff_hosts = set()
    for conn in dst_host_srv_connections:
        if conn['src_ip'] != src_ip:
            dst_host_diff_hosts.add(conn['src_ip'])
    
    dst_host_srv_diff_host_rate = len(dst_host_diff_hosts) / max(dst_host_srv_count, 1)
    
    dst_host_serror_connections = [conn for conn in dst_host_connections 
                                  if conn['flag'] in ['S0', 'S1', 'REJ']]
    dst_host_rerror_connections = [conn for conn in dst_host_connections 
                                  if conn['flag'] == 'REJ']
    
    dst_host_serror_rate = len(dst_host_serror_connections) / max(dst_host_count, 1)
    dst_host_rerror_rate = len(dst_host_rerror_connections) / max(dst_host_count, 1)
    
    dst_host_srv_serror_connections = [conn for conn in dst_host_srv_connections 
                                      if conn['flag'] in ['S0', 'S1', 'REJ']]
    dst_host_srv_rerror_connections = [conn for conn in dst_host_srv_connections 
                                      if conn['flag'] == 'REJ']
    
    dst_host_srv_serror_rate = len(dst_host_srv_serror_connections) / max(dst_host_srv_count, 1)
    dst_host_srv_rerror_rate = len(dst_host_srv_rerror_connections) / max(dst_host_srv_count, 1)
    
    return {
        'count': count,
        'srv_count': srv_count,
        'serror_rate': serror_rate,
        'srv_serror_rate': srv_serror_rate,
        'rerror_rate': rerror_rate,
        'srv_rerror_rate': srv_rerror_rate,
        'same_srv_rate': same_srv_rate,
        'diff_srv_rate': diff_srv_rate,
        'srv_diff_host_rate': srv_diff_host_rate,
        'dst_host_count': dst_host_count,
        'dst_host_srv_count': dst_host_srv_count,
        'dst_host_same_srv_rate': dst_host_same_srv_rate,
        'dst_host_diff_srv_rate': dst_host_diff_srv_rate,
        'dst_host_same_src_port_rate': dst_host_same_src_port_rate,
        'dst_host_srv_diff_host_rate': dst_host_srv_diff_host_rate,
        'dst_host_serror_rate': dst_host_serror_rate,
        'dst_host_srv_serror_rate': dst_host_srv_serror_rate,
        'dst_host_rerror_rate': dst_host_rerror_rate,
        'dst_host_srv_rerror_rate': dst_host_srv_rerror_rate
    }

def extract_features(pkt):
    try:
        src_ip = pkt.ip.src if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'src') else '0.0.0.0'
        dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'dst') else '0.0.0.0'

        protocol_type = pkt.transport_layer.lower() if hasattr(pkt, 'transport_layer') and pkt.transport_layer else 'unknown'

        if protocol_type == 'tcp' and hasattr(pkt, 'tcp'):
            tcp_layer = pkt.tcp
            src_port = int(tcp_layer.srcport) if hasattr(tcp_layer, 'srcport') else 0
            dst_port = int(tcp_layer.dstport) if hasattr(tcp_layer, 'dstport') else 0
            flag = get_flag_symbol(tcp_layer)
        elif protocol_type == 'udp' and hasattr(pkt, 'udp'):
            udp_layer = pkt.udp
            src_port = int(udp_layer.srcport) if hasattr(udp_layer, 'srcport') else 0
            dst_port = int(udp_layer.dstport) if hasattr(udp_layer, 'dstport') else 0
            flag = 'SF'
        else:
            src_port = 0
            dst_port = 0
            flag = 'OTH'

        service = map_service(dst_port)

        src_bytes = int(pkt.length) if hasattr(pkt, 'length') else 0
        dst_bytes = 0

        update_connection_history(src_ip, dst_ip, src_port, dst_port, protocol_type, service, flag)

        land = 1 if src_ip == dst_ip and src_port == dst_port else 0
        wrong_fragment = int(pkt.ip.frag_offset) if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'frag_offset') else 0
        urgent = int(pkt.tcp.urgent_pointer) if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'urgent_pointer') else 0

        content_features = {
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 1 if flag == 'SF' and service in ['http', 'ftp', 'ssh'] else 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0
        }

        session_features = compute_session_features(
            dst_ip, dst_port, src_ip, src_port, protocol_type, service, flag
        )

        feature_data = {
            'duration': 0,
            'protocol_type': protocol_type,
            'service': service,
            'flag': flag,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'land': land,
            'wrong_fragment': wrong_fragment,
            'urgent': urgent,
            **content_features,
            **session_features
        }

        return feature_data
    except Exception as e:
        print(f"Error processing packet: {e}")
        return None

def listen_for_responses(sock):
    while True:
        try:
            response = sock.recv(4096).decode().strip()
            if response:
                response_data = json.loads(response)
                if response_data.get("status") == "problematic_packet":
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    if not os.path.exists("problematic_packets"):
                        os.makedirs("problematic_packets")
                    with open(f"problematic_packets/problematic_packet_{timestamp}.json", "w") as f:
                        json.dump(response_data["data"], f, indent=2)
                    print(f"Problematic packet logged at problematic_packets/problematic_packet_{timestamp}.json")
        except Exception as e:
            print(f"Error receiving response: {e}")
            break

def main():
    try:
        print(f"Connecting to prediction server at {SERVER_IP}:{SERVER_PORT}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, SERVER_PORT))
        
        print("Available network interfaces:")
        interfaces = pyshark.LiveCapture().interfaces
        for i, interface in enumerate(interfaces):
            print(f"{i}: {interface}")
            
        selected = int(input("Select interface number to monitor: "))
        interface = interfaces[selected]
        
        print(f"Starting packet capture on interface: {interface}")
        capture = pyshark.LiveCapture(interface=interface)
        
        listener_thread = threading.Thread(target=listen_for_responses, args=(sock,), daemon=True)
        listener_thread.start()

        packet_count = 0
        for packet in capture.sniff_continuously():
            packet_count += 1
            print(f"\nProcessing packet #{packet_count}...")
            
            feature_data = extract_features(packet)
            if feature_data:
                try:
                    json_data = json.dumps(feature_data)
                    sock.sendall(json_data.encode() + b"\n")
                    print(f"Sent features to prediction server.")
                except Exception as e:
                    print(f"Error sending data: {e}")
                    break
            
            if packet_count % 100 == 0:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                if not os.path.exists("packet_logs"):
                    os.makedirs("packet_logs")
                with open(f"packet_logs/packet_{timestamp}.json", "w") as f:
                    json.dump(feature_data, f, indent=2)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as e:
        print(f"Error in capture: {e}")
    finally:
        if 'sock' in locals():
            sock.close()
            print("Connection to prediction server closed.")

if __name__ == "__main__":
    main()