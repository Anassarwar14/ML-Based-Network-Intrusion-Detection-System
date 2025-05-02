# import pyshark
# from collections import defaultdict
# import time
# import socket
# import json



# capture = pyshark.LiveCapture(interface='\\Device\\NPF_{ADF2B56F-2F44-4C2E-87DF-2938738A5215}', output_file='./test.pcapng')
# # capture.sniff(timeout=5)
# print("Capturing packets...")
# for packet in capture.sniff_continuously(packet_count=1):  # Capture 20 packets
#     feature_data = extract_features(packet)
#     if feature_data:
#         print(feature_data)  # Print extracted features


# __________________________ uncomment below code________________________________ 

# import pyshark
# from collections import defaultdict
# import time
# import socket
# import json

# SERVER_IP = "127.0.0.1"  # Change this to the actual destination IP if needed
# SERVER_PORT = 5000  

# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# sock.connect((SERVER_IP, SERVER_PORT))

# # Track session-based data for aggregation
# session_data = defaultdict(lambda: {
#     'count': 0, 'srv_count': 0, 'serror_rate': 0, 'srv_serror_rate': 0,
#     'rerror_rate': 0, 'srv_rerror_rate': 0, 'same_srv_rate': 0, 'diff_srv_rate': 0,
#     'srv_diff_host_rate': 0, 'dst_host_count': 0, 'dst_host_srv_count': 0,
#     'dst_host_same_srv_rate': 0, 'dst_host_diff_srv_rate': 0,
#     'dst_host_same_src_port_rate': 0, 'dst_host_srv_diff_host_rate': 0,
#     'dst_host_serror_rate': 0, 'dst_host_srv_serror_rate': 0,
#     'dst_host_rerror_rate': 0, 'dst_host_srv_rerror_rate': 0
# })

# # Capture network packets
# def extract_features(pkt):
#     try:
#         # Extract basic properties
#         src_ip = pkt.ip.src if hasattr(pkt, 'ip') else '0.0.0.0'
#         dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else '0.0.0.0'
#         src_port = pkt[pkt.transport_layer].srcport if hasattr(pkt, pkt.transport_layer) else '0'
#         dst_port = pkt[pkt.transport_layer].dstport if hasattr(pkt, pkt.transport_layer) else '0'
#         protocol_type = pkt.transport_layer if hasattr(pkt, 'transport_layer') else 'unknown'
#         tcp_layer = packet.tcp if hasattr(packet, 'tcp') else None
#         udp_layer = packet.udp if hasattr(packet, 'udp') else None
#         # service = pkt.highest_layer if hasattr(pkt, 'highest_layer') else 'unknown'
#         # flag = pkt.tcp.flags if 'TCP' in pkt else 'N/A'

#         # Packet size
#         src_bytes = int(pkt.length) if hasattr(pkt, 'length') else 0

#         # Identify session
#         session_key = (src_ip, dst_ip, src_port, dst_port)

#         # Compute derived features
#         land = 1 if src_ip == dst_ip and src_port == dst_port else 0
#         wrong_fragment = int(pkt.ip.frag_offset) if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'frag_offset') else 0
#         urgent = int(pkt.tcp.urgent_pointer) if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'urgent_pointer') else 0
#         # logged_in = 1 if protocol_type == 'tcp' and flag == 'SF' else 0  # Example assumption

#         # Attack-specific features (requires tracking over time)
#         session = session_data[session_key]
#         session['count'] += 1
#         session['srv_count'] += 1 if dst_port in session else 0
#         session['same_srv_rate'] = session['srv_count'] / session['count'] if session['count'] else 0
#         session['diff_srv_rate'] = 1 - session['same_srv_rate']
#         session['srv_diff_host_rate'] = 0  # Placeholder: Requires tracking multiple hosts

#         # Error rates (only for TCP)
#         if protocol_type == 'tcp':
#             # is_error = flag in ['S0', 'S1', 'REJ']
#             # session['serror_rate'] = sum(1 for s in session_data.values() if s['count'] and is_error) / session['count']
#             session['srv_serror_rate'] = session['serror_rate']  # Assuming same for srv
#             session['rerror_rate'] = 0  # Placeholder: Would need RST tracking
#             session['srv_rerror_rate'] = session['rerror_rate']

#         # Destination-based tracking
#         session['dst_host_count'] += 1
#         # session['dst_host_srv_count'] += 1 if service in session else 0
#         session['dst_host_same_srv_rate'] = session['dst_host_srv_count'] / session['dst_host_count']
#         session['dst_host_diff_srv_rate'] = 1 - session['dst_host_same_srv_rate']
#         session['dst_host_same_src_port_rate'] = 0  # Placeholder: Requires tracking ports
#         session['dst_host_srv_diff_host_rate'] = 0  # Placeholder


#         def get_flag_symbol(tcp):
#             flags = tcp.flags
#             flag_bits = {
#                 '0x0002': 'S0',  # SYN
#                 '0x0010': 'REJ', # ACK only, often rejected
#                 '0x0012': 'SF',  # SYN+ACK
#             }
#             return flag_bits.get(flags, 'OTH')

#         def map_service(pkt):
#             port = pkt.tcp.dstport if tcp_layer else (pkt.udp.dstport if udp_layer else None)
#             if port:
#                 common_services = {
#                     '80': 'http',
#                     '443': 'https',
#                     '21': 'ftp',
#                     '22': 'ssh',
#                     '23': 'telnet',
#                     '25': 'smtp',
#                     '53': 'domain',
#                     '110': 'pop_3',
#                     '143': 'imap',
#                     '513': 'remote_job',
#                     '514': 'private',
#                 }
#                 return common_services.get(str(port), 'private')
#             return 'private'


#         # Construct output
#         extracted_data = {
#             'duration': time.time(),  # Capture timestamp (for duration calculations)
#             'protocol_type': protocol_type,
#             'service': map_service(packet),
#             'flag': get_flag_symbol(tcp_layer) if tcp_layer else 'OTH',
#             'src_bytes': src_bytes,
#             'dst_bytes': 0,  # Requires tracking responses
#             'land': land,
#             'wrong_fragment': wrong_fragment,
#             'urgent': urgent,
#             'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
#             'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
#             'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
#             'num_access_files': 0, 'num_outbound_cmds': 0,
#             'is_host_login': 0, 'is_guest_login': 0,
#             **session  # Merge session-based computed values
#         }


# __________________________ uncomment above code________________________________ 

        # Example
        # {'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'REJ',
        # 'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0,
        # 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0,
        # 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
        # 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        # 'count': 205, 'srv_count': 12, 'serror_rate': 0.00, 'srv_serror_rate': 0.00,
        # 'rerror_rate': 1.00, 'srv_rerror_rate': 1.00, 'same_srv_rate': 0.06,
        # 'diff_srv_rate': 0.06, 'srv_diff_host_rate': 0.00, 'dst_host_count': 255,
        # 'dst_host_srv_count': 12, 'dst_host_same_srv_rate': 0.05,
        # 'dst_host_diff_srv_rate': 0.07, 'dst_host_same_src_port_rate': 0.00,
        # 'dst_host_srv_diff_host_rate': 0.00, 'dst_host_serror_rate': 0.00,
        # 'dst_host_srv_serror_rate': 0.00, 'dst_host_rerror_rate': 1.00,
        # 'dst_host_srv_rerror_rate': 1.00}

# __________________________ uncomment below code________________________________ 
#         return extracted_data
#     except Exception as e:
#         print(f"Error processing packet: {e}")
#         return None


# # Start capturing packets
# capture = pyshark.LiveCapture(interface='\\Device\\NPF_{ADF2B56F-2F44-4C2E-87DF-2938738A5215}')
# print("Capturing packets...")
# for packet in capture.sniff_continuously(packet_count=20):
#     feature_data = extract_features(packet)
#     if feature_data:
#         print(feature_data)
#         try:
#             json_data = json.dumps(feature_data)  # Convert to JSON
#             sock.sendall(json_data.encode() + b"\n")  # Send JSON over socket
#         except Exception as e:
#             print(f"Error sending data: {e}")
#             break

# sock.close()

# __________________________ uncomment above code________________________________ 


# # Track session-based data for aggregation
# session_data = defaultdict(lambda: {
#     'count': 0, 'srv_count': 0, 'serror_rate': 0, 'srv_serror_rate': 0,
#     'rerror_rate': 0, 'srv_rerror_rate': 0, 'same_srv_rate': 0, 'diff_srv_rate': 0,
#     'srv_diff_host_rate': 0, 'dst_host_count': 0, 'dst_host_srv_count': 0,
#     'dst_host_same_srv_rate': 0, 'dst_host_diff_srv_rate': 0,
#     'dst_host_same_src_port_rate': 0, 'dst_host_srv_diff_host_rate': 0,
#     'dst_host_serror_rate': 0, 'dst_host_srv_serror_rate': 0,
#     'dst_host_rerror_rate': 0, 'dst_host_srv_rerror_rate': 0
# })

# # Extract packet features
# def extract_features(pkt):
#     try:
#         # Extract basic properties
#         src_ip = pkt.ip.src if hasattr(pkt, 'ip') else '0.0.0.0'
#         dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else '0.0.0.0'
#         protocol_type = pkt.transport_layer if hasattr(pkt, 'transport_layer') else 'unknown'
#         service = pkt.highest_layer.lower() if hasattr(pkt, 'highest_layer') else 'unknown'
        
#         # Extract TCP/UDP port numbers
#         src_port, dst_port = '0', '0'
#         if hasattr(pkt, 'tcp') or hasattr(pkt, 'udp'):
#             src_port = pkt[pkt.transport_layer].srcport
#             dst_port = pkt[pkt.transport_layer].dstport
        
#         # Extract TCP flag safely
#         flag = pkt.tcp.flags if hasattr(pkt, 'tcp') else 'N/A'

#         # Packet size
#         src_bytes = int(pkt.length) if hasattr(pkt, 'length') else 0

#         # Identify session
#         session_key = (src_ip, dst_ip, src_port, dst_port)
#         session = session_data[session_key]

#         # Compute session-based features
#         session['count'] += 1
#         session['srv_count'] += 1
#         session['same_srv_rate'] = session['srv_count'] / session['count'] if session['count'] else 0
#         session['diff_srv_rate'] = 1 - session['same_srv_rate']

#         # TCP error tracking
#         if protocol_type == 'tcp' and flag in ['S0', 'S1', 'REJ']:
#             session['serror_rate'] = (session['serror_rate'] * (session['count'] - 1) + 1) / session['count']
#             session['srv_serror_rate'] = session['serror_rate']
        
#         # Destination-based tracking
#         session['dst_host_count'] += 1
#         session['dst_host_srv_count'] += 1 if service else 0
#         session['dst_host_same_srv_rate'] = session['dst_host_srv_count'] / session['dst_host_count']
#         session['dst_host_diff_srv_rate'] = 1 - session['dst_host_same_srv_rate']

#         # Construct output
#         extracted_data = {
#             'timestamp': time.time(),
#             'protocol_type': protocol_type,
#             'service': service,
#             'flag': flag,
#             'src_bytes': src_bytes,
#             'dst_bytes': 0,
#             'land': 1 if src_ip == dst_ip and src_port == dst_port else 0,
#             'wrong_fragment': int(pkt.ip.frag_offset) if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'frag_offset') else 0,
#             'urgent': int(pkt.tcp.urgent_pointer) if hasattr(pkt, 'tcp') and hasattr(pkt, 'tcp.urgent_pointer') else 0,
#             **session  # Merge session-based computed values
#         }

#         return extracted_data
#     except Exception as e:
#         print(f"Error processing packet: {e}")
#         return None



# ___________________________________________________________________________________________________________
import pyshark
from collections import defaultdict
import time
import socket
import json

# Server settings
SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

# Connect to the server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((SERVER_IP, SERVER_PORT))

# Track session-based data
session_data = defaultdict(lambda: {
    'count': 0, 'srv_count': 0, 'serror_rate': 0, 'srv_serror_rate': 0,
    'rerror_rate': 0, 'srv_rerror_rate': 0, 'same_srv_rate': 0, 'diff_srv_rate': 0,
    'srv_diff_host_rate': 0, 'dst_host_count': 0, 'dst_host_srv_count': 0,
    'dst_host_same_srv_rate': 0, 'dst_host_diff_srv_rate': 0,
    'dst_host_same_src_port_rate': 0, 'dst_host_srv_diff_host_rate': 0,
    'dst_host_serror_rate': 0, 'dst_host_srv_serror_rate': 0,
    'dst_host_rerror_rate': 0, 'dst_host_srv_rerror_rate': 0
})

# Map common service ports
def map_service(port):
    common_services = {
        '80': 'http',
        '443': 'https',
        '21': 'ftp',
        '22': 'ssh',
        '23': 'telnet',
        '25': 'smtp',
        '53': 'domain',
        '110': 'pop_3',
        '143': 'imap',
        '513': 'remote_job',
        '514': 'private',
    }
    return common_services.get(str(port), 'private')

# Convert TCP flags to symbols
def get_flag_symbol(flags_hex):
    flag_map = {
        '0x0002': 'S0',   # SYN
        '0x0010': 'REJ',  # ACK only
        '0x0012': 'SF',   # SYN + ACK
    }
    return flag_map.get(flags_hex, 'OTH')

# Feature extraction function
def extract_features(pkt):
    try:
        src_ip = pkt.ip.src if hasattr(pkt, 'ip') else '0.0.0.0'
        dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else '0.0.0.0'
        protocol_type = pkt.transport_layer if hasattr(pkt, 'transport_layer') else 'unknown'

        src_port = dst_port = '0'
        if protocol_type in ['TCP', 'UDP']:
            src_port = pkt[protocol_type].srcport
            dst_port = pkt[protocol_type].dstport

        service = map_service(dst_port)
        flag = get_flag_symbol(pkt.tcp.flags) if protocol_type == 'TCP' and hasattr(pkt, 'tcp') else 'OTH'

        src_bytes = int(pkt.length) if hasattr(pkt, 'length') else 0
        land = 1 if src_ip == dst_ip and src_port == dst_port else 0
        wrong_fragment = int(pkt.ip.frag_offset) if hasattr(pkt.ip, 'frag_offset') else 0
        urgent = int(pkt.tcp.urgent_pointer) if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'urgent_pointer') else 0

        session_key = (src_ip, dst_ip, src_port, dst_port)
        session = session_data[session_key]
        session['count'] += 1
        session['srv_count'] += 1
        session['same_srv_rate'] = session['srv_count'] / session['count'] if session['count'] else 0
        session['diff_srv_rate'] = 1 - session['same_srv_rate']

        if protocol_type == 'TCP' and flag in ['S0', 'S1', 'REJ']:
            session['serror_rate'] = (session['serror_rate'] * (session['count'] - 1) + 1) / session['count']
            session['srv_serror_rate'] = session['serror_rate']

        session['dst_host_count'] += 1
        session['dst_host_srv_count'] += 1
        session['dst_host_same_srv_rate'] = session['dst_host_srv_count'] / session['dst_host_count']
        session['dst_host_diff_srv_rate'] = 1 - session['dst_host_same_srv_rate']

        # Final feature vector
        features = {
            'duration': time.time(),
            'protocol_type': protocol_type.lower(),
            'service': service,
            'flag': flag,
            'src_bytes': src_bytes,
            'dst_bytes': 0,
            'land': land,
            'wrong_fragment': wrong_fragment,
            'urgent': urgent,
            'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
            'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
            'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0,
            **session
        }

        return features
    except Exception as e:
        print(f"Error processing packet: {e}")
        return None

# Start live capture
# capture = pyshark.LiveCapture(interface='\\Device\\NPF_{ADF2B56F-2F44-4C2E-87DF-2938738A5215}')
capture = pyshark.LiveCapture(interface='\\Device\\NPF_{B9562CBB-B385-4841-A1B4-2DFA70DA22B9}')  # Wi-Fi
print("Capturing packets...")
try:
    for pkt in capture.sniff_continuously(packet_count=20):
        feature_data = extract_features(pkt)
        if feature_data:
            print(feature_data)
            try:
                json_data = json.dumps(feature_data)
                sock.sendall(json_data.encode() + b"\n")
            except Exception as e:
                print(f"Error sending data: {e}")
                break
finally:
    sock.close()
    print("Socket closed. Capture complete.")





