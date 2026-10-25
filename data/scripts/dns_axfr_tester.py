import sys
import socket
import struct
import random
import json
import base64

def build_axfr_query(domain):
    """يبني طلب DNS من نوع AXFR للـ domain المحدد"""
    # Header: ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    tx_id = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query
    header = struct.pack('!HHHHHH', tx_id, flags, 1, 0, 0, 0)
    # Question section
    qname = b''.join(bytes([len(label)]) + label.encode() for label in domain.split('.')) + b'\x00'
    qtype = 252  # AXFR
    qclass = 1   # IN
    question = qname + struct.pack('!HH', qtype, qclass)
    return header + question

def send_axfr(nameserver, domain, timeout=10):
    query = build_axfr_query(domain)
    # TCP DNS messages are prefixed with two-byte length
    msg = struct.pack('!H', len(query)) + query
    with socket.create_connection((nameserver, 53), timeout=timeout) as sock:
        sock.sendall(msg)
        data = b''
        while True:
            # read length prefix
            length_bytes = sock.recv(2)
            if not length_bytes:
                break
            (length,) = struct.unpack('!H', length_bytes)
            chunk = b''
            while len(chunk) < length:
                part = sock.recv(length - len(chunk))
                if not part:
                    break
                chunk += part
            if not chunk:
                break
            data += chunk
            # AXFR ends with a second message containing the original query ID
            if len(chunk) >= 12:
                resp_id = struct.unpack('!H', chunk[:2])[0]
                if resp_id == struct.unpack('!H', query[:2])[0] and len(data) > len(query):
                    # received the final empty SOA record – stop reading
                    break
        return data

def parse_response(raw):
    if not raw:
        return {"status": "failure", "reason": "No data received"}
    # Check RCODE in header (last 4 bits of flags)
    flags = struct.unpack('!H', raw[2:4])[0]
    rcode = flags & 0x000F
    if rcode != 0:
        return {"status": "failure", "reason": f"RCODE {rcode}"}
    # Return base64 of the raw zone data for inspection
    return {"status": "success", "zone_base64": base64.b64encode(raw).decode()}

def main():
    if len(sys.argv) != 3:
        sys.stderr.write('Usage: python dns_axfr_tester.py <nameserver_ip> <domain>\n')
        sys.exit(1)
    nameserver = sys.argv[1]
    domain = sys.argv[2]
    try:
        raw = send_axfr(nameserver, domain)
        result = parse_response(raw)
    except Exception as e:
        result = {"status": "error", "reason": str(e)}
    output = {
        "target": nameserver,
        "domain": domain,
        "result": result
    }
    print(json.dumps(output, ensure_ascii=False))

if __name__ == '__main__':
    main()
