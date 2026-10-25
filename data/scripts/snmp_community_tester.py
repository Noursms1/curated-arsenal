import sys, json, socket, argparse, random, struct

def encode_length(length):
    if length < 0x80:
        return bytes([length])
    else:
        len_bytes = []
        while length:
            len_bytes.insert(0, length & 0xFF)
            length >>= 8
        return bytes([0x80 | len(len_bytes)] + len_bytes)

def encode_integer(value):
    # Encode as signed integer
    if value == 0:
        content = b"\x00"
    else:
        # big‑endian, minimal length
        content = b""
        while value:
            content = bytes([value & 0xFF]) + content
            value >>= 8
        # if the highest bit is set, prepend 0x00 to indicate positive number
        if content[0] & 0x80:
            content = b"\x00" + content
    return b"\x02" + encode_length(len(content)) + content

def encode_octet_string(data: bytes):
    return b"\x04" + encode_length(len(data)) + data

def encode_null():
    return b"\x05\x00"

def encode_oid(oid_str: str):
    # OID like '1.3.6.1.2.1.1.1.0'
    parts = [int(p) for p in oid_str.split('.')]
    if len(parts) < 2:
        raise ValueError('Invalid OID')
    first_byte = 40 * parts[0] + parts[1]
    encoded = bytes([first_byte])
    for sub_id in parts[2:]:
        if sub_id < 0x80:
            encoded += bytes([sub_id])
        else:
            # base‑128 encoding
            sub_bytes = []
            while sub_id:
                sub_bytes.insert(0, (sub_id & 0x7F) | 0x80)
                sub_id >>= 7
            sub_bytes[-1] &= 0x7F  # clear MSB of last byte
            encoded += bytes(sub_bytes)
    return b"\x06" + encode_length(len(encoded)) + encoded

def build_snmp_get(community: str, request_id: int) -> bytes:
    # OID for sysDescr.0
    oid = encode_oid('1.3.6.1.2.1.1.1.0')
    varbind = b"\x30" + encode_length(len(oid) + len(encode_null())) + oid + encode_null()
    varbind_list = b"\x30" + encode_length(len(varbind)) + varbind
    pdu_body = (
        encode_integer(request_id) +
        encode_integer(0) +               # error-status
        encode_integer(0) +               # error-index
        varbind_list
    )
    pdu = b"\xA0" + encode_length(len(pdu_body)) + pdu_body
    version = encode_integer(0)  # SNMPv1
    community_enc = encode_octet_string(community.encode())
    message_body = version + community_enc + pdu
    message = b"\x30" + encode_length(len(message_body)) + message_body
    return message

def test_community(target_ip: str, community: str, timeout: float = 2.0) -> bool:
    request_id = random.randint(0, 0x7fffffff)
    packet = build_snmp_get(community, request_id)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (target_ip, 161))
            data, _ = sock.recvfrom(4096)
    except socket.timeout:
        return False
    except Exception:
        return False
    # Very basic validation: response must start with 0x30 (SEQUENCE)
    return data.startswith(b"\x30")

def main():
    parser = argparse.ArgumentParser(description='SNMP community string tester')
    parser.add_argument('target', help='IP address of the SNMP agent')
    parser.add_argument('communities', help='Comma‑separated list of community strings to test')
    args = parser.parse_args()

    target = args.target
    community_list = [c.strip() for c in args.communities.split(',') if c.strip()]
    valid = []
    for comm in community_list:
        if test_community(target, comm):
            valid.append(comm)
    result = {
        'target': target,
        'valid_communities': valid,
        'tested': len(community_list)
    }
    print(json.dumps(result, ensure_ascii=False))

if __name__ == '__main__':
    main()
