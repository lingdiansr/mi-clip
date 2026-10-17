"""Synthetic UDP peer only: no real device, account or network capture."""
import pathlib
import socket
import struct
import subprocess
import sys
import threading

binary = pathlib.Path(sys.argv[1]).resolve()

def varint(n):
    value = bytearray()
    while n > 127:
        value.append((n & 127) | 128)
        n >>= 7
    value.append(n)
    return bytes(value)

def message(field, body):
    return varint(field * 8 + 2) + varint(len(body)) + body

def segment(sequence, fragment, body):
    return struct.pack('<IBBHIIII', 0x12345678, 81, fragment, 128, 123, sequence, 1, len(body)) + body

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(('127.0.0.1', 0))
server.settimeout(8)
errors = []

def peer():
    try:
        packet, address = server.recvfrom(65535)
        assert struct.unpack_from('<I', packet)[0] == 0x12345678
        assert packet[4] == 81 and packet[24:26] == bytes([9, 4])
        assert int.from_bytes(packet[26:28], 'big') == len(packet) - 24
        # Structurally valid synthetic phone information, including Unicode.
        info = bytes([40, 1]) + message(6, '测试手机'.encode())
        physical = bytes([16, 2]) + message(4, message(2, info))
        body = message(2, message(2, physical))
        frame = bytes([9, 4]) + (len(body) + 4).to_bytes(2, 'big') + body
        midpoint = len(frame) // 2
        server.sendto(b'not-a-KCP-packet', address)
        server.sendto(segment(1, 0, frame[midpoint:]), address)
        server.sendto(segment(0, 1, frame[:midpoint]), address)
        while True:
            ack, _ = server.recvfrom(65535)
            if len(ack) >= 24 and ack[4] == 82 and struct.unpack_from('<I', ack, 16)[0] == 2:
                break
    except BaseException as error:
        errors.append(error)

worker = threading.Thread(target=peer)
worker.start()
process = subprocess.run([str(binary), '--probe', '127.0.0.1', str(server.getsockname()[1])], capture_output=True, text=True, timeout=10)
worker.join(timeout=10)
server.close()
assert not worker.is_alive() and not errors, errors
assert process.returncode == 0, process.stderr
assert 'negotiation passed' in process.stdout
assert '127.0.0.1' not in process.stdout and '测试手机' not in process.stdout
print('PASS: Rust UDP negotiation, malformed datagram rejection, out-of-order fragments, cumulative ACK, no device metadata in output')
