import struct
from config import MAX_MESSAGE_SIZE


def pack(message : bytes) -> bytes:
    header = struct.pack("!I", len(message))
    return header + message

def split(buffer : bytes) -> tuple[list[bytes], bytes]:
    message_list = []
    while True:
        if (len(buffer)) < 4:
            break
        (message_len,) = struct.unpack("!I", buffer[:4])
        if message_len > MAX_MESSAGE_SIZE:
            raise ValueError(f"Message length ({message_len} bytes) exceeds of limit of {MAX_MESSAGE_SIZE} bytes!")
        
        if len(buffer) < 4 + message_len:
            break
        message = buffer[4:4 + message_len]
        message_list.append(message)
        buffer = buffer[4 + message_len:]
    return message_list, buffer