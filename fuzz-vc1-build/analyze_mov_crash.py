import struct
import sys

data = open('../fuzz-corpus-mov/crash_1.bin', 'rb').read()
print(f'File size: {len(data)} bytes')
print(f'MOV data: {len(data)-2048} bytes')

# Config区 (倒数2048-1024字节)
config = data[-2048:-1024]
io_buf_size = struct.unpack('<I', config[0:4])[0]
flags = config[4]
filesize = struct.unpack('<Q', config[12:20])[0]
interrupt_ctr = struct.unpack('<I', config[20:24])[0]
print(f'io_buffer_size: {io_buf_size}')
print(f'flags: 0x{flags:02x} (seekable={bool(flags&1)})')
print(f'filesize: {filesize}')
print(f'interrupt_counter: {interrupt_ctr}')

# Filename区 (最后1024字节)
filename = data[-1024:]
fn_str = filename.split(b'\x00')[0].decode('ascii', errors='replace')
print(f'filename: {repr(fn_str)}')

# MOV数据前128字节hex
mov_data = data[:-2048]
print(f'\nMOV data first 128 bytes hex:')
for i in range(0, min(128, len(mov_data)), 16):
    hex_str = ' '.join(f'{b:02x}' for b in mov_data[i:i+16])
    ascii_str = ''.join(chr(b) if 32<=b<127 else '.' for b in mov_data[i:i+16])
    print(f'  {i:04x}: {hex_str}  {ascii_str}')

# 检查atom结构
print(f'\nAtom structure:')
pos = 0
while pos < len(mov_data) - 8:
    atom_size = struct.unpack('>I', mov_data[pos:pos+4])[0]
    atom_type = mov_data[pos+4:pos+8].decode('ascii', errors='replace')
    print(f'  Atom at {pos}: type={atom_type} size={atom_size}')
    if atom_size < 8 or pos + atom_size > len(mov_data):
        print(f'    [INVALID: truncated or corrupt]')
        break
    pos += atom_size