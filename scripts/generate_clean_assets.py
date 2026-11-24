import zlib
import struct
from collections import deque
import math

def read_png(path):
    with open(path, 'rb') as f:
        data = f.read()
    w = int.from_bytes(data[16:20], 'big')
    h = int.from_bytes(data[20:24], 'big')
    idat = b''
    idx = 8
    while idx < len(data):
        length = int.from_bytes(data[idx:idx+4], 'big')
        ctype = data[idx+4:idx+8]
        if ctype == b'IDAT':
            idat += data[idx+8:idx+8+length]
        idx += 12 + length
    raw = zlib.decompress(idat)
    stride = 1 + w * 4
    pixels = []
    for y in range(h):
        row = []
        line = raw[y*stride+1 : (y+1)*stride]
        for x in range(w):
            row.append(list(line[x*4 : x*4+4]))
        pixels.append(row)
    return w, h, pixels

def write_png_rgba(w, h, pixels):
    raw_out = bytearray()
    for y in range(h):
        raw_out.append(0) # filter type 0
        for x in range(w):
            raw_out.extend(pixels[y][x])
    compressed = zlib.compress(bytes(raw_out), 9)

    def make_chunk(ctype, cdata):
        return struct.pack('>I', len(cdata)) + ctype + cdata + struct.pack('>I', zlib.crc32(ctype + cdata) & 0xffffffff)

    png_data = b'\x89PNG\r\n\x1a\n'
    ihdr = struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)
    png_data += make_chunk(b'IHDR', ihdr)
    png_data += make_chunk(b'IDAT', compressed)
    png_data += make_chunk(b'IEND', b'')
    return png_data

def resample_image(pixels, orig_w, orig_h, new_w, new_h):
    new_pixels = []
    x_ratio = orig_w / new_w
    y_ratio = orig_h / new_h
    for ny in range(new_h):
        row = []
        for nx in range(new_w):
            # Area-averaging box filter
            src_x0 = nx * x_ratio
            src_x1 = (nx + 1) * x_ratio
            src_y0 = ny * y_ratio
            src_y1 = (ny + 1) * y_ratio

            x_start = max(0, int(math.floor(src_x0)))
            x_end = min(orig_w, int(math.ceil(src_x1)))
            y_start = max(0, int(math.floor(src_y0)))
            y_end = min(orig_h, int(math.ceil(src_y1)))

            total_weight = 0.0
            r_acc, g_acc, b_acc, a_acc = 0.0, 0.0, 0.0, 0.0
            for sy in range(y_start, y_end):
                y_weight = min(sy + 1, src_y1) - max(sy, src_y0)
                for sx in range(x_start, x_end):
                    x_weight = min(sx + 1, src_x1) - max(sx, src_x0)
                    weight = x_weight * y_weight
                    pix = pixels[sy][sx]
                    alpha = pix[3] / 255.0
                    r_acc += pix[0] * alpha * weight
                    g_acc += pix[1] * alpha * weight
                    b_acc += pix[2] * alpha * weight
                    a_acc += pix[3] * weight
                    total_weight += weight

            if total_weight > 0 and a_acc > 0:
                final_a = a_acc / total_weight
                norm_a = final_a / 255.0
                if norm_a > 0.001:
                    final_r = min(255, max(0, int(round((r_acc / total_weight) / norm_a))))
                    final_g = min(255, max(0, int(round((g_acc / total_weight) / norm_a))))
                    final_b = min(255, max(0, int(round((b_acc / total_weight) / norm_a))))
                else:
                    final_r, final_g, final_b = 0, 0, 0
                row.append([final_r, final_g, final_b, min(255, max(0, int(round(final_a))))])
            else:
                row.append([0, 0, 0, 0])
        new_pixels.append(row)
    return new_pixels

def create_ico(resolutions_dict):
    """
    Constructs a valid Windows .ico file containing standard DIB entries and a 256x256 PNG.
    resolutions_dict: {size: (pixels_grid, png_bytes or None)}
    """
    entries = []
    image_blobs = []
    
    sizes = sorted(resolutions_dict.keys())
    header = struct.pack('<HHH', 0, 1, len(sizes))

    # Calculate offset after directory
    # Each directory entry is 16 bytes
    cur_offset = 6 + len(sizes) * 16

    for s in sizes:
        grid = resolutions_dict[s]
        if s == 256:
            # Store as PNG
            png_bytes = write_png_rgba(256, 256, grid)
            b_width = 0
            b_height = 0
            blob = png_bytes
        else:
            # Standard uncompressed Windows 32-bit BMP/DIB (bottom-up BGRA + 1bpp mask)
            b_width = s
            b_height = s
            
            # BITMAPINFOHEADER (40 bytes)
            # biHeight is s * 2 (color image + AND mask)
            header_bytes = struct.pack('<IIIHHIIIIII',
                40,             # biSize
                s,              # biWidth
                s * 2,          # biHeight
                1,              # biPlanes
                32,             # biBitCount
                0,              # biCompression (BI_RGB)
                s * s * 4,      # biSizeImage
                0, 0, 0, 0
            )
            # Pixel data (bottom-up, BGRA)
            pixel_bytes = bytearray()
            for y in reversed(range(s)):
                for x in range(s):
                    r, g, b, a = grid[y][x]
                    pixel_bytes.extend([b, g, r, a])
            
            # AND mask (1 bit per pixel, bottom-up, rows padded to 32-bit boundary)
            mask_row_bytes = (s + 31) // 32 * 4
            mask_bytes = bytearray(mask_row_bytes * s) # all zeroes = opaque/use alpha channel
            for y in reversed(range(s)):
                row_offset = (s - 1 - y) * mask_row_bytes
                for x in range(s):
                    if grid[y][x][3] < 128:
                        byte_idx = row_offset + (x // 8)
                        bit_idx = 7 - (x % 8)
                        mask_bytes[byte_idx] |= (1 << bit_idx)

            blob = header_bytes + bytes(pixel_bytes) + bytes(mask_bytes)

        image_blobs.append(blob)
        dir_entry = struct.pack('<BBBBHHII',
            b_width,
            b_height,
            0,          # color palette
            0,          # reserved
            1,          # color planes
            32,         # bits per pixel
            len(blob),  # size of resource
            cur_offset  # offset
        )
        entries.append(dir_entry)
        cur_offset += len(blob)

    ico_data = header + b''.join(entries) + b''.join(image_blobs)
    return ico_data

def main():
    print("[*] Extracting original emblem from git history...")
    w, h, pixels = read_png("target/logo_f753f34.png")

    # 1. Flood fill background to transparent
    visited = set()
    q = deque()
    for x in range(w):
        for y in [0, h-1]:
            visited.add((x, y))
            q.append((x, y))
    for y in range(h):
        for x in [0, w-1]:
            if (x, y) not in visited:
                visited.add((x, y))
                q.append((x, y))

    bg_r, bg_g, bg_b = 172, 177, 186
    while q:
        x, y = q.popleft()
        r, g, b, a = pixels[y][x]
        dist = abs(r - bg_r) + abs(g - bg_g) + abs(b - bg_b)
        if dist < 65:
            pixels[y][x][3] = 0
            for dx, dy in [(-1,0), (1,0), (0,-1), (0,1)]:
                nx, ny = x+dx, y+dy
                if 0 <= nx < w and 0 <= ny < h and (nx, ny) not in visited:
                    visited.add((nx, ny))
                    q.append((nx, ny))

    # Bounding box of visible emblem
    min_x, max_x = w, 0
    min_y, max_y = h, 0
    for y in range(h):
        for x in range(w):
            if pixels[y][x][3] > 0:
                if x < min_x: min_x = x
                if x > max_x: max_x = x
                if y < min_y: min_y = y
                if y > max_y: max_y = y

    crop_w = max_x - min_x + 1
    crop_h = max_y - min_y + 1

    cropped = []
    for y in range(min_y, max_y + 1):
        row = []
        for x in range(min_x, max_x + 1):
            row.append(pixels[y][x])
        cropped.append(row)

    print(f"[*] Cropped emblem size: {crop_w}x{crop_h}")

    # Scale emblem to fit comfortably within 256x256 with 12px margin on all sides (232x232 target box)
    target_box = 232
    scale = min(target_box / crop_w, target_box / crop_h)
    fit_w = int(round(crop_w * scale))
    fit_h = int(round(crop_h * scale))

    print(f"[*] Resampling emblem to fit 256x256: {fit_w}x{fit_h}...")
    scaled_emblem = resample_image(cropped, crop_w, crop_h, fit_w, fit_h)

    # Place centered into 256x256 canvas
    canvas_256 = [[[0, 0, 0, 0] for _ in range(256)] for _ in range(256)]
    start_x = (256 - fit_w) // 2
    start_y = (256 - fit_h) // 2
    for y in range(fit_h):
        for x in range(fit_w):
            canvas_256[start_y + y][start_x + x] = scaled_emblem[y][x]

    # Save clean 256x256 logo.png
    png_256 = write_png_rgba(256, 256, canvas_256)
    with open("assets/logo.png", "wb") as f:
        f.write(png_256)
    with open("logo-removebg-preview.png", "wb") as f:
        f.write(png_256)
    print(f"[✔] Generated assets/logo.png (256x256, {len(png_256)} bytes)")

    # Generate multi-resolution icons for Windows ICO and Linux
    sizes = [16, 24, 32, 48, 64, 128, 256]
    resolutions = {}
    for s in sizes:
        if s == 256:
            resolutions[256] = canvas_256
        else:
            print(f"[*] Resampling for {s}x{s} icon...")
            resolutions[s] = resample_image(canvas_256, 256, 256, s, s)

    ico_data = create_ico(resolutions)
    with open("assets/icon.ico", "wb") as f:
        f.write(ico_data)
    print(f"[✔] Generated assets/icon.ico ({len(ico_data)} bytes, {len(sizes)} resolutions)")

    # Also save Linux hicolor PNGs into target/linux_icons/
    import os
    os.makedirs("target/linux_icons", exist_ok=True)
    for s in sizes:
        p_bytes = write_png_rgba(s, s, resolutions[s])
        with open(f"target/linux_icons/sentient_{s}x{s}.png", "wb") as f:
            f.write(p_bytes)
    print("[✔] Generated Linux hicolor icon set in target/linux_icons/")

if __name__ == '__main__':
    main()
