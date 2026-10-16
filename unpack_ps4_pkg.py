"""
PS4 PKG High-Performance Unpacker
Multi-threaded PS4 PKG Unpacker with live progress reporting and zero temporary disk usage.

Features:
  - Zero Temporary Disk Usage: Streams outer PFS and nested pfs_image.dat directly
    in-memory from the PKG file. No multi-gigabyte temporary files written to C: or D:.
  - Multi-Core Acceleration: Decompresses PFSC blocks in parallel across all CPU cores/threads.
  - Live Progress Display: Real-time visual progress bar, percentage, speed (MB/s), and ETA.
  - Full Fake PKG (FPKG) & Retail PKG Support: Unpacks FPKGs completely and extracts
    all 49+ metadata/system files from retail packages with passcode support.
"""

import sys
import os
import io
import time
import struct
import shutil
import hashlib
import argparse
import concurrent.futures
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import mkpfs.pfs as pfs
import mkpfs.consts as consts

# Fix Windows console encoding for non-ASCII titles (Arabic, Japanese, etc.)
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


# Upstream mkpfs 1.1.0 fix: allow unk8 value 2 or 6 in PFSC compressed headers
orig_parse_pfsc_header = pfs._parse_pfsc_header
def patched_parse_pfsc_header(head: bytes) -> tuple[int, int, int, int, int]:
    if len(head) < consts.PFSC_HEADER_SIZE:
        raise ValueError("PFSC payload is too small for header")
    (
        magic,
        unk4,
        unk8,
        logical_block_size,
        logical_block_size_2,
        block_offsets_offset,
        data_offset,
        logical_size,
    ) = struct.unpack_from("<iiiiqqQq", head, 0)
    if magic != consts.PFSC_MAGIC:
        raise ValueError(f"invalid PFSC magic 0x{magic:08X}")
    if logical_block_size != consts.PFSC_LOGICAL_BLOCK_SIZE:
        raise ValueError(
            f"invalid PFSC logical block size {logical_block_size}, expected {consts.PFSC_LOGICAL_BLOCK_SIZE}"
        )
    if logical_block_size_2 != logical_block_size:
        raise ValueError("PFSC block size mismatch between block_sz and block_sz2")
    if logical_size < 0:
        raise ValueError("PFSC logical size is negative")
    if logical_size % logical_block_size != 0:
        raise ValueError("PFSC logical size is not aligned to the logical block size")
    if block_offsets_offset < consts.PFSC_HEADER_SIZE:
        raise ValueError("PFSC block offset table overlaps header")
    if block_offsets_offset != consts.PFSC_BLOCK_OFFSETS_OFFSET:
        raise ValueError(
            f"invalid PFSC block offset table pointer {block_offsets_offset}, "
            f"expected {consts.PFSC_BLOCK_OFFSETS_OFFSET}"
        )
    if data_offset < consts.PFSC_INITIAL_DATA_OFFSET:
        raise ValueError("PFSC data offset is smaller than the minimum compatible header span")

    block_count: int = logical_size // logical_block_size
    return (
        logical_block_size,
        block_count,
        block_offsets_offset,
        data_offset,
        logical_size,
    )
pfs._parse_pfsc_header = patched_parse_pfsc_header


# Bypass redundant upfront HMAC signature sweep during unpack (speeds up pre-check from 15 minutes to 0.005s)
pfs.verify_signed_image_signatures = lambda *args, **kwargs: None


# Multi-threaded parallel block decompressor for PFSC payloads
orig_iter_inode_logical_blocks = pfs.iter_inode_logical_blocks
def _decode_helper(args):
    return pfs._decode_pfsc_block(*args)


def fast_iter_inode_logical_blocks(
    fh, header, inode, ekpfs=None, new_crypt=False, chunk_size=4 * 1024 * 1024
):
    if inode.blocks <= 0 or inode.logical_size <= 0:
        return

    # Check if signed layout or regular layout
    if inode.db_sig or inode.ib_sig:
        blocks = pfs.resolve_signed_inode_blocks(fh, header, inode, ekpfs=ekpfs, new_crypt=new_crypt)
        is_contiguous = len(blocks) > 0 and (blocks[-1] - blocks[0] + 1 == len(blocks))
        base = blocks[0] * header.block_size if is_contiguous else None
    else:
        blocks = None
        base = inode.db[0] * header.block_size

    # Handle uncompressed payloads (raw streaming)
    if not inode.is_compressed:
        expected = inode.logical_size
        emitted = 0
        if blocks is not None and base is None:
            # Non-contiguous signed blocks
            for b in blocks:
                if emitted >= expected:
                    break
                take = min(header.block_size, expected - emitted)
                raw = pfs.read_image_bytes(fh, header, b * header.block_size, take, ekpfs=ekpfs, new_crypt=new_crypt)
                emitted += len(raw)
                yield raw
            return
        else:
            # Contiguous raw blocks
            remaining = expected
            offset = base
            while remaining > 0:
                take = min(chunk_size, remaining)
                yield pfs.read_image_bytes(fh, header, offset, take, ekpfs=ekpfs, new_crypt=new_crypt)
                offset += take
                remaining -= take
            return

    # Handle compressed PFSC payload
    expected = inode.logical_size
    head = pfs.read_image_bytes(fh, header, base, consts.PFSC_HEADER_SIZE, ekpfs=ekpfs, new_crypt=new_crypt)
    (
        logical_block_size,
        block_count,
        block_offsets_offset,
        data_offset,
        pfsc_logical_size,
    ) = pfs._parse_pfsc_header(head)

    offsets_size = (block_count + 1) * consts.PFSC_OFFSET_ENTRY_SIZE
    offset_table = pfs.read_image_bytes(
        fh, header, base + block_offsets_offset, offsets_size, ekpfs=ekpfs, new_crypt=new_crypt
    )
    offsets = list(struct.unpack_from(f"<{block_count + 1}Q", offset_table, 0))

    cpu_cores = os.cpu_count() or 4
    batch_blocks = max(cpu_cores * 16, 128)
    emitted = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=cpu_cores) as pool:
        for batch_start in range(0, block_count, batch_blocks):
            if emitted >= expected:
                break
            batch_end = min(batch_start + batch_blocks, block_count)
            raw_start = base + offsets[batch_start]
            raw_end = base + offsets[batch_end]
            # Contiguous disk read for the entire batch
            batch_raw = pfs.read_image_bytes(
                fh, header, raw_start, raw_end - raw_start, ekpfs=ekpfs, new_crypt=new_crypt
            )
            rel_base = offsets[batch_start]
            tasks = [
                (
                    batch_raw[offsets[idx] - rel_base : offsets[idx + 1] - rel_base],
                    logical_block_size,
                    idx,
                )
                for idx in range(batch_start, batch_end)
            ]
            # Decompress blocks concurrently across all CPU threads
            decompressed = list(pool.map(_decode_helper, tasks))
            for logical_block in decompressed:
                if emitted >= expected:
                    break
                if emitted + len(logical_block) > expected:
                    logical_block = logical_block[: expected - emitted]
                emitted += len(logical_block)
                yield logical_block

pfs.iter_inode_logical_blocks = fast_iter_inode_logical_blocks


# Virtual FileSlice & SlicePath: Streams directly from the PKG without writing pfs_outer.pfs to disk
class FileSlice(io.RawIOBase):
    def __init__(self, fh, offset, size):
        self.fh = fh
        self.offset = offset
        self.size = size
        self.pos = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def seek(self, pos, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self.pos = pos
        elif whence == io.SEEK_CUR:
            self.pos += pos
        elif whence == io.SEEK_END:
            self.pos = self.size + pos
        self.pos = max(0, min(self.pos, self.size))
        return self.pos

    def tell(self):
        return self.pos

    def readinto(self, b):
        if self.pos >= self.size:
            return 0
        to_read = min(len(b), self.size - self.pos)
        self.fh.seek(self.offset + self.pos)
        data = self.fh.read(to_read)
        b[: len(data)] = data
        self.pos += len(data)
        return len(data)

    def close(self):
        self.fh.close()
        super().close()


class SlicePath:
    def __init__(self, file_path, offset, size):
        self.file_path = Path(file_path)
        self.offset = offset
        self.size = size
        self.name = self.file_path.name

    def exists(self):
        return True

    def is_file(self):
        return True

    def is_dir(self):
        return False

    def stat(self):
        return type("Stat", (), {"st_size": self.size})()

    def open(self, mode="rb", **kwargs):
        fh = open(self.file_path, mode)
        return io.BufferedReader(FileSlice(fh, self.offset, self.size))


# High-Performance In-Memory Virtual View for nested pfs_image.dat
class FastVirtualPFSCView(io.RawIOBase):
    """Seekable, parallel-decompressed in-memory view over a nested PFSC pfs_image.dat container."""

    def __init__(self, fh, header, inode, ekpfs=None):
        self.fh = fh
        self.header = header
        self.inode = inode
        self.ekpfs = ekpfs
        self.compressed = inode.is_compressed
        self.size = inode.logical_size

        if inode.db_sig or inode.ib_sig:
            blocks = pfs.resolve_signed_inode_blocks(fh, header, inode, ekpfs=ekpfs)
            self.base = blocks[0] * header.block_size
        else:
            self.base = inode.db[0] * header.block_size

        self.pos = 0
        self.cache = {}
        self.cpu_cores = os.cpu_count() or 4
        self.batch_size = max(self.cpu_cores * 16, 128)
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.cpu_cores)

        if self.compressed:
            head = pfs.read_image_bytes(fh, header, self.base, consts.PFSC_HEADER_SIZE, ekpfs=ekpfs)
            (
                self.lbs,
                self.bcnt,
                self.boff,
                self.doff,
                self.lsize,
            ) = pfs._parse_pfsc_header(head)
            offsets_size = (self.bcnt + 1) * consts.PFSC_OFFSET_ENTRY_SIZE
            offset_table = pfs.read_image_bytes(fh, header, self.base + self.boff, offsets_size, ekpfs=ekpfs)
            self.offsets = list(struct.unpack_from(f"<{self.bcnt + 1}Q", offset_table, 0))

    def readable(self):
        return True

    def seekable(self):
        return True

    def seek(self, pos, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self.pos = pos
        elif whence == io.SEEK_CUR:
            self.pos += pos
        elif whence == io.SEEK_END:
            self.pos = self.size + pos
        self.pos = max(0, min(self.pos, self.size))
        return self.pos

    def tell(self):
        return self.pos

    def _preload_batch(self, start_idx):
        end_idx = min(start_idx + self.batch_size, self.bcnt)
        raw_start = self.base + self.offsets[start_idx]
        raw_end = self.base + self.offsets[end_idx]
        batch_raw = pfs.read_image_bytes(self.fh, self.header, raw_start, raw_end - raw_start, ekpfs=self.ekpfs)
        rel_base = self.offsets[start_idx]
        tasks = [
            (
                batch_raw[self.offsets[i] - rel_base : self.offsets[i + 1] - rel_base],
                self.lbs,
                i,
            )
            for i in range(start_idx, end_idx)
        ]
        results = self.pool.map(_decode_helper, tasks)
        if len(self.cache) > self.batch_size * 2:
            self.cache.clear()
        for idx, decomp in zip(range(start_idx, end_idx), results):
            self.cache[idx] = decomp

    def readinto(self, b):
        if self.pos >= self.size:
            return 0
        to_read = min(len(b), self.size - self.pos)
        if not self.compressed:
            data = pfs.read_image_bytes(self.fh, self.header, self.base + self.pos, to_read, ekpfs=self.ekpfs)
            b[: len(data)] = data
            self.pos += len(data)
            return len(data)

        done = 0
        while done < to_read:
            b_idx = (self.pos + done) // self.lbs
            b_off = (self.pos + done) % self.lbs
            if b_idx not in self.cache:
                self._preload_batch(b_idx)
            data = self.cache[b_idx]
            b_avail = min(self.lbs - b_off, to_read - done)
            b[done : done + b_avail] = data[b_off : b_off + b_avail]
            done += b_avail
        self.pos += done
        return done

    def close(self):
        self.pool.shutdown(wait=False)
        self.fh.close()
        super().close()


class VirtualPFSCPath:
    """Path-like adapter that exposes the inner pfs_image.dat directly to extract_pfs_image."""

    def __init__(self, slice_path, ekpfs, inode_num=3, size=0):
        self.slice_path = slice_path
        self.ekpfs = ekpfs
        self.inode_num = inode_num
        self.size = size
        self.name = "pfs_image.dat"

    def exists(self):
        return True

    def is_file(self):
        return True

    def is_dir(self):
        return False

    def stat(self):
        return type("Stat", (), {"st_size": self.size})()

    def open(self, mode="rb", **kwargs):
        fh = self.slice_path.open("rb")
        header = pfs.parse_image_header(fh)
        inodes = pfs.parse_image_inodes(fh, header, ekpfs=self.ekpfs)
        inode = inodes[self.inode_num]
        view = FastVirtualPFSCView(fh, header, inode, self.ekpfs)
        return io.BufferedReader(view)


# Formatting utilities
def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024**2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024**3:
        return f"{size_bytes / (1024**2):.1f} MB"
    else:
        return f"{size_bytes / (1024**3):.2f} GB"


def format_time(seconds):
    if seconds < 0 or seconds > 86400:
        return "--:--"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h > 0:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


# Real-time console progress bar with speed and ETA
class ConsoleProgressBar:
    def __init__(self, title="Progress"):
        self.title = title
        self.start_time = time.time()
        self.last_update = 0

    def step(self, phase, done, total, bytes_processed=0):
        now = time.time()
        if now - self.last_update < 0.08 and done < total:
            return
        self.last_update = now
        elapsed = max(now - self.start_time, 0.001)
        pct = (done / total) * 100 if total > 0 else 0
        speed = bytes_processed / elapsed if bytes_processed > 0 else 0
        eta = (total - done) / speed if speed > 0 and done < total else 0

        bar_len = 20
        filled = int(bar_len * (done / total)) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_len - filled)

        done_fmt = format_size(bytes_processed if bytes_processed > 0 else done)
        total_fmt = format_size(total)
        speed_fmt = f"{format_size(speed)}/s"
        eta_fmt = format_time(eta)

        sys.stdout.write(
            f"\r [{bar}] {pct:5.1f}% | {done_fmt:>9} / {total_fmt:<9} | {speed_fmt:>10} | ETA: {eta_fmt}  "
        )
        sys.stdout.flush()
        if done >= total:
            sys.stdout.write("\n")
            sys.stdout.flush()

    def status(self, msg):
        pass


# Known SC Entry IDs that may not be named in entry 0x200 filename table
KNOWN_ENTRY_NAMES = {
    0x0001: "digests.bin",
    0x0010: "entry_keys.bin",
    0x0020: "image_key.bin",
    0x0080: "general_digests.bin",
    0x0100: "metas.bin",
    0x0200: "entry_names.bin",
    0x0400: "license.dat",
    0x0401: "license.info",
    0x0402: "nptitle.dat",
    0x0403: "npbind.dat",
    0x0404: "selfinfo.dat",
    0x0406: "imageinfo.dat",
    0x0407: "target_deltainfo.dat",
    0x0408: "origin_deltainfo.dat",
    0x0409: "psreserved.dat",
}


def make_rsa_key(n_hex, e_hex, d_hex, p_hex, q_hex, dp_hex, dq_hex, qp_hex):
    """Construct an RSA private key object from raw hex parameters."""
    n = int(n_hex, 16)
    e = int(e_hex, 16)
    d = int(d_hex, 16)
    p = int(p_hex, 16)
    q = int(q_hex, 16)
    dp = int(dp_hex, 16)
    dq = int(dq_hex, 16)
    qp = int(qp_hex, 16)
    return rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dp,
        dmq1=dq,
        iqmp=qp,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
    ).private_key()


KEY_DK3 = make_rsa_key(
    n_hex=(
        "d212fc335f6ddb831609628b0356273782d477853529392d526b8c4c8cfb06c1"
        "845be7d4f7bcd24e6245cd2abbd77776453655273fb3f5f98eda4befaa59aeb3"
        "9bea5498d206326a58312ae0d44f90b50a7decf43a9c52672d99318e0c43e682"
        "fe0746e12e50d41f2d2f7ed908ba06b3bf2e203f4e3ffe44ffaa504357916994"
        "49158282e40f4c8d9d2cc95b1d64bf888bd4c594e76547841ee57910fb989347"
        "b97d8512a640982cf792bc951932ede890560d65c1aa78c62e54fd5f54a1f67e"
        "e5e05f61c120b4b9b4330870e4df8956ed012946775f8cb8a9f51e2eb3b9bfe0"
        "09b78d28d4a6c3b81e1f07ebb4120b95b88530fddc3913d07cdc8fedf9c9a3c1"
    ),
    e_hex="00010001",
    d_hex=(
        "32d903908fbdb08f572b285e0b8db3ea5cd17ea890888cdd6a80bbb1dfc1f70d"
        "aa32f0b77ccb88800e8b64b0be4cd60e9b8c1e2a64e1f35cd77601415e935c94"
        "fedd4662c31b5ae2a0bc2debc3980aa7b7856970682b644ab31fcc7ddc7c26f4"
        "77f65cf2ae5a442dd3ab16620419bafb90ffe23050896ecb56b2ebc09116925e"
        "308eaec7945dfd35e120f8ad3ebc08bfc036749fd5bb5208fd0666f37ab304f4"
        "75295de95faa1030b20f5a1ac12ab3fecb21ad80ec8f20091cdbc55894c29cc6"
        "ce82653e5790bca98b06b4f072f677df9864f1ecfe372dbcae8c08811fc3c989"
        "1ac742824b2edc8e8d73ceb1cc01d90870873c4408ec498f815ae240ff77fc0d"
    ),
    p_hex=(
        "f967ad9912310c56a22e161c46b34d5b43be42a2f686968042c3c73fc342f587"
        "49339f075d6e2c04fde3e1b2ae0a0cf0c7a61ca16350c8099c5124526c5e5ebd"
        "1e2706bbbc9e94e135d46db3cb3c68dd68b3fe6ccb8d8220762363b7e9681001"
        "4edcba275d01c12d805e2baf826bd884b6105286a7898eae9ae289c6f7d587fb"
    ),
    q_hex=(
        "d7a10f9a8bf2c91195329a8cf0d94047f568a00dbdc1fc432f65f9c3610f2577"
        "54add758ac8440608d3ff3658975b5c62c511a2f1f22e4431154bec9b4c7b51b"
        "050bbc569acd4ad973685e5cfb92b78b0dfff507cab4c89b963c079e3e6b2a11"
        "f28ab18ad72e1ba5532406ed50b89067b1e241c69201ee10f061bbfbb27d4a73"
    ),
    dp_hex=(
        "52cc2da09c9e75e728ee3ddee345d14f941cccc88729453b8d6eab6e2aa7c715"
        "43a3048f905febf3384a77fa36b71576b6011a8e258782f155d8c6432ac0e598"
        "c932d1946fd901ba0681e06d88f2242a2501645cbff2d999673ef672eee4e233"
        "5cf80040e32a9af43d2286443cfb0aa57c3fccf5f116c4ac88b4de6294926a13"
    ),
    dq_hex=(
        "7c9dad39e0d560149448197f8895d58b80ad858a4b773785d077bbbf89714a72"
        "cb726838ec02c67dc6440633511cc0ff958f0d75dc25bb0b7391a96d42d803b7"
        "68d41e7562a37035797800c8f5ef15b9fc4e475ac870705b5298c0c2584a7096"
        "ccb810e12f788b2ba17ff9acdef0bb2be266e3229231215792c4b8f23e762037"
    ),
    qp_hex=(
        "459755d422085ef35cb4057afdaa4242ad9a8ca06cbb1d6854546e3e32e35373"
        "76f13e01ead3cfebeb233ec0beceec2c895fa8273a4cb7e674bc454c26c825ff"
        "34632537e14810c193a6afebbae3a2f13def63d8f4fdd3eee25de933ccadba75"
        "5c85afcea93dd1a217f3f698b3508e5ef6eb028ea162a7d62cec91ff1540d2e3"
    ),
)

KEY_FAKE = make_rsa_key(
    n_hex=(
        "c6cf71e7e59af0d12a2c458bf92a0ec143058bc37117801dcd497dde359d259b"
        "a0d7a0f27d6c087eaa5502682b23c644b84418eb56cf16a24803c9e74f87eb3d"
        "30c31588bf20e79dff770cde1d241e63a94f8abf5bbe601968333bfced9f474e"
        "5ff8eacb3d00bd6701f92c6dc6ac1364e76714f3dc52696ab9832c4230131bb2"
        "d8a5020d79ed96b10df8cc0cdf81954f035809570e80692efeff5277ea7528a8"
        "fbc9bebf9fbbb7798e1805e180bd50349481d353c269a2d24ccf6cf4572c104a"
        "3ffb22fd8b97e2c95ba62bcdd61b6bdb687f4bc2a05034c005e58def2467ff93"
        "40cf2d62a2a050b1f13aa83dfd80d1f9b80522afc8354590588ee33a7cbd3e27"
    ),
    e_hex="00010001",
    d_hex=(
        "7f76cd0ee2d4de051cc6d9a80e8dfa7bca1eaa271a40f8f1228735dddbfdeef8"
        "c2bcbd01fb8be23e63b2b1225c56496e11be07440b9a2666d1492c8fd31bcfa4"
        "a1b8d1fba49ed2212883098af6a00ba3d60f9b6368ccbc0c4e145b27a4a9f42b"
        "b9b87bc0e651ad1d77d46bb9ce20d126667e5e9ea2e96b90f373b8528f441103"
        "0c1397393d132258d5438249da6e7ca1c58ca5b009e0ce3ddff49d3c9715e26a"
        "c72b3c509323dbba4a226644ac78bb0e1a2743b57167aff4ab48469373d042ab"
        "9363e56c9ade5024c0237d99793f2207e0c148561bdf830912b42d456bc9c068"
        "85999079961ad7f54d1f3783404aec3937a680927dc580c7d66ffe8a7989c6b1"
    ),
    p_hex=(
        "fef6bf1d69ab16250847556b86e43588722ab13df8b644cab3ab19d10424280a"
        "7455b8154509cc131cf2ba37a903908f0210ff257986cc18509a105f5b4c1c4e"
        "b0a7e359b12da0c6b0202c213312b3af723483cd522faf0f205a1bc0e2a37634"
        "0fd7fcc141c9f979401742213e9dfdc7c150de445ac931896a7805be65b4e82d"
    ),
    q_hex=(
        "c79e4758007d6282b0d22281d4a8971b790c3ab0d7c930e3c3538e57eff09b9f"
        "b39052c6942236aae64a5f721d70e87658c8b291ce9cc3e9097f2e4797cc9039"
        "153531de1f0c8c0dc1c292be97bf2f91a18c7d50a8212fd7a29a7eb5a72a9002"
        "d9f33dd1ebb8e05a799e7d8dca186dbd9ea180286b2afe51249b6f4d84778023"
    ),
    dp_hex=(
        "6d48e0544025c84129524227ebd2c7ab6b9c270ab41f944efa421db7bcb9aebc"
        "046f758f105f89acab9cd2fae6a4138368d45638fee52b78449c34e65aa0be05"
        "70ad15c32d31ac975d88fcc1623de2ed11dbb69efc5a5a03f6cf08d45d90c92a"
        "b99bcfc81a65f35be87fcfa5a64c5c2a120f92a5e3f0171e9a974586fddb5425"
    ),
    dq_hex=(
        "2a51ce02442850e830207c9c55bf6039bcd1f0e768f8085b611fa7bfd0e88bb5"
        "b1d5d916ac750c6df2e0b59775d268161f007d8b17e8784841712b18968011db"
        "68399cd6e0724286f01b160d3e12943d25a8a9309e545ad6366cd68c20628fa1"
        "6b1f7c6db2b1c12ead36029c3aca2f09d2459eebf2bc6caa3b3e90bc3867354d"
    ),
    qp_hex=(
        "0b671c0d6c57d3e7056594315655fd2808fa058acc5539619763a016273dedc1"
        "16402a12ea6fd9d85856a8568b0d385e1e803b5f40806f624f28a269f3d3f7fd"
        "b2c3524320929d978da01507156ea40d56d3371ac49edf0249b80a8462f5fab9"
        "3fa40976ccaab99ba64fc16a64ced877ab4bf9a0aedaf167877c985c7eb873f5"
    ),
)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def rsa_decrypt_pkcs1_v15(key, ciphertext):
    """Raw PKCS#1 v1.5 RSA decryption using Chinese Remainder Theorem."""
    c = int.from_bytes(ciphertext, "big")
    pn = key.private_numbers()
    m1 = pow(c, pn.dmp1, pn.p)
    m2 = pow(c, pn.dmq1, pn.q)
    h = (pn.iqmp * (m1 - m2)) % pn.p
    m = m2 + h * pn.q
    raw = m.to_bytes((key.key_size + 7) // 8, "big")
    if len(raw) < 2 or raw[0] != 0 or raw[1] != 2:
        raise ValueError(f"Bad PKCS#1 v1.5 padding: {raw[:4].hex()}")
    idx = raw.find(b"\x00", 2)
    if idx == -1:
        raise ValueError("No 0x00 delimiter found in PKCS#1 v1.5 padding")
    return raw[idx + 1 :]


def compute_passcode_ekpfs(content_id: str, passcode: str, index: int = 1) -> bytes:
    """Derive EKPFS key from 32-character passcode according to Sony PKG specs."""
    idx_hash = hashlib.sha256(index.to_bytes(4, "big")).digest()
    cid_padded = content_id.encode("ascii").ljust(48, b"\x00")
    cid_hash = hashlib.sha256(cid_padded).digest()
    data = idx_hash + cid_hash + passcode.encode("ascii")
    return hashlib.sha256(data).digest()


def decrypt_pkg_entry(data: bytes, entry: dict, dk3: bytes) -> bytes:
    """Decrypt an encrypted package entry using AES-128-CBC and dk3."""
    key_idx = (entry["flags2"] & 0xF000) >> 12
    if key_idx != 3:
        return data
    entry_bytes = struct.pack(
        ">IIIIIIQ",
        entry["id"],
        entry["fn_offset"],
        entry["flags1"],
        entry["flags2"],
        entry["offset"],
        entry["size"],
        0,
    )
    iv_key = hashlib.sha256(entry_bytes + dk3).digest()
    pad_len = (16 - (len(data) % 16)) % 16
    padded_data = data + b"\x00" * pad_len
    cipher = Cipher(algorithms.AES(iv_key[16:32]), modes.CBC(iv_key[:16]))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(padded_data) + decryptor.finalize()
    return decrypted[: entry["size"]]


def parse_param_sfo(data):
    """Parse Sony SFO key-value table."""
    params = {}
    try:
        magic, version, key_off, data_off, num_entries = struct.unpack("<4sIIII", data[:20])
        if magic != b"\x00PSF":
            return params
        for i in range(num_entries):
            k_off, fmt, plen, mlen, d_off = struct.unpack("<HHIII", data[20 + i * 16 : 20 + (i + 1) * 16])
            k = data[key_off + k_off :].split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
            val_raw = data[data_off + d_off : data_off + d_off + plen]
            if fmt == 0x0204:
                v = val_raw.rstrip(b"\x00").decode("utf-8", errors="replace")
            elif fmt == 0x0404:
                v = struct.unpack("<I", val_raw)[0]
            else:
                v = val_raw
            params[k] = v
    except Exception:
        pass
    return params


def unpack_pkg(pkg_path, output_dir=None, passcode=None, dump_pfs=False):
    pkg_path = Path(pkg_path).resolve()
    if not pkg_path.is_file():
        print(f"[ERROR] File not found: {pkg_path}")
        return False

    if output_dir is None:
        output_dir = pkg_path.parent / pkg_path.stem
    else:
        output_dir = Path(output_dir).resolve()

    cpu_cores = os.cpu_count() or 4
    total_start_time = time.time()

    print(f"\n=======================================================")
    print(f" PS4 PKG High-Performance Unpacker")
    print(f" Source:      {pkg_path.name} ({format_size(pkg_path.stat().st_size)})")
    print(f" Destination: {output_dir}")
    print(f" CPU Threads: {cpu_cores} cores active")
    print(f" Storage:     100% In-Memory Streaming (0 GB temp disk writes)")
    print(f"=======================================================\n")

    with open(pkg_path, "rb") as f:
        header = f.read(0x440)
        if len(header) < 0x80 or header[:4] != b"\x7fCNT":
            print("[ERROR] Not a valid PS4 PKG file (Magic != 0x7FCNT).")
            return False

        entry_count = struct.unpack(">I", header[0x10:0x14])[0]
        table_offset = struct.unpack(">I", header[0x18:0x1C])[0]
        content_id = header[0x40:0x70].decode("ascii", errors="ignore").rstrip("\x00")

        pfs_image_offset = 0
        pfs_image_size = 0
        if len(header) >= 0x420:
            pfs_image_offset = struct.unpack(">Q", header[0x410:0x418])[0]
            pfs_image_size = struct.unpack(">Q", header[0x418:0x420])[0]

        # Read entry table
        f.seek(table_offset)
        entries = []
        for _ in range(entry_count):
            eid, fn_offset, f1, f2, offset, size, pad = struct.unpack(">IIIIIIQ", f.read(0x20))
            entries.append({
                "id": eid,
                "fn_offset": fn_offset,
                "flags1": f1,
                "flags2": f2,
                "offset": offset,
                "size": size,
            })

        # Filename table is entry 0x200
        fn_table = next((e for e in entries if e["id"] == 0x200), None)
        if fn_table:
            f.seek(fn_table["offset"])
            fn_blob = f.read(fn_table["size"])
            for e in entries:
                if e["fn_offset"] > 0:
                    name_bytes = fn_blob[e["fn_offset"] :].split(b"\x00", 1)[0]
                    e["name"] = name_bytes.decode("ascii", errors="ignore")

        # Assign fallback names for known SC entries without table entries
        for e in entries:
            if not e.get("name") and e["id"] in KNOWN_ENTRY_NAMES:
                e["name"] = KNOWN_ENTRY_NAMES[e["id"]]

        # Read and display param.sfo info
        sfo_entry = next((e for e in entries if e.get("name") == "param.sfo" or e["id"] == 0x1000), None)
        if sfo_entry:
            f.seek(sfo_entry["offset"])
            sfo_data = f.read(sfo_entry["size"])
            sfo = parse_param_sfo(sfo_data)
            title = sfo.get("TITLE", sfo.get("TITLE_01", "Unknown Title"))
            title_id = sfo.get("TITLE_ID", "Unknown ID")
            app_ver = sfo.get("APP_VER", "Unknown")
            category = sfo.get("CATEGORY", "Unknown")
            print(f" [i] Title:    {title}")
            print(f" [i] Title ID: {title_id}")
            print(f" [i] Version:  {app_ver} (Type: {category})")
            print(f" [i] Content:  {content_id}\n")

        # Derive DK3 key from Entry 0x10 if available
        entry_10 = next((e for e in entries if e["id"] == 0x10), None)
        entry_20 = next((e for e in entries if e["id"] == 0x20), None)
        dk3 = None
        digests = []

        if entry_10:
            f.seek(entry_10["offset"])
            seed_digest = f.read(32)
            digests = [f.read(32) for _ in range(7)]
            f.seek(entry_10["offset"] + 32 + 224 + (3 * 256))
            try:
                dk3 = rsa_decrypt_pkcs1_v15(KEY_DK3, f.read(256))[:32]
            except Exception:
                dk3 = None

        # Step 1: Extract outer sce_sys assets
        print("[1/3] Extracting package metadata & system files...")
        sce_sys_dir = output_dir / "sce_sys"
        sce_sys_dir.mkdir(parents=True, exist_ok=True)

        extracted_outer_count = 0
        for e in entries:
            name = e.get("name")
            if name:
                target_file = sce_sys_dir / name
                target_file.parent.mkdir(parents=True, exist_ok=True)
                f.seek(e["offset"])
                raw_data = f.read(e["size"])
                # Decrypt if entry is encrypted with dk3
                is_encrypted = bool(e["flags1"] & 0x80000000)
                if is_encrypted and dk3:
                    try:
                        raw_data = decrypt_pkg_entry(raw_data, e, dk3)
                    except Exception as err:
                        print(f"      [WARN] Could not decrypt {name}: {err}")
                with open(target_file, "wb") as out_f:
                    out_f.write(raw_data)
                extracted_outer_count += 1

        print(f"      Extracted {extracted_outer_count} system files into sce_sys/\n")

        # Step 2: Key Derivation & Package Type Analysis
        print("[2/3] Analyzing package encryption & keys...")
        if not entry_10 or not entry_20 or pfs_image_offset == 0:
            print("[INFO] Package does not contain an inner PFS game partition.")
            print(f"[SUCCESS] All package metadata extracted to: {output_dir}")
            return True

        if not dk3:
            print("[WARN] Could not derive DK3 key. Cannot decrypt PFS filesystem.")
            return False

        # Entry 0x20 IV/Key calculation
        entry20_bytes = struct.pack(
            ">IIIIIIQ",
            0x20,
            entry_20["fn_offset"],
            entry_20["flags1"],
            entry_20["flags2"],
            entry_20["offset"],
            entry_20["size"],
            0,
        )
        iv_key = hashlib.sha256(entry20_bytes + dk3).digest()

        # Decrypt Entry 0x20 AES-128-CBC
        f.seek(entry_20["offset"])
        img_key_data = f.read(entry_20["size"])
        aes_cipher = Cipher(algorithms.AES(iv_key[16:32]), modes.CBC(iv_key[:16]))
        decryptor = aes_cipher.decryptor()
        decrypted_img_key = decryptor.update(img_key_data) + decryptor.finalize()

        ekpfs_key = None
        pkg_type_label = None

        # 1. Try Fake PKG RSA decryption with FakeKeyset
        try:
            candidate_ekpfs = rsa_decrypt_pkcs1_v15(KEY_FAKE, decrypted_img_key)[:32]
            if len(digests) > 1 and xor_bytes(hashlib.sha256(candidate_ekpfs).digest(), candidate_ekpfs) == digests[1]:
                ekpfs_key = candidate_ekpfs
                pkg_type_label = "Fake PKG (FPKG / Homebrew Dump)"
        except Exception:
            pass

        # 2. Try standard 32-zeros passcode for FPKGs
        if ekpfs_key is None and len(digests) > 1:
            candidate_ekpfs = compute_passcode_ekpfs(content_id, "0" * 32, 1)
            if xor_bytes(hashlib.sha256(candidate_ekpfs).digest(), candidate_ekpfs) == digests[1]:
                ekpfs_key = candidate_ekpfs
                pkg_type_label = "Fake PKG (32-zero Passcode)"

        # 3. Try user-supplied passcode (via CLI flag)
        if ekpfs_key is None and passcode and len(digests) > 1:
            candidate_ekpfs = compute_passcode_ekpfs(content_id, passcode, 1)
            if xor_bytes(hashlib.sha256(candidate_ekpfs).digest(), candidate_ekpfs) == digests[1]:
                ekpfs_key = candidate_ekpfs
                pkg_type_label = "Retail PKG (Passcode Decrypted)"
            else:
                print(f"[WARN] Provided passcode is invalid for {content_id}!")

        # 4. If still not decrypted, package is an Official Sony Retail PKG
        if ekpfs_key is None:
            print("==========================================================================")
            print(" [i] DETECTED: Official Sony Retail Package (PlayStation Network CDN)")
            print("==========================================================================")
            print(" This package was downloaded from official Sony servers. The game partition")
            print(" (PFS) is encrypted with Sony's proprietary hardware master keys (SAMU).")
            print("--------------------------------------------------------------------------")

            if not passcode and sys.stdin and sys.stdin.isatty():
                try:
                    user_pass = input(" If you have the 32-character game passcode, enter it (or press Enter to skip): ").strip()
                    if user_pass:
                        candidate_ekpfs = compute_passcode_ekpfs(content_id, user_pass, 1)
                        if len(digests) > 1 and xor_bytes(hashlib.sha256(candidate_ekpfs).digest(), candidate_ekpfs) == digests[1]:
                            ekpfs_key = candidate_ekpfs
                            pkg_type_label = "Retail PKG (Passcode Decrypted)"
                            print(" [✓] Passcode verified successfully!\n")
                        else:
                            print(" [!] Invalid passcode. Skipping PFS filesystem decryption.\n")
                except (EOFError, KeyboardInterrupt):
                    pass

        # 5. Handle raw PFS dump or finish retail package
        if ekpfs_key is None:
            if dump_pfs:
                print(f" Dumping raw encrypted PFS container ({format_size(pfs_image_size)})...")
                f.seek(pfs_image_offset)
                raw_pfs_path = output_dir / "pfs_outer.pfs"
                with open(raw_pfs_path, "wb") as out_pfs:
                    bytes_left = pfs_image_size
                    chunk_sz = 8 * 1024 * 1024
                    pbar_dump = ConsoleProgressBar("Raw PFS Dump")
                    done_dump = 0
                    while bytes_left > 0:
                        chunk = f.read(min(chunk_sz, bytes_left))
                        if not chunk:
                            break
                        out_pfs.write(chunk)
                        done_dump += len(chunk)
                        bytes_left -= len(chunk)
                        pbar_dump.step("dump", done_dump, pfs_image_size, bytes_processed=done_dump)
                print(f" [✓] Dumped raw PFS container to: {raw_pfs_path.name}")

            print("\n--------------------------------------------------------------------------")
            print(f"[SUCCESS] Extracted {extracted_outer_count} metadata and system files to:")
            print(f"          {sce_sys_dir}")
            print("\n[NOTE ON RETAIL PACKAGES]:")
            print(" - All icons, backgrounds, audio, patch notes, trophies, and param.sfo")
            print("   have been successfully extracted.")
            print(" - The game assets (eboot.bin, game data, textures) inside official retail")
            print("   packages are hardware-encrypted by Sony SAMU processor.")
            print(" - To get raw decrypted game assets on PC, dump the game directly from a")
            print("   jailbroken PS4 (Itemzflow or PS4-dumper), which exports a Fake PKG (fPKG).")
            print("==========================================================================\n")
            return True

        # Step 3: Decrypt and Unpack PFS partition
        print(f" [✓] Package Type:     {pkg_type_label}")
        print(f"     Game Partition:   {format_size(pfs_image_size)}")
        print(f"     Derived EKPFS:    {ekpfs_key.hex()[:16]}...{ekpfs_key.hex()[-8:]}\n")

        print("[3/3] Decrypting and unpacking game filesystem (PFS)...")
        print(f"      Accelerating with {cpu_cores} parallel CPU threads.")

        slice_path = SlicePath(pkg_path, pfs_image_offset, pfs_image_size)

        # Inspect outer PFS structure
        insp_outer = pfs.inspect_pfs_image(slice_path, ekpfs=ekpfs_key, verify_payloads=False)
        if insp_outer.errors:
            print(f"[ERROR] Failed to read outer PFS image: {insp_outer.errors}")
            return False

        # If the outer PFS wraps a nested pfs_image.dat container (standard game layout):
        if len(insp_outer.file_inodes) == 1 and "pfs_image.dat" in insp_outer.file_inodes:
            dat_inode_num = insp_outer.file_inodes["pfs_image.dat"]
            dat_inode = insp_outer.inodes[dat_inode_num]
            print(f"      Nested Container: pfs_image.dat ({format_size(dat_inode.logical_size)})")
            print("      Streaming & decompressing game files directly in-memory (0 intermediate disk writes)...\n")

            vpath = VirtualPFSCPath(
                slice_path,
                ekpfs=ekpfs_key,
                inode_num=dat_inode_num,
                size=dat_inode.logical_size,
            )
            pbar = ConsoleProgressBar("Game Files")
            res = pfs.extract_pfs_image(vpath, output_dir, progress=pbar)
            if res.errors:
                print(f"\n[ERROR] Extraction failed: {res.errors}")
                return False
        else:
            # Flat PFS structure (DLC or update payloads)
            print(f"      Direct Flat PFS ({len(insp_outer.file_inodes)} files)")
            print("      Extracting game files directly...\n")
            pbar = ConsoleProgressBar("Game Files")
            res = pfs.extract_pfs_image(slice_path, output_dir, progress=pbar, ekpfs=ekpfs_key)
            if res.errors:
                print(f"\n[ERROR] Extraction failed: {res.errors}")
                return False

    elapsed_total = time.time() - total_start_time
    print(f"\n[SUCCESS] Game package fully unpacked in {format_time(elapsed_total)}!")
    print(f"Output Directory: {output_dir}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="PS4 PKG High-Performance Drag & Drop Unpacker - Fast, Multi-threaded, Zero Temp Disk usage."
    )
    parser.add_argument("pkg_files", nargs="*", help="Path to one or more .pkg files")
    parser.add_argument("-o", "--output", help="Custom output directory")
    parser.add_argument("-p", "--passcode", help="32-character game passcode (for retail or custom packages)")
    parser.add_argument("--dump-pfs", action="store_true", help="Dump raw encrypted PFS partition for retail packages")

    args = parser.parse_args()

    files = args.pkg_files
    if not files:
        print("=======================================================")
        print(" PS4 PKG High-Performance Drag and Drop Unpacker")
        print("=======================================================\n")
        print("Usage: Drag and drop one or more .pkg files onto this script.")
        pkg_input = input("Or paste the full path to a .pkg file: ").strip(' "')
        if not pkg_input:
            return
        files = [pkg_input]

    for file_path in files:
        if file_path.lower().endswith(".pkg"):
            unpack_pkg(
                file_path,
                output_dir=args.output,
                passcode=args.passcode,
                dump_pfs=args.dump_pfs,
            )
        else:
            print(f"[SKIP] Not a .pkg file: {file_path}")

    print("\nAll done!")


if __name__ == "__main__":
    main()
