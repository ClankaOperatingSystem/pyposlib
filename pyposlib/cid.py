# Copyright (C) 2026 Chris Gough
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""IPFS content identifiers, computed locally, as poslib's doc/formats.org specifies.

The CID ipfs add gives under the unixfs-v1-2025 import profile: CIDv1,
sha2-256, raw leaves, 1 MiB chunks, a balanced layout of 1024 links a node.
Hidden entries are left out; names are hashed as stored. A directory whose
node would exceed 256 KiB is a HAMT shard, as IPFS makes it.
"""
import base64
import hashlib
import os
import stat

CHUNK_SIZE = 1048576
FILE_MAX_LINKS = 1024
SHARDING_THRESHOLD = 262144
HAMT_FANOUT = 256
MURMUR3_X64_64 = 0x22

RAW = 0x55
DAG_PB = 0x70
DAG_JSON = 0x0129


def varint(n):
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7f) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def varint_field(number, value):
    return varint(number << 3) + varint(value)


def bytes_field(number, data):
    return varint(number << 3 | 2) + varint(len(data)) + data


def binary_cid(codec, block):
    return b'\x01' + varint(codec) + b'\x12\x20' + hashlib.sha256(block).digest()


def text(cid):
    return 'b' + base64.b32encode(cid).decode().lower().rstrip('=')


# A node is (cid, tsize, filesize): its binary CID, the bytes of its whole
# DAG, and for files the bytes of content.

def pb_block(links, data):
    """The dag-pb block of links (cid, name, tsize) and data, links first."""
    return b''.join(bytes_field(2, bytes_field(1, c) + bytes_field(2, n) + varint_field(3, t))
                    for c, n, t in links) + bytes_field(1, data)


def pb_node(links, data):
    block = pb_block(links, data)
    return binary_cid(DAG_PB, block), len(block) + sum(t for _, _, t in links)


def murmur3_x64_64(data):
    """The first 64 bits of MurmurHash3 x64 128 of data, seed 0, big-endian:
    the multihash murmur3-x64-64, by which a HAMT places a name."""
    mask = (1 << 64) - 1

    def rotl(x, r):
        return ((x << r) | (x >> (64 - r))) & mask

    def fmix(k):
        k ^= k >> 33
        k = (k * 0xff51afd7ed558ccd) & mask
        k ^= k >> 33
        k = (k * 0xc4ceb9fe1a85ec53) & mask
        return k ^ (k >> 33)

    c1, c2 = 0x87c37b91114253d5, 0x4cf5ad432745937f
    h1 = h2 = 0
    n = len(data)
    for i in range(0, n - n % 16, 16):
        k1 = int.from_bytes(data[i:i + 8], 'little')
        k2 = int.from_bytes(data[i + 8:i + 16], 'little')
        h1 ^= (rotl((k1 * c1) & mask, 31) * c2) & mask
        h1 = (rotl(h1, 27) + h2) & mask
        h1 = (h1 * 5 + 0x52dce729) & mask
        h2 ^= (rotl((k2 * c2) & mask, 33) * c1) & mask
        h2 = (rotl(h2, 31) + h1) & mask
        h2 = (h2 * 5 + 0x38495ab5) & mask
    tail = data[n - n % 16:]
    if len(tail) > 8:
        k2 = int.from_bytes(tail[8:], 'little')
        h2 ^= (rotl((k2 * c2) & mask, 33) * c1) & mask
    if tail:
        k1 = int.from_bytes(tail[:8], 'little')
        h1 ^= (rotl((k1 * c1) & mask, 31) * c2) & mask
    h1 ^= n
    h2 ^= n
    h1 = (h1 + h2) & mask
    h2 = (h2 + h1) & mask
    h1 = fmix(h1)
    h2 = fmix(h2)
    h1 = (h1 + h2) & mask
    return h1.to_bytes(8, 'big')


def shard(entries, level, blocks):
    """The HAMT shard node over entries, (hash, (cid, name, tsize)), placed
    by byte level of their hashes: a lone entry in a slot is linked under
    the slot's two hex digits and its name, several under the digits alone
    as a sub-shard placed by the next byte. Each shard's block is put in
    blocks by its CID when blocks is given."""
    slots = {}
    for digest, link in entries:
        slots.setdefault(digest[level], []).append((digest, link))
    bitfield = bytearray(HAMT_FANOUT // 8)
    links = []
    for index in sorted(slots):
        bitfield[-1 - index // 8] |= 1 << (index % 8)
        prefix = b'%02X' % index
        if len(slots[index]) == 1:
            c, name, t = slots[index][0][1]
            links.append((c, prefix + name, t))
        else:
            c, t = shard(slots[index], level + 1, blocks)
            links.append((c, prefix, t))
    data = (varint_field(1, 5) + bytes_field(2, bytes(bitfield).lstrip(b'\0'))
            + varint_field(5, MURMUR3_X64_64) + varint_field(6, HAMT_FANOUT))
    node = pb_node(links, data)
    if blocks is not None:
        blocks[text(node[0])] = pb_block(links, data)
    return node


def directory_node(links, blocks=None):
    """The node of a directory linking links, (cid, name, tsize): a plain
    directory node, or a HAMT shard where that node would exceed
    SHARDING_THRESHOLD bytes. Its blocks are put in blocks by CID when
    blocks is given."""
    data = varint_field(1, 1)
    block = pb_block(links, data)
    if len(block) > SHARDING_THRESHOLD:
        return shard([(murmur3_x64_64(name), link) for link in links for name in (link[1],)], 0, blocks)
    node = pb_node(links, data)
    if blocks is not None:
        blocks[text(node[0])] = block
    return node


def leaf(data):
    return binary_cid(RAW, data), len(data), len(data)


def file_node(children):
    sizes = [c[2] for c in children]
    data = varint_field(1, 2) + varint_field(3, sum(sizes)) + b''.join(varint_field(4, s) for s in sizes)
    cid, tsize = pb_node([(c[0], b'', c[1]) for c in children], data)
    return cid, tsize, sum(sizes)


def balance(nodes, max_links):
    """One leaf is its own root; otherwise each level groups the one below."""
    while len(nodes) > 1:
        nodes = [file_node(nodes[i:i + max_links]) for i in range(0, len(nodes), max_links)]
    return nodes[0]


def content(size, read, chunk_size, max_links):
    leaves, start = [], 0
    while True:
        leaves.append(leaf(read(start, min(size, start + chunk_size))))
        start += chunk_size
        if start >= size:
            return balance(leaves, max_links)


def file_content(path, chunk_size, max_links):
    with open(path, 'rb') as stream:
        size = os.fstat(stream.fileno()).st_size

        def read(start, end):
            stream.seek(start)
            return stream.read(end - start)
        return content(size, read, chunk_size, max_links)


def directory(path, rel, visit, chunk_size, max_links):
    links = []
    for name in sorted(n for n in os.listdir(os.fsencode(path)) if not n.startswith(b'.')):
        child = os.path.join(os.fsencode(path), name)
        child_rel = os.fsdecode(name) if not rel else rel + '/' + os.fsdecode(name)
        info = os.lstat(child)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f'Symlinks have no CID here: {os.fsdecode(child)}')
        if stat.S_ISDIR(info.st_mode):
            node = directory(child, child_rel, visit, chunk_size, max_links)
        elif stat.S_ISREG(info.st_mode):
            node = file_content(child, chunk_size, max_links)
            visit(child_rel, node)
        else:
            raise ValueError(f'Not a regular file: {os.fsdecode(child)}')
        links.append((node[0], name, node[1]))
    node = directory_node(links)
    visit(rel or '.', node)
    return node


def cid_bytes(data, chunk_size=CHUNK_SIZE, max_links=FILE_MAX_LINKS):
    """The CID of data, as a file's content."""
    return text(content(len(data), lambda s, e: data[s:e], chunk_size, max_links)[0])


def cid_file(path, chunk_size=CHUNK_SIZE, max_links=FILE_MAX_LINKS):
    """The CID of the file at path."""
    return text(file_content(path, chunk_size, max_links)[0])


def cid_directory(path, chunk_size=CHUNK_SIZE, max_links=FILE_MAX_LINKS):
    """The CID of the tree at path."""
    return text(directory(path, '', lambda rel, node: None, chunk_size, max_links)[0])


def cid_tree(path, chunk_size=CHUNK_SIZE, max_links=FILE_MAX_LINKS):
    """The CID of every file and directory under path, the root as '.'."""
    cids = {}
    directory(path, '', lambda rel, node: cids.__setitem__(rel, text(node[0])), chunk_size, max_links)
    return cids


def cid_block(codec, block):
    """The CID of block under codec: how a DAG-JSON ledger event is named."""
    return text(binary_cid(codec, block))


def blocks(data, chunk_size=CHUNK_SIZE, max_links=FILE_MAX_LINKS):
    """The blocks of data as a file, {cid: block}: its leaves, and the nodes
    over them when it is more than one chunk. The file's CID is among them."""
    held, nodes, start = {}, [], 0
    while True:
        chunk = data[start:start + chunk_size]
        node = leaf(chunk)
        held[text(node[0])] = chunk
        nodes.append(node)
        start += chunk_size
        if start >= len(data):
            break
    while len(nodes) > 1:
        level = []
        for i in range(0, len(nodes), max_links):
            children = nodes[i:i + max_links]
            sizes = [c[2] for c in children]
            links = [(c[0], b'', c[1]) for c in children]
            content = (varint_field(1, 2) + varint_field(3, sum(sizes))
                       + b''.join(varint_field(4, s) for s in sizes))
            node = pb_node(links, content)
            held[text(node[0])] = pb_block(links, content)
            level.append((*node, sum(sizes)))
        nodes = level
    return held


def read_varint(block, at):
    value, shift = 0, 0
    while True:
        byte = block[at]
        at += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, at
        shift += 7


def codec(text_cid):
    """The multicodec of text_cid: RAW, DAG_PB or DAG_JSON."""
    return read_varint(decode(text_cid), 1)[0]


def parse(block):
    """A dag-pb block as (links, data): each link (cid, name, tsize), as pb_block takes them."""
    links, data, at = [], b'', 0
    while at < len(block):
        tag, at = read_varint(block, at)
        length, at = read_varint(block, at)
        field, at = block[at:at + length], at + length
        if tag >> 3 == 1:
            data = field
        else:
            child, name, tsize, inner = b'', b'', 0, 0
            while inner < len(field):
                key, inner = read_varint(field, inner)
                if key & 7 == 2:
                    size, inner = read_varint(field, inner)
                    value, inner = field[inner:inner + size], inner + size
                    if key >> 3 == 1:
                        child = value
                    else:
                        name = value
                else:
                    tsize, inner = read_varint(field, inner)
            links.append((child, name, tsize))
    return links, data


def decode(text_cid):
    """The binary CID of text_cid, a CID in lower-case multibase base32."""
    body = text_cid[1:]
    if len(text_cid) < 2 or text_cid[0] != 'b' or body != body.lower():
        raise ValueError(f'Not a base32 CID: {text_cid}')
    return base64.b32decode(body.upper() + '=' * (-len(body) % 8))


def file_tsize(size, chunk_size=CHUNK_SIZE, max_links=FILE_MAX_LINKS):
    """The bytes of the DAG a file of size bytes makes, from size alone.

    A leaf's size is its chunk's and a node's is its block's plus its
    children's, and a binary CID is 36 bytes whatever it hashes, so no
    content is needed."""
    leaves, start = [], 0
    while True:
        n = min(size, start + chunk_size) - start
        leaves.append((b'\0' * 36, n, n))
        start += chunk_size
        if start >= size:
            return balance(leaves, max_links)[1]


def cid_inventory(entries, empty=(), chunk_size=CHUNK_SIZE, max_links=FILE_MAX_LINKS, blocks=None):
    """The CID of every file and directory over entries, {path: (cid, size)},
    and the empty directories empty.

    Directories are derived from the paths as cid_tree finds them on disk;
    one that holds nothing has no file to derive it from and is listed in
    empty. A hidden component is refused since IPFS would leave it out.
    {path: cid}, files as given, the root as '.'. Each directory's blocks,
    the shards of one IPFS shards among them, are put in blocks, by CID,
    when blocks is given."""
    tree = {}
    for path, (given, size) in entries.items():
        parts = path.split('/')
        if any(not p or p.startswith('.') for p in parts):
            raise ValueError(f'Not a path IPFS would add: {path}')
        node = tree
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                raise ValueError(f'A file and a directory share a path: {path}')
        if parts[-1] in node:
            raise ValueError(f'A file and a directory share a path: {path}')
        node[parts[-1]] = (decode(given), file_tsize(size, chunk_size, max_links), given)
    for path in empty:
        parts = path.split('/')
        if any(not p or p.startswith('.') for p in parts):
            raise ValueError(f'Not a path IPFS would add: {path}')
        node = tree
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                raise ValueError(f'A file and a directory share a path: {path}')
        if parts[-1] in node:
            raise ValueError(f'Not an empty directory: {path}')
        node[parts[-1]] = {}
    cids = {}

    def walk(node, rel):
        links = []
        for name in sorted(node, key=lambda n: n.encode('utf-8')):
            child = node[name]
            path = f'{rel}/{name}' if rel else name
            if isinstance(child, dict):
                c, t = walk(child, path)
            else:
                c, t, given = child
                cids[path] = given
            links.append((c, name.encode('utf-8'), t))
        c, t = directory_node(links, blocks)
        cids[rel or '.'] = text(c)
        return c, t

    walk(tree, '')
    return cids
