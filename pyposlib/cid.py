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
Hidden entries are left out; names are hashed as stored. A directory
IPFS would shard raises ShardingUnsupported rather than get a wrong CID.
"""
import base64
import hashlib
import os
import stat

CHUNK_SIZE = 1048576
FILE_MAX_LINKS = 1024
SHARDING_THRESHOLD = 262144

RAW = 0x55
DAG_PB = 0x70
DAG_JSON = 0x0129


class ShardingUnsupported(ValueError):
    """A directory needs HAMT sharding, which is not implemented."""


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
    data = varint_field(1, 1)
    size = len(pb_block(links, data))
    if size > SHARDING_THRESHOLD:
        raise ShardingUnsupported(f'{os.fsdecode(path)}: directory block of {size} bytes')
    node = pb_node(links, data)
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


def cid_inventory(entries, empty=(), chunk_size=CHUNK_SIZE, max_links=FILE_MAX_LINKS):
    """The CID of every file and directory over entries, {path: (cid, size)},
    and the empty directories empty.

    Directories are derived from the paths as cid_tree finds them on disk;
    one that holds nothing has no file to derive it from and is listed in
    empty. A hidden component is refused since IPFS would leave it out.
    {path: cid}, files as given, the root as '.'. Raises ShardingUnsupported
    as cid_directory does."""
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
        data = varint_field(1, 1)
        size = len(pb_block(links, data))
        if size > SHARDING_THRESHOLD:
            raise ShardingUnsupported(f'{rel or "."}: directory block of {size} bytes')
        c, t = pb_node(links, data)
        cids[rel or '.'] = text(c)
        return c, t

    walk(tree, '')
    return cids
