import base64
import os
from math import ceil
from pathlib import Path
from typing import BinaryIO, Callable

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

from constants import ENCODING, NONCE_SIZE, SLASH_REPLACER, ENCRYPTED_FILE_PREFIX, CHUNK_SIZE, DECRYPT_CHUNK_SIZE, \
    TAG_SIZE
from path_utils import map_path


class BytesInStream:
    def read(self, size: int = -1) -> bytes:
        """read"""
        pass

    def seek(self, position: int):
        """seek"""
        pass


class InMemoryBytesInStream(BytesInStream):
    def __init__(self):
        self.buf = bytes()
        self.position = 0

    def read(self, size: int = -1):
        if size == -1:
            return self.buf[self.position:]
        return self.buf[self.position:size]

    def seek(self, position: int):
        self.position = position


class BinaryIOBytesInStream(BytesInStream):
    def __init__(self, in_stream: BinaryIO):
        self.in_stream = in_stream

    def read(self, size: int = -1):
        if size == -1:
            return self.in_stream.read()
        return self.in_stream.read(size)

    def seek(self, position: int):
        self.in_stream.seek(position)


class BytesOutStream:
    def write(self, buf: bytes):
        """write"""
        pass


class InMemoryBytesOutStream(BytesOutStream):
    def __init__(self):
        self.buf = bytes()

    def write(self, buf: bytes):
        self.buf += buf


class BinaryIOBytesOutStream(BytesOutStream):
    def __init__(self, out_stream: BinaryIO):
        self.out_stream = out_stream

    def write(self, buf: bytes):
        self.out_stream.write(buf)


def encrypt(key: str | bytes, source: bytes) -> bytes:
    if isinstance(key, str):
        key = SHA256.new(bytes(key, ENCODING)).digest()
    nonce = Random.new().read(NONCE_SIZE)
    encryptor = AES.new(key, AES.MODE_GCM, nonce=nonce)
    encrypted, tag = encryptor.encrypt_and_digest(source)
    return nonce + encrypted + tag


def encrypt_name(key: str | bytes, name: str) -> str:
    return (ENCRYPTED_FILE_PREFIX + base64.b64encode(encrypt(key, bytes(name, ENCODING))).decode(ENCODING)
            .replace('/', SLASH_REPLACER)
            .replace('\\', SLASH_REPLACER))


def decrypt(key: str | bytes, source: bytes) -> bytes:
    if isinstance(key, str):
        key = SHA256.new(bytes(key, ENCODING)).digest()
    decrypter = AES.new(key, AES.MODE_GCM, nonce=source[:NONCE_SIZE])
    return decrypter.decrypt_and_verify(source[NONCE_SIZE:-TAG_SIZE], received_mac_tag=source[-TAG_SIZE:])


def decrypt_name(key: str | bytes, name: str) -> str:
    return decrypt(key, base64.b64decode(name.replace(SLASH_REPLACER, '/'))).decode(ENCODING)


def decrypt_path(key: str | bytes, path: str) -> str:
    return map_path(path, lambda x: decrypt_name(key, x))


def convert_size_of_encrypted_to_real_size(size: int) -> int:
    return size - (ceil(size / DECRYPT_CHUNK_SIZE) * (NONCE_SIZE + TAG_SIZE))


def encrypt_stream(key: str | bytes, in_stream: BytesInStream, out_stream: BytesOutStream):
    while True:
        buf = in_stream.read(CHUNK_SIZE)
        if not buf:
            break
        buf = encrypt(key, buf)
        out_stream.write(buf)


def empty():
    # empty
    pass


def decrypt_stream(key: str | bytes,
                   in_stream: BytesInStream,
                   out_stream: BytesOutStream,
                   start: int = 0,
                   iterate_callback: Callable = empty):
    if start != 0:
        chunk_count = start // CHUNK_SIZE

        in_stream.seek(DECRYPT_CHUNK_SIZE * chunk_count)
        buf = in_stream.read(DECRYPT_CHUNK_SIZE)
        buf = decrypt(key, buf)
        buf = buf[start - (CHUNK_SIZE * chunk_count):]

        iterate_callback()
        out_stream.write(buf)

    while True:
        iterate_callback()
        buf = in_stream.read(DECRYPT_CHUNK_SIZE)
        if not buf:
            break
        buf = decrypt(key, buf)
        out_stream.write(buf)


def encrypt_content(key: bytes, path: str, rename: bool = False):
    path = Path(path)
    if os.path.isdir(path):
        if rename and not path.name.startswith(ENCRYPTED_FILE_PREFIX):
            temp = path.parent.joinpath(encrypt_name(key, path.name))
            path.rename(temp)
            path = temp
        for f in os.listdir(path):
            encrypt_content(key, str(path.joinpath(f)), True)
    else:
        if not path.name.startswith(ENCRYPTED_FILE_PREFIX):
            with open(path, 'rb') as f_in, open(path.parent.joinpath(encrypt_name(key, path.name)), 'wb') as f_out:
                encrypt_stream(key, BinaryIOBytesInStream(f_in), BinaryIOBytesOutStream(f_out))
            os.remove(path)
