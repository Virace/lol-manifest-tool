# -*- coding: utf-8 -*-
# @Author  : Virace
# @Email   : Virace@aliyun.com
# @Site    : x-item.com
# @Software: Pycharm
# @Create  : 2022/8/28 19:18
# @Update  : 2022/8/28 19:18
# @Detail  : 描述

import os
import shutil
import struct
from contextlib import contextmanager


@contextmanager
def write_file_or_remove(path, binary=True):
    """Open a file for writing, create its parent directory if needed
    If the writing fails, the file is removed.
    """
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb' if binary else 'w') as f:
            yield f
    except:
        # remove partially written file
        try:
            os.remove(path)
        except OSError:
            pass
        raise


class BinaryParser:
    """Helper class to read from binary file object"""

    def __init__(self, f):
        self.f = f

    def tell(self):
        return self.f.tell()

    def seek(self, position):
        self.f.seek(position, 0)

    def skip(self, amount):
        self.f.seek(amount, 1)

    def rewind(self, amount):
        self.f.seek(-amount, 1)

    def unpack(self, fmt):
        length = struct.calcsize(fmt)
        return struct.unpack(fmt, self.f.read(length))

    def raw(self, length):
        return self.f.read(length)

    def unpack_string(self):
        """Unpack string prefixed by its 32-bit length"""
        return self.f.read(self.unpack('<L')[0]).decode('utf-8')