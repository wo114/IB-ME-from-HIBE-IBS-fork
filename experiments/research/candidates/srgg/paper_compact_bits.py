"""Bounded canonical bit fields used only by the optional paper codec.

Integers are packed most-significant-bit first. No coefficient reduction,
lossy rounding, entropy coding or data-dependent protocol change is performed.
This Python implementation is not constant-time.
"""
from __future__ import annotations

from ibme.core.errors import SerializationError


def pack(values, width):
    """Pack nonnegative integers and zero-pad the final low bits."""
    if type(width) is not int or not 0 <= width <= 257:
        raise SerializationError("compact integer width out of range")
    result = bytearray()
    accumulator = pending = 0
    for value in values:
        if type(value) is not int or value < 0 or value.bit_length() > width:
            raise SerializationError("compact integer outside its bit field")
        accumulator = (accumulator << width) | value
        pending += width
        while pending >= 8:
            pending -= 8
            result.append((accumulator >> pending) & 255)
        accumulator &= (1 << pending)-1
    if pending:
        result.append(accumulator << (8-pending))
    return bytes(result)


def unpack(data, count, width):
    """Decode an exactly sized field and reject nonzero unused low bits."""
    if (type(data) is not bytes or type(count) is not int or count < 0
            or type(width) is not int or not 0 <= width <= 257
            or len(data) != (count*width+7)//8):
        raise SerializationError("compact bit-field length/width mismatch")
    padding = (-count*width) % 8
    if padding and data[-1] & ((1 << padding)-1):
        raise SerializationError("nonzero compact bit-field padding")
    if width == 0:
        return (0,)*count
    result = []
    accumulator = pending = offset = 0
    mask = (1 << width)-1
    for _ in range(count):
        while pending < width:
            accumulator = (accumulator << 8) | data[offset]
            offset += 1
            pending += 8
        pending -= width
        result.append((accumulator >> pending) & mask)
        accumulator &= (1 << pending)-1
    return tuple(result)


def zigzag(value):
    if type(value) is not int or abs(value).bit_length() > 256:
        raise SerializationError("compact exact signed coefficient out of range")
    return 2*value if value >= 0 else -2*value-1


def unzigzag(value):
    result = value//2 if value % 2 == 0 else -(value//2)-1
    if abs(result).bit_length() > 256:
        raise SerializationError("compact exact signed coefficient out of range")
    return result


class Reader:
    """Check wire capacity and each length before allocating parsed vectors."""
    def __init__(self, data, maximum):
        if type(data) is not bytes or not 1 <= len(data) <= maximum:
            raise SerializationError("bounded compact bytes required")
        self.data, self.position = data, 0

    def take(self, count):
        if type(count) is not int or count < 0 or count > len(self.data)-self.position:
            raise SerializationError("truncated compact field")
        start, self.position = self.position, self.position+count
        return self.data[start:self.position]

    def integer(self, count):
        return int.from_bytes(self.take(count), "big")

    def finish(self):
        if self.position != len(self.data):
            raise SerializationError("appended compact bytes")


class Writer:
    def __init__(self, maximum):
        self.data, self.maximum = bytearray(), maximum

    def add(self, value):
        if type(value) is not bytes or len(value) > self.maximum-len(self.data):
            raise SerializationError("compact object exceeds wire capacity")
        self.data.extend(value)

    def integer(self, value, count):
        if type(value) is not int or not 0 <= value < 1 << (8*count):
            raise SerializationError("compact fixed integer out of range")
        self.add(value.to_bytes(count, "big"))

    def finish(self):
        return bytes(self.data)
