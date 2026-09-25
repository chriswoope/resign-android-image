"""Minimal protobuf decoder and encoder, enough to read Android OTA messages without a schema and to
write simple messages."""


def varint(data, pos):
    value = shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated protobuf varint")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift >= 70:
            raise ValueError("invalid protobuf varint")


def fields(data):
    """Return {field_number: [(wire_type, value), ...]}."""
    out = {}
    pos = 0
    while pos < len(data):
        key, pos = varint(data, pos)
        number, wire = key >> 3, key & 7
        if not number:
            raise ValueError("invalid protobuf field 0")

        if wire == 0:
            value, pos = varint(data, pos)
        elif wire == 1:
            value, pos = data[pos:pos + 8], pos + 8
        elif wire == 2:
            size, pos = varint(data, pos)
            value, pos = data[pos:pos + size], pos + size
        elif wire == 5:
            value, pos = data[pos:pos + 4], pos + 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")

        if pos > len(data):
            raise ValueError("truncated protobuf field")
        out.setdefault(number, []).append((wire, value))
    return out


def last_int(message, number):
    for wire, value in reversed(message.get(number, [])):
        if wire == 0:
            return value
    return None


def last_bytes(message, number):
    for wire, value in reversed(message.get(number, [])):
        if wire == 2:
            return value
    return None


def all_bytes(message, number):
    return [value for wire, value in message.get(number, []) if wire == 2]


def encode_varint(value):
    out = bytearray()
    while value > 0x7f:
        out.append(value & 0x7f | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def encode_bytes(number, value):
    """A length-delimited field: bytes, a string or an embedded message."""
    return encode_varint(number << 3 | 2) + encode_varint(len(value)) + value
