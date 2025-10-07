# Универсальные теги
import binascii

UNIVERSAL_TAGS = {
    0x01: 'BOOLEAN',
    0x02: 'INTEGER',
    0x03: 'BIT_STRING',
    0x04: 'OCTET_STRING',
    0x05: 'NULL',
    0x06: 'OBJECT_IDENTIFIER',
    0x0C: 'UTF8String',
    0x10: 'SEQUENCE',
    0x11: 'SET',
    0x13: 'PrintableString',
    0x16: 'IA5String',
    0x17: 'UTCTime',
    0x30: 'SEQUENCE',  # Конструктивный
}

CLASS_NAMES = {
            0: 'UNIVERSAL',
            1: 'APPLICATION',
            2: 'CONTEXT',
            3: 'PRIVATE'
        }

def parse_asn(data_bytes, len_recurse=-1):
    result = parse_der_tlv(data_bytes,0, len_recurse)
    return result


def parse_der_tlv(data_bytes, index, len_recurse=-1):
    tag_name, constructed, tag_number, index = parse_tag(data_bytes, index)
    length, index = parse_length(data_bytes, index)
    value_bytes = data_bytes[index: index + length]
    if constructed:
        if len_recurse == 0:
            value = value_bytes
        else:
            value = parse_sequence(value_bytes, len_recurse - 1)
    else:
         if tag_name == 'BOOLEAN':
             value = parse_boolean(value_bytes)
         elif tag_name == 'INTEGER':
             value = parse_integer(value_bytes)
         elif tag_name == 'OCTET_STRING':
             value = parse_octet_string(value_bytes)
         elif tag_name == 'NULL':
             value = parse_null(value_bytes)
         elif tag_name == 'OBJECT_IDENTIFIER':
             value = parse_object_identifier(value_bytes)
         else:
             # Another way read bytes
             value = value_bytes
             value = binascii.hexlify(value).decode('ascii')

    return value, index + length

def parse_tag(data_bytes, index):
    first_byte = data_bytes[index]

    # Analyze first byte
    tag_class = (first_byte >> 6) & 0x03
    constructed = bool((first_byte >> 5) & 0x01)
    tag_number = first_byte & 0x1F

    if tag_number == 0x1F:
        raise ValueError(f"Unsupported tag_number {tag_number}")

    # Name of tag
    if tag_class == 0 and tag_number in UNIVERSAL_TAGS:
        tag_name = UNIVERSAL_TAGS[tag_number]
    else:
        tag_name = f"{CLASS_NAMES[tag_class]}[{tag_number}]"

    return tag_name, constructed, tag_number, index+1

def parse_length(data_bytes, index):
    first_byte = data_bytes[index]
    index += 1
    if first_byte == 0x80:
        raise ValueError("Unsupported length DER")

    if first_byte & 0x80:  # Long form
        num_bytes = first_byte & 0x7F
        if num_bytes == 0:
            raise ValueError("Unsupported length DER")

        length = 0
        for i in range(num_bytes):
            length = (length << 8) | data_bytes[index]
            index += 1

        if length < 128:
            raise ValueError("Length must code in short form")

    else:
        length = first_byte

    return length, index

def parse_sequence(sequence_bytes, len_recurse):
    results = []
    index = 0
    while index < len(sequence_bytes):
        value, index = parse_der_tlv(sequence_bytes, index, len_recurse)
        results.append(value)
    return tuple(results)

def parse_integer(integer_bytes) -> int:
    if len(integer_bytes) > 1:
        first_byte = integer_bytes[0]
        second_byte = integer_bytes[1] & 0x80
        if first_byte == 0x00 and not second_byte:
            raise ValueError("Zero byte in INTEGER")
        if first_byte == 0xFF and second_byte:
            raise ValueError("Zero byte 0xFF in INTEGER")

    return int.from_bytes(integer_bytes, byteorder='big', signed=True)

def parse_boolean(boolean_bytes) -> bool:
    if len(boolean_bytes) != 1:
        raise ValueError("BOOLEAN must length 1 bytes")
    return boolean_bytes[0] != 0

def parse_octet_string(octet_bytes) -> bytes:
    return octet_bytes

def parse_null(null_bytes) -> None:
    if len(null_bytes) != 0:
        raise ValueError("NULL must length 0")
    return None

def parse_object_identifier(object_bytes) -> str:
    """Parse OBJECT IDENTIFIER"""
    if len(object_bytes) == 0:
        return ""

    oid_parts = []

    # First byte: X * 40 + Y
    first_byte = object_bytes[0]
    oid_parts.append(str(first_byte // 40))
    oid_parts.append(str(first_byte % 40))

    # Another bytes
    current_value = 0
    for i in range(1, len(object_bytes)):
        byte_val = object_bytes[i]
        current_value = (current_value << 7) | (byte_val & 0x7F)

        if not (byte_val & 0x80):  # Last bytes number
            oid_parts.append(str(current_value))
            current_value = 0

    return '.'.join(oid_parts)