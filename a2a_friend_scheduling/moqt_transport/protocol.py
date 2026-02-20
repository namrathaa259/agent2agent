"""
MOQT (Media over QUIC Transport) Protocol Implementation
Based on draft-ietf-moq-transport-14 and draft-a2a-moqt-transport-00

Wire format: QUIC variable-length integers (RFC 9000 §16)
Control messages: type (varint) + length (varint) + payload
OBJECT_STREAM:  type (varint) + fields + raw payload (no length, fills stream)
"""

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MOQT_ALPN = "moq-00"
MOQT_VERSION = 0xFF00000E  # draft-14

A2A_NAMESPACE = ["a2a"]  # root namespace for all A2A traffic


class MsgType(IntEnum):
    OBJECT_STREAM = 0x00
    OBJECT_DATAGRAM = 0x01
    SUBSCRIBE_UPDATE = 0x02
    SUBSCRIBE = 0x03
    SUBSCRIBE_OK = 0x04
    SUBSCRIBE_ERROR = 0x05
    ANNOUNCE = 0x06
    ANNOUNCE_OK = 0x07
    ANNOUNCE_ERROR = 0x08
    UNANNOUNCE = 0x09
    UNSUBSCRIBE = 0x0A
    SUBSCRIBE_DONE = 0x0B
    ANNOUNCE_CANCEL = 0x0C
    TRACK_STATUS_REQUEST = 0x0D
    TRACK_STATUS = 0x0E
    GOAWAY = 0x10
    MAX_SUBSCRIBE_ID = 0x15
    SUBSCRIBE_NAMESPACE = 0x16
    SUBSCRIBE_NAMESPACE_OK = 0x17
    SUBSCRIBE_NAMESPACE_ERROR = 0x18
    CLIENT_SETUP = 0x40
    SERVER_SETUP = 0x41
    STREAM_HEADER_TRACK = 0x50
    STREAM_HEADER_GROUP = 0x51


class FilterType(IntEnum):
    LATEST_GROUP = 0x01
    LATEST_OBJECT = 0x02
    ABSOLUTE_START = 0x03
    ABSOLUTE_RANGE = 0x04


class GroupOrder(IntEnum):
    DEFAULT = 0x00
    ASCENDING = 0x01
    DESCENDING = 0x02


# ---------------------------------------------------------------------------
# Varint encoding/decoding (RFC 9000 §16)
# ---------------------------------------------------------------------------

def encode_varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    elif value < 0x4000:
        return struct.pack(">H", value | 0x4000)
    elif value < 0x40000000:
        return struct.pack(">I", value | 0x80000000)
    elif value < 0x4000000000000000:
        return struct.pack(">Q", value | 0xC000000000000000)
    else:
        raise ValueError(f"Varint value too large: {value}")


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    if offset >= len(data):
        raise BufferError("Not enough data for varint")
    b = data[offset]
    prefix = b >> 6
    if prefix == 0:
        return b & 0x3F, offset + 1
    elif prefix == 1:
        if offset + 2 > len(data):
            raise BufferError("Need 2 bytes for varint")
        return struct.unpack_from(">H", data, offset)[0] & 0x3FFF, offset + 2
    elif prefix == 2:
        if offset + 4 > len(data):
            raise BufferError("Need 4 bytes for varint")
        return struct.unpack_from(">I", data, offset)[0] & 0x3FFFFFFF, offset + 4
    else:
        if offset + 8 > len(data):
            raise BufferError("Need 8 bytes for varint")
        return struct.unpack_from(">Q", data, offset)[0] & 0x3FFFFFFFFFFFFFFF, offset + 8


# ---------------------------------------------------------------------------
# String / bytes / tuple helpers
# ---------------------------------------------------------------------------

def encode_bytes_field(data: bytes) -> bytes:
    return encode_varint(len(data)) + data


def decode_bytes_field(data: bytes, offset: int) -> tuple[bytes, int]:
    length, offset = decode_varint(data, offset)
    return bytes(data[offset: offset + length]), offset + length


def encode_string(s: str) -> bytes:
    return encode_bytes_field(s.encode("utf-8"))


def decode_string(data: bytes, offset: int) -> tuple[str, int]:
    raw, offset = decode_bytes_field(data, offset)
    return raw.decode("utf-8"), offset


def encode_tuple(parts: list[str]) -> bytes:
    """Encode a MOQT Tuple (§ 2 of draft-14): count + length-prefixed strings."""
    out = encode_varint(len(parts))
    for p in parts:
        out += encode_string(p)
    return out


def decode_tuple(data: bytes, offset: int) -> tuple[list[str], int]:
    count, offset = decode_varint(data, offset)
    parts = []
    for _ in range(count):
        s, offset = decode_string(data, offset)
        parts.append(s)
    return parts, offset


# ---------------------------------------------------------------------------
# Control-message framing
# ---------------------------------------------------------------------------

def frame_message(msg_type: MsgType, payload: bytes) -> bytes:
    """Wrap payload in MOQT control-message framing: type + length + payload."""
    return encode_varint(msg_type) + encode_varint(len(payload)) + payload


def parse_control_message(data: bytes, offset: int = 0) -> tuple[MsgType, bytes, int]:
    """
    Parse one MOQT control message from a byte buffer.
    Returns (msg_type, payload_bytes, new_offset).
    Raises BufferError if the buffer is incomplete.
    """
    msg_type_val, offset = decode_varint(data, offset)
    length, offset = decode_varint(data, offset)
    if offset + length > len(data):
        raise BufferError("Incomplete MOQT message payload")
    payload = bytes(data[offset: offset + length])
    return MsgType(msg_type_val), payload, offset + length


# ---------------------------------------------------------------------------
# MOQT Message dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ClientSetup:
    supported_versions: list[int]
    role: int = 3  # 0x01=publisher 0x02=subscriber 0x03=pub+sub

    def encode(self) -> bytes:
        payload = encode_varint(len(self.supported_versions))
        for v in self.supported_versions:
            payload += encode_varint(v)
        # One parameter: ROLE (key=0x00), varint value
        role_param = encode_varint(0x00) + encode_varint(1) + encode_varint(self.role)
        payload += encode_varint(1) + role_param
        return frame_message(MsgType.CLIENT_SETUP, payload)

    @classmethod
    def decode(cls, payload: bytes) -> "ClientSetup":
        offset = 0
        count, offset = decode_varint(payload, offset)
        versions = []
        for _ in range(count):
            v, offset = decode_varint(payload, offset)
            versions.append(v)
        param_count, offset = decode_varint(payload, offset)
        role = 3
        for _ in range(param_count):
            key, offset = decode_varint(payload, offset)
            length, offset = decode_varint(payload, offset)
            if key == 0x00:
                role, _ = decode_varint(payload, offset)
            offset += length
        return cls(supported_versions=versions, role=role)


@dataclass
class ServerSetup:
    selected_version: int
    role: int = 3

    def encode(self) -> bytes:
        payload = encode_varint(self.selected_version)
        role_param = encode_varint(0x00) + encode_varint(1) + encode_varint(self.role)
        payload += encode_varint(1) + role_param
        return frame_message(MsgType.SERVER_SETUP, payload)

    @classmethod
    def decode(cls, payload: bytes) -> "ServerSetup":
        offset = 0
        version, offset = decode_varint(payload, offset)
        param_count, offset = decode_varint(payload, offset)
        role = 3
        for _ in range(param_count):
            key, offset = decode_varint(payload, offset)
            length, offset = decode_varint(payload, offset)
            if key == 0x00:
                role, _ = decode_varint(payload, offset)
            offset += length
        return cls(selected_version=version, role=role)


@dataclass
class Announce:
    namespace: list[str]

    def encode(self) -> bytes:
        payload = encode_tuple(self.namespace) + encode_varint(0)  # 0 params
        return frame_message(MsgType.ANNOUNCE, payload)

    @classmethod
    def decode(cls, payload: bytes) -> "Announce":
        ns, _ = decode_tuple(payload, 0)
        return cls(namespace=ns)


@dataclass
class AnnounceOk:
    namespace: list[str]

    def encode(self) -> bytes:
        return frame_message(MsgType.ANNOUNCE_OK, encode_tuple(self.namespace))

    @classmethod
    def decode(cls, payload: bytes) -> "AnnounceOk":
        ns, _ = decode_tuple(payload, 0)
        return cls(namespace=ns)


@dataclass
class Subscribe:
    subscribe_id: int
    track_alias: int
    namespace: list[str]
    track_name: str
    subscriber_priority: int = 128
    group_order: GroupOrder = GroupOrder.ASCENDING
    filter_type: FilterType = FilterType.LATEST_OBJECT

    def encode(self) -> bytes:
        payload = (
            encode_varint(self.subscribe_id)
            + encode_varint(self.track_alias)
            + encode_tuple(self.namespace)
            + encode_string(self.track_name)
            + encode_varint(self.subscriber_priority)
            + encode_varint(self.group_order)
            + encode_varint(self.filter_type)
            + encode_varint(0)  # 0 params
        )
        return frame_message(MsgType.SUBSCRIBE, payload)

    @classmethod
    def decode(cls, payload: bytes) -> "Subscribe":
        offset = 0
        sub_id, offset = decode_varint(payload, offset)
        alias, offset = decode_varint(payload, offset)
        ns, offset = decode_tuple(payload, offset)
        name, offset = decode_string(payload, offset)
        priority, offset = decode_varint(payload, offset)
        order, offset = decode_varint(payload, offset)
        ftype, offset = decode_varint(payload, offset)
        return cls(
            subscribe_id=sub_id,
            track_alias=alias,
            namespace=ns,
            track_name=name,
            subscriber_priority=priority,
            group_order=GroupOrder(order),
            filter_type=FilterType(ftype),
        )


@dataclass
class SubscribeOk:
    subscribe_id: int
    expires: int = 0
    group_order: GroupOrder = GroupOrder.ASCENDING
    content_exists: bool = False

    def encode(self) -> bytes:
        payload = (
            encode_varint(self.subscribe_id)
            + encode_varint(self.expires)
            + encode_varint(self.group_order)
            + bytes([0x01 if self.content_exists else 0x00])
            + encode_varint(0)  # 0 params
        )
        return frame_message(MsgType.SUBSCRIBE_OK, payload)

    @classmethod
    def decode(cls, payload: bytes) -> "SubscribeOk":
        offset = 0
        sub_id, offset = decode_varint(payload, offset)
        expires, offset = decode_varint(payload, offset)
        order, offset = decode_varint(payload, offset)
        content_exists = payload[offset] == 0x01
        return cls(
            subscribe_id=sub_id,
            expires=expires,
            group_order=GroupOrder(order),
            content_exists=content_exists,
        )


@dataclass
class SubscribeNamespace:
    namespace_prefix: list[str]

    def encode(self) -> bytes:
        payload = encode_tuple(self.namespace_prefix) + encode_varint(0)
        return frame_message(MsgType.SUBSCRIBE_NAMESPACE, payload)

    @classmethod
    def decode(cls, payload: bytes) -> "SubscribeNamespace":
        ns, _ = decode_tuple(payload, 0)
        return cls(namespace_prefix=ns)


@dataclass
class SubscribeNamespaceOk:
    namespace_prefix: list[str]

    def encode(self) -> bytes:
        return frame_message(MsgType.SUBSCRIBE_NAMESPACE_OK, encode_tuple(self.namespace_prefix))

    @classmethod
    def decode(cls, payload: bytes) -> "SubscribeNamespaceOk":
        ns, _ = decode_tuple(payload, 0)
        return cls(namespace_prefix=ns)


@dataclass
class ObjectStream:
    """
    OBJECT_STREAM (0x00) — sent on its own unidirectional QUIC stream.
    Header fields come first (no length prefix); payload fills the rest of the stream.
    """
    subscribe_id: int
    track_alias: int
    group_id: int
    object_id: int
    publisher_priority: int
    object_payload: bytes

    def encode(self) -> bytes:
        header = (
            encode_varint(MsgType.OBJECT_STREAM)
            + encode_varint(self.subscribe_id)
            + encode_varint(self.track_alias)
            + encode_varint(self.group_id)
            + encode_varint(self.object_id)
            + encode_varint(self.publisher_priority)
        )
        return header + self.object_payload

    @classmethod
    def decode(cls, data: bytes) -> "ObjectStream":
        """Decode from stream bytes AFTER the message-type varint has been consumed."""
        offset = 0
        sub_id, offset = decode_varint(data, offset)
        alias, offset = decode_varint(data, offset)
        group_id, offset = decode_varint(data, offset)
        obj_id, offset = decode_varint(data, offset)
        priority, offset = decode_varint(data, offset)
        return cls(
            subscribe_id=sub_id,
            track_alias=alias,
            group_id=group_id,
            object_id=obj_id,
            publisher_priority=priority,
            object_payload=bytes(data[offset:]),
        )


# ---------------------------------------------------------------------------
# A2A Track-namespace helpers  (draft-a2a-moqt-transport-00 §3.2)
# ---------------------------------------------------------------------------

def request_track(agent_id: str) -> tuple[list[str], str]:
    """Track the HOST publishes requests on → agent reads."""
    return (["a2a"], f"agent-{agent_id}/request")


def response_track(agent_id: str) -> tuple[list[str], str]:
    """Track the AGENT publishes responses on → host reads."""
    return (["a2a"], f"agent-{agent_id}/response")


def discovery_track(agent_id: str) -> tuple[list[str], str]:
    """Track the AGENT publishes its AgentCard on."""
    return (["a2a", "discovery"], f"agent-{agent_id}")


def stream_track(agent_id: str, task_id: str) -> tuple[list[str], str]:
    """Track for streaming task updates."""
    return (["a2a"], f"agent-{agent_id}/task_{task_id}")



