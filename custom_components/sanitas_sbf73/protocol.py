"""Sanitas SBF73 BLE protocol: payload builders and parsers.

Pure Python, no Home Assistant or bleak import, so it can be unit tested alone.
The scale uses the standard Bluetooth SIG Weight Scale (0x181D), Body Composition
(0x181B) and User Data (0x181C) services, plus a vendor service for user list,
initials, activity level and measurement trigger.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
import struct


def _uuid16(short: int) -> str:
    return f"0000{short:04x}-0000-1000-8000-00805f9b34fb"


# Standard characteristics
CHR_BATTERY_LEVEL = _uuid16(0x2A19)
CHR_CURRENT_TIME = _uuid16(0x2A2B)
CHR_DATE_OF_BIRTH = _uuid16(0x2A85)
CHR_GENDER = _uuid16(0x2A8C)
CHR_HEIGHT = _uuid16(0x2A8E)
CHR_DB_CHANGE_INCREMENT = _uuid16(0x2A99)
CHR_BODY_COMPOSITION = _uuid16(0x2A9C)
CHR_WEIGHT_MEASUREMENT = _uuid16(0x2A9D)
CHR_USER_CONTROL_POINT = _uuid16(0x2A9F)

# Vendor characteristics (service 0xFFFF)
SVC_VENDOR = _uuid16(0xFFFF)
CHR_VENDOR_USER_LIST = _uuid16(0x0001)
CHR_VENDOR_INITIALS = _uuid16(0x0002)
CHR_VENDOR_ACTIVITY_LEVEL = _uuid16(0x0004)
CHR_VENDOR_TAKE_MEASUREMENT = _uuid16(0x0006)

# User Control Point op codes and response values (Bluetooth UDS spec)
UCP_REGISTER_NEW_USER = 0x01
UCP_CONSENT = 0x02
UCP_RESPONSE = 0x20

UCP_SUCCESS = 0x01
UCP_NOT_SUPPORTED = 0x02
UCP_INVALID_PARAMETER = 0x03
UCP_OPERATION_FAILED = 0x04
UCP_USER_NOT_AUTHORIZED = 0x05

UCP_RESULT_NAMES = {
    UCP_SUCCESS: "success",
    UCP_NOT_SUPPORTED: "op code not supported",
    UCP_INVALID_PARAMETER: "invalid parameter",
    UCP_OPERATION_FAILED: "operation failed (user limit reached?)",
    UCP_USER_NOT_AUTHORIZED: "user not authorized (wrong PIN?)",
}

# The vendor user list characteristic answers a `00` write with one notification
# per user (first byte 0x00), then a status byte.
USER_LIST_COMPLETE = 0x01
USER_LIST_FAILED = 0x02
# Writing 0x10 + user index asks the scale to show that user's PIN on its display.
# It answers 0x11 (PIN shown) or 0x12 (failed) on the same characteristic.
USER_LIST_SHOW_PIN_BASE = 0x10
PIN_SHOWN = 0x11
PIN_FAILED = 0x12
MAX_USERS = 8

# Take Measurement (0x0006) answers
TAKE_MEASUREMENT_OK = 0x01
TAKE_MEASUREMENT_NOT_AUTHORIZED = 0x04

GENDER_MALE = 0
GENDER_FEMALE = 1


class ProtocolError(Exception):
    """A payload could not be parsed."""


@dataclass
class UcpResponse:
    request: int
    result: int
    user_index: int | None = None

    @property
    def ok(self) -> bool:
        return self.result == UCP_SUCCESS

    @property
    def result_name(self) -> str:
        return UCP_RESULT_NAMES.get(self.result, f"0x{self.result:02x}")


@dataclass
class ScaleUser:
    index: int
    initials: str
    birth_date: date | None
    height_cm: int
    gender: int
    activity_level: int


@dataclass
class Measurement:
    """One weighing, merged from the weight and body composition indications."""

    timestamp: datetime | None = None
    user_index: int | None = None
    weight_kg: float | None = None
    bmi: float | None = None
    height_m: float | None = None
    fat_pct: float | None = None
    bmr_kcal: float | None = None
    muscle_pct: float | None = None
    muscle_mass_kg: float | None = None
    fat_free_mass_kg: float | None = None
    soft_lean_mass_kg: float | None = None
    water_mass_kg: float | None = None
    impedance_ohm: float | None = None
    extra: dict[str, float] = field(default_factory=dict)

    def merge(self, other: Measurement) -> None:
        for name, value in vars(other).items():
            if value is not None and name != "extra":
                setattr(self, name, value)
        self.extra.update(other.extra)

    @property
    def water_pct(self) -> float | None:
        if self.water_mass_kg is None or not self.weight_kg:
            return None
        return round(self.water_mass_kg / self.weight_kg * 100, 1)

    @property
    def bone_mass_kg(self) -> float | None:
        """Bone mass as the app computes it: weight - fat mass - soft lean mass."""
        if not self.weight_kg or not self.fat_pct or self.soft_lean_mass_kg is None:
            return None
        fat_mass = self.weight_kg * self.fat_pct / 100
        return round(self.weight_kg - fat_mass - self.soft_lean_mass_kg, 2)


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = bytes(data)
        self.pos = 0

    def take(self, fmt: str) -> int:
        size = struct.calcsize(fmt)
        if self.pos + size > len(self.data):
            raise ProtocolError(
                f"payload too short ({len(self.data)} bytes): {self.data.hex()}"
            )
        (value,) = struct.unpack_from(fmt, self.data, self.pos)
        self.pos += size
        return value

    def u8(self) -> int:
        return self.take("<B")

    def u16(self) -> int:
        return self.take("<H")

    def date_time(self) -> datetime | None:
        year, month, day = self.u16(), self.u8(), self.u8()
        hour, minute, second = self.u8(), self.u8(), self.u8()
        if year == 0 or month == 0 or day == 0:
            return None
        return datetime(year, month, day, hour, minute, second)


def parse_weight(data: bytes) -> Measurement:
    """Parse a Weight Measurement (0x2A9D) indication."""
    r = _Reader(data)
    flags = r.u8()
    imperial = bool(flags & 0x01)
    raw_weight = r.u16()
    m = Measurement(
        weight_kg=round(raw_weight * 0.01 * 0.45359237, 2)
        if imperial
        else round(raw_weight * 0.005, 2)
    )
    if flags & 0x02:
        m.timestamp = r.date_time()
    if flags & 0x04:
        m.user_index = r.u8()
    if flags & 0x08:
        m.bmi = round(r.u16() * 0.1, 1)
        raw_height = r.u16()
        m.height_m = round(raw_height * 0.1 * 0.0254 if imperial else raw_height * 0.001, 3)
    return m


def parse_body_composition(data: bytes) -> Measurement:
    """Parse a Body Composition Measurement (0x2A9C) indication."""
    r = _Reader(data)
    flags = r.u16()
    imperial = bool(flags & 0x0001)
    mass = 0.01 * 0.45359237 if imperial else 0.005
    m = Measurement(fat_pct=round(r.u16() * 0.1, 1))
    if flags & 0x0002:
        m.timestamp = r.date_time()
    if flags & 0x0004:
        m.user_index = r.u8()
    if flags & 0x0008:
        m.bmr_kcal = round(r.u16() / 4.1868)  # transmitted in kJ
    if flags & 0x0010:
        m.muscle_pct = round(r.u16() * 0.1, 1)
    if flags & 0x0020:
        m.muscle_mass_kg = round(r.u16() * mass, 2)
    if flags & 0x0040:
        m.fat_free_mass_kg = round(r.u16() * mass, 2)
    if flags & 0x0080:
        m.soft_lean_mass_kg = round(r.u16() * mass, 2)
    if flags & 0x0100:
        m.water_mass_kg = round(r.u16() * mass, 2)
    if flags & 0x0200:
        m.impedance_ohm = round(r.u16() * 0.1, 1)
    if flags & 0x0400:
        m.weight_kg = round(r.u16() * mass, 2)
    if flags & 0x0800:
        raw_height = r.u16()
        m.height_m = round(raw_height * 0.1 * 0.0254 if imperial else raw_height * 0.001, 3)
    if not m.fat_pct and not m.impedance_ohm:
        # All zeros: the scale could not measure impedance (socks, dry feet).
        return Measurement(timestamp=m.timestamp, user_index=m.user_index)
    return m


def parse_ucp_response(data: bytes) -> UcpResponse:
    """Parse a User Control Point (0x2A9F) indication."""
    r = _Reader(data)
    if r.u8() != UCP_RESPONSE:
        raise ProtocolError(f"not a UCP response: {bytes(data).hex()}")
    resp = UcpResponse(request=r.u8(), result=r.u8())
    if resp.request == UCP_REGISTER_NEW_USER and resp.ok:
        resp.user_index = r.u8()
    return resp


def parse_user_list_entry(data: bytes) -> ScaleUser | int:
    """Parse a vendor user list (0x0001) notification.

    Returns a ScaleUser, or the status byte (USER_LIST_COMPLETE, USER_LIST_FAILED,
    PIN_SHOWN, PIN_FAILED...). User layout: 0x00, index, 3 initials bytes,
    year u16, month, day, height cm u8, gender, activity level.
    """
    if not data:
        return USER_LIST_FAILED
    if data[0] != 0x00 or len(data) < 12:
        return data[0]
    r = _Reader(data)
    r.u8()
    index = r.u8()
    raw = bytes(r.data[2:5])
    r.pos = 5
    initials = "" if raw == b"\xff\xff\xff" else raw.decode("ascii", "replace").strip("\x00 ")
    year, month, day = r.u16(), r.u8(), r.u8()
    try:
        birth = date(year, month, day)
    except ValueError:
        birth = None
    return ScaleUser(
        index=index,
        initials=initials,
        birth_date=birth,
        height_cm=r.u8(),
        gender=r.u8(),
        activity_level=r.u8(),
    )


def build_register_new_user(consent_code: int) -> bytes:
    return struct.pack("<BH", UCP_REGISTER_NEW_USER, _check_consent(consent_code))


def build_consent(user_index: int, consent_code: int) -> bytes:
    return struct.pack("<BBH", UCP_CONSENT, user_index, _check_consent(consent_code))


def build_current_time(now: datetime) -> bytes:
    return struct.pack(
        "<HBBBBBBBB",
        now.year,
        now.month,
        now.day,
        now.hour,
        now.minute,
        now.second,
        now.isoweekday(),  # 1 = Monday .. 7 = Sunday
        0,  # fractions256
        0,  # adjust reason
    )


def build_date_of_birth(birth: date) -> bytes:
    return struct.pack("<HBB", birth.year, birth.month, birth.day)


def build_gender(gender: int) -> bytes:
    return bytes([gender])


def build_height(height_cm: int) -> bytes:
    # One byte, like the official app (the UDS spec says uint16).
    return bytes([height_cm])


def build_activity_level(level: int) -> bytes:
    if not 1 <= level <= 5:
        raise ValueError("activity level must be between 1 and 5")
    return bytes([level])


def build_db_change_increment(value: int) -> bytes:
    return struct.pack("<I", value)


def build_initials(name: str) -> bytes:
    cleaned = "".join(c for c in name.upper() if c.isascii() and c.isalnum())
    return cleaned[:3].ljust(3).encode("ascii")


def _check_consent(code: int) -> int:
    if not 0 <= code <= 9999:
        raise ValueError("consent code must be between 0 and 9999")
    return code
