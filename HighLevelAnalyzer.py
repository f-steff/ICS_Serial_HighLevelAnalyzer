"""
ICS Scope UART High Level Analyzer

Decodes ICS command (host→target) frames, responses (target→host),
and streaming scope packets (H_CODE_MODE*).
Run on top of a UART analyzer (8-N-1).
"""

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame

# Header codes (from ICS.c)
H_CODE_ACK = 0xA5
H_CODE_NAK = 0xC5
H_CODE_MODE1_1 = 0x66
H_CODE_MODE1_2 = 0x67
H_CODE_MODE2 = 0x68
H_CODE_MODE3_1 = 0x69
H_CODE_MODE3_2 = 0x6A
H_CODE_MODE3_3 = 0x6B
# Defined but not emitted in this port: 0x65 (MODE0), 0x6D..0x72 (MODE4/5)

CMD_NAMES = {
    3: "CPU name",
    4: "LIB version",
    5: "Read 8-bit",
    6: "Read 16-bit",
    7: "Read 32-bit",
    8: "Write 8-bit",
    9: "Write 16-bit",
    10: "Write 32-bit",
    11: "Check rightfulness",
    32: "Scope support1",
    34: "Set scope channel",
}

HDR_NAMES = {
    H_CODE_ACK: "ACK",
    H_CODE_NAK: "NAK",
    H_CODE_MODE1_1: "MODE1_1 (8ch, first half)",
    H_CODE_MODE1_2: "MODE1_2 (8ch, second half)",
    H_CODE_MODE2: "MODE2 (4ch once)",
    H_CODE_MODE3_1: "MODE3_1 (12ch, part 1)",
    H_CODE_MODE3_2: "MODE3_2 (12ch, part 2)",
    H_CODE_MODE3_3: "MODE3_3 (12ch, part 3)",
}


def le32(buf, offset):
    return (
        buf[offset]
        | (buf[offset + 1] << 8)
        | (buf[offset + 2] << 16)
        | (buf[offset + 3] << 24)
    ) & 0xFFFFFFFF


def xor_bytes(buf):
    v = 0
    for b in buf:
        v ^= b
    return v & 0xFF


def fmt_payload(payload_bytes):
    hex_str = " ".join(f"{b:02X}" for b in payload_bytes)
    ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in payload_bytes)
    return f"len={len(payload_bytes)} hex=[{hex_str}] ascii='{ascii_str}'"


class PacketAssembler:
    def __init__(self):
        self.reset()

    def reset(self):
        self.buf = []
        self.expected_len = None
        self.kind = None
        self.start_time = None

    def feed(self, byte, frame):
        if not self.buf:
            if byte == 0xAA:
                self.kind = "cmd"
                self.expected_len = 12
            elif byte in HDR_NAMES:
                self.kind = "resp"
                self.expected_len = 18
            else:
                return None
            self.start_time = frame.start_time

        self.buf.append(byte)
        end_time = frame.end_time

        if self.expected_len and len(self.buf) == self.expected_len:
            pkt = (self.kind, self.buf, self.start_time, end_time)
            self.reset()
            return pkt
        return None


class HlaBase(HighLevelAnalyzer):
    """
    Base HLA: run on top of a UART analyzer (8-N-1, matching ICS baud).
    """

    result_types = {
        "ics_cmd": {"format": "ICS CMD {{data.cmd_name}} d1={{data.d1}} d2={{data.d2}} chk={{data.checksum_ok}}"},
        "ics_resp": {"format": "ICS RESP {{data.header_name}} {{data.summary}} chk={{data.checksum_ok}}"},
        "ics_stream": {"format": "ICS STREAM {{data.header_name}} ch={{data.channels_str}} chk={{data.checksum_ok}}"},
        "ics_nak": {"format": "ICS NAK err={{data.error_hex}}"},
    }

    def __init__(self):
        self.asm = PacketAssembler()

    def decode(self, frame: AnalyzerFrame):
        if frame.type != "data":
            return None
        b = frame.data.get("data", None)
        if b is None:
            return None
        byte = b if isinstance(b, int) else b[0]

        pkt = self.asm.feed(byte, frame)
        if not pkt:
            return None

        kind, buf, start, end = pkt
        if kind == "cmd":
            return self._decode_cmd(buf, start, end)
        return self._decode_resp(buf, start, end)

    def _decode_cmd(self, buf, start, end):
        checksum_ok = xor_bytes(buf) == 0xFF
        cmd = buf[2]
        d1 = le32(buf, 4)
        d2 = le32(buf, 8)
        cmd_name = CMD_NAMES.get(cmd, f"Unknown ({cmd})")
        data = {
            "cmd": int(cmd),
            "cmd_name": cmd_name,
            "d1": int(d1),
            "d2": int(d2),
            "checksum_ok": bool(checksum_ok),
        }
        return AnalyzerFrame("ics_cmd", start, end, data)

    def _decode_resp(self, buf, start, end):
        header = int(buf[0])
        header_name = HDR_NAMES.get(header, f"Header 0x{header:02X}")
        checksum_ok = xor_bytes(buf) == 0xFF

        # Stream packets (mode headers)
        if header in {H_CODE_MODE1_1, H_CODE_MODE1_2, H_CODE_MODE2, H_CODE_MODE3_1, H_CODE_MODE3_2, H_CODE_MODE3_3}:
            channels = []
            payload = buf[2:18]
            for i in range(0, len(payload), 4):
                channels.append(le32(payload, i))
            return AnalyzerFrame(
                "ics_stream",
                start,
                end,
                {
                    "header": header,
                    "header_name": header_name,
                    "channels_str": "[" + ", ".join(f"0x{x:08X}" for x in channels) + "]",
                    "checksum_ok": bool(checksum_ok),
                },
            )

        # NAK with error code in b[4]
        if header == H_CODE_NAK:
            err = int(buf[4]) if len(buf) > 4 else 0
            payload = buf[2:]
            return AnalyzerFrame(
                "ics_nak",
                start,
                end,
                {
                    "header": header,
                    "header_name": header_name,
                    "error": err,
                    "error_hex": f"0x{err:02X}",
                    "checksum_ok": bool(checksum_ok),
                    "summary": f"err=0x{err:02X} {fmt_payload(payload)}",
                },
            )

        # Generic ACK/other: summarize payload
        if header == H_CODE_ACK and len(buf) >= 6:
            payload = buf[4:]
            parts = []
            if len(payload) >= 4:
                parts.append(f"u32=0x{le32(payload,0):08X}")
                if len(payload) > 4 and any(b != 0 for b in payload[4:]):
                    parts.append(f"tail=[{fmt_payload(payload[4:])}]")
            elif len(payload) >= 2:
                val16 = payload[0] | (payload[1] << 8)
                parts.append(f"u16=0x{val16:04X}")
                if len(payload) > 2 and any(b != 0 for b in payload[2:]):
                    parts.append(f"tail=[{fmt_payload(payload[2:])}]")
            else:
                parts.append(f"payload=[{fmt_payload(payload)}]")
            summary = " ".join(parts)
        else:
            payload = buf[2:]
            summary = fmt_payload(payload)

        return AnalyzerFrame(
            "ics_resp",
            start,
            end,
            {"header": header, "header_name": header_name, "summary": summary, "checksum_ok": bool(checksum_ok)},
        )


class HlaRx(HlaBase):
    """Expose for UART RX (host->target)."""
    pass


class HlaTx(HlaBase):
    """Expose for UART TX (target->host)."""
    pass


class HlaTxRespOnly(HlaBase):
    """
    TX-side decoder that ignores streaming packets (H_CODE_MODE*).
    Useful if you want a clean view of ACK/NAK responses only.
    """

    def _decode_resp(self, buf, start, end):
        header = int(buf[0])
        header_name = HDR_NAMES.get(header, f"Header 0x{header:02X}")
        checksum_ok = xor_bytes(buf) == 0xFF

        # Skip stream packets entirely
        if header in {H_CODE_MODE1_1, H_CODE_MODE1_2, H_CODE_MODE2, H_CODE_MODE3_1, H_CODE_MODE3_2, H_CODE_MODE3_3}:
            return None

        if header == H_CODE_NAK:
            err = int(buf[4]) if len(buf) > 4 else 0
            payload = buf[2:]
            return AnalyzerFrame(
                "ics_nak",
                start,
                end,
                {
                    "header": header,
                    "header_name": header_name,
                    "error": err,
                    "error_hex": f"0x{err:02X}",
                    "checksum_ok": bool(checksum_ok),
                    "summary": f"err=0x{err:02X} {fmt_payload(payload)}",
                },
            )

        if header == H_CODE_ACK and len(buf) >= 6:
            payload = buf[4:]
            parts = []
            if len(payload) >= 4:
                parts.append(f"u32=0x{le32(payload,0):08X}")
                if len(payload) > 4 and any(b != 0 for b in payload[4:]):
                    parts.append(f"tail=[{fmt_payload(payload[4:])}]")
            elif len(payload) >= 2:
                val16 = payload[0] | (payload[1] << 8)
                parts.append(f"u16=0x{val16:04X}")
                if len(payload) > 2 and any(b != 0 for b in payload[2:]):
                    parts.append(f"tail=[{fmt_payload(payload[2:])}]")
            else:
                parts.append(f"payload=[{fmt_payload(payload)}]")
            summary = " ".join(parts)
        else:
            payload = buf[2:]
            summary = fmt_payload(payload)

        return AnalyzerFrame(
            "ics_resp",
            start,
            end,
            {"header": header, "header_name": header_name, "summary": summary, "checksum_ok": bool(checksum_ok)},
        )


class HlaTxStreamOnly(HlaBase):
    """
    TX-side decoder that only emits streaming packets (H_CODE_MODE*).
    Useful if you want a clean view of scope samples without protocol responses.
    """

    def _decode_resp(self, buf, start, end):
        header = int(buf[0])
        header_name = HDR_NAMES.get(header, f"Header 0x{header:02X}")
        checksum_ok = xor_bytes(buf) == 0xFF

        if header not in {H_CODE_MODE1_1, H_CODE_MODE1_2, H_CODE_MODE2, H_CODE_MODE3_1, H_CODE_MODE3_2, H_CODE_MODE3_3}:
            return None

        channels = []
        payload = buf[2:18]
        for i in range(0, len(payload), 4):
            channels.append(le32(payload, i))
        return AnalyzerFrame(
            "ics_stream",
            start,
            end,
            {
                "header": header,
                "header_name": header_name,
                "channels_str": "[" + ", ".join(f"0x{x:08X}" for x in channels) + "]",
                "checksum_ok": bool(checksum_ok),
            },
        )
