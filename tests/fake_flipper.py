"""
fake_flipper.py — a scripted stand-in for the Flipper Zero serial CLI.

Implements the small part of the pyserial interface that capture.FlipperCLI
uses, and answers commands with output shaped like the stock firmware's.
Lets the capture tool and the full pipeline be tested without hardware.
"""

PROMPT = b"\r\n>: "

SD_CARD = {
    "/ext/subghz/garage_remote.sub": (
        "Filetype: Flipper SubGhz Key File\nVersion: 1\nFrequency: 315000000\n"
        "Preset: FuriHalSubGhzPresetOok650Async\nProtocol: Princeton\nBit: 24\n"
        "Key: 00 00 00 00 00 5A 1C 33\nTE: 390\n"
    ),
    "/ext/lfrfid/badge.rfid": "Filetype: Flipper RFID key\nVersion: 1\nKey type: EM4100\nData: 55 00 82 48 06\n",
    "/ext/infrared/tv.ir": (
        "Filetype: IR signals file\nVersion: 1\n#\nname: Power\ntype: parsed\n"
        "protocol: NEC\naddress: 04 00 00 00\ncommand: 08 00 00 00\n"
    ),
}

LIVE = {
    "subghz rx 433920000 0": (
        "Listening at frequency: 433920000 device: 0\r\nPress CTRL+C to stop\r\n"
        "Princeton 24bit\r\nKey:0x00A12F44\r\nYek:0x0022F485\r\nSn:0x00A12F Btn:4\r\nTe:410us\r\n"
        "Princeton 24bit\r\nKey:0x00A12F44\r\nYek:0x0022F485\r\nSn:0x00A12F Btn:4\r\nTe:412us\r\n"
    ),
    "subghz rx 315000000 0": "Listening at frequency: 315000000 device: 0\r\nPress CTRL+C to stop\r\n",
    "rfid read": "Reading RFID...\r\nPress Ctrl+C to abort\r\nEM-Micro EM4100\r\n1C 00 3F 7A 21\r\n",
    "ikey read": "Reading iButton...\r\nPress Ctrl+C to abort\r\nDallas DS1990\r\n01 A2 B3 C4 D5 E6 F7 08\r\n",
    "ir rx": "Receiving INFRARED...\r\nPress Ctrl+C to abort\r\nNECext, A:0xEE87, C:0x5D\r\nNECext, A:0xEE87, C:0x5D R\r\n",
}

NFC_DUMP = (
    "Filetype: Flipper NFC device\nVersion: 4\nDevice type: Mifare Classic\n"
    "UID: 4A 3B 2C 1D\nATQA: 00 04\nSAK: 08\nMifare Classic type: 1K\n"
)

DEVICE_INFO = (
    "hardware_name        : Fake-Flip\r\nfirmware_version     : 1.4.3\r\n"
    "firmware_commit      : deadbeef\r\nradio_stack_major    : 1\r\n"
)


class FakeFlipperSerial:
    def __init__(self, fail_live=False):
        self._out = bytearray(b"Welcome to Flipper Zero Command Line Interface!" + PROMPT)
        self._line = bytearray()
        self._streaming = False
        self._nfc_shell = False
        self.fail_live = fail_live
        self.files = dict(SD_CARD)
        self.commands = []

    # -- pyserial surface ------------------------------------------------
    @property
    def in_waiting(self):
        return len(self._out)

    def read(self, n=1):
        chunk, self._out = bytes(self._out[:n]), self._out[n:]
        return chunk

    def reset_input_buffer(self):
        self._out.clear()

    def close(self):
        pass

    def write(self, data: bytes):
        for b in data:
            if b == 0x03:  # Ctrl+C
                if self._streaming:
                    self._streaming = False
                    self._out += PROMPT
            elif b == 0x0D:
                self._handle(self._line.decode())
                self._line.clear()
            else:
                self._line.append(b)
        return len(data)

    # -- command handling -----------------------------------------------
    def _reply(self, cmd, body, prompt=True):
        self._out += f"{cmd}\r\n{body}".encode()
        if prompt:
            self._out += b"[nfc]>: " if self._nfc_shell else PROMPT

    def _handle(self, cmd: str):
        cmd = cmd.strip()
        self.commands.append(cmd)
        if not cmd:
            self._out += PROMPT
        elif cmd == "info device":
            self._reply(cmd, DEVICE_INFO)
        elif cmd.startswith("storage list "):
            folder = cmd.split(" ", 2)[2]
            rows = [f"\t[F] {p.rsplit('/', 1)[1]} {len(c)}b" for p, c in self.files.items()
                    if p.rsplit("/", 1)[0] == folder]
            self._reply(cmd, "\r\n".join(rows) or "\tEmpty")
        elif cmd.startswith("storage read "):
            path = cmd.split(" ", 2)[2]
            c = self.files.get(path)
            body = f"Size: {len(c)}\r\n{c.replace(chr(10), chr(13) + chr(10))}" if c else "Storage error: file/dir not exist"
            self._reply(cmd, body)
        elif cmd == "nfc":
            self._nfc_shell = True
            self._reply(cmd, "")
        elif cmd == "exit" and self._nfc_shell:
            self._nfc_shell = False
            self._reply(cmd, "")
        elif self._nfc_shell and cmd.startswith("dump"):
            path = cmd.split("-f ", 1)[1].split()[0]
            self.files[path] = NFC_DUMP
            self._reply(cmd, f"Dumped to {path}")
        elif cmd in LIVE:
            if self.fail_live:
                self._reply(cmd, "")
                return
            self._streaming = True
            self._reply(cmd, LIVE[cmd], prompt=False)
        else:
            self._reply(cmd, f"`{cmd.split()[0]}` command not found")
