# Demo Assessment — Sample Captures
**Generated:** 2026-09-29 17:50Z  
**Framework:** Flipper Security Framework  
**Tool:** Flipper Zero + Python Analysis Pipeline  
**Identifiers:** shown in full

---

## Executive Summary

| Total Captures | CRITICAL | HIGH | MEDIUM | LOW | INFO |
|---|---|---|---|---|---|
| 8 | 1 | 3 | 2 | 2 | 0 |

**Overall Risk Posture:** 🔴 **CRITICAL**

---

## Replay-Resistance Checks

**🟢 Replay-resistance check: code changes on every press — rolling code behavior** (433.92 MHz)

> Separate button presses produced packets with the same structure but different content, so a recorded press cannot simply be replayed. Residual risk: jam-and-replay (RollJam) and relay attacks, which this check does not test.

| Recording A | Recording B | Packet similarity | Result |
|---|---|---|---|
| `car_fob_raw_press1.sub` | `car_fob_raw_press2.sub` | 83% | changed |

**Recommended Mitigations:**
- No action needed against simple replay
- Consider a signal-blocking pouch if relay attacks on keyless entry are a concern

*Method: repeated packets are extracted from each RAW recording and compared after normalizing pulse widths. Assumes the recordings are the same transmitter.*

---

## Findings

### Finding 1 — 🔴 CRITICAL | `office_badge.rfid` (RFID)

**Capture Details:**
- **Card Type:** `H10301`
- **Uid:** `1C 3F 7A`

**🔴 125 kHz proximity credential detected — no encryption**

> 125 kHz LF credentials (EM4100, HID Prox/H10301, Indala, AWID, ...) have no encryption or authentication. The ID can be read and cloned in seconds, sometimes from several feet away with a long-range reader.

**Recommended Mitigations:**
- Migrate to 13.56 MHz credentials with mutual authentication (DESFire EV2/EV3, iCLASS SE, SEOS)
- Pair the badge with a second factor (PIN or biometric) at sensitive doors
- Deploy anti-cloning card sleeves as an interim measure

---

### Finding 2 — 🟠 HIGH | `garage_door.sub` (SUBGHZ)

**Capture Details:**
- **Protocol:** `Princeton`
- **Frequency:** `433920000`
- **Preset:** `FuriHalSubGhzPresetOok650Async`
- **Key:** `00 00 00 00 00 A1 2F 44`

**🟠 Fixed-code remote detected — replayable**

> Fixed-code protocols send the same code on every press. Anyone within radio range can record one press and replay it to operate the device.

**Recommended Mitigations:**
- Replace with rolling-code (KeeLoq, Security+ 2.0) or challenge-response systems
- Implement RF jamming detection on entry systems
- Audit which devices in scope use this protocol

**🟡 433 MHz transmission captured**

> 433 MHz is a common unencrypted ISM band used by many consumer IoT devices, sensors, and remote controls. Traffic may be unencrypted.

**Recommended Mitigations:**
- Identify device owner and model
- Assess whether traffic contains sensitive operational data
- Consider RF shielding for sensitive areas

---

### Finding 3 — 🟠 HIGH | `access_card.nfc` (NFC)

**Capture Details:**
- **Card Type:** `Mifare Classic 1K`
- **Uid:** `4A 3B 2C 1D`
- **Atqa:** `00 04`
- **Sak:** `08`

**🟠 Mifare Classic card detected — known cryptographic weakness**

> Mifare Classic uses the broken CRYPTO1 cipher. Cards can be cloned with commodity hardware. Widely used in access control and transit systems.

**Recommended Mitigations:**
- Replace with Mifare DESFire EV2/EV3 or ICODE SLIX2
- Implement mutual authentication at the reader level
- Audit all access control readers using this card type

---

### Finding 4 — 🟠 HIGH | `door_key.ibtn` (IBUTTON)

**Capture Details:**
- **Protocol:** `DS1990`
- **Key Data:** `01 A2 B3 C4 D5 E6 F7 08`

**🟠 iButton contact key detected — clonable**

> Dallas/Cyfral/Metakom keys expose a fixed ID with no authentication. A single touch is enough to read and duplicate the key onto a blank.

**Recommended Mitigations:**
- Replace with keys that use challenge-response (e.g. DS1961S/DS28E-series secure authenticators)
- Restrict physical access to readers and key holders
- Log and review key usage at controlled doors

---

### Finding 5 — 🟡 MEDIUM | `car_fob_raw_press1.sub` (SUBGHZ)

**Capture Details:**
- **Protocol:** `RAW`
- **Frequency:** `433920000`
- **Preset:** `FuriHalSubGhzPresetOok650Async`

**🟡 433 MHz transmission captured**

> 433 MHz is a common unencrypted ISM band used by many consumer IoT devices, sensors, and remote controls. Traffic may be unencrypted.

**Recommended Mitigations:**
- Identify device owner and model
- Assess whether traffic contains sensitive operational data
- Consider RF shielding for sensitive areas

**🟢 Unidentified Sub-GHz transmission captured (raw)**

> Signal was captured but protocol could not be identified. May be proprietary or encrypted.

**Recommended Mitigations:**
- Perform deeper signal analysis with a SDR (e.g. GQRX, URH)
- Document frequency, timing, and signal characteristics
- Cross-reference with known protocol databases

---

### Finding 6 — 🟡 MEDIUM | `car_fob_raw_press2.sub` (SUBGHZ)

**Capture Details:**
- **Protocol:** `RAW`
- **Frequency:** `433920000`
- **Preset:** `FuriHalSubGhzPresetOok650Async`

**🟡 433 MHz transmission captured**

> 433 MHz is a common unencrypted ISM band used by many consumer IoT devices, sensors, and remote controls. Traffic may be unencrypted.

**Recommended Mitigations:**
- Identify device owner and model
- Assess whether traffic contains sensitive operational data
- Consider RF shielding for sensitive areas

**🟢 Unidentified Sub-GHz transmission captured (raw)**

> Signal was captured but protocol could not be identified. May be proprietary or encrypted.

**Recommended Mitigations:**
- Perform deeper signal analysis with a SDR (e.g. GQRX, URH)
- Document frequency, timing, and signal characteristics
- Cross-reference with known protocol databases

---

### Finding 7 — 🟢 LOW | `car_fob.sub` (SUBGHZ)

**Capture Details:**
- **Protocol:** `KeeLoq`
- **Frequency:** `315000000`
- **Preset:** `FuriHalSubGhzPresetOok650Async`
- **Key:** `5A 3C 11 0F 88 21 4D 07`

**🟢 Rolling-code remote detected — resists simple replay**

> The code changes on every press, so a recorded signal will not work twice. Residual risks are relay/jam-and-replay attacks (e.g. RollJam) and weak manufacturer key management for older KeeLoq implementations.

**Recommended Mitigations:**
- Keep the key fob in a signal-blocking pouch when not in use if relay attacks are a concern
- Prefer systems with challenge-response or UWB distance bounding for keyless entry
- Document manufacturer and model for the asset inventory

---

### Finding 8 — 🟢 LOW | `conference_room_tv.ir` (IR)

**Capture Details:**
- **Signals:** `[{'name': 'Power', 'type': 'parsed', 'protocol': 'NECext', 'address': '04 00 00 00', 'command': '08 00 00 00'}, {'name': 'Vol+', 'type': 'parsed', 'protocol': 'NECext', 'address': '04 00 00 00', 'command': '02 00 00 00'}, {'name': 'Vol-', 'type': 'parsed', 'protocol': 'NECext', 'address': '04 00 00 00', 'command': '03 00 00 00'}, {'name': 'Mute', 'type': 'parsed', 'protocol': 'NECext', 'address': '04 00 00 00', 'command': '09 00 00 00'}]`

**🟢 IR remote signals captured — consumer A/V device**

> Standard IR remote codes captured for common A/V equipment. IR has no authentication; signals can be replayed freely.

**Recommended Mitigations:**
- If device controls sensitive systems (displays in secure areas, conference rooms), consider IR blockers or physical controls
- Document devices controllable via captured codes

**🟢 IR signals captured**

> Infrared signals recorded. IR has no encryption or authentication.

**Recommended Mitigations:**
- Identify controlled device and assess sensitivity of function
- Document in IR signal inventory

---

## Methodology & Scope

This assessment was conducted using the Flipper Security Framework, an ethical RF, NFC, and IoT security assessment workflow built on Flipper Zero hardware and Python analysis scripts.

**In scope:** Sub-GHz signal capture and classification, NFC/RFID tag inventory, IR signal documentation, IoT device recon.

**Out of scope:** Exploitation of discovered vulnerabilities, unauthorized access to any system, or active attacks of any kind.

All testing was conducted with proper authorization. Findings are provided for defensive purposes only.

---

*Report generated by Flipper Security Framework — https://github.com/jakeb2568-sys/flipper-security-framework*