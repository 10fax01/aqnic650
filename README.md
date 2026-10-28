# aqnic650

Aquantia AQtion NDIS 6.x miniport network driver. Exposes a custom Method OID (`0xFF6A0001`) whose handler dispatches on an attacker-controlled sub-type selector to multiple **write-what-where** primitives (attacker-controlled destination, HW/driver-derived value), an **arbitrary MMIO read**, and a HW-to-memory copy with attacker-controlled length. Also contains at least one kernel info-leak path and several untriaged parsers with user-controlled offsets.

## Driver Info

| Field | Value |
|-------|-------|
| Name | aqnic650.sys |
| SHA-256 | 9ddc23de653d14e88a394248245f762a6d1dbad615ef8451468f3030a05c4b79 |
| Arch | x64 |
| Windows Version | Windows 10, 11 |
| Class | Kernel |
| Family | Aquantia |
| Signer | Microsoft Windows Hardware Compatibility Publisher |
| Signed Date | 2024-11-08 (internal build date: 2024-04-23) |

## Tests

This driver hasn't been tested ive only confirmed it can load fine on modern windows, but i havent done a PoC.

## Primitives

| Primitive | Entry | Mechanism | Function |
|-----------|-------|-----------|----------|
| **Arbitrary MMIO Read** | OID `0xFF6A0001`, Method, sub-type `5` | Reads `*(DWORD*)(MMIO_base + offset)` where `offset = *(DWORD*)attacker_ptr`; writes the result back to `attacker_ptr` | `sub_14001DA3C` → `sub_140026358` |
| **Write-what-where (16 bytes, HW-derived value)** | OID `0xFF6A0001`, Method, sub-type `1` | Copies 16 bytes of HW state to attacker-controlled pointer at `+0x08` | `sub_14001DA3C` (calls hw vtable `+0xF8`, then memcpy-style loop) |
| **Write-what-where (5 bytes, HW-derived link state)** | OID `0xFF6A0001`, Method, sub-type `2` | HW vtable `+0x100` receives attacker pointer as destination; writes bytes at `+0`, `+1`, `+2`, `+4` (link-state) | `sub_14001DA3C` |
| **Write-what-where (4 bytes, HW-derived size)** | OID `0xFF6A0001`, Method, sub-type `10` | HW vtable `+0xF0` called with `(attacker_ptr+5, &size, attacker_ptr+4)`; returned size written to `attacker_ptr` | `sub_14001DA3C` |
| **Write-what-where (4 bytes status) + HW-copy to `attacker_ptr+4`** | OID `0xFF6A0001`, Method, sub-type `12` | Length `*(DWORD*)attacker_ptr` validated against InformationBufferLength; HW vtable `+0x140` copies that many bytes from HW into `attacker_ptr+4`; status written to `attacker_ptr` | `sub_14001DA3C` |
| **Kernel Info Leak** | Query OIDs `0x10108`, `0x10109`, `0x1010B` | Multiplication overflow can mis-set `BytesWritten` on the info-buffer copy-back; uninitialized kernel memory returned to user | `sub_14001C778` |
| **Heap OOB (MAYBE?)** | OIDs `0xFD01010A`, `0xFD01010D` | Parser walks user-controlled `next-entry` offsets at `+0x98` of each entry; no bounds validation | `sub_14001EC1C`, `sub_14001E7E4` |

## Notes & Extras

### Dispatch chain

Statically confirmed from decompilation only!

User OID request (NDIS Method, RequestType 12) -> sub_14001C5B0(direct OID dispatcher, case 12) -> sub_14001C4FC(checks OID == 0xFF6A0001) -> sub_14001DA3C(a1 = adapter, a2 = NDIS_OID_REQUEST*) -> switch on *(DWORD*)(a2 + 0x18)

`a2` is the NDIS OID request. The InformationBuffer pointer and both
length fields are attacker-controlled; the sub-type selector is also
attacker-controlled.

+0x04   Method / RequestType        must be 12 to reach the vulnerable path
+0x08   InformationBuffer pointer   attacker-controlled
+0x10   InformationBufferLength     attacker-controlled
+0x14   OutputBufferLength          attacker-controlled
+0x18   Sub-type selector           attacker-controlled
+0x1C   BytesWritten                set by handler
+0x20   OID                          must be 0xFF6A0001
+0x24   BytesNeeded                 set by handler

To hit a primitive: set OID to 0xFF6A0001, place the target address (or MMIO offset) at +0x08, and pick the sub-type at +0x18.

Sub-type | Effect
---------|---------------------------------------------------------------
1        | 16-byte HW-state write to *(QWORD*)attacker_ptr
2        | HW vtable +0x100 writes 5 link-state bytes to attacker pointer
5        | MMIO read at base + *(DWORD*)attacker_ptr; result written back to attacker pointer
10       | HW vtable +0xF0; returned size written to attacker pointer
12       | HW vtable +0x140; HW copy of attacker-length bytes into attacker_ptr+4; status written to attacker pointer

little reachability note: delivering a Method OID to the miniport requires NdisOpenAdapter / IOCTL_NDIS_* access, which conventionally requires administrator privileges!
