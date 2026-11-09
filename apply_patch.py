"""
ImeService.exe LLKHF_INJECTED 绕过补丁（VoiceKeyHookProc）

目标：让软件注入的键盘事件（SendInput / 键盘映射工具，KBDLLHOOKSTRUCT.flags & 0x10 != 0）
      能够像物理按键一样触发豆包语音输入。

逆向依据（IDA, ImeService-org.exe, ImageBase = 0x140000000）：
  VoiceKeyHookProc = 0x1407DE550  (源文件 server_main.cpp，VoiceKeyHookProc 角色)

  共 4 个独立的注入检测点（report.md 只记录了 2 个，且第 2 个偏移 0x7DD974 是错的，
  该位置其实是 0x7DE573 指令的 +1 字节）：

    (1) 0x7DE5B5  mov r14d,[rsi+8] / shr r14d,4 / and r14b,1
        -> r14d = (flags >> 4) & 1，即 LLKHF_INJECTED
        -> 0x7DE5C1 存入 [rsp+var_A87]（后续被复用，不是独立检测）
    (2) 0x7DE573  test r14d,r14d / jnz loc_1407DF192 (CallNextHookEx)
        -> 事件一进来若为注入，直接「放行给下一个钩子 / 不做任何处理」→ 语音键逻辑完全不执行
    (3) 0x7DE62E  test r14b,r14b / jnz loc_1407DE662
        -> 不做 TEB 按键状态机记录
    (4) 0x7DEC11  lParam[2] (= flags) test al,10h / jz loc_1407DEC3E
        -> 命中则记录 "injected" 并吞掉按键

补丁（4 处、全部等长改写，不改文件大小）：
    1. 0x7DD973 : test r14d,r14d(3) / jnz rel32(6) -> jmp loc_1407DF192(CallNextHookEx) + 4*nop
                  （注入事件不再提前放行，继续走正常语音键处理）
    2. 0x7DD9B5 : mov r14d,[r13](4) / shr r14d,4(4) -> xor r14d,r14d + nop*6
                  （注入标志始终为 0）
    3. 0x7DE62E : test r14b,r14b / jnz short -> jmp short loc_1407DE662 (EB 30 90 90)
                  （注入事件的按键状态机处理与物理键等价）
    4. 0x7DE011 : test al,10h / jz short -> jmp short loc_1407DEC3E (EB 2B 90 90)
                  （注入事件始终被视为「干净」按键）

用法:
    python apply_patch.py            # 生成 ImeService-patch-v2.exe
    python apply_patch.py --verify   # 只校验偏移/字节，不写文件
"""
import argparse
import struct
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
SRC = BASE / "ImeService-org.exe"
DST = BASE / "ImeService-patch-v2.exe"

IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000   # .text VirtualAddress
TEXT_RAW = 0x400    # .text PointerToRawData

PATCH1_TARGET = 0x1407DF192  # loc_1407DF192: CallNextHookEx (跳过处理的出口，nCode = r14d)


def ea_of(file_off: int) -> int:
    """把 .text 内的文件偏移转换成 IDA 中看到的 VA。"""
    return IMAGE_BASE + TEXT_RVA + (file_off - TEXT_RAW)


# (文件偏移, 期望的原始字节, 补丁字节, 说明)
# patched 为 None 表示需要按跳转目标现算 rel32
PATCHES = [
    # 0x1407DE573: test r14d,r14d (3B) + jnz 0x1407DF192 (6B)
    # jnz 原本处理「注入事件 -> 直接 CallNextHookEx 跳过所有语音键逻辑」。
    # 把 6 字节 jnz 整条改成 nop，事件继续往下走正常处理路径。
    (0x7DD976, "0f85160c0000", "90" * 6,
     "jnz loc_1407DF192(CallNextHookEx)  ->  nop*6 (注入事件不再提前跳过)"),
    # 0x1407DE5B5: mov r14d,[rsi+8] + shr r14d,4 + and r14b,1
    # 强制 r14d = 0，即「未注入」，后续所有 r14b 检查都按物理键处理。
    (0x7DD9B5, "458b750041c1ee04", "4531f6" + "90" * 5,
     "mov r14d,[r13] / shr r14d,4  ->  xor r14d,r14d (注入标志恒为 0)"),
    # 0x1407DE62E: test r14b,r14b (3B) + jnz 0x1407DE662 (2B) = 5 字节
    # 整条替换为 jmp rel8 + nop*3，保持总长 5 字节。
    (0x7DDA2E, "4584f6752f", "eb32" + "90" * 3,
     "test r14b,r14b / jnz  ->  jmp 0x1407DE662 (按键状态机按物理键处理)"),
    # 0x1407DEC11: test al,0x10 (flags & LLKHF_INJECTED) + jz
    (0x7DE011, "a8107429", "eb2b" + "90" * 2,
     "test al,10h / jz  ->  jmp 0x1407DEC3E (注入事件视为干净按键)"),
]


def make_patch_bytes(off: int, orig: bytes, patched_hex):
    new = bytes.fromhex(patched_hex)
    if len(new) != len(orig):
        raise SystemExit(f"[!] 0x{off:X}: 补丁长度 {len(new)} != 原始长度 {len(orig)}")
    return new


def build(src: bytes) -> bytes:
    data = bytearray(src)
    for off, orig_hex, patched_hex, _ in PATCHES:
        orig = bytes.fromhex(orig_hex)
        got = bytes(data[off:off + len(orig)])
        if got != orig:
            sys.exit(f"[!] 0x{off:X} 原始字节不匹配: 期望 {orig.hex()} / 实际 {got.hex()}")
        data[off:off + len(orig)] = make_patch_bytes(off, orig, patched_hex)
    return bytes(data)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true", help="只校验，不写文件")
    args = ap.parse_args()

    if not SRC.exists():
        sys.exit(f"[!] 找不到原版文件: {SRC}")

    src = SRC.read_bytes()
    out = build(src)
    assert len(out) == len(src), "文件大小不应改变"

    print(f"[+] 原始文件: {SRC}  ({len(src)} 字节)")

    if args.verify:
        print("[+] 所有偏移与原始字节校验通过。")
        return 0

    DST.write_bytes(out)
    changed = [i for i in range(len(src)) if src[i] != out[i]]

    print(f"[+] 输出文件: {DST}")
    print(f"[+] 修改字节数: {len(changed)}")
    for off, orig_hex, patched_hex, desc in PATCHES:
        n = len(bytes.fromhex(orig_hex))
        new = out[off:off + n].hex()
        print(f"    0x{off:07X}  {orig_hex}  ->  {new}   {desc}")
    print()
    print("[i] 下一步：重新计算 PE 校验和并签名（见 证书安装.ps1 / Build-SignedIme.ps1）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
