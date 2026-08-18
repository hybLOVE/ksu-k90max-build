#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fix_vermagic.py - 修改 KernelSU kernelsu.ko 的 vermagic 字符串以匹配目标内核。

原理:
  insmod/finit_module 加载内核模块时, 第一道校验是比较 .modinfo 段里的
  "vermagic=<kernelrelease> <flags>" 字符串与目标内核的 UTS_RELEASE+flags 是否
  完全一致。KMI 冻结范围内(如 android16-6.12), 即使 SUBLEVEL 不同(6.12.58 vs
  6.12.76), ABI 符号一致, 改对 vermagic 后通常即可加载(前提 CONFIG_MODVERSIONS
  未对所用符号产生 CRC 冲突; KernelSU 使用 kallsyms 动态解析, 一般不受影响)。

用法:
  python fix_vermagic.py <in.ko> <new_vermagic> [out.ko]

  new_vermagic 示例:
    6.12.58-android16-6-g3690567af937-abogki504922916-4k SMP preempt mod_unload modversions aarch64

  若省略 out.ko, 默认写回 <in>.fixed.ko。
  若 new_vermagic 比原字符串长, 脚本会检查后续填充空间是否足够, 不足则报错退出。

注意:
  1. 新字符串长度 <= 原字符串长度 + 后续可用填充空间才可替换(超长会破坏相邻数据)。
  2. 请先确认设备真实 vermagic:
       设备上执行:  insmod /data/local/tmp/xxx.ko 2>&1
       若报 "version magic '...' should be '...'", 引号内后者即为设备期望值。
       或: adb shell cat /proc/version 结合 CONFIG 推导。
"""
import re
import shutil
import sys


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    in_ko = sys.argv[1]
    new_vermagic = sys.argv[2].encode("utf-8")
    out_ko = sys.argv[3] if len(sys.argv) > 3 else in_ko + ".fixed.ko"

    data = open(in_ko, "rb").read()

    m = re.search(rb"vermagic=", data)
    if not m:
        print("[-] vermagic= not found in %s" % in_ko)
        sys.exit(1)

    start = m.end()
    old_end = data.find(b"\x00", start)
    if old_end < 0:
        print("[-] malformed vermagic (no NUL terminator)")
        sys.exit(1)
    old = data[start:old_end]
    print("[*] old vermagic (%d B): %s" % (len(old), old.decode(errors="replace")))
    print("[*] new vermagic (%d B): %s" % (len(new_vermagic), new_vermagic.decode(errors="replace")))

    # 计算替换后所需空间: 新串 + NUL
    need = len(new_vermagic) + 1
    # 可用空间 = 原串区 + 原 NUL 之后的连续零填充(直到第一个非零或文件边界)
    avail_start = old_end
    run = 0
    i = old_end
    while i < len(data) and data[i] == 0:
        run += 1
        i += 1
    avail = (old_end - start) + run  # 原串长度 + 后续零填充
    print("[*] available space after vermagic=: %d B (原串 %d + 零填充 %d)" % (avail, old_end - start, run))

    if need > avail:
        print("[-] ERROR: new vermagic too long (%d B needed, %d available)." % (need, avail))
        print("    缩短版本号/去掉不匹配的 flags, 或改用目标版本内核源码编译。")
        sys.exit(2)

    # 写入: vermagic= + new + NUL, 其余保留
    new_block = b"vermagic=" + new_vermagic + b"\x00"
    # 将旧区(vermagic=..\0 + 填充)整体替换为新块, 剩余位置填 0, 保持文件长度不变
    fill_end = old_end + run
    patched = bytearray(data)
    # 清空整个可用区
    for j in range(start - len(b"vermagic="), fill_end):
        patched[j] = 0
    # 写回 vermagic= 前缀 + 新串 + NUL
    patched[start - len(b"vermagic="):start - len(b"vermagic=") + len(new_block)] = new_block
    patched = bytes(patched)

    # 写文件
    with open(out_ko, "wb") as f:
        f.write(patched)
    print("[+] written: %s (%d B)" % (out_ko, len(patched)))

    # 校验
    data2 = open(out_ko, "rb").read()
    m2 = re.search(rb"vermagic=", data2)
    s2 = m2.end()
    e2 = data2.find(b"\x00", s2)
    print("[*] verify new vermagic: %s" % data2[s2:e2].decode(errors="replace"))
    if data2[s2:e2] != new_vermagic:
        print("[-] WARNING: verification mismatch!")
        sys.exit(3)
    print("[+] OK")


if __name__ == "__main__":
    main()
