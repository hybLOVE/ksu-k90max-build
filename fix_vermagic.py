#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fix_vermagic.py - 修改/追加 KernelSU kernelsu.ko 的 vermagic 字符串以匹配目标内核。

原理:
  insmod/finit_module 加载内核模块时, 第一道校验是比较 .modinfo 段里的
  "vermagic=<kernelrelease> <flags>" 字符串与目标内核的 UTS_RELEASE+flags 是否
  完全一致。KMI 冻结范围内(如 android16-6.12), 即使 SUBLEVEL 不同, ABI 符号
  一致, 改对 vermagic 后通常即可加载。

用法:
  python fix_vermagic.py <in.ko> <new_vermagic> [out.ko]

  new_vermagic 示例:
    6.12.58-android16-6-g3690567af937-abogki504922916-4k SMP preempt mod_unload modversions aarch64

  若省略 out.ko, 默认写回 <in>.fixed.ko。
  若 .ko 中已有 vermagic= 条目: 替换(新串不能超过原串+后续填充空间)。
  若 .ko 中无 vermagic= 条目: 在 .modinfo 段空余空间追加。
"""
import re
import struct
import sys


def cstr(buf, off):
    end = buf.index(b"\x00", off)
    return buf[off:end]


def find_modinfo_section(data):
    """返回 (.modinfo 段文件偏移, 段大小) 或 None"""
    if data[:4] != b"\x7fELF":
        return None
    endian = "<" if data[5] == 1 else ">"
    if data[4] != 2:  # 仅支持 ELF64
        return None
    e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]
    e_shentsize = struct.unpack_from(endian + "H", data, 58)[0]
    e_shnum = struct.unpack_from(endian + "H", data, 60)[0]
    e_shstrndx = struct.unpack_from(endian + "H", data, 62)[0]
    if e_shnum == 0 or e_shstrndx == 0 or e_shstrndx >= e_shnum:
        return None
    shstr_off = struct.unpack_from(endian + "Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    shstr_size = struct.unpack_from(endian + "Q", data, e_shoff + e_shstrndx * e_shentsize + 32)[0]
    shstr = data[shstr_off:shstr_off + shstr_size]
    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        name_off = struct.unpack_from(endian + "I", data, sh)[0]
        name = cstr(shstr, name_off)
        if name == b".modinfo":
            sh_offset = struct.unpack_from(endian + "Q", data, sh + 24)[0]
            sh_size = struct.unpack_from(endian + "Q", data, sh + 32)[0]
            return sh_offset, sh_size
    return None


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    in_ko = sys.argv[1]
    new_vermagic = sys.argv[2].encode("utf-8")
    out_ko = sys.argv[3] if len(sys.argv) > 3 else in_ko + ".fixed.ko"

    data = open(in_ko, "rb").read()
    patched = None

    # ---- 模式1: 已有 vermagic=, 原地替换 ----
    m = re.search(rb"vermagic=", data)
    if m:
        start = m.end()
        old_end = data.find(b"\x00", start)
        old = data[start:old_end]
        print("[*] old vermagic (%d B): %s" % (len(old), old.decode(errors="replace")))
        print("[*] new vermagic (%d B): %s" % (len(new_vermagic), new_vermagic.decode(errors="replace")))
        run = 0
        i = old_end
        while i < len(data) and data[i] == 0:
            run += 1
            i += 1
        avail = (old_end - start) + run
        need = len(new_vermagic) + 1
        print("[*] available space after vermagic=: %d B" % avail)
        if need > avail:
            print("[-] ERROR: new vermagic too long (%d B needed, %d available)." % (need, avail))
            sys.exit(2)
        p = bytearray(data)
        # 保留 "vermagic=" 前缀, 只清空值区并写入新值
        for j in range(start, old_end + run):
            p[j] = 0
        p[start:start + len(new_vermagic)] = new_vermagic
        patched = bytes(p)
        print("[+] vermagic 已替换")

    # ---- 模式2: 无 vermagic=, 在 .modinfo 段追加 ----
    else:
        print("[*] 未找到现有 vermagic=, 尝试在 .modinfo 段追加")
        sec = find_modinfo_section(data)
        if sec is None:
            print("[-] ERROR: 无法定位 .modinfo 段 (非 ELF64 或结构异常)")
            sys.exit(2)
        off, size = sec
        seg = data[off:off + size]
        last = 0
        for i in range(size):
            if seg[i] != 0:
                last = i
        free_start = last + 1
        free = size - free_start
        # 需要追加的条目: vermagic + (缺失时的 name/depends); 条目级检查, 防误命中 kernelsu.mod.name= 子串
        entries_list = [e for e in seg.split(b"\x00") if e.strip()]
        has_name = any(e.startswith(b"name=") for e in entries_list)
        has_depends = any(e.startswith(b"depends=") for e in entries_list)
        entries = [b"vermagic=" + new_vermagic + b"\x00"]
        if not has_name:
            entries.append(b"name=kernelsu\x00")
            print("[*] 缺少 name= 条目, 将追加 name=kernelsu")
        if not has_depends:
            entries.append(b"depends=\x00")
            print("[*] 缺少 depends= 条目, 将追加")
        need = sum(len(e) for e in entries)
        print("[*] .modinfo 段: offset=%d size=%d, 已用=%d, 空闲=%d B, 需追加=%d B" % (off, size, free_start, free, need))
        if need <= free:
            p = bytearray(data)
            pos = off + free_start
            for e in entries:
                p[pos:pos + len(e)] = e
                pos += len(e)
            patched = bytes(p)
            print("[+] 条目已追加到 .modinfo 段")
        else:
            # ---- 模式3: 空闲不足, 扩展 .modinfo 段(移到文件末尾) ----
            print("[*] 空闲不足, 扩展 .modinfo 段: 复制到文件末尾并更新 section header")
            new_content = seg + b"".join(entries)  # 原内容 + 新条目
            # 对齐到 8 字节
            align = (len(data) + 7) & ~7
            new_off = align
            p = bytearray(data)
            p += b"\x00" * (new_off - len(data))
            p += new_content
            # 更新 section header (.modinfo)
            endian = "<" if data[5] == 1 else ">"
            e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]
            e_shentsize = struct.unpack_from(endian + "H", data, 58)[0]
            e_shnum = struct.unpack_from(endian + "H", data, 60)[0]
            e_shstrndx = struct.unpack_from(endian + "H", data, 62)[0]
            shstr_off = struct.unpack_from(endian + "Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
            shstr_size = struct.unpack_from(endian + "Q", data, e_shoff + e_shstrndx * e_shentsize + 32)[0]
            shstr = data[shstr_off:shstr_off + shstr_size]
            for i in range(e_shnum):
                sh = e_shoff + i * e_shentsize
                name_off = struct.unpack_from(endian + "I", data, sh)[0]
                name = cstr(shstr, name_off)
                if name == b".modinfo":
                    struct.pack_into(endian + "Q", p, sh + 24, new_off)   # sh_offset
                    struct.pack_into(endian + "Q", p, sh + 32, len(new_content))  # sh_size
                    print("[+] .modinfo 段已扩展: offset=%d size=%d" % (new_off, len(new_content)))
                    break
            patched = bytes(p)
            print("[+] vermagic 条目已随段扩展写入")

    with open(out_ko, "wb") as f:
        f.write(patched)
    print("[+] written: %s (%d B)" % (out_ko, len(patched)))

    # 校验
    data2 = open(out_ko, "rb").read()
    m2 = re.search(rb"vermagic=", data2)
    if not m2:
        print("[-] WARNING: 校验未找到 vermagic= !")
        sys.exit(3)
    s2 = m2.end()
    e2 = data2.find(b"\x00", s2)
    print("[*] verify new vermagic: %s" % data2[s2:e2].decode(errors="replace"))
    if data2[s2:e2] != new_vermagic:
        print("[-] WARNING: verification mismatch!")
        sys.exit(3)
    print("[+] OK")


if __name__ == "__main__":
    main()
