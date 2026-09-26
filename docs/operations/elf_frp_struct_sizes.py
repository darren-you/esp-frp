#!/usr/bin/env python3
"""从固定 SDK ELF 的 DWARF 读取 FRP 会话、Yamux 和工作流尺寸。"""

import argparse
from elftools.elf.elffile import ELFFile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf")
    args = parser.parse_args()
    wanted = {"efrp_session", "efrp_work_set_t", "efrp_work_stream_t", "efrp_yamux_t"}
    sizes = {}
    with open(args.elf, "rb") as source:
        for unit in ELFFile(source).get_dwarf_info().iter_CUs():
            for entry in unit.iter_DIEs():
                name = entry.attributes.get("DW_AT_name")
                if not name or name.value.decode(errors="replace") not in wanted:
                    continue
                value = name.value.decode()
                target = entry.get_DIE_from_attribute("DW_AT_type") if entry.tag == "DW_TAG_typedef" else entry
                if target and "DW_AT_byte_size" in target.attributes:
                    sizes[value] = target.attributes["DW_AT_byte_size"].value
    if sizes.keys() != wanted:
        parser.error(f"ELF 缺少结构：{wanted - sizes.keys()}")
    for name in sorted(sizes):
        print(f"{name}={sizes[name]}")


if __name__ == "__main__":
    main()
