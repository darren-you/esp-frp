#!/usr/bin/env python3
"""读取固定 SDK ELF 中 efrp_session 的成员偏移与尺寸。"""

import argparse
from elftools.elf.elffile import ELFFile


def name(die):
    value = die.attributes.get("DW_AT_name")
    return value.value.decode(errors="replace") if value else "<anonymous>"


def byte_size(die):
    while die:
        if die.tag == "DW_TAG_array_type":
            element = byte_size(die.get_DIE_from_attribute("DW_AT_type"))
            if element is None:
                return None
            for subrange in die.iter_children():
                if subrange.tag != "DW_TAG_subrange_type":
                    continue
                attributes = subrange.attributes
                if "DW_AT_count" in attributes:
                    element *= attributes["DW_AT_count"].value
                elif "DW_AT_upper_bound" in attributes:
                    lower = attributes.get("DW_AT_lower_bound")
                    element *= attributes["DW_AT_upper_bound"].value - (lower.value if lower else 0) + 1
                else:
                    return None
            return element
        value = die.attributes.get("DW_AT_byte_size")
        if value:
            return value.value
        die = die.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in die.attributes else None
    return None


def describe(die, prefix=""):
    for member in die.iter_children():
        if member.tag != "DW_TAG_member":
            continue
        offset = member.attributes.get("DW_AT_data_member_location")
        target = member.get_DIE_from_attribute("DW_AT_type")
        print(f"{prefix}{name(member)} offset={offset.value if offset else 0} size={byte_size(target)}")
        while target and target.tag == "DW_TAG_typedef":
            target = target.get_DIE_from_attribute("DW_AT_type")
        if target and target.tag in {"DW_TAG_structure_type", "DW_TAG_union_type"}:
            describe(target, prefix + "  ")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf")
    args = parser.parse_args()
    with open(args.elf, "rb") as source:
        dwarf = ELFFile(source).get_dwarf_info()
        for unit in dwarf.iter_CUs():
            for die in unit.iter_DIEs():
                if die.tag == "DW_TAG_structure_type" and name(die) == "efrp_session" and byte_size(die):
                    print(f"efrp_session size={byte_size(die)}")
                    describe(die)
                    return
    parser.error("ELF 缺少 efrp_session DWARF")


if __name__ == "__main__":
    main()
