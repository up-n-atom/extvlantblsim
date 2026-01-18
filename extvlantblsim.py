#!/usr/bin/env python3

import sys
import argparse
from dataclasses import dataclass, fields, astuple
from typing import List


@dataclass(frozen=True)
class VlanTagOp:
    # CAUTION: field order must match bit-stream for sorting
    # filter fields
    f_out_prio: int
    f_out_vid: int
    f_out_tpid: int
    f_in_prio: int
    f_in_vid: int
    f_in_tpid: int
    f_ext_crit: int
    f_eth_type: int
    # treatment fields
    tag_rem: int
    t_out_prio: int
    t_out_vid: int
    t_out_tpid: int
    t_in_prio: int
    t_in_vid: int
    t_in_tpid: int

    def __post_init__(self) -> None:
        for field in fields(self):
            name = field.name
            val = getattr(self, name)

            match name.split("_"):
                case ["f", _, "prio"]:
                    if val not in {*range(9), 14, 15}:
                        raise ValueError(f"'{name}' invalid priority: {val}")
                case ["t", _, "prio"]:
                    if val not in {*range(11), 15}:
                        raise ValueError(f"'{name}' invalid priority: {val}")
                case ["f", _, "vid"]:
                    if not 0 <= val <= 4096:
                        raise ValueError(f"'{name}' out of range: {val}")
                case ["t", _, "vid"]:
                    if not 0 <= val <= 4097:
                        raise ValueError(f"'{name}' out of range: {val}")
                case ["f", _, "tpid"]:
                    if val not in (0, 4, 5, 6, 7):
                        raise ValueError(f"'{name}' invalid enum: {val}")
                case ["t", _, "tpid"]:
                    if not  0 <= val <= 7:
                        raise ValueError(f"'{name}' invalid enum: {val}")
                case ["tag", "rem"]:
                    if not 0 <= val <= 3:
                        raise ValueError(f"'{name}' invalid enum: {val}")
                case _:
                    continue

    @property
    def is_zero_tag(self) -> bool:
        return self.f_out_prio == 15 and self.f_in_prio == 15

    @property
    def is_single_tag(self) -> bool:
        return self.f_out_prio == 15 and self.f_in_prio != 15

    @property
    def is_double_tag(self) -> bool:
        return self.f_out_prio != 15 and self.f_in_prio != 15

    @property
    def is_default(self) -> bool:
        return (
            self.f_out_prio in (14, 15) and
            self.f_out_vid == 4096 and
            self.f_in_prio in (14, 15) and
            self.f_in_vid == 4096 and
            self.f_ext_crit == 0
        )

    @property
    def is_transparent(self) -> bool:
        return (
            self.tag_rem == 0 and
            self.t_out_prio == 15 and
            self.t_in_prio == 15
        )


class VlanTagOpTable:
    def __init__(self, ops: List[VlanTagOp] = None) -> None:
        # CAUTION: VlanTagOp field order must match bit-stream for sorting
        # Slicing the first 8 fields is a 'lossy' sort key because the upstream parser discards the
        # padding/reserved bits (assume the bits are normalized across rules)
        # Default rules last
        self.ops = sorted(ops or [], key=lambda op: (1 if op.is_default else 0, astuple(op)[:8]))

    @classmethod
    def from_stream(cls, stream) -> 'VlanTagOpTable':
        ops = []

        for line in stream:
            op = line.split()

            if len(op) == 15 and all(map(lambda x: x.isdigit(), op)):
                vals = [int(x) for x in op]

                # OLT deletion check (last 8 bytes = 0xFF)
                # 8191 is an invalid VID, confirming bits were all 1s (normalized)
                if tuple(vals[8:]) == (3, 15, 8191, 7, 15, 8191, 7):
                    continue

                # Fix order to match bit-stream
                vals[6], vals[7] = vals[7], vals[6]

                ops.append(VlanTagOp(*vals))

        return cls(ops)


def main() -> None:
    parser = argparse.ArgumentParser(description="G.988 Extended VLAN Tagging Operation Simulator")
    parser.add_argument("infile", nargs="?", type=argparse.FileType("r"), default=sys.stdin)
    args = parser.parse_args()

    table = VlanTagOpTable.from_stream(args.infile)

    if args.infile is not sys.stdin:
        args.infile.close()

    if not table.ops:
        print("No valid G.988 extended VLAN tagging operation table data found.")
        return

    for op in table.ops:
        print(op)


if __name__ == "__main__":
    main()