import sys
import argparse
from dataclasses import dataclass, fields
from typing import List

@dataclass(frozen=True)
class VlanTagOp:
    f_out_prio: int
    f_out_vid: int
    f_out_tpid: int
    f_in_prio: int
    f_in_vid: int
    f_in_tpid: int
    f_eth_type: int
    f_ext_crit: int
    tag_rem: int
    t_out_prio: int
    t_out_vid: int
    t_out_tpid: int
    t_in_prio: int
    t_in_vid: int
    t_in_tpid: int
    idx: int

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


class VlanTagOpTable:
    def __init__(self, ops: List[VlanTagOp] = None) -> None:
        self.ops = ops or []

    @classmethod
    def from_stream(cls, stream) -> None:
        ops = []

        for line in stream:
            op = line.split()

            if len(op) == 15 and all(map(lambda x: x.isdigit(), op)):
                ops.append(VlanTagOp(*map(int, op), idx=len(ops) + 1))

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
