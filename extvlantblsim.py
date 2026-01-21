#!/usr/bin/env python3

import sys
import argparse
from dataclasses import dataclass, fields, field, astuple
from typing import Tuple, List, Dict, Iterator, Optional, Union, Any


@dataclass(frozen=True)
class VlanTag:
    vid: int
    pcp: int = 0
    tpid: int = 0x8100
    dei: int = 0

    def __post_init__(self) -> None:
        if not 0 <= self.vid <= 4094:
            raise ValueError(f"VID must be 0-4094: {self.vid}")

        if not 0 <= self.pcp <= 7:
            raise ValueError(f"PCP must be 0-7: {self.pcp}")

    def __repr__(self) -> str:
        return f"[VID: {self.vid:>4}, PCP: {self.pcp}, TPID: 0x{self.tpid:04x}]"

    __str__ = __repr__


@dataclass(frozen=True)
class EthFrame:
    tags: Tuple[VlanTag, ...] = field(default_factory=tuple)

    def __repr__(self) -> str:
        return "EthFrame(Untagged)" if not self.tags else f"EthFrame(Tags: {', '.join(repr(t) for t in self.tags)})"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return format(str(self), format_spec)

    @classmethod
    def raw(cls) -> 'EthFrame':
        return cls(tags=[])

    @classmethod
    def from_single_tag(cls, vlan: int, pcp: int = 0) -> 'EthFrame':
        return cls(tags=[VlanTag(vid=vlan, pcp=pcp)])

    @classmethod
    def from_double_tag(cls, outer_vid: int, inner_vid: int, outer_pcp: int = 0, inner_pcp: int = 0) -> 'EthFrame':
        return cls(tags=[
            VlanTag(vid=outer_vid, pcp=outer_pcp),
            VlanTag(vid=inner_vid, pcp=inner_pcp)
        ])

    @classmethod
    def from_priority(cls, pcp: int = 0) -> 'EthFrame':
        return cls.from_single_tag(0, pcp)

    @property
    def is_raw(self) -> bool:
        return len(self.tags) == 0

    @property
    def is_single_tagged(self) -> bool:
        return len(self.tags) == 1

    @property
    def is_double_tagged(self) -> bool:
        return len(self.tags) >= 2

    @property
    def inner_tag(self) -> Optional[VlanTag]:
        # Inner tag is the last one in the header sequence
        # Negative indexing prevents IndexError if the list is empty.
        return self.tags[-1] if self.tags else None

    @property
    def outer_tag(self) -> Optional[VlanTag]:
        # Check length to ensure we don't accidentally grab the inner tag of a single-tagged frame
        return self.tags[-2] if len(self.tags) >= 2 else None


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
                    if not (0 <= val <= 4094 or val == 4096):
                        raise ValueError(f"'{name}' out of range: {val}")
                case ["t", _, "vid"]:
                    if not (0 <= val <= 4094 or val in (4096, 4097)):
                        raise ValueError(f"'{name}' out of range: {val}")
                case ["f", _, "tpid"]:
                    if val not in (0, 4, 5, 6, 7):
                        raise ValueError(f"'{name}' invalid enum: {val}")
                case ["t", _, "tpid"]:
                    if not 0 <= val <= 7:
                        raise ValueError(f"'{name}' invalid enum: {val}")
                case ["f", "ext", "crit"]:
                    if not 0 <= val <= 2:
                        raise ValueError(f"'{name}' invalid enum: {val}")
                case ["f", "eth", "type"]:
                    if not 0 <= val <= 5:
                        raise ValueError(f"'{name}' invalid enum: {val}")
                case ["tag", "rem"]:
                    if not 0 <= val <= 3:
                        raise ValueError(f"'{name}' invalid enum: {val}")
                case _:
                    continue

    def __repr__(self) -> str:
        vals = astuple(self)

        f = " ".join(f"{v:>4}" for v in vals[:8])
        t = " ".join(f"{v:>4}" for v in vals[8:])

        return f"Filter:[{f}] -> Treatment:[{t}]"

    __str__ = __repr__

    @property
    def is_untagged_filter(self) -> bool:
        return (
            self.f_out_prio == 15 and
            self.f_in_prio == 15
        )

    @property
    def is_single_tagged_filter(self) -> bool:
        return (
            self.f_out_prio == 15 and
            self.f_in_prio != 15
        )

    @property
    def is_double_tagged_filter(self) -> bool:
        return self.f_out_prio != 15

    @property
    def is_untagged_default(self) -> bool:
        return (
            self.f_out_prio == 15 and
            self.f_out_vid == 4096 and
            self.f_in_prio == 15 and
            self.f_in_vid == 4096 and
            self.f_ext_crit == 0
        )

    @property
    def is_single_tagged_default(self) -> bool:
        return (
            self.f_out_prio == 15 and
            self.f_out_vid == 4096 and
            self.f_in_prio == 14 and
            self.f_in_vid == 4096 and
            self.f_ext_crit == 0
        )

    @property
    def is_double_tagged_default(self) -> bool:
        return (
            self.f_out_prio == 14 and
            self.f_out_vid == 4096 and
            self.f_in_prio == 14 and
            self.f_in_vid == 4096 and
            self.f_ext_crit == 0
        )

    @property
    def is_default(self) -> bool:
        return (
            self.is_untagged_default or
            self.is_single_tagged_default or
            self.is_double_tagged_default
        )

    @property
    def is_transparent_treatment(self) -> bool:
        if self.tag_rem != 0:
            return False

        if self.is_untagged_filter:
            return (
                self.t_out_prio == 15 and  # Do not add outer
                self.t_in_prio  == 15      # Do not add inner
            )

        if self.is_single_tagged_filter:
            return (
                self.t_out_prio == 15 and   # Don't add an extra outer tag
                self.t_in_prio == 8 and     # Copy Inner Prio
                self.t_in_vid == 4096 and   # Copy Inner VID
                self.t_in_tpid == 0         # Copy Inner TPID/DEI
            )

        if self.is_double_tagged_filter:
            return (
                self.t_out_prio == 9 and    # Copy Outer Prio
                self.t_out_vid == 4097 and  # Copy Outer VID
                self.t_out_tpid == 1 and    # Copy Outer TPID/DEI
                self.t_in_prio == 8 and     # Copy Inner Prio
                self.t_in_vid == 4096 and   # Copy Inner VID
                self.t_in_tpid == 0         # Copy Inner TPID/DEI
            )

        return False

    @property
    def is_drop_treatment(self) -> bool:
        return self.tag_rem == 3

    def matches_filter(self, frame: EthFrame, input_tpid: int = 0x8100) -> bool:
        def check_tpid(tpid_dei: int, tag: VlanTag) -> bool:
            match tpid_dei:
                case 0:
                    return True
                case 4:
                    return tag.tpid == 0x8100
                case 5:
                    return tag.tpid == input_tpid
                case 6:
                    return tag.tpid == input_tpid and tag.dei == 0
                case 7:
                    return tag.tpid == input_tpid and tag.dei == 1
                case _:
                    return False

        if frame.is_raw and not self.is_untagged_filter:
            return False
        if frame.is_single_tagged and not self.is_single_tagged_filter:
            return False
        if frame.is_double_tagged and not self.is_double_tagged_filter:
            return False

        # Outer Tag Match
        if frame.is_double_tagged:
            tag = frame.outer_tag
            if not check_tpid(self.f_out_tpid, tag):
                return False
            if self.f_out_prio < 8 and self.f_out_prio != tag.pcp:
                return False
            if self.f_out_vid not in (4096, tag.vid):
                return False

        # Inner Tag Match
        if not frame.is_raw:
            tag = frame.inner_tag
            if not check_tpid(self.f_in_tpid, tag):
                return False
            if self.f_in_prio < 8 and self.f_in_prio != tag.pcp:
                return False
            if self.f_in_vid not in (4096, tag.vid):
                return False

        return True

    def transform(self, frame: EthFrame, output_tpid: int = 0x8100) -> EthFrame:
        def resolve_pcp(prio: int) -> int:
            match prio:
                case p if 0 <= p <= 7:
                    return p
                case 8:   # Copy from inner priority of received frame
                    return frame.inner_tag.pcp if frame.inner_tag else 0
                case 9:   # Copy from outer priority of received frame
                    return frame.outer_tag.pcp if frame.outer_tag else 0
                case 10:  # DSCP to P-bit mapping (Defaulting to 0)
                    return 0
                case _:
                    return 0

        def resolve_vid(vid: int) -> int:
            match vid:
                case v if 0 <= v <= 4094:
                    return v
                case 4096:  # Copy from inner VID of received frame
                    return frame.inner_tag.vid if frame.inner_tag else 0
                case 4097:  # Copy from outer VID of received frame
                    return frame.outer_tag.vid if frame.outer_tag else 0
                case _:
                    return 0

        def resolve_tpid_dei(tpid_dei: int) -> tuple[int, int]:
            match tpid_dei:
                case 0:  # Copy TPID/DEI from inner
                    return (frame.inner_tag.tpid, frame.inner_tag.dei) if frame.inner_tag else (0x8100, 0)
                case 1:  # Copy TPID/DEI from outer
                    return (frame.outer_tag.tpid, frame.outer_tag.dei) if frame.outer_tag else (0x8100, 0)
                case 2:  # Use Output TPID, Copy DEI from inner
                    return (output_tpid, frame.inner_tag.dei if frame.inner_tag else 0)
                case 3:  # Use Output TPID, Copy DEI from outer
                    dei = frame.outer_tag.dei if frame.outer_tag else 0
                    return (output_tpid, dei)
                case 4:  # Set TPID 0x8100 (Implicit DEI=0 or preserved)
                    return (0x8100, 0)
                case 6:  # Use Output TPID, Set DEI = 0
                    return (output_tpid, 0)
                case 7:  # Use Output TPID, Set DEI = 1
                    return (output_tpid, 1)
                case _:  # Reserved or fallback
                    return (output_tpid, 0)

        if self.is_drop_treatment:
            return None

        tags = []

        # Outer Treatment (S-Tag)
        if self.t_out_prio != 15:
            tags.append(VlanTag(
                resolve_vid(self.t_out_vid),
                resolve_pcp(self.t_out_prio),
                *resolve_tpid_dei(self.t_out_tpid)
            ))

        # Inner Treatment (C-Tag)
        if self.t_in_prio != 15:
            tags.append(VlanTag(
                resolve_vid(self.t_in_vid),
                resolve_pcp(self.t_in_prio),
                *resolve_tpid_dei(self.t_in_tpid)
            ))

        return EthFrame(tags=tuple(tags) if tags else frame.tags[self.tag_rem:])


class VlanTagOpTable:
    def __init__(self, ops: List[VlanTagOp] = None) -> None:
        # CAUTION: VlanTagOp field order must match bit-stream for sorting
        # Slicing the first 8 fields is a 'lossy' sort key because the upstream parser discards the
        # padding/reserved bits (assume the bits are normalized across rules)
        # Default rules last
        self._ops = sorted(ops or [], key=lambda op: (1 if op.is_default else 0, astuple(op)[:8]))

    def __getitem__(self, index: Union[int, slice]) -> Union[VlanTagOp, List[VlanTagOp]]:
        return self._ops[index]

    def __len__(self) -> int:
        return len(self._ops)

    def __iter__(self) -> Iterator[VlanTagOp]:
        return iter(self._ops)

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

    def process_frame(self, frame: EthFrame) -> Optional[EthFrame]:
        for op in self:
            if op.matches_filter(frame):
                return op.transform(frame)

        return None


class VlanClassifier:
    @staticmethod
    def rank_vlan_from_priority(table: VlanTagOpTable, target_prio: int = 0) -> List[Dict[str, Any]]:
        def calc_likelihood(op):
            likelihood = 0.5
            weight = 0.40 # Default weight for treatment copy priority (8)

            # Prioritize standard 802.1Q VLAN range (1-4094), excluding priority-tagged
            likelihood *= 0.95 if 1 <= op.f_in_vid <= 4094 else 0.05

            # Ingress filter analysis
            match op.f_in_prio:
                case p if p == target_prio:
                    likelihood *= 0.90
                    weight = 0.70  # Upgrade trust for direct match
                case 8:
                    likelihood *= 0.50 if target_prio == 0 else 0.10
                case _:
                    likelihood *= 0.05

            # Egress treatment analysis
            match op.t_in_prio:
                case p if p == target_prio:
                    likelihood *= 0.999 if target_prio != 0 else 0.95
                case 8:
                    likelihood *= weight if target_prio != 0 else 0.85
                case _:
                    likelihood *= 0.0001 # Disqualifier

            # Bonus for VID translation
            likelihood *= 0.85 if op.t_in_vid != op.f_in_vid and op.t_in_vid <= 4094 else 0.82

            return likelihood

        results = []
        total_lik = 0.0

        for i, op in enumerate(table):
            if op.is_single_tagged_filter and not (op.is_single_tagged_default or op.is_drop_treatment):
                total_lik += (likelihood := calc_likelihood(op))

                results.append({
                    "vid": op.f_in_vid,
                    "likelihood": likelihood,
                    "index": i
                })

        # Normalize
        for r in results:
            r["confidence"] = round((r["likelihood"] / total_lik) * 100, 2) if total_lik > 0 else 0.0

        results.sort(key=lambda x: x["likelihood"], reverse=True)

        return results


def main() -> None:
    parser = argparse.ArgumentParser(description="G.988 Extended VLAN Tagging Operation Simulator")
    parser.add_argument("infile", nargs="?", type=argparse.FileType("r"), default=sys.stdin)
    args = parser.parse_args()

    table = VlanTagOpTable.from_stream(args.infile)

    if args.infile is not sys.stdin:
        args.infile.close()

    if not table:
        print("No valid G.988 extended VLAN tagging operation table data found.")
        return

    print("-"*120)
    print(f"{'VLAN TAGGING OPERATION TABLE':^120}")
    print("-"*120)
    for i, op in enumerate(table):
        print(f"{i:<2}", f"{op}")

    services = {
        0: "HSI",
        5: "VOIP",
        4: "IPTV"
    }

    frames = {
        "Untagged": EthFrame.raw(),
        "Priority-Tagged": EthFrame.from_priority(0),
    }

    print("-"*120)
    print(f"{'SERVICE VLAN':^120}")
    print("-"*120)
    for prio, desc in services.items():
        rankings = VlanClassifier.rank_vlan_from_priority(table, prio)
        print(f"{desc:<5}", f"{rankings[0]['vid']:<4}" if rankings else "N/A")
        if prio == 0 and rankings:
            frames["Service-Tagged"] = EthFrame.from_single_tag(rankings[0]["vid"])

    print("-"*120)
    print(f"{'ROUTER CONFIGURATION TEST':^120}")
    print("-"*120)
    print(f"{'WAN CONFIG':<15} {'UNI FRAME':<50} PON FRAME")
    print("-"*120)
    for conf, uni_frame in frames.items():
        pon_frame = table.process_frame(uni_frame)
        print(f"{conf:<15}", f"{uni_frame!s:<50}", f"{pon_frame!s}" if pon_frame else "DISCARDED")


if __name__ == "__main__":
    main()