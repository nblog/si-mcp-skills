from capstone import CS_ARCH_X86, CS_GRP_RET, Cs
from capstone.x86_const import X86_INS_JMP, X86_OP_IMM, X86_OP_MEM

PATCH_BLOCK_SIZE = 512


class InlineGap(ValueError):
    """The code bytes cannot be compared or decoded safely."""


def diff_runs(expected: bytes, live: bytes) -> list[tuple[int, int]]:
    if len(expected) != len(live):
        raise InlineGap("incomplete_compare")
    runs: list[tuple[int, int]] = []
    start: int | None = None
    for offset, (left, right) in enumerate(zip(expected, live)):
        if left != right:
            if start is None:
                start = offset
        elif start is not None:
            runs.append((start, offset))
            start = None
    if start is not None:
        runs.append((start, len(live)))
    return runs


def classify_patch(expected: bytes, live: bytes, mode: int, address: int) -> dict:
    runs = diff_runs(expected, live)
    if len(runs) != 1:
        raise InlineGap("expected_one_contiguous_patch")
    start, end = runs[0]
    result = {
        "status": "patch",
        "offset": start,
        "size": end - start,
        "boundary": "patch_start",
    }
    if end - start >= PATCH_BLOCK_SIZE:
        return result

    engine = Cs(CS_ARCH_X86, mode)
    engine.detail = True
    first_live = next(engine.disasm(live[start:end], address + start, count=1), None)
    first_disk = next(engine.disasm(expected[start:end], address + start, count=1), None)
    if first_live is None:
        return result
    result["live_mnemonic"] = first_live.mnemonic
    if first_disk is not None:
        result["disk_mnemonic"] = first_disk.mnemonic

    if first_live.id == X86_INS_JMP and first_live.size <= end - start:
        result.update(status="inline_candidate", jump_kind={
            X86_OP_IMM: "direct", X86_OP_MEM: "memory_indirect",
        }.get(first_live.operands[0].type, "register_indirect"))
        if first_live.operands[0].type == X86_OP_IMM:
            result["branch_target"] = first_live.operands[0].imm
        elif first_live.operands[0].type == X86_OP_MEM:
            result["memory_operand"] = first_live.operands[0].mem.disp
        return result

    disk_engine = Cs(CS_ARCH_X86, mode)
    disk_engine.detail = True
    disk_returns = {
        instruction.address - (address + start)
        for instruction in disk_engine.disasm(expected[start:end], address + start, count=8)
        if instruction.group(CS_GRP_RET)
    }
    for instruction in engine.disasm(live[start:end], address + start, count=8):
        offset = instruction.address - (address + start)
        if instruction.group(CS_GRP_RET) and offset not in disk_returns:
            result.update(status="entry_return_patch", return_offset=offset)
            break
    return result
