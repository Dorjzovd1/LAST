"""Forensic CLI хэрэгслүүдийг аюулгүй ажиллуулах субпроцесс туслах.

Бүх forensic шинжилгээний tool-уудыг (mmls, fls, icat, blkls, tsk_recover,
photorec, foremost, scalpel, blockdev, lsblk, dd, ewfacquire) энд төвлөрсөн
байдлаар дуудна. shell=False ашиглан command injection-ээс хамгаална.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass

logger = logging.getLogger("rea.tools")


class ToolNotFoundError(RuntimeError):
    """Шаардлагатай CLI хэрэгсэл системд олдсонгүй."""


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def which(tool: str) -> str | None:
    return shutil.which(tool)


def is_available(tool: str) -> bool:
    return which(tool) is not None


def run(
    args: list[str],
    *,
    timeout: int | None = None,
    check: bool = False,
    input_bytes: bytes | None = None,
    cwd: str | None = None,
) -> CommandResult:
    """CLI команд ажиллуулна. args[0] нь хэрэгслийн нэр.

    shell=False тул аргументууд escape хийгдэх шаардлагагүй.
    """
    tool = args[0]
    if which(tool) is None:
        raise ToolNotFoundError(f"'{tool}' хэрэгсэл системд олдсонгүй (PATH).")

    logger.debug("RUN: %s", " ".join(args))
    proc = subprocess.run(  # noqa: S603 - args нь shell-гүй жагсаалт
        args,
        input=input_bytes,
        capture_output=True,
        timeout=timeout,
        cwd=cwd,
    )
    result = CommandResult(
        returncode=proc.returncode,
        stdout=proc.stdout.decode("utf-8", errors="replace"),
        stderr=proc.stderr.decode("utf-8", errors="replace"),
    )
    if check and not result.ok:
        raise subprocess.CalledProcessError(
            result.returncode, args, output=result.stdout, stderr=result.stderr
        )
    return result


def run_to_file(args: list[str], output_path: str, *, timeout: int | None = None) -> CommandResult:
    """Командын stdout-ыг файл руу бичнэ (жишээ нь icat, blkls)."""
    tool = args[0]
    if which(tool) is None:
        raise ToolNotFoundError(f"'{tool}' хэрэгсэл системд олдсонгүй (PATH).")

    logger.debug("RUN>file: %s -> %s", " ".join(args), output_path)
    with open(output_path, "wb") as fh:
        proc = subprocess.run(args, stdout=fh, stderr=subprocess.PIPE, timeout=timeout)  # noqa: S603
    return CommandResult(
        returncode=proc.returncode,
        stdout="",
        stderr=proc.stderr.decode("utf-8", errors="replace") if proc.stderr else "",
    )
