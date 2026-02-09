#!/usr/bin/env python3
"""
Utility to diff two LaTeX project directories and produce a highlighted PDF.

Workflow:
1. Copies both directories into a temporary workspace so paths remain intact.
2. Detects (or accepts) the main .tex entry point relative to each directory.
3. Runs `latexdiff --flatten` to capture changes across sub-directories.
4. Compiles the resulting diff file with latexmk (or pdflatex fallback).

Example:
    python latex_differ.py path/to/original path/to/revised -o diff.pdf
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Iterable, List, Optional


DEFAULT_LATEXDIFF_ARGS = [
    "--exclude-textcmd=caption,captionof,section,subsection,subsubsection",
    "--exclude-textcmd=textbf,textit,emph,textsc,gls,glspl,ac,acf,acp,acs,acl",
    "--graphics-markup=none",
    "--floattype=IDENTICAL",
]

TABULAR_ENV_PATTERN = re.compile(r"\\begin\{(tabularx?|longtable)\}")
STRUCTURE_ENV_LABELS = {
    "table": "Table",
    "table*": "Table",
    "figure": "Figure",
    "figure*": "Figure",
    "algorithm": "Algorithm",
    "algorithm*": "Algorithm",
    "algorithm2e": "Algorithm",
    "lstlisting": "Code Listing",
    "algorithmic": "Pseudo Code",
}
ENV_PATTERN = re.compile(
    r"\\begin\{(?P<name>table\*?|figure\*?|algorithm\*?|algorithm2e|lstlisting|algorithmic)\}"
)
PROTECTED_TABLE_COMMANDS = (
    "\\toprule",
    "\\midrule",
    "\\bottomrule",
    "\\cmidrule",
    "\\addlinespace",
    "\\endhead",
    "\\endfoot",
    "\\endlastfoot",
    "\\hline",
    "\\cline",
)
TABLE_COMMAND_LITERALS = ("&", "\\\\", "\\tabularnewline")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Produce a latexdiff-based PDF from two LaTeX directories."
    )
    parser.add_argument("old_dir", help="Directory containing the older LaTeX sources.")
    parser.add_argument("new_dir", help="Directory containing the newer LaTeX sources.")
    parser.add_argument(
        "-m",
        "--main",
        help=(
            "Path to the main .tex file relative to each directory. "
            "If omitted, the script tries to auto-detect it."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        default="latex_diff.pdf",
        help="Destination for the diff PDF (default: latex_diff.pdf).",
    )
    parser.add_argument(
        "--engine",
        choices=("auto", "latexmk", "pdflatex"),
        default="auto",
        help="Which LaTeX build tool to use (default: auto-detect).",
    )
    parser.add_argument(
        "--latexdiff-arg",
        action="append",
        default=[],
        help=(
            "Extra option to pass to latexdiff (repeat flag as needed, "
            "e.g., --latexdiff-arg='-t CFONT')."
        ),
    )
    parser.add_argument(
        "--no-default-latexdiff-args",
        action="store_true",
        help="Disable the built-in latexdiff safety flags (caption/section exclusions).",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Preserve the temporary working directory for inspection.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging for troubleshooting.",
    )
    return parser.parse_args()


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


def ensure_command(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(
            f"Required command '{name}' not found on PATH. "
            "Ensure TeX Live tools are installed and accessible."
        )
    logging.debug("Located command %s at %s", name, path)
    return path


def expand_latexdiff_args(values: Iterable[str]) -> List[str]:
    tokens: List[str] = []
    for value in values:
        tokens.extend(shlex.split(value))
    return tokens


def detect_main_tex(directory: Path) -> Path:
    logging.info("Attempting to auto-detect main .tex file in %s", directory)
    for tex_path in sorted(directory.rglob("*.tex")):
        try:
            text = tex_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "\\begin{document}" in text:
            rel_path = tex_path.relative_to(directory)
            logging.info("Detected main file: %s", rel_path)
            return rel_path
    raise FileNotFoundError(
        f"Could not auto-detect a main .tex file under {directory}. "
        "Please specify one via --main."
    )


def copy_tree(src: Path, dst: Path) -> None:
    logging.debug("Copying %s -> %s", src, dst)
    shutil.copytree(src, dst)


def materialize_source(src: Path, dst: Path) -> None:
    """Copy, extract, or stage the user input into the workspace."""
    if src.is_dir():
        copy_tree(src, dst)
        return
    suffix = src.suffix.lower()
    dst.mkdir(parents=True, exist_ok=True)
    if suffix == ".zip":
        logging.debug("Extracting %s -> %s", src, dst)
        with zipfile.ZipFile(src) as archive:
            archive.extractall(dst)
        return
    if suffix == ".tex":
        logging.debug("Copying single LaTeX file %s -> %s", src, dst)
        shutil.copy2(src, dst / src.name)
        return
    raise ValueError(
        f"Unsupported input '{src}'. Provide a directory, .tex file, or .zip archive."
    )


def run_latexdiff(
    old_main: Path,
    new_main: Path,
    output_dir: Path,
    extra_args: List[str],
) -> Path:
    ensure_command("latexdiff")
    diff_tex = output_dir / "diff.tex"
    cmd = ["latexdiff", "--flatten", *extra_args, str(old_main), str(new_main)]
    logging.info("Running latexdiff to build diff.tex")
    logging.debug("latexdiff command: %s", " ".join(cmd))
    try:
        with diff_tex.open("w", encoding="utf-8") as diff_file:
            proc = subprocess.run(
                cmd,
                stdout=diff_file,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
    except FileNotFoundError as exc:
        raise RuntimeError("latexdiff executable not found") from exc

    if proc.returncode != 0:
        raise RuntimeError(
            "latexdiff failed with exit code "
            f"{proc.returncode}:\n{proc.stderr.strip()}"
        )
    if proc.stderr:
        logging.debug("latexdiff stderr:\n%s", proc.stderr.strip())
    logging.info("Latexdiff output saved to %s", diff_tex)
    return diff_tex


def annotate_structural_changes(diff_path: Path) -> None:
    text = diff_path.read_text(encoding="utf-8")
    text = ensure_highlight_macro(text)
    text = highlight_added_structures(text)
    text = highlight_modified_structures(text)
    diff_path.write_text(text, encoding="utf-8")


def ensure_highlight_macro(text: str) -> str:
    if "\\diffHighlight" in text:
        return text
    macro = (
        "% Added by latex_differ structural highlighter\n"
        "\\providecommand{\\diffHighlight}[1]{%\n"
        "  \\par\\noindent\\colorbox{yellow!30}{\\strut\\textbf{#1}}\\par\n"
        "}\n"
        "\\providecommand{\\diffFloatBanner}[1]{%\n"
        "  \\noindent\\colorbox{yellow!30}{\\strut\\textbf{#1}}\\\\[4pt]\n"
        "}\n"
    )
    marker = "\\begin{document}"
    pos = text.find(marker)
    if pos == -1:
        return macro + text
    return text[:pos] + macro + "\n" + text[pos:]


def highlight_added_structures(text: str) -> str:
    idx = 0
    chunks: List[str] = []
    while True:
        start = text.find("\\DIFaddbegin", idx)
        if start == -1:
            chunks.append(text[idx:])
            break
        chunks.append(text[idx:start])
        if text.startswith("\\DIFaddbeginFL", start):
            begin_cmd = "\\DIFaddbeginFL"
            end_cmd = "\\DIFaddendFL"
        else:
            begin_cmd = "\\DIFaddbegin"
            end_cmd = "\\DIFaddend"
        body_start = start + len(begin_cmd)
        end = text.find(end_cmd, body_start)
        if end == -1:
            chunks.append(text[start:])
            break
        body = text[body_start:end]
        label = detect_structure_label(body)
        segment_end = end + len(end_cmd)
        if label:
            decorated = insert_banner_into_env(body, f"New {label}")
            chunks.append(decorated)
        else:
            chunks.append(text[start:segment_end])
        idx = segment_end
    return "".join(chunks)


def highlight_modified_structures(text: str) -> str:
    idx = 0
    chunks: List[str] = []
    while True:
        match = ENV_PATTERN.search(text, idx)
        if not match:
            chunks.append(text[idx:])
            break
        env_name = match.group("name")
        chunks.append(text[idx:match.start()])
        inner_end, env_end = _find_matching_end(text, match.end(), env_name)
        block = text[match.start():env_end]
        needs_highlight = (
            ("\\DIFadd" in block or "\\DIFdel" in block)
            and "\\diffFloatBanner" not in block
        )
        if needs_highlight:
            label = STRUCTURE_ENV_LABELS.get(env_name, "Structure")
            banner = f"\n\\diffFloatBanner{{Updated {label}}}\n"
            chunks.append(text[match.start():match.end()])
            chunks.append(banner)
            chunks.append(text[match.end():env_end])
        else:
            chunks.append(block)
        idx = env_end
    return "".join(chunks)


def insert_banner_into_env(body: str, banner_text: str) -> str:
    match = ENV_PATTERN.search(body)
    if not match:
        return body
    insertion_point = match.end()
    banner = f"\n\\diffFloatBanner{{{banner_text}}}\n"
    return body[:insertion_point] + banner + body[insertion_point:]


def detect_structure_label(body: str) -> Optional[str]:
    stripped = body.lstrip()
    for env, label in STRUCTURE_ENV_LABELS.items():
        if stripped.startswith(f"\\begin{{{env}}}"):
            return label
    if "\\includegraphics" in body or "\\begin{tikzpicture}" in body:
        return "Figure"
    if "\\begin{algorithmic}" in body:
        return "Pseudo Code"
    return None


def sanitize_tabular_sections(diff_path: Path) -> None:
    """Reinsert %DIF-deleted structural commands inside tables to keep rows intact."""
    try:
        text = diff_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Unable to read diff file {diff_path}") from exc

    pieces: List[str] = []
    cursor = 0
    while True:
        match = TABULAR_ENV_PATTERN.search(text, cursor)
        if not match:
            pieces.append(text[cursor:])
            break
        env_name = match.group(1)
        begin = match.start()
        pieces.append(text[cursor:begin])
        begin_token = match.group(0)
        pieces.append(begin_token)
        inner_start = match.end()
        inner_end, env_end = _find_matching_end(text, inner_start, env_name)
        inner = text[inner_start:inner_end]
        pieces.append(_restore_dif_comments(inner))
        pieces.append(text[inner_end:env_end])
        cursor = env_end

    diff_path.write_text("".join(pieces), encoding="utf-8")


def _find_matching_end(text: str, start_idx: int, env_name: str) -> tuple[int, int]:
    begin_token = f"\\begin{{{env_name}}}"
    end_token = f"\\end{{{env_name}}}"
    depth = 1
    search_idx = start_idx
    while depth > 0:
        next_begin = text.find(begin_token, search_idx)
        next_end = text.find(end_token, search_idx)
        if next_end == -1:
            raise RuntimeError(f"Unmatched \\begin{{{env_name}}} in diff output.")
        if next_begin != -1 and next_begin < next_end:
            depth += 1
            search_idx = next_begin + len(begin_token)
            continue
        depth -= 1
        search_idx = next_end + len(end_token)
    return next_end, search_idx


def _restore_dif_comments(segment: str) -> str:
    lines: List[str] = []
    inside_del_block = False
    for line in segment.splitlines(keepends=True):
        if line.endswith("\r\n"):
            body = line[:-2]
            eol = "\r\n"
        elif line.endswith("\n"):
            body = line[:-1]
            eol = "\n"
        else:
            body = line
            eol = ""
        pct_idx = body.find("%DIF")
        line_has_begin = "\\DIFdelbegin" in body
        line_has_end = "\\DIFdelend" in body
        restore_here = inside_del_block or line_has_begin
        if pct_idx == -1 or not restore_here:
            lines.append(body + eol)
        else:
            prefix = body[:pct_idx]
            comment = body[pct_idx:]
            restored = _extract_dif_payload(comment.lstrip())
            safe = _filter_table_payload(restored)
            if safe:
                prefix += safe
            lines.append(prefix + eol)
        if line_has_begin:
            inside_del_block = True
        if line_has_end:
            inside_del_block = False
    return "".join(lines)


def _filter_table_payload(payload: str) -> str:
    stripped = payload.lstrip()
    if not stripped:
        return ""
    for literal in TABLE_COMMAND_LITERALS:
        if stripped.startswith(literal):
            return literal
    if not stripped.startswith("\\"):
        return ""
    for prefix in PROTECTED_TABLE_COMMANDS:
        if stripped.startswith(prefix):
            return stripped
    return ""


def _extract_dif_payload(line: str) -> str:
    marker = "<" if "<" in line else (">" if ">" in line else "")
    if not marker:
        return ""
    payload = line.split(marker, 1)[1]
    payload = payload.rstrip()
    payload = payload.rstrip("%").rstrip()
    return payload


def compile_pdf(
    tex_path: Path,
    workspace: Path,
    engine_pref: str,
    tex_search_dirs: Optional[List[Path]] = None,
) -> Path:
    pdf_path = tex_path.with_suffix(".pdf")
    env = build_tex_env(tex_search_dirs) if tex_search_dirs else None
    if engine_pref in ("auto", "latexmk"):
        latexmk = shutil.which("latexmk")
        if latexmk:
            cmd = [
                latexmk,
                "-pdf",
                "-interaction=nonstopmode",
                "-halt-on-error",
                tex_path.name,
            ]
            logging.info("Compiling diff with latexmk")
            run_logged(cmd, cwd=workspace, env=env)
            return pdf_path
        if engine_pref == "latexmk":
            raise RuntimeError(
                "Requested engine 'latexmk', but latexmk is not on PATH."
            )

    # Fallback to pdflatex
    pdflatex = ensure_command("pdflatex")
    cmd = [pdflatex, "-interaction=nonstopmode", tex_path.name]
    logging.info("Compiling diff with pdflatex (two passes)")
    run_logged(cmd, cwd=workspace, env=env)
    run_logged(cmd, cwd=workspace, env=env)
    return pdf_path


def run_logged(
    cmd: List[str],
    cwd: Optional[Path] = None,
    env: Optional[dict[str, str]] = None,
) -> None:
    logging.debug("Executing: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if proc.stdout:
        logging.debug(proc.stdout)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stdout}"
        )


def build_tex_env(paths: Optional[List[Path]]) -> dict[str, str]:
    env = os.environ.copy()
    if not paths:
        return env
    str_paths = [str(p) for p in paths if p]
    tex_value = compose_search_path(str_paths, env.get("TEXINPUTS"))
    bib_value = compose_search_path(str_paths, env.get("BIBINPUTS"))
    env["TEXINPUTS"] = tex_value
    env["BIBINPUTS"] = bib_value
    return env


def compose_search_path(entries: List[str], existing: Optional[str]) -> str:
    parts = list(entries)
    if existing:
        parts.append(existing)
    parts.append("")
    return os.pathsep.join(parts)


def ensure_bibliography(main_tex: Path) -> None:
    """Ensure a .bbl exists for the given main TeX file."""
    bbl_path = main_tex.with_suffix(".bbl")
    if bbl_path.exists():
        logging.debug("Found bibliography: %s", bbl_path)
        return
    logging.info("Generating bibliography for %s", main_tex)
    compile_bibliography(main_tex)
    if not bbl_path.exists():
        raise RuntimeError(f"Failed to produce bibliography file {bbl_path}")


def compile_bibliography(main_tex: Path) -> None:
    tex_dir = main_tex.parent
    tex_name = main_tex.name
    env = build_tex_env([tex_dir])
    latexmk = shutil.which("latexmk")
    if latexmk:
        cmd = [latexmk, "-pdf", "-interaction=nonstopmode", "-halt-on-error", tex_name]
        run_logged(cmd, cwd=tex_dir, env=env)
        return

    pdflatex = ensure_command("pdflatex")
    run_logged([pdflatex, "-interaction=nonstopmode", tex_name], cwd=tex_dir, env=env)
    bibtex = shutil.which("bibtex")
    if not bibtex:
        raise RuntimeError("bibtex not found on PATH; cannot build bibliography.")
    run_logged([bibtex, main_tex.stem], cwd=tex_dir, env=env)
    run_logged([pdflatex, "-interaction=nonstopmode", tex_name], cwd=tex_dir, env=env)


def prepare_workspace(keep: bool) -> tuple[Path, Optional[tempfile.TemporaryDirectory]]:
    if keep:
        path = Path(tempfile.mkdtemp(prefix="latex-differ-"))
        logging.info("Using preserved workspace: %s", path)
        return path, None
    tmp_obj = tempfile.TemporaryDirectory(prefix="latex-differ-")
    path = Path(tmp_obj.name)
    logging.debug("Created temporary workspace: %s", path)
    return path, tmp_obj


def main() -> int:
    args = parse_args()
    configure_logging(args.verbose)

    old_dir = Path(args.old_dir).expanduser().resolve()
    new_dir = Path(args.new_dir).expanduser().resolve()
    output_pdf = Path(args.output).expanduser().resolve()

    if not old_dir.is_dir():
        logging.error("Old directory not found: %s", old_dir)
        return 1
    if not new_dir.is_dir():
        logging.error("New directory not found: %s", new_dir)
        return 1

    if args.main:
        main_rel = Path(args.main)
        if main_rel.is_absolute():
            logging.error("--main should be a relative path rather than absolute.")
            return 1
    else:
        main_rel = detect_main_tex(new_dir)

    old_main = old_dir / main_rel
    new_main = new_dir / main_rel
    if not old_main.is_file():
        logging.error("Main file missing from old directory: %s", old_main)
        return 1
    if not new_main.is_file():
        logging.error("Main file missing from new directory: %s", new_main)
        return 1

    extra_args: List[str] = []
    if not args.no_default_latexdiff_args:
        extra_args.extend(DEFAULT_LATEXDIFF_ARGS)
    extra_args.extend(expand_latexdiff_args(args.latexdiff_arg))
    workspace, tmp_obj = prepare_workspace(args.keep_temp)

    try:
        tmp_old = workspace / "old"
        tmp_new = workspace / "new"
        copy_tree(old_dir, tmp_old)
        copy_tree(new_dir, tmp_new)

        ensure_bibliography(tmp_old / main_rel)
        ensure_bibliography(tmp_new / main_rel)

        diff_tex = run_latexdiff(
            tmp_old / main_rel,
            tmp_new / main_rel,
            tmp_new,
            extra_args,
        )
        annotate_structural_changes(diff_tex)
        sanitize_tabular_sections(diff_tex)

        pdf_path = compile_pdf(
            diff_tex,
            tmp_new,
            args.engine,
            [tmp_new, tmp_old],
        )
        output_pdf.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(pdf_path, output_pdf)
            logging.info("Diff PDF written to %s", output_pdf)
        except PermissionError as exc:
            fallback = output_pdf.with_name(
                f"{output_pdf.stem}.locked.{int(time.time())}{output_pdf.suffix}"
            )
            shutil.copy2(pdf_path, fallback)
            logging.warning(
                "Unable to overwrite %s (%s). Wrote diff to %s instead.",
                output_pdf,
                exc,
                fallback,
            )
        if args.keep_temp:
            logging.info("Temporary workspace retained at %s", workspace)
    except Exception as exc:
        logging.error("%s", exc)
        return 1
    finally:
        if tmp_obj is not None:
            tmp_obj.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
