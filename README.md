# LaTeX Differ

`latex_differ.py` creates a side-by-side PDF diff between two LaTeX project folders. It wraps `latexdiff`/`latexmk`, injects custom banners for floats, and restores key table tokens so that changes inside `table`, `figure`, `algorithm`, and similar environments are highlighted **in place** (cell-level edits, figure swaps, etc.).

## Features
- Works on full LaTeX **projects with nested folders**: both input directories are copied intact to a temporary workspace so relative paths/graphics continue to resolve.
- Auto-detects the main `.tex` file (or accept `--main`) and calls `latexdiff --flatten` so multi-file projects are merged.
- Structural highlighter adds `Updated Figure/Table/Algorithm` banners and keeps table separators, ensuring float changes are called out where they actually render.
- Normal, deleted, and added text is rendered using the standard `latexdiff` blue/red markup while tables still compile cleanly thanks to selective reinsertion of `%DIF` commands.
- Uses `latexmk` (fallback to `pdflatex`) and copies the resulting `diff.pdf` to your chosen output path, with a locked-file fallback if the viewer keeps the file open.

## Requirements
- Python 3.10+
- TeX Live (or another TeX distribution) providing `latexdiff`, `latexmk`, and `pdflatex`
- A shell environment that can run the above binaries on `PATH`

## Usage
```bash
python latex_differ.py path/to/old path/to/new -o diff.pdf
```

Common options:

| Flag | Description |
| ---- | ----------- |
| `--main path/to/main.tex` | Relative path to the main file if auto-detect fails. |
| `--latexdiff-arg "..."` | Pass-through options to `latexdiff` (repeatable). |
| `--no-default-latexdiff-args` | Disable the built-in safety exclusions. |
| `--engine {auto,latexmk,pdflatex}` | Force a specific LaTeX build tool. |
| `--keep-temp` | Leave the temporary workspace on disk for debugging. |
| `--verbose` | Show all commands executed. |

Example with explicit main file and custom PDF name:

```bash
python latex_differ.py ./old ./new --main access.tex -o trustworthiness_diff.pdf --verbose
```

## Output
- `diff.pdf` (or `diff.locked.<timestamp>.pdf` if the target is in use) written to the working directory.
- Temporary workspace printed when `--keep-temp` is set, useful if you want to inspect `diff.tex` or run LaTeX manually.

## Notes
- Because the script copies both trees before running `latexdiff`, any large assets (figures, data files) will be duplicated temporarily; ensure you have enough disk space.
- Bibliography flattening requires that `.bbl` files already exist in both source trees. Run `latexmk`/`bibtex` on each version first if citations are missing.
- This tool and its documentation were built with assistance from OpenAI Codex.
