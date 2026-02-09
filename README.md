# LaTeX Differ

`latex_differ.py` creates a side-by-side PDF diff between two LaTeX sources. Each input can be a full project folder, a single `.tex` file, or a `.zip` archive. The script wraps `latexdiff`/`latexmk`, injects custom banners for floats, and restores key table tokens so that changes inside `table`, `figure`, `algorithm`, and similar environments are highlighted **in place** (cell-level edits, figure swaps, etc.).

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
### Basic command
```bash
python latex_differ.py path/to/old path/to/new -o diff.pdf
```

Each `path/to/...` may be:
- a directory containing a LaTeX project,
- a single `.tex` file (the script copies it into an isolated workspace),
- or a `.zip` archive (automatically extracted before diffing).

### Common options

| Flag | Description |
| ---- | ----------- |
| `--main path/to/main.tex` | Relative path to the main file if auto-detect fails. |
| `--latexdiff-arg "..."` | Pass-through options to `latexdiff` (repeatable). |
| `--no-default-latexdiff-args` | Disable the built-in safety exclusions. |
| `--engine {auto,latexmk,pdflatex}` | Force a specific LaTeX build tool. |
| `--keep-temp` | Leave the temporary workspace on disk for debugging. |
| `--verbose` | Show all commands executed. |

### Example workflows

Diff two directories (explicit main file + verbose logging):

```bash
python latex_differ.py ./old ./new --main access.tex -o trustworthiness_diff.pdf --verbose
```

Diff two zipped projects:

```bash
python latex_differ.py old_version.zip new_version.zip -o diff.pdf
```

Diff two standalone `.tex` files:

```bash
python latex_differ.py paper_v1.tex paper_v2.tex
```

## Output
- `diff.pdf` (or `diff.locked.<timestamp>.pdf` if the target is in use) written to the working directory.
- Temporary workspace printed when `--keep-temp` is set, useful if you want to inspect `diff.tex` or run LaTeX manually.

## Notes
- Inputs are copied/extracted into a temporary workspace before diffing, so originals remain untouched. Large assets (figures, images, data) are duplicated temporarily—ensure sufficient disk space.
- The script automatically runs `latexmk` (or falls back to `pdflatex` + `bibtex`) on each staged project so that `.bbl` files exist and newly added references appear in the diff.
- This tool and its documentation were built with assistance from OpenAI Codex.

## License
MIT (or adapt to your project’s chosen license). Contributions and suggestions welcome—please open a PR/issue on GitHub.
