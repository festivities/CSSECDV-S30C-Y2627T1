"""Build the Canvas .docx deliverables from the Markdown sources in this folder.

Run:  C:\\Apps\\convert-markdown\\.venv\\Scripts\\python.exe docs\\build_docx.py

Handles only the Markdown subset these docs use: #/##/### headings, paragraphs,
"- " bullets, "1. " numbered lists, pipe tables, fenced code, and inline
**bold**, _italic_, `code`.
"""
import re
from pathlib import Path

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.shared import Pt

HERE = Path(__file__).parent
DOCS = ["SECURITY_DOCUMENTATION", "ACCESS_CONTROL_MATRIX", "TEST_CASES"]
INLINE = re.compile(r"(\*\*.+?\*\*|`[^`]+`|(?<![A-Za-z0-9])_[^_]+_(?![A-Za-z0-9]))")


def add_inline(par, text):
    for part in INLINE.split(text):
        if not part:
            continue
        if part.startswith("**"):
            par.add_run(part[2:-2]).bold = True
        elif part.startswith("`"):
            par.add_run(part[1:-1]).font.name = "Consolas"
        elif part.startswith("_") and part.endswith("_") and len(part) > 2:
            par.add_run(part[1:-1]).italic = True
        else:
            par.add_run(part)


def cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def build(name):
    doc = Document()
    sec = doc.sections[0]  # landscape: the required tables are 3-5 columns wide
    sec.orientation = WD_ORIENT.LANDSCAPE
    sec.page_width, sec.page_height = sec.page_height, sec.page_width
    doc.styles["Normal"].font.size = Pt(10)

    lines = (HERE / f"{name}.md").read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
        elif line.startswith("```"):
            i += 1
            code = []
            while not lines[i].startswith("```"):
                code.append(lines[i])
                i += 1
            i += 1
            doc.add_paragraph().add_run("\n".join(code)).font.name = "Consolas"
        elif m := re.match(r"(#{1,3}) (.*)", line):
            doc.add_heading(m[2], level=len(m[1]) - 1)  # "# " -> Title
            i += 1
        elif line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(cells(lines[i]))
                i += 1
            rows.pop(1)  # the |---| separator
            table = doc.add_table(rows=len(rows), cols=len(rows[0]))
            table.style = "Table Grid"
            for r, row in enumerate(rows):
                for c, text in enumerate(row):
                    par = table.cell(r, c).paragraphs[0]
                    add_inline(par, text)
                    if r == 0:
                        for run in par.runs:
                            run.bold = True
            doc.add_paragraph()
        elif m := re.match(r"(- |\d+\. )(.*)", line):
            style = "List Bullet" if m[1] == "- " else "List Number"
            add_inline(doc.add_paragraph(style=style), m[2])
            i += 1
        else:
            add_inline(doc.add_paragraph(), line)
            i += 1
    doc.save(HERE / f"{name}.docx")
    print("wrote", f"{name}.docx")


if __name__ == "__main__":
    for n in DOCS:
        build(n)
