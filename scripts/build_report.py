#!/usr/bin/env python3
"""Build report_23b1075_23b1057.pdf from the markdown in report/.

Minimal, dependency-light markdown -> PDF using reportlab (no pandoc needed).
Supports: # / ## / ### headings, paragraphs, **bold**, `inline code`, bullet lists,
GitHub pipe tables, ``` fenced code blocks, > blockquotes, and ![caption](path) images.

Usage:  python3 scripts/build_report.py
"""
import glob
import os
import re
import html

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Preformatted,
                                Table, TableStyle, Image, PageBreak)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_DIR = os.path.join(ROOT, "report")
OUT = os.path.join(ROOT, "report_23b1075_23b1057.pdf")

styles = getSampleStyleSheet()
styles.add(ParagraphStyle("Body2", parent=styles["BodyText"], fontSize=9.5, leading=13,
                          spaceAfter=6))
styles.add(ParagraphStyle("H1x", parent=styles["Heading1"], fontSize=16, spaceBefore=10,
                          spaceAfter=6, textColor=colors.HexColor("#1a1a2e")))
styles.add(ParagraphStyle("H2x", parent=styles["Heading2"], fontSize=13, spaceBefore=10,
                          spaceAfter=5, textColor=colors.HexColor("#16213e")))
styles.add(ParagraphStyle("H3x", parent=styles["Heading3"], fontSize=11, spaceBefore=8,
                          spaceAfter=4, textColor=colors.HexColor("#0f3460")))
styles.add(ParagraphStyle("CodeBlk", parent=styles["BodyText"], fontName="Courier",
                          fontSize=8, leading=10, backColor=colors.HexColor("#f4f4f8"),
                          borderPadding=4, spaceAfter=6))
styles.add(ParagraphStyle("Quote", parent=styles["Body2"], leftIndent=10,
                          textColor=colors.HexColor("#444444"),
                          backColor=colors.HexColor("#f7f7fb"), borderPadding=4))
styles.add(ParagraphStyle("Cap", parent=styles["Body2"], fontSize=8,
                          textColor=colors.HexColor("#666666"), alignment=1, spaceAfter=10))


def inline(text):
    """Convert a subset of inline markdown to reportlab markup (escaped)."""
    text = html.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"`(.+?)`", r'<font face="Courier" size="8.5">\1</font>', text)
    # footnote-ish [n] and links [text](url) -> keep text
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", text)
    return text


def parse_table(lines):
    rows = []
    for ln in lines:
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        rows.append(cells)
    # drop the --- separator row
    rows = [r for r in rows if not all(set(c) <= set("-: ") for c in r)]
    data = [[Paragraph(inline(c), styles["Body2"]) for c in r] for r in rows]
    t = Table(data, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f4f8")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def render_markdown(md, flow):
    lines = md.split("\n")
    i = 0
    while i < len(lines):
        ln = lines[i]
        # fenced code
        if ln.strip().startswith("```"):
            i += 1
            buf = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            flow.append(Preformatted("\n".join(buf), styles["CodeBlk"]))
            continue
        # image
        m = re.match(r"!\[(.*?)\]\((.+?)\)", ln.strip())
        if m:
            cap, path = m.group(1), m.group(2)
            abspath = os.path.join(ROOT, path)
            if os.path.exists(abspath):
                img = Image(abspath)
                maxw = 165 * mm
                if img.drawWidth > maxw:
                    scale = maxw / img.drawWidth
                    img.drawWidth *= scale
                    img.drawHeight *= scale
                flow.append(img)
                if cap:
                    flow.append(Paragraph(inline(cap), styles["Cap"]))
            i += 1
            continue
        # table block
        if ln.strip().startswith("|"):
            buf = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                buf.append(lines[i])
                i += 1
            flow.append(parse_table(buf))
            flow.append(Spacer(1, 5))
            continue
        # headings
        if ln.startswith("### "):
            flow.append(Paragraph(inline(ln[4:]), styles["H3x"]))
        elif ln.startswith("## "):
            flow.append(Paragraph(inline(ln[3:]), styles["H2x"]))
        elif ln.startswith("# "):
            flow.append(Paragraph(inline(ln[2:]), styles["H1x"]))
        elif ln.strip().startswith(("- ", "* ")):
            buf = []
            while i < len(lines) and lines[i].strip().startswith(("- ", "* ")):
                buf.append("• " + inline(lines[i].strip()[2:]))
                i += 1
            for b in buf:
                flow.append(Paragraph(b, ParagraphStyle("li", parent=styles["Body2"],
                                                        leftIndent=12)))
            continue
        elif ln.strip().startswith(">"):
            buf = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip().lstrip(">").strip())
                i += 1
            flow.append(Paragraph(inline(" ".join(buf)), styles["Quote"]))
            continue
        elif ln.strip() == "":
            flow.append(Spacer(1, 3))
        else:
            # gather a paragraph
            buf = [ln]
            i += 1
            while i < len(lines) and lines[i].strip() != "" and \
                    not lines[i].startswith(("#", "|", ">", "- ", "* ", "```")) and \
                    not re.match(r"!\[", lines[i].strip()):
                buf.append(lines[i])
                i += 1
            flow.append(Paragraph(inline(" ".join(buf)), styles["Body2"]))
            continue
        i += 1


def main():
    flow = []
    # title page
    flow.append(Spacer(1, 40 * mm))
    flow.append(Paragraph("Breaking the Ratchet", styles["Title"]))
    flow.append(Paragraph("Assignment 3 — Technical Report", styles["H2x"]))
    flow.append(Spacer(1, 6 * mm))
    flow.append(Paragraph("Roll numbers: 23b1075, 23b1057", styles["Body2"]))
    flow.append(Paragraph("Double Ratchet + X3DH lab — implementation flaw analysis",
                          styles["Body2"]))
    flow.append(Spacer(1, 4 * mm))
    flow.append(Paragraph("<i>All attacks (0, 1, 2) and every quantitative claim were "
                          "reproduced on the provided Docker lab; logs and figures are "
                          "under results/ and regenerated by the scripts/ experiment "
                          "runners.</i>",
                          styles["Quote"]))
    flow.append(PageBreak())

    for path in sorted(glob.glob(os.path.join(REPORT_DIR, "*.md"))):
        with open(path) as f:
            render_markdown(f.read(), flow)
        flow.append(Spacer(1, 4))

    doc = SimpleDocTemplate(OUT, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm,
                            title="Breaking the Ratchet — Report")
    doc.build(flow)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
