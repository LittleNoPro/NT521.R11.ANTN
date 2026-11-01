#!/usr/bin/env bash
# Biên dịch báo cáo. Cần: lualatex + luaotfload + font DejaVu.
# Nếu thiếu luaotfload (texlive-luatex), các gói đã được cài sẵn trong ~/texmf.
set -e
export TEXMFHOME="${TEXMFHOME:-$HOME/texmf}"
cd "$(dirname "$0")"
lualatex -interaction=nonstopmode report.tex
lualatex -interaction=nonstopmode report.tex   # lần 2 cho mục lục
echo "-> report.pdf"
