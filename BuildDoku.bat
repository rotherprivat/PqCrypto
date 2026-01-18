@echo off
copy /y readme.md docfx\index.md
cd docfx
docfx docfx.json --serve
