"""Render markdown into _site/."""
import pathlib


def main():
    out = pathlib.Path("_site")
    out.mkdir(exist_ok=True)
    for page in pathlib.Path("pages").glob("*.md"):
        (out / (page.stem + ".html")).write_text(page.read_text(), encoding="utf-8")


main()
