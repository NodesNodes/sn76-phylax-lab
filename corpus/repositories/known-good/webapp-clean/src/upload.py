import tarfile
from pathlib import Path

DEST = Path("/srv/uploads")


def unpack(archive: str) -> None:
    with tarfile.open(archive) as tar:
        tar.extractall(DEST, filter="data")
