import sys


def main() -> None:
    for line in sys.stdin:
        print("- " + line.strip())


if __name__ == "__main__":
    main()
