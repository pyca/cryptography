"""Versioning"""
import argparse

__version__ = "1.1.6"


def main():
    """Set the version attribute from the cmd line parameters"""
    parser = argparse.ArgumentParser(description="Set __version__")
    parser.add_argument("major", type=int)
    parser.add_argument("minor", type=int)
    parser.add_argument("micro", type=int)
    args = parser.parse_args()
    version_str = f"{args.major}.{args.minor}.{args.micro}"
    with open(__file__) as f:
        lines = f.readlines()
    i = lines.index('__version__ = "0.0.0"\n')
    new_version = lines[i].replace("0.0.0", version_str)
    print(new_version)
    lines[i] = new_version
    with open(__file__, "wt") as f:
        f.writelines(lines)


if __name__ == "__main__":
    main()
