#!/usr/bin/env python3
"""Emit radsrs-compatible JSON text sequences through argusPython."""

import argparse
import sys


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Emit native Argus records as RFC 7464 JSON text sequences."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-r", "--read", metavar="FILE", help="read a native Argus file; '-' reads stdin")
    source.add_argument("-S", "--server", metavar="SERVER", help="read a native Argus TCP server")
    parser.add_argument("--filter", default="", help="Argus filter to enforce locally")
    args = parser.parse_args(argv)

    try:
        import argusPython
    except ImportError as error:
        parser.exit(
            1,
            f"{parser.prog}: cannot import argusPython with {sys.executable}: {error}\n"
            "Build and install pythonlib with this same Python interpreter.\n",
        )

    try:
        with argusPython.Reader(filter=args.filter) as reader:
            if args.read is not None:
                if args.read == "-":
                    reader.add_stdin()
                else:
                    reader.add_file(args.read)
            else:
                reader.add_server(args.server)
            reader.run(lambda record: sys.stdout.buffer.write(record.json_seq))
    except (ConnectionError, OSError, RuntimeError, ValueError) as error:
        parser.exit(1, f"{parser.prog}: {error}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
