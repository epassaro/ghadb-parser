#!/usr/bin/env python

import argparse
import json
from pathlib import Path


def main(folder: str, output: str) -> str:
    """
    This script reads JSON files from a the GitHub Advisory Database repository and
    extracts information from them to create a dictionary called `db`. The `db`
    dictionary maps aliases to affected package names and fixed versions, and is
    written to a JSON file.

    Args:
        folder (str): The path to the directory containing the JSON files.
        output (str): The path to the output JSON file.

    Returns:
        None
    """
    db = {}
    target = Path(folder)
    for json_file in target.glob("**/*.json"):

        with open(json_file, "r") as f:
            data = json.load(f)

        for als in data.get("aliases"):
            for aff in data.get("affected"):
                pkg = aff.get("package")

                try:
                    rng = aff.get("ranges")[0]
                    for evt in rng.get("events"):
                        fix = evt.get("fixed")

                except TypeError:
                    continue

                db.update({als: {"name": pkg.get("name"), "fixed": fix}})

    with open(output, "w") as f:
        json.dump(db, f, indent=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="repo2json")
    parser.add_argument("-i", "--input", help="path to the repository folder")
    parser.add_argument("-o", "--output", help="path to the output JSON file")
    args = parser.parse_args()

    main(args.input, args.output)
