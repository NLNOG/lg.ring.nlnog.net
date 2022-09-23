#! /usr/bin/env python3

""" Check commmunity files for inconsistencies. """

import os
import re
import sys
import glob

re_range = re.compile(r"^(\d+)\-(\d+)$")


def is_private(asn):
    """ check if a ASN is a private/reserved ASN. """
    asn = int(asn)
    return 64496 <= asn <= 64511 or 65536 <= asn <= 65551 or \
        64512 <= asn <= 65534 or 4200000000 <= asn <= 4294967294 or \
        asn == 65535 or 65552 <= asn <= 131071 or asn == 4294967295


def check_communitydesc(filename):
    """ Check community descriptions in a file. """
    lines = []
    warnings = 0
    with open(filename, "r", encoding="utf8") as filehandle:
        for entry in [line.strip() for line in filehandle.readlines()]:
            if entry.startswith("#") or "," not in entry:
                lines.append(("comment", entry))
                continue
            (comm, desc) = entry.split(",", 1)
            if len(desc) > 50:
                lines.append(("WARN: too long", entry))
                warnings += 1
            if ":" not in comm:
                lines.append(("WARN: malformed", entry))
                warnings += 1
                continue
            (asn, value) = comm.split(":", 1)
            if f"as{asn}.txt" != filename.split("/")[-1] and not is_private(asn):
                lines.append(("WARN: wrong file", entry))
                warnings += 1
            if value.isnumeric():
                lines.append(("exact", entry))
            else:
                value = value.lower()
                if value == "nnn":
                    lines.append(("number", entry))
                elif "x" in value:
                    lines.append(("digit", entry))
                elif re_range.match(value):
                    match = re_range.match(value)
                    first, last = int(match.group(1)), int(match.group(2))
                    if first > last:
                        lines.append(("WARN: bad range", entry))
                        warnings += 1
                        continue
                    lines.append(("range", entry))

    return (warnings, lines)


def check_communities(files=None, all_lines=False, warnings_only=True):
    """ Check some or all files for inconsistencies and errors. """
    if not files:
        currentdir = os.path.dirname(os.path.realpath(__file__))
        files = glob.glob(f"{currentdir}/*.txt")

    total_warnings = 0
    for filename in files:
        (warnings, lines) = check_communitydesc(filename)
        total_warnings += warnings
        if warnings == 0 and not warnings_only:
            print(f"{filename}: OK")
        elif warnings > 0:
            print(f"{filename}: {warnings} warnings")
            print("line  description       text")
            print("----  ----------------- ---------------------------------------")

            for index, (desc, line) in enumerate(lines):
                if desc.startswith("WARN:") or all_lines:
                    print("%03d   %-15s   %s" % (index, desc, line))
            print()

    sys.exit(total_warnings)


if __name__ == "__main__":
    check_communities()
