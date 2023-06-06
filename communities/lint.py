#! /usr/bin/env python3

""" Check commmunity files for inconsistencies. """

import os
import re
import sys
import glob
from nlnog_lg import get_community_type

sys.path.append(".")

re_range = re.compile(r"^(\d+)\-(\d+)$")


def is_private(asn):
    """ check if a ASN is a private/reserved ASN. """
    asn = int(asn)
    return 64496 <= asn <= 64511 or 65536 <= asn <= 65551 or \
        64512 <= asn <= 65534 or 4200000000 <= asn <= 4294967294 or \
        asn == 65535 or 65552 <= asn <= 131071 or asn == 4294967295


def check_communitydesc(filename):
    """ Check community descriptions in a file. """

    re_range = re.compile(r"(\d+)\-(\d+)")
    re_regular_exact = re.compile(r"^\d+:\d+$")
    re_large_exact = re.compile(r"^\d+:\d+:\d+$")
    re_extended_exact = re.compile(r"^\w+ \w+(:\w+)$")

    lines = []
    warnings = 0
    with open(filename, "r", encoding="utf8") as filehandle:
        for entry in [line.strip() for line in filehandle.readlines()]:
            if entry.startswith("#") or "," not in entry:
                lines.append(("comment", entry))
                continue
            (comm, desc) = entry.split(",", 1)
            if ":" not in comm:
                lines.append(("WARN: malformed", entry))
                warnings += 1
                continue
            ctype = get_community_type(comm)
            if ctype == "unknown":
                lines.append(("WARN: unknown community type", entry))
                warnings += 1

            if (ctype == "regular" and re_regular_exact.match(comm)) or \
                (ctype == "large" and re_large_exact.match(comm)) or \
                (ctype == "extended" and re_extended_exact.match(comm)):
                # exact community, no ranges or wildcards
                if len(desc) > 50:
                    lines.append(("WARN: too long", entry))
                    warnings += 1
            else:
                comm = comm.lower()
                print(comm)
                regex = None
                if "nnn" in comm:
                    regex = re.compile(comm.replace("nnn", r"(\d+)"))
                elif "x" in comm:
                    regex = re.compile(comm.replace("x", r"(\d)"))
                elif re_range.match(comm):
                    match = re_range.match(comm)
                    first, last = int(match.group(1)), int(match.group(2))
                    if first > last:
                        lines.append(("WARN: incorrect range", entry))
                        warnings += 1
                        continue
                if not regex:
                    lines.append(("WARN: unknown format", entry))
                    warnings += 1


    return (warnings, lines)


def check_communities(files=None, all_lines=False, warnings_only=False):
    """ Check some or all files for inconsistencies and errors. """
    if not files:
        currentdir = os.path.dirname(os.path.realpath(__file__))
        files = glob.glob(f"{currentdir}/*.txt")

    total_warnings = 0
    for filename in files:
        (warnings, lines) = check_communitydesc(filename)
        total_warnings += warnings
        if warnings == 0 and not warnings_only:
            print(f"File: {filename}: OK")
        elif warnings > 0:
            print(f"File: {filename}: {warnings} warnings\n")
            print("      line  description       text")
            print("      ----  ----------------- ---------------------------------------")

            for index, (desc, line) in enumerate(lines):
                if desc.startswith("WARN:") or all_lines:
                    print("      %03d   %-15s   %s" % (index, desc, line))
            print()

    sys.exit(total_warnings)


if __name__ == "__main__":
    check_communities()
