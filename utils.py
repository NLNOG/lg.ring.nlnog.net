#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Shared utility functions for the NLNOG Looking Glass.
This module contains functions that are used by both the main application and the API.
"""

import bz2
import glob
import json
import os
import random
import re
import sqlite3
import string
import subprocess
import time
from datetime import datetime, timedelta, timezone

import netaddr
import requests
import yaml
from commparser import BGPCommunityParser
from dns.resolver import NoAnswer, NoNameservers, NXDOMAIN, Resolver, Timeout


class LGException(Exception):
    """Custom exception"""


def valid_archive_id(archive_id: str) -> bool:
    """check if a string is a valid archive ID name"""
    re_id = re.compile(r"[a-zA-Z0-9]{10}")
    return re_id.match(archive_id)


def is_regular_community(community: str) -> bool:
    """check if a community string matches a regular community, with optional ranges"""
    re_community = re.compile(r"^[\w\-]+:[\w\-]+$")
    return re_community.match(community)


def is_large_community(community: str) -> bool:
    """check if a community string matches a large community, with optional ranges"""
    re_large = re.compile(r"^[\w\-]+:[\w\-]+:[\w\-]+$")
    return re_large.match(community)


def is_extended_community(community: str) -> bool:
    """check if a community string is an extended community, with optional ranges"""
    re_extended = re.compile(r"^\w+ [\w\-]+(:[\w\-]+)?$")
    return re_extended.match(community)


def get_community_type(community: str) -> str:
    """determine the community type of a community."""
    if is_regular_community(community):
        return "regular"
    if is_large_community(community):
        return "large"
    if is_extended_community(community):
        return "extended"

    print(f"unknown community type for '{community}'")
    return "unknown"


def fix_extended_community(community: str) -> str:
    """rewrite the extended community from the format openbgpd uses to the rfc format
    see IANA_EXT_COMMUNITIES in bgpd.h source of openbgpd source code
    """

    replacemap = {
        "rt": "0x02:0x02",
        "soo": "0x02:0x03",
        "odi": "0x02:0x05",
        "bdc": "0x02:0x08",
        "srcas": "0x02:0x09",
        "l2vid": "0x02:0x0a",
    }

    if " " not in community:
        return community
    csplit = community.split(" ")
    if csplit[0] in replacemap:
        return f"{replacemap[csplit[0]]}:{csplit[1]}"
    return community


def read_communities(config, data=None) -> dict:
    """Read the list of community definitions from communities/as*.txt and translate them
    into a dictionary containing community lists for exact matches, ranges and regexps.
    """
    start = time.time()
    clist = {}
    re_range = re.compile(r"^(\d+)\-(\d+)$")
    re_regular_exact = re.compile(r"^\d+:\d+$")
    re_large_exact = re.compile(r"^\d+:\d+:\d+$")
    re_extended_exact = re.compile(r"^\w+ \w+(:\w+)$")

    print("reading communities")
    if config.get("COMMUNITY_FILE", ""):
        with open(config["COMMUNITY_FILE"], "r") as fh:
            try:
                commlist = yaml.safe_load(fh)
                sources = commlist.get("sources", {})
                for asn in sources:
                    if type(sources[asn]) == str:
                        sources[asn] = [sources[asn]]
                    commparser = BGPCommunityParser()
                    for url in sources[asn]:
                        commparser.load_source(url)
                    clist[asn] = {
                        "obj": commparser,
                        "regular": {"exact": {}, "re": [], "range": [], "raw": {}},
                        "large": {"exact": {}, "re": [], "range": [], "raw": {}},
                        "extended": {"exact": {}, "re": [], "range": [], "raw": {}},
                    }
            except Exception as err:
                print(f"Failed to parse community URL file: {err}")

    currentdir = os.path.dirname(os.path.realpath(__file__))
    files = glob.glob(f"{currentdir}/communities/as*.txt")
    files.append(f"{currentdir}/communities/well-known.txt")
    for filename in files:
        with open(filename, "r", encoding="utf8") as filehandle:
            asn = filename.split("/")[-1].replace(".txt", "")
            if asn not in clist:
                clist[asn] = {
                    "obj": None,
                    "regular": {"exact": {}, "re": [], "range": [], "raw": {}},
                    "large": {"exact": {}, "re": [], "range": [], "raw": {}},
                    "extended": {"exact": {}, "re": [], "range": [], "raw": {}},
                }
            replaceAsn = ""
            if os.path.islink(filename):
                replaceAsn = asn[2:]
            for entry in [line.strip() for line in filehandle.readlines()]:
                if entry.startswith("#") or "," not in entry:
                    continue
                if replaceAsn != "":
                    entry = entry.replace("<ASN>", replaceAsn)
                (comm, desc) = entry.split(",", 1)
                ctype = get_community_type(comm)
                if ctype == "unknown":
                    print(f"unknown communtity format: '{comm}'")
                    continue

                if (
                    (ctype == "regular" and re_regular_exact.match(comm))
                    or (ctype == "large" and re_large_exact.match(comm))
                    or (ctype == "extended" and re_extended_exact.match(comm))
                ):
                    # exact community, no ranges or wildcards
                    clist[asn][ctype]["exact"][comm] = desc
                    clist[asn][ctype]["raw"][comm] = desc
                else:
                    # funky notations:
                    # nnn -> any number
                    # x -> any digit
                    # a-b -> numeric range a upto b
                    comm = comm.lower()
                    regex = None
                    if "nnn" in comm:
                        regex = re.compile(comm.replace("nnn", r"(\d+)"))
                    elif "x" in comm:
                        regex = re.compile(comm.replace("x", r"(\d)"))
                    elif re_range.match(comm):
                        match = re_range.match(comm)
                        first, last = int(match.group(1)), int(match.group(2))
                        if first > last:
                            print(
                                f"Bad range for as {comm}, {first} should be less than {last}"
                            )
                            continue
                        clist[asn][ctype]["range"].append((first, last, desc))
                    if regex:
                        clist[asn][ctype]["re"].append((regex, desc))
                        clist[asn][ctype]["raw"][comm] = desc

    print(f"read communities in {time.time() - start} sec")
    return clist


def get_community_descr_from_list(community: str, communitylist: dict) -> str:
    """Given a community try to figure out if we can match it to something in the list"""

    community = community.strip()
    ctype = get_community_type(community)

    if ctype == "extended":
        asn = "as" + community.split(" ")[1].split(":")[0]
        community = fix_extended_community(community)
    else:
        asn = f"as{community.split(':')[0]}"

    if ctype == "unknown":
        print(f"Unknown community requested: {community}")
        return ""

    if asn not in communitylist.keys():
        # no AS specific things found, let's check wellknown
        if community in communitylist["well-known"][ctype]:
            return communitylist["well-known"][ctype][community]
        else:
            return ""

    # look if the bgpparser object can handle it
    if communitylist[asn]["obj"]:
        commdesc = communitylist[asn]["obj"].parse_community(community)
        if commdesc:
            return commdesc

    # first try to find an exact match
    if community in communitylist[asn][ctype]["exact"]:
        return communitylist[asn][ctype]["exact"][community]

    # try if it matches a range
    # TODO FIX THIS, we don't know where to apply the range here!
    for start, end, desc in communitylist[asn][ctype]["range"]:
        if start <= int(community) <= end:
            return desc

    # try a regexp instead
    for regex, desc in communitylist[asn][ctype]["re"]:
        match = regex.match(community)
        if match:
            for count, group in enumerate(match.groups()):
                desc = desc.replace(f"${count}", group)
            return desc

    # no luck
    return ""


asnlist = {}


def get_asn_name(asn: str):
    """Lookup the name for an ASN. Keep it in a cache because we probably need it again."""
    if not asn.isnumeric():
        return None
    asn = int(asn)
    if asn in asnlist:
        return asnlist[asn]

    # hints for well known private ASNs
    if 64496 <= asn <= 64511 or 65536 <= asn <= 65551:
        return "reserved for documentation (RFC5398)"
    if 64512 <= asn <= 65534 or 4200000000 <= asn <= 4294967294:
        return "reseved for internal use (RFC6996)"
    if asn == 65535 or 65552 <= asn <= 131071 or asn == 4294967295:
        return "reserved ASN"

    # use CYMRU's DNS service
    resolver = Resolver()
    resolver.search = ""
    try:
        query = resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT")
        asname = query.rrset[0].to_text().split("|")[-1][:-1].strip()
        asnlist[asn] = asname
        return asname
    except (NXDOMAIN, NoAnswer, NoNameservers, Timeout):
        return None


def whois_command(query: str, config):
    """Run a WHOIS command and return the output."""
    server = []
    if config.get("WHOIS_SERVER", ""):
        server = ["-h", config.get("WHOIS_SERVER")]
    return (
        subprocess.Popen(["whois"] + server + [query], stdout=subprocess.PIPE)
        .communicate()[0]
        .decode("utf-8", "ignore")
    )


def write_archive(data: dict, prefix: str, peer: str, config) -> str:
    """Save LG output JSON, store data in a sqlite db, return the ID if successful"""
    try:
        archive_id = "".join(
            random.SystemRandom().choice(string.ascii_letters + string.digits)
            for _ in range(10)
        )
        currentdir = os.path.dirname(os.path.realpath(__file__))
        fname = "%s/%s/%s.json.bz2" % (
            currentdir,
            config.get("ARCHIVE_DIR", ""),
            archive_id,
        )
        compressed = bz2.compress(bytes(json.dumps(data), "utf-8"))

        with open(fname, "wb") as fhandle:
            fhandle.write(compressed)
            fhandle.close()
        conn = sqlite3.connect(config.get("DB_FILE", "nlnog-lg.sqlite"))
        cur = conn.cursor()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS archive
                    ([id] TEXT PRIMARY KEY, [created] DATETIME,
                    [prefix] TEXT, [peer] TEXT, [linked] INTEGER)"""
        )
        conn.commit()

        cur.execute(
            f"INSERT INTO archive (id, created, prefix, peer, linked) VALUES ('{archive_id}',"
            f"strftime('%s', 'now'), '{prefix}', '{peer}', 0)"
        )
        conn.commit()
        conn.close()

        return archive_id
    except Exception as err:  # pylint: disable=broad-except
        print(err)
        raise LGException("Failed to store data.") from err


def read_archive(archive_id: str, config):
    """Read LG output from a stored file."""

    if not valid_archive_id(archive_id):
        raise LGException("Invalid archive id.")

    try:
        conn = sqlite3.connect("%s" % config.get("DB_FILE", "nlnog-lg.sqlite"))
        cur = conn.cursor()
        cur.execute(
            f"SELECT prefix, peer, created FROM archive WHERE id='{archive_id}'"
        )
        result = cur.fetchall()
        if len(result) != 1:
            raise LGException("ID not found.")
        (prefix, peer, created) = result[0]
        peer = peer.split(",")
        currentdir = os.path.dirname(os.path.realpath(__file__))
        filename = "%s/%s/%s.json.bz2" % (
            currentdir,
            config.get("ARCHIVE_DIR", ""),
            archive_id,
        )
        if not os.path.exists(filename):
            print(f"Failed to find {filename}.")
            raise LGException("Data not found.")
        with bz2.open(filename, "rb") as fhandle:
            data = json.loads(fhandle.read())
            data["created"] = created
            cur.execute(f"UPDATE archive SET linked=linked+1 WHERE id='{archive_id}'")
            conn.commit()
            return (data, prefix, peer)
    except Exception as err:
        raise LGException("Failed to read stored output.") from err


def openbgpd_command(router: str, command: str, args: dict = None):
    """Run a query on an OpenBGPD endpoint."""
    command_map = {
        "summary": "neighbors",
        "route": "rib",
        "peer": "neighbors",
        "memory": "memory",
    }

    if args is None:
        args = {}

    url = f"{router}/bgplgd/{command_map[command]}"
    try:
        data = requests.get(url, verify=False, params=args, timeout=60)
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
        return False, "The NLNOG LG API is not available."

    if data.status_code == 200:
        try:
            return True, data.json()
        except Exception as err:  # pylint: disable=broad-except
            print(f"Error retrieving data from {url}: {err}")
            return False, "No valid JSON returned by the LG endpoint."
    else:
        print(f"Error: {data.status_code}: {data.text}")
        return False, "Query failed."


def get_peer_info(config, names_only: bool = False, established_only: bool = False):
    """Get a list of peers with optional additional information."""

    totals = {
        "v4_up": 0,
        "v6_up": 0,
        "v4_down": 0,
        "v6_down": 0,
        "v4_pfx": 0,
        "v6_pfx": 0,
    }

    result = ""
    from_cache = False

    try:
        if os.path.exists(config.get("PEER_CACHE", "NOPEERCACHE")):
            with open(config["PEER_CACHE"], "r") as fh:
                cache = json.load(fh)
                ttl = int(config.get("PEER_CACHE_TTL", "300"))
                timestamp = cache.get("timestamp", 0)
                age = int(time.time()) - timestamp
                print(f"cache age: {age}")
                if age < ttl:
                    (status, result) = (True, cache["data"])
                    print("read cache")
                    from_cache = True
                else:
                    print("cache too old")
    except Exception as e:
        print(f"Something went wrong reading the peer cache: {e}")

    if not from_cache:
        print("querying API for peer list")
        status, q_result = openbgpd_command(config["ROUTER"], "summary")

        if not status:
            if names_only:
                return []
            return ({}, totals)

        result = q_result

        try:
            with open(config["PEER_CACHE"], "w") as fh:
                json.dump({"timestamp" : int(time.time()), "data": result}, fh)
                print("saved cache")
        except Exception as e:
            print(f"Failed to store cache: {e}")

    data = []

    if names_only:
        return sorted(
            [
                "%s (AS%s)"
                % (
                    neighbor.get("description", "no name"),
                    neighbor.get("remote_as", "unknown"),
                )
                for neighbor in result.get("neighbors", [])
                if neighbor["state"].lower() in ["up", "established"]
            ]
        )

    for neighbor in result.get("neighbors", []):
        props = {}
        props["name"] = neighbor.get("description", "no name")
        props["remote_as"] = neighbor["remote_as"]
        props["state"] = neighbor["state"]
        props["since"] = neighbor["last_updown"]
        props["prefixes"] = neighbor["stats"]["prefixes"]["received"]
        props["info"] = neighbor["remote_addr"]
        if (
            established_only and neighbor["state"].lower() in ["up", "established"]
        ) or not established_only:
            data.append(props)
        afi = "v4" if netaddr.valid_ipv4(neighbor["remote_addr"]) else "v6"
        if neighbor["state"].lower() in ["up", "established"]:
            totals[f"{afi}_up"] += 1
            totals[f"{afi}_pfx"] += neighbor["stats"]["prefixes"]["received"]
        else:
            totals[f"{afi}_down"] += 1

    return (data, totals)


def resolve(domain: str) -> str:
    """Try to resolve a domain."""
    resv = Resolver()
    resv.timeout = 1

    # Try resolving IPv6 first
    try:
        return str(resv.query(domain, "AAAA")[0])
    except (NXDOMAIN, NoAnswer, NoNameservers, Timeout):
        pass

    # Try resolving IPv4
    try:
        return str(resv.query(domain, "A")[0])
    except (NXDOMAIN, NoAnswer, NoNameservers, Timeout):
        pass

    # No answer
    return None


def get_ringnodes():
    try:
        data = requests.get("https://api.ring.nlnog.net/1.0/nodes").json()
        if data["info"]["success"] != 1:
            return {}
        nodes = {}
        for node in data["results"]["nodes"]:
            if node["asn"] not in nodes:
                nodes[node["asn"]] = {
                    node["hostname"].replace(".ring.nlnog.net", ""): node
                }
            else:
                nodes[node["asn"]][
                    node["hostname"].replace(".ring.nlnog.net", "")
                ] = node
        return nodes
    except Exception:
        return {}
