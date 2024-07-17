#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
 Looking Glass code for the NLNOG Looking Glass.
 Written by Teun Vink <nlnog@teun.tv>

 Code contributions:
  * Filip Hruška
  * Martin Pels

 Source code: https://github/com/NLNOG/nlnog-lg


 Copyright (c) 2022 Stichting NLNOG <stichting@nlnog.net>

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.

 THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS. IN NO EVENT SH671025ALL THE AUTHOR BE LIABLE FOR
 ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""

import os
import re
import bz2
import glob
import json
import time
import yaml
import random
import string
import sqlite3
import textwrap
import argparse
import operator
import subprocess
from urllib.parse import unquote
from datetime import datetime, timezone, timedelta
import pydot
import netaddr
import requests
from commparser import BGPCommunityParser
from markupsafe import escape
from flask import Flask, abort, jsonify, render_template, request, Response, make_response, send_from_directory
from dns.resolver import Resolver, NXDOMAIN, Timeout, NoAnswer, NoNameservers

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--config", dest="config_file", help="path to config file", default="nlnog-lg.conf")
parser.add_argument("-d", "--debug", dest="debug", action="store_const", const=True, default=False)
arguments = parser.parse_args()

app = Flask(__name__)
app.config.from_pyfile(arguments.config_file)
app.secret_key = app.config["SESSION_KEY"]
app.debug = arguments.debug
app.version = "0.2.1"
asnlist = {}


class Datastore:
    communitylist = {}


class LGException(Exception):
    """ Custom exception
    """


def valid_archive_id(archive_id: str) -> bool:
    """ check if a string is a valid archive ID name
    """
    re_id = re.compile(r"[a-zA-Z0-9]{10}")
    return re_id.match(archive_id)


def is_regular_community(community: str) -> bool:
    """ check if a community string matches a regular community, with optional ranges
    """
    re_community = re.compile(r"^[\w\-]+:[\w\-]+$")
    return re_community.match(community)


def is_large_community(community: str) -> bool:
    """ check if a community string matches a large community, with optional ranges
    """
    re_large = re.compile(r"^[\w\-]+:[\w\-]+:[\w\-]+$")
    return re_large.match(community)


def is_extended_community(community: str) -> bool:
    """ check if a community string is an extended community, with optional ranges
    """
    re_extended = re.compile(r"^\w+ [\w\-]+(:[\w\-]+)?$")
    return re_extended.match(community)


def get_community_type(community: str) -> str:
    """ determine the community type of a community.
    """
    if is_regular_community(community):
        return "regular"
    if is_large_community(community):
        return "large"
    if is_extended_community(community):
        return "extended"

    print(f"unknown community type for '{community}'")
    return "unknown"


def fix_extended_community(community: str) -> str:
    """ rewrite the extended community from the format openbgpd uses to the rfc format
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


def read_communities() -> dict:
    """ Read the list of community definitions from communities/*.txt and translate them
        into a dictionary containing community lists for exact matches, ranges and regexps.
    """
    start = time.time()
    clist = {}
    re_range = re.compile(r"^(\d+)\-(\d+)$")
    re_regular_exact = re.compile(r"^\d+:\d+$")
    re_large_exact = re.compile(r"^\d+:\d+:\d+$")
    re_extended_exact = re.compile(r"^\w+ \w+(:\w+)$")

    print("reading communities")
    if app.config.get("COMMUNITY_FILE", ""):
        with open(app.config["COMMUNITY_FILE"], "r") as fh:
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
    files = glob.glob(f"{currentdir}/communities/*.txt")
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
            for entry in [line.strip() for line in filehandle.readlines()]:
                if entry.startswith("#") or "," not in entry:
                    continue
                (comm, desc) = entry.split(",", 1)
                ctype = get_community_type(comm)
                if ctype == "unknown":
                    print(f"unknown communtity format: '{comm}'")
                    continue

                if (ctype == "regular" and re_regular_exact.match(comm)) or \
                   (ctype == "large" and re_large_exact.match(comm)) or \
                   (ctype == "extended" and re_extended_exact.match(comm)):
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
                            print(f"Bad range for as {comm}, {first} should be less than {last}")
                            continue
                        clist[asn][ctype]["range"].append((first, last, desc))
                    if regex:
                        clist[asn][ctype]["re"].append((regex, desc))
                        clist[asn][ctype]["raw"][comm] = desc

    print(f"read communities in {time.time() - start} sec")
    return clist


def get_community_descr_from_list(community: str) -> str:
    """Given a community try to figure out if we can match it to something in the list
    """

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

    if asn not in data.communitylist.keys():
        # no AS specific things found, let's check wellknown
        if community in data.communitylist["well-known"][ctype]:
            return data.communitylist["well-known"][ctype][community]
        else:
            return ""

    # look if the bgpparser object can handle it
    if data.communitylist[asn]["obj"]:
        commdesc = data.communitylist[asn]["obj"].parse_community(community)
        if commdesc:
            return commdesc

    # first try to find an exact match
    if community in data.communitylist[asn][ctype]["exact"]:
        return data.communitylist[asn][ctype]["exact"][community]

    # try if it matches a range
    # TODO FIX THIS, we don't know where to apply the range here!
    for (start, end, desc) in data.communitylist[asn][ctype]["range"]:
        if start <= int(community) <= end:
            return desc

    # try a regexp instead
    for (regex, desc) in data.communitylist[asn][ctype]["re"]:
        match = regex.match(community)
        if match:
            for count, group in enumerate(match.groups()):
                desc = desc.replace(f"${count}", group)
            return desc

    # no luck
    return ""


def get_asn_name(asn: str):
    """ Lookup the name for an ASN. Keep it in a cache because we probably need it again.
    """
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


def whois_command(query: str):
    """ Run a WHOIS command and return the output.
    """
    server = []
    if app.config.get("WHOIS_SERVER", ""):
        server = ["-h", app.config.get("WHOIS_SERVER")]
    return subprocess.Popen(['whois'] + server + [query], stdout=subprocess.PIPE).communicate()[0].decode('utf-8', 'ignore')


def write_archive(data: dict, prefix: str, peer: str) -> str:
    """ Save LG output JSON, store data in a sqlite db, return the ID if successful
    """
    try:
        archive_id = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(10))
        currentdir = os.path.dirname(os.path.realpath(__file__))
        fname = "%s/%s/%s.json.bz2" % (currentdir, app.config.get("ARCHIVE_DIR", ""), archive_id)
        compressed = bz2.compress(bytes(json.dumps(data), "utf-8"))

        with open(fname, "wb") as fhandle:
            fhandle.write(compressed)
            fhandle.close()
        conn = sqlite3.connect(app.config.get("DB_FILE", "nlnog-lg.sqlite"))
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS archive
                    ([id] TEXT PRIMARY KEY, [created] DATETIME,
                    [prefix] TEXT, [peer] TEXT, [linked] INTEGER)""")
        conn.commit()

        cur.execute(f"INSERT INTO archive (id, created, prefix, peer, linked) VALUES ('{archive_id}',"
                    f"strftime('%s', 'now'), '{prefix}', '{peer}', 0)")
        conn.commit()
        conn.close()

        return archive_id
    except Exception as err:  # pylint: disable=broad-except
        print(err)
        raise LGException("Failed to store data.") from err


def read_archive(archive_id: str):
    """ Read LG output from a stored file.
    """

    if not valid_archive_id(archive_id):
        raise LGException("Invalid archive id.")

    try:
        conn = sqlite3.connect("%s" % app.config.get("DB_FILE", "nlnog-lg.sqlite"))
        cur = conn.cursor()
        cur.execute(f"SELECT prefix, peer, created FROM archive WHERE id='{archive_id}'")
        result = cur.fetchall()
        if len(result) != 1:
            raise LGException("ID not found.")
        (prefix, peer, created) = result[0]
        peer = peer.split(",")
        currentdir = os.path.dirname(os.path.realpath(__file__))
        filename = "%s/%s/%s.json.bz2" % (currentdir, app.config.get("ARCHIVE_DIR", ""), archive_id)
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
    """ Run a query on an OpenBGPD endpoint.
    """
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


def get_peer_info(names_only: bool = False, established_only: bool = False):
    """ Get a list of peers with optional additional information.
    """

    totals = {
        "v4_up": 0,
        "v6_up": 0,
        "v4_down": 0,
        "v6_down": 0,
        "v4_pfx": 0,
        "v6_pfx": 0,
    }

    status, result = openbgpd_command(app.config["ROUTER"], "summary")
    if not status:
        if names_only:
            return []
        return ({}, totals)

    data = []

    if names_only:
        return sorted(["%s (AS%s)" % (neighbor.get("description", "no name"), neighbor.get("remote_as", "unknown")) for neighbor in
                       result.get("neighbors", []) if neighbor["state"].lower() in ["up", "established"]])

    for neighbor in result.get("neighbors", []):
        props = {}
        props["name"] = neighbor.get("description", "no name")
        props["remote_as"] = neighbor["remote_as"]
        props["state"] = neighbor["state"]
        props["since"] = neighbor["last_updown"]
        props["prefixes"] = neighbor["stats"]["prefixes"]["received"]
        props["info"] = neighbor["remote_addr"]
        if (established_only and neighbor["state"].lower() in ["up", "established"]) or not established_only:
            data.append(props)
        afi = "v4" if netaddr.valid_ipv4(neighbor["remote_addr"]) else "v6"
        if neighbor["state"].lower() in ["up", "established"]:
            totals[f"{afi}_up"] += 1
            totals[f"{afi}_pfx"] += neighbor["stats"]["prefixes"]["received"]
        else:
            totals[f"{afi}_down"] += 1

    return (data, totals)


def resolve(domain: str) -> str:
    """ Try to resolve a domain.
    """
    resv = Resolver()
    resv.timeout = 1

    # Try resolving IPv6 first
    try:
        return str(resv.query(domain, 'AAAA')[0])
    except (NXDOMAIN, NoAnswer, NoNameservers, Timeout):
        pass

    # Try resolving IPv4
    try:
        return str(resv.query(domain, 'A')[0])
    except (NXDOMAIN, NoAnswer, NoNameservers, Timeout):
        pass

    # No answer
    return None


def generate_map(routes: dict, prefix: str):
    """ Generate a SVG map for routes for a prefix.
    """
    graph = pydot.Dot('map', graph_type='digraph', rankdir='LR')
    asns = {}
    links = []

    def add_asn(peer, fgcolor, bgcolor):
        if peer[0] not in asns:
            label = '\n'.join(textwrap.wrap(f"AS{peer[0]} | {escape(peer[1])}", width=28))
            asns[peer[0]] = pydot.Node(peer[0], label=label, fontsize="10", style="filled",
                                       fillcolor=bgcolor, fontcolor=fgcolor, fontname="Arial")

            graph.add_node(asns[peer[0]])

    def add_link(src, dest, label='', fontsize=10, color="black"):
        if f'{src}_{dest}' not in links or label != '':
            links.append(f'{src}_{dest}')

            edge = pydot.Edge(src, dest, label=label, fontsize=fontsize, fontname="Arial")
            edge.set_color(color)  # pylint: disable=no-member
            graph.add_edge(edge)  # pylint: disable=no-member

    def visualize_route(route):
        # Generate a consistent color hash
        color = 0xffffff
        for _ in route['aspath']:
            try:
                color *= int(_[0])
            except ValueError:
                continue
        color &= 0xffffff

        fontcolor = "#000000"
        # invert font color if the background is dark
        try:
            (red, green, blue) = tuple(int(("%06x" % color)[i:i+2], 16) for i in (0, 2, 4))
            if (red + green + blue) / 3 < 100:
                fontcolor = "#ffffff"
        except ValueError:
            pass

        is_subgraph = False
        subgraph = []
        for idx, ashop in enumerate(route['aspath']):
            if ashop[0] == "{":
                subgraph = []
                is_subgraph = True
            elif ashop[0] == "}":
                is_subgraph = False
                subg = pydot.Cluster('subgraph', graph_type="digraph")
                for item in subgraph:
                    label = '\n'.join(textwrap.wrap(f"AS{item[0]} | {escape(item[1])}", width=28))
                    asns[item[0]] = pydot.Node(item[0], label=label, fontsize="10", style="filled", fontname="Arial",
                                               fontcolor=fontcolor)
                    subg.add_node(asns[item[0]])
                graph.add_subgraph(subg)
            elif is_subgraph:
                subgraph.append(ashop)
                continue
            else:
                add_asn(ashop, fgcolor=fontcolor, bgcolor="#%06x" % color)

            # Add a link from the looking glass node node
            if idx == 0:
                add_link("lgnode", route['aspath'][0][0], label=route['peer'].upper(), fontsize=9)

            # Add a link towards the prefix
            if idx+1 == len(route['aspath']):
                if ashop[0] == "}":
                    new_idx = idx - 1
                    while route['aspath'][new_idx][0] != "{":
                        add_link(route['aspath'][new_idx][0], "DESTINATION", color="#%06x" % color)
                        new_idx -= 1
                else:
                    add_link(ashop[0], "DESTINATION", color="#%06x" % color)
                continue

            # Add links in between
            if route['aspath'][idx+1][0] == "{":
                new_idx = idx + 2
                # pull in all aggregates
                while route['aspath'][new_idx][0] != "}" and new_idx <= len(route['aspath']):
                    add_link(ashop[0], route['aspath'][new_idx][0], color="#%06x" % color)
                    new_idx += 1
            elif route['aspath'][idx][0] == "}":
                new_idx = idx - 1
                while route['aspath'][new_idx][0] != "{":
                    add_link(route['aspath'][idx - 1][0], route['aspath'][new_idx][0], color="#%06x" % color)
                    new_idx -= 1
            elif not is_subgraph:
                add_link(ashop[0], route['aspath'][idx+1][0], color="#%06x" % color)

    # Add the prefix node
    pfxnode = pydot.Node("DESTINATION", label=prefix, shape="box", fillcolor="#f4511e", style="filled", fontsize="10", fontname="Arial")
    graph.add_node(pfxnode)

    # Add the looking glass node
    lgnode = pydot.Node("lgnode", label=f"{app.config['LOOKING_GLASS_NAME'].upper()}",
                        shape="box", fillcolor="#f4511e", style="filled", fontsize="10", fontname="Arial")
    graph.add_node(lgnode)

    # Visualize every path
    for route in routes:
        visualize_route(route)

    return graph


def get_ringnodes():
    try:
        data = requests.get("https://api.ring.nlnog.net/1.0/nodes").json()
        if data["info"]["success"] != 1:
            return {}
        nodes = {}
        for node in data["results"]["nodes"]:
            if node["asn"] not in nodes:
                nodes[node["asn"]] = {node["hostname"].replace(".ring.nlnog.net", ""): node}
            else:
                nodes[node["asn"]][node["hostname"].replace(".ring.nlnog.net", "")] = node
        return nodes
    except Exception:
        return {}


@app.route("/")
def mainpage():
    """ Handle the main page: show a form.
    """
    (peerinfo, totals) = get_peer_info(names_only=False, established_only=True)
    if len(peerinfo) == 0:
        return render_template("error.html", warning=["No data received from the NLNOG Ring API endpoint."])

    peer = None
    if request.args.get("peer", "_") in [p["name"] for p in peerinfo]:
        peer = [p.split(" ")[0] for p in request.args.getlist('peer')]
    searchquery = request.cookies.get("searchquery", "")
    match = request.cookies.get("match", "exact")
    return render_template("form.html", peers=peerinfo, totals=totals, hideform=True, searchquery=searchquery, match=match, peer=peer)


@app.route("/summary")
def bgp_summary():
    """ Handle the BGP peer summary page.
    """
    (data, totals) = get_peer_info(names_only=False)
    if len(data) == 0:
        return render_template("error.html", warning=["No data received from the NLNOG Ring API endpoint."])
    peers = [peer["name"] for peer in data]
    return render_template('summary.html', peers=peers, summary=data, totals=totals)


@app.route("/detail/<peer>")
def show_peer_details(peer: str):
    """ Handle the peer details page.
    """
    ret, result = openbgpd_command(app.config["ROUTER"], "peer", {"neighbor": peer})
    ringnodes = get_ringnodes()
    remote_as = int(result["neighbors"][0]["remote_as"])
    errors = []
    if not ret:
        errors = [f"Failed to retrieve information for {peer}."]
    peers = get_peer_info(names_only=True, established_only=True)
    if len(peers) == 0:
        return render_template("error.html", warning=["No data received from the NLNOG Ring API endpoint."])
    return render_template('peer.html', peer=peer, peers=peers, data=result["neighbors"][0],
                           errors=errors, ringnodes=ringnodes.get(remote_as, {}))


@app.route("/prefix")
@app.route("/prefix/map")
@app.route("/prefix/map/fullscreen")
@app.route("/prefix/map/source")
@app.route("/prefix/text")
@app.route("/prefix/html")
@app.route("/query/<prefix>/<netmask>")
def show_route_for_prefix(prefix=None, netmask=None):
    """ Handle the prefix details page.

        Look up BGP routes.
    """
    warnings = []
    errors = []
    result = None
    query_id = "bla"

    if "saved" in request.args:
        query_id = request.args["saved"]
        try:
            (result, prefix, nodelist) = read_archive(request.args["saved"])
        except LGException as err:
            return render_template('error.html', errors=[err]), 400
    else:
        if netmask:
            prefix = f"{prefix}/{netmask}"
        else:
            prefix = unquote(request.args.get('q', '').strip())
        if not prefix:
            abort(400)

        args = {}

        # try to see if the argument is a network by typecasting it to IPNetwork
        try:
            net = netaddr.IPNetwork(prefix)
            # single addresses without a netmask would be a valid IPNetwork too, ignore them
            if "/" in prefix:
                if (netaddr.valid_ipv4(str(net.ip)) and net.prefixlen <= 16) or \
                   (netaddr.valid_ipv6(str(net.ip)) and net.prefixlen <= 48):
                    warnings.append("Not showing more specific routes, too many results, showing exact matches only.")
                elif request.args.get("match") == "orlonger" and request.path != '/prefix/map':
                    args["all"] = 1
        except netaddr.core.AddrFormatError:
            if not netaddr.valid_ipv4(prefix) and not netaddr.valid_ipv6(prefix):
                # Test domain resolution
                resolved = resolve(prefix)

                # Make sure the received answer is either valid IPv4 or IPv6
                if resolved and (netaddr.valid_ipv4(resolved) or netaddr.valid_ipv6(resolved)):
                    prefix = resolved
                else:
                    return render_template('error.html', errors=[f"{prefix} is not a valid IPv4 or IPv6 address."]), 400
        args["prefix"] = prefix

        result = {"rib": []}

        nodelist = []
        if request.args.get("all") == "all":
            nodelist = ["all"]
        else:
            nodelist = [p.split(" ")[0] for p in request.args.getlist('peer')]

        for peername in nodelist:
            if peername != "all":
                args["neighbor"] = peername

            # query the OpenBGPD API endpoint
            status, peerresult = openbgpd_command(app.config["ROUTER"], "route", args=args)
            if not status:
                return render_template('error.html', errors=["Failed to query the NLNOG Looking Glass backend."]), 400
            if "rib" in peerresult:
                result["rib"] = result["rib"] + peerresult["rib"]

        try:
            query_id = write_archive(result, prefix, ",".join(nodelist))
        except LGException:
            return render_template("error.html", errors=["Failed to store results."]), 400

    routes = {}

    # get a list of peers for the dropdown list in the menu
    peers = get_peer_info(names_only=True, established_only=True)
    if len(peers) == 0:
        return render_template("error.html", warning=["No data received from the NLNOG LG API endpoint."])

    ringnodes = get_ringnodes()

    create_date = None
    if result.get("created", False):
        create_date = datetime.utcfromtimestamp(result["created"]).strftime("%Y-%m-%d %H:%M:%S UTC")

    if "rib" in result:
        now = datetime.now(timezone.utc)
        for route in result.get("rib", []):
            delta = timedelta(seconds=int(route.get("last_update_sec", 0)))
            timestamp = now - delta
            otc = ""
            for attribute in route.get("attributes", []):
                if attribute["type"] == "OTC":
                    otc = (attribute["as"], get_asn_name(str(attribute["as"])))
            if route["prefix"] not in routes:
                routes[route["prefix"]] = []
            routes[route["prefix"]].append({
                "peer": route["neighbor"].get("description", "no description"),
                "ip": route["neighbor"]["remote_addr"],
                "bgp_id": route["neighbor"]["bgp_id"],
                "aspath": [(r, get_asn_name(r)) for r in route["aspath"].split(" ")],
                "origin": route["origin"],
                "source": route["source"],
                "communities": [(c, get_community_descr_from_list(c.strip()))
                                for c in route.get("communities", [])],
                "extended_communities": [(c, get_community_descr_from_list(c.strip()))
                                         for c in route.get("extended_communities", [])],
                "large_communities": [(c, get_community_descr_from_list(c.strip()))
                                      for c in route.get("large_communities", [])],
                "valid": route["valid"],
                "ovs": route["ovs"],
                "avs": route.get("avs", "unknown"),
                "exit_nexthop": route["exit_nexthop"],
                "last_update": route["last_update"],
                "last_update_at": timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "metric": route["metric"],
                "otc": otc,
            })

    # sort output by peername per prefix
    for pfx in routes:  # pylint: disable=consider-using-dict-items
        routes[pfx].sort(key=operator.itemgetter('peer'))

    # pylint: disable=undefined-loop-variable
    if request.path == '/prefix/map/fullscreen':
        # Return a fullscreen map svg
        dot = generate_map(routes[route["prefix"]], route["prefix"])
        svgmap = dot.create_svg().decode()  # pylint: disable=no-member
        response = Response(svgmap, mimetype='image/svg+xml')
        response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0'

        return response

    if request.path == '/prefix/map':
        # Return a map page
        dot = generate_map(routes[route["prefix"]], route["prefix"]).to_string()
        return render_template("map.html", peer=nodelist, peers=peers, routes=routes, prefix=prefix, query_id=query_id,
                               warnings=warnings, errors=errors, match=request.args.get("match"), collected=create_date,
                               dot=dot)

    if request.path == "/prefix/text" or (request.cookies.get("output") == "text" and request.path != "/prefix/html"):
        # return a route view in plain text style
        return render_template("route-text.html", peer=nodelist, peers=peers, routes=routes, prefix=prefix, query_id=query_id,
                               warnings=warnings, errors=errors, match=request.args.get("match"), collected=create_date,
                               ringnodes=ringnodes)

    # pylint: enable=undefined-loop-variable

    # Return a route view in HTML table style
    return render_template("route.html", peer=nodelist, peers=peers, routes=routes, prefix=prefix, query_id=query_id,
                           warnings=warnings, errors=errors, match=request.args.get("match"), collected=create_date,
                           ringnodes=ringnodes)


@app.route("/about")
def about():
    """ Handle the about page.
    """
    peers = get_peer_info(names_only=True, established_only=True)
    if len(peers) == 0:
        return render_template("error.html", warning=["No data received from the NLNOG Ring API endpoint."])

    return render_template("about.html", peers=peers)


@app.route("/communitylist")
def communitylist():
    """ Handle the communitylist page.
    """
    communities = []
    peers = get_peer_info(names_only=True, established_only=True)
    if len(peers) == 0:
        return render_template("error.html", warning=["No data received from the NLNOG Ring API endpoint."])
    for community in sorted([int(c) for c in read_communities()]):
        communities.append((community, get_asn_name(str(community))))

    return render_template("communities.html", communities=communities, peers=peers)


@app.route('/communitylist/<asn>')
def communitylist_specific(asn):
    """ Handle the community details page.
    """
    asn = unquote(asn.strip())
    communitylist = read_communities()
    if asn not in communitylist:
        abort(400)
    asname = get_asn_name(asn)
    peers = get_peer_info(names_only=True, established_only=True)
    if len(peers) == 0:
        return render_template("error.html", warning=["No data received from the NLNOG Ring API endpoint."])
    return render_template("communities-specific.html", ASN=asn, communities=communitylist[asn]["raw"], asname=asname, peers=peers)


@app.route("/statistics")
def stats():
    """ Handle the statistics page.
    """
    result, stats = openbgpd_command(app.config["ROUTER"], "memory")
    if not result:
        return render_template("error.html", errors=["Failed to retrieve Looking glass server statistics."])
    peers = get_peer_info(names_only=True, established_only=True)
    if len(peers) == 0:
        return render_template("error.html", warning=["No data received from the NLNOG Ring API endpoint."])
    return render_template("statistics.html", stats=stats, peers=peers)


@app.route("/preferences", methods=["GET", "POST"])
def store_preferences():
    """ Handle the preferences page.
    """
    peers = get_peer_info(names_only=True, established_only=True)
    if len(peers) == 0:
        return render_template("error.html", warning=["No data received from the NLNOG Ring API endpoint."])

    if request.method == "GET":
        outformat = request.cookies.get("output", "html")
        searchquery = request.cookies.get("searchquery", "")
        match = request.cookies.get("match", "exact")
        return render_template("preferences.html", peers=peers, outformat=outformat, searchquery=searchquery, match=match)

    outformat = request.form.get("output")
    searchquery = request.form.get("searchquery", "")
    match = request.form.get("match", "")
    errors = []

    if searchquery:
        try:
            netaddr.IPNetwork(searchquery)
        except netaddr.core.AddrFormatError:
            if not netaddr.valid_ipv4(searchquery) and not netaddr.valid_ipv6(searchquery):
                resolved = resolve(searchquery)
                if not (resolved and (netaddr.valid_ipv4(resolved) or netaddr.valid_ipv6(resolved))):
                    errors.append(f"'{searchquery}' is not a valid IPv4 or IPv6 address.")
                    searchquery = ""

    output = render_template("preferences.html", infoitems=["preferences stored."],
                             outformat=outformat, peers=peers, searchquery=searchquery, errors=errors, match=match)
    response = make_response(output)
    response.set_cookie("output", outformat, max_age=60*60*24*365*2)
    response.set_cookie("searchquery", searchquery, max_age=60*60*24*365*2)
    response.set_cookie("match", match, max_age=60*60*24*365*2)
    return response


@app.errorhandler(400)
def incorrect_request(_: str):
    """ A generic error handler for 400 errors.
    """
    return render_template('error.html', warnings=["The server could not understand the request"]), 400


@app.errorhandler(404)
def page_not_found(_: str):
    """ A generic error handler for 404 errors.
    """
    return render_template('error.html', warnings=["The requested URL was not found on the server."]), 404


@app.route("/whois")
def whois():
    """ handler for whois requests.
    """
    query = unquote(request.args.get('q', '').strip())
    if not query:
        abort(400)

    try:
        asnum = int(query)
        query = "as%d" % asnum
    except ValueError:
        try:
            netaddr.IPNetwork(query)
        except netaddr.core.AddrFormatError:
            abort(400)

    output = whois_command(query)

    # we return JSON data which is rendered in the front end
    return jsonify(output=output, title=query)


@app.route("/robots.txt")
def robots():
    """ handle robots.txt
    """
    return send_from_directory(app.static_folder, "robots.txt")


data = Datastore()
data.communitylist = read_communities()


if __name__ == "__main__":
    app.run(app.config.get("BIND_IP", "0.0.0.0"), app.config.get("BIND_PORT", 5000))
