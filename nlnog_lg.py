#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
 Looking Glass code for the NLNOG Looking Glass.
 Written by Teun Vink <nlnog@teun.tv>

 Code contributions:
  * Filip Hruška

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
import glob
import textwrap
import argparse
import subprocess
from urllib.parse import unquote
from datetime import datetime, timezone, timedelta
import pydot
import netaddr
import requests
from flask import Flask, abort, jsonify, render_template, request, escape, Response
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


def read_communities():
    """ Read the list of community definitions from communities/*.txt and translate them
        into a dictionary containing community lists for exact matches, ranges and regexps.
    """
    communitylist = {}
    re_range = re.compile(r"^(\d+)\-(\d+)$")

    currentdir = os.path.dirname(os.path.realpath(__file__))
    files = glob.glob(f"{currentdir}/communities/*.txt")
    for filename in files:
        with open(filename, "r", encoding="utf8") as filehandle:
            for entry in [line.strip() for line in filehandle.readlines()]:
                if entry.startswith("#") or "," not in entry:
                    continue
                (comm, desc) = entry.split(",", 1)
                if ":" not in comm:
                    print(f"Doesn't look like a community: {entry}")
                    continue
                (asn, value) = comm.split(":", 1)
                if value.isnumeric():
                    if asn not in communitylist:
                        communitylist[asn] = {"exact": {comm: desc}, "re": [], "range": [], "raw": {}}
                    else:
                        communitylist[asn]["exact"][comm] = desc
                        communitylist[asn]["raw"][comm] = desc
                else:
                    # funky notations:
                    # nnn -> any number
                    # x -> any digit
                    # a-b -> numeric range a upto b
                    value = value.lower()
                    regex = None
                    if value == "nnn":
                        regex = re.compile(value.replace("nnn", r"\d+"))
                    elif "x" in value:
                        regex = re.compile(value.replace("x", r"\d"))
                    elif re_range.match(value):
                        match = re_range.match(value)
                        first, last = int(match.group(1)), int(match.group(2))
                        if first > last:
                            print(f"Bad range for as {asn}, {first} should be less than {last}")
                            continue
                        if asn not in communitylist:
                            communitylist[asn] = {"exact": {}, "re": [], "range": [(first, last, desc)]}
                        else:
                            communitylist[asn]["range"].append((first, last, desc))
                    if regex:
                        if asn not in communitylist:
                            communitylist[asn] = {"exact": {}, "re": [(regex, desc)], "range": [], "raw": {}}
                        else:
                            communitylist[asn]["re"].append((regex, desc))
                            communitylist[asn]["raw"][comm] = desc

    return communitylist


def get_community_descr_from_list(community: str, communitylist: dict):
    """Given a community try to figure out if we can match it to something in the list
    """

    # inore anything that doesn't look like a community
    if ":" not in community:
        return ""
    (asn, value) = community.split(":", 1)

    # if we can't find the ASN, we stop
    if asn not in communitylist:
        return ""

    # first try to find an exact match
    if community in communitylist[asn]["exact"]:
        return communitylist[asn]["exact"][community]

    # try if it matches a range
    for (start, end, desc) in communitylist[asn]["range"]:
        if start <= int(value) <= end:
            return desc

    # try a regexp instead
    for (regex, desc) in communitylist[asn]["re"]:
        if regex.match(value):
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
        query = resolver.query(f"AS{asn}.asn.cymru.com", "TXT")
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


def openbgpd_command(router: str, command: str, args: dict = None):
    """ Run a query on an OpenBGPD endpoint.
    """
    command_map = {
        "summary": "neighbors",
        "route": "rib",
        "peer": "neighbors",
    }

    if args is None:
        args = {}

    url = f"{router}/bgplgd/{command_map[command]}"
    data = requests.get(url, verify=False, params=args, timeout=60)
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
        return render_template("error.html", warnings=["NLNOG LG API not available"])

    data = []

    if names_only:
        return sorted([neighbor.get("description", "no name") for neighbor in
                       result.get("neighbors", []) if neighbor["state"].lower() in ["up", "established"]])

    for neighbor in result.get("neighbors", []):
        props = {}
        props["name"] = neighbor.get("description", "no name")
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
    graph = pydot.Dot('map', graph_type='digraph')

    asns = {}
    links = []

    def add_asn(peer):
        if peer[0] not in asns:
            label = '\n'.join(textwrap.wrap(f"AS{peer[0]} | {escape(peer[1])}", width=28))
            asns[peer[0]] = pydot.Node(peer[0], label=label, fontsize="10")

            graph.add_node(asns[peer[0]])

    def add_link(src, dest, label='', fontsize=10, fillcolor="black"):
        if f'{src}_{dest}' not in links or label != '':
            links.append(f'{src}_{dest}')

            edge = pydot.Edge(src, dest, label=label, fontsize=fontsize)
            edge.set_color(fillcolor)  # pylint: disable=no-member
            graph.add_edge(edge)  # pylint: disable=no-member

    def visualize_route(route):
        # Generate a consistent color hash
        color = 0xffffff
        for _ in route['aspath']:
            color *= int(_[0])
        color &= 0xffffff

        for idx, ashop in enumerate(route['aspath']):
            add_asn(ashop)

            # Add a link from the looking glass node node
            if idx == 0:
                add_link("lgnode", route['aspath'][0][0], label=route['peer'].upper(), fontsize=9, fillcolor="#%x" % color)

            # Add a link towards the prefix
            if idx+1 == len(route['aspath']):
                add_link(ashop[0], prefix, fillcolor="#%x" % color)
                continue

            # Add links in between
            add_link(ashop[0], route['aspath'][idx+1][0], fillcolor="#%x" % color)

    # Add the prefix node
    pfxnode = pydot.Node(prefix, label=prefix, shape="box", fillcolor="#F5A9A9", style="filled", fontsize="10")
    graph.add_node(pfxnode)

    # Add the looking glass node
    lgnode = pydot.Node("lgnode", label=f"{app.config['LOOKING_GLASS_NAME'].upper()}",
                        shape="box", fillcolor="#F5A9A9", style="filled", fontsize="10")
    graph.add_node(lgnode)

    # Visualize every path
    for route in routes:
        visualize_route(route)

    return graph.create_svg().decode()  # pylint: disable=no-member


@app.route("/")
def mainpage():
    """ Handle the main page: show a form.
    """
    (peerinfo, totals) = get_peer_info(names_only=False, established_only=True)
    peers = [peer["name"] for peer in peerinfo]
    peers.sort()
    return render_template("form.html", peers=peers, totals=totals)


@app.route("/summary")
def bgp_summary():
    """ Handle the BGP peer summary page.
    """
    (data, totals) = get_peer_info(names_only=False)
    peers = [peer["name"] for peer in data]
    return render_template('summary.html', peers=peers, summary=data, totals=totals)


@app.route("/detail/<peer>")
def show_peer_details(peer: str):
    """ Handle the peer details page.
    """
    ret, result = openbgpd_command(app.config["ROUTER"], "peer", {"neighbor": peer})
    errors = []
    if not ret:
        errors = [f"Failed to retrieve information for {peer}."]
    return render_template('peer.html', peer=peer, data=result["neighbors"][0], errors=errors)


@app.route("/prefix")
@app.route("/prefix/map")
@app.route("/prefix/map/fullscreen")
@app.route("/prefix/text")
def show_route_for_prefix():
    """ Handle the prefix details page.

        Look up BGP routes.
    """
    warnings = []
    errors = []
    prefix = unquote(request.args.get('q', '').strip())
    peer = unquote(request.args.get('peer', 'all').strip())
    if not prefix:
        abort(400)

    args = {}
    if peer != "all":
        args["neighbor"] = peer

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

    routes = {}

    # query the OpenBGPD API endpoint
    status, result = openbgpd_command(app.config["ROUTER"], "route", args=args)
    if not status:
        return render_template('error.html', errors=["Failed to query the NLNOG Looking Glass backend."]), 400

    # get a list of peers for the dropdown list in the menu
    peers = get_peer_info(names_only=True, established_only=True)
    communitylist = read_communities()

    if "rib" in result:
        now = datetime.now(timezone.utc)
        for route in result.get("rib", []):
            delta = timedelta(seconds=int(route.get("last_update_sec", 0)))
            timestamp = now - delta
            if route["prefix"] not in routes:
                routes[route["prefix"]] = []
            routes[route["prefix"]].append({
                "peer": route["neighbor"]["description"],
                "ip": route["neighbor"]["remote_addr"],
                "bgp_id": route["neighbor"]["bgp_id"],
                "aspath": [(r, get_asn_name(r)) for r in route["aspath"].split(" ")],
                "origin": route["origin"],
                "source": route["source"],
                "communities": [(c, get_community_descr_from_list(c, communitylist)) for c in route.get("communities", ["-"])],
                "extended_communities": route.get("extended_communities", ["-"]),
                "large_communities": route.get("large_communities", ["-"]),
                "valid": route["valid"],
                "ovs": route["ovs"],
                "exit_nexthop": route["exit_nexthop"],
                "last_update": route["last_update"],
                "last_update_at": timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "metric": route["metric"],
            })

    # pylint: disable=undefined-loop-variable
    if request.path == '/prefix/map/fullscreen':
        # Return a fullscreen map svg
        svgmap = generate_map(routes[route["prefix"]], route["prefix"])
        response = Response(svgmap, mimetype='image/svg+xml')
        response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0'

        return response

    if request.path == '/prefix/map':
        # Return a map page
        return render_template("map.html", peer=peer, peers=peers, routes=routes, prefix=route["prefix"],
                               warnings=warnings, errors=errors, match=request.args.get("match"))

    if request.path == "/prefix/text":
        # return a route view in plain text style
        return render_template("route-text.html", peer=peer, peers=peers, routes=routes, prefix=prefix,
                               warnings=warnings, errors=errors, match=request.args.get("match"))

    # pylint: enable=undefined-loop-variable

    # Return a route view in HTML table style
    return render_template("route.html", peer=peer, peers=peers, routes=routes, prefix=prefix,
                           warnings=warnings, errors=errors, match=request.args.get("match"))


@app.route("/about")
def about():
    """ Handle the about page.
    """
    peers = get_peer_info(names_only=True, established_only=True)
    return render_template("about.html", peers=peers)


@app.route("/communitylist")
def communitylist():
    """ Handle the communitylist page.
    """
    communities = []
    peers = get_peer_info(names_only=True, established_only=True)
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
    return render_template("communities-specific.html", ASN=asn, communities=communitylist[asn]["raw"], asname=asname, peers=peers)


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
        match = re.match(r"[\w\d-]*\.(?P<domain>[\d\w-]+\.[\d\w-]+)$", query)
        if match:
            query = query.groupdict()["domain"]

    output = whois_command(query)

    # we return JSON data which is rendered in the front end
    return jsonify(output=output, title=query)


if __name__ == "__main__":
    app.run(app.config.get("BIND_IP", "0.0.0.0"), app.config.get("BIND_PORT", 5000))
