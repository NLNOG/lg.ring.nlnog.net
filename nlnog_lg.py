#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
  Looking Glass code for the NLNOG Looking Glass.
  Written by Teun Vink <nlnog@teun.tv>

  Code contributions:
   * Filip Hruška
   * Martin Pels

  Source code: https://github/com/NLNOG/nlnog-lg


  Copyright (c) 2022-2024 Stichting NLNOG <stichting@nlnog.net>

  Permission to use, copy, modify, and distribute this software for any
  purpose with or without fee is hereby granted, provided that the above
  copyright notice and this permission notice appear in all copies.

  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""

import argparse
import operator
import textwrap
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

import netaddr
import pydot
from flask import (
    abort,
    Flask,
    jsonify,
    make_response,
    render_template,
    request,
    Response,
    send_from_directory,
    url_for,
)
from markupsafe import escape
from utils import (
    get_asn_name,
    get_community_descr_from_list,
    get_peer_info,
    get_ringnodes,
    LGException,
    openbgpd_command,
    read_archive,
    read_communities,
    resolve,
    whois_command,
    write_archive,
)

parser = argparse.ArgumentParser()
parser.add_argument(
    "-c",
    "--config",
    dest="config_file",
    help="path to config file",
    default="nlnog-lg.conf",
)
parser.add_argument(
    "-d", "--debug", dest="debug", action="store_const", const=True, default=False
)
arguments = parser.parse_args()

app = Flask(__name__)
app.config.from_pyfile(arguments.config_file)
app.secret_key = app.config["SESSION_KEY"]
app.debug = arguments.debug
app.version = "0.2.1"

# Register the API blueprint
from api import api

api.config = app.config
app.register_blueprint(api, url_prefix="/api")


class Datastore:
    communitylist = {}


def generate_map(routes: dict, prefix: str):
    """Generate a SVG map for routes for a prefix."""
    graph = pydot.Dot("map", graph_type="digraph", rankdir="LR")
    asns = {}
    links = []

    def add_asn(peer, fgcolor, bgcolor):
        if peer[0] not in asns:
            label = "\n".join(
                textwrap.wrap(f"AS{peer[0]} | {escape(peer[1])}", width=28)
            )
            asns[peer[0]] = pydot.Node(
                peer[0],
                label=label,
                fontsize="10",
                style="filled",
                fillcolor=bgcolor,
                fontcolor=fgcolor,
                fontname="Arial",
            )

            graph.add_node(asns[peer[0]])

    def add_link(src, dest, label="", fontsize=10, color="black"):
        if f"{src}_{dest}" not in links or label != "":
            links.append(f"{src}_{dest}")

            edge = pydot.Edge(
                src, dest, label=label, fontsize=fontsize, fontname="Arial"
            )
            edge.set_color(color)  # pylint: disable=no-member
            graph.add_edge(edge)  # pylint: disable=no-member

    def visualize_route(route):
        # Generate a consistent color hash
        color = 0xFFFFFF
        for _ in route["aspath"]:
            try:
                color *= int(_[0])
            except ValueError:
                continue
        color &= 0xFFFFFF

        fontcolor = "#000000"
        # invert font color if the background is dark
        try:
            (red, green, blue) = tuple(
                int(("%06x" % color)[i : i + 2], 16) for i in (0, 2, 4)
            )
            if (red + green + blue) / 3 < 100:
                fontcolor = "#ffffff"
        except ValueError:
            pass

        is_subgraph = False
        subgraph = []
        for idx, ashop in enumerate(route["aspath"]):
            if ashop[0] == "{":
                subgraph = []
                is_subgraph = True
            elif ashop[0] == "}":
                is_subgraph = False
                subg = pydot.Cluster("subgraph", graph_type="digraph")
                for item in subgraph:
                    label = "\n".join(
                        textwrap.wrap(f"AS{item[0]} | {escape(item[1])}", width=28)
                    )
                    asns[item[0]] = pydot.Node(
                        item[0],
                        label=label,
                        fontsize="10",
                        style="filled",
                        fontname="Arial",
                        fontcolor=fontcolor,
                    )
                    subg.add_node(asns[item[0]])
                graph.add_subgraph(subg)
            elif is_subgraph:
                subgraph.append(ashop)
                continue
            else:
                add_asn(ashop, fgcolor=fontcolor, bgcolor="#%06x" % color)

            # Add a link towards the prefix
            if idx + 1 == len(route["aspath"]):
                if ashop[0] == "}":
                    new_idx = idx - 1
                    while route["aspath"][new_idx][0] != "{":
                        add_link(
                            route["aspath"][new_idx][0],
                            "DESTINATION",
                            color="#%06x" % color,
                        )
                        new_idx -= 1
                else:
                    add_link(ashop[0], "DESTINATION", color="#%06x" % color)
                continue

            # Add links in between
            if route["aspath"][idx + 1][0] == "{":
                new_idx = idx + 2
                # pull in all aggregates
                while route["aspath"][new_idx][0] != "}" and new_idx <= len(
                    route["aspath"]
                ):
                    add_link(
                        ashop[0], route["aspath"][new_idx][0], color="#%06x" % color
                    )
                    new_idx += 1
            elif route["aspath"][idx][0] == "}":
                new_idx = idx - 1
                while route["aspath"][new_idx][0] != "{":
                    add_link(
                        route["aspath"][idx - 1][0],
                        route["aspath"][new_idx][0],
                        color="#%06x" % color,
                    )
                    new_idx -= 1
            elif not is_subgraph:
                add_link(ashop[0], route["aspath"][idx + 1][0], color="#%06x" % color)

    # Add the prefix node
    pfxnode = pydot.Node(
        "DESTINATION",
        label=prefix,
        shape="box",
        fillcolor="#f4511e",
        style="filled",
        fontsize="10",
        fontname="Arial",
    )
    graph.add_node(pfxnode)

    # Visualize every path
    for route in routes:
        visualize_route(route)

    return graph


@app.route("/")
def mainpage():
    """Handle the main page: show a form."""
    (peerinfo, totals) = get_peer_info(
        app.config, names_only=False, established_only=True
    )
    if len(peerinfo) == 0:
        return render_template(
            "error.html", warning=["No data received from the NLNOG Ring API endpoint."]
        )

    peer = None
    if request.args.get("peer", "_") in [p["name"] for p in peerinfo]:
        peer = [p.split(" ")[0] for p in request.args.getlist("peer")]
    searchquery = request.cookies.get("searchquery", "")
    match = request.cookies.get("match", "exact")
    return render_template(
        "form.html",
        peers=peerinfo,
        totals=totals,
        hideform=True,
        searchquery=searchquery,
        match=match,
        peer=peer,
    )


@app.route("/summary")
def bgp_summary():
    """Handle the BGP peer summary page."""
    (data, totals) = get_peer_info(app.config, names_only=False)
    if len(data) == 0:
        return render_template(
            "error.html", warning=["No data received from the NLNOG Ring API endpoint."]
        )
    peers = [peer["name"] for peer in data]
    return render_template("summary.html", peers=peers, summary=data, totals=totals)


@app.route("/detail/<peer>")
def show_peer_details(peer: str):
    """Handle the peer details page."""
    ret, result = openbgpd_command(app.config["ROUTER"], "peer", {"neighbor": peer})
    ringnodes = get_ringnodes()
    remote_as = int(result["neighbors"][0]["remote_as"])
    errors = []
    if not ret:
        errors = [f"Failed to retrieve information for {peer}."]
    peers = get_peer_info(app.config, names_only=True, established_only=True)
    if len(peers) == 0:
        return render_template(
            "error.html", warning=["No data received from the NLNOG Ring API endpoint."]
        )
    return render_template(
        "peer.html",
        peer=peer,
        peers=peers,
        data=result["neighbors"][0],
        errors=errors,
        ringnodes=ringnodes.get(remote_as, {}),
    )


@app.route("/prefix")
@app.route("/prefix/map")
@app.route("/prefix/map/fullscreen")
@app.route("/prefix/map/source")
@app.route("/prefix/text")
@app.route("/prefix/html")
@app.route("/query/<prefix>/<netmask>")
def show_route_for_prefix(prefix=None, netmask=None):
    """Handle the prefix details page.

    Look up BGP routes.
    """
    warnings = []
    errors = []
    result = None
    query_id = "bla"

    if "saved" in request.args:
        query_id = request.args["saved"]
        try:
            (result, prefix, nodelist) = read_archive(request.args["saved"], app.config)
        except LGException as err:
            return render_template("error.html", errors=[err]), 400
    else:
        if netmask:
            prefix = f"{prefix}/{netmask}"
        else:
            prefix = unquote(request.args.get("q", "").strip())
        if not prefix:
            abort(400)

        args = {}

        # try to see if the argument is a network by typecasting it to IPNetwork
        try:
            net = netaddr.IPNetwork(prefix)
            # single addresses without a netmask would be a valid IPNetwork too, ignore them
            if "/" in prefix:
                if request.args.get("match", "exact") != "exact" and (
                    (netaddr.valid_ipv4(str(net.ip)) and net.prefixlen <= 16)
                    or (netaddr.valid_ipv6(str(net.ip)) and net.prefixlen <= 48)
                ):
                    warnings.append(
                        "Not showing more specific routes, too many results, showing exact matches only."
                    )
                elif (
                    request.args.get("match") == "orlonger"
                    and request.path != "/prefix/map"
                ):
                    args["all"] = 1
        except netaddr.core.AddrFormatError:
            if not netaddr.valid_ipv4(prefix) and not netaddr.valid_ipv6(prefix):
                # Test domain resolution
                resolved = resolve(prefix)

                # Make sure the received answer is either valid IPv4 or IPv6
                if resolved and (
                    netaddr.valid_ipv4(resolved) or netaddr.valid_ipv6(resolved)
                ):
                    prefix = resolved
                else:
                    return (
                        render_template(
                            "error.html",
                            errors=[f"{prefix} is not a valid IPv4 or IPv6 address."],
                        ),
                        400,
                    )
        args["prefix"] = prefix

        result = {"rib": []}

        nodelist = []
        if request.args.get("all") == "all":
            nodelist = ["all"]
        else:
            nodelist = [p.split(" ")[0] for p in request.args.getlist("peer")]

        for peername in nodelist:
            if peername != "all":
                args["neighbor"] = peername

            # query the OpenBGPD API endpoint
            status, peerresult = openbgpd_command(
                app.config["ROUTER"], "route", args=args
            )
            if not status:
                return (
                    render_template(
                        "error.html",
                        errors=["Failed to query the NLNOG Looking Glass backend."],
                    ),
                    400,
                )
            if "rib" in peerresult:
                result["rib"] = result["rib"] + peerresult["rib"]

        try:
            query_id = write_archive(result, prefix, ",".join(nodelist), app.config)
        except LGException:
            return (
                render_template("error.html", errors=["Failed to store results."]),
                400,
            )

    routes = {}

    # get a list of peers for the dropdown list in the menu
    peers = get_peer_info(app.config, names_only=True, established_only=True)
    if len(peers) == 0:
        return render_template(
            "error.html", warning=["No data received from the NLNOG LG API endpoint."]
        )

    ringnodes = get_ringnodes()

    create_date = None
    if result.get("created", False):
        create_date = datetime.utcfromtimestamp(result["created"]).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )

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
            routes[route["prefix"]].append(
                {
                    "peer": route["neighbor"].get("description", "no description"),
                    "ip": route["neighbor"]["remote_addr"],
                    "bgp_id": route["neighbor"]["bgp_id"],
                    "aspath": [
                        (r, get_asn_name(r)) for r in route["aspath"].split(" ")
                    ],
                    "origin": route["origin"],
                    "source": route["source"],
                    "communities": [
                        (
                            c,
                            get_community_descr_from_list(
                                c.strip(), data.communitylist
                            ),
                        )
                        for c in route.get("communities", [])
                    ],
                    "extended_communities": [
                        (
                            c,
                            get_community_descr_from_list(
                                c.strip(), data.communitylist
                            ),
                        )
                        for c in route.get("extended_communities", [])
                    ],
                    "large_communities": [
                        (
                            c,
                            get_community_descr_from_list(
                                c.strip(), data.communitylist
                            ),
                        )
                        for c in route.get("large_communities", [])
                    ],
                    "valid": route["valid"],
                    "ovs": route["ovs"],
                    "avs": route.get("avs", "unknown"),
                    "exit_nexthop": route["exit_nexthop"],
                    "last_update": route["last_update"],
                    "last_update_at": timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "metric": route["metric"],
                    "otc": otc,
                }
            )

    # sort output by peername per prefix
    for pfx in routes:  # pylint: disable=consider-using-dict-items
        routes[pfx].sort(key=operator.itemgetter("peer"))

    # pylint: disable=undefined-loop-variable
    if request.path == "/prefix/map/fullscreen":
        # Return a fullscreen map svg
        dot = generate_map(routes[route["prefix"]], route["prefix"])
        svgmap = dot.create_svg().decode()  # pylint: disable=no-member
        response = Response(svgmap, mimetype="image/svg+xml")
        response.headers["Cache-Control"] = "no-cache, no-store, max-age=0"

        return response

    if request.path == "/prefix/map":
        # Return a map page
        dot = generate_map(routes[route["prefix"]], route["prefix"]).to_string()
        return render_template(
            "map.html",
            peer=nodelist,
            peers=peers,
            routes=routes,
            prefix=prefix,
            query_id=query_id,
            warnings=warnings,
            errors=errors,
            match=request.args.get("match", "Exact"),
            collected=create_date,
            dot=dot,
        )

    if request.path == "/prefix/text" or (
        request.cookies.get("output") == "text" and request.path != "/prefix/html"
    ):
        # return a route view in plain text style
        return render_template(
            "route-text.html",
            peer=nodelist,
            peers=peers,
            routes=routes,
            prefix=prefix,
            query_id=query_id,
            warnings=warnings,
            errors=errors,
            match=request.args.get("match"),
            collected=create_date,
            ringnodes=ringnodes,
        )

    # pylint: enable=undefined-loop-variable

    # Return a route view in HTML table style
    return render_template(
        "route.html",
        peer=nodelist,
        peers=peers,
        routes=routes,
        prefix=prefix,
        query_id=query_id,
        warnings=warnings,
        errors=errors,
        match=request.args.get("match"),
        collected=create_date,
        ringnodes=ringnodes,
    )


@app.route("/about")
def about():
    """Handle the about page."""
    peers = get_peer_info(app.config, names_only=True, established_only=True)
    if len(peers) == 0:
        return render_template(
            "error.html", warning=["No data received from the NLNOG Ring API endpoint."]
        )

    return render_template("about.html", peers=peers)


@app.route("/communitylist")
def communitylist():
    """Handle the communitylist page."""
    communities = []
    peers = get_peer_info(app.config, names_only=True, established_only=True)
    if len(peers) == 0:
        return render_template(
            "error.html", warning=["No data received from the NLNOG Ring API endpoint."]
        )
    for community in sorted([int(c) for c in read_communities(app.config)]):
        communities.append((community, get_asn_name(str(community))))

    return render_template("communities.html", communities=communities, peers=peers)


@app.route("/communitylist/<asn>")
def communitylist_specific(asn):
    """Handle the community details page."""
    asn = unquote(asn.strip())
    communitylist = read_communities(app.config)
    if asn not in communitylist:
        abort(400)
    asname = get_asn_name(asn)
    peers = get_peer_info(app.config, names_only=True, established_only=True)
    if len(peers) == 0:
        return render_template(
            "error.html", warning=["No data received from the NLNOG Ring API endpoint."]
        )
    return render_template(
        "communities-specific.html",
        ASN=asn,
        communities=communitylist[asn]["raw"],
        asname=asname,
        peers=peers,
    )


@app.route("/statistics")
def stats():
    """Handle the statistics page."""
    result, stats = openbgpd_command(app.config["ROUTER"], "memory")
    if not result:
        return render_template(
            "error.html", errors=["Failed to retrieve Looking glass server statistics."]
        )
    peers = get_peer_info(app.config, names_only=True, established_only=True)
    if len(peers) == 0:
        return render_template(
            "error.html", warning=["No data received from the NLNOG Ring API endpoint."]
        )
    return render_template("statistics.html", stats=stats, peers=peers)


@app.route("/preferences", methods=["GET", "POST"])
def store_preferences():
    """Handle the preferences page."""
    peers = get_peer_info(app.config, names_only=True, established_only=True)
    if len(peers) == 0:
        return render_template(
            "error.html", warning=["No data received from the NLNOG Ring API endpoint."]
        )

    if request.method == "GET":
        outformat = request.cookies.get("output", "html")
        searchquery = request.cookies.get("searchquery", "")
        match = request.cookies.get("match", "exact")
        return render_template(
            "preferences.html",
            peers=peers,
            outformat=outformat,
            searchquery=searchquery,
            match=match,
        )

    outformat = request.form.get("output")
    searchquery = request.form.get("searchquery", "")
    match = request.form.get("match", "")
    errors = []

    if searchquery:
        try:
            netaddr.IPNetwork(searchquery)
        except netaddr.core.AddrFormatError:
            if not netaddr.valid_ipv4(searchquery) and not netaddr.valid_ipv6(
                searchquery
            ):
                resolved = resolve(searchquery)
                if not (
                    resolved
                    and (netaddr.valid_ipv4(resolved) or netaddr.valid_ipv6(resolved))
                ):
                    errors.append(
                        f"'{searchquery}' is not a valid IPv4 or IPv6 address."
                    )
                    searchquery = ""

    output = render_template(
        "preferences.html",
        infoitems=["preferences stored."],
        outformat=outformat,
        peers=peers,
        searchquery=searchquery,
        errors=errors,
        match=match,
    )
    response = make_response(output)
    response.set_cookie("output", outformat, max_age=60 * 60 * 24 * 365 * 2)
    response.set_cookie("searchquery", searchquery, max_age=60 * 60 * 24 * 365 * 2)
    response.set_cookie("match", match, max_age=60 * 60 * 24 * 365 * 2)
    return response


@app.errorhandler(400)
def incorrect_request(_: str):
    """A generic error handler for 400 errors."""
    return (
        render_template(
            "error.html", warnings=["The server could not understand the request"]
        ),
        400,
    )


@app.errorhandler(404)
def page_not_found(_: str):
    """A generic error handler for 404 errors."""
    return (
        render_template(
            "error.html", warnings=["The requested URL was not found on the server."]
        ),
        404,
    )


@app.route("/whois")
def whois():
    """handler for whois requests."""
    query = unquote(request.args.get("q", "").strip())
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

    output = whois_command(query, app.config)

    # we return JSON data which is rendered in the front end
    return jsonify(output=output, title=query)


@app.route("/robots.txt")
def robots():
    """handle robots.txt"""
    return send_from_directory(app.static_folder, "robots.txt")


data = Datastore()
data.communitylist = read_communities(app.config)

# Initialize the API communitylist as well
api.communitylist = data.communitylist


if __name__ == "__main__":
    app.run(app.config.get("BIND_IP", "0.0.0.0"), app.config.get("BIND_PORT", 5000))
