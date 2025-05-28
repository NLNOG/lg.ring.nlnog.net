#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
 API endpoints for the NLNOG Looking Glass.
 This file provides JSON API endpoints for the NLNOG Looking Glass functionality.
"""

import operator
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

import netaddr
from flask import abort, Blueprint, jsonify, request
from nlnog_lg import (
    get_asn_name,
    get_community_descr_from_list,
    get_peer_info,
    get_ringnodes,
    LGException,
    openbgpd_command,
    read_archive,
    read_communities,
    whois_command,
    write_archive,
)

api = Blueprint("api", __name__)


@api.route("/summary")
def api_bgp_summary():
    """API endpoint for BGP peer summary information."""
    (data, totals) = get_peer_info(names_only=False)
    if len(data) == 0:
        return (
            jsonify({"error": "No data received from the NLNOG Ring API endpoint."}),
            500,
        )

    return jsonify({"peers": data, "totals": totals})


@api.route("/peer/<peer>")
def api_peer_details(peer: str):
    """API endpoint for peer details."""
    ret, result = openbgpd_command(api.config["ROUTER"], "peer", {"neighbor": peer})
    ringnodes = get_ringnodes()

    if not ret:
        return jsonify({"error": f"Failed to retrieve information for {peer}."}), 500

    remote_as = int(result["neighbors"][0]["remote_as"])

    return jsonify(
        {
            "peer": peer,
            "data": result["neighbors"][0],
            "ringnodes": ringnodes.get(remote_as, {}),
        }
    )


@api.route("/prefix")
def api_show_route_for_prefix():
    """API endpoint for prefix lookup."""
    warnings = []
    prefix = unquote(request.args.get("q", "").strip())

    if not prefix:
        return jsonify({"error": "No prefix specified."}), 400

    args = {}

    # Try to see if the argument is a network by typecasting it to IPNetwork
    try:
        net = netaddr.IPNetwork(prefix)
        # Single addresses without a netmask would be a valid IPNetwork too, ignore them
        if "/" in prefix:
            if request.args.get("match", "exact") != "exact" and (
                (netaddr.valid_ipv4(str(net.ip)) and net.prefixlen <= 16)
                or (netaddr.valid_ipv6(str(net.ip)) and net.prefixlen <= 48)
            ):
                warnings.append(
                    "Not showing more specific routes, too many results, showing exact matches only."
                )
            elif request.args.get("match") == "orlonger":
                args["all"] = 1
    except netaddr.core.AddrFormatError:
        if not netaddr.valid_ipv4(prefix) and not netaddr.valid_ipv6(prefix):
            # Test domain resolution
            from nlnog_lg import resolve

            resolved = resolve(prefix)

            # Make sure the received answer is either valid IPv4 or IPv6
            if resolved and (
                netaddr.valid_ipv4(resolved) or netaddr.valid_ipv6(resolved)
            ):
                prefix = resolved
            else:
                return (
                    jsonify(
                        {"error": f"{prefix} is not a valid IPv4 or IPv6 address."}
                    ),
                    400,
                )

    args["prefix"] = prefix

    result = {"rib": []}

    nodelist = []
    if request.args.get("all") == "all":
        nodelist = ["all"]
    else:
        nodelist = request.args.getlist("peer")
        if not nodelist:
            # If no peers specified, use all
            nodelist = ["all"]

    for peername in nodelist:
        if peername != "all":
            args["neighbor"] = peername

        # Query the OpenBGPD API endpoint
        status, peerresult = openbgpd_command(api.config["ROUTER"], "route", args=args)
        if not status:
            return (
                jsonify({"error": "Failed to query the NLNOG Looking Glass backend."}),
                500,
            )

        if "rib" in peerresult:
            result["rib"] = result["rib"] + peerresult["rib"]

    try:
        query_id = write_archive(result, prefix, ",".join(nodelist))
    except LGException:
        return jsonify({"error": "Failed to store results."}), 500

    routes = {}

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
                        (c, get_community_descr_from_list(c.strip()))
                        for c in route.get("communities", [])
                    ],
                    "extended_communities": [
                        (c, get_community_descr_from_list(c.strip()))
                        for c in route.get("extended_communities", [])
                    ],
                    "large_communities": [
                        (c, get_community_descr_from_list(c.strip()))
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

    # Sort output by peername per prefix
    for pfx in routes:
        routes[pfx].sort(key=operator.itemgetter("peer"))

    return jsonify(
        {
            "query_id": query_id,
            "prefix": prefix,
            "routes": routes,
            "warnings": warnings,
            "collected": create_date,
        }
    )


@api.route("/prefix/saved/<query_id>")
def api_show_saved_route(query_id):
    """API endpoint for retrieving saved prefix lookup results."""
    try:
        (result, prefix, nodelist) = read_archive(query_id)
    except LGException as err:
        return jsonify({"error": str(err)}), 400

    routes = {}
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
                        (c, get_community_descr_from_list(c.strip()))
                        for c in route.get("communities", [])
                    ],
                    "extended_communities": [
                        (c, get_community_descr_from_list(c.strip()))
                        for c in route.get("extended_communities", [])
                    ],
                    "large_communities": [
                        (c, get_community_descr_from_list(c.strip()))
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

    # Sort output by peername per prefix
    for pfx in routes:
        routes[pfx].sort(key=operator.itemgetter("peer"))

    return jsonify(
        {
            "query_id": query_id,
            "prefix": prefix,
            "peers": nodelist,
            "routes": routes,
            "collected": create_date,
        }
    )


@api.route("/communities")
def api_communitylist():
    """API endpoint for community list."""
    communities = []
    for community in sorted([int(c) for c in read_communities()]):
        communities.append({"asn": community, "name": get_asn_name(str(community))})

    return jsonify({"communities": communities})


@api.route("/communities/<asn>")
def api_communitylist_specific(asn):
    """API endpoint for community details for a specific ASN."""
    asn = unquote(asn.strip())
    communitylist = read_communities()

    if asn not in communitylist:
        return jsonify({"error": f"ASN {asn} not found in community list."}), 404

    asname = get_asn_name(asn)

    return jsonify(
        {"asn": asn, "name": asname, "communities": communitylist[asn]["raw"]}
    )


@api.route("/statistics")
def api_stats():
    """API endpoint for statistics."""
    result, stats = openbgpd_command(api.config["ROUTER"], "memory")

    if not result:
        return (
            jsonify({"error": "Failed to retrieve Looking glass server statistics."}),
            500,
        )

    return jsonify({"statistics": stats})


@api.route("/whois")
def api_whois():
    """API endpoint for whois requests."""
    query = unquote(request.args.get("q", "").strip())

    if not query:
        return jsonify({"error": "No query specified."}), 400

    try:
        asnum = int(query)
        query = f"as{asnum}"
    except ValueError:
        try:
            netaddr.IPNetwork(query)
        except netaddr.core.AddrFormatError:
            return jsonify({"error": f"Invalid query: {query}"}), 400

    output = whois_command(query)

    return jsonify({"query": query, "output": output})
