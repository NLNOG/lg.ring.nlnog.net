# NLNOG Looking Glass API Documentation

This document describes the API endpoints available for the NLNOG Looking Glass.

## Base URL

All API endpoints are available under the `/api` prefix.

## Endpoints

### BGP Summary

```
GET /api/summary
```

Returns a summary of all BGP peers.

**Response:**

```json
{
  "peers": [
    {
      "name": "peer1 (AS1234)",
      "remote_as": "1234",
      "state": "Established",
      "since": "2023-01-01 12:00:00",
      "prefixes": 123456,
      "info": "192.0.2.1"
    },
    ...
  ],
  "totals": {
    "v4_up": 10,
    "v6_up": 5,
    "v4_down": 1,
    "v6_down": 0,
    "v4_pfx": 1000000,
    "v6_pfx": 500000
  }
}
```

### Peer Details

```
GET /api/peer/<peer>
```

Returns detailed information about a specific BGP peer.

**Parameters:**

- `peer`: The name or IP address of the peer

**Response:**

```json
{
  "peer": "peer1",
  "data": {
    "remote_as": "1234",
    "state": "Established",
    "last_updown": "2023-01-01 12:00:00",
    ...
  },
  "ringnodes": {
    "node1": {
      "hostname": "node1.ring.nlnog.net",
      ...
    },
    ...
  }
}
```

### Prefix Lookup

```
GET /api/prefix
```

Returns routing information for a specific prefix.

**Parameters:**

- `q`: The prefix to look up (e.g., "192.0.2.0/24")
- `match`: Match type, can be "exact" or "orlonger" (default: "exact")
- `peer`: The peer(s) to query (can be specified multiple times, e.g., `peer=peer1&peer=peer2`)
- `all`: If set to "all", query all peers

**Examples:**

```bash
# Basic prefix lookup
curl "https://lg.ring.nlnog.net/api/prefix?q=8.8.8.0/24"

# Lookup with specific peer
curl "https://lg.ring.nlnog.net/api/prefix?q=8.8.8.0/24&peer=Google"

# Lookup with multiple peers
curl "https://lg.ring.nlnog.net/api/prefix?q=8.8.8.0/24&peer=Google&peer=Cloudflare"

# Lookup showing more specific routes
curl "https://lg.ring.nlnog.net/api/prefix?q=8.8.0.0/16&match=orlonger"

# Query all peers
curl "https://lg.ring.nlnog.net/api/prefix?q=8.8.8.0/24&all=all"

# Domain name resolution (automatically resolved to IP)
curl "https://lg.ring.nlnog.net/api/prefix?q=google.com"

# IPv6 prefix lookup
curl "https://lg.ring.nlnog.net/api/prefix?q=2001:4860:4860::8888/128"

# Lookup with URL encoding for special characters
curl "https://lg.ring.nlnog.net/api/prefix?q=192.0.2.0%2F24"
```

**Response:**

```json
{
  "query_id": "abcdef1234",
  "prefix": "8.8.8.0/24",
  "routes": {
    "8.8.8.0/24": [
      {
        "peer": "Google (AS15169)",
        "ip": "192.0.2.1",
        "bgp_id": "8.8.8.8",
        "aspath": [["15169", "Google LLC"]],
        "origin": "IGP",
        "source": "BGP",
        "communities": [["15169:1", "Google community"]],
        "extended_communities": [],
        "large_communities": [["15169:1:1", "Google large community"]],
        "valid": true,
        "ovs": "Valid",
        "avs": "Valid",
        "exit_nexthop": "192.0.2.1",
        "last_update": "1d 2h 3m 4s",
        "last_update_at": "2023-01-15 10:30:45 UTC",
        "metric": 0,
        "otc": ["15169", "Google LLC"]
      }
    ]
  },
  "warnings": ["Not showing more specific routes, too many results"],
  "collected": "2023-01-15 10:31:00 UTC"
}
```

**Use Cases:**

- **Network Troubleshooting**: Check routing paths and BGP attributes for specific prefixes
- **Route Monitoring**: Monitor how your prefixes are advertised across different peers
- **Path Analysis**: Analyze AS paths and detect routing anomalies
- **Community Analysis**: Examine BGP communities attached to routes
- **RPKI Validation**: Check route validation status (ROV/RPKI)
- **Multi-peer Comparison**: Compare routing information from different BGP peers

### Saved Prefix Lookup

```
GET /api/prefix/saved/<query_id>
```

Returns a previously saved prefix lookup result.

**Parameters:**

- `query_id`: The ID of the saved query

**Response:**

Same as the prefix lookup endpoint.

### Community List

```
GET /api/communities
```

Returns a list of all BGP communities.

**Response:**

```json
{
  "communities": [
    {
      "asn": 1234,
      "name": "AS1234 Name"
    },
    ...
  ]
}
```

### Community Details

```
GET /api/communities/<asn>
```

Returns details about communities for a specific ASN.

**Parameters:**

- `asn`: The ASN to look up

**Response:**

```json
{
  "asn": "1234",
  "name": "AS1234 Name",
  "communities": {
    "1234:1": "Community description",
    "1234:2": "Another community description",
    ...
  }
}
```

### Statistics

```
GET /api/statistics
```

Returns statistics about the looking glass server.

**Response:**

```json
{
  "statistics": {
    "memory": {
      "rde": {
        "rdemem": {
          "total": 1234567,
          ...
        },
        ...
      },
      ...
    }
  }
}
```

### WHOIS Lookup

```
GET /api/whois
```

Returns WHOIS information for a prefix or ASN.

**Parameters:**

- `q`: The prefix or ASN to look up

**Response:**

```json
{
  "query": "192.0.2.0/24",
  "output": "WHOIS output text..."
}
```

## Error Responses

All API endpoints return appropriate HTTP status codes and error messages in case of errors.

Example error response:

```json
{
  "error": "No prefix specified."
}
```

Common HTTP status codes:

- 200: Success
- 400: Bad request (e.g., invalid parameters)
- 404: Not found
- 500: Internal server error
