#!/usr/bin/env python3
"""
 Module for parsing ietf-bgp-communities style BGP community definitions
 Based on code written by Martin Pels

 This file is part of the NLNOG Looking Glass code.
 Source code: https://github/com/NLNOG/nlnog-lg


 Copyright (c) 2022-2025 Stichting NLNOG <stichting@nlnog.net>

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

import re
import json
import requests


class BGPCommunityParser:
    """
    An object to keep track of one or more ietf-bgp-communities style BGP community definitions
    and do lookups on them.
    """
    def __init__(self, sources=None):
        self.comm_regular = []
        self.comm_large = []
        self.comm_extended = []
        self.sources = []

        if not sources:
            return

        if not isinstance(sources, list):
            sources = [sources]

        for source in sources:
            self.load_source(source)

    def load_source(self, source: str):
        """
        Load a ietf-bgp-communities style BGP community definition from
        an URL or file.
        """
        jdata = None
        if source.startswith("http://") or source.startswith("https://"):
            jdata = requests.get(source, timeout=5).json()
        else:
            jdata = json.load(source)

        self.comm_regular += jdata["ietf-bgp-communities:bgp-communities"].get("regular", [])
        self.comm_large += jdata["ietf-bgp-communities:bgp-communities"].get("large", [])
        self.comm_extended += jdata["ietf-bgp-communities:bgp-communities"].get("extended", [])
        self.sources.append(source)

    def __str__(self):
        """
        Simple string representation of the object.
        """
        return f"BGPCommunityParser object with {len(self.sources)} sources, " \
            f"{len(self.comm_regular)} regular, " \
            f"{len(self.comm_large)} large and {len(self.comm_extended)} communities"

    def parse_community(self, community: str) -> str:
        """
        Lookup a community string in the loaded community definitions.
        """
        if re.match(r"^\d+:\d+$", community):
            return self.parse_regular_community(community)
        if re.match(r"^\d+:\d+:\d+$", community):
            return self.parse_large_community(community)
        if re.match(r"^0x\d\d:0x\d\d:\d+:\d+$", community):
            return self.parse_extended_community(community)
        return None

    def parse_regular_community(self, community: str) -> str:
        """
        Process RFC1997 community
        """
        asn, content = community.split(":", 1)

        found = self._try_candidates_regular(asn, content, self.comm_regular)
        if found:
            fieldvals = self._candidate2fields(content, found["local-admin"], 16)
            return self._print_match(community, found, fieldvals)

        return None

    def parse_large_community(self, community: str) -> str:
        """
        Process RFC8092 community
        """
        asn, content1, content2 = community.split(":", 2)

        found = self._try_candidates_large(asn, content1, content2, self.comm_large)
        if found:
            fieldvals = self._candidate2fields_large(
                content1, content2, found["local-data-part-1"], found["local-data-part-2"]
            )
            return self._print_match(community, found, fieldvals)

        return None

    def parse_extended_community(self, community: str) -> str:
        """
        Process RFC4360 community
        """
        extype, exsubtype, asn, content = community.split(":", 3)

        found = self._try_candidates_extended(
            extype, exsubtype, asn, content, self.comm_extended
        )
        if found:
            if 'asn' in found:
                return(self._print_match(community, found, 
                                         self._candidate2fields(content, found['local-admin'], 32)))
            elif 'asn4' in found:
                return(self._print_match(community, found, 
                                         self._candidate2fields(content, found['local-admin'], 16)))
            else:
                return None

        return None

    def _try_candidates_regular(self, asn: str, content: str, candidates: list):
        """
        Try to find a matching Regular Community amongst candidate JSON definitions
        """
        for candidate in candidates:
            if asn != str(candidate["global-admin"]):
                continue
            if "format" in candidate["local-admin"]:
                if candidate["local-admin"]["format"] == "binary":
                    content = self._decimal2bits(content, 16)
            if self._try_candidate_fields(content, candidate["local-admin"]["field"]):
                return candidate
        return False

    def _try_candidates_large(self, asn, content1, content2, candidates):
        """
        Try to find a matching Large Community amongst candidate JSON definitions
        """
        for candidate in candidates:
            if asn != str(candidate["global-admin"]):
                continue
            if candidate["local-data-part-1"].get("format") == "binary":
                content1 = self._decimal2bits(content1, 32)
            if candidate["local-data-part-2"].get("format") == "binary":
                content2 = self._decimal2bits(content2, 32)
            if self._try_candidate_fields(
                content1, candidate["local-data-part-1"]["field"]
            ) and self._try_candidate_fields(
                content2, candidate["local-data-part-2"]["field"]
            ):
                return candidate
        return False

    def _try_candidates_extended(self, extype, exsubtype, asn, content, candidates):
        """
        Try to find a matching Extended Community amongst candidate JSON definitions
        """
        for candidate in candidates:
            contentstring = content
            if int(extype, 16) != candidate["type"]:
                continue
            if int(exsubtype, 16) != candidate["subtype"]:
                continue
            if "asn" in candidate:
                if asn != str(candidate["asn"]):
                    continue
            elif "asn4" in candidate:
                if asn != str(candidate["asn4"]):
                    continue
            else:
                continue
            if "format" in candidate["local-admin"]:
                if candidate["local-admin"]["format"] == "binary":
                    if "asn4" in candidate:
                        contentstring = self._decimal2bits(content, 16)
                    else:
                        contentstring = self._decimal2bits(content, 32)
            if self._try_candidate_fields(
                contentstring, candidate["local-admin"]["field"]
            ):
                return candidate
        return False

    def _try_candidate_fields(self, content, cfields):
        """
        Try to match fields from a single candidate JSON definition
        """
        pos = 0
        for cfield in cfields:
            if "length" in cfield:
                value = content[pos: pos + cfield["length"]]
            else:
                value = content
            pattern = cfield["pattern"]
            if pattern.startswith("^"):
                pattern = pattern[1:]
            if pattern.endswith("$"):
                pattern = pattern[:-1]
            if not re.match("^{}$".format(pattern), value):
                return False
            if "length" in cfield:
                pos = pos + cfield["length"]
        return True

    def _candidate2fields(self, contentbits, clocaladmin, localadminlength):
        """
        Link values from tested community to field names in matched candidate
        """
        fields = {}
        pos = 0
        if "format" in clocaladmin:
            if clocaladmin["format"] == "binary":
                contentbits = self._decimal2bits(contentbits, localadminlength)
        for fid, field in enumerate(clocaladmin["field"]):
            if "length" in field:
                length = field["length"]
            else:
                length = len(contentbits)
            fields[fid] = contentbits[pos: pos + length]
            pos = pos + length
        return fields

    def _candidate2fields_large(
        self, contentbits1, contentbits2, clocaldatapart1, clocaldatapart2
    ):
        """
        Link values from tested large community to field names in matched candidate
        """
        fields = {}
        if "format" in clocaldatapart1:
            if clocaldatapart1["format"] == "binary":
                contentbits1 = self._decimal2bits(contentbits1, 32)
        if "format" in clocaldatapart2:
            if clocaldatapart2["format"] == "binary":
                contentbits2 = self._decimal2bits(contentbits2, 32)

        pos = 0
        foffset = 0
        for fid, field in enumerate(clocaldatapart1["field"]):
            if "length" in field:
                length = field["length"]
            else:
                length = len(contentbits1)
            fields[foffset + fid] = contentbits1[pos: pos + length]
            pos = pos + length

        pos = 0
        foffset = len(clocaldatapart1["field"])
        for fid, field in enumerate(clocaldatapart2["field"]):
            if "length" in field:
                length = field["length"]
            else:
                length = len(contentbits2)
            fields[foffset + fid] = contentbits2[pos: pos + length]
            pos = pos + length
        return fields

    def _decimal2bits(self, decimal, length):
        """
        Convert decimal value to bit string
        """
        return f"{int(decimal):0{length}b}"

    def _print_match(self, community, candidate, fieldvals):
        """
        Return out a matched community description
        """
        output_sections = []
        output_fields = []
        if "local-admin" in candidate:
            for fid, field in enumerate(candidate["local-admin"]["field"]):
                if "description" in field:
                    output_fields.append(f'{field["name"]}={field["description"]}')
                else:
                    output_fields.append(f'{field["name"]}={fieldvals[fid]}')
            output_sections.append(",".join(output_fields))
        elif "local-data-part-1" in candidate:
            offset = 0
            output_fields = []
            for fid, field in enumerate(candidate["local-data-part-1"]["field"]):
                if "description" in field:
                    output_fields.append(f"{field['name']}={field['description']}")
                else:
                    output_fields.append(f"{field['name']}={fieldvals[offset + fid]}")
            output_sections.append(",".join(output_fields))

            offset = len(candidate["local-data-part-1"]["field"])
            output_fields = []
            for fid, field in enumerate(candidate["local-data-part-2"]["field"]):
                if "description" in field:
                    output_fields.append(f'{field["name"]}={field["description"]}')
                else:
                    output_fields.append(f'{field["name"]}={fieldvals[offset + fid]}')
            output_sections.append(",".join(output_fields))

        return f"{':'.join(output_sections)}"
