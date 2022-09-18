# nlnog-lg
This is the NLNOG Looking Glass for OpenBPGD, written by Teun Vink <nlnog@teun.tv>. This code is used as a front end to the <a href="https://openbgpd.org">OpenBGPD</a> route collector operated by NLNOG. The looking glass is hosted at https://lg.ring.nlnog.net.

**Please note**: this code is not intended as general purpose looking glass code. It is custom made for this specific use case. 

Questions about the status of the Looking Glass or its peers should be directed at ring-admins@nlnog.net.

## known communities
Where possible the Looking Glass tries to provide information on communities used on routes. This is done using information stored in the [`communities`](communities) folder. This folder contains a file per ASN for known communities. Each line should contain a community entry followed by a comma, followed by the description of the community. Any line not matching this format is ignored.

The following types of entries are accepted for communities:
* **exact matches**, for example: `65535:666`, only matching this exact community
* **ranges**, for example: `65535:0-100`, matching anything from `65535:0` upto `65535:100`
* **single digit wildcards**, for example: `65535:x0`, matching for `65535:00`, `65535:10`, `65535:20`, etc
* **any number**, for example: `65535:nnn`, which matches any community staring with `65535:`

Additions and updates to the list of communities are welcome, if possible please provide a source for the data as a comment on the first line of the file, and name the file `asNNN.txt`, where `NNN` is the ASN.