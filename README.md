# NLNOG Looking Glass
This is the NLNOG Looking Glass for OpenBGPD, written by Teun Vink. This code is used as a front end to the <a href="https://openbgpd.org">OpenBGPD</a> route collector operated by NLNOG. The looking glass is hosted at https://lg.ring.nlnog.net. The code was inspired on [bird-lg](https://github.com/sileht/bird-lg/) by Mehdi Abaakouk.

**Please note**: this code is not intended as general purpose looking glass code. It is custom made for this specific use case. 

Questions about the status of the Looking Glass or its peers should be directed at ring-admins@nlnog.net.

## Known communities
Where possible the Looking Glass tries to provide information on communities used on routes. This is done using information stored in the [`communities`](communities) folder. This folder contains a file per ASN for known communities. Each line should contain a community entry followed by a comma, followed by the description of the community. Any line not matching this format is ignored.

The following types of entries are accepted for communities:
* **exact matches**, for example: `65535:666`, only matching this exact community
* **ranges**, for example: `65535:0-100`, matching anything from `65535:0` upto `65535:100`
* **single digit wildcards**, for example: `65535:x0`, matching for `65535:00`, `65535:10`, `65535:20`, etc
* **any number**, for example: `65535:nnn`, which matches any community staring with `65535:` followed by any number.

**Large communities** are supported as well. They can be formatted similar to regular communities, only contain three parts separated by semicolons. For example: `65535:0:12345`, `65535:nnn:0`, `65535:123:100x`.

**Extended communities** can be specified by the `label number` or `label number:number` notation, using the same wildcard options. For example: `soo 65535:0`, `soo 65535:nnn`.

When using wildcards, wildcard values can be replaced in the description by referencing them by number. For example:
```
65535:0:nnn,do not announce to AS$0
65535:x:nnn,prepend $0 times to AS$1
```

Additions and updates to the list of communities are welcome, if possible please provide a source for the data as a comment on the first line of the file, and name the file `asNNN.txt`, where `NNN` is the ASN.

## License
```
 Copyright (c) 2022 Stichting NLNOG <stichting@nlnog.net>

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
 ```
