# nlogx: NGiNX access log parser 

Extract meaningful information from NGiNX access logs.

## Getting Started

```shell script
go install github.com/jfsmig/nginx-logs/nlogx
```

``nlogx`` is designed to consume its standard input and produce valuable information
on its standard output. Only the

For each record in the access log, ``nlogx`` dumps a refined line with only a few useful fields:
* The source address of the request
* The day it happened
* The time of day
* The request's HTTP method
* the 
* The URL path
* The HTTP referrer field
* The beginning of the User-agent

## Usage

Without format flag, ``nlogx`` produces items that are easy to parse.

```shell script
$ nlogx < /path/to/log/file.access \
  | while read SRC DAY TIME CODE PATH REFERRER AGENT ; do \
      echo src=$SRC day=${DAY} time=${TIME} code=$CODE path=$PATH ref=$REFERRER agent=$AGENT ; \
  done
src=35.247.12.10 day=2020-05-13 time=20:15:43 code=301 path=/ ref=- agent="-"
src=35.247.12.10 day=2020-05-13 time=20:15:43 code=200 path=/index.html ref=http://gunkan.io/ agent="-"
src=195.54.160.121 day=2020-05-13 time=20:49:39 code=200 path=/index.html ref=http://51.38.234.78:80/api/jsonws/invoke agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chro
me/78.0.3904.108 Safari/537.36"
```

The `--json` (or `-j`) flag produce a stream of JSON objects, each on one line. The output is then
very ease to parse with tools like ``jq``:

```shell script
$ nlogx --json < /path/to/log/file.access | jq .src | sort | uniq -c
1 "195.54.160.121"
2 "35.247.12.10"
```

The ``--day`` (or ``-d``) option expects an integer (named `N` here-after) and it triggers the filtering of the lines
regarding the previous `N` days.

The ``--agent`` (or ``-A``) flag remove access log records exhibiting User-Agent fields know to belong to bots. 

The ``--source`` (or ``-s``) flag triggers the filtering of well-known source requests. So you can remove your own
probes, monitoring queries, etc.

The ``--addr`` (or ``-x``) options expects an argument that is an address, and only the access log
records from the given source will be displayed. The option can be repeated.

The ``--human`` (or ``-H``) flag has an effect with the default format of the output and produces lines
with an alignment that make them more suitable for human readers. As a trade-off, the output is harder to parse.

## How To Contribute

Contributions are what make the open source community such an amazing place.
Any contributions you make are greatly appreciated.

1. Fork the Project
2. Create your Feature Branch (git checkout -b feature/AmazingFeature)
3. Commit your Changes (git commit -m 'Add some AmazingFeature')
4. Push to the Branch (git push origin feature/AmazingFeature)
5. Open a Pull Request

For more information, please refer to [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

Distributed under the Mozilla Public License v2. See [LICENSE](./LICENSE) for more information.

I strongly believe in Open Source for many reasons:
* For software quality purposes because a software with open sources is the best
  way to have its bugs identified and fixed as soon as possible.
* For a greater adoption, we chose a deliberately liberal license so that
  there cannot be any legal concern.
* Because I do not expect to make any money with this, ever.

## Contact

Follow the development on GitHub with the [jfsmig/nginx-logs](https://github.com/jfsmig/nginx-logs) project.

## Acknowledgements

We welcome any volunteer and we already have a list of
[amazing authors of nlogx](./AUTHORS.md).
