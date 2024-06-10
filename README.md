This is a collection of wrappers for some tools prepared for DAST automation.
"Jockeys" are scripts that prepare configs and gather output.


## License

Where not stated otherwise, this work is licensed under MIT terms,
according to the root-level LICENSE file. LICENSE file(s) located
in subdirectories override root-level one:

- squma is a toolset that executes sqlmap and parses the results,
so that derivative work is under sqlmap-GPL terms.


## Docker-images Building Environment

### Make-powered way, for _plus_-images

```sh
cd zapplus
make full dump # i.e. with `--no-cache`

cd kaplus
make # express-build by default
make dump
```

### Bash _(sic!)_ script for other tools

```sh
./pull-n-dump.sh goatandwolf
./pull-n-dump.sh juiceshop
```


## ZAP Config/Environment Generator

Sample usage:

```sh
python3 zap-jockey.py -t templates-zap -o _tmp/zo <<< '
    {
        "endpoints": [
            "http://172.17.0.4:8081",
            "http://172.17.0.4:8081/klmn",
            "http://172.17.0.4:8081/prst"
        ],
        "excludepaths": [
            ".*/static/.*",
            ".*\\.js",
            ".*\\.css",
            ".*\\.png",
            ".*\\.jpg",
            ".*\\.jpeg",
            ".*\\.svg",
            ".*exit",
            ".*logout.*"
        ],
        "headers": [
            ["X-Auth-Token", "00112233445566778899aabbccddeeff"]
        ],
        "oas": {"file": "oapi-specs/klmn.yaml"}
    }'
```
