


## ZAP Config/Environment Generator

Sample usage:

```sh
python3 gen-zapenv.py -t templates-zap -o _tmp/zo <<< '
    {
        "endpoints": [
            "http://172.17.0.4:8081",
            "http://172.17.0.4:8081/klmn",
            "http://172.17.0.4:8081/prst"
        ],
        "headers": [
            ["X-Auth-Token", "00112233445566778899aabbccddeeff"]
        ],
        "oas": {"file": "oapi-specs/klmn.yaml"}
    }'
```
