"""Validate input options, generate configs for ZAP, and run docker container.

IN:
    * CLI options with templates and output locations.
    * STDIN: Endpoints, Headers, API spec. in JSON format.
OUT:
    * STDOUT: An acknowledgement on job started, in JSON format.

Docker container is spawned in detached mode.
Its result is to be placed under requested output location.
"""


import argparse
import docker
import jinja2
import json
import jsonschema
import requests
import shutil
import sys
import uuid
from pathlib import Path


DOCKER_IMAGE = 'zap-plus'

CFG_SCH = {"type": "object", "required": ["endpoints"], "additionalProperties": False, "properties": {
    "endpoints": {"type": "array",
        "items": {"type": "string"}},
    "headers": {"type": "array",
        "items": {"type": "array", "minItems": 2, "maxItems": 2,
            "prefixItems": [{"type": "string"}, {"type": "string"}]}},
    "oas": {"type": "object",
        "properties": {
            "file": {"type": "string"},
            "url": {"type": "string"}},
        "oneOf": [
            {"required": ["file"]},
            {"required": ["url"]}]}
}}

JOB_ID = str(uuid.uuid1())


## Parse CLI options
parser = argparse.ArgumentParser()
parser.add_argument('-o', '--out-dir', default='.')
parser.add_argument('-t', '--templates-dir', default='./templates-zap')
parser.add_argument('--do-not-run', action='store_true', help='Do not run Docker container')
args = parser.parse_args()

## Parse STDIN data
try:
    cfg = json.load(sys.stdin)
    jsonschema.validate(cfg, schema=CFG_SCH)
except Exception as e:
    print(type(e).__name__, str(e))
    sys.exit(1)

## Copy or download API spec. to the working dir,
## and adjust corresponding config section.
if 'oas' in cfg:
    if cfg['oas'].get('file'):
        shutil.copy(Path(cfg['oas']['file']), Path(args.out_dir))
        cfg['oas'] = {'file': '/zap/wrk/' + Path(cfg['oas']['file']).name}
    elif cfg['oas'].get('url'):
        with open(Path(args.out_dir, 'oas-downloaded.txt'), 'wb') as fo:
            fo.write(requests.get(cfg['oas']['url']).content)
        cfg['oas'] = {'file': '/zap/wrk/oas-downloaded.txt'}

cfg['job_id'] = JOB_ID

## Feed Jinja templates with the obtained config
jenv = jinja2.Environment(
    loader=jinja2.FileSystemLoader(args.templates_dir),
    trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True
)
jenv.globals = cfg
for template_file in [
        'zap-af.yaml.j2',      # URLs and API spec. ref. to go there
        'zap-options.cfg.j2',  # (Not parametrized yet)
        'hsendr.py.j2',        # Headers to go there
        ]:
    try:
        if template_rendered := jenv.get_template(template_file).render():
            with open(Path(args.out_dir, Path(template_file).stem), 'w') as fo:
                fo.write(template_rendered)
    except Exception as e:
        print(type(e).__name__, str(e))
        sys.exit(1)

## Container's processes will write to this subdirectory
Path(args.out_dir, 'out').mkdir(parents=False, exist_ok=True) # TODO: mode 777?

if args.do_not_run:
    sys.exit(0)

dclient = docker.from_env()
try:
    dcontainer = dclient.containers.run(
        image=DOCKER_IMAGE,
        volumes={Path(args.out_dir).resolve(): {'bind': '/zap/wrk', 'mode': 'rw'}},
        command='./zap.sh -cmd -autorun /zap/wrk/zap-af.yaml -configfile /zap/wrk/zap-options.cfg',
        auto_remove=True,
        remove=True,
        detach=True
    )
except Exception as e:
    # (e.g. docker.errors.ImageNotFound)
    print(type(e).__name__, str(e))
    sys.exit(1)

## Report on Docker container start
print(json.dumps(
    {
        'job_id': JOB_ID,
        str(dcontainer): None,
        'outpath': Path(args.out_dir, 'out').resolve().as_posix(),
    }
, indent=4))

## TODO: For Logging/Debug facility
dcontainer_logstream = dcontainer.logs(stream=True, timestamps=True)
with open(Path(args.out_dir, 'out', JOB_ID + '.log'), 'wb') as fo:
    fo.writelines(dcontainer_logstream)

dcontainer_exitstatus = dcontainer.wait()

## Report on Docker container finish
print(json.dumps(
    {
        'job_id': JOB_ID,
        str(dcontainer): dcontainer_exitstatus,
        'outpath': Path(args.out_dir, 'out').resolve().as_posix(),
    }
, indent=4))
