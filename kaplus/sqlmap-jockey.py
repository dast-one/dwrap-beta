#!/usr/bin/env python3

import pathlib
import sys
import threading

sys.path.insert(1, pathlib.Path('/usr/share/sqlmap').expanduser().as_posix())
from lib.utils.api import *
from lib.utils.api import _client
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import input as _input
from thirdparty.six.moves import urllib as _urllib
# from sqlmapapi import *

# sys.path.insert(1, pathlib.Path('~/prj/masc/src/dyna-misc/kaplus').expanduser().as_posix())
from openapi_sqlmap import oas_load, sqlmap_tasks


class SqlmapApiClient:
    """Based on sqlmapapi client.

    [lib/utils/api.py](https://github.com/sqlmapproject/sqlmap/blob/master/lib/utils/api.py)
    """

    def __init__(
        self,
        host=RESTAPI_DEFAULT_ADDRESS, port=RESTAPI_DEFAULT_PORT,
        username=None, password=None
    ):
        DataStore.username = username
        DataStore.password = password

        self.addr = "http://%s:%d" % (host, port)
        logger.info("Starting REST-JSON API client to '%s'..." % self.addr)

        try:
            _client(self.addr)
        except Exception as ex:
            if not isinstance(ex, _urllib.error.HTTPError) or ex.code == _http_client.UNAUTHORIZED:
                errMsg = "There has been a problem while connecting to the "
                errMsg += "REST-JSON API server at '%s' " % self.addr
                errMsg += "(%s)" % getSafeExString(ex)
                logger.critical(errMsg)
                return

    def new_scan_w(self, command):
        """Create and start new scan, waiting for finish.
        """
        if isinstance(command, str):
            try:
                argv = ["sqlmap.py"] + shlex.split(command)[1:]
            except Exception as ex:
                logger.error("Error occurred while parsing arguments ('%s')" % getSafeExString(ex))
                taskid = None
                raise
        elif all(isinstance(x, str) for x in command):
            argv = list(command)
        else:
            logger.error("Cannot decide WTF is ('%s')" % getSafeExString(ex))

        logger.info(argv)

        try:
            cmdLineOptions = cmdLineParser(argv).__dict__
        except:
            taskid = None
            raise

        for key in list(cmdLineOptions):
            if cmdLineOptions[key] is None:
                del cmdLineOptions[key]

        raw = _client("%s/task/new" % self.addr)
        res = dejsonize(raw)
        if not res["success"]:
            logger.error("Failed to create new task ('%s')" % res.get("message", ""))
            raise
        taskid = res["taskid"]
        logger.info("New task ID is '%s'" % taskid)

        raw = _client("%s/scan/%s/start" % (self.addr, taskid), cmdLineOptions)
        res = dejsonize(raw)
        if not res["success"]:
            logger.error("Failed to start scan ('%s')" % res.get("message", ""))
            raise
        logger.info(f"[{taskid}] started")

        # if command in ("data", "log", "status", "stop", "kill"):
        #     if not taskid:
        #         logger.error("No task ID in use")
        #         continue
        #     raw = _client("%s/scan/%s/%s" % (addr, taskid, command))
        #     res = dejsonize(raw)
        #     if not res["success"]:
        #         logger.error("Failed to execute command %s" % command)
        #     dataToStdout("%s\n" % raw)

        
        while dejsonize(_client("%s/scan/%s/%s" % (self.addr, taskid, 'status'))).get('status') == 'running':
            time.sleep(2)
        logger.info(f"[{taskid}] finished")

    def list_tasks(self):
        command = 'list'
        raw = _client("%s/admin/%s" % (self.addr, command))
        res = dejsonize(raw)
        if not res["success"]:
            logger.error("Failed to execute command %s" % command)
        elif command == "flush":
            taskid = None
        dataToStdout("%s\n" % raw)


def thread_worker(sqlmap_task):
    with pool_sema:
        # logger.debug(sqlmap_task)
        sm.new_scan_w(sqlmap_task)


logger.setLevel(logging.DEBUG)

max_threads = 3
pool_sema = threading.BoundedSemaphore(max_threads)

sm = SqlmapApiClient()
sm.list_tasks()

base_url = 'http://localhost:10013'

for smt in sqlmap_tasks(oas_load('/hka/oas.yaml')):
    u = '/'.join((base_url.rstrip('/'), smt['url'].lstrip('/')))
    t = threading.Thread(
        target=thread_worker,
        args=(
            f"new -u {u} -X {smt['method']} -H 'content-type:application/json'"
            + (f" --data '{smt['data']}'" if smt.get('data') else '')
            + ' --random-agent --level=5 --risk=3 --skip="Host,Referer,User-Agent" --ignore-code=*',
        )
    )
    t.start()

