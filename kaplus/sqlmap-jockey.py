#!/usr/bin/env python3

import pathlib
import sys
import threading

sys.path.insert(1, pathlib.Path('~/src/sqlmap').expanduser().as_posix())
from lib.utils.api import *
from lib.utils.api import _client
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import input as _input
from thirdparty.six.moves import urllib as _urllib
# from sqlmapapi import *

# sys.path.insert(1, pathlib.Path('~/prj/masc/src/runner-suppl/kaplus').expanduser().as_posix())
from openapi_sqlmap import oas_load, sqlmap_tasks





def sqlmapapi_client(host=RESTAPI_DEFAULT_ADDRESS, port=RESTAPI_DEFAULT_PORT, username=None, password=None):
    DataStore.username = username
    DataStore.password = password

    dbgMsg = "Example client access from command line:"
    dbgMsg += "\n\t$ taskid=$(curl http://%s:%d/task/new 2>1 | grep -o -I '[a-f0-9]\\{16\\}') && echo $taskid" % (host, port)
    dbgMsg += "\n\t$ curl -H \"Content-Type: application/json\" -X POST -d '{\"url\": \"http://testphp.vulnweb.com/artists.php?artist=1\"}' http://%s:%d/scan/$taskid/start" % (host, port)
    dbgMsg += "\n\t$ curl http://%s:%d/scan/$taskid/data" % (host, port)
    dbgMsg += "\n\t$ curl http://%s:%d/scan/$taskid/log" % (host, port)
    logger.debug(dbgMsg)

    addr = "http://%s:%d" % (host, port)
    logger.info("Starting REST-JSON API client to '%s'..." % addr)

    try:
        _client(addr)
    except Exception as ex:
        if not isinstance(ex, _urllib.error.HTTPError) or ex.code == _http_client.UNAUTHORIZED:
            errMsg = "There has been a problem while connecting to the "
            errMsg += "REST-JSON API server at '%s' " % addr
            errMsg += "(%s)" % getSafeExString(ex)
            logger.critical(errMsg)
            return



    ##################################
    # elif command in ("list", "flush"):
    command = 'new -u 172.21.0.11:10013/tokens -X POST --data \'{"username":"U","password":"P"}\' --ignore-code=\'*\''
    try:
        argv = ["sqlmap.py"] + shlex.split(command)[1:]
    except Exception as ex:
        logger.error("Error occurred while parsing arguments ('%s')" % getSafeExString(ex))
        taskid = None
        raise

    try:
        cmdLineOptions = cmdLineParser(argv).__dict__
    except:
        taskid = None
        raise

    for key in list(cmdLineOptions):
        if cmdLineOptions[key] is None:
            del cmdLineOptions[key]

    raw = _client("%s/task/new" % addr)
    res = dejsonize(raw)
    if not res["success"]:
        logger.error("Failed to create new task ('%s')" % res.get("message", ""))
        raise
    taskid = res["taskid"]
    logger.info("New task ID is '%s'" % taskid)

    raw = _client("%s/scan/%s/start" % (addr, taskid), cmdLineOptions)
    res = dejsonize(raw)
    if not res["success"]:
        logger.error("Failed to start scan ('%s')" % res.get("message", ""))
        raise
    logger.info("Scanning started")

    ##################################
    # elif command in ("list", "flush"):
    command = 'list'
    raw = _client("%s/admin/%s" % (addr, command))
    res = dejsonize(raw)
    if not res["success"]:
        logger.error("Failed to execute command %s" % command)
    elif command == "flush":
        taskid = None
    dataToStdout("%s\n" % raw)






max_threads = 3

pool_sema = threading.BoundedSemaphore(max_threads)


def thread_task(sqlmap_task):
    with pool_sema:
        delta_t = random.randint(3, 10)
        time.sleep(random.random())
        print(f'task {task_id} started with delta {delta_t}', args)
        time.sleep(delta_t)
        print(f'task {task_id} finished')



for smt in sqlmap_tasks(oas_load('~/tmp/masc/oapi-specs/vAPI.yaml')):
    print(smt)
    # t = threading.Thread(target=thread_task, args=smt)
    # t.start()

sqlmapapi_client(host='172.21.0.11')

# def task_new():
#     """
#     Create a new task
#     """
#     taskid = encodeHex(os.urandom(8), binary=False)
#     remote_addr = request.remote_addr
#
#     DataStore.tasks[taskid] = Task(taskid, remote_addr)
#
#     logger.debug("Created new task: '%s'" % taskid)
#     return jsonize({"success": True, "taskid": taskid})
