#!/usr/bin/env python

import sys
from concurrent import futures

import grpc

import request_rewrite_plugin_pb2
import request_rewrite_plugin_pb2_grpc


# Implement the RewritePlugin interface
class RewritePluginServicer(request_rewrite_plugin_pb2_grpc.RewritePluginServicer):
    def Rewrite(self, request, context):
        """Rewrite every request, adding auth parameter."""
        h = 'tkn=xep'  # TODO: parametrize this.
        bs = request.url.split('?', 1)
        if len(bs) == 1:
            request.url += '?' + h
        else:
            request.url = '?'.join([bs[0], '&'.join([h, bs[1]])])
        return request


if __name__ == '__main__':
    # Boot up the gRPC server
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    request_rewrite_plugin_pb2_grpc.add_RewritePluginServicer_to_server(
        RewritePluginServicer(), server)
    server.add_insecure_port('127.0.0.1:50051')
    server.start()

    # Inform mapi of the port we're listening on
    print("50051")
    sys.stdout.flush()

    server.wait_for_termination()
