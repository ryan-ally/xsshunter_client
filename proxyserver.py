#!/usr/bin/env python
import os
import json
import yaml
import random
import string

from pprint import pprint
from libmproxy import controller, proxy
from libmproxy.proxy.server import ProxyServer

try:
    with open( 'config.yaml', 'r' ) as f:
        settings = yaml.load( f )
except IOError:
    print "Error reading config.yaml, have you created one? (Hint: Try running ./generate_config.py)"
    exit()

keyword = "replaceme"

class PayloadReplaceProxy(controller.Master):
    def __init__(self, server):
        controller.Master.__init__(self, server)

    def run(self):
        try:
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_request( self, flow ):
        if keyword in flow.request.content:
            replace_dict = replace_probe_markers( flow.request.content )
            flow.request.content = replace_dict["request_body"]

            for probe_id in replace_dict["probe_ids"]:
                notify_probe_server( { "request": get_full_http_request_text( flow.request ), "owner_correlation_key": settings["owner_correlation_key"], "injection_key": probe_id } )

        flow.reply()

def get_full_http_request_text( request ):
    http_request_text = request.method + " " + request.path + " HTTP/1.1\r\n"
    for header_pair in request.headers.fields:
        http_request_text += header_pair[0] + ": " + header_pair[1] + "\r\n"
    http_request_text += "\r\n"
    http_request_text += request.body
    return http_request_text

def replace_probe_markers( request_body, probe_marker_return_list = [] ):
    payload_id = get_random_id( 6 )
    payload = settings["host_url"] + "/" + payload_id
    print( "[STATUS] Replacing '" + keyword + "' with " + payload )
    request_body = request_body.replace( keyword, payload, 1 )
    probe_marker_return_list.append( payload_id )

    if keyword in request_body:
        return replace_probe_markers( request_body, probe_marker_return_list )
    return { "probe_ids": probe_marker_return_list, "request_body": request_body }

def notify_probe_server( request_details ):
    pass
    #thread = unirest.post( "https://api.xsshunter.com/api/record_injection", headers={"Accept": "application/json"}, params=json.dumps( request_details ), callback=payload_server_handler, verify=False)

def payload_server_handler( response ):
    print response.rawbody

def get_random_id( num ):
    return ''.join( random.choice( string.ascii_lowercase + string.digits ) for _ in range( num ) )

config = proxy.ProxyConfig( port=1234 )
server = ProxyServer( config )
m = PayloadReplaceProxy( server )
m.run()
