#!/usr/bin/env python
from __future__ import unicode_literals, print_function, division

import yaml
import random
import string

from requests_futures.sessions import FuturesSession

try:
    with open('config.yaml', 'r') as f:
        settings = yaml.load(f)
except IOError:
    print("Error reading config.yaml, have you created one? (Hint: Try "
          "running ./generate_config.py)")
    exit()

KEYWORD = "replaceme"

futures_sess = FuturesSession()


def request(context, flow):
    if KEYWORD in flow.request.content:
        req_body, probe_ids = replace_probe_markers(
            flow.request.content,
            context
        )
        flow.request.content = req_body

        for probe_id in probe_ids:
            notify_probe_server({
                "request": get_full_http_request_text(flow.request),
                "owner_correlation_key": settings["owner_correlation_key"],
                "injection_key": probe_id
            }, context)


def get_full_http_request_text(req):
    http_request_text = req.method + " " + req.path + " HTTP/1.1\r\n"
    for header_pair in req.headers.fields:
        http_request_text += header_pair[0] + ": " + header_pair[1] + "\r\n"
    http_request_text += "\r\n"
    http_request_text += req.body
    return http_request_text


def replace_probe_markers(request_body, context):
    probe_marker_list = []

    while KEYWORD in request_body:
        payload_id = get_random_id(10)
        payload = settings["host_url"] + "/" + payload_id
        context.log("[STATUS] Replacing '" + KEYWORD + "' with " + payload)
        request_body = request_body.replace(KEYWORD, payload, 1)
        probe_marker_list.append(payload_id)
    return request_body, probe_marker_list


def notify_probe_server(request_details, context):
    fut = futures_sess.post(
        "https://api.xsshunter.com/api/record_injection",
        headers={"Accept": "application/json"},
        json=request_details,
    )
    fut.add_done_callback(lambda x: probe_sent_cb(x, context))


def probe_sent_cb(fut, context):
    resp = fut.result()
    context.log(resp)
    context.log(resp.text)


def get_random_id(num):
    choices = string.ascii_lowercase + string.digits
    return ''.join(random.choice(choices) for _ in range(num))
