# XSS Hunter Client

## What is the this tool for?
This tool can be used to generate correlated XSS payloads, these payloads are tagged with a unique ID which can be used to track which HTTP request caused which XSS payload to fire. By using this tool all of your injection attempts are tracked and the reports you generate will have the responsible injection attempt included in the final output. This is useful since XSS payloads can often traverse multiple services (and even protocols) before firing, so it's not always clear what injection caused a certain XSS payload to fire.

## Setup
1. Create an XSS Hunter account at https://xsshunter.com/
2. Create a new virtual environment by running `virtualenv env`
3. Source the newly created enviroment by running `source env/bin/activate`
4. Install the required libraries by running `pip install -r requirements.txt`
5. Run the config generation tool `./generate_config.py` and follow the steps mentioned.
6. Now run mitmproxy with this client as an inline script: `mitmproxy -s mitm_xsshunter.py -p 1234`
7. Proxy your browser through this new tool, keep in mind that you may have to [install the mitmproxy certificate authority](http://docs.mitmproxy.org/en/stable/certinstall.html) if you have not done so already.

## Using the XSS Hunter Client
Using the client is simple, during the config generation you will set a list of *dummy words*, these are special strings which will be replaced upon being seen by the proxy tool. For example, one rule could have the dummy word be `https://example.com` with the `javascript:` URI payload selected. Once the proxy sees `https://example.com` in the request it will automatically replace it with the `javascript:` URI payload. It is **very important** that you choose a unique dummy word that is unlikely to appear regularly in the request, else you risk scattering your payloads where you don't want them.
