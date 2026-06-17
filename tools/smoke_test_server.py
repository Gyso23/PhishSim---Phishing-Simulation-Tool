import urllib.request, ssl
hosts = ['127.0.0.1', 'localhost']
ports = [8443, 8082, 5000, 8000]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

for host in hosts:
    for port in ports:
        for proto in ['https', 'http']:
            url = f"{proto}://{host}:{port}/"
            try:
                if proto == 'https':
                    req = urllib.request.Request(url)
                    with urllib.request.urlopen(req, context=ctx, timeout=2) as resp:
                        print(url, resp.status)
                else:
                    req = urllib.request.Request(url)
                    with urllib.request.urlopen(req, timeout=2) as resp:
                        print(url, resp.status)
            except Exception as e:
                print(url, 'ERROR:', str(e))
