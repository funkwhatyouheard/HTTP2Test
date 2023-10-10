#!/usr/bin/python3

import socket, ssl, sys, argparse, ipaddress

socket.setdefaulttimeout(5)

headers = {"user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"}

def connect_h2_socket(host):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2'])
    sock.connect((host, 443))
    sock = context.wrap_socket(sock, server_hostname=host)
    return sock

def test_h2(host):
    protocol = ''
    with connect_h2_socket(host) as s:
        protocol = s.selected_alpn_protocol()
        s.shutdown(socket.SHUT_RDWR)
        s.close()
    return protocol

def check_http2(domain_names=None,CIDRs=None,supportedOnly=False):
    results = []
    hosts = []
    if domain_names != None:
        if not isinstance(domain_names,list):
            domain_names = [domain_names]
        hosts.extend(domain_names)
    if CIDRs != None:
        if not isinstance(CIDRs,list):
            CIDRs = [CIDRs]
        ips = []
        for CIDR in CIDRs:
            ips.extend([str(ip) for ip in ipaddress.IPv4Network(CIDR,False)])
        hosts.extend(ips)
        # attempt to do a reverse lookup, sometimes you'll want hostname over IP b/c of host headers
        for ip in ips:
            lookup = socket.getnameinfo((ip, 0),0)[0]
            if lookup != ip:
                hosts.append(lookup)
    # dedupe
    hosts = list(set(hosts))
    for d in hosts:
        result = {"host":d,"http2_support":False}
        try:
            pp = test_h2(d)
            if pp == "h2":
                result['http2_support'] = True
            results.append(result)
        except:
            results.append(result)
            continue
    if supportedOnly:
        results = [r for r in results if r['http2_support'] == True]
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domains", help="Space delimited domains to check http2 support for.", type=str, nargs='*', default=None)
    parser.add_argument("-c", "--CIDRs", help="CIDRs to check http2 support for",type=str, nargs="*", default=None)
    parser.add_argument("-so", "--supportedOnly", help="Only return hosts/domains that support http2",default=False, action='store_true')
    args = parser.parse_args()
    if len(sys.argv) > 1:
        print("\n".join(["{0}:{1}".format(d['host'],d['http2_support']) for d in check_http2(args.domains,args.CIDRs,args.supportedOnly)]))
    else:
        parser.print_help()
