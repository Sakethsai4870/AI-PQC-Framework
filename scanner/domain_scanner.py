import socket
import dns.resolver


def scan_domain(domain):
    result = {
        'ip_addresses': [],
        'mx_records': [],
        'ns_records': [],
        'txt_records': [],
        'dnssec_enabled': False,
        'error': None,
    }

    try:
        result['ip_addresses'] = [str(ip) for ip in socket.getaddrinfo(domain, None, socket.AF_INET)]
        ips = set()
        for addr in result['ip_addresses']:
            ips.add(addr[4][0])
        result['ip_addresses'] = list(ips)
    except Exception as e:
        result['error'] = str(e)

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        try:
            mx_records = resolver.resolve(domain, 'MX')
            result['mx_records'] = [str(r.exchange) for r in mx_records]
        except Exception:
            pass

        try:
            ns_records = resolver.resolve(domain, 'NS')
            result['ns_records'] = [str(r) for r in ns_records]
        except Exception:
            pass

        try:
            txt_records = resolver.resolve(domain, 'TXT')
            result['txt_records'] = [str(r) for r in txt_records]
        except Exception:
            pass

        try:
            dnskey = resolver.resolve(domain, 'DNSKEY')
            if dnskey:
                result['dnssec_enabled'] = True
        except Exception:
            result['dnssec_enabled'] = False

    except Exception as e:
        if not result['error']:
            result['error'] = str(e)

    return result
