import pyshark
import whois


def dns_domain_request(file_path):
    capture = pyshark.FileCapture(file_path, display_filter='dns')
    domain_names = {}
    for packet in capture:
        try:
            dns_layer = packet.dns
            if dns_layer.flags_response == '0':
                domain_name = dns_layer.qry_name[:-1]
                if domain_name not in domain_names:
                    domain_names[domain_name] = [packet.sniff_time - capture[0].sniff_time]
                else:
                    domain_names[domain_name].append(packet.sniff_time - capture[0].sniff_time)
        except AttributeError:
            pass

    capture.close()

    with open('Dns_domain_request.txt', 'w') as file:
        file.write("Number of domain names requested : " + str(len(domain_names)) + "\n")
        for domain, tab in domain_names.items():
            file.write("Domain : " + domain + "\n")
            for elem in tab:
                file.write(" Requested after : " + str(elem) + "\n")


def dns_request(file_path):
    capture = pyshark.FileCapture(file_path, display_filter='dns')
    dns_types = {}
    for packet in capture:
        try:
            dns_layer = packet.dns
            dns_type = dns_layer.qry_type
            if dns_type not in dns_types:
                dns_types[dns_type] = 1
            else:
                dns_types[dns_type] += 1
        except AttributeError:
            pass

    capture.close()

    with open('dns_request.txt', 'w') as file:
        file.write("DNS request types:\n")
        for req_type, count in dns_types.items():
            if req_type == '1':
                file.write("A : " + str(count) + "\n")
            elif req_type == '28':
                file.write("AAAA : " + str(count) + "\n")
            else:
                file.write(req_type + " : " + str(count) + "\n")


def extract_authoritative_servers(filename):
    capture = pyshark.FileCapture(filename, display_filter='dns')

    domain_names = {}

    for packet in capture:
        try:
            dns_layer = packet.dns
            if dns_layer.flags_response == '1':
                domain_name = dns_layer.qry_name[:-1]
                if domain_name not in domain_names:
                    domain_names[domain_name] = dns_layer.ns
        except AttributeError:
            pass

    with open('authoritative_servers.txt', 'w') as f:
        for domain, servers in domain_names.items():
            f.write("Nom de domaine : " + domain + "'\n")
            f.write("Entreprise qui possède ce nom de domaine : " + str(get_registrant(domain)) + "\n")
            f.write("Serveurs autoritatifs : " + servers + "\n")
            f.write("Registrant du serveur autoritatifs : " + str(get_registrant(servers)))
            f.write("\n \n")

    capture.close()


def get_registrant(server):
    try:
        w = whois.whois(server)
        org = w.org
        print(w)
        if org is None:
            org = "None"
        return org
    except whois.parser.PywhoisError:
        return "Information WHOIS non trouvée"

