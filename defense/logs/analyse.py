import csv
import sys
import json

if len(sys.argv) < 2:
    print(f'Usage: python3 {sys.argv[0]} logfile.csv')
    exit()

filename = sys.argv[1]

ases, ips, ports, ases_ips, ips_ports, aip, nonces = set(), set(), set(), set(), set(), set(), set()

ases_ips_count = dict()
ases_packets_count = dict()

total_packets = 0

with open(filename) as f:
    reader = csv.reader(f)
    i = 0
    next(reader)
    for row in reader:
        total_packets += 1
        az, ip, port, payload_json = row
        payload = json.loads(payload_json)
        ases.add(az)
        ips.add(ip)
        ports.add(port)
        nonces.add(payload['NonceB'])
        ases_ips.add(f'{az},{ip}')
        ips_ports.add(f'{ip}:{ports}')
        aip.add(f'{az},{ip}:{port}')

        count = ases_ips_count.get(f'{az},{ip}', 0)
        ases_ips_count[f'{az},{ip}'] = count + 1

        count = ases_packets_count.get(az, 0)
        ases_packets_count[az] = count + 1


print(f'Total packets: {total_packets}')
print(f'Unique ASes: {len(ases)}')
print(f'Unique IPs: {len(ips)}')
print(f'Unique Ports: {len(ports)}')
print(f'Unique ASes_IPs: {len(ases_ips)}')
print(f'Unique IPs_Ports: {len(ips_ports)}')
print(f'Unique ASes_IPs_Ports: {len(aip)}')
print(f'Unique nonces: {len(nonces)}, {"all unique" if len(nonces) == total_packets else "some repeated"}')

ases_ips_count = dict(sorted(ases_ips_count.items(), key=lambda item: item[1]))
ases_packets_count = dict(sorted(ases_packets_count.items(), key=lambda item: item[1]))

print(f'{"-" * 10}Packet count per IP{"-" * 10}')
ips_single_packet = 0
for k, v in ases_ips_count.items():
    if v == 1:
        ips_single_packet += 1
    else:
        print(f'{k} - {v} requests')

print(f'\t-> Omitted {ips_single_packet} IPs because they sent a single packet')

print(f'{"-" * 10}Packet count per AS{"-" * 10}')
for k, v in ases_packets_count.items():
        print(f'{k} - {v} requests')
