#! /usr/bin/env python

# IT 567 Port scanner, because we have to reinvent the wheel
# Created by Aleks Christensen

import scapy 
import argparse
import netaddr

def main():
  args = parsing()
  print args
  return 0


def parsing():
  parser = argparse.ArgumentParser(prog='PORTScanner', formatter_class=argparse.RawTextHelpFormatter)

  parser.add_argument('-H', '--hosts', action='store', nargs='+', help='IP address of the host(s) to target in port scan.\nInput can be a single target, list of addresses, range, or subnet to scan.\nSingle target:\t192.168.1.1\nList:\t192.168.12.15,192.168.12.18,192.168.12.22\nRange:\t192.168.41.30-60\nSubnet:\t192.168.55.0/24\nCombination:\t192.168.43.18,192.168.56.12-15,192.168.79.16/28')
  parser.add_argument('-P', '--ports', action='store', nargs='+', help='Port(s) to scan on target(s).\nInput can be a single port, list of ports, or range.\nSingle port:\t22\nList:\t22,80,443,587,3389\nRange:\t1000-1500\nCombination:\t22,80,500-800')
  parser.add_argument('-f', dest='hostsfile', action='store', type=argparse.FileType('r'), help='Text file containing a list of hosts to scan, one IP address per line')
  parser.add_argument('-o', dest='outfile', action='store', type=argparse.FileType('w'), help='File to store the output of the scan in')
  parser.add_argument('-r', dest='protocol', action='store', default='TCP', choices=['TCP', 'UDP'], help='Protocol to use when scanning')

  args = parser.parse_args()

  args.rawhosts = args.hosts
  args.hosts = parseHosts(args.hosts[0].split(','))

  args.rawports = args.ports
  args.ports = parsePorts(args.ports[0].split(','))

  return args

def parseHosts(rawhosts):
  hosts = []
  for host in rawhosts:
    if '-' in host:
      raw = host.split('-')
      startaddr = raw[0]
      temp = startaddr.split('.')
      endaddr = temp[0] + '.' + temp[1] + '.' + temp[2] + '.' + raw[1]
      for addr in list(netaddr.IPRange(startaddr, endaddr)):
        hosts.append(str(addr))
      continue
    if '/' in host:
      for addr in list(netaddr.IPNetwork(host)):
        hosts.append(str(addr))
      continue
    else:
      hosts.append(netaddr.IPAddress(host))
  return hosts

def parsePorts(rawports):
  ports = []
  for port in rawports:
    if '-' in port:
      raw = port.split('-')
      for p in range(int(raw[0]), int(raw[1])+1):
        ports.append(p)
    else:
      ports.append(int(port))
  return ports


def scan(hosts, ports):
  return 0

main()
