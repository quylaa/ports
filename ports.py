#! /usr/bin/env python

# IT 567 Port scanner, because we have to reinvent the wheel
# Created by Aleks Christensen

import scapy 
import argparse

def main():
  args = parsing()
  print args
  return 0


def parsing():
  parser = argparse.ArgumentParser()

  parser.add_argument('hosts', action='store', nargs='+', help='IP address of the host(s) to target in port scan. Input can be a single target, list of addresses, range, or subnet to scan.\nSingle target:\t192.168.1.1\nList:\t192.168.12.15,192.168.12.18,192.168.12.22\nRange:\t192.168.41.30-60\nSubnet:\t192.168.55.0/24\nCombination:\t192.168.43.18,192.168.56.12-15,192.168.79.16/28')
  parser.add_argument('ports', action='store', nargs='+', help='Port(s) to scan on target(s). Input can be a single port, list of ports, or range.\nSingle port:\t22\nList:\t22,80,443,587,3389\nRange:\t1000-1500\nCombination:\t22,80,500-800')
  parser.add_argument('-f', dest='hostsfile', action='store', type=argparse.FileType('r'), help='Text file containing a list of hosts to scan, one IP address per line')
  parser.add_argument('-o', dest='outfile', action='store', type=argparse.FileType('w'), help='File to store the output of the scan in')

  args = parser.parse_args()
  return args

#if __name__ == "__main__":
main()
