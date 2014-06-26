#!/usr/bin/python

import sys
import argparse
import requests
import json


token = ''
tenant_id = ''

def main(argv):
    parser = argparse.ArgumentParser(description='Info about products and templates')

    parser.add_argument("-u", "--username", help='valid username', required=True)
    parser.add_argument("-p", "--password", help='valid password', required=True)
    parser.add_argument("-r", "--region", dest='region', default='Spain', help='the name of region')
    parser.add_argument("-k", "--url", dest="url_base", default='cloud.lab.fi-ware.org:4731',
        help='url to keystone <host or ip>:<port>')
    parser.add_argument("-t", "--tenant", dest="tenantid", help="tenant-id", default="00000000000000000000000000000001",
        required=True)

    args = parser.parse_args()

    print args

    find_token_and_services(url_base=args.url_base, tenant_id=args.tenantid, user=args.username, password=args.password,
        region=args.region)


def find_token_and_services(url_base, tenant_id, user, password, region):
    url = 'http://' + url_base + '/v2.0/tokens'
    headers = {'Accept': 'application/json'}
    payload = {'auth': {'tenantName': '' + tenant_id + '',
                        'passwordCredentials': {'username': '' + user + '', 'password': '' + password + ''}}}
    response = requests.post(url, headers=headers, data=json.dumps(payload))
    response_json = response.json()

    token = response_json['access']['token']['id']
    tenant_id = response_json['access']['token']['tenant']['id']

    print "Token used: " + token
    for i in response_json['access']['serviceCatalog']:
        if i['name'] == 'paasmanager':
            for j in i['endpoints']:
                if j['region'] == region:
                    find_all_environments(j['publicURL'], j['region'])
        if i['name'] == 'sdc':
            for j in i['endpoints']:
                if j['region'] == region:
                    find_all_products(j['publicURL'], j['region'])


def send(headers, url):
    response = requests.get(url, headers=headers)
    response_json = response.json()
    print json.dumps(response_json, sort_keys=True, indent=4, separators=(',', ': '))


def find_all_environments(url_base, region):
    # request for abstract environments
    print "find all environments in " + region + '->' + url_base
    url = url_base + '/catalog/org/FIWARE/environment'
    headers = {'Accept': 'application/json',
               'X-Auth-Token': '' + token + '',
               'Tenant-Id': '' + tenant_id + ''
    }
    send(headers, url)


def find_all_products(url_base, region):
    print "find all products in " + region + '->' + url_base

    url = url_base + '/catalog/product'
    headers = {'Accept': 'application/json',
               'X-Auth-Token': '' + token + '',
               'Tenant-Id': '' + tenant_id + ''
    }
    send(headers, url)

if __name__ == "__main__":
    main(sys.argv[1:])
