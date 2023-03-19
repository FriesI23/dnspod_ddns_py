# coding: utf-8

# Copyright (c) 2019 Fries_I23
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import traceback
import argparse
import random
import json
import os

from requests import Session
from bs4 import BeautifulSoup


__version__ = 'v0.0.2'
_DEBUG = False


HTTP = 'http'
HTTPS = 'https'

DEFAULT_CACHE_PATH = '/tmp/dnspod_upload'

REAL_IP_URL = (HTTP, 'ip.cn')
REAL_IP_URL_IPHTTPS = (HTTPS, 'ip.cn')
REAL_IP_URL_BK_1 = (HTTP, 'www.trackip.net')
REAL_IP_URL_BK_2 = (HTTPS, 'api.ip.sb')
REAL_IP_URL_IPINFO_IO = (HTTP, 'ipinfo.io')
REAL_IP_URL_MYIPIPIP = (HTTPS, 'myip.ipip.net')

session = Session()

def get_real_ip():
    fns = [
        # _get_real_ip_ip,
        # _get_real_ip_ip_https,
        _get_real_ip_trackip, # ip.trackip cant\'t connect with GFW
        # _get_real_ip_sb,
        # _get_real_ip_ipinfo,
        _get_real_ip_myip,
    ]
    random.shuffle(fns)
    err = Exception()
    for fn in fns:
        try:
            return fn()
        except Exception as e:
            _DEBUG and traceback.print_exc()
            err = e
            continue
    raise err


def _get_real_ip_ip():
    print('try using ip.cn...')
    r = session.get('://'.join(REAL_IP_URL), timeout=1)
    r.raise_for_status()
    r_bs = BeautifulSoup(r.text, features='html.parser')
    div = r_bs.find('div', attrs={'class': 'well'})
    datas = div.find_all(name='code')
    return {'ipv4': datas[0].text, 'where_cn': datas[1].text}


def _get_real_ip_ip_https():
    print('try using ip cn https...')
    r = session.get('://'.join(REAL_IP_URL_IPHTTPS), timeout=1)
    r.raise_for_status()
    r_json = r.json()
    return {'ipv4': r_json['ip'], 'where_cn': r_json['country']}


def _get_real_ip_trackip() :
    print('try using trackip.net...')
    url = r'{0}://{1}/ip?json'.format(*REAL_IP_URL_BK_1)
    r = session.get(url, timeout=1)
    r.raise_for_status()
    data = r.json()
    return {'ipv4': data['IP'], 'where_cn': data['Country']}


def _get_real_ip_sb():
    print('tring using ip.sb...')
    url = r'{0}://{1}/geoip'.format(*REAL_IP_URL_BK_2)
    r = session.get(url, timeout=1)
    r.raise_for_status()
    data = r.json()
    return {'ipv4': data['ip'], 'where_cn': data['country_code']}


def _get_real_ip_ipinfo():
    print('try using ipinfo.op...')
    r = session.get('://'.join(REAL_IP_URL_IPINFO_IO), timeout=1)
    r.raise_for_status()
    r_json = r.json()
    return {'ipv4': r_json['ip'], 'where_cn': r_json['country']}


def _get_real_ip_myip():
    print('try using myip.ipip.net...')
    url = r'{0}://{1}/json'.format(*REAL_IP_URL_MYIPIPIP)
    r = session.get(url, timeout=1)
    r.raise_for_status()
    data = r.json()
    return {'ipv4': data['data']['ip'], 'where_cn': ''.join(data['data']['location'])}


class DnsPodAPIError(Exception):
    def __init__(self, msg, data, *args):
        super().__init__(msg, *args)
        self.err_data = data


def DnsPodAPIException(method, err):
    err_code = err['code']
    err_msg = err['message']
    return DnsPodAPIError(
        'error status code in CALL {}: code {}, msg "{}"'.format(
            method, err_code, err_msg), err)


class DnsPodAPIs(object):
    APIURL_RECORD_LIST = "https://dnsapi.cn/Record.List"
    APIURL_UPLOAD_RECORD = "https://dnsapi.cn/Record.Create"
    APIURL_MODIFY_RECORD = "https://dnsapi.cn/Record.Modify"
    APIURL_UPDATE_DDNS_RECORD = "https://dnsapi.cn/Record.Ddns"

    def __init__(self, token, r_session=None):
        self._token = token
        self._session = r_session or session

    def post(self, url, data=None, json=None, **kwargs):
        if not data:
            data = {}
        data.setdefault('login_token', self._token)
        data.setdefault('format', 'json')
        resp = self._session.post(url, data, json, **kwargs)
        resp.raise_for_status()
        return resp

    def get_domain_list(self, domain=None, domain_id=None, record_type=None, datas=None, **kwargs):
        params = datas or {}
        if domain_id:
            params.setdefault('domain_id', domain_id)
        elif domain:
            params.setdefault('domain', domain)
        else:
            raise TypeError('Must set value between domain and domain_id')

        if record_type:
            params.setdefault('record_type', record_type)

        kwargs.update({'data': params})

        resp = self.post(self.APIURL_RECORD_LIST, **kwargs)
        result = resp.json()

        status_code = result['status']['code']
        if int(status_code)!= 1:
            raise DnsPodAPIException(self.APIURL_RECORD_LIST, result['status'])

        return result

    def upload_domain_record(self, *args, **kwargs):
        return self._modify_domain_record(self.APIURL_UPLOAD_RECORD, *args, **kwargs)

    def modify_domain_record(self, *args, **kwargs):
        if 'record_id' not in kwargs or not kwargs['record_id']:
            raise TypeError('record id must set value')
        elif kwargs['datas']:
            kwargs['datas']['record_id'] = kwargs.pop('record_id')
        else:
            kwargs['datas'] = {'record_id': kwargs.pop('record_id')}
        return self._modify_domain_record(self.APIURL_MODIFY_RECORD, *args, **kwargs)

    def _modify_domain_record(self, url, domain=None, domain_id=None, sub_domain='www', record_type='A',
                             record_line='默认', value=None, datas=None, **kwargs):
        params = datas or {}
        if domain_id:
            params.setdefault('domain_id', domain_id)
        elif domain:
            params.setdefault('domain', domain)
        else:
            raise TypeError('Must set value between domain and domain_id')

        if sub_domain:
            params.setdefault('sub_domain', sub_domain)

        if not record_type or not record_line or not value:
            raise TypeError('Error input value, some value should not be None')

        params.setdefault('value', value)
        params.setdefault('record_type', record_type)
        params.setdefault('record_line', record_line)

        kwargs.update({'data': params})

        resp = self.post(url, **kwargs)
        result = resp.json()

        status_code = result['status']['code']
        if int(status_code)!= 1:
            raise DnsPodAPIException(url, result['status'])

        return result

    def update_ddns_record(self, domain=None, domain_id=None, record_id=None, sub_domain='www',
                           record_line='默认', value=None, datas=None, **kwargs):
        params = datas or {}
        if domain_id:
            params.setdefault('domain_id', domain_id)
        elif domain:
            params.setdefault('domain', domain)
        else:
            raise TypeError('Must set value between domain and domain_id')

        if sub_domain:
            params.setdefault('sub_domain', sub_domain)

        if not record_line or not record_id:
            raise TypeError('Error input value, some value should not be None')

        params.setdefault('record_line', record_line)
        params.setdefault('record_id', record_id)

        if value:
            params.setdefault('value', value)

        kwargs.update({'data': params})

        resp = self.post(self.APIURL_UPDATE_DDNS_RECORD, **kwargs)
        result = resp.json()

        status_code = result['status']['code']
        if int(status_code)!= 1:
            raise DnsPodAPIException(self.APIURL_UPDATE_DDNS_RECORD, result['status'])

        return result


def get_domain_id(dnsPod: DnsPodAPIs, domain=None, domain_id=None, **kwargs):
    result = dnsPod.get_domain_list(domain, domain_id, **kwargs)
    return int(result['domain']['id'])

def upload_domain_record(dnsPod: DnsPodAPIs, domain=None, domain_id=None, value=None, **kwargs):
    result = dnsPod.upload_domain_record(domain, domain_id, value=value, **kwargs)
    return result['record']

def modify_domain_record(dnsPod: DnsPodAPIs, domain=None, domain_id=None, value=None, record_id=None,
                         datas=None, **kwargs):
    result = dnsPod.modify_domain_record(domain, domain_id, record_id=record_id,
                                         value=value, datas=datas, **kwargs)
    return result['record']

def update_ddns_record(dnsPod: DnsPodAPIs, domain=None, domain_id=None, value=None, record_id=None,
                       **kwargs):
    result = dnsPod.update_ddns_record(domain, domain_id, record_id, value=value, **kwargs)
    return result['record']


def update_ddns_record_in_file_cache(dnspod: DnsPodAPIs, record_id, value,
                                     cache_path=DEFAULT_CACHE_PATH, **kwargs):
    file_name = 'ddns_record_{}'.format(record_id)
    file_path = os.path.join(cache_path, file_name)
    if not os.path.exists(cache_path):
        os.makedirs(cache_path, exist_ok=True)

    def _check_upload():
        if not os.path.exists(file_path):
            return True

        with open(file_path, 'r') as _fd:
            data = json.load(_fd)
            if not data:
                return True

            if data['value'] != value:
                return True
            else:
                raise RuntimeError(
                    'Check ddns uplaod error, {} == {}'.format(data['value'], value))

        raise RuntimeError('Check ddns upload error')

    _check_upload()

    result = update_ddns_record(dnspod, record_id=record_id, value=value, **kwargs)

    with open(file_path, 'w+') as fd:
        json.dump(result, fd)


def get_real_ipv4_local(p):
    print('get_real_ipv4_local', p)
    with open(p, 'r') as fp:
        d = fp.read().strip()
        return d


def __parse_args__():
    parser = argparse.ArgumentParser()
    parser.add_argument('method',
                         help='switch method, support ddns_update/...')
    parser.add_argument('-lt', '--login-token', required=True,
                        help='DNSPod login token, format: "tokenID,tokenVal"')
    parser.add_argument('-dn', '--domain-name',
                        help='domain name to record')
    parser.add_argument('-rid', '--record-id', help='domain record id')
    parser.add_argument('--datas', default='{}',
                        help='externel data, format: json')
    parser.add_argument('--local-cache', help='use local cache', default='')
    parser.add_argument('--debug', action='store_true')
    return parser


def __main__():
    parser = __parse_args__()
    args = parser.parse_args()
    _DEBUG = args.debug
    if args.local_cache:
        new_ipv4 = get_real_ipv4_local(args.local_cache)
    else:
        new_ipv4 = get_real_ip()['ipv4']
    dnspod = DnsPodAPIs(args.login_token)

    datas = json.loads(args.datas)

    if args.method == 'ddns_update':
        if not args.record_id:
            print('ERROR: [{}]: record_id must set'.format(args.method))
            return 2
        update_ddns_record_in_file_cache(dnspod, args.record_id, new_ipv4,
                                         domain=args.domain_name, **datas)
    else:
        print('ERROR: un-support method: {}'.format(args.methods))
        return -1

    return 0


if __name__ == '__main__':
    exit_code = 0
    try:
        exit_code = __main__()
    except Exception as err:
        import traceback
        traceback.print_exc()
    finally:
        exit(exit_code)
