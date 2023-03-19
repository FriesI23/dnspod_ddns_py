# DDNS upload script for Dnspod

## Usage

```shell
/path/to/python /path/to/dnspod_ddns.py ddns_update -lt tokenID,tokenVal -dn domain.com -rid recordid --datas '{"sub_domain": "raw"}' --local-cache /path/to/localipfile
```

## Position Args

| Args | Desc |
| ---- | ---- |
| method | 操作方式, 现在支持 `ddns_update` |

## Options Args

| Args | Desc |
| ---- | ---- |
| -lt / --login-token | Dnspod登录需要的token, 格式`tokenID,tokenVal` |
| -dn / --domain-name | 需要更新的域名 |
| -rid / --record-id | 域名recordid |
| --datas | 额外的请求信息, 格式需要为json |
| --local-cache | 如果设置该值, 则使用本地缓存的ip(而不是用在线获取) |


## `--local-cache` 文件格式举例

```shell
foo@bar:/tmp/dnspod_upload$ cat /tmp/wanip_cache_ip
123.45.678.23
```

## `--login-token`

登录需要的token在 [DNSPod Token](https://console.dnspod.cn/account/token/token)

## `--record-id`

1. 获取`domain-id`

[获取域名列表](https://docs.dnspod.cn/api/domains-list/)

```shell
curl 'https://dnsapi.cn/Domain.List' -d 'login_token=tokenID,tokenVal&format=json'
```

2. 根据`domain-id`获取`record-id`

[记录列表](https://docs.dnspod.cn/api/record-list/)

```shell
curl 'https://dnsapi.cn/Record.List' -d 'login_token=tokenID,tokenVal&domain_id=domain-id&sub_domain=sub-domain&format=json'
```