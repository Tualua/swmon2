from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi.responses import (
    Response,
    JSONResponse
)
from puresnmp.aio.api.pythonic import (bulkwalk)
from collections import (
    ChainMap,
    defaultdict
)
from .config import settings
import time
import asyncio
import json
import typing
import urllib.request


class PrettyJSONResponse(Response):
    media_type = "application/json"

    def render(self, content: typing.Any) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=None,
            separators=(",", ":"),
        ).encode("utf-8")


def def_value():
    return "Not Present"


def invoke_kea_command(ipaddress, port, command, service):
    headers = {}
    content = '{ "command": "' + command + '"'
    content += ', "service": ["' + service + '"]'
    content += ' }'
    headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(
        url=f'http://{ipaddress}:{port}',
        data=str.encode(content),
        headers=headers
    )
    resp = urllib.request.urlopen(req)
    result = json.loads(resp.read().decode("utf-8"))
    return result


def get_kea_dhcp4_leases(ipaddress, port):
    result = defaultdict(def_value)
    data = invoke_kea_command(ipaddress, port, "lease4-get-all", "dhcp4")
    leases = data[0]['arguments']['leases']
    for lease in leases:
        result[lease['hw-address'].upper()] = lease['ip-address']
    return result


async def get_ifnames(ipaddress, community):
    oidifName = ['.1.3.6.1.2.1.31.1.1.1.1']
    ifnames = await bulkwalk(ipaddress, community, oidifName)
    return ifnames


def portnumber(interfacename, quantity):
    if interfacename[0] == 'F':
        return int(interfacename.rpartition('/')[2])
    elif interfacename[0] == 'G':
        return int(interfacename.rpartition('/')[2])+quantity


async def get_mapping(ipaddress, community, vlan):
    dot1dBasePortIfIndex = ['.1.3.6.1.2.1.17.1.4.1.2']
    mapping = {
        int(m.oid[-1]): int(m.value) async for m in
        bulkwalk(
            ipaddress, "@".join([community, str(vlan)]),
            dot1dBasePortIfIndex)
    }
    return mapping


async def get_mappings(ipaddress, community, vlans):
    tasks = [get_mapping(ipaddress, community, vlan) for vlan in vlans]
    res = await asyncio.gather(*tasks)
    res = dict(ChainMap(*res))
    return res


async def get_vlan_fdb(ipaddress, community, vlan, mappings):
    dot1dTpFdbPort = ['.1.3.6.1.2.1.17.4.3.1.2']
    vlan_fdb = [
        (
            portnumber(mappings[m.value], 48),
            ":".join(["{:02X}".format(int(octet)) for octet in m.oid[-6:]])
        ) async for m in bulkwalk(
            ipaddress, "@".join([community, str(vlan)]), dot1dTpFdbPort)
    ]
    return vlan_fdb


async def get_fdb(ipaddress, community, vlans, mappings):
    tasks = [
        get_vlan_fdb(
            ipaddress, community, vlan, mappings
        ) for vlan in vlans
    ]
    res = await asyncio.gather(*tasks)
    res = [item for sublist in res for item in sublist]
    return sorted(res, key=lambda x: x[0])

app = FastAPI()


@app.get("/fdb/{sw_num}")
async def fdb(sw_num):
    leases = get_kea_dhcp4_leases(settings.kea_ipaddr, settings.kea_api_port)
    start_time = time.time()
    vtpVlanState = ['.1.3.6.1.4.1.9.9.46.1.3.1.1.2.1']
    oidifName = ['.1.3.6.1.2.1.31.1.1.1.1']
    ipaddress = f'172.17.17.{sw_num}'
    # uplinkports = []
    community = settings.snmp_community
    swIfaces = bulkwalk(ipaddress, community, oidifName)
    swVlans = {int(vlan.oid[-1]) async for vlan in bulkwalk(
        ipaddress, community, vtpVlanState)}
    swIfNames = {
        int(i.oid[-1]): i.value.decode('utf-8') async for i in swIfaces
    }
    swMappings = await get_mappings(ipaddress, community, swVlans)
    swMappings = {k: swIfNames[v] for k, v in swMappings.items()}
    swFDB = await get_fdb(ipaddress, community, swVlans, swMappings)
    devices = [[fdb[0], leases[fdb[1]], fdb[1]] for fdb in swFDB]
    end_time = time.time()
    result = jsonable_encoder({
        "start_time": start_time,
        "end_time": end_time,
        "elapsed_time": end_time - start_time,
        "data": devices
    })
    return PrettyJSONResponse(content=result)


@app.get("/kea")
async def kea():
    leases = get_kea_dhcp4_leases(settings.kea_ipaddr, settings.kea_api_port)
    return JSONResponse(content=leases)
