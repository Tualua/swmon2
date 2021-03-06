from fastapi import (
    FastAPI,
    Depends
)
from starlette.background import BackgroundTask
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from fastapi.responses import (
    Response,
    JSONResponse
)
from puresnmp.aio.api.pythonic import (
    bulkwalk
)
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
import aiohttp
import ssl
from librouteros import connect
from librouteros.login import plain
from librouteros.query import Key


# KEA DHCP lease states
KEA_STATE_DEFAULT = 0
KEA_STATE_DECLINED = 1
KEA_STATE_EXPIRED_RECLAIMED = 2


class HttpClient:
    session: aiohttp.ClientSession = None

    def start(self):
        self.session = aiohttp.ClientSession()

    async def stop(self):
        await self.session.close()
        self.session = None

    def __call__(self) -> aiohttp.ClientSession:
        assert self.session is not None
        return self.session


http_client = HttpClient()


class PrettyJSONResponse(Response):
    media_type = "application/json"

    def __init__(
        self,
        content: typing.Any = None,
        indent: int = None,
        status_code: int = 200,
        headers: dict = None,
        media_type: str = None,
        background: BackgroundTask = None,
    ) -> None:
        self.status_code = status_code
        if media_type is not None:
            self.media_type = media_type
        self.background = background
        self.body = self.render(content, indent)
        self.init_headers(headers)

    def render(self, content: typing.Any, indent: int) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=indent,
            separators=(",", ":"),
        ).encode("utf-8")


def def_value():
    return "Not Present"


def get_ros_dhcp_leases(ipaddress, port, username, password):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    method = plain

    api = connect(
        username=username,
        password=password,
        host=ipaddress,
        ssl_wrapper=ctx.wrap_socket,
        port=port,
        login_method=method
    )
    ipaddress = Key('active-address')
    macaddress = Key('mac-address')
    hostname = Key('host-name')
    status = Key('status')
    data = api.path('/ip/dhcp-server/lease').select(
        ipaddress, macaddress, hostname).where(status == 'bound')
    """
    leases = (
        (l['mac-address'], l['active-address'], l['host-name'])
        if 'host-name' in l.keys() else (
            l['mac-address'], l['active-address'], '') for l in data)
    """
    result = defaultdict(def_value)
    for lease in data:
        result[lease["mac-address"].upper()] = lease["active-address"]
    return result


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
        if lease['state'] == KEA_STATE_DEFAULT:
            result[lease['hw-address'].upper()] = lease['ip-address']
    return result


async def get_kea_dhcp4_leases_a(ipaddress, port, http_client):
    result = defaultdict(def_value)
    headers = {}
    content = '{ "command": "' + "lease4-get-all" + '"'
    content += ', "service": ["' "dhcp4" + '"]'
    content += ' }'
    headers['Content-Type'] = 'application/json'

    req = await http_client.post(
        url=f"http://{ipaddress}:{port}",
        data=str.encode(content), headers=headers)
    resp = await req.json()
    leases = resp[0]['arguments']['leases']
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
            ":".join(["{:02X}".format(int(octet)) for octet in m.oid[-6:]]),
            vlan
        ) async for m in bulkwalk(
            ipaddress, "@".join([community, str(vlan)]), dot1dTpFdbPort)
    ]
    return vlan_fdb


async def get_fdb_cisco(ipaddress, community, vlans, mappings):
    tasks = [
        get_vlan_fdb(
            ipaddress, community, vlan, mappings
        ) for vlan in vlans
    ]
    res = await asyncio.gather(*tasks)
    res = [item for sublist in res for item in sublist]
    return sorted(res, key=lambda x: x[0])


async def get_fdb_dlink(ipaddress, community):
    oiddot1qTpFdbEntry = ['.1.3.6.1.2.1.17.7.1.2.2.1.2']
    res = [
                (int(m.value), ":".join(
                    ["{:02X}".format(int(octet)) for octet in m.oid[-6:]]),
                    int(m.oid[-7]))
                async for m in bulkwalk(
                    ipaddress, community, oiddot1qTpFdbEntry)]
    return sorted(res, key=lambda x: x[0])


app = FastAPI()

origins = ['*']

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    http_client.start()


@app.get("/cisco/{sw_num}")
async def fdb_cisco(sw_num):
    start_time = time.time()
    devices = {}
    leases = get_kea_dhcp4_leases(settings.kea_ipaddr, settings.kea_api_port)
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
    swFDB = await get_fdb_cisco(ipaddress, community, swVlans, swMappings)
    for iface in range(1, 49):
        devices[iface] = {
            "ipaddr": "Not Found",
            "macaddr": "Not Found",
            "vlan": "Not Found"
        }

    for fdb in swFDB:
        if fdb[0] <= 48:
            devices[fdb[0]] = {
                "ipaddr": leases[fdb[1]],
                "macaddr": fdb[1],
                "vlan": fdb[2]
            }

    """
    devices = [{
        "port": fdb[0],
        "ipaddr": leases[fdb[1]],
        "macaddr": fdb[1],
        "vlan": fdb[2]}
        for fdb in swFDB if fdb[0] <= 48]
    """
    end_time = time.time()
    result = jsonable_encoder({
        "fdb": devices,
        "exec_time": end_time - start_time,
    })

    return PrettyJSONResponse(content=result, indent=4)


@app.get("/narva/{sw_num}")
async def fdb_cisco_narva(sw_num):
    start_time = time.time()
    devices = {}
    leases = get_ros_dhcp_leases(
        settings.narva_ros_addr, settings.narva_ros_port,
        settings.narva_dhcp_username, settings.narva_dhcp_password)
    vtpVlanState = ['.1.3.6.1.4.1.9.9.46.1.3.1.1.2.1']
    oidifName = ['.1.3.6.1.2.1.31.1.1.1.1']
    sw_ip = int(sw_num) if sw_num.isdigit() else None
    if sw_ip is None:
        end_time = time.time()
        result = jsonable_encoder({
            "fdb": "",
            "exec_time": end_time - start_time,
            "error": "wrong switch number"
        })
        return PrettyJSONResponse(content=result, indent=4)

    ipaddress = f'172.18.17.{int(sw_num)+10}'
    # uplinkports = []
    community = settings.snmp_community
    try:
        swIfaces = bulkwalk(ipaddress, community, oidifName)
    except Exception as e:
        end_time = time.time()
        result = jsonable_encoder({
            "fdb": "",
            "exec_time": end_time - start_time,
            "error": str(e)
        })
        return PrettyJSONResponse(content=result, indent=4)
    try:
        swVlans = {int(vlan.oid[-1]) async for vlan in bulkwalk(
            ipaddress, community, vtpVlanState)}
    except Exception as e:
        end_time = time.time()
        result = jsonable_encoder({
            "fdb": "",
            "exec_time": end_time - start_time,
            "error": str(e)
        })
        return PrettyJSONResponse(content=result, indent=4)
    swIfNames = {
        int(i.oid[-1]): i.value.decode('utf-8') async for i in swIfaces
    }
    swMappings = await get_mappings(ipaddress, community, swVlans)
    swMappings = {k: swIfNames[v] for k, v in swMappings.items()}
    swFDB = await get_fdb_cisco(ipaddress, community, swVlans, swMappings)
    for iface in range(1, 49):
        devices[iface] = {
            "ipaddr": "Not Found",
            "macaddr": "Not Found",
            "vlan": "Not Found"
        }

    for fdb in swFDB:
        if fdb[0] <= 48:
            devices[fdb[0]] = {
                "ipaddr": leases[fdb[1]],
                "macaddr": fdb[1],
                "vlan": fdb[2]
            }

    end_time = time.time()
    result = jsonable_encoder({
        "fdb": devices,
        "exec_time": end_time - start_time,
    })

    return PrettyJSONResponse(content=result, indent=4)


@app.get("/dlink/{sw_num}")
async def fdb_dlink(sw_num):
    start_time = time.time()
    leases = get_kea_dhcp4_leases(settings.kea_ipaddr, settings.kea_api_port)
    ipaddress = f'172.17.17.{sw_num}'
    community = settings.snmp_community
    swFDB = await get_fdb_dlink(ipaddress, community)
    devices = [{
        "port": fdb[0],
        "ipaddr": leases[fdb[1]],
        "macaddr": fdb[1],
        "vlan": fdb[2]}
        for fdb in swFDB if fdb[0] <= 48 and fdb[0] >= 1]
    end_time = time.time()
    result = jsonable_encoder({
        "fdb": devices,
        "exec_time": end_time - start_time,
    })
    return PrettyJSONResponse(content=result, indent=4)


@app.get("/kea")
async def kea():
    leases = get_kea_dhcp4_leases(settings.kea_ipaddr, settings.kea_api_port)
    return JSONResponse(content=leases)


@app.get("/akea")
async def akea(http_client: aiohttp.ClientSession = Depends(http_client)):
    headers = {}
    content = '{ "command": "' + "lease4-get-all" + '"'
    content += ', "service": ["' "dhcp4" + '"]'
    content += ' }'
    headers['Content-Type'] = 'application/json'

    req = await http_client.post(
        url=f"http://{settings.kea_ipaddr}:{settings.kea_api_port}",
        data=str.encode(content), headers=headers)
    resp = await req.json()
    leases = resp[0]['arguments']['leases']
    return PrettyJSONResponse(leases, indent=4)
