#!/usr/bin/env python3

import time
import socket
import requests
import time
import json
import dbm
import random
import dateutil.parser
import datetime
import sys
import solaredge  # type: ignore
import logging
import typing
import yaml
import hashlib

MAX_WAIT = 150


REGION = "SE3"
CONTROL_BASE = (
    "https://poolheater-2a8c2-default-rtdb.europe-west1.firebasedatabase.app/"
)


class Price(typing.TypedDict):
    value: float
    timestamp: datetime.datetime


class Override(typing.TypedDict):
    start: str
    end: str
    state: bool


class Config(typing.TypedDict):
    pricecutoff: float
    solarcutoff: float
    heattemp: float
    lowtemp: float


class NetConfig(typing.TypedDict):
    config: Config
    override: list[Override]


class AquaTempConfig(typing.TypedDict):
    username: str
    password: str


class SolarEdgeConfig(typing.TypedDict):
    siteid: float
    apikey: str


class SecretConfig(typing.TypedDict):
    solaredge: SolarEdgeConfig
    aquatemp: AquaTempConfig


Database: typing.TypeAlias = "dbm._Database"


defaults: Config = {
    "pricecutoff": 60,
    "solarcutoff": 5000,
    "heattemp": 28,
    "lowtemp": 10,
}

logger = logging.getLogger()


def get_config() -> NetConfig:
    if not CONTROL_BASE:
        return {"config": defaults, "override": []}

    logger.debug(f"Checking control data {CONTROL_BASE}/.json\n")

    r = requests.get(f"{CONTROL_BASE}/.json")
    if r.status_code != 200:
        raise SystemError("override URL set but failed to fetch")
    j = json.loads(r.text.strip('"').encode("ascii").decode("unicode_escape"))

    if not "config" in j:
        j["config"] = defaults
    else:
        for p in defaults:
            if not p in j["config"]:
                j["config"][p] = defaults[p]  # type:ignore

    return j


def override_active(config: NetConfig) -> typing.Tuple[bool, bool]:
    current_data = False

    if not "override" in config:
        return (False, False)

    now = datetime.datetime.now().timestamp()
    for p in config["override"]:
        try:
            start = dateutil.parser.parse(p["start"]).astimezone().timestamp()
            end = dateutil.parser.parse(p["end"]).astimezone().timestamp()

            if start <= now and now <= end:
                # Matches
                logger.debug(f"Matching override data {p}\n")

                state = False
                if p["state"] == True or p["state"] == "on" or p["state"] == "1":
                    state = True

                return True, state
        except:
            pass

    logger.debug(f"Returning form override check - override is {current_data}\n")

    # Override info but no info for now, leave off
    return (current_data, False)


def setup_logger(
    console_level: int = logging.DEBUG,
    file_level: int = logging.DEBUG,
    filename: str = "poolheatcontrol.log",
) -> None:
    h = logging.StreamHandler()
    h.setLevel(console_level)
    logger.addHandler(h)
    f = logging.FileHandler(filename)
    f.setFormatter(logging.Formatter("{asctime} - {levelname} - {message}", style="{"))
    f.setLevel(file_level)
    logger.addHandler(f)

    logger.setLevel(min(file_level, console_level))


def price_apply(x: Price, config: Config) -> bool:
    today = datetime.datetime.now()
    if x["timestamp"].day == today.day:
        return True
    return False


def filter_prices(p: list[Price], config: Config) -> list[Price]:
    p.sort(key=lambda x: x["value"])

    # Filter out prices below the cutoff

    return list(
        filter(
            lambda x: x["value"] < config["pricecutoff"],
            p,
        )
    )


def should_heat(db: Database, config: Config, secrets: SecretConfig) -> bool:
    t = time.localtime().tm_hour

    all_prices = get_prices(db)

    prices = list(filter_prices(all_prices, config))
    logger.debug(f"Prices after filtering for low are {prices}")

    # We have already checked borders and only need to see if we're
    # in one of the cheap slots

    allowed = False

    for p in prices:
        if p["timestamp"].hour == int(t):
            logger.debug(f"Found this hour ({t}) in low prices, heating allowed")
            allowed = True

    if not allowed:
        return False

    l = solaredge_get_current(db, secrets["solaredge"])
    if l > config["solarcutoff"]:
        return True

    return False


def get_prices(db: Database) -> list[Price]:
    key = f"prices{time.strftime('%Y%m%d')}"
    if key in db:
        pricedata = db[key]
    else:
        logger.debug("Fetching spot prices")
        r = requests.get(f"https://spot.utilitarian.io/electricity/SE3/latest")
        if r.status_code != 200:
            raise SystemError("could not fetch electricity info")

        pricedata = bytes(r.text, "ascii")
        db[key] = pricedata

    def fix_entry(x: dict[str, str]) -> Price:
        r = Price(
            value=float(x["value"]),
            timestamp=dateutil.parser.parse(x["timestamp"]).astimezone(),
        )
        return r

    fixed = list(map(fix_entry, json.loads(pricedata)))

    return fixed


def solaredge_get_current(db: Database, se: SolarEdgeConfig) -> float:
    key = "solaredgedata"

    if key in db:
        l = json.loads(db[key].decode("ascii"))
        (timestamp, val) = l[0], l[1]

        if time.time() - timestamp < 15 * 60:
            return val

    api = solaredge.Solaredge(se["apikey"])
    l = api.get_overview(se["siteid"])

    w = l["overview"]["currentPower"]["power"]
    db[key] = json.dumps([time.time(), w])

    return w


def aquatemp_login(
    db: Database, at: AquaTempConfig, force: bool = False
) -> typing.Tuple[str, str]:
    key = "aquatemptokenandid"

    if not force and key in db:
        l = json.loads(db[key].decode("ascii"))
        (token, id) = l[0], l[1]
        return (token, id)

    md5 = hashlib.new("md5")
    md5.update(bytes(at["password"], "utf-8"))

    r = requests.request(
        method="POST",
        url="https://cloud.linked-go.com:449/crmservice/api/app/user/login",
        json={"userName": at["username"], "password": md5.hexdigest()},
        headers={"Content-Type": "application/json"},
    )

    if (not r.ok) or int(r.json()["error_code"]) != 0:
        raise SystemError("bad return from aquatemp login")

    token = str(r.json()["objectResult"]["x-token"])
    id = str(r.json()["objectResult"]["userId"])
    db[key] = json.dumps((token, id))
    return (token, id)


def aquatemp_get_device(db: Database, token: str, id: str) -> str:
    key = "aquatempdevice"

    if key in db:
        return db[key].decode("ascii")

    r = requests.request(
        method="POST",
        url="https://cloud.linked-go.com:449/crmservice/api/app/device/getMyAppectDeviceShareDataList",
        json={"toUser": id},
        headers={"Content-Type": "application/json", "x-token": token},
    )

    if (not r.ok) or int(r.json()["error_code"]) != 0:
        logger.debug(f"Bad return from aquatemp when fetching device: {r.text}")
        raise SystemError("bad return from aquatemp device check")

    device = str(r.json()["objectResult"][0]["deviceCode"])
    db[key] = device
    return device


def aquatemp_get_target_temp(db: Database, token: str, id: str) -> float:
    device = aquatemp_get_device(db, token, id)

    # T02 is in, T03 is out, Set_Temp is target

    r = requests.request(
        method="POST",
        url="https://cloud.linked-go.com:449/crmservice/api/app/device/getDataByCode",
        json={"deviceCode": device, "protocalCodes": ["Set_Temp", "R02"]},
        headers={"Content-Type": "application/json", "x-token": token},
    )

    if (not r.ok) or int(r.json()["error_code"]) != 0:
        logger.debug(f"Bad return from aquatemp when fetching temperature: {r.text}")
        raise SystemError("bad return from aquatemp temperature fetch")

    return float(r.json()["objectResult"][0]["value"])


def aquatemp_set_target_temp(db: Database, token: str, id: str, temp: float) -> None:
    device = aquatemp_get_device(db, token, id)

    t = str(temp)
    # T02 is in, T03 is out, Set_Temp is target

    r = requests.request(
        method="POST",
        url="https://cloud.linked-go.com:449/crmservice/api/app/device/control",
        json={
            "param": [
                {"deviceCode": device, "protocolCode": "Set_Temp", "value": t},
                {"deviceCode": device, "protocolCode": "R02", "value": t},
            ]
        },
        headers={"Content-Type": "application/json", "x-token": token},
    )

    if (not r.ok) or int(r.json()["error_code"]) != 0:
        logger.debug(f"Bad return from aquatemp when setting temperature: {r.text}")
        raise SystemError("bad return from aquatemp temperature set")


def is_heating(db: Database, secret: SecretConfig, config: Config) -> bool:
    try:
        (token, id) = aquatemp_login(db, secret["aquatemp"])
        t = aquatemp_get_target_temp(db, token, id)
    except SystemError:
        (token, id) = aquatemp_login(db, secret["aquatemp"], force=True)
        t = aquatemp_get_target_temp(db, token, id)

    return not (t == config["lowtemp"])


def set_heating(db: Database, at: AquaTempConfig, config: Config, ns: bool) -> None:
    (token, id) = aquatemp_login(db, at)

    temp = config["lowtemp"]
    if ns:
        temp = config["heattemp"]

    aquatemp_set_target_temp(db, token, id, temp)


if __name__ == "__main__":
    setup_logger()

    db = dbm.open("poolheatcontrol.db", "c")
    apply = False

    secretconfig = None
    with open("config.yaml") as configfile:
        secretconfig = yaml.safe_load(configfile)

    allconfig = get_config()
    (apply, correct_state) = override_active(allconfig)
    if not apply:
        correct_state = should_heat(db, allconfig["config"], secretconfig)
    current_state = is_heating(db, secretconfig, allconfig["config"])

    logger.debug(f"Currently runing is {current_state}\n")
    logger.debug(f"Should be running is {correct_state}\n")

    # correct_state = True
    if current_state != correct_state:
        logger.debug(f"Need to change state of running to {correct_state}\n")

        set_heating(db, secretconfig["aquatemp"], allconfig["config"], correct_state)
