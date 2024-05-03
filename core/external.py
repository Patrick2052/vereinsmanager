import requests
from typing import Any


def get_ip_location(ip_address: str) -> Any | None:
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        geodata = response.json()

        if not response.ok:
            return None

        if response['status'] == 'fail':
            return None
        return geodata
    except:
        return None

