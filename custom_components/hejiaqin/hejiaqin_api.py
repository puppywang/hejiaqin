import aiohttp
import asyncio
import requests
import json
import functools
import hashlib
import uuid
import time
import logging
import textwrap
import urllib.parse
from abc import ABC

from homeassistant import config_entries
from .const import (
    DOMAIN,
    SL_DEVICES,
    CONFIG,
    CONF_REQUESTS_SESSION,
)

_LOGGER = logging.getLogger(__name__)

USER_AGENT = 'zhihuiguanjia/8.4.0 (iPhone; iOS 17.5.1; Scale/3.00);UniApp'
HTTPS_SUFFIX = 'https://'
HTTP_SUFFIX = 'http://'
DEVICE_SUFFIX = '/espapi/v3/cloud/json/family/devices'
BASE_URL = HTTPS_SUFFIX + 'andlink.komect.com'
DEVICES_URL = BASE_URL + DEVICE_SUFFIX + '/list' 
CONTROL_URL = BASE_URL + DEVICE_SUFFIX + '/parameters/control'
DETAIL_URL = BASE_URL + DEVICE_SUFFIX + '/detail/get'
HEAD_AUTH = 'API_KEY'
LANGUAGE = 'zh-Hans_US'
HEADERS = {
    'User-Agent': USER_AGENT,
    'Accept': '*/*',
    'Accept-Language': LANGUAGE,
}

# Login API URLs
LOGIN_URL = 'https://base.hjq.komect.com/base/user/passwdLogin'
LOGIN_BY_HJQ_TOKEN_URL = 'https://video.komect.com/user/login/loginByHJQToken'
VIDEO_SIGN_SECRET = 'r8rw4d1kjwqgqqto9dwsq3ew0ip2np1b'
REAL_API_KEY_URL = 'https://andlink.komect.com/espapi/cloud/json/loginByApp?cloudName=CMCC&keyType=0'

DP_RELAY_0 = "relay0"
DP_RELAY_1 = "relay1"
DP_RELAY_2 = "relay2"
DP_RELAY_3 = "relay3"
DP_RELAY_4 = "relay4"
DP_RELAY_5 = "relay5"
DP_RELAY_6 = "relay6"
DP_RELAY_7 = "relay7"
DP_LED = "led"
DP_DEFAULT = "def_st"
DP_REMOTE = "remote"
DP_RELAY = "response"
DP_ELECTRIC = "electric"
DP_POWER = "power"
DP_CURRENT = "current"
DP_VOLTAGE = "voltage"
DP_ELECTRICITY = "electricity"
DP_ELECTRICITY_HOUR = "electricity_hour"
DP_ELECTRICITY_DAY = "electricity_day"
DP_ELECTRICITY_WEEK = "electricity_week"
DP_ELECTRICITY_MONTH = "electricity_month"
DP_ELECTRICITY_LASTMONTH = "electricity_lastmonth"

def get_session(hass):
    entry_id = None
    session = requests.Session()
    try:
        entry_id = config_entries.current_entry.get().entry_id
    except: pass

    try:
        if entry_id is not None and hass.data[DOMAIN][CONFIG][entry_id][CONF_REQUESTS_SESSION] is not None:
            session = hass.data[DOMAIN][CONFIG][entry_id][CONF_REQUESTS_SESSION]
    except: pass
        
    return session

class HTTPRequest(ABC):
    hass = None
    session = None
    timeout = None

    async def async_make_request_by_requests(self, method, url, data=None, headers=None, verify=None):
        # session = self.session
        if method == "GET":
            func = functools.partial(
                self.session.get, 
                url,
                headers=headers, 
                params=data,
                verify=verify,
                timeout=self.timeout,
            )
        elif method == "POST":
            func = functools.partial(
                self.session.post,
                url,
                headers=headers,
                data=json.dumps(data),
                verify=verify,
                timeout=self.timeout,
            )
        elif method == "PUT":
            func = functools.partial(
                self.session.put,
                url,
                headers=headers,
                data=json.dumps(data),
                verify=verify,
                timeout=self.timeout,
            )

        resp = await self.hass.async_add_executor_job(func)
        return resp

    def make_request_by_requests(self, method, url, data=None, headers={}):
        # session = self.session
        if method == "GET":
            func = functools.partial(
                self.session.get, url, headers=headers, params=data
            )
        elif method == "POST":
            func = functools.partial(
                self.session.post,
                url,
                headers=headers,
                data=json.dumps(data),
            )
        elif method == "PUT":
            func = functools.partial(
                self.session.put,
                url,
                headers=headers,
                data=json.dumps(data),
            )

        resp = func()
        return resp


class CloudAPI(HTTPRequest):
    def __init__(self, hass):
        self.hass = hass
        # self.session = requests.Session()
        self.session = get_session(self.hass)

    async def async_get_devices_list(self, api_key):
        headers = HEADERS.copy()
        headers[HEAD_AUTH] = api_key
        # _LOGGER.debug(headers)
        data = {
            # "checkPersistent": True,
            # "getAndMuCamera": True,
            # "getHyRouter": True,
            # "getShared": True,
            # "getSharedFamily": True,
            # "getSource": True,
        }
        resp = await self.async_make_request_by_requests("GET", DEVICES_URL, headers=headers, data=data)
        # _LOGGER.debug(resp.headers)
        return resp
        #https://andlink.komect.com/espapi/v3/cloud/json/family/devices/parameters/get?deviceId=CMCC-590384-xxxxxx

class PlugAPI(HTTPRequest):

    _api_key = None
    headers = None

    def __init__(self, hass, api_key, entry_id=None):
        self.hass = hass
        self.api_key = api_key
        self.entry_id = entry_id
        self.session = get_session(self.hass)
        self.async_set_status = self.async_set_power_status
        self.async_set_led = self.async_set_signal_light
    
    @property
    def api_key(self):
        return self._api_key
    
    @api_key.setter
    def api_key(self, api_key):
        if api_key is not None:
            self._api_key = api_key
            self.headers = HEADERS.copy()
            self.headers[HEAD_AUTH] = api_key

    def _should_refresh_api_key(self, resp) -> bool:
        """Return True if response indicates API_KEY/auth failure."""
        try:
            if getattr(resp, 'status_code', None) in (401, 403):
                return True
        except Exception:
            pass

        try:
            r_json = resp.json()
        except Exception:
            return False

        if not isinstance(r_json, dict):
            return False

        result_code = r_json.get('resultCode')
        if result_code in (401, 403):
            return True

        if result_code is None or result_code == 0:
            return False

        desc = (
            r_json.get('resultCodeDesc')
            or r_json.get('resultMsg')
            or r_json.get('message')
            or ''
        )
        desc_l = str(desc).lower()
        keywords = [
            'api_key',
            'apikey',
            'token',
            'expired',
            'invalid',
            'auth',
            '鉴权',
            '认证',
            '过期',
            '失效',
        ]
        return any(k in desc_l for k in keywords)

    async def _async_refresh_api_key(self):
        """Refresh API_KEY using saved credentials in config entry."""
        if not self.entry_id:
            return None

        entry = self.hass.config_entries.async_get_entry(self.entry_id)
        if entry is None:
            return None

        try:
            user_input = entry.data.get('user_input', {})
            tel = user_input.get('phone')
            pwd = user_input.get('password')
        except Exception:
            tel = None
            pwd = None

        if not tel or not pwd:
            return None

        error, new_api_key = await async_login_and_get_api_key(tel, pwd)
        if error or not new_api_key:
            _LOGGER.error('API key refresh failed: %s', error)
            return None

        # update entry data
        try:
            new_data = {**entry.data}
            new_ui = {**new_data.get('user_input', {})}
            new_ui['api_key'] = new_api_key
            new_data['user_input'] = new_ui

            new_devices = {}
            for dev_id, dev_cfg in (new_data.get('devices') or {}).items():
                dev_cfg = {**dev_cfg}
                dev_cfg['api_key'] = new_api_key
                new_devices[dev_id] = dev_cfg
            if new_devices:
                new_data['devices'] = new_devices

            self.hass.config_entries.async_update_entry(entry, data=new_data)
        except Exception as e:
            _LOGGER.debug('Failed to persist refreshed api_key: %s', e)

        # update loaded devices in memory
        try:
            cfg = self.hass.data.get(DOMAIN, {}).get(CONFIG, {}).get(self.entry_id)
            if cfg and isinstance(cfg.get(SL_DEVICES), list):
                for dev in cfg[SL_DEVICES]:
                    try:
                        if getattr(dev, 'api', None) is not None:
                            dev.api.api_key = new_api_key
                        if getattr(dev, 'config', None) is not None:
                            dev.config['api_key'] = new_api_key
                    except Exception:
                        pass
        except Exception:
            pass

        return new_api_key

    async def _async_request_with_reauth(self, method, url, data=None, headers=None, verify=None):
        """Make request, and re-login once if API_KEY is expired."""
        resp = await self.async_make_request_by_requests(method, url, data=data, headers=headers, verify=verify)
        if self._should_refresh_api_key(resp):
            new_api_key = await self._async_refresh_api_key()
            if new_api_key:
                # retry with new header
                if headers is None:
                    headers = self.headers
                else:
                    headers = {**headers}
                    headers[HEAD_AUTH] = new_api_key
                resp = await self.async_make_request_by_requests(method, url, data=data, headers=headers, verify=verify)
        return resp

    # def set_api_key(self, api_key):
    #     if api_key is not None:
    #         self.headers = HEADERS.copy()
    #         self.headers[HEAD_AUTH] = api_key


    async def async_get_detail(self, decice_id):
        data = {"checkConnected": True, "deviceId": decice_id}

        resp = await self._async_request_with_reauth("GET", DETAIL_URL, data=data, headers=self.headers)
        return resp

    async def async_set_outlet_status(self, decice_id, index, status):
        headers = self.headers.copy()
        headers['Content-Type'] = "application/json"
        data = {"deviceId":decice_id,"parameters":{"param":[{"name": "outletStatus", "index": index, "content": status}]}}

        resp = await self._async_request_with_reauth("POST", CONTROL_URL, data=data, headers=headers)
        return resp
    
    async def async_set_power_status(self, decice_id, index, status):
        headers = self.headers.copy()
        headers['Content-Type'] = "application/json"
        data = {"deviceId":decice_id,"parameters":{"param":[{"name": "powerSwitch", "content": status}]}}

        resp = await self._async_request_with_reauth("POST", CONTROL_URL, data=data, headers=headers)
        return resp
    
    async def async_set_current_protect(self, decice_id, status):
        headers = self.headers.copy()
        headers['Content-Type'] = "application/json"
        data = data = {"deviceId":decice_id,"parameters":{"param":[{"name": "overCurrentProtect", "content": status}]}}

        resp = await self._async_request_with_reauth("POST", CONTROL_URL, data=data, headers=headers)
        return resp
    
    async def async_set_voltage_protect(self, decice_id, status):
        headers = self.headers.copy()
        headers['Content-Type'] = "application/json"
        data = data = {"deviceId":decice_id,"parameters":{"param":[{"name": "overVoltageProtect", "content": status}]}}

        resp = await self._async_request_with_reauth("POST", CONTROL_URL, data=data, headers=headers)
        return resp
    
    async def async_set_signal_light(self, decice_id, status):
        headers = self.headers.copy()
        headers['Content-Type'] = "application/json"
        data = data = {"deviceId":decice_id,"parameters":{"param":[{"name": "signalLight", "content": status}]}}

        resp = await self._async_request_with_reauth("POST", CONTROL_URL, data=data, headers=headers)
        return resp
    
    async def async_set_energy(self, decice_id, status):
        headers = self.headers.copy()
        headers['Content-Type'] = "application/json"
        data = data = {"deviceId":decice_id,"parameters":{"param":[{"name": "energy", "content": status}]}}

        resp = await self._async_request_with_reauth("POST", CONTROL_URL, data=data, headers=headers)
        return resp

    async def async_set_default(self, decice_id, status):
        headers = self.headers.copy()
        headers['Content-Type'] = "application/json"
        data = data = {"deviceId":decice_id,"parameters":{"param":[{"name": "pwCutMemory", "content": status}]}}

        resp = await self._async_request_with_reauth("POST", CONTROL_URL, data=data, headers=headers)
        return resp
    
    async def async_set_children_lock(self, decice_id, status):
        headers = self.headers.copy()
        headers['Content-Type'] = "application/json"
        data = data = {"deviceId":decice_id,"parameters":{"param":[{"name": "childrenLock", "content": status}]}}

        resp = await self._async_request_with_reauth("POST", CONTROL_URL, data=data, headers=headers)
        return resp
    
    async def async_set_status_by_name(self, decice_id, name, status):
        headers = self.headers.copy()
        headers['Content-Type'] = "application/json"
        data = data = {"deviceId":decice_id,"parameters":{"param":[{"name": name, "content": status}]}}

        resp = await self._async_request_with_reauth("POST", CONTROL_URL, data=data, headers=headers)
        return resp

    async def async_add_timer(self, decice_id, timer):
        #{"time": 2023, "repeat": 0, "enable": 1, "action": 0}
        #%257B%2522time%2522%253A2023%252C%2522repeat%2522%253A0%252C%2522enable%2522%253A1%252C%2522action%2522%253A0%257D
        #%7B%22time%22%3A2023%2C%22repeat%22%3A0%2C%22enable%22%3A1%2C%22action%22%3A0%7D
        pass


class LoginAPI:
    """API class for handling login via phone number and password."""
    
    def __init__(self):
        self.hjq_token = None
        self.pass_id = None
        self.tel = None
    
    @staticmethod
    def get_md5(value: str) -> str:
        """Calculate MD5 hash of a string."""
        md5_hash = hashlib.md5()
        md5_hash.update(value.encode("utf-8"))
        return md5_hash.hexdigest()

    @staticmethod
    def get_sha1(value: str) -> str:
        """Calculate SHA1 hash of a string."""
        sha1_hash = hashlib.sha1()
        sha1_hash.update(value.encode("utf-8"))
        return sha1_hash.hexdigest()

    async def async_login(self, tel: str, pwd: str) -> tuple[str, str, str]:
        """
        Login with phone number and password.
        
        Returns:
            tuple: (error_message, hjq_token, pass_id)
                   error_message is None if successful
        """
        self.tel = tel
        body = json.dumps({
            "virtualAuthdata": self.get_md5(pwd),
            "authType": "10",
            "userAccount": tel,
            "authdata": self.get_sha1("fetion.com.cn:" + pwd),
        })
        headers = {"Content-Type": "application/json"}
        
        try:
            async with aiohttp.ClientSession() as client:
                resp = await client.post(LOGIN_URL, data=body, headers=headers)
                resp_text = await resp.text()
                _LOGGER.debug(f"Login response: {resp_text}")
                
                if "Set-Cookie" not in resp.headers:
                    resp_json = await resp.json()
                    error_msg = resp_json.get("message", "Login failed: No cookie returned")
                    return error_msg, None, None
                
                self.hjq_token = resp.headers["Set-Cookie"].split("=")[1].split(";")[0]
                resp_json = await resp.json()
                
                if resp_json.get("code") != '1000000':
                    error_msg = resp_json.get("message", "Login failed")
                    return error_msg, None, None
                
                self.pass_id = resp_json["data"]["passId"]
                _LOGGER.info(f"Login successful for {tel}, hjq_token: {self.hjq_token[:20]}...")
                
                return None, self.hjq_token, self.pass_id
                
        except aiohttp.ClientError as e:
            _LOGGER.error(f"Login request failed: {e}")
            return f"Connection error: {str(e)}", None, None
        except Exception as e:
            _LOGGER.error(f"Login failed with exception: {e}")
            return f"Login error: {str(e)}", None, None

    async def async_get_real_api_key(self) -> tuple[str, str]:
        """Exchange hjq_token for real API key via loginByApp."""
        if not self.hjq_token:
            return 'hjq_token is empty', None

        pseudo_key = f"{self.hjq_token}:010108:15"
        headers = {"API_KEY": pseudo_key}

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as client:
                resp = await client.get(REAL_API_KEY_URL, headers=headers)
                resp_text = await resp.text()
                _LOGGER.debug(f"loginByApp response: {resp_text}")

                resp_json = await resp.json(content_type=None)
                if not isinstance(resp_json, dict):
                    return 'loginByApp response is not json', None

                if resp_json.get('resultCode') != 0:
                    return resp_json.get('resultCodeDesc') or resp_json.get('message') or 'loginByApp failed', None

                key = resp_json.get('key')
                if not isinstance(key, str) or not key:
                    return 'loginByApp key is empty', None

                return None, key

        except aiohttp.ClientError as e:
            _LOGGER.error(f"loginByApp request failed: {e}")
            return f"Connection error: {str(e)}", None
        except Exception as e:
            _LOGGER.error(f"loginByApp failed with exception: {e}")
            return f"loginByApp error: {str(e)}", None

    def get_api_key(self) -> str:
        """
        Get API key for device API calls.
        The API key format is: hjq_token:010108:15
        """
        if self.hjq_token:
            return f"{self.hjq_token}:010108:15"
        return None


async def async_login_and_get_api_key(tel: str, pwd: str) -> tuple[str, str]:
    """
    Convenience function to login and get API key.
    
    Args:
        tel: Phone number
        pwd: Password
        
    Returns:
        tuple: (error_message, api_key)
               error_message is None if successful
    """
    login_api = LoginAPI()
    error, hjq_token, pass_id = await login_api.async_login(tel, pwd)
    
    if error:
        return error, None

    error, real_api_key = await login_api.async_get_real_api_key()
    if error:
        return error, None

    return None, real_api_key