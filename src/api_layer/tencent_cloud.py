"""
腾讯云API
"""
from datetime import datetime
import time
from typing import Dict, BinaryIO, Union
from hmac import HMAC
from hashlib import sha1
from urllib import parse

from requests.auth import AuthBase

from api_layer.api import BasicApi, Action, Hooks, Protocol


class TencentAuth(AuthBase):
    sign_key = ""
    key_time = ""
    expire_time = -1

    def __init__(self, config):
        self.expire_seconds = config.expire_seconds or 10
        self.secret_key = config.secret_key or ""
        self.secret_id = config.secret_id or ""
        self.mode = config.use_mode or "headers"

    def build(self):
        time_now = int(time.time())
        end_time_stamp = time_now + self.expire_seconds
        self.expire_time = end_time_stamp
        key_time = f"{time_now};{end_time_stamp}"
        self.sign_key = HMAC(
            self.secret_key.encode("utf8"), key_time.encode("utf8"), "sha1"
        ).hexdigest().lower()
        self.key_time = key_time

    def build_kv(self, path_url):
        plist = path_url.split("?", 2)
        _base = plist[1] if len(plist) == 2 else None
        if not _base:
            return "", ""
        _param = {}
        for _signal_param in _base.split("&"):
            if "=" in _signal_param:
                k, v = tuple(_signal_param.split("=", 2))
            else:
                k = _signal_param
                v = ""
            if k not in _param:
                _param[k] = v
            else:
                if isinstance(_param[k], list):
                    _param[k].append(v)
                else:
                    _param[k] = [_param[k], v]

        klist = sorted(_param.keys())
        # 字典序排序
        _values = []
        for k in klist:
            _p = _param.get(k, "")
            if isinstance(_p, list):
                _p = sorted(_p)
                _values.append("&".join([f"{i}={_p}" for i in _p]))
            else:
                _values.append(f"{k}={_p}")
        _value = "&".join(_values)
        # XXX: 需要注意,这里有缺陷，因为lower中的dict_order会受到影响
        _k = ";".join(klist).lower()
        return _k, _value

    def build_header_kv(self, headers):
        _klist = sorted(headers.keys())
        _values = []
        for k in _klist:
            _v = headers.get(k, "")
            _values.append(f"{k.lower()}={parse.quote(_v, safe=[])}")
        _value = "&".join(_values)
        _k = ";".join(_klist).lower()
        return _k, _value

    def use_signature(self, signature: Dict[str, str], r):
        if self.mode == "headers":
            _vs = []
            for k, v in signature.items():
                _vs.append(f"{k}={v}")
            r.headers["Authorization"] = "&".join(_vs)
        elif self.mode == "args":
            r.prepare_url(r.url, signature)

    def __call__(self, r):
        if time.time() > self.expire_time:
            self.build()
        pk, v = self.build_kv(r.path_url)
        hk, hv = self.build_header_kv(r.headers)
        http_string = "\n".join([
            r.method.lower(), r.path_url.split("?")[0], v, hv, ""])
        signed_string = "\n".join([
            "sha1", self.key_time,
            sha1(http_string.encode("utf8")).hexdigest().lower(), ""
        ])
        signed_header = HMAC(
            self.sign_key.encode("utf8"), signed_string.encode("utf8"), "sha1"
        ).hexdigest().lower()
        signature = {
            "q-sign-algorithm": "sha1",
            "q-ak": self.secret_id,
            "q-sign-time": self.key_time,
            "q-key-time": self.key_time,
            "q-header-list": hk,
            "q-url-param-list": pk,
            "q-signature": signed_header
        }
        self.use_signature(signature, r)
        return r


class TencentCloudApi(BasicApi):
    name = "tencent_api"
    url = "https://service.cos.myqcloud.com"
    protocol = Protocol.http

    def __init__(self, config):
        self.auth = TencentAuth(config)

    @Action
    def cos_list_buckets(
            self,
            region: Union[None, str] = None
    ):
        """
        列出指定区域，或者所有区域的存储桶列表
        :param region: 区域
        :return:
        """
        url = None
        if region is not None:
            url = f"https://cos.{region}.mycloud.com"
        return {
            "url": url,
            "headers": {
                "date": datetime.now().isoformat()
            },
            "params": {}
        }

    @Action(action_type="PUT")
    def cos_put_object(
            self,
            object_key: str,
            bucket_name: str,
            app_id: str,
            region: str,
            content: BinaryIO,
            content_type: str = "text/plain"
    ):
        """
        cos文件上传
        :param object_key: 文件路径
        :param bucket_name: 存储桶名称
        :param app_id: 应用名称
        :param region: 区域名称
        :param content: 文件内容
        :param content_type: 文件类型
        """
        url = f"https://{bucket_name}-{app_id}.cos.{region}.myqcloud.com"
        return {
            "url": url,
            "path": object_key,
            "headers": {
                "content-type": content_type
            },
            "data": content
        }
