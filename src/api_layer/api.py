"""
基础的api模块
"""
from copy import deepcopy
from enum import auto, Flag
from functools import partial
from typing import Any, Dict, Union, List

from flask import Flask
from requests import Session, Request


class Hooks:
    def __init__(self, func):
        self.func = func

    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)

    def bind_instance(self, instance):
        self.func = partial(self.func, instance)


class ActionState(Flag):
    success = auto()
    failed = auto()
    pending = auto()


class MetaAction(type):
    def __call__(cls, *args, **kwargs):
        if args and callable(args[0]):
            return super().__call__(name=args[0].__name__)(args[0])
        else:
            return super().__call__(*args, **kwargs)


class Action(metaclass=MetaAction):
    instance = None
    action_name: str = ""  # 动作名称
    action_type: str = "GET"  # 动作类型
    action_target: str = ""  # 动作目标
    action_payload: Dict[str, Any] = {
        "hooks": [],
        "url": ""
    }  # 动作负载

    args = ()
    kwargs = {}

    def __init__(
            self,
            name: str = None,
            path: str = "",
            action_type: str = "GET"):
        self.action_name = name
        self.action_payload["path"] = path
        self.action_type = action_type

    def __call__(self, *args, **kwargs):
        func = None
        if args:
            func = args[0]
            if self.action_name is None:
                self.action_name = func.__name__
        if callable(func):
            self.func = func
        else:
            new_action = deepcopy(self)
            new_action.args = args
            new_action.kwargs = kwargs
            return new_action
        return self

    def __repr__(self):
        return f"<Action {self.action_name} at {hex(id(self))}>"

    def build_payload(self):
        self.action_payload.update(
            self.func(self.instance, *self.args, **self.kwargs))

    def bind_instance(self, instance):
        self.instance = instance
        for hook in self.action_payload.get("hooks", []):
            hook.bind_instance(instance)

    def hook(self, hook):
        self.action_payload["hooks"].append(hook)


class ActionResult:
    state: ActionState = ActionState.pending

    def __init__(self, result_basic):
        self.basic_result = result_basic

    @property
    def result(self):
        return self.basic_result


class Protocol(Flag):
    http = auto()
    tcp = auto()
    udp = auto()
    undefined = auto()


class ProtocolTool:
    protocol = Protocol.undefined

    @classmethod
    def build(cls, protocol: Protocol):
        ins = None
        for _subcls in cls.__subclasses__():
            if _subcls.protocol in protocol:
                ins = _subcls()
                break
        return ins

    def bind_config(self, config: Dict[str, Any]):
        raise NotImplementedError()


class HttpProtocolTool(ProtocolTool):
    protocol = Protocol.http
    basic_url = ""  # 基础网址
    basic_auth = None  # 鉴权
    basic_hooks = []  # 基础hooks

    def bind_config(self, config: Dict[str, Any]) -> ProtocolTool:
        self.basic_url = config.get("basic_url", "")
        self.basic_auth = config.get("basic_auth", None)
        self.basic_hooks = config.get("basic_hooks", [])
        return self

    def build_request(self, method, payload):
        url = payload.pop("url", "") or self.basic_url
        req = Request(
            method=method,
            url=url + payload.pop("path", "/"),
            auth=self.basic_auth,
            hooks={
                "response": self.basic_hooks + payload.pop("hooks", [])
            },
            **payload
        )
        prepped = req.prepare()
        return prepped

    def do(self, action: Action):
        if action is None:
            return None
        action.build_payload()
        _payload = action.action_payload
        _action_type = action.action_type

        prepared_req = self.build_request(_action_type, _payload)

        with Session() as s:
            r = s.send(prepared_req)
        return r


class MetaBasicApi(type):
    def __new__(cls, cls_name, cls_bases, cls_dict):
        hooks = []
        actions = []
        for k, v in cls_dict.items():
            if isinstance(v, Hooks):
                hooks.append(v)
            elif isinstance(v, Action):
                actions.append((v.action_name or k, v))

        cls_dict["hooks"] = hooks
        cls_dict["actions"] = dict(actions)
        new_cls = super().__new__(cls, cls_name, cls_bases, cls_dict)
        return new_cls

    def __call__(cls, *args, **kwargs):
        ins = super().__call__(*args, **kwargs)
        for action in ins.actions.values():
            action.bind_instance(ins)
        for hook in ins.hooks:
            hook.bind_instance(ins)
        return ins


class BasicApi(metaclass=MetaBasicApi):
    protocol = Protocol.http
    url = ""
    auth = None
    actions = {}

    @classmethod
    def bind_flask_app(cls, app: Flask):
        api = {}
        for SubCls in cls.__subclasses__():
            sub_instance = SubCls(app.app_config)
            api[sub_instance.name] = sub_instance
        app.api = type("Api", (), api)()

    def do_action(self, action: Union[str, Action]) -> ActionResult:
        """
        执行动作
        :param action: 定义的动作
        :return: Action Request 动作执行的结果
        """
        if isinstance(action, str):
            action: Action = self.actions.get(action, None)
        action_result = self.protocol_tools.do(action)
        return ActionResult(action_result)

    def do_actions(
            self, actions: List[Union[str, Action]]) -> List[ActionResult]:
        """
        批量执行动作
        :param actions: 动作列表
        :return:
        """
        results = []
        for action in actions:
            print(action)
            results.append(self.do_action(action))
        return results

    @property
    def config(self):
        return {
            "basic_auth": self.auth,
            "basic_url": self.url,
            "basic_hooks": self.hooks
        }

    @property
    def protocol_tools(self):
        return ProtocolTool.build(self.protocol).bind_config(self.config)
