"""
Api Layer

主要是调用外部api的集成体系
"""
from api_layer.api import BasicApi as Api
from api_layer.tencent_cloud import TencentCloudApi

__all__ = (
    "Api", "TencentCloudApi"
)
