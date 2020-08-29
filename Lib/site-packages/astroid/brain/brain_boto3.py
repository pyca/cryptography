# Licensed under the LGPL: https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html
# For details: https://github.com/PyCQA/astroid/blob/master/COPYING.LESSER

"""Astroid hooks for understanding boto3.ServiceRequest()"""
import astroid
from astroid import MANAGER, extract_node

BOTO_SERVICE_FACTORY_QUALIFIED_NAME = "boto3.resources.base.ServiceResource"


def service_request_transform(node):
    """Transform ServiceResource to look like dynamic classes"""
    code = """
    def __getattr__(self, attr):
        return 0
    """
    func_getattr = extract_node(code)
    node.locals["__getattr__"] = [func_getattr]
    return node


def _looks_like_boto3_service_request(node):
    return node.qname() == BOTO_SERVICE_FACTORY_QUALIFIED_NAME


MANAGER.register_transform(
    astroid.ClassDef, service_request_transform, _looks_like_boto3_service_request
)
