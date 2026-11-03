"""沙箱驱动实现集合。"""

from app.engines.sandbox.drivers.libvirt_driver import LibvirtDriver
from app.engines.sandbox.drivers.mock_driver import MockDriver
from app.engines.sandbox.drivers.virtualbox_driver import VirtualBoxDriver

DRIVERS = {
    "mock": MockDriver,
    "virtualbox": VirtualBoxDriver,
    "libvirt": LibvirtDriver,
}

__all__ = ["DRIVERS", "MockDriver", "VirtualBoxDriver", "LibvirtDriver"]
