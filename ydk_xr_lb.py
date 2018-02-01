#!/usr/bin/env python
#
# Copyright 2016 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Create configuration for model Cisco-IOS-XR-ifmgr-cfg.
usage: nc-create-xr-ifmgr-cfg-30-ydk.py [-h] [-v] device
positional arguments:
  username       username
  password       password
  device         NETCONF device

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  print debugging messages
"""

from argparse import ArgumentParser
from urlparse import urlparse

from ydk.services import CRUDService
from ydk.providers import NetconfServiceProvider
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_ifmgr_cfg \
    as xr_ifmgr_cfg
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_ipv4_bgp_cfg \
    as xr_ipv4_bgp_cfg
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_ipv4_bgp_datatypes \
    as xr_ipv4_bgp_datatypes
from ydk.types import Empty
import logging


def config_interface(interface_configurations, address):
    """Add config data to interface_configurations object."""
    # configure IPv4 loopback
    interface_configuration = interface_configurations.InterfaceConfiguration()
    interface_configuration.active = "act"
    interface_configuration.interface_name = "Loopback99"
    interface_configuration.interface_virtual = Empty()
    interface_configuration.description = "ADDITIONAL ROUTER LOOPBACK"
    primary = interface_configuration.ipv4_network.addresses.Primary()
    primary.address = address
    primary.netmask = "255.255.255.255"
    interface_configuration.ipv4_network.addresses.primary = primary
    interface_configurations.interface_configuration.append(interface_configuration)

def config_bgp(bgp, address):
    """Add config data to bgp object."""
    # global configuration
    instance = bgp.Instance()
    instance.instance_name = "default"
    instance_as = instance.InstanceAs()
    instance_as.as_ = 0
    four_byte_as = instance_as.FourByteAs()
    four_byte_as.as_ = 65504
    afi = four_byte_as.DefaultVrf().Global_().GlobalAfs().GlobalAf()
    afi.af_name = "ipv4-unicast"
    sourced_net = afi.SourcedNetworks().SourcedNetwork()
    sourced_net.network_addr = address
    sourced_net.network_prefix = 32

    # append configuration objects
    afi.sourced_networks.sourced_network.append(sourced_net)
    four_byte_as.default_vrf.global_.global_afs.global_af.append(afi)
    instance_as.four_byte_as.append(four_byte_as)
    instance.instance_as.append(instance_as)
    bgp.instance.append(instance)

if __name__ == "__main__":
    """Execute main program."""
    parser = ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging messages",
                        action="store_true")
    parser.add_argument("username",
                      help="username")
    parser.add_argument("password",
                      help="password")
    parser.add_argument("device",
                      help="NETCONF device")
    args = parser.parse_args()

    suffix = args.device.split(".")[3]
    address = "192.168.123." + suffix

    # log debug messages if verbose argument specified
    if args.verbose:
        logger = logging.getLogger("ydk")
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(("%(asctime)s - %(name)s - "
                                      "%(levelname)s - %(message)s"))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # create NETCONF provider
    provider = NetconfServiceProvider(address=args.device,
                                      port=830,
                                      username=args.username,
                                      password=args.password,
                                      protocol="ssh")
    # create CRUD service
    crud = CRUDService()

    # create interface config
    interface_configurations = xr_ifmgr_cfg.InterfaceConfigurations()  # create object
    config_interface(interface_configurations, address)  # add object configuration

    # create configuration on NETCONF device
    crud.create(provider, interface_configurations)

    # create BGP config
    bgp_configuration = xr_ipv4_bgp_cfg.Bgp()  # create object
    config_bgp(bgp_configuration, address)

    crud.create(provider, bgp_configuration) 
    exit()
# End of script