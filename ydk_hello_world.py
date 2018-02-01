#!/usr/bin/env python
#
# Copyright 2018 Cisco Systems, Inc.
# import providers, services and models 
from argparse import ArgumentParser
from ydk.services import CRUDService
from ydk.providers import NetconfServiceProvider
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_shellutil_cfg \
	as xr_shellutil_cfg
from datetime import timedelta
import logging
        
if __name__ == "__main__":
	"""Main execution path"""

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

	# log debug messages if verbose argument specified
	if args.verbose:
		logger = logging.getLogger("ydk")
		logger.setLevel(logging.DEBUG)
		handler = logging.StreamHandler()
		formatter = logging.Formatter(("%(asctime)s - %(name)s - "
										"%(levelname)s - %(message)s"))
		handler.setFormatter(formatter)
		logger.addHandler(handler)
    
    # create NETCONF session
	provider = NetconfServiceProvider(address=args.device,
										port=830,
										username=args.username,
										password=args.password,
										protocol="ssh")

	# create CRUD service
	crud = CRUDService()
            
	# create hostname object
	hostname = xr_shellutil_cfg.HostNames()
          
	# read hostmame from device
	host_name = crud.read(provider, hostname)
            
	# Print hostname
	print("Hostname is " + host_name.host_name.get())

	exit()           
  
