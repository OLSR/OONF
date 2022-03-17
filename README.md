# How to Install

See http://www.olsr.org/mediawiki/index.php/OLSR.org_Network_Framework for a longer explanation. This README is the short version.

## Installing from source

Get your code from the OLSR.org Network Framework GitHub:
(see https://github.com/OLSR/OONF)

 * ``git clone https://github.com/OLSR/OONF.git``

### Pre-requisites

Download and install the neccessary build requirements
(see http://www.olsr.org/mediawiki/index.php/OLSR.org_Network_Framework#Requirements)

For Debian you will mostly need the following ones:
  * cmake: ``sudo apt-get install cmake``
  * build-essentials: ``sudo apt-get install build-essential libnl-3-dev``

## Compiling
  * ``cd build``
  * ``cmake ..``
  * ``make``

## Configuring OLSRv2

## Starting OLSRv2

Assuming your interfaces you want olsrd2 to listen on are ``eth0, wlan0 and lo`` you could start it like this:

  * ``sudo ./olsrd2_static eth0 wlan0 lo``

You won't see much output though. You can enable more output (by default it comes on stderr) for several subsystems. You can get a list of these subsystems with:

  * ``./olsrd2_static --schema=logging.info``
  * ``./olsrd2_static --schema=logging.debug``

This shows you which info and debug schemas exist. Let's say we are interested in the neighborhood disovery protocol (NHDP, RFC6130, "Hello messages"). We can set this subsystem writing actions to debug level via:

  * ``sudo ./olsrd2_static --set=log.debug=nhdp_w eth0 wlan0  lo``

You should now see some output which shows you the info from the hello packets.

## How to proceed from here

If you managed to start olsrd2 and see some output, you made it! Now is the time to review the detailed configuration setups at http://www.olsr.org/mediawiki/index.php/OLSR_network_deployments 
