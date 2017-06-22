At the moment you need the following things to compile OLSRd2:
1) a C buildchain (normally gcc, but should work with LLVM/Clang)
2) cmake (2.8.12 or newer)
3) git
4) developer files for libnl-3 (e.g. libnl-3-dev)
5) libtomcrypt-dev for security plugins
6) libuci for OpenWRT uciloader plugin

To build the OLSR.org Network Framework open a shell in the OONF
directory and run the following commands:

> cd build
> cmake ..
> make

There are some build variables you can choose to configure building.
We suggest to use ccmake to do this, but the defaults should
be already reasonable.

> cd build
> ccmake ..

If you want to crosscompile the routing agent, you will find a few
examples in the cmake/cross. To compile the code with OpenWRT, you
can use the repository (or a local copy) as an OpenWRT feed.

You will find more information in our wiki:
http://www.olsr.org/mediawiki/index.php/OLSR.org_Network_Framework
