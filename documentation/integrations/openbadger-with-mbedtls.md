mbedtls, as delivered in the package libmbedtls-dev, was tested with
obtest-pk-pacs.

the certificate parser is based on mbedtls.
note there is a stand-alone version so you can use
it as a bolt-on component.



# Building mbedtls #

set up packages.  include git autoconf libtool make cmake

do the clone.  get 4.1.0 specifically, not tip of the tree.

```
git clone https://github.com/Mbed-TLS/mbedtls --branch mbedtls-4.1.0
```

get the submodules.  remember the recursive switch.
```
git submodule update --init --recursive
```

cd to the directory.  make a build directory.

```
cd mbedtls
mkdir build
```

configure the project (that's a cmake thing.)

```
cmake -B build .
```

build it (compile stuff.)
```
cmake --build .
```

install it. as used in production, so sudo to install

```
sudo cmake --install .
```



clone
cd to mbedtls
 2016  git submodule update --init --recursive
 2043  mkdir build
 2044  cmake -S . -B build
 2046  cmake --build build
 2048  sudo cmake --install build

