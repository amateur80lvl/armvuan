#!/bin/bash

SRC=`dirname $0`
SRC=`realpath "${SRC}"`

cp "${SRC}"/cli-armvuan.sh "${SRC}"/armbian/lib/functions/cli/
cp -a "${SRC}"/distributions/* "${SRC}"/armbian/config/distributions/
pushd "${SRC}"/armbian
patch -Np1 <"${SRC}"/armbian.patch
popd
"${SRC}"/armbian/lib/tools/gen-library.sh
