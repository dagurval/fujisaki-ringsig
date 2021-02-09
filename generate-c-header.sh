#!/bin/sh

if ! which cbindgen > /dev/null; then
    echo "ERROR: Please install 'cbindgen' using cargo:"
    echo "    cargo install cbindgen"
    exit 1
fi

bindgen_options="--lang c --crate fujisaki_ringsig"

cmd="cbindgen ${bindgen_options} --output c_header.h"
echo ${cmd}
${cmd}

