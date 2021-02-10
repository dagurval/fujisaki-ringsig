#!/bin/sh

if ! which cbindgen > /dev/null; then
    echo "ERROR: Please install 'cbindgen' using cargo:"
    echo "    cargo install cbindgen"
    exit 1
fi

bindgen_options="--lang c --cpp-compat=true --crate fujisaki_ringsig"

cmd="cbindgen ${bindgen_options} --output fujisaki_ringsig.h"
echo ${cmd}
${cmd}

