#!/bin/bash

# required: sudo apt install musl-tools libssl-dev ca-certificates curl git wget ;

cd "$(dirname $0)";

SCRIPT_DIR="$PWD";
BIN_NAME="wxwork_robotd";

OPENSSL_URL=https://www.openssl.org/source/openssl-1.1.0h.tar.gz;
OPENSSL_PKG=$(basename $OPENSSL_URL);

BUILD_TARGETS=(
    "ENABLE_CROSS_COMPILE=0 TARGET_ARCH=x86_64-unknown-linux-gnu"
    "ENABLE_CROSS_COMPILE=1 TARGET_ARCH=x86_64-unknown-linux-musl"
    "ENABLE_CROSS_COMPILE=1 TARGET_ARCH=aarch64-unknown-linux-gnu"
    "ENABLE_CROSS_COMPILE=1 TARGET_ARCH=arm-unknown-linux-musleabi"
    "ENABLE_CROSS_COMPILE=1 TARGET_ARCH=armv7-unknown-linux-musleabihf"
    "ENABLE_CROSS_COMPILE=1 TARGET_ARCH=i686-unknown-freebsd"
    "ENABLE_CROSS_COMPILE=1 TARGET_ARCH=i686-unknown-linux-musl"
    "ENABLE_CROSS_COMPILE=1 TARGET_ARCH=mips-unknown-linux-gnu"
    "ENABLE_CROSS_COMPILE=1 TARGET_ARCH=mips64-unknown-linux-gnuabi64"
    "ENABLE_CROSS_COMPILE=1 TARGET_ARCH=x86_64-unknown-freebsd"
);

# BUILD_TARGETS=(
#     "x86_64-unknown-linux-gnu"
#     "CROSS:x86_64-unknown-linux-musl"
#     "CROSS:i686-unknown-linux-musl"
#     "CROSS:x86_64-apple-darwin"
#     "CROSS:aarch64-unknown-linux-musl"
#     "CROSS:armv7-unknown-linux-musleabihf"
#     "CROSS:mips-unknown-linux-musl"
#     "CROSS:mipsel-unknown-linux-musl"
# );

function get_openssl_pkg() {
    if [ ! -e "$SCRIPT_DIR/$OPENSSL_PKG" ]; then
        wget --no-check-certificate $OPENSSL_URL -O "$SCRIPT_DIR/$OPENSSL_PKG";
    fi
}

function build_for_arch() {
    for ENV_VAR in $@; do
        echo "export $ENV_VAR;";
        export $ENV_VAR;
    done
    if [ "$PWD" != "$SCRIPT_DIR" ]; then
        cd "$SCRIPT_DIR";
    fi

    CROSS_COMPILE_DIR="$TARGET_ARCH";
    CROSS_COMPILE_TARGET="--target $CROSS_COMPILE_DIR";

    if [ -z "$ENABLE_CROSS_COMPILE" ]; then
        ENABLE_CROSS_COMPILE=0;
    fi

    echo "ENABLE_CROSS_COMPILE=$ENABLE_CROSS_COMPILE";
    # return;

    # rustup target add --toolchain stable $TARGET_ARCH;

    # build std and core
    # which xargo > /dev/null 2>&1 ;
    # if [ 0 -ne $? ]; then
    #     cargo install xargo;
    # fi
    # rustup component list | grep rust-src | grep installed > /dev/null 2>&1 ;
    # if [ 0 -ne $? ]; then
    #     rustup component add rust-src;
    # fi
    # xargo build $CROSS_COMPILE_TARGET --release ;

    # build $BIN_NAME
    # cargo clean; 
    if [ $ENABLE_CROSS_COMPILE -ne 0 ]; then
        cross build $CROSS_COMPILE_TARGET --release --features system-alloc ;
    else
        env PKG_CONFIG_ALL_STATIC=1 cargo build --release $CROSS_COMPILE_TARGET;
    fi

    if [ $? -ne 0 ]; then
        echo -e "\033[31mBuild $BIN_NAME with ${CROSS_COMPILE_DIR} failed.\033[0m";
        return;
    fi

    cd "$SCRIPT_DIR";
    cp -f target/${CROSS_COMPILE_DIR}/release/${BIN_NAME} ./${BIN_NAME}-${CROSS_COMPILE_DIR} ;

    which strip > /dev/null 2>&1 ;
    if [ 0 -eq $? ]; then
        echo "Try to strip executable file";
        strip ./${BIN_NAME}-${CROSS_COMPILE_DIR};
        if [ $? -ne 0 ]; then
            echo -e "\033[33mStrip ${BIN_NAME}-${CROSS_COMPILE_DIR} failed.\033[0m";
        fi
    fi

    which upx > /dev/null 2>&1 ;
    if [ 0 -eq $? ]; then
        echo "Try to upx executable file";
        if [ -e "./${BIN_NAME}-${CROSS_COMPILE_DIR}.min" ]; then
            rm -f "./${BIN_NAME}-${CROSS_COMPILE_DIR}.min";
        fi
        upx --ultra-brute -o ./${BIN_NAME}-${CROSS_COMPILE_DIR}.min ./${BIN_NAME}-${CROSS_COMPILE_DIR};
        if [ $? -ne 0 ]; then
            echo -e "\033[33mZip exe file ${BIN_NAME}-${CROSS_COMPILE_DIR} failed.\033[0m";
        fi
    fi

    echo -e "\033[32mBuild ${BIN_NAME}-${CROSS_COMPILE_DIR} done.\033[0m";
}

which xargo > /dev/null;
if [ $? -ne 0 ]; then
    cargo install xargo;
fi

which cross > /dev/null;
if [ $? -ne 0 ]; then
    # sudo pacman -S -s docker docker-compose
    # sudo apt install docker docker-compose
    # sudo yum install docker
    # sudo dnf install docker docker-compose
    cargo install cross;
fi

for COMPILE_OPTIONS in "${BUILD_TARGETS[@]}"; do
    build_for_arch $COMPILE_OPTIONS;
done