#!/bin/bash

# required: sudo apt install musl-tools libssl-dev ca-certificates curl git wget ;

cd "$(dirname $0)";

SCRIPT_DIR="$PWD";
BIN_NAME="wxwork_robotd";

# sed -i.bak 's/\#error.*getprogname.*/return program_invocation_short_name;/' /data/workspace/wxwork_robotd/target/libressl-2.9.2/crypto/compat/getprogname_linux.c

BUILD_TARGETS=(
    "USING_MUSL_TOOLCHAIN=0 ENABLE_CROSS_COMPILE=1 USING_SYSTEM_ALLOC=0 TARGET_ARCH=x86_64-unknown-linux-musl"
    # "USING_MUSL_TOOLCHAIN=0 ENABLE_CROSS_COMPILE=1 USING_SYSTEM_ALLOC=1 TARGET_ARCH=aarch64-unknown-linux-musl"
    # "USING_MUSL_TOOLCHAIN=0 ENABLE_CROSS_COMPILE=1 USING_SYSTEM_ALLOC=1 TARGET_ARCH=armv7-unknown-linux-musleabihf"
    # "USING_MUSL_TOOLCHAIN=0 ENABLE_CROSS_COMPILE=1 USING_SYSTEM_ALLOC=0 TARGET_ARCH=i686-unknown-linux-musl"
    # "USING_MUSL_TOOLCHAIN=0 ENABLE_CROSS_COMPILE=1 USING_SYSTEM_ALLOC=0 TARGET_ARCH=mips-unknown-linux-musl"
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

function get_libressl_pkg() {
    if [ ! -e "$SCRIPT_DIR/target/libressl/$LIBRESSL_PKG" ]; then
        wget -c --no-check-certificate $LIBRESSL_URL -O "$SCRIPT_DIR/target/libressl/$LIBRESSL_PKG";
    fi
}

function build_musl_libressl() {
    TARGET_ARCH="$1";
    LIBRESSL_PREBUILT_DIR="$SCRIPT_DIR/target/libressl/$TARGET_ARCH";
    if [ ! -e "$LIBRESSL_PREBUILT_DIR" ]; then
        mkdir -p "$SCRIPT_DIR/target/libressl";
        get_libressl_pkg;
        cd "$SCRIPT_DIR/target/libressl";
        tar -axvf $LIBRESSL_PKG;
        cd ${LIBRESSL_PKG//.tar.*};
        mkdir -p build_jobs_dir && cd build_jobs_dir;
        sed -i.bak 's/\#error.*getprogname.*/return program_invocation_short_name;/' ../crypto/compat/getprogname_linux.c ;
        env CC=musl-gcc cmake .. "-DCMAKE_INSTALL_PREFIX=$LIBRESSL_PREBUILT_DIR" ${LIBRESSL_CMAKE_ARGS[@]} -DCMAKE_C_COMPILER=musl-gcc ;
        cmake --build . -- install -j8;

        if [ 0 -ne $? ]; then
            echo -e "\033[1;31mWe require cross-gcc-dev, musl, musl-dev, musl-tools to do this.\033[0m";
        fi
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
    CROSS_COMPILE_TARGET="--target=$CROSS_COMPILE_DIR";

    if [ -z "$ENABLE_CROSS_COMPILE" ]; then
        ENABLE_CROSS_COMPILE=0;
    fi

    if [ -z "$USING_MUSL_TOOLCHAIN" ]; then
        USING_MUSL_TOOLCHAIN=0;
    fi

    echo "ENABLE_CROSS_COMPILE=$ENABLE_CROSS_COMPILE";

    if [ $USING_MUSL_TOOLCHAIN -eq 0 ] && [ $ENABLE_CROSS_COMPILE -ne 0 ]; then
        which xargo > /dev/null;
        if [ $? -ne 0 ]; then
            cargo install xargo;
        fi

        which cross > /dev/null;
        if [ $? -ne 0 ]; then

            cargo install cross;
            if [ 0 -ne $? ]; then
                echo -e "\033[1;31mTry to install cross by 'cargo install cross' failed.";
                echo "Please try to use these command to install docker first(depend on your system):
    sudo pacman -S -s docker docker-compose
    sudo apt install docker docker-compose
    sudo yum install docker
    sudo dnf install docker docker-compose
                
    See https://github.com/rust-embedded/cross for detail.";
            fi
        fi
    fi

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
    if [ ! -z "$TARGET_ARCH" ] && [ "$TARGET_ARCH" != "0" ]; then
        BUILD_WITH_SYSTEM_ALLOC=" --features system-alloc";
    fi
    if [ $USING_MUSL_TOOLCHAIN -ne 0 ]; then
        cargo build --release $CROSS_COMPILE_TARGET $BUILD_WITH_SYSTEM_ALLOC ;
    elif [ $ENABLE_CROSS_COMPILE -ne 0 ]; then
        cross build $CROSS_COMPILE_TARGET --release $BUILD_WITH_SYSTEM_ALLOC ;
    else
        cargo build --release $CROSS_COMPILE_TARGET $BUILD_WITH_SYSTEM_ALLOC;
    fi

    if [ $? -ne 0 ]; then
        echo -e "\033[31mBuild $BIN_NAME with ${CROSS_COMPILE_DIR} failed.\033[0m";
        return;
    fi

    cd "$SCRIPT_DIR";
    if [ -e target/${CROSS_COMPILE_DIR}/release/etc ]; then
        rm -rf target/${CROSS_COMPILE_DIR}/release/etc;
    fi
    cp -rf etc target/${CROSS_COMPILE_DIR}/release/;
    cd target/${CROSS_COMPILE_DIR}/release/;
    mkdir -p bin;
    cp -f ${BIN_NAME} bin/;

    which strip > /dev/null 2>&1 ;
    if [ 0 -eq $? ]; then
        echo "Try to strip executable file";
        strip bin/${BIN_NAME};
        if [ $? -ne 0 ]; then
            echo -e "\033[33mStrip ${BIN_NAME} for ${CROSS_COMPILE_DIR} failed.\033[0m";
        fi
    fi

    # which upx > /dev/null 2>&1 ;
    # if [ 0 -eq $? ]; then
    #     echo "Try to upx executable file";
    #     if [ -e "./${BIN_NAME}-${CROSS_COMPILE_DIR}.min" ]; then
    #         rm -f "./${BIN_NAME}-${CROSS_COMPILE_DIR}.min";
    #     fi
    #     upx --ultra-brute -o ./${BIN_NAME}-${CROSS_COMPILE_DIR}.min ./${BIN_NAME}-${CROSS_COMPILE_DIR};
    #     if [ $? -ne 0 ]; then
    #         echo -e "\033[33mZip exe file ${BIN_NAME}-${CROSS_COMPILE_DIR} failed.\033[0m";
    #     fi
    # fi

    tar -Jcvf ${BIN_NAME}-${CROSS_COMPILE_DIR}.tar.xz etc bin;
    cd "$SCRIPT_DIR";
    mv -f target/${CROSS_COMPILE_DIR}/release/${BIN_NAME}-${CROSS_COMPILE_DIR}.tar.xz ./;
    echo -e "\033[32mBuild ${BIN_NAME}-${CROSS_COMPILE_DIR} done.\033[0m";
}

for COMPILE_OPTIONS in "${BUILD_TARGETS[@]}"; do
    build_for_arch $COMPILE_OPTIONS;
done
