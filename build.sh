export ASAN_OPTIONS=disable_coredump=0:unmap_shadow_on_exit=1:fast_unwind_on_malloc=0;
type=${TYPE:-asan}
[ $type = "asan" ] && type=asan
[ $type = "ubsan" ] && type=UBSan
[ $type = "rel" ] && type=RelWithDebInfo
[ $type = "debug" ] && type=Debug
cmake -B build -GNinja -DCMAKE_BUILD_TYPE=$type -DCMAKE_INSTALL_PREFIX=build

# Usage: main -p <socket_path> [-s] [-t <target>] [-h]
ninja -C build -v && build/examples/vhost_test -p /var/lib/zbs/aurorad/vhost-blk.0
# for vhost-scsi
# ninja -C build -v && build/examples/vhost_test -p /var/lib/zbs/aurorad/vhost-blk.0 -s -t 0

# ninja -C build install -v
#cd build; cpack3
#cd -
