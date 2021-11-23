 TYPE=rel ./build.sh
 /bin/rm -rf /dev/hugepages/libvhost.*
#LD_PRELOAD=/root/libvfio/build/lib/libvhost_fio_plugin.so /root/fio-master/fio examples/randread-256k.fio
./build/bin/fio examples/vhost-randread-4k.fio
