nvme_rpc_path=/var/lib/zbs/aurorad/aurorad-rpc.sock
init() {
    sleep 3
    /root/spdk/scripts/rpc.py -s $nvme_rpc_path construct_malloc_bdev 128 4096 -b Malloc0
    /root/spdk/scripts/rpc.py -s $nvme_rpc_path construct_vhost_blk_controller vhost-blk.0 Malloc0
}
init &
/root/spdk/build/bin/spdk_tgt -r $nvme_rpc_path -m 0x1 -s 100 -S /var/lib/zbs/aurorad/ -L vhost -L vhost_blk -L vhost_blk_data -L vhost_ring

# sleep 3
# build/bin/fio examples/vhost-randread-4k.fio
