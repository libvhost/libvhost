nvme_rpc_path=/var/lib/zbs/aurorad/aurorad-rpc.sock
init() {
    sleep 3
    /root/spdk/scripts/rpc.py -s $nvme_rpc_path construct_malloc_bdev 128 4096 -b Malloc0
    /root/spdk/scripts/rpc.py -s $nvme_rpc_path nvmf_subsystem_create nqn.2018-11.io.spdk:nqn-0 -a
    /root/spdk/scripts/rpc.py -s $nvme_rpc_path nvmf_subsystem_add_ns nqn.2018-11.io.spdk:nqn-0 Malloc0
    /root/spdk/scripts/rpc.py -s $nvme_rpc_path nvmf_create_transport -t TCP -u 16384 -p 8 -c 8192
    /root/spdk/scripts/rpc.py -s $nvme_rpc_path nvmf_subsystem_add_listener nqn.2018-11.io.spdk:nqn-0 -t tcp -a 0.0.0.0 -s 4420
}
init &
/root/spdk/build/bin/spdk_tgt -r $nvme_rpc_path -m 0x1 -s 100 -S /var/lib/zbs/aurorad/ -L vhost -L vhost_blk -L vhost_blk_data -L vhost_ring
