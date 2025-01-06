
# TODO
- [x] 大页内存退出时不释放
- [ ] virtio
    - [x] indirect desc support
    - [ ] packed ring support
    - [ ] interrupt io(eventfd) support
- [ ] kernel vhost-scsi support
- [ ] 超过文件范围的 IO 确认失败
- [x] 获取后端设备的 block size 和 长度
- [ ] 检测后端设备是 vhost-blk 或者 vhost-scsi
- [x] 支持 vhost-user-scsi
- [x] 支持后端重启后重连
- [ ] 重写内存分配器

