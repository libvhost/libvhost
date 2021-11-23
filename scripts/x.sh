  zbs-iscsi target create fl-iscsi
  zbs-iscsi lun create fl-iscsi 1 2
  zbs-procurator bdev bdev_zbs_create fuck#fl-iscsi#1
  zbs-procurator controller create foo-vhost-blk.0  fuck#fl-iscsi#1
