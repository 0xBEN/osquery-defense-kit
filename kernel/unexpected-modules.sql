SELECT *
FROM kernel_modules
WHERE name NOT IN (
        '8021q',
        'ac97_bus',
        'acpi_cpufreq',
        'acpi_pad',
        'acpi_tad',
        'acpi_thermal_rel',
        'aesni_intel',
        'af_alg',
        'af_packet',
        'agpgart',
        'ahci',
        'algif_aead',
        'algif_hash',
        'algif_skcipher',
        'amd_pmc',
        'amdgpu',
        'apple_mfi_fastcharge',
        'asn1_encoder',
        'asus_wmi',
        'atkbd',
        'authenc',
        'autofs4',
        'backlight',
        'battery',
        'binfmt_misc',
        'bluetooth',
        'bnep',
        'bpf_preload',
        'br_netfilter',
        'bridge',
        'btbcm',
        'btintel',
        'btmtk',
        'btrtl',
        'btusb',
        'button',
        'cbc',
        'ccm',
        'ccp',
        'cdc_ether',
        'cec',
        'cfg80211',
        'cmac',
        'configfs',
        'coretemp',
        'cqhci',
        'crc_t10dif',
        'crc16',
        'crc32_pclmul',
        'crc32c_generic',
        'crc32c_intel',
        'crct10dif_common',
        'crct10dif_generic',
        'crct10dif_pclmul',
        'cros_ec_chardev',
        'cros_ec_debugfs',
        'cros_ec_dev',
        'cros_ec_lpcs',
        'cros_ec_sysfs',
        'cros_ec',
        'cros_usbpd_charger',
        'cros_usbpd_logger',
        'cros_usbpd_notify',
        'cryptd',
        'crypto_simd',
        'crypto_user',
        'dca',
        'deflate',
        'des_generic',
        'dm_crypt',
        'dm_mod',
        'dm_multipath',
        'drm_buddy',
        'drm_display_helper',
        'drm_dp_helper',
        'drm_kms_helper',
        'drm_ttm_helper',
        'drm',
        'ecb',
        'ecc',
        'ecdh_generic',
        'edac_core',
        'edac_mce_amd',
        'ee1004',
        'eeepc_wmi',
        'efi_pstore',
        'efivarfs',
        'encrypted_keys',
        'essiv',
        'evdev',
        'ext4',
        'fat',
        'fb_sys_fops',
        'firmware_attributes_class',
        'fuse',
        'ghash_clmulni_intel',
        'gigabyte_wmi',
        'gpio_amdpt',
        'gpio_generic',
        'gpu_sched',
        'hid_apple',
        'hid_generic',
        'hid_jabra',
        'hid_logitech_dj',
        'hid_logitech_hidpp',
        'hid_multitouch',
        'hid_sensor_als',
        'hid_sensor_custom',
        'hid_sensor_hub',
        'hid_sensor_iio_common',
        'hid_sensor_trigger',
        'hid',
        'i2c_algo_bit',
        'i2c_core',
        'i2c_designware_core',
        'i2c_designware_platform',
        'i2c_hid_acpi',
        'i2c_hid',
        'i2c_i801',
        'i2c_piix4',
        'i2c_scmi',
        'i2c_smbus',
        'i8042',
        'i915',
        'icp',
        'idma64',
        'igb',
        'igc',
        'igen6_edac',
        'industrialio_triggered_buffer',
        'industrialio',
        'input_leds',
        'int3400_thermal',
        'int3403_thermal',
        'int340x_thermal_zone',
        'intel_cstate',
        'intel_gtt',
        'intel_ish_ipc',
        'intel_ishtp_hid',
        'intel_ishtp',
        'intel_lpss_pci',
        'intel_lpss',
        'intel_pmc_bxt',
        'intel_powerclamp',
        'intel_rapl_common',
        'intel_rapl_msr',
        'intel_soc_dts_iosf',
        'intel_tcc_cooling',
        'intel_uncore',
        'intel_vsec',
        'iommu_v2',
        'ip_set',
        'ip_tables',
        'ip_vs_rr',
        'ip_vs_sh',
        'ip_vs_wrr',
        'ip_vs',
        'ip6_tables',
        'ip6t_REJECT',
        'ip6t_rpfilter',
        'ip6t_rt',
        'ip6table_nat',
        'ipmi_devintf',
        'ipmi_msghandler',
        'ipt_REJECT',
        'ipt_rpfilter',
        'iptable_filter',
        'iptable_nat',
        'irqbypass',
        'iTCO_vendor_support',
        'iTCO_wdt',
        'iwlmei',
        'iwlmvm',
        'iwlwifi',
        'jbd2',
        'joydev',
        'k10temp',
        'kfifo_buf',
        'kvm_amd',
        'kvm_intel',
        'kvm',
        'led_class',
        'ledtrig_audio',
        'libaes',
        'libahci',
        'libarc4',
        'libata',
        'libcrc32c',
        'libdes',
        'libps2',
        'llc',
        'loop',
        'lp',
        'mac_hid',
        'mac80211',
        'macvlan',
        'mbcache',
        'mc',
        'md4',
        'mei_hdcp',
        'mei_me',
        'mei_pxp',
        'mei_wdt',
        'mei',
        'mii',
        'mmc_core',
        'mousedev',
        'msr',
        'mtd',
        'mxm_wmi',
        'nf_conntrack_broadcast',
        'nf_conntrack_netbios_ns',
        'nf_conntrack_netlink',
        'nf_conntrack',
        'nf_defrag_ipv4',
        'nf_defrag_ipv6',
        'nf_log_syslog',
        'nf_nat',
        'nf_reject_ipv4',
        'nf_reject_ipv6',
        'nf_tables',
        'nfnetlink',
        'nft_chain_nat',
        'nft_compat',
        'nft_counter',
        'nft_ct',
        'nft_fib_inet',
        'nft_fib_ipv4',
        'nft_fib_ipv6',
        'nft_fib',
        'nft_limit',
        'nft_objref',
        'nft_reject_inet',
        'nft_reject',
        'nls_cp437',
        'nls_iso8859_1',
        'nvidia_drm',
        'nvidia_modeset',
        'nvidia_uvm',
        'nvidia',
        'nvme_core',
        'nvme',
        'nvram',
        'overlay',
        'parport_pc',
        'parport',
        'pcspkr',
        'pinctrl_amd',
        'pinctrl_tigerlake',
        'pkcs8_key_parser',
        'platform_profile',
        'pmt_class',
        'pmt_telemetry',
        'ppdev',
        'pps_core',
        'processor_thermal_device_pci_legacy',
        'processor_thermal_device',
        'processor_thermal_mbox',
        'processor_thermal_rapl',
        'processor_thermal_rfim',
        'psmouse',
        'pstore_blk',
        'pstore_zone',
        'pstore',
        'ptp',
        'qrtr',
        'r8152',
        'r8153_ecm',
        'r8169',
        'ramoops',
        'rapl',
        'raydium_i2c_ts',
        'rc_core',
        'reed_solomon',
        'rfcomm',
        'rfkill',
        'rndis_host',
        'rndis_wlan',
        'rng_core',
        'roles',
        'rtc_cmos',
        'rtsx_pci_sdmmc',
        'rtsx_pci',
        'rtw89_8852a',
        'rtw89_8852ae',
        'rtw89_core',
        'rtw89_pci',
        'sch_fq_codel',
        'scsi_common',
        'scsi_mod',
        'sdhci_pci',
        'sdhci',
        'serio_raw',
        'serio',
        'sg',
        'snd_acp_config',
        'snd_acp3x_pdm_dma',
        'snd_acp3x_rn',
        'snd_compress',
        'snd_ctl_led',
        'snd_hda_codec_generic',
        'snd_hda_codec_hdmi',
        'snd_hda_codec_idt',
        'snd_hda_codec_realtek',
        'snd_hda_codec',
        'snd_hda_core',
        'snd_hda_ext_core',
        'snd_hda_intel',
        'snd_hrtimer',
        'snd_hwdep',
        'snd_intel_dspcfg',
        'snd_intel_sdw_acpi',
        'snd_pci_acp3x',
        'snd_pci_acp5x',
        'snd_pci_acp6x',
        'snd_pcm_dmaengine',
        'snd_pcm',
        'snd_rawmidi',
        'snd_rn_pci_acp3x',
        'snd_seq_device',
        'snd_seq_dummy',
        'snd_seq_midi_event',
        'snd_seq_midi',
        'snd_seq',
        'snd_soc_acpi_intel_match',
        'snd_soc_acpi',
        'snd_soc_core',
        'snd_soc_dmic',
        'snd_soc_hdac_hda',
        'snd_soc_hdac_hdmi',
        'snd_soc_intel_hda_dsp_common',
        'snd_soc_skl_hda_dsp',
        'snd_sof_amd_acp',
        'snd_sof_amd_renoir',
        'snd_sof_intel_hda_common',
        'snd_sof_intel_hda',
        'snd_sof_pci_intel_tgl',
        'snd_sof_pci',
        'snd_sof_utils',
        'snd_sof_xtensa_dsp',
        'snd_sof',
        'snd_timer',
        'snd_usb_audio',
        'snd_usbmidi_lib',
        'snd',
        'soundcore',
        'soundwire_bus',
        'soundwire_cadence',
        'soundwire_generic_allocation',
        'soundwire_intel',
        'sp5100_tco',
        'sparse_keymap',
        'spi_intel_pci',
        'spi_intel',
        'spi_nor',
        'spl',
        'squashfs',
        'stp',
        'sunrpc',
        'syscopyarea',
        'sysfillrect',
        'sysimgblt',
        't10_pi',
        'tap',
        'tee',
        'think_lmi',
        'thinkpad_acpi',
        'thunderbolt',
        'tiny_power_button',
        'tls',
        'tpm_crb',
        'tpm_tis_core',
        'tpm_tis',
        'tpm',
        'trusted',
        'ttm',
        'tun',
        'typec_ucsi',
        'typec',
        'uas',
        'ucsi_acpi',
        'uinput',
        'usb_common',
        'usb_storage',
        'usbcore',
        'usbhid',
        'usbnet',
        'uvcvideo',
        'veth',
        'vfat',
        'video',
        'videobuf2_common',
        'videobuf2_memops',
        'videobuf2_v4l2',
        'videobuf2_vmalloc',
        'videodev',
        'vivaldi_fmap',
        'watchdog',
        'wmi_bmof',
        'wmi',
        'x_tables',
        'x86_pkg_temp_thermal',
        'xfrm_algo',
        'xfrm_user',
        'xhci_hcd',
        'xhci_pci_renesas',
        'xhci_pci',
        'xt_addrtype',
        'xt_comment',
        'xt_conntrack',
        'xt_hl',
        'xt_limit',
        'xt_LOG',
        'xt_mark',
        'xt_MASQUERADE',
        'xt_nat',
        'xt_pkttype',
        'xt_statistic',
        'xt_tcpudp',
        'zavl',
        'zcommon',
        'zfs',
        'zlua',
        'znvpair',
        'zram',
        'zunicode',
        'zzstd'
    )