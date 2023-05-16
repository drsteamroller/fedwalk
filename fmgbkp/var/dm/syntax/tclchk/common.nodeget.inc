nodeget %{
	"wireless-controller vap local-authentication" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		namespace import global::is_wlan_local_st_skip
		set opts $CLI_CUR_VALUE
		if { ![is_wlan_local_st_skip $CLI_CUR_PARENT_NODE] } {
			set local_st [cli_get_value $CLI_CUR_PARENT_NODE "" "" "local-standalone"]
			if { $local_st eq "enable" } {
				set opts [cli_update_opts 0 $opts "disable"]
			}
		}
		return $opts
	}
}
	%}
	"wireless-controller wtp" = %{
if { $CLI_GET_TM } {
	if { $CLI_GLOBAL_DEV } { return }
	if { [scan $CLI_CUR_VALUE "%lu,%lu,%lu" g v t] ne 3 } {
		return
	}
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "Fortigate-80E"] ||
		[string match -nocase $platform "Fortigate-80E-POE"] ||
		[string match -nocase $platform "Fortigate-80F"] ||
		[string match -nocase $platform "Fortigate-80F-BYPASS"] ||
		[string match -nocase $platform "Fortigate-81E"] ||
		[string match -nocase $platform "Fortigate-81E-POE"] ||
		[string match -nocase $platform "Fortigate-81F"] ||
		[string match -nocase $platform "Fortigate-90E"] ||
		[string match -nocase $platform "Fortigate-91E"] } {
		if { ($v > 0) && ($v < 96) } {
			set v 96
		}
	}
	if { $v > 0 && [cli_has_feature "a_fwf"] && [cli_has_feature "f_wireless_ac"] } {
		set v [expr ($v + 1)]
	}
	return [format "%lu,%lu,%lu" $g $v $t]
}
	%}
	"wireless-controller wtp-profile radio-2 mode" = %{
if { $CLI_GET_TD && $CLI_GLOBAL_DEV } {
	return "ap"
}
	%}
    "wireless-controller timers client-idle-timeout" = %{
if { $CLI_GET_TT } {
	return "3600,0"
}
	%}
        "vpn ssl web portal os-check-list latest-patch-level" = %{
if { $CLI_GET_TD } {
        if { $CLI_SUPPORT_CDB_OPS } {
                cli_skip_cache
                set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
                if { $name eq "windows-2000" } {
                        return "4"
                } elseif { $name eq "windows-xp" } {
                        return "3"
                } elseif { $name eq "windows-vista" } {
                        return "2"
                } elseif { $name eq "windows-7" } {
                        return "0"
                } else {
                        return "0"
                }
        }
}
        %}
	"antivirus quarfilepattern" = %{
if { $CLI_GET_TO } {
	set g [cli_get_devinfo "get_log_disk_info"]
	if { $g eq "NA" } {
		set g [cli_get_devinfo "hdd"]
	}
	if { $g ne "NA" } {
		if { $g eq "no" } {
			return 0
		}
	}
}
	%}
	"system resource-limits" = %{
if { $CLI_GET_TO } {
	if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
		return $CLI_CUR_VALUE
	}
	return 0
}
	%}
        "system alarm" = %{
if { $CLI_GET_TO } {
        if { [cli_get_devinfo "FIPS"] eq "yes" } {
                return $CLI_CUR_VALUE
        }
        return 0
}
        %}
        "antivirus settings default-db" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
        if { [cli_get_devinfo "VM"] ne "yes" } { return }
        set opts $CLI_CUR_VALUE
	set exist 0
        foreach opt $opts {
                if { $opt eq "extreme" } {
			set exist 1
			break
                }
	}
	if { $exist ne 1 } {
		append opts " extreme"
	}
        return $opts
}
        %}
        "system vdom-property" = %{
if { $CLI_GET_TM } {
	if { $CLI_GLOBAL_DEV } { return }
	if { [scan $CLI_CUR_VALUE "%lu,%lu,%lu" g v t] ne 3 } {
		return
	}
	set ng [cli_feature_value "max_vdom_num"]
	if { $ng eq 0 || $ng eq "" } {
		return
	}
	return [format "%lu,%lu,%lu" $ng $v $t]
}
        %}
	"log {syslogd syslogd2 syslogd3 syslogd4 webtrends memory disk fortiguard null-device fortianalyzer fortianalyzer2 fortianalyzer3} filter exclude-list" = %{
if { $CLI_GET_TO } {
        if { [cli_get_devinfo "FIPS"] eq "yes" } {
                return $CLI_CUR_VALUE
        }
        return 0
}
	%}
	"log {syslogd fortiguard fortianalyzer} override-filter exclude-list" = %{
if { $CLI_GET_TO } {
        if { [cli_get_devinfo "FIPS"] eq "yes" } {
                return $CLI_CUR_VALUE
        }
        return 0
}
	%}
        "router multicast interface hello-holdtime" = %{
if { $CLI_GET_TD } {
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		set interval [cli_get_value $CLI_CUR_PARENT_NODE "" "" "hello-interval"]
		if { $interval ne "" } {
			set maxsize [cli_get_objlimit 0 "router multicast interface" "hello-holdtime"]
			set hold [expr int($interval * 3.5)]
			if {$maxsize > 0 && $hold > $maxsize} {
				set hold $maxsize
			}
			return $hold
		}
	}
}
        %}
        "alertemail setting {local-disk-usage log-disk-usage-warning}" = %{
if { $CLI_GET_TO } {
        if { $CLI_GLOBAL_DEV } { return }
        set g [cli_get_devinfo "get_log_disk_info"]
        if { $g eq "NA" } {
                set g [cli_get_devinfo "hdd"]
        }
        if { $g ne "NA" } {
                if { $g eq "no" } {
                        return 0
                }
        }
}
        %}
        "wireless-controller wtp-profile handoff-sta-thresh" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 200] } {
		cli_skip_cache
		namespace import global::wtp_profile_platform
		set plat [wtp_profile_platform $CLI_CUR_PARENT_NODE]
		set ho_sta_max [cli_get_devinfo "pm2_wl_handoff_sta_max" $plat]
		if { $ho_sta_max > 0 } {
			return [expr {$ho_sta_max - 5}]
		}
		return 0
	}
	return 30
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 200] && ![cli_branchpt_start 700 1235] } {
		return "4294967295,0"
	} elseif { ![cli_branchpt_start 600 200] } {
		return "35,5"
	}
}
if { $CLI_GET_ND } {
	if { [cli_branchpt_start 600 200] } {
		return 1
	}
	return 0
}
	%}
	"system dhcp server lease-time" = %{
if { $CLI_GET_TT } {
	return "8640000,0"
}
	%}
	"wireless-controller qos-profile dscp-wmm-vo" = %{
if { [cli_ver_start 700 0] } {
	return $CLI_CUR_VALUE
}
if { $CLI_GET_TD } {
	return "48 56"
}
	%}
	"wireless-controller qos-profile dscp-wmm-vi" = %{
if { [cli_ver_start 700 0] } {
	return $CLI_CUR_VALUE
}
if { $CLI_GET_TD } {
	return "32 40"
}
	%}
	"wireless-controller qos-profile dscp-wmm-be" = %{
if { [cli_ver_start 700 0] } {
	return $CLI_CUR_VALUE
}
if { $CLI_GET_TD } {
	return "0 24"
}
	%}
	"wireless-controller qos-profile dscp-wmm-bk" = %{
if { [cli_ver_start 700 0] } {
	return $CLI_CUR_VALUE
}
if { $CLI_GET_TD } {
	return "8 16"
}
	%}
	"web-proxy explicit {https-incoming-port pac-file-server-port}" = %{
if { $CLI_GET_TD } {
	return "0"
}
	%}
	"antivirus quarantine destination" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	set g [cli_get_devinfo "get_log_disk_info"]
	if { $g eq "NA" } {
		set g [cli_get_devinfo "hdd"]
	}
	if { $g ne "NA" } {
		if { $g eq "no" } {
			return "NULL"
		}
	}
	return "disk"
}
	%}
	"log memory filter local-traffic" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	set g [cli_get_devinfo "get_log_disk_info"]
	if { $g eq "NA" } {
		set g [cli_get_devinfo "hdd"]
	}
	if { $g ne "NA" } {
		if { $g eq "no" } {
			return "disable"
		}
	}
	return "enable"
}
	%}
	"log memory filter severity" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { ![cli_ver_start 600 4] } {
		set g [cli_get_devinfo "get_log_disk_info"]
		if { $g eq "NA" } {
			set g [cli_get_devinfo "hdd"]
		}
		if { $g ne "NA" } {
			if { $g eq "no" } {
				return "warning"
			}
		}
		return "information"
	}
	return $CLI_CUR_VALUE
}
	%}
	"system fortiguard auto-join-forticloud" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 131] } {
		if { [cli_get_devinfo "VM"] eq "yes" } {
			return $CLI_CUR_VALUE
		}
		namespace import global::platform_digit_start
		if { ![platform_digit_start $platform "1000" ] } {
			return $CLI_CUR_VALUE
		}
	}
	return 0
}
	%}
	"ips global" = %{
if { $CLI_GLOBAL_DEV } {
	if { $CLI_GET_TO } {
		set products [cli_get_devinfo "adom_restricted_prds"]
		if { [string match -nocase "FortiFirewall*" $products] } {
			return 0
		}
	}
	return
}
if { $CLI_GET_TO } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase "FortiFirewall*" $platform] } {
		return 0
	}
}
	%}
	"system settings policy-offload-level" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_ver_start 700 0] && ![cli_branchpt_start 700 352] } {
		return 0
	} elseif { [cli_ver_start 600 0] && ![cli_branchpt_start 600 2014] } {
		return 0
	}
	return $CLI_CUR_VALUE
}
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	namespace import global::is_platform_support_hyperscale
	if { [is_platform_support_hyperscale] } {
		set hyperscale [cli_get_devinfo "hyperscale"]
		if { $hyperscale eq "yes" } {
			set opts [cli_update_opts 1 $opts "full-offload"]
		} else {
			set opts [cli_update_opts 0 $opts "full-offload"]
		}
	}
	return $opts
}
	%}
	"system global {switch-controller fortiextender}" = %{
if { $CLI_GET_TN } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wireless-controller"] eq "disable" } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "enable"]
	}
}
	%}
	"system npu {policy-offload-level}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	namespace import global::is_platform_support_hyperscale
	if { [is_platform_support_hyperscale] } {
		set hyperscale [cli_get_devinfo "hyperscale"]
		if { $hyperscale eq "yes" } {
			return "full-offload"
		}
	}
	return $CLI_CUR_VALUE
}
if { $CLI_GET_TO } {
	if { [cli_ver_start 700 0] && ![cli_branchpt_start 700 352] } {
		return 0
	}
	if { [cli_ver_start 600 0] && ![cli_branchpt_start 600 2014] } {
		return 0
	}
}
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	namespace import global::is_platform_support_hyperscale
	if { [is_platform_support_hyperscale] } {
		set hyperscale [cli_get_devinfo "hyperscale"]
		if { $hyperscale eq "yes" } {
			set opts [cli_update_opts 1 $opts "full-offload"]
		} else {
			set opts [cli_update_opts 0 $opts "full-offload"]
		}
	}
	return $opts
}
	%}
	"log {fortiguard fortianalyzer} {setting override-setting} upload-option" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set g [cli_get_devinfo "get_log_disk_info"]
	if { $g eq "NA" } {
		set g [cli_get_devinfo "hdd"]
	}
	if { $g ne "NA" } {
		if { $g eq "no" } {
			return [cli_update_opts 0 $CLI_CUR_VALUE "store-and-upload"]
		}
	}
}
	%}
	"log {fortianalyzer2 fortianalyzer3 fortianalyzer-cloud} setting upload-option" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set g [cli_get_devinfo "get_log_disk_info"]
	if { $g eq "NA" } {
		set g [cli_get_devinfo "hdd"]
	}
	if { $g ne "NA" } {
		if { $g eq "no" } {
			return [cli_update_opts 0 $CLI_CUR_VALUE "store-and-upload"]
		}
	}
}
	%}
	"firewall {policy policy6 proxy-policy profile-group} {profile-protocol-options ssl-ssh-profile}" = %{
if { $CLI_GLOBAL_DEV } {
	if { $CLI_GET_TO } {
		set products [cli_get_devinfo "adom_restricted_prds"]
		if { [string match -nocase "FortiFirewall*" $products] } {
			return 0
		}
	}
	return
}
if { $CLI_GET_TO } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase "FortiFirewall*" $platform] } {
		return 0
	}
}
	%}
%};
