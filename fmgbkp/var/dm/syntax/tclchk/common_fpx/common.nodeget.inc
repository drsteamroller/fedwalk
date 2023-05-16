nodeget %{
	"system replacemsg-image image-base64" = %{
if { $CLI_GET_ND } {
	return 0
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
	"system resource-limits" = %{
if { $CLI_GET_TO } {
	if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
		return 1
	}
	return 0
}
	%}
        "system alarm" = %{
if { $CLI_GET_TO } {
        if { [cli_get_devinfo "FIPS"] eq "yes" } {
                return 1
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
	"log {syslogd syslogd2 syslogd3 syslogd4 webtrends memory disk fortiguard null-device fortianalyzer fortianalyzer2 fortianalyzer3} filter exclude-list" = %{
if { $CLI_GET_TO } {
        if { [cli_get_devinfo "FIPS"] eq "yes" } {
                return 1
        }
        return 0
}
	%}
	"log {syslogd fortiguard fortianalyzer} override-filter exclude-list" = %{
if { $CLI_GET_TO } {
        if { [cli_get_devinfo "FIPS"] eq "yes" } {
                return 1
        }
        return 0
}
	%}
	"application custom category" = %{
if { $CLI_GET_TD } {
	return 0
}
	%}
	"dnsfilter profile ftgd-dns filters category" = %{
if { $CLI_GET_TD } {
	return 0
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
	"system dhcp server lease-time" = %{
if { $CLI_GET_TT } {
	return "8640000,0"
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
	if { [cli_get_devinfo "is_logdisk_mounted"] eq "yes" } {
		return "disk"
	}
	return "NULL"
}
	%}
	"log memory filter local-traffic" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_get_devinfo "is_logdisk_mounted"] eq "yes" } {
		return "enable"
	}
	return "disable"
}
	%}

	"log memory filter severity" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { ![cli_ver_start 600 4] } {
		if { [cli_get_devinfo "is_logdisk_mounted"] eq "yes" } {
			return "information"
		}
		return "warning"
	}
	return $CLI_CUR_VALUE
}
	%}
%};
