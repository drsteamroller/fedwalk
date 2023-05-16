nodeget %{
	"system npu mcast-session-counting" = %{
if { $CLI_GET_TO } {
	if { $CLI_GLOBAL_DEV } { return }
	if { [cli_branchpt_start 600 1158] } {
		return 0
	}
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiCarrier-6000F"] ||
	     [string match -nocase $platform "FortiCarrier-7000E"] ||
	     [string match -nocase $platform "Fortigate-6000F"] ||
	     [string match -nocase $platform "Fortigate-7000E"] } {
		return 1
	}
	return 0
}
	%}
	"firewall {hyperscale-policy hyperscale-policy64} poolname" = %{
if { $CLI_GET_TM } {
        if { [scan $CLI_CUR_VALUE "%lu,%lu,%lu" g v t] ne 3 } {
                return
        }
        set t 1
        return [format "%lu,%lu,%lu" $g $v $t]
}
	%}
	"firewall policy utm-status" = %{
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
if { $CLI_GET_TD } {
	if { $CLI_IS_RESYNC && $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "learning-mode"] eq "enable" } {
			return "enable"
		}
	}
}
	%}
	"firewall policy6 utm-status" = %{
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
	"firewall {profile-protocol-options proxy-policy proxy-address proxy-addrgrp}" = %{
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
	"wireless-controller utm-profile" = %{
if { $CLI_GLOBAL_DEV } {
	if { $CLI_GET_TO } {
		set products [cli_get_devinfo "adom_restricted_prds"]
		if { [string match -nocase "FortiFirewall*" $products] } {
			return 0
		}
	}
	if { $CLI_GET_RV } {
		if { $CLI_CUR_NODE_NAME eq "wireless-controller vap" && [cli_reserved_value_is "wifi"] } {
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
	"firewall address" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [scan $CLI_CUR_VALUE "%lu,%lu,%lu" g v t] ne 3 } {
		return
	}
	if { [cli_branchpt_start 600 885] } {
		set p [cli_get_devinfo "platform"]
		if { [expr [string match -nocase $p "Fortigate-80E"] || [string match -nocase $p "Fortigate-80E-POE"] || [string match -nocase $p "Fortigate-81E"] || [string match -nocase $p "Fortigate-81E-POE"] || [string match -nocase $p "FortiWiFi-81CM"] || [string match -nocase $p "Fortigate-82C"] || [string match -nocase $p "Fortigate-70D"] || [string match -nocase $p "Fortigate-70D-POE"] || [string match -nocase $p "FortigateRugged-90D"] || [string match -nocase $p "Fortigate-90D"] || [string match -nocase $p "Fortigate-90D-POE"] || [string match -nocase $p "FortiWiFi-90D"] || [string match -nocase $p "FortiWiFi-90D-POE"] || [string match -nocase $p "Fortigate-90E"] || [string match -nocase $p "Fortigate-91E"] || [string match -nocase $p "Fortigate-92D"] || [string match -nocase $p "FortiWiFi-92D"] || [string match -nocase $p "Fortigate-94D-POE"] || [string match -nocase $p "Fortigate-98D-POE"] || [string match -nocase $p "Fortigate-100"] || [string match -nocase $p "Fortigate-100A"]] } {
			set g 10000
			set v 10000
		}
	}
	return [format "%lu,%lu,%lu" $g $v $t]
}
if { $CLI_GET_RV } {
	if { $CLI_GLOBAL_DEV } { return }
	if { [cli_reserved_value_is "metadata-server"] } {
		set platform [cli_get_devinfo "platform"]
		if { ![string match -nocase $platform "FortiCarrier-VM64-AWS"] && ![string match -nocase $platform "Fortigate-VM64-AWS"] && ![string match -nocase $platform "FortiCarrier-VM64-AWSONDEMAND"] && ![string match -nocase $platform "Fortigate-VM64-AWSONDEMAND"] } {
			return 0
		}
	}
}
	%}
	"system global dnsproxy-worker-count" = %{
if { $CLI_GLOBAL_DEV } { return }
set cpu [cli_get_devinfo "cpu_limit"]
if { $cpu eq "0" } { return }
if { $CLI_GET_TT } {
	return "$cpu,1"
}
	%}
	"system global url-filter-count" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $cpu eq "0" } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
set max_cpu_num [cli_get_devinfo "cpu_limit"]
if { $CLI_GET_TT } {
	set cpu [expr (($max_cpu_num +9)/10)]
	if( $cpu > 10 ) {
		set cpu 10
	}
	return "$cpu,1"
}
	%}
	"system global scanunit-count" = %{
if { $CLI_GLOBAL_DEV } { return }
set cpu [cli_get_devinfo "cpu_limit"]
if { $cpu eq "0" } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 920] } {
		return "0"
	}
	set default [expr ($cpu - 1)]
	if { $cpu >= 2 && $default < 2 } {
		set default 2
	}
	return "$default"
}
if { $CLI_GET_TT } {
	return "$cpu,1"
}
	%}
	"system global proxy-worker-count" = %{
if { $CLI_GLOBAL_DEV } { return }
set cpu [cli_get_devinfo "cpu_limit"]
if { $cpu eq "0" } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 920] } {
		return "0"
	}
	set default [expr ($cpu / 2)]
	return "$default"
}
if { $CLI_GET_TT } {
	return "$cpu,1"
}
	%}
	"system global sslvpn-max-worker-count" = %{
if { $CLI_GLOBAL_DEV } { return }
set cpu [cli_get_devinfo "cpu_limit"]
if { $cpu eq "0" } { return }
if { $CLI_GET_TT } {
	if { $cpu > 128 } {
		set cpu 128
	}
	return "$cpu,0"
}
	%}
	"system global wad-worker-count" = %{
if { $CLI_GLOBAL_DEV } { return }
set cpu [cli_get_devinfo "cpu_limit"]
if { $cpu eq "0" } { return }
if { $CLI_GET_TT } {
	return "$cpu,0"
}
	%}
	"system global wad-csvc-db-count" = %{
if { $CLI_GLOBAL_DEV } { return }
set cpu [cli_get_devinfo "cpu_limit"]
if { $cpu eq "0" } { return }
if { $CLI_GET_TT } {
	return "$cpu,0"
}
	%}
        "system global virtual-server-count" = %{
if { $CLI_GLOBAL_DEV } { return }
set cpu [cli_get_devinfo "cpu"]
if { $cpu eq "0" } {
        return
}
if { $CLI_GET_TD } {
        set default [expr ($cpu / 2)]
        return "$default"
}
if { $CLI_GET_TT } {
        set VSD_MAX_WORKERS 32
        if { $cpu > $VSD_MAX_WORKERS } {
                return "$VSD_MAX_WORKERS,1"
        } else {
                return "$cpu,1"
        }
}
        %}
        "user pop3 port" = %{
if { $CLI_GET_TD } {
        if { $CLI_SUPPORT_CDB_OPS } {
                cli_skip_cache
                set secure [cli_get_value $CLI_CUR_PARENT_NODE "" "" "secure"]
                if { $secure eq "pop3s" } {
                        return "995"
                } else {
                        return "110"
                }
        }
}
        %}
	"system replacemsg {mail http webproxy ftp nntp fortiguard-wf spam im alertmail admin sslvpn ec nac-quar traffic-quota mms device-detection-portal utm auth captive-portal-dflt mm1 mm3 mm4 mm7} {buffer smil-part message html-part rsp-text subject from domain}" = %{
if { $CLI_GET_TD } {
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		set item [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
		return [cli_replmsg_defval $CLI_CUR_PARENT_NAME $item $CLI_CUR_NODE_NAME]
	}
}
	%}
	"system replacemsg {mail http webproxy ftp nntp fortiguard-wf spam im alertmail admin sslvpn ec nac-quar traffic-quota mms device-detection-portal utm auth captive-portal-dflt mm1 mm3 mm4 mm7} {header format rsp-status class priority from-sender sender-visibility add-smil charset add-html addr-type allow-content-adaptation}" = %{
if { $CLI_GET_TD } {
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		set item [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
		set msg [cli_replmsg_defval $CLI_CUR_PARENT_NAME $item $CLI_CUR_NODE_NAME]
		return [string trim $msg \"]
	}
}
	%}
	"system replacemsg {fortiguard-wf spam}" = %{
if { $CLI_GET_TO } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase "FortiFirewall*" $platform] } {
		return 0
	}
}
	%}
	"firewall profile-protocol-options {http ftp imap pop3 smtp nntp im mapi} {oversize-limit uncompressed-oversize-limit}" = %{
if { $CLI_GET_TT } {
	namespace import global::nCfg_get_proxy_filesize_limit_bounds
	set m [nCfg_get_proxy_filesize_limit_bounds]
	if { $m != 0 } {
		return "$m,1"
	}
}
	%}
	"antivirus service uncompsizelimit" = %{
if { $CLI_GET_TT } {
	namespace import global::nCfg_get_proxy_filesize_limit_bounds
	set m [nCfg_get_proxy_filesize_limit_bounds]
	if { $m != 0 } {
		return "$m,1"
	}
}
	%}
	"log memory setting status" = %{
if { $CLI_GET_TD } {
	if { [cli_in_featurelist "e_DISK_LOG_DEFAULT_DISABLE"] } {
		if { [cli_has_feature "e_DISK_LOG_DEFAULT_DISABLE"] } {
			return "enable"
		}
	}
        set g [cli_get_devinfo "get_log_disk_info"]
        if { $g eq "NA" } {
                set g [cli_get_devinfo "hdd"]
        }
        if { $g eq "no" } {
                return "enable"
        }
        return "disable"
}
	%}
	"log disk setting status" = %{
if { $CLI_GET_TD } {
        namespace import global::disk_log_default_enabled
        if { [disk_log_default_enabled] } {
		return "enable"
	} else {
		return "disable"
	}
}
	%}
        "system resource-limits {webproxy proxy}" = %{
if { $CLI_GET_TD } {
        set d [cli_feature_value "webproxy_user_limits"]
	if { $d > 0 } {
		return "$d"
	}
}
if { $CLI_GET_TT } {
        set m [cli_feature_value "webproxy_user_limits"]
	if { $m > 0 } {
		return "$m,1"
	}
}
        %}
	"antivirus profile analytics-max-upload" = %{
if { $CLI_GET_TT } {
	namespace import global::nCfg_get_proxy_filesize_limit_bounds
	set m [nCfg_get_proxy_filesize_limit_bounds]
	if { $m != 0 } {
		return "$m,1"
	}
}
	%}
	"wireless-controller wtp-profile platform type" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1051] } {
		return "221E"
	}
	return "220B"
}
if { $CLI_GET_TN } {
	namespace import global::ncfg_is_fapc_platform
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1136] } {
		set opts [cli_update_opts 1 $opts "432F" "234F" "231F" "23JF"]
	} else {
		set opts [cli_update_opts 0 $opts "432F" "234F" "231F" "23JF"]
	}
	if { [cli_branchpt_start 600 1104] } {
		set opts [cli_update_opts 1 $opts "433F" "231E" "431F"]
	} else {
		set opts [cli_update_opts 0 $opts "433F" "231E" "431F"]
	}
	if { [cli_branchpt_start 600 997] } {
		set opts [cli_update_opts 1 $opts "U433F" "U431F"]
	} else {
		set opts [cli_update_opts 0 $opts "U433F" "U431F"]
	}
	set wtp_num [cli_get_devinfo "cli_get_tablesize" "wireless-controller wtp" "vdom"]
	set wtp [cli_get_devinfo "pm2_wl_wtp_plat"]
	set nopts ""
	foreach opt $opts {
		if { $opt eq "80CM-81CM" || $opt eq "60C" } {
			if { $wtp ne $opt } {
				continue
			}
		} elseif { $wtp_num == 0 } {
			continue
		}
		if { [cli_is_match $CLI_CUR_VDOM_NODE 0 "wireless-controller setting" "fapc-compatibility" 0 "disable"] } {
			if { [ncfg_is_fapc_platform $opt] } {
				continue
			}
		}
		if { $nopts ne "" } {
			append nopts " "
		}
		append nopts $opt
	}
	if { [cli_is_match $CLI_CUR_VDOM_NODE 0 "wireless-controller setting" "fapc-compatibility" 0 "enable"] } {
		set nopts [cli_update_opts 1 $nopts "C220C" "C225C" "C226E" "C23JD" "C24JE" "C21D"]
	}
	return $nopts
}
	%}
	"wireless-controller wtp-group platform-type" = %{
if { $CLI_GET_TN } {
	namespace import global::ncfg_is_fapc_platform
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1136] } {
		set opts [cli_update_opts 1 $opts "432F" "234F" "231F" "23JF"]
	} else {
		set opts [cli_update_opts 0 $opts "432F" "234F" "231F" "23JF"]
	}
	if { [cli_branchpt_start 600 1104] } {
		set opts [cli_update_opts 1 $opts "433F" "231E" "431F"]
	} else {
		set opts [cli_update_opts 0 $opts "433F" "231E" "431F"]
	}
	if { [cli_branchpt_start 600 997] } {
		set opts [cli_update_opts 1 $opts "U433F" "U431F"]
	} else {
		set opts [cli_update_opts 0 $opts "U433F" "U431F"]
	}
	set nopts ""
	foreach opt $opts {
		if { [cli_is_match $CLI_CUR_VDOM_NODE 0 "wireless-controller setting" "fapc-compatibility" 0 "disable"] } {
			if { [ncfg_is_fapc_platform $opt] } {
				continue
			}
		}
		if { $nopts ne "" } {
			append nopts " "
		}
		append nopts $opt
	}
	if { [cli_is_match $CLI_CUR_VDOM_NODE 0 "wireless-controller setting" "fapc-compatibility" 0 "enable"] } {
		set nopts [cli_update_opts 1 $nopts "C220C" "C225C" "C226E" "C23JD" "C24JE" "C21D"]
	}
	return $nopts
}
	%}
	"system global admin-https-redirect" = %{
if { $CLI_GET_TO } {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return 0
	}
}
	%}
	"system central-management enc-algorithm" = %{
if { $CLI_GET_TD } {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return "low"
	}
}
	%}
	"vpn ipsec {phase1 phase1-interface phase2 phase2-interface manualkey manualkey-interface concentrator forticlient}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 920] && ![cli_is_traffic_vdom] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1 proposal" = %{
if { $CLI_GET_TD } {
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		namespace import global::phase1_unset_proposal
		set ikever [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ike-version"]
		return [phase1_unset_proposal $ikever]
	}
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return "des-md5 des-sha1 des-sha256 des-sha384 des-sha512"
	}
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return "aes128-sha1 aes128-sha256 aes128-sha384 aes128-sha512 aes256-sha1 aes256-sha256 aes256-sha384 aes256-sha512"
	}
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "1"] } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "aes128gcm-prfsha1" "aes128gcm-prfsha256" "aes128gcm-prfsha384" "aes128gcm-prfsha512" "aes256gcm-prfsha1" "aes256gcm-prfsha256" "aes256gcm-prfsha384" "aes256gcm-prfsha512" "chacha20poly1305-prfsha1" "chacha20poly1305-prfsha256" "chacha20poly1305-prfsha384" "chacha20poly1305-prfsha512"]
	}
}
if { $CLI_GET_ND } {
	return 1
}
	%}
        "vpn ipsec phase2 proposal" = %{
if { $CLI_GET_TD } {
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		namespace import global::phase2_unset_proposal
		return [phase2_unset_proposal]
	}
}
if { $CLI_GET_TN} {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return "null-md5 null-sha1 null-sha256 null-sha384 null-sha512 des-null des-md5 des-sha1 des-sha256 des-sha384 des-sha512"
	}
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return "aes128-sha1 aes128-sha256 aes128-sha384 aes128-sha512 aes128gcm aes256-sha1 aes256-sha256 aes256-sha384 aes256-sha512 aes256gcm"
        }
}
if { $CLI_GET_ND } {
	return 1
}
	%}
        "vpn ipsec manualkey authentication" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
        if { $CLI_GET_TD } {
                return "sha256"
        }
        if { $CLI_GET_TN } {
                return [cli_update_opts 0 $CLI_CUR_VALUE "null" "md5"]
        }
}
        %}
	"vpn ipsec manualkey encryption" = %{
if { $CLI_GET_TN} {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return "null des"
	}
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return "3des aes128 aes192 aes256"
        }
}
if { $CLI_GET_TD } {
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
                return "3des"
        }
}
	%}
        "vpn ipsec phase1-interface proposal" = %{
if { $CLI_GET_TD } {
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		namespace import global::phase1_unset_proposal
		set ikever [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ike-version"]
		return [phase1_unset_proposal $ikever]
	}
}
if { $CLI_GET_TN} {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
			return "des-md5 des-sha1 des-sha256 des-sha384 des-sha512"
	}
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return "aes128-sha1 aes128-sha256 aes128-sha384 aes128-sha512 aes256-sha1 aes256-sha256 aes256-sha384 aes256-sha512"
	}
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "1"] } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "aes128gcm-prfsha1" "aes128gcm-prfsha256" "aes128gcm-prfsha384" "aes128gcm-prfsha512" "aes256gcm-prfsha1" "aes256gcm-prfsha256" "aes256gcm-prfsha384" "aes256gcm-prfsha512" "chacha20poly1305-prfsha1" "chacha20poly1305-prfsha256" "chacha20poly1305-prfsha384" "chacha20poly1305-prfsha512"]
	}
}
if { $CLI_GET_ND } {
	return 1
}
	%}
        "vpn ipsec phase2-interface proposal" = %{
if { $CLI_GET_TD } {
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		namespace import global::phase2_unset_proposal
		return [phase2_unset_proposal]
	}
}
if { $CLI_GET_TN} {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return "null-md5 null-sha1 null-sha256 null-sha384 null-sha512 des-null des-md5 des-sha1 des-sha256 des-sha384 des-sha512"
	}
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return "aes128-sha1 aes128-sha256 aes128-sha384 aes128-sha512 aes128gcm aes256-sha1 aes256-sha256 aes256-sha384 aes256-sha512 aes256gcm"
        }
}
if { $CLI_GET_ND } {
	return 1
}
	%}
        "vpn ipsec manualkey-interface auth-alg" = %{
if { $CLI_GET_TN} {
        if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return [cli_update_opts 0 $CLI_CUR_VALUE "null" "md5"]
        }
}
if { $CLI_GET_TD } {
        if {[cli_get_devinfo "FIPS"] eq "yes"} {
                return "sha1"
        }
}
        %}
	"vpn ipsec manualkey-interface enc-alg" = %{
if { $CLI_GET_TN} {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return "null des"
	}
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return "3des aes128 aes192 aes256"
        }
}
if { $CLI_GET_TD } {
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
                return "3des"
        }
}
	%}
	"log {fortiguard fortianalyzer fortianalyzer2 fortianalyzer3} {setting override-setting} enc-algorithm" = %{
if { $CLI_GET_TD } {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return "low"
	}
}
	%}
	"system fips-cc status" = %{
if { $CLI_GET_TO } {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return 0
	}
}
	%}
	"system fortisandbox enc-algorithm" = %{
if { $CLI_GET_TD } {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return "low"
	}
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
                return "high"
        }
}
	%}
	"system global alarm-poll-interval" = %{
if { $CLI_GET_TO } {
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return $CLI_CUR_VALUE
	}
	return 0
}
	%}
	"system global strong-crypto" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_RD } {
		return 1
	}
}
	%}
	"system global dh-params" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "3072"
	}
}
	%}
	"system global fds-statistics" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "disable"
	}
}
	%}
	"system global post-login-banner" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "enable"
	}
}
	%}
	"system global tftp" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "disable"
	}
}
	%}
	"system global check-reset-range" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "strict"
	}
}
	%}
	"system global admin-ssh-v1" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_RD } {
		return 1
	}
}
	%}
	"system global {user-server-cert auth-cert}" = %{
if { $CLI_GET_TD } {
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return "self-sign"
	} elseif {[cli_get_devinfo "LENC"] eq "yes"} {
		return "self-sign"
	}
}
	%}
	"wireless-controller vap encrypt" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "TKIP" "TKIP-AES"]
	}
}
	%}
	"system interface allowaccess" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		set opts [cli_update_opts 0 $opts "http" "telnet"]
	}
	if { $CLI_TCLENV_VARS } {
		if { $CLI_ADMIN_TELNET } {
		} else {
			set opts [cli_update_opts 0 $opts "telnet"]
		}
	} else {
		if {[cli_is_match $CLI_GLOBAL_NODE 0 "system global" "admin-telnet" 0 "disable"]} {
			set opts [cli_update_opts 0 $opts "telnet"]
		}
	}
	if { [cli_branchpt_start 600 1055] } {
		set opts [cli_update_opts 1 $opts "fabric"]
		set opts [cli_update_opts 0 $opts "capwap"]
	} else {
		set opts [cli_update_opts 0 $opts "fabric"]
		set opts [cli_update_opts 1 $opts "capwap"]
	}
	return $opts
}
	%}
	"system interface ipv6 ip6-allowaccess" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		set opts [cli_update_opts 0 $opts "http" "telnet"]
	}
	if { $CLI_TCLENV_VARS } {
		if { $CLI_ADMIN_TELNET } {
		} else {
			set opts [cli_update_opts 0 $opts "telnet"]
		}
	} else {
		if {[cli_is_match $CLI_GLOBAL_NODE 0 "system global" "admin-telnet" 0 "disable"]} {
			set opts [cli_update_opts 0 $opts "telnet"]
		}
	}
	if { [cli_branchpt_start 600 1055] } {
		set opts [cli_update_opts 1 $opts "fabric"]
		set opts [cli_update_opts 0 $opts "capwap"]
	} else {
		set opts [cli_update_opts 0 $opts "fabric"]
		set opts [cli_update_opts 1 $opts "capwap"]
	}
	return $opts
}
	%}
	"system interface secondaryip allowaccess" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		set opts [cli_update_opts 0 $opts "http" "telnet"]
	}
	if { $CLI_TCLENV_VARS } {
		if { $CLI_ADMIN_TELNET } {
		} else {
			set opts [cli_update_opts 0 $opts "telnet"]
		}
	} else {
		if {[cli_is_match $CLI_GLOBAL_NODE 0 "system global" "admin-telnet" 0 "disable"]} {
			set opts [cli_update_opts 0 $opts "telnet"]
		}
	}
	if { [cli_branchpt_start 600 1055] } {
		set opts [cli_update_opts 1 $opts "fabric"]
		set opts [cli_update_opts 0 $opts "capwap"]
	} else {
		set opts [cli_update_opts 0 $opts "fabric"]
		set opts [cli_update_opts 1 $opts "capwap"]
	}
	return $opts
}
	%}
	"system ha {encryption authentication}" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "enable"
	} elseif { $CLI_GET_RD } {
		return 1
	}
}
	%}
	"web-proxy explicit ssl-algorithm" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "medium" "low"]
	}
}
	%}
	"user setting auth-type" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "http https"
	}
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "ftp" "telnet"]
	}
}
	%}
	"user setting auth-secure-http" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "enable"
	}
}
	%}
	"user setting auth-lockout-duration" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "60"
	}
}
	%}
	"vpn ssl settings" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 920] && ![cli_is_traffic_vdom] } {
		return 0
	}
}
	%}
        "vpn ssl settings algorithm" = %{
if {[cli_get_devinfo "LENC"] eq "yes"} {
	if { $CLI_GET_TO } {
                return 0
        }
}
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TN } {
                return [cli_update_opts 0 $CLI_CUR_VALUE "default" "low"]
        }
}
        %}
        "vpn ssl settings authentication-rule cipher" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_RD } {
		return 1
        }
}
if {[cli_get_devinfo "LENC"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "any"
	}
}
        %}
	"webfilter {override-user ftgd-warning} expires" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "1969/12/31 17:00:00"
	}
}
	%}
	"vpn ipsec {phase1 phase2 phase1-interface phase2-interface} dhgrp" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "15"
	}
}
	%}
	"wanopt settings tunnel-ssl-algorithm" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "medium" "low"]
	}
}
	%}
	"firewall vip ssl-cipher-suites cipher" = %{
if { $CLI_GET_TN } {
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return "TLS-DHE-RSA-WITH-AES-128-CBC-SHA TLS-DHE-RSA-WITH-AES-256-CBC-SHA TLS-DHE-RSA-WITH-AES-128-CBC-SHA256 TLS-DHE-RSA-WITH-AES-128-GCM-SHA256 TLS-DHE-RSA-WITH-AES-256-CBC-SHA256 TLS-DHE-RSA-WITH-AES-256-GCM-SHA384 TLS-DHE-DSS-WITH-AES-128-CBC-SHA TLS-DHE-DSS-WITH-AES-256-CBC-SHA TLS-DHE-DSS-WITH-AES-128-CBC-SHA256 TLS-DHE-DSS-WITH-AES-128-GCM-SHA256 TLS-DHE-DSS-WITH-AES-256-CBC-SHA256 TLS-DHE-DSS-WITH-AES-256-GCM-SHA384 TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256 TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256 TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384 TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384 TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256 TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256 TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384 TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384 TLS-RSA-WITH-AES-128-CBC-SHA TLS-RSA-WITH-AES-256-CBC-SHA TLS-RSA-WITH-AES-128-CBC-SHA256 TLS-RSA-WITH-AES-128-GCM-SHA256 TLS-RSA-WITH-AES-256-CBC-SHA256 TLS-RSA-WITH-AES-256-GCM-SHA384 TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA TLS-RSA-WITH-3DES-EDE-CBC-SHA"
	}
	if {[cli_get_devinfo "LENC"] eq "yes" } {
		return "TLS-RSA-WITH-3DES-EDE-CBC-SHA TLS-DHE-RSA-WITH-DES-CBC-SHA TLS-DHE-DSS-WITH-DES-CBC-SHA"
	}
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "TLS-AES-128-GCM-SHA256" "TLS-AES-256-GCM-SHA384" "TLS-CHACHA20-POLY1305-SHA256"]
	} else {
		set opts [cli_update_opts 0 $opts "TLS-AES-128-GCM-SHA256" "TLS-AES-256-GCM-SHA384" "TLS-CHACHA20-POLY1305-SHA256"]
	}
	return $opts
}
	%}
	"firewall ssl-server ssl-algorithm" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "medium" "low"]
	}
}
	%}
	"firewall {policy64 policy46 explicit-proxy-policy multicast-policy multicast-policy6 interface-policy interface-policy6 DoS-policy DoS-policy6 central-snat-map} status" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "disable"
	}
}
	%}
	"firewall {policy policy6} status" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "disable"
	}
}
	%}
	"firewall {policy6 explicit-proxy-policy interface-policy interface-policy6 sniffer} logtraffic" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "all"
	}
}
	%}
	"firewall policy logtraffic" = %{
if { $CLI_GET_TD } {
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return "all"
	}
	if { $CLI_IS_RESYNC && $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "learning-mode"] eq "enable" } {
			return "all"
		}
	}
}
	%}
	"firewall {policy policy6 explicit-proxy-policy} logtraffic-start" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "enable"
	}
}
	%}
	"firewall {policy64 policy46} logtraffic" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "enable"
	}
}
	%}
	"firewall explicit-proxy-policy identity-based-policy logtraffic" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "all"
	}
}
	%}
	"firewall explicit-proxy-policy identity-based-policy logtraffic-start" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "enable"
	}
}
	%}
	"log {syslogd syslogd2 syslogd3 syslogd4} {setting override-setting} reliable" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "enable"
	}
}
	%}
	"log {syslogd syslogd2 syslogd3 syslogd4} {setting override-setting} port" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "601"
	}
}
	%}
	"log {memory disk} setting diskfull" = %{
if { $CLI_GET_TD } {
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return "blocktraffic"
	}
}
if { $CLI_GET_TN } {
	if {[cli_get_devinfo "FIPS"] ne "yes"} {
		return [cli_update_opts 0 $CLI_CUR_VALUE "blocktraffic"]
	}
}
	%}
	"log {syslogd syslogd2 syslogd3 syslogd4 webtrends memory disk fortiguard null-device fortianalyzer fortianalyzer2 fortianalyzer3} {filter filter-type}" = %{
if { $CLI_GET_TO } {
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return 0
	}
}
	%}
	"log {syslogd fortiguard fortianalyzer} override-filter {filter filter-type}" = %{
if { $CLI_GET_TO } {
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return 0
	}
}
	%}
	"router rip interface auth-mode" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "md5"]
	}
}
	%}
	"router ospf area authentication" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "md5"]
	}
}
	%}
	"router ospf area virtual-link authentication" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "md5"]
	}
}
	%}
	"router ospf ospf-interface authentication" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "md5"]
	}
}
	%}
	"user group group-type" = %{
if { $CLI_GET_TD } {
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
		if { $name eq "SSO_Guest_Users" } {
			return "fsso-service"
		}
	}
}
	%}
	"report setting status" = %{
if { $CLI_GET_TD } {
	if {[cli_get_devinfo "hdd"] eq "yes"} {
                return "enable"
        }
	return "disable"
}
	%}
        "certificate {local crl}" = %{
if { $CLI_GET_TO } {
	if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
		return $CLI_CUR_VALUE
	}
	return 0
}
        %}
	"system resource-limits log-disk-quota" = %{
if { $CLI_GET_TD } {
        set quota [cli_get_devinfo "logdisk_size"]
        if { $quota > 0 } {
		namespace import global::storage_log_disk_get_wanopt_size
		set wanopt [storage_log_disk_get_wanopt_size]
		set quota [expr {$quota - $wanopt}]
		if { $quota > 0 } {
			return "$quota"
		}
        }
}
	%}
	"vpn certificate ca" = %{
if { $CLI_GET_RV } {
        if { $CLI_GLOBAL_DEV } { return }
        if { [cli_reserved_value_is "Fortinet_CA"] } {
		if { [cli_get_devinfo "LENC"] eq "yes" } {
			return 0
		}
	} elseif { [cli_reserved_value_is "Entrust_Root_Certification_Authority_-_G2"] } {
		return 0
	} elseif { [cli_reserved_value_is "PositiveSSL_CA"] } {
		return 0
	} elseif { [cli_reserved_value_is "Fortinet_NSX"] } {
		if { ![cli_has_feature "f_netx"] } {
			return 0
		}
	}
}
	%}
	"certificate ca" = %{
if { $CLI_GET_RV } {
        if { $CLI_GLOBAL_DEV } { return }
        if { [cli_reserved_value_is "Fortinet_CA"] } {
		if { [cli_get_devinfo "LENC"] eq "yes" } {
			return 0
		}
	} elseif { [cli_reserved_value_is "Entrust_Root_Certification_Authority_-_G2"] } {
		return 0
	} elseif { [cli_reserved_value_is "PositiveSSL_CA"] } {
		return 0
	} elseif { [cli_reserved_value_is "Fortinet_NSX"] } {
		if { ![cli_has_feature "f_netx"] } {
			return 0
		}
	}
}
if { $CLI_GET_TO } {
	if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
		return $CLI_CUR_VALUE
	}
	return 0
}
	%}
	"application internet-service" = %{
if { $CLI_GET_RV } {
        if { $CLI_GLOBAL_DEV } { return }
        if { [cli_reserved_value_is "3276991"] } {
		return 0
	} elseif { [cli_reserved_value_is "196615"] } {
		return 0
	}
}
	%}
	"firewall policy {action scan-botnet-connections}" = %{
if { $CLI_GET_TD } {
	if { $CLI_IS_RESYNC && $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "learning-mode"] eq "enable" } {
			set a $CLI_CUR_NODE_NAME
			if { $a eq "action" } {
				return "accept"
			} elseif { $a eq "scan-botnet-connections" } {
				return "monitor"
			}
		}
	}
}
	%}
        "log disk filter dlp-archive" = %{
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
        "wireless-controller setting country" = %{
if { $CLI_GET_TD } {
        set region [cli_get_devinfo "region"]
        if { $region ne "" } {
                return [cli_get_wl_country "default" $region]
        }
}
if { $CLI_GET_TN } {
        set region [cli_get_devinfo "region"]
        if { $region ne "" } {
                return [cli_get_wl_country "options" $region]
        }
}
        %}
	"firewall shaping-policy application" = %{
if { $CLI_GET_TM } {
	set g 0
	set v 0
	set t 0
	return [format "%lu,%lu,%lu" $g $v $t]
}
	%}
	"switch-controller quarantine" = %{
if { $CLI_GET_TO } {
	return 0
}
	%}
	"antivirus {heuristic settings quarantine notification mms-checksum profile}" = %{
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
	"application {categories name custom rule-settings list group}" = %{
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
	"dlp {filepattern sensitivity fp-doc-source sensor settings}" = %{
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
	"ips {custom sensor decoder rule rule-settings settings}" = %{
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
	"voip profile" = %{
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
	"waf {main-class sub-class signature profile}" = %{
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
	"web-proxy {profile wisp forward-server forward-server-group debug-url explicit global url-match}" = %{
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
	"webfilter {content ftgd-local-cat categories content-header urlfilter profile ips-urlfilter-setting ips-urlfilter-setting6 ips-urlfilter-cache-setting fortiguard override ftgd-local-rating search-engine}" = %{
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
	"wireless-controller {inter-controller vap global setting log bonjour-profile region wids-profile ble-profile vap-group wtp-profile wtp-group qos-profile snmp ap-status}" = %{
if { $CLI_GLOBAL_DEV } {
	if { $CLI_GET_RV } {
		if { $CLI_CUR_NODE_NAME eq "wireless-controller vap" && [cli_reserved_value_is "wifi"] } {
			return 0
		}
	}
	return
}
	%}
	"dnsfilter {domain-filter profile}" = %{
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
	"icap {server profile}" = %{
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
	"ftp-proxy explicit" = %{
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
	"firewall consolidated policy" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	namespace import global::platform_digit_start
	set plat [cli_get_devinfo "platform"]
	set model_rank [cli_get_devinfo "model_rank"]
	set serial [cli_get_devinfo "sn"]
	if { [string first "FGVMXX" $serial] == 0 } {
		return "10,10,0"
	} elseif { [cli_branchpt_start 600 997] } {
		if { [regexp -nocase {^FortiOS-VM64} $plat] } {
			return "200000,200000,0"
		} elseif { [platform_digit_start $plat "FGT_3000D"] } {
			return "200000,200000,0"
		} elseif { [platform_digit_start $plat "FGT_1000D"] } {
			return "100000,100000,0"
		} elseif { [platform_digit_start $plat "FGT_100D"] } {
			return "10000,10000,0"
		} elseif { [platform_digit_start $plat "FGT_30E"] } {
			return "5000,5000,0"
		} else {
		}
	} else {
		if { [regexp -nocase {^FortiOS-VM64} $plat] } {
			return "512,256,0"
		} elseif { [platform_digit_start $plat "FGT_30E"] } {
			return "512,256,0"
		} else {
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"system interface mediatype" = %{
if { $CLI_GET_ND } {
	if { $CLI_GLOBAL_DEV } { return }
	set platform [cli_get_devinfo "platform"]
	if { ![string match -nocase $platform "FortiGate-6000F"] && ![string match -nocase $platform "FortiGate-7000E"] && ![string match -nocase $platform "FortiCarrier-6000F"] && ![string match -nocase $platform "FortiCarrier-7000E"] } {
		return 0
	}
}
	%}
	"system interface forward-error-correction" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD && $CLI_SUPPORT_CDB_OPS } {
	cli_skip_cache
	namespace import global::sys_intf_is_media_iface
	namespace import global::platform_digit_suffix
	set platform [cli_get_devinfo "platform"]
	set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	set ifname [string trim $ifname \"]
	if { [sys_intf_is_media_iface $ifname] } {
		set suffix [platform_digit_suffix $platform]
		if { [regexp -nocase {1100E|1101E|2200E|2201E|3400E|3401E|3600E|3601E} $suffix] } {
			## make the default as empty, to force show value as no-default-value behaviour 
			return ""
		}
	}
	return $CLI_CUR_VALUE
}
if { $CLI_GET_TN } {
	namespace import global::sys_intf_is_media_iface
	namespace import global::platform_digit_suffix
	set platform [cli_get_devinfo "platform"]
	set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	set ifname [string trim $ifname \"]
	if { $CLI_SUPPORT_CDB_OPS && [sys_intf_is_media_iface $ifname] } {
		set suffix [platform_digit_suffix $platform]
		if { [regexp -nocase {1100E|1101E|2200E|2201E|3400E|3401E|3600E|3601E} $suffix] } {
			set speed [cli_get_value $CLI_CUR_PARENT_NODE "" "" "speed"]
			if { $speed eq "25000full" || $speed eq "25000auto" || $speed eq "100Gfull" } {
				return "disable fec-cl91 fec-cl74"
			} elseif { $speed eq "100Gauto" } {
				return "disable fec-cl91"
			}
			return $CLI_CUR_VALUE
		}
	}

	if { ![string match -nocase $platform "FortiGate-6000F"] &&
	     ![string match -nocase $platform "FortiGate-7000E"] &&
	     ![string match -nocase $platform "FortiGate-7000F"] &&
	     ![string match -nocase $platform "FortiCarrier-6000F"] &&
	     ![string match -nocase $platform "FortiCarrier-7000E"] &&
	     ![string match -nocase $platform "FortiCarrier-7000F"] } {
		return
	}
	if { $CLI_SUPPORT_CDB_OPS } {
		namespace import global::sys_intf_forward_error_correction_option
		set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
		set ifname [string trim $ifname \"]
		set platform [cli_get_devinfo "platform"]
		set mediatype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mediatype"]
		set speed [cli_get_value $CLI_CUR_PARENT_NODE "" "" "speed"]
		set list {}
		set nopts ""
		if { [sys_intf_forward_error_correction_option list $platform $ifname $mediatype $speed] > 0 } {
			foreach opt $list {
				if { $nopts ne "" } {
					append nopts " "
				}
				append nopts $opt
			}
		}
		return $nopts
	}
}
	%}
	"authentication setting {rewrite-https-port}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"dlp filepattern entries file-type" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "flac"]
		set opts [cli_update_opts 0 $opts "ignored"]
	} else {
		set opts [cli_update_opts 0 $opts "flac"]
		set opts [cli_update_opts 1 $opts "ignored"]
	}
	return $opts
}
	%}
	"dnsfilter profile dns-translation {status}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"emailfilter profile file-filter entries {encryption}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"emailfilter profile file-filter entries {password-protected}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"endpoint-control fctems source-ip" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "0.0.0.0"
	}
	return "0.101.99.100"
}
	%}
	"endpoint-control fctems {call-timeout}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"endpoint-control settings {forticlient-ems-rest-api-call-timeout}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"firewall address6 list {obj-id net-id}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"firewall consolidated policy {webproxy-profile webproxy-forward-server wanopt webcache webcache-https wanopt-detection wanopt-passive-opt wanopt-profile wanopt-peer}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"firewall gtp {policy-v2}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"firewall internet-service {latency-threshold jitter-threshold packetloss-threshold}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"firewall internet-service-cat-definition" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"firewall ngfw-policy" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"firewall policy {match-vip-only}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"firewall policy6 {webproxy-profile waf-profile webproxy-forward-server webcache webcache-https}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"firewall prematch-policy" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"firewall shaper traffic-shaper {dscp-marking-method exceed-bandwidth exceed-dscp maximum-dscp overhead}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 982] } {
		return "4294967295,0"
	}
	return "31,2"
}
	%}
	"firewall shaper traffic-shaper {exceed-class-id}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 982] } {
		return "4294967295,0"
	}
	return "31,2"
}
if { $CLI_GET_TD } {
	return "0"
}
	%}
	"firewall shaping-profile shaping-entries {limit burst-in-msec cburst-in-msec red-probability min max}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"firewall shaping-profile {type}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"firewall ssl-server ssl-max-version" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1051] } {
		return "tls-1.2"
	} elseif { [cli_branchpt_start 600 927] } {
		return ""
	} elseif { [cli_branchpt_start 600 910] } {
		return "tls-1.3"
	}
	return "tls-1.2"
}
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 927] } {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	} elseif { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"firewall ssl-server ssl-min-version" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 927] } {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	} elseif { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"firewall vip ssl-cipher-suites versions" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "ssl-3.0 tls-1.0 tls-1.1 tls-1.2 tls-1.3"
	}
	return "ssl-3.0 tls-1.0 tls-1.1 tls-1.2"
}
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"firewall vip ssl-max-version" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "tls-1.3"
	}
	return "tls-1.2"
}
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"firewall vip ssl-min-version" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"firewall vip ssl-server-cipher-suites cipher" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "TLS-AES-128-GCM-SHA256" "TLS-AES-256-GCM-SHA384" "TLS-CHACHA20-POLY1305-SHA256"]
	} else {
		set opts [cli_update_opts 0 $opts "TLS-AES-128-GCM-SHA256" "TLS-AES-256-GCM-SHA384" "TLS-CHACHA20-POLY1305-SHA256"]
	}
	return $opts
}
	%}
	"firewall vip ssl-server-cipher-suites versions" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return ""
	}
	return "ssl-3.0 tls-1.0 tls-1.1 tls-1.2"
}
	%}
	"firewall vip ssl-server-max-version" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"firewall vip ssl-server-min-version" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"firewall vip {ssl-client-rekey-count http-redirect}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"firewall vip6 ssl-cipher-suites cipher" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "TLS-AES-128-GCM-SHA256" "TLS-AES-256-GCM-SHA384" "TLS-CHACHA20-POLY1305-SHA256"]
	} else {
		set opts [cli_update_opts 0 $opts "TLS-AES-128-GCM-SHA256" "TLS-AES-256-GCM-SHA384" "TLS-CHACHA20-POLY1305-SHA256"]
	}
	return $opts
}
	%}
	"firewall vip6 ssl-cipher-suites versions" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "ssl-3.0 tls-1.0 tls-1.1 tls-1.2 tls-1.3"
	}
	return "ssl-3.0 tls-1.0 tls-1.1 tls-1.2"
}
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"firewall vip6 ssl-max-version" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "tls-1.3"
	}
	return "tls-1.2"
}
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"firewall vip6 ssl-min-version" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"firewall vip6 ssl-server-cipher-suites cipher" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "TLS-AES-128-GCM-SHA256" "TLS-AES-256-GCM-SHA384" "TLS-CHACHA20-POLY1305-SHA256"]
	} else {
		set opts [cli_update_opts 0 $opts "TLS-AES-128-GCM-SHA256" "TLS-AES-256-GCM-SHA384" "TLS-CHACHA20-POLY1305-SHA256"]
	}
	return $opts
}
	%}
	"firewall vip6 ssl-server-cipher-suites versions" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 982] } {
		return "ssl-3.0 tls-1.0 tls-1.1 tls-1.2 tls-1.3"
	} elseif { [cli_branchpt_start 600 910] } {
		return ""
	}
	return "ssl-3.0 tls-1.0 tls-1.1 tls-1.2"
}
	%}
	"firewall vip6 ssl-server-max-version" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"firewall vip6 ssl-server-min-version" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"firewall vip6 {ssl-client-rekey-count http-redirect}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log disk filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log disk setting uploadtype" = %{
if { $CLI_GET_TD } {
	set defval $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set defval [cli_update_opts 1 $defval "cifs" "ssh" "ssl"]
	} else {
		set defval [cli_update_opts 0 $defval "cifs" "ssh" "ssl"]
	}
	return $defval
}
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "cifs" "file-filter" "ssh" "ssl"]
	} else {
		set opts [cli_update_opts 0 $opts "cifs" "file-filter" "ssh" "ssl"]
	}
	return $opts
}
	%}
	"log fortianalyzer filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log fortianalyzer override-filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log fortianalyzer-cloud filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log fortianalyzer-cloud override-filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log fortianalyzer-cloud setting ips-archive" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "disable"
	}
	return "enable"
}
	%}
	"log fortianalyzer2 filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log fortianalyzer2 override-filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log fortianalyzer3 filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log fortianalyzer3 override-filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log fortiguard filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log fortiguard override-filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log fortiguard setting {conn-timeout}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log memory filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log null-device filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log syslogd filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log syslogd override-filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log syslogd2 filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log syslogd2 override-filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log syslogd3 filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log syslogd3 override-filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log syslogd4 filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log syslogd4 override-filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"log webtrends filter {dns ssh ssl cifs}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"router bgp neighbor {route-map-out-preferable}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"router bgp neighbor-group {route-map-out-preferable}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"router multicast interface {rpf-nbr-fail-back rpf-nbr-fail-back-filter}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"router ospf area virtual-link md5-keys key-string" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 910] } {
		return "16"
	}
	return "12"
}
	%}
	"router ospf ospf-interface md5-keys key-string" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 910] } {
		return "16"
	}
	return "12"
}
	%}
	"router ospf6 area virtual-link {authentication key-rollover-interval ipsec-auth-alg ipsec-enc-alg}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"router ospf6 area virtual-link {ipsec-keys}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"router ospf6 area {authentication key-rollover-interval ipsec-auth-alg ipsec-enc-alg}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"router ospf6 area {ipsec-keys}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"router ospf6 ospf6-interface {authentication key-rollover-interval ipsec-auth-alg ipsec-enc-alg}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"router ospf6 ospf6-interface {ipsec-keys}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"router policy {input-device-negate}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"router static6 {link-monitor-exempt}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"switch-controller global mac-retention-period" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 910] } {
		return "168,0"
	}
	return "168,1"
}
	%}
	"switch-controller global {mac-event-logging}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch ports speed" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1104] } {
		set opts [cli_update_opts 1 $opts "2500auto"]
		set opts [cli_update_opts 0 $opts "2500full"]
	} else {
		set opts [cli_update_opts 0 $opts "2500auto"]
		set opts [cli_update_opts 1 $opts "2500full"]
	}
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "25000cr4" "25000sr4" "5000full"]
	} else {
		set opts [cli_update_opts 0 $opts "25000cr4" "25000sr4" "5000full"]
	}
	return $opts
}
	%}
	"switch-controller managed-switch ports {export-to-pool-flag mac-addr}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch ports {export-to-pool_flag}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch {override-snmp-sysinfo override-snmp-trap-threshold override-snmp-community override-snmp-user}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch {snmp-sysinfo snmp-trap-threshold snmp-community snmp-user remote-log}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"switch-controller {remote-log snmp-community snmp-sysinfo snmp-trap-threshold snmp-user}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"switch-controller traffic-policy guaranteed-bandwidth" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "10000"
	}
	return "0"
}
	%}
	"switch-controller traffic-policy guaranteed-burst" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "45000"
	}
	return "0"
}
	%}
	"switch-controller traffic-policy maximum-burst" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "67500"
	}
	return "0"
}
	%}
	"system automation-action aws-api-key" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 910] } {
		return "123"
	}
	return "127"
}
	%}
	"system automation-action azure-api-key" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 910] } {
		return "123"
	}
	return "127"
}
	%}
	"system automation-action email-body" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "%%log%%"
	}
	return ""
}
	%}
	"system automation-action {azure-function-authorization}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system cluster-sync {ipsec-tunnel-sync}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	set platform [cli_get_devinfo "platform"]
	set suffix [platform_digit_suffix $platform]
	if { [regexp -nocase {6000F|7000E|7000F} $suffix] } {
		if { ![cli_branchpt_start 600 1263] } {
			return "enable"
		} else {
			return "disable"
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"system dns {server-hostname}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system external-resource {source-ip}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system fortiguard {proxy-server-ip proxy-server-port proxy-username proxy-password}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system global {vdom-admin url-filter-affinity}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system interface {aggregate redundant-interface fortilink-neighbor-detect lacp-mode lacp-ha-slave lacp-speed min-links min-links-down algorithm link-up-delay priority-override ring-rx ring-tx eip}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system interface {member}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system npu {ipsec-inbound-cache}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system remote-admin" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system saml service-providers assertion-attributes type" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 0 $opts "privilege"]
	} else {
		set opts [cli_update_opts 1 $opts "privilege"]
	}
	return $opts
}
	%}
	"system saml {default-profile}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system sdn-connector use-metadata-iam" = %{
if { $CLI_GET_TD } {
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
		if { $type eq "aws" } {
			set platform [cli_get_devinfo "platform"]
			if { [string match -nocase $platform "FortiCarrier-VM64-AWS"] ||
				[string match -nocase $platform "Fortigate-VM64-AWS"] ||
				[string match -nocase $platform "Fortigate-VM64-AWSONDEMAND"] } {
				return "enable"
			}
		} elseif { $type eq "oci" } {
			set platform [cli_get_devinfo "platform"]
			if { [string match -nocase $platform "FortiCarrier-VM64-OPC"] ||
				[string match -nocase $platform "Fortigate-VM64-OPC"] } {
				return "enable"
			}
		} elseif { $type eq "gcp" } {
			set platform [cli_get_devinfo "platform"]
			if { [string match -nocase $platform "FortiCarrier-VM64-GCP"] ||
				[string match -nocase $platform "Fortigate-VM64-GCP"] ||
				[string match -nocase $platform "Fortigate-VM64-GCPONDEMAND"] } {
				return "enable"
			}
		} elseif { $type eq "azure" } {
			set platform [cli_get_devinfo "platform"]
			if { [string match -nocase $platform "FortiCarrier-VM64-AZURE"] ||
				[string match -nocase $platform "Fortigate-VM64-AZURE"] ||
				[string match -nocase $platform "Fortigate-VM64-AZUREONDEMAND"] } {
				return "enable"
			}
		}
	}
	return "disable"
}
	%}
	"system sdn-connector oci-region" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return ""
	}
	return "phoenix"
}
	%}
	"system sdn-connector region" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 910] } {
		return "31"
	}
	return "15"
}
	%}
	"system sdn-connector {updating last-update}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] || [cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"system sdn-connector {oci-region-type}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system settings ecmp-max-paths" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "255"
	}
	return "10"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 910] } {
		return "255,1"
	}
	return "100,1"
}
	%}
	"system settings {ssl-ssh-profile}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system sso-admin" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system vdom-dns {server-hostname}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system virtual-wan-link health-check {internet-service-id}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system virtual-wan-link members volume-ratio" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "1"
	}
	return "0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 910] } {
		return "255,1"
	}
	return "255,0"
}
	%}
	"system virtual-wan-link members weight" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "1"
	}
	return "0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 910] } {
		return "255,1"
	}
	return "255,0"
}
	%}
	"system virtual-wan-link service {input-device-negate role standalone-action sla-compare-method}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system virtual-wan-link {neighbor-hold-down neighbor-hold-down-time neighbor-hold-boot-time}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system virtual-wan-link {neighbor}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"system zone {description}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"user device type" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return ""
	}
}
	%}
	"user device {hardware-vendor family os hardware-version software-version}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"user exchange auth-level" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "privacy"
	}
	return "high"
}
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "call" "connect" "integrity" "packet" "privacy"]
		set opts [cli_update_opts 0 $opts "high" "low" "medium" "normal"]
	} else {
		set opts [cli_update_opts 0 $opts "call" "connect" "integrity" "packet" "privacy"]
		set opts [cli_update_opts 1 $opts "high" "low" "medium" "normal"]
	}
	return $opts
}
	%}
	"user exchange connect-protocol" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "rpc-over-https"
	}
	return "rpc-over-tcp"
}
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "rpc-over-https"]
	} else {
		set opts [cli_update_opts 0 $opts "rpc-over-https"]
	}
	return $opts
}
	%}
	"user exchange {addr-type ip6}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"user exchange {auth-type http-auth-type ssl-min-proto-version}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"user exchange {kdc-ip}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"user ldap server-identity-check" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "enable"
	}
	return "disable"
}
	%}
	"user password-policy {expired-password-renewal}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 982] } {
		return "disable"
	}
	return "enable"
}
	%}
	"user setting {auth-ssl-min-proto-version}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"voip profile sip ssl-max-version" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"voip profile sip ssl-min-version" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"vpn ipsec phase1-interface net-device" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "disable"
	}
	return "enable"
}
	%}
	"vpn ipsec phase1-interface {aggregate-member}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"vpn ssl settings banned-cipher" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 0 $opts "DH" "ECDH"]
	} else {
		set opts [cli_update_opts 1 $opts "DH" "ECDH"]
	}
	return $opts
}
	%}
	"vpn ssl settings {ssl-max-proto-ver ssl-min-proto-ver dtls-max-proto-ver dtls-min-proto-ver}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"vpn ssl web {favorite host-check-software realm user-bookmark user-group-bookmark}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 920] && ![cli_is_traffic_vdom] } {
		return 0
	}
}
	%}
	"vpn ssl web portal" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 920] && ![cli_is_traffic_vdom] } {
		return 0
	}
}
if { $CLI_GET_TM } {
	namespace import global::platform_digit_between
	set plat [cli_get_devinfo "platform"]
	if { [platform_digit_between $plat "FGT_30E" "FGR_35D"] } {
		if { [cli_branchpt_start 600 1136] } {
			return "0,5,0"
		}
		return "0,1,0"
	}
	return $CLI_CUR_VALUE
}
	%}
	"vpn ssl web portal bookmark-group bookmarks apptype" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 0 $opts "citrix" "portforward"]
	} else {
		set opts [cli_update_opts 1 $opts "citrix" "portforward"]
	}
	return $opts
}
	%}
	"vpn ssl web portal bookmark-group bookmarks server-layout" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "fr-ca-qwerty"]
	} else {
		set opts [cli_update_opts 0 $opts "fr-ca-qwerty"]
	}
	return $opts
}
	%}
	"vpn ssl web user-bookmark bookmarks apptype" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 0 $opts "citrix" "portforward"]
	} else {
		set opts [cli_update_opts 1 $opts "citrix" "portforward"]
	}
	return $opts
}
	%}
	"vpn ssl web user-bookmark bookmarks server-layout" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "fr-ca-qwerty"]
	} else {
		set opts [cli_update_opts 0 $opts "fr-ca-qwerty"]
	}
	return $opts
}
	%}
	"vpn ssl web user-group-bookmark bookmarks apptype" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 0 $opts "citrix" "portforward"]
	} else {
		set opts [cli_update_opts 1 $opts "citrix" "portforward"]
	}
	return $opts
}
	%}
	"vpn ssl web user-group-bookmark bookmarks server-layout" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "fr-ca-qwerty"]
	} else {
		set opts [cli_update_opts 0 $opts "fr-ca-qwerty"]
	}
	return $opts
}
	%}
	"web-proxy forward-server-group ldb-method" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "active-passive"]
	} else {
		set opts [cli_update_opts 0 $opts "active-passive"]
	}
	return $opts
}
	%}
	"webfilter profile file-filter entries {encryption}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"webfilter profile file-filter entries {password-protected}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"wireless-controller setting {wfa-compatibility}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"wireless-controller timers darrp-optimize" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 982] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 910] } {
		return "86400"
	}
	return "1800"
}
	%}
	"wireless-controller timers {darrp-day darrp-time}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"wireless-controller timers darrp-optimize-schedules" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] || [cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"wireless-controller vap {mu-mimo}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 930] } {
		return "enable"
	}
	return "disable"
}
	%}
	"wireless-controller wids-profile {ap-bgscan-disable-day ap-bgscan-disable-start ap-bgscan-disable-end}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"wireless-controller wids-profile {ap-bgscan-disable-schedules}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"wireless-controller wtp allowaccess" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "snmp"]
	} else {
		set opts [cli_update_opts 0 $opts "snmp"]
	}
	return $opts
}
	%}
	"wireless-controller wtp-profile ap-country" = %{
if { $CLI_GET_TN } {
        if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1232] } {
		set opts [cli_update_opts 1 $opts "BS"]
	} else {
		set opts [cli_update_opts 0 $opts "BS"]
	}
	if { [cli_branchpt_start 600 910] } {
		set opts [cli_update_opts 1 $opts "CF"]
	} else {
		set opts [cli_update_opts 0 $opts "CF"]
	}
	return $opts
}
	%}
	"wireless-controller wtp-profile {snmp}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 910] } {
		return 0
	}
}
	%}
	"vpn {pptp l2tp ocvpn}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 920] && ![cli_is_traffic_vdom] } {
		return 0
	}
}
	%}
	"vpn ocvpn overlays" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 600 910] } {
		return "0,0,10"
	}
	return "512,256,0"
}
	%}
	"firewall consolidated policy {internet-service internet-service-src}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 920] } {
		return 0
	}
}
	%}
	"firewall consolidated policy {internet-service-id internet-service-group internet-service-custom internet-service-custom-group internet-service-src-id internet-service-src-group internet-service-src-custom internet-service-src-custom-group}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 920] } {
		return 0
	}
}
	%}
	"firewall consolidated policy {application app-category url-category app-group}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 920] } {
		return 0
	}
}
	%}
	"firewall ngfw-policy" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 920] } {
		return 0
	}
}
	%}
	"firewall policy {fsso-groups}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 920] } {
		return 0
	}
}
	%}
	"firewall prematch-policy" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 920] } {
		return 0
	}
}
	%}
	"firewall security-policy" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 920] } {
		return 0
	}
}
if { $CLI_GET_TM } {
	namespace import global::platform_digit_start
	set plat [cli_get_devinfo "platform"]
	set model_rank [cli_get_devinfo "model_rank"]
	set serial [cli_get_devinfo "sn"]
	if { [string first "FGVMXX" $serial] == 0 } {
		return "10,10,0"
	} elseif { [cli_branchpt_start 600 997] } {
		if { [regexp -nocase {^FortiOS-VM64} $plat] } {
			return "200000,200000,0"
		} elseif { [platform_digit_start $plat "FGT_3000D"] } {
			return "200000,200000,0"
		} elseif { [platform_digit_start $plat "FGT_1000D"] } {
			return "100000,100000,0"
		} elseif { [platform_digit_start $plat "FGT_100D"] } {
			return "10000,10000,0"
		} elseif { [platform_digit_start $plat "FGT_30E"] } {
			return "5000,5000,0"
		} else {
		}
	} else {
		if { [regexp -nocase {^FortiOS-VM64} $plat] } {
			return "512,256,0"
		} elseif { [platform_digit_start $plat "FGT_30E"] } {
			return "512,256,0"
		} else {
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"firewall shaping-profile shaping-entries priority" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 920] } {
		set opts [cli_update_opts 1 $opts "critical" "top"]
	} else {
		set opts [cli_update_opts 0 $opts "critical" "top"]
	}
	return $opts
}
	%}
	"system csf management-ip" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 920] } {
		return ""
	}
	return "0.0.0.0"
}
	%}
	"system global {gui-fortisandbox-cloud gui-allow-default-hostname}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 920] } {
		return 0
	}
}
	%}
	"system interface {ingress-shaping-profile}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 920] } {
		return 0
	}
}
	%}
	"system saml role" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 920] } {
		return "service-provider"
	}
	return "SP"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 920] } {
		set opts [cli_update_opts 1 $opts "identity-provider" "service-provider"]
		set opts [cli_update_opts 0 $opts "IDP" "SP"]
	} else {
		set opts [cli_update_opts 0 $opts "identity-provider" "service-provider"]
		set opts [cli_update_opts 1 $opts "IDP" "SP"]
	}
	return $opts
}
	%}
	"system settings {gui-per-policy-disclaimer}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 920] } {
		return 0
	}
}
	%}
	"user adgrp id" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 920] } {
		return 0
	}
}
	%}
	"user device avatar" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 920] } {
		return "255"
	}
	return "4095"
}
	%}
	"user device {hardware-vendor family os hardware-version software-version}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 920] } {
		return 0
	}
}
	%}
	"user fsso {ldap-poll ldap-poll-interval ldap-poll-filter}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 920] } {
		return 0
	}
}
	%}
	"user {local group} {id}" = %{
if { $CLI_GET_RD } {
	expr [cli_branchpt_start 600 920]
}
	%}
	"dlp sensor filter proto" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	namespace import global::is_carrier_platform
	namespace import global::ngfw_mode_policy
	set opts $CLI_CUR_VALUE
	set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
	if { $type eq "file" } {
		set opts [cli_update_opts 1 $opts "ftp http-get"]
		if { [is_carrier_platform] } {
			set opts [cli_update_opts 1 $opts "mm1 mm3 mm4 mm7"]
		}
	} else {
		set opts [cli_update_opts 0 $opts "ftp http-get"]
		if { [is_carrier_platform] } {
			set opts [cli_update_opts 0 $opts "mm1 mm3 mm4 mm7"]
		}
	}
	if { [ngfw_mode_policy] } {
		set opts [cli_update_opts 0 $opts "mapi"]
	} else {
		set opts [cli_update_opts 1 $opts "mapi"]
	}
	if { [cli_branchpt_start 600 982] } {
		set opts [cli_update_opts 1 $opts "ssh"]
	} else {
		set opts [cli_update_opts 0 $opts "ssh"]
	}
	return $opts
}
	%}
	"firewall security-policy utm-status" = %{
if { $CLI_GET_RD } {
	expr [cli_branchpt_start 600 927]
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 927] } {
		return "enable"
	}
	return "disable"
}
	%}
	"antivirus profile scan-mode" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 982] } {
		return "default"
	}
	return "full"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	set platform [cli_get_devinfo "platform"]
	if { [cli_branchpt_start 600 982] || [string match -nocase "FortiFirewall*" $platform] } {
		set opts [cli_update_opts 1 $opts "default" "legacy"]
		set opts [cli_update_opts 0 $opts "full" "quick"]
	} else {
		set opts [cli_update_opts 0 $opts "default" "legacy"]
		set opts [cli_update_opts 1 $opts "full" "quick"]
	}
	return $opts
}
	%}
	"antivirus profile ssh" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 920] } {
		return 0
	}
}
	%}
	"antivirus quarantine {drop-blocked drop-heuristic drop-infected}" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 982] } {
		set opts [cli_update_opts 1 $opts "ssh"]
	} else {
		set opts [cli_update_opts 0 $opts "ssh"]
	}
	return $opts
}
	%}
	"antivirus quarantine {store-blocked }" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 982] } {
		return "imap smtp pop3 http ftp nntp imaps smtps pop3s ftps mapi cifs ssh"
	}
	return "imap smtp pop3 http ftp nntp imaps smtps pop3s ftps mapi cifs"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 982] } {
		set opts [cli_update_opts 1 $opts "ssh"]
	} else {
		set opts [cli_update_opts 0 $opts "ssh"]
	}
	return $opts
}
	%}
	"antivirus quarantine {store-heuristic store-infected}" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 982] } {
		return "imap smtp pop3 http ftp nntp imaps smtps pop3s https ftps mapi cifs ssh"
	}
	return "imap smtp pop3 http ftp nntp imaps smtps pop3s https ftps mapi cifs"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 982] } {
		set opts [cli_update_opts 1 $opts "ssh"]
	} else {
		set opts [cli_update_opts 0 $opts "ssh"]
	}
	return $opts
}
	%}
	"certificate remote" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"cifs profile server-keytab keytab" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 982] } {
		return "8191"
	}
	return "4095"
}
	%}
	"cifs profile server-keytab {password}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"dlp sensor {full-archive-proto summary-proto}" = %{
if { $CLI_GET_TN } {
	namespace import global::ngfw_mode_policy
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 982] } {
		set opts [cli_update_opts 1 $opts "ssh"]
	} else {
		set opts [cli_update_opts 0 $opts "ssh"]
	}
	if { [ngfw_mode_policy] } {
		set opts [cli_update_opts 0 $opts "mapi"]
	} else {
		set opts [cli_update_opts 1 $opts "mapi"]
	}
	return $opts
}
	%}
	"dnsfilter profile dns-translation {addr-type src6 dst6 prefix}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"firewall address filter" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 982] } {
		return "2047"
	}
	return "255"
}
	%}
	"firewall address type" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 982] } {
		set opts [cli_update_opts 0 $opts "wildcard-fqdn"]
	} else {
		set opts [cli_update_opts 1 $opts "wildcard-fqdn"]
	}
	return $opts
}
	%}
	"firewall address {fsso-group}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"firewall address sub-type" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"firewall address clearpass-spt" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	set platform [cli_get_devinfo "platform"]
	if { [cli_branchpt_start 600 997] || [string match -nocase "FortiFirewall*" $platform] } {
		set opts [cli_update_opts 1 $opts "transient"]
		set opts [cli_update_opts 0 $opts "transition"]
	} else {
		set opts [cli_update_opts 0 $opts "transient"]
		set opts [cli_update_opts 1 $opts "transition"]
	}
	return $opts
}
	%}
	"firewall consolidated policy {srcaddr-negate dstaddr-negate service-negate internet-service-negate internet-service-src-negate captive-portal-exempt}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"firewall ldb-monitor type" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 982] } {
		set opts [cli_update_opts 1 $opts "https"]
	} else {
		set opts [cli_update_opts 0 $opts "https"]
	}
	return $opts
}
	%}
	"firewall profile-protocol-options {ftp http} comfort-amount" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 982] } {
		return "65535,1"
	}
	return "10240,1"
}
	%}
	"firewall profile-protocol-options http {stream-based-uncompressed-limit ssl-offloaded}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"firewall profile-protocol-options {ftp imap pop3 smtp} {ssl-offloaded}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"firewall profile-protocol-options ssh" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"firewall security-policy {fsso-groups send-deny-packet}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"firewall shaping-policy class-id" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 982] } {
		return "4294967295,0"
	}
	return "255,0"
}
if { $CLI_GET_TD } {
	return "0"
}
	%}
	"firewall shaping-profile default-class-id" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 982] } {
		return "4294967295,0"
	}
	return "31,2"
}
if { $CLI_GET_TD } {
	return "0"
}
	%}
	"firewall shaping-profile shaping-entries class-id" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 982] } {
		return "4294967295,0"
	}
	return "31,2"
}
if { $CLI_GET_TD } {
	return "0"
}
	%}
	"firewall traffic-class" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"ftp-proxy explicit {ssl ssl-cert ssl-dh-bits ssl-algorithm}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"ips global socket-size" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 982] } {
		return $CLI_CUR_VALUE
	}
	return "0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 982] } {
		return "512,0"
	}
	return "1024,0"
}
	%}
	"log fortianalyzer {setting override-setting} {priority max-log-rate}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"log fortianalyzer-cloud setting {priority max-log-rate}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"log fortianalyzer2 {setting override-setting} {priority max-log-rate}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"log fortianalyzer3 {setting override-setting} {priority max-log-rate}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"log fortiguard {setting override-setting} {priority max-log-rate}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"log syslogd {setting override-setting} {priority max-log-rate}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"log syslogd2 {setting override-setting} {priority max-log-rate}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"log syslogd3 {setting override-setting} {priority max-log-rate}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"log syslogd4 {setting override-setting} {priority max-log-rate}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"ssh-filter profile {block log}" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 982] } {
		set opts [cli_update_opts 1 $opts "scp"]
	} else {
		set opts [cli_update_opts 0 $opts "scp"]
	}
	return $opts
}
	%}
	"ssh-filter profile file-filter" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"switch-controller 802-1X-settings reauth-period" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 982] } {
		return "1440,0"
	}
	return "1440,1"
}
	%}
	"switch-controller auto-config policy {igmp-flood-report igmp-flood-traffic}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 997] } {
		return "disable"
	}
	return "enable"
}
	%}
	"switch-controller global {vlan-all-mode vlan-optimization bounce-quarantined-link}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"switch-controller lldp-profile 802.3-tlvs" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 982] } {
		set opts [cli_update_opts 1 $opts "power-negotiation"]
	} else {
		set opts [cli_update_opts 0 $opts "power-negotiation"]
	}
	return $opts
}
	%}
	"switch-controller lldp-profile med-network-policy {assign-vlan}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch 802-1X-settings reauth-period" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 982] } {
		return "1440,0"
	}
	return "1440,1"
}
	%}
	"switch-controller traffic-sniffer {mode}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"system automation-action {tls-certificate}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"system dhcp server {wifi-ac-service dns-server4}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"system dhcp6 server {dns-server4}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"system fortiguard port" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 982] } {
		set opts [cli_update_opts 1 $opts "443"]
	} else {
		set opts [cli_update_opts 0 $opts "443"]
	}
	return $opts
}
	%}
	"system global {fortitoken-cloud}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"system gre-tunnel {diffservcode}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"system interface {switch-controller-rspan-mode}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"system npu {port-cpu-map}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"system sdn-connector type" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 982] } {
		return "aws"
	}
	return "CLI_GET_NULL"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 997] } {
		set opts [cli_update_opts 1 $opts "sepm"]
	} else {
		set opts [cli_update_opts 0 $opts "sepm"]
	}
	return $opts
}
	%}
	"system settings {sip-expectation}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"system settings {sip-helper gui-dlp}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"system speed-test-server timestamp" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 982] } {
		return "0"
	}
	return "valid"
}
	%}
	"system vdom-exception object" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1136] } {
		set opts [cli_update_opts 1 $opts "system.interface"]
	} else {
		set opts [cli_update_opts 0 $opts "system.interface"]
	}
	if { [cli_branchpt_start 600 1104] } {
		set opts [cli_update_opts 1 $opts "firewall.ippool" "firewall.vip6" "router.route-map" "router.prefix-list" "system.virtual-wan-link" "firewall.vip46" "vpn.ipsec.phase1-interface" "router.static6" "vpn.ipsec.phase2-interface" "router.bgp" "firewall.ippool6" "firewall.vip" "firewall.vip64" "router.static"]
	} else {
		set opts [cli_update_opts 0 $opts "firewall.vip6" "system.virtual-wan-link" "firewall.vip46" "router.static6" "firewall.ippool6" "firewall.vip" "firewall.vip64" "router.static"]
	}
	if { [cli_branchpt_start 600 982] } {
		set opts [cli_update_opts 1 $opts "log.fortianalyzer-cloud.override-setting" "log.fortianalyzer-cloud.setting" "log.fortianalyzer2.override-setting" "log.fortianalyzer2.setting" "log.fortianalyzer3.override-setting" "log.fortianalyzer3.setting" "system.central-management" "system.csf" "user.radius"]
	} else {
		set opts [cli_update_opts 0 $opts "log.fortianalyzer-cloud.override-setting" "log.fortianalyzer-cloud.setting" "log.fortianalyzer2.override-setting" "log.fortianalyzer2.setting" "log.fortianalyzer3.override-setting" "log.fortianalyzer3.setting" "system.central-management" "system.csf" "user.radius"]
	}
	return $opts
}
	%}
	"system virtual-wan-link health-check {ha-priority}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"user krb-keytab keytab" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 982] } {
		return "8191"
	}
	return "2047"
}
	%}
	"user krb-keytab {password}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"user ldap {two-factor}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"user saml" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"vpn certificate setting {certname-rsa4096 certname-ecdsa521 certname-ed25519 certname-ed448}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1 wizard-type" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 982] } {
		set opts [cli_update_opts 1 $opts "hub-fortigate-auto-discovery" "simplified-static-fortigate" "spoke-fortigate-auto-discovery"]
	} else {
		set opts [cli_update_opts 0 $opts "hub-fortigate-auto-discovery" "simplified-static-fortigate" "spoke-fortigate-auto-discovery"]
	}
	return $opts
}
	%}
	"vpn ipsec phase1-interface wizard-type" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 982] } {
		set opts [cli_update_opts 1 $opts "hub-fortigate-auto-discovery" "simplified-static-fortigate" "spoke-fortigate-auto-discovery"]
	} else {
		set opts [cli_update_opts 0 $opts "hub-fortigate-auto-discovery" "simplified-static-fortigate" "spoke-fortigate-auto-discovery"]
	}
	return $opts
}
	%}
	"vpn ssl web portal os-check-list tolerance" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 982] } {
		return "65535,0"
	}
	return "255,0"
}
	%}
	"vpn ssl web portal {transform-backward-slashes}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"wireless-controller setting {darrp-optimize-schedules}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"wireless-controller setting {darrp-optimize}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"wireless-controller vap mpsk-key {mpsk-schedules}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"wireless-controller vap portal-type" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 982] } {
		set opts [cli_update_opts 1 $opts "external-auth"]
	} else {
		set opts [cli_update_opts 0 $opts "external-auth"]
	}
	return $opts
}
	%}
	"wireless-controller vap {external-web-format primary-wag-profile secondary-wag-profile tunnel-echo-interval tunnel-fallback-interval}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"wireless-controller wag-profile" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 982] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile lldp" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 982] } {
		return "enable"
	}
	return "disable"
}
	%}
	"wireless-controller wtp-profile {radio-1 radio-2} channel-utilization" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 982] } {
		return "enable"
	}
	return "disable"
}
	%}
	"user adgrp" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	namespace import global::platform_digit_start
	set plat [cli_get_devinfo "platform"]
	set model_rank [cli_get_devinfo "model_rank"]
	if { [cli_branchpt_start 600 982] } {
		if { [regexp -nocase {^FortiOS-VM64} $plat] } {
			return "0,80000,0"
		} elseif { [platform_digit_start $plat "FGT_3000D"] } {
			return "0,80000,0"
		} elseif { [platform_digit_start $plat "FGT_900D"] } {
			return "0,16384,0"
		} elseif { [platform_digit_start $plat "FGT_100D"] } {
			return "0,4096,0"
		} elseif { [platform_digit_start $plat "FGT_30E"] } {
			return "0,1024,0"
		} else {
			if { $model_rank eq "VMEV" } {
				return "0,1024,0"
			} elseif { $model_rank eq "1U" } {
				return "0,4096,0"
			} elseif { $model_rank eq "HIGHEND" } {
				return "0,16384,0"
			}
		}
	} else {
		if { [regexp -nocase {^FortiOS-VM64} $plat] } {
			return "0,8192,0"
		} elseif { [platform_digit_start $plat "FGT_1000D"] } {
			return "0,8192,0"
		} elseif { [platform_digit_start $plat "FGT_300D"] } {
			return "0,1024,0"
		} elseif { [platform_digit_start $plat "FGT_30E"] } {
			return "0,256,0"
		} else {
			if { $model_rank eq "VMEV" } {
				return "0,256,0"
			} elseif { $model_rank eq "1U" } {
				return "0,1024,0"
			} elseif { $model_rank eq "HIGHEND" } {
				return "0,8192,0"
			}
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"wireless-controller {address addrgrp}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	namespace import global::platform_digit_between
	set plat [cli_get_devinfo "platform"]
	set model_rank [cli_get_devinfo "model_rank"]
	if { [cli_branchpt_start 600 982] } {
		if { [regexp -nocase {^FortiOS-VM64} $plat] } {
			return "0,1024,0"
		} elseif { [platform_digit_start $plat "FGT_3000D"] } {
			return "0,1024,0"
		} elseif { [platform_digit_start $plat "FGT_30E"] } {
			return "0,256,0"
		} else {
			if { $model_rank eq "VMEV" } {
				return "0,256,0"
			} else {
				return "0,1024,0"
			}
		}
	} else {
		return "512,256,0"
	}
	return $CLI_CUR_VALUE
}
	%}
	"application custom signature" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 997] } {
		return "4095"
	}
	return "1023"
}
	%}
	"endpoint-control fctems {fortinetone-cloud-authentication}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
	%}
	"firewall gtp {sub-second-sampling sub-second-interval}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
	%}
	"gtp apn-shaper apn" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 997] } {
		return ""
	}
	return ""
}
	%}
	"ips custom signature" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 997] } {
		return "4095"
	}
	return "1023"
}
	%}
	"log fortianalyzer-cloud filter {anomaly forward-traffic gtp local-traffic multicast-traffic sniffer-traffic voip}" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 997] } {
		return "enable"
	}
	return "disable"
}
	%}
	"log fortianalyzer-cloud override-filter {anomaly forward-traffic gtp local-traffic multicast-traffic sniffer-traffic voip}" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 997] } {
		return "enable"
	}
	return "disable"
}
	%}
	"switch-controller managed-switch {mclag-igmp-snooping-aware}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
	%}
	"system central-management {fmg-update-port}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
	%}
	"system fortiguard {fortiguard-anycast fortiguard-anycast-source}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
	%}
	"system global {admin-server-cert}" = %{
if { $CLI_GET_TD } {
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return "self-sign"
	} elseif {[cli_get_devinfo "LENC"] eq "yes"} {
		return "self-sign"
	}
	if { [cli_branchpt_start 600 997] } {
		return "self-sign"
	}
	set special_plats {FortiCarrier-3810D Fortigate-100D Fortigate-1200D Fortigate-140D Fortigate-300D Fortigate-3810D}
	set plat [cli_get_devinfo "platform"]
	if { [string first "VM" $plat] != -1 || [lsearch -nocase $special_plats $plat] != -1 } {
		return "self-sign"
	}
	return "Fortinet_Factory"
}
	%}
	"system global {virtual-switch-vlan}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
	%}
	"system interface {switch-controller-igmp-snooping-proxy switch-controller-igmp-snooping-fast-leave trunk}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
	%}
	"system sdn-connector {group-name}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
	%}
	"system virtual-switch {vlan}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
	%}
	"user fsso type" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 997] } {
		set opts [cli_update_opts 1 $opts "fortiems-cloud"]
	} else {
		set opts [cli_update_opts 0 $opts "fortiems-cloud"]
	}
	return $opts
}
	%}
	"user fsso {group-poll-interval}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
	%}
	"vpn ssl settings authentication-rule {user-peer}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
	%}
	"vpn ssl settings {user-peer}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
	%}
	"wireless-controller vap {high-efficiency target-wake-time}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
	%}
	"wireless-controller wtp {radio-1 radio-2 radio-3 radio-4} vap-all" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1616] } {
		return "tunnel"
	}
	return "enable"
}
if { $CLI_GET_TN } {
	if { ![cli_branchpt_start 600 1616] } {
		return "disable enable"
	}
}
	%}
	"wireless-controller wtp {radio-1 radio-2 radio-3} band" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1055] } {
		set opts [cli_update_opts 1 $opts "802.11ax,n-only" "802.11ax" "802.11ax,n,g-only" "802.11ax-only"]
	} else {
		set opts [cli_update_opts 0 $opts "802.11ax,n-only" "802.11ax" "802.11ax,n,g-only" "802.11ax-only"]
	}
	if { [cli_branchpt_start 600 997] } {
		set opts [cli_update_opts 1 $opts "802.11ax,ac-only" "802.11ax-5G" "802.11ax,ac,n-only" "802.11ax-5G-only"]
	} else {
		set opts [cli_update_opts 0 $opts "802.11ax,ac-only" "802.11ax-5G" "802.11ax,ac,n-only" "802.11ax-5G-only"]
	}
	return $opts
}
	%}
	"wireless-controller wtp-profile platform {mode}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { $CLI_GLOBAL_DEV } { return }
	if { [cli_branchpt_start 600 1104] } {
		return "single-5G"
	}
	return "dual-5G"
}
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3} band" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1055] } {
		set opts [cli_update_opts 1 $opts "802.11ax,n-only" "802.11ax" "802.11ax,n,g-only" "802.11ax-only"]
	} else {
		set opts [cli_update_opts 0 $opts "802.11ax,n-only" "802.11ax" "802.11ax,n,g-only" "802.11ax-only"]
	}
	if { [cli_branchpt_start 600 997] } {
		set opts [cli_update_opts 1 $opts "802.11ax,ac-only" "802.11ax-5G" "802.11ax,ac,n-only" "802.11ax-5G-only"]
	} else {
		set opts [cli_update_opts 0 $opts "802.11ax,ac-only" "802.11ax-5G" "802.11ax,ac,n-only" "802.11ax-5G-only"]
	}
	return $opts
}
	%}
	"wireless-controller wtp-profile {radio-1 radio-2} channel-bonding" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 997] } {
		set opts [cli_update_opts 1 $opts "160MHz"]
	} else {
		set opts [cli_update_opts 0 $opts "160MHz"]
	}
	return $opts
}
	%}
	"wireless-controller {wtp wtp-profile} {radio-3}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 997] } {
		return 0
	}
}
	%}
	"system global gui-theme" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1006] } {
		set opts [cli_update_opts 1 $opts "neutrino"]
		set opts [cli_update_opts 0 $opts "red"]
	} else {
		set opts [cli_update_opts 0 $opts "neutrino"]
		set opts [cli_update_opts 1 $opts "red"]
	}
	return $opts
}
	%}
	"alertemail setting username" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1051] } {
		return "63"
	}
	return "35"
}
	%}
	"firewall consolidated policy {fsso-groups}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"firewall consolidated policy {global-label}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"firewall policy6 {fsso-groups}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"firewall security-policy {uuid-idx global-label}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"log eventfilter" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase "FortiFirewall*" $platform] } {
		return 0
	}
}
	%}
	"log eventfilter {compliance-check}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"log fortiguard filter {dlp-archive}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"log fortiguard override-filter {dlp-archive}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"router bgp neighbor {route-map-out6-preferable}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"router bgp neighbor-group {route-map-out6-preferable}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"switch-controller auto-config default fgt-policy" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1051] } {
		return "default"
	}
	return ""
}
	%}
	"switch-controller auto-config default icl-policy" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1051] } {
		return "default-icl"
	}
	return ""
}
	%}
	"switch-controller auto-config default isl-policy" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1051] } {
		return "default"
	}
	return ""
}
	%}
	"switch-controller flow-tracking level" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1051] } {
		set opts [cli_update_opts 1 $opts "mac"]
	} else {
		set opts [cli_update_opts 0 $opts "mac"]
	}
	return $opts
}
	%}
	"switch-controller mac-sync-settings" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"switch-controller qos dot1p-map {egress-pri-tagging}" = %{
if { $CLI_GET_TO } {
	if { $CLI_GLOBAL_DEV } { return }
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"switch-controller system {data-sync-interval}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"system central-management {ca-cert}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"system geneve" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"system global admin-https-ssl-versions" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1051] } {
		return "tlsv1-1 tlsv1-2 tlsv1-3"
	}
	return "tlsv1-1 tlsv1-2"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1051] } {
		set opts [cli_update_opts 1 $opts "tlsv1-3"]
		set opts [cli_update_opts 0 $opts "tlsv1-0"]
	} else {
		set opts [cli_update_opts 0 $opts "tlsv1-3"]
		set opts [cli_update_opts 1 $opts "tlsv1-0"]
	}
	return $opts
}
	%}
	"system global ssl-min-proto-version" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1051] } {
		set opts [cli_update_opts 1 $opts "TLSv1-3"]
	} else {
		set opts [cli_update_opts 0 $opts "TLSv1-3"]
	}
	return $opts
}
	%}
	"system global {admin-http-connection-receive-timeout compliance-check compliance-check-time}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"system interface type" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1051] } {
		set opts [cli_update_opts 1 $opts "geneve"]
	} else {
		set opts [cli_update_opts 0 $opts "geneve"]
	}
	return $opts
}
	%}
	"system np6 hpe {pri-type-max}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1232] } {
		return "200000"
	}
	return "1000000"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1232] } {
		return "1000000000,1000"
	}
	return "4000000000,10000"
}
	%}
	"system npu {priority-protocol}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"system sdn-connector nic ip {resource-group}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"system sdn-connector route-table {resource-group}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"system settings {auxiliary-session}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"system settings {compliance-check}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"system smc-ntp" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] || [cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"system snmp user auth-proto" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1051] } {
		set opts [cli_update_opts 1 $opts "sha224" "sha256" "sha512" "sha384"]
	} else {
		set opts [cli_update_opts 0 $opts "sha224" "sha256" "sha512" "sha384"]
	}
	return $opts
}
	%}
	"system stp {region-name status config-revision}" = %{
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
	if { [cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"system virtual-switch {qos}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"vpn ssl settings {hsts-include-subdomains}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"vpn ssl web portal theme" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1051] } {
		set opts [cli_update_opts 1 $opts "neutrino"]
		set opts [cli_update_opts 0 $opts "red"]
	} else {
		set opts [cli_update_opts 0 $opts "neutrino"]
		set opts [cli_update_opts 1 $opts "red"]
	}
	return $opts
}
	%}
	"wireless-controller global fiapp-eth-type" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1051] } {
		return "5252,5252"
	}
	return "65535,0"
}
	%}
	"wireless-controller global mesh-eth-type" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1051] } {
		return "8755,8755"
	}
	return "65535,0"
}
	%}
	"wireless-controller wids-profile {ap-scan-threshold}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1051] } {
		return 0
	}
}
	%}
	"wireless-controller wtp radio-1 radio-id" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1051] } {
		return "4,0"
	}
	return "2,0"
}
	%}
	"wireless-controller wtp radio-2 radio-id" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1051] } {
		return "4,0"
	}
	return "2,0"
}
	%}
	"wireless-controller wtp radio-3 radio-id" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1051] } {
		return "4,0"
	}
	return "2,0"
}
	%}
	"wireless-controller wtp-profile ext-info-enable" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1051] } {
		return "enable"
	}
	return "disable"
}
	%}
	"wireless-controller wtp-profile radio-1 radio-id" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1051] } {
		return "4,0"
	}
	return "2,0"
}
	%}
	"wireless-controller wtp-profile radio-2 radio-id" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1051] } {
		return "4,0"
	}
	return "2,0"
}
	%}
	"wireless-controller wtp-profile radio-3 radio-id" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1051] } {
		return "4,0"
	}
	return "2,0"
}
	%}
	"system interface {fortiheartbeat}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1055] } {
		return 0
	}
}
	%}
	"dpdk cpus" = %{
if { $CLI_GET_TO } {
	if { $CLI_GLOBAL_DEV } { return }
	if { ![cli_branchpt_start 600 1055] || ![cli_has_feature "f_dpdk"] } {
		return 0
	}
}
	%}
	"dpdk global" = %{
if { $CLI_GET_TO } {
	if { $CLI_GLOBAL_DEV } { return }
	if { ![cli_branchpt_start 600 1055] || ![cli_has_feature "f_dpdk"] } {
		return 0
	}
}
	%}
	"load-balance setting workers slot" = %{
if { $CLI_GET_TT } {
	namespace import global::platform_digit_suffix
	set plat [cli_get_devinfo "platform"]
	set suffix [platform_digit_suffix $plat]
	if { $suffix eq "7000E" } {
		if { [cli_branchpt_start 600 1065] } {
			return "6,3"
		}
		return "4,3"
	}
	if { $suffix eq "6000F" } {
		if { [cli_branchpt_start 600 1065] } {
			return "10,1"
		}
		return "6,1"
	}
	return $CLI_CUR_VALUE
}
	%}
	"system console-server entries port" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1065] } {
		return "60010,60001"
	}
	return "60006,60001"
}
	%}
	"system console-server entries slot-id" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1065] } {
		return "10,1"
	}
	return "6,1"
}
	%}
	"system csf configuration-sync" = %{
if { $CLI_GET_TD } {
	namespace import global::platform_digit_suffix
	set plat [cli_get_devinfo "platform"]
	set suffix [platform_digit_suffix $plat]
	if { $suffix eq "7000E" || $suffix eq "6000F" } {
		if { [cli_branchpt_start 600 1065] } {
			return "local"
		}
		return "default"
	}
	return $CLI_CUR_VALUE
}
	%}
	"firewall {policy policy6 policy64 policy46}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
   	if { [scan $CLI_CUR_VALUE "%lu,%lu,%lu" g v t] ne 3 } {
                return
        }
	set serial [cli_get_devinfo "sn"]
	if { [string first "FGVMXX" $serial] == 0 } {
		set g 10
		set v 10
	}
        return [format "%lu,%lu,%lu" $g $v $t]
}
	%}
	"user group guest id" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1066] } {
		return $CLI_CUR_VALUE
	}
	return 0
}
	%}
	"application list {force-inclusion-ssl-di-sigs}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"firewall address6 type" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1104] } {
		set opts [cli_update_opts 1 $opts "mac"]
	} else {
		set opts [cli_update_opts 0 $opts "mac"]
	}
	return $opts
}
	%}
	"firewall address6 {start-mac end-mac}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"firewall internet-service-append" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"system admin name" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1104] } {
		return "64"
	}
	return "35"
}
	%}
	"system admin {two-factor-authentication two-factor-notification}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"system central-management {interface-select-method interface}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"system dns {interface-select-method interface}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"system fortiguard {interface-select-method interface}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"system link-monitor {probe-timeout}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"system lte-modem {band-restrictions image-preference allow-modify-wireless-profile-table}" = %{
if { $CLI_GET_TO } {
	if { ![cli_has_feature "f_int_lte_modem"] || ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"system lte-modem {gps-service}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase "*30E-3G4G*" $platform] && [cli_branchpt_start 600 1232] } {
		return 0
	}
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"system lte-modem {gps-port}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase "*30E-3G4G*" $platform] && [cli_branchpt_start 600 1232] } {
		return 0
	}
}
	%}
	"system lte-modem {gpsd-enabled}" = %{
if { $CLI_GET_TO } {
	if { ![cli_has_feature "f_int_lte_modem"]  [cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"system npu {mcast-session-accounting}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"system sso-admin name" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1104] } {
		return "64"
	}
	return "35"
}
	%}
	"system vdom-dns {interface-select-method interface}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"system virtual-wan-link health-check {probe-timeout diffservcode}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"user ldap {two-factor-authentication two-factor-notification interface-select-method interface}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"user local {two-factor-authentication two-factor-notification}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"user radius accounting-server {interface-select-method interface}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"user radius {interface-select-method interface}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"user tacacs+ {interface-select-method interface}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"vpn certificate setting {ssl-ocsp-source-ip cmp-key-usage-checking}" = %{
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
		return $CLI_CUR_VALUE
	}
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"vpn l2tp {compress}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"vpn ssl settings {encode-2f-sequence}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"webfilter fortiguard cache-mem-percent" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1104] } {
		namespace import global::platform_digit_start
		set plat [cli_get_devinfo "platform"]
		if { [platform_digit_start $plat "30E"] && ![platform_digit_start $plat "100D"] } {
			return "1"
		}
	}
	return "2"
}
	%}
	"webfilter override expires" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1104] } {
		return "1969/12/31 17:00:00"
	}
	return "1969/12/31 16:00:00"
}
	%}
	"wireless-controller global data-ethernet-II" = %{
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1104] } {
		return "enable"
	}
	return "disable"
}
	%}
	"wireless-controller vap sae-groups" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1104] } {
		set opts [cli_update_opts 0 $opts "1" "29" "5" "17" "15" "2" "28" "18" "16" "27" "31" "14" "30"]
	} else {
		set opts [cli_update_opts 1 $opts "1" "29" "5" "17" "15" "2" "28" "18" "16" "27" "31" "14" "30"]
	}
	return $opts
}
	%}
	"wireless-controller wtp {radio-4}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile platform {ddscan}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-1 {band-5g-type zero-wait-dfs}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-2 {band-5g-type zero-wait-dfs}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-3 {band-5g-type zero-wait-dfs}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile {radio-4}" = %{
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1104] } {
		return 0
	}
}
	%}
	"firewall vip realservers" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	namespace import global::platform_digit_start
	set plat [cli_get_devinfo "platform"]
	set model_rank [cli_get_devinfo "model_rank"]
	if { [cli_branchpt_start 600 1104] } {
		if { [platform_digit_start $plat "FGC_3000D"] } {
			return "0,0,256"
		} elseif { [platform_digit_start $plat "FGT_1000D"] } {
			return "0,0,64"
		} elseif { [platform_digit_start $plat "FGT_100D"] } {
			return "0,0,16"
		} elseif { [platform_digit_start $plat "FGT_30E"] } {
			return "0,0,4"
		} else {
			if { $model_rank eq "VMEV" } {
				return "0,0,4"
			} elseif { $model_rank eq "1U" } {
				return "0,0,16"
			} elseif { $model_rank eq "HIGHEND" } {
				return "0,0,256"
			}
		}
	} else {
		if { [platform_digit_start $plat "FGT_1000D"] } {
			return "0,0,32"
		} elseif { [platform_digit_start $plat "FGT_100D"] } {
			return "0,0,8"
		} elseif { [platform_digit_start $plat "FGT_30E"] } {
			return "0,0,4"
		} else {
			if { $model_rank eq "VMEV" } {
				return "0,0,4"
			} elseif { $model_rank eq "1U" } {
				return "0,0,8"
			} elseif { $model_rank eq "HIGHEND" } {
				return "0,0,32"
			}
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"user local {username-case-sensitivity}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1112] || [cli_branchpt_start 600 1259] } {
		return 0
	}
}
	%}
	"system 3g-modem custom {modeswitch-string}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1136] } {
		return 0
	}
}
	%}
	"system interface {dhcp-relay-interface-select-method dhcp-relay-interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1136] } {
		return 0
	}
}
	%}
	"system npu {gtp-enhanced-mode gtp-enhanced-cpu-range}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1136] } {
		return 0
	}
}
	%}
	"system ntp ntpserver {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1136] } {
		return 0
	}
}
	%}
	"system sdn-connector route-table {subscription-id}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1136] } {
		return 0
	}
}
	%}
	"system settings {dhcp-proxy-interface-select-method dhcp-proxy-interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1136] } {
		return 0
	}
}
	%}
	"system virtual-wan-link service {member}" = %{
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1136] } {
		return 0
	}
}
	%}
	"user fsso {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1136] } {
		return 0
	}
}
	%}
	"vpn certificate setting {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1136] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1 {dhcp-ra-giaddr dhcp6-ra-linkaddr}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1136] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1-interface {dhcp-ra-giaddr dhcp6-ra-linkaddr}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1136] } {
		return 0
	}
}
	%}
	"system npu ipsec-mtu-override" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1136] && ![cli_branchpt_start 600 1142] } {
		return $CLI_CUR_VALUE
	}
	if { [cli_branchpt_start 600 1168] } {
		return $CLI_CUR_VALUE
	}
	return 0
}
	%}
	"firewall {DoS-policy DoS-policy6 sniffer} anomaly action" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	namespace import global::is_platform_support_hyperscale
	if { [is_platform_support_hyperscale] } {
		set hyperscale [cli_get_devinfo "hyperscale"]
		if { $hyperscale eq "yes" } {
			set opts [cli_update_opts 0 $opts "proxy"]
		} else {
			set opts [cli_update_opts 1 $opts "proxy"]
		}
	}
	return $opts
}
	%}
	"system npu default-qos-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	namespace import global::is_platform_support_hyperscale
	if { [is_platform_support_hyperscale] } {
		set hyperscale [cli_get_devinfo "hyperscale"]
		if { $hyperscale eq "yes" } {
			return "policing"
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"user local" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	namespace import global::platform_digit_start
	set plat [cli_get_devinfo "platform"]
	if { [platform_digit_start $plat "FGT_400E"] &&
	     ![platform_digit_start $plat "FGT_700E"] } {
		if { [cli_branchpt_start 600 1161] } {
			return "0,3000,0"
		} else {
			return "0,1000,0"
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"user group member" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 600 1161] } {
		return "0,0,3000"
	} else {
		return "0,0,2000"
	}
	return $CLI_CUR_VALUE
}
	%}
	"firewall policy {reputation-direction reputation-minimum}" = %{
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
	"emailfilter {bwl profile}" = %{
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
	"firewall {profile-group ssl-ssh-profile}" = %{
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
	"log {fortianalyzer fortianalyzer2 fortianalyzer3} setting {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1168] } {
		return 0
	}
}
	%}
	"log {fortianalyzer fortianalyzer2 fortianalyzer3} override-setting {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1168] } {
		return 0
	}
}
	%}
	"log {disk fortiguard fortianalyzer-cloud} setting {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1168] } {
		return 0
	}
}
	%}
	"log {syslogd syslogd2 syslogd3 syslogd4} setting {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1168] } {
		return 0
	}
}
	%}
	"log {syslogd syslogd2 syslogd3 syslogd4} override-setting {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1168] } {
		return 0
	}
}
	%}
	"switch-controller location {address-civic coordinates elin-number} parent-key" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1168] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch ports trunk-member" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1168] } {
		return 0
	}
}
	%}
	"credential-store domain-controller" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1168] } {
		return 0
	}
}
	%}
	"ips global packet-log-queue-depth" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1168] } {
		return 0
	}
}
	%}
	"system lte-modem {sim-auto-switch connection-auto-switch}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1168] } {
		return 0
	}
}
	%}
	"system lte-modem {sim-hot-swap connection-hot-swap}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1168] } {
		return 0
	}
}
	%}
	"vpn ssl web portal use-sdwan" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1168] } {
		return 0
	}
}
	%}
	"application list entries exclusion" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1168] } {
		return 0
	}
}
	%}
	"cifs domain-controller domain-name" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1168] } {
		return "255"
	}
	return "79"
}
	%}
	"cifs domain-controller server-name" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1168] } {
		return "255"
	}
	return "63"
}
	%}
	"cifs profile domain-controller" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1168] } {
		return "255"
	}
	return "63"
}
	%}
	"firewall profile-protocol-options cifs {server-credential-type}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1173] } {
		return 0
	}
}
	%}
	"firewall profile-protocol-options cifs {server-keytab}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1173] } {
		return 0
	}
}
	%}
	"firewall vip46 {srcintf-filter}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1173] } {
		return 0
	}
}
	%}
	"ips global {tls-active-probe}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1173] } {
		return 0
	}
}
	%}
		"monitoring npu-hpe" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1232] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch stp-instance priority" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1232] } {
		set opts [cli_update_opts 1 $opts "12328"]
		set opts [cli_update_opts 0 $opts "12288"]
	} else {
		set opts [cli_update_opts 0 $opts "12328"]
		set opts [cli_update_opts 1 $opts "12288"]
	}
	return $opts
}
	%}
	"system automation-action {accprofile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1232] } {
		return 0
	}
}
	%}
	"system global {pmtu-discovery}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1232] } {
		return 0
	}
}
	%}
	"system np6 hpe {arp-max esp-max icmp-max ip-frag-max ip-others-max l2-others-max sctp-max}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1232] } {
		return "200000"
	}
	return "1000000"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1232] } {
		return "1000000000,1000"
	}
	return "4000000000,10000"
}
	%}
	"system np6 hpe {tcp-max tcpsyn-max udp-max}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1232] } {
		return "600000"
	}
	return "5000000"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1232] } {
		return "1000000000,1000"
	}
	return "4000000000,10000"
}
	%}
	"system np6 hpe {tcpsyn-ack-max tcpfin-rst-max}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1232] } {
		return 0
	}
}
	%}
	"system npu {uesp-offload}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1232] } {
		return 0
	}
}
	%}
	"load-balance setting {ipsec-load-balance}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set platform [cli_get_devinfo "platform"]
	if { ![string match -nocase $platform "FortiGate-6000F"] &&
	     ![string match -nocase $platform "FortiGate-7000E"] &&
	     ![string match -nocase $platform "FortiCarrier-6000F"] &&
	     ![string match -nocase $platform "FortiCarrier-7000E"] } {
		return 0
	}
	if { [cli_branchpt_start 600 1158] } {
		return 0
	}
}
	%}
	"system auto-script script" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1259] } {
		return "1023"
	}
	return "255"
}
	%}
	"system interface {dhcp-relay-request-all-server}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1259] } {
		return 0
	}
}
	%}
	"user local {username-sensitivity}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1259] } {
		return 0
	}
}
	%}
	"wireless-controller vap {port-macauth port-macauth-timeout port-macauth-reauth-timeout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1259] } {
		return 0
	}
}
	%}
	"system npu hpe {tcp-max tcpsyn-max udp-max}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { ![cli_branchpt_start 600 1190] } {
		return "125000"
	} elseif { ![cli_branchpt_start 600 1232] } {
		return "600000"
	} else {
		return "40000"
	}
}
if { $CLI_GET_TT } {
	if { ![cli_branchpt_start 600 1190] } {
		return "1000000000,1000"
	} else {
		return "40000000,1000"
	}
}
	%}
	"system npu hpe {arp-max esp-max icmp-max ip-frag-max ip-others-max l2-others-max pri-type-max sctp-max}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { ![cli_branchpt_start 600 1232] } {
		return "40000"
	} else {
		return "20000"
	}
}
if { $CLI_GET_TT } {
	if { ![cli_branchpt_start 600 1190] } {
		return "1000000000,1000"
	} else {
		return "40000000,1000"
	}
}
	%}
	"system npu hpe {all-protocol}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1190] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { ![cli_branchpt_start 600 1232] } {
		return "10000000"
	} else {
		return "400000"
	}
}
	%}
	"system npu hpe {high-priority}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1190] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { ![cli_branchpt_start 600 1232] } {
		return "10000000"
	} else {
		return "400000"
	}
}
if { $CLI_GET_TT } {
	if { ![cli_branchpt_start 600 1232] } {
		return "40000000,0"
	} else {
		return "40000000,1000"
	}
}
	%}
	"system npu hpe {tcpsyn-ack-max tcpfin-rst-max}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1190] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { ![cli_branchpt_start 600 1232] } {
		return "600000"
	} else {
		return "40000"
	}
}
	%}
	"report setting {pdf-report fortiview}" = %{
if { $CLI_GET_TD } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiCarrier-3000D"] ||
	     [string match -nocase $platform "Fortigate-3000D"] ||
	     [string match -nocase $platform "Fortigate-81E-POE"] } {
		if { ![cli_branchpt_start 600 1232] } {
			return "enable"
		}
	}
}
	%}
%};
