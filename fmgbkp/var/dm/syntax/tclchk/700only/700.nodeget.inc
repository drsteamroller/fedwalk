nodeget %{
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
set max_cpu_num [cli_get_devinfo "cpu_limit"]
if { $CLI_GET_TT } {
	set cpu [expr (($max_cpu_num +9)/10)]
	if { $cpu > 10 } {
		set cpu 10
	}
	return "$cpu,1"
}
	%}
	"system global scanunit-count" = %{
if { $CLI_GLOBAL_DEV } { return }
set cpu [cli_get_devinfo "cpu_limit"]
if { $cpu eq "0" } { return }
if { $CLI_GET_TT } {
	return "$cpu,1"
}
	%}
	"system global proxy-worker-count" = %{
if { $CLI_GLOBAL_DEV } { return }
set cpu [cli_get_devinfo "cpu_limit"]
if { $cpu eq "0" } { return }
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
	"system replacemsg {mail http webproxy ftp nntp fortiguard-wf spam im alertmail admin sslvpn ec nac-quar traffic-quota mms device-detection-portal utm auth captive-portal-dflt mm1 mm3 mm4 mm7 icap automation} {buffer smil-part message html-part rsp-text subject from domain}" = %{
if { $CLI_GET_TD } {
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		set item [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
		return [cli_replmsg_defval $CLI_CUR_PARENT_NAME $item $CLI_CUR_NODE_NAME]
	}
}
	%}
	"system replacemsg {mail http webproxy ftp nntp fortiguard-wf spam im alertmail admin sslvpn ec nac-quar traffic-quota mms device-detection-portal utm auth captive-portal-dflt mm1 mm3 mm4 mm7 icap automation} {header format rsp-status class priority from-sender sender-visibility add-smil charset add-html addr-type allow-content-adaptation}" = %{
if { $CLI_GET_TD } {
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		set item [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
		set msg [cli_replmsg_defval $CLI_CUR_PARENT_NAME $item $CLI_CUR_NODE_NAME]
		return [string trim $msg \"]
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
	"system resource-limits webproxy" = %{
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
	"system resource-limits proxy" = %{
if { $CLI_GET_TD } {
	namespace import global::platform_digit_start
	set d [cli_feature_value "webproxy_user_limits"]
	if { $d > 0 } {
		set plat [cli_get_devinfo "platform"]
		set plats_3k "FortiGate-3000D FortiGate-3100D FortiGate-3200D FortiGate-3700D FortiGate-3800D FortiGate-3810D FortiGate-3815D FortiGate-5001D"
		if { ![cli_branchpt_start 700 233] } {
			if { [platform_digit_start $plat "FGT_3000D"] } {
				if { [lsearch -nocase [split $plats_3k " "] $plat] != -1 } {
					return "64000"
				}
			} elseif { [platform_digit_start $plat "FGT_1000D"] } {
				return "16000"
			} elseif { [platform_digit_start $plat "FGT_100D"]   } {
				return "8000"
			}
		}
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
if { $CLI_GET_TN } {
	namespace import global::ncfg_is_fapc_platform
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
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
	if { [cli_get_devinfo "LENC"] eq "yes" } {
		return 0
	}
}
	%}
	"system central-management enc-algorithm" = %{
if { $CLI_GET_TD } {
	if { [cli_get_devinfo "LENC"] eq "yes" } {
		return "low"
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
	if { [cli_get_devinfo "LENC"] eq "yes" } {
		return "des-md5 des-sha1 des-sha256 des-sha384 des-sha512"
	}
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
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
if { $CLI_GET_TN } {
	if { [cli_get_devinfo "LENC"] eq "yes" } {
		return "null-md5 null-sha1 null-sha256 null-sha384 null-sha512 des-null des-md5 des-sha1 des-sha256 des-sha384 des-sha512"
	}
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return "aes128-sha1 aes128-sha256 aes128-sha384 aes128-sha512 aes128gcm aes256-sha1 aes256-sha256 aes256-sha384 aes256-sha512 aes256gcm"
	}
}
if { $CLI_GET_ND } {
	return 1
}
	%}
	"vpn ipsec manualkey authentication" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "sha256"
	}
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "null" "md5"]
	}
}
	%}
	"vpn ipsec manualkey encryption" = %{
if { $CLI_GET_TN } {
	if { [cli_get_devinfo "LENC"] eq "yes" } {
		return "null des"
	}
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return "3des aes128 aes192 aes256"
	}
}
if { $CLI_GET_TD } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
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
if { $CLI_GET_TN } {
	if { [cli_get_devinfo "LENC"] eq "yes" } {
		return "des-md5 des-sha1 des-sha256 des-sha384 des-sha512"
	}
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
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
if { $CLI_GET_TN } {
	if { [cli_get_devinfo "LENC"] eq "yes" } {
		return "null-md5 null-sha1 null-sha256 null-sha384 null-sha512 des-null des-md5 des-sha1 des-sha256 des-sha384 des-sha512"
	}
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return "aes128-sha1 aes128-sha256 aes128-sha384 aes128-sha512 aes128gcm aes256-sha1 aes256-sha256 aes256-sha384 aes256-sha512 aes256gcm"
	}
}
if { $CLI_GET_ND } {
	return 1
}
	%}
	"vpn ipsec manualkey-interface auth-alg" = %{
if { $CLI_GET_TN } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "null" "md5"]
	}
}
if { $CLI_GET_TD } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return "sha1"
	}
}
	%}
	"vpn ipsec manualkey-interface enc-alg" = %{
if { $CLI_GET_TN } {
	if { [cli_get_devinfo "LENC"] eq "yes" } {
		return "null des"
	}
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return "3des aes128 aes192 aes256"
	}
}
if { $CLI_GET_TD } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return "3des"
	}
}
	%}
	"log {fortiguard fortianalyzer fortianalyzer2 fortianalyzer3} {setting override-setting} enc-algorithm" = %{
if { $CLI_GET_TD } {
	if { [cli_get_devinfo "LENC"] eq "yes" } {
		return "low"
	}
}
	%}
	"system fips-cc status" = %{
if { $CLI_GET_TO } {
	if { [cli_get_devinfo "LENC"] eq "yes" } {
		return 0
	}
}
	%}
	"system fortisandbox enc-algorithm" = %{
if { $CLI_GET_TD } {
	if { [cli_get_devinfo "LENC"] eq "yes" } {
		return "low"
	}
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return "high"
	}
}
	%}
	"system global alarm-poll-interval" = %{
if { $CLI_GET_TO } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return $CLI_CUR_VALUE
	}
	return 0
}
	%}
	"system global strong-crypto" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_RD } {
		return 1
	}
}
	%}
	"system global dh-params" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "3072"
	}
}
	%}
	"system global fds-statistics" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "disable"
	}
}
	%}
	"system global post-login-banner" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "enable"
	}
}
	%}
	"system global tftp" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "disable"
	}
}
	%}
	"system global check-reset-range" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "strict"
	}
}
	%}
	"system global admin-ssh-v1" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_RD } {
		return 1
	}
}
	%}
	"system global {user-server-cert auth-cert}" = %{
if { $CLI_GET_TD } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return "self-sign"
	} elseif { [cli_get_devinfo "LENC"] eq "yes" } {
		return "self-sign"
	}
}
	%}
	"wireless-controller vap encrypt" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "TKIP" "TKIP-AES"]
	}
}
	%}
	"system interface allowaccess" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
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
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "speed-test"]
	} else {
		set opts [cli_update_opts 0 $opts "speed-test"]
	}
	return $opts
}
	%}
	"system interface ipv6 ip6-allowaccess" = %{
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
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
	return $opts
}
	%}
	"system interface secondaryip allowaccess" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
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
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "speed-test"]
	} else {
		set opts [cli_update_opts 0 $opts "speed-test"]
	}
	return $opts
}
	%}
	"system ha {encryption authentication}" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "enable"
	} elseif { $CLI_GET_RD } {
		return 1
	}
}
	%}
	"web-proxy explicit ssl-algorithm" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "medium" "low"]
	}
}
	%}
	"user setting auth-type" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "http https"
	}
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "ftp" "telnet"]
	}
}
	%}
	"user setting auth-secure-http" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "enable"
	}
}
	%}
	"user setting auth-lockout-duration" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "60"
	}
}
	%}
	"vpn ssl settings algorithm" = %{
if { [cli_get_devinfo "LENC"] eq "yes" } {
	if { $CLI_GET_TO } {
		return 0
	}
}
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "default" "low"]
	}
}
	%}
	"vpn ssl settings authentication-rule cipher" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_RD } {
		return 1
	}
}
if { [cli_get_devinfo "LENC"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "any"
	}
}
	%}
	"webfilter {override-user ftgd-warning} expires" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "1969/12/31 17:00:00"
	}
}
	%}
	"vpn ipsec {phase1 phase2 phase1-interface phase2-interface} dhgrp" = %{
if { $CLI_GET_TD } {
	if { $CLI_GLOBAL_DEV } { 
		return "14 5"
	}
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return "15"
	}
	return $CLI_CUR_VALUE
}
	%}
	"wanopt settings tunnel-ssl-algorithm" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "medium" "low"]
	}
}
	%}
	"firewall vip ssl-cipher-suites cipher" = %{
if { $CLI_GET_TN } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return "TLS-DHE-RSA-WITH-AES-128-CBC-SHA TLS-DHE-RSA-WITH-AES-256-CBC-SHA TLS-DHE-RSA-WITH-AES-128-CBC-SHA256 TLS-DHE-RSA-WITH-AES-128-GCM-SHA256 TLS-DHE-RSA-WITH-AES-256-CBC-SHA256 TLS-DHE-RSA-WITH-AES-256-GCM-SHA384 TLS-DHE-DSS-WITH-AES-128-CBC-SHA TLS-DHE-DSS-WITH-AES-256-CBC-SHA TLS-DHE-DSS-WITH-AES-128-CBC-SHA256 TLS-DHE-DSS-WITH-AES-128-GCM-SHA256 TLS-DHE-DSS-WITH-AES-256-CBC-SHA256 TLS-DHE-DSS-WITH-AES-256-GCM-SHA384 TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256 TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256 TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384 TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384 TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256 TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256 TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384 TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384 TLS-RSA-WITH-AES-128-CBC-SHA TLS-RSA-WITH-AES-256-CBC-SHA TLS-RSA-WITH-AES-128-CBC-SHA256 TLS-RSA-WITH-AES-128-GCM-SHA256 TLS-RSA-WITH-AES-256-CBC-SHA256 TLS-RSA-WITH-AES-256-GCM-SHA384 TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA TLS-RSA-WITH-3DES-EDE-CBC-SHA"
	}
	if { [cli_get_devinfo "LENC"] eq "yes" } {
		return "TLS-RSA-WITH-3DES-EDE-CBC-SHA TLS-DHE-RSA-WITH-DES-CBC-SHA TLS-DHE-DSS-WITH-DES-CBC-SHA"
	}
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"]
	} else {
		set opts [cli_update_opts 0 $opts "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"]
	}
	return $opts
}
	%}
	"firewall ssl-server ssl-algorithm" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "medium" "low"]
	}
}
	%}
	"firewall {policy64 policy46 explicit-proxy-policy multicast-policy multicast-policy6 interface-policy interface-policy6 DoS-policy DoS-policy6 central-snat-map} status" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "disable"
	}
}
	%}
	"firewall {policy policy6} status" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "disable"
	}
}
	%}
	"firewall {policy6 explicit-proxy-policy interface-policy interface-policy6 sniffer} logtraffic" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "all"
	}
}
	%}
	"firewall policy logtraffic" = %{
if { $CLI_GET_TD } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
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
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "enable"
	}
}
	%}
	"firewall {policy64 policy46} logtraffic" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "enable"
	}
}
	%}
	"firewall explicit-proxy-policy identity-based-policy logtraffic" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "all"
	}
}
	%}
	"firewall explicit-proxy-policy identity-based-policy logtraffic-start" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "enable"
	}
}
	%}
	"log {syslogd syslogd2 syslogd3 syslogd4} {setting override-setting} reliable" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "enable"
	}
}
	%}
	"log {syslogd syslogd2 syslogd3 syslogd4} {setting override-setting} port" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "601"
	}
}
	%}
	"log disk setting diskfull" = %{
if { $CLI_GET_TD } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return "blocktraffic"
	}
}
if { $CLI_GET_TN } {
	if { [cli_get_devinfo "FIPS"] ne "yes" } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "blocktraffic"]
	}
}
	%}
	"log {syslogd syslogd2 syslogd3 syslogd4 webtrends memory disk fortiguard null-device fortianalyzer fortianalyzer2 fortianalyzer3} {filter filter-type}" = %{
if { $CLI_GET_TO } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return 0
	}
}
	%}
	"log {syslogd fortiguard fortianalyzer} override-filter {filter filter-type}" = %{
if { $CLI_GET_TO } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return 0
	}
}
	%}
	"router rip interface auth-mode" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "md5"]
	}
}
	%}
	"router ospf area authentication" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "md5"]
	}
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "message-digest"]
		set opts [cli_update_opts 0 $opts "md5"]
	} else {
		set opts [cli_update_opts 0 $opts "message-digest"]
		set opts [cli_update_opts 1 $opts "md5"]
	}
	return $opts
}
	%}
	"router ospf area virtual-link authentication" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "md5"]
	}
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "message-digest"]
		set opts [cli_update_opts 0 $opts "md5"]
	} else {
		set opts [cli_update_opts 0 $opts "message-digest"]
		set opts [cli_update_opts 1 $opts "md5"]
	}
	return $opts
}
	%}
	"router ospf ospf-interface authentication" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "md5"]
	}
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "message-digest"]
		set opts [cli_update_opts 0 $opts "md5"]
	} else {
		set opts [cli_update_opts 0 $opts "message-digest"]
		set opts [cli_update_opts 1 $opts "md5"]
	}
	return $opts
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
	if { [cli_get_devinfo "hdd"] eq "yes" } {
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
if { $CLI_GET_RV } {
	if { $CLI_CUR_NODE_NAME eq "wireless-controller vap" && [cli_reserved_value_is "wifi"] } {
		set platform [cli_get_devinfo "platform"]
		if { ![string match -nocase "FortiWiFi-40F*" $platform] && ![string match -nocase "FortiWiFi-60E*" $platform] && ![string match -nocase $platform "FortiWiFi-60F"] && ![string match -nocase $platform "FortiWiFi-61E"] && ![string match -nocase $platform "FortiWiFi-61F"] && ![string match -nocase $platform "FortiWiFi-80F-2R"] && ![string match -nocase "FortiWiFi-81F*" $platform] } {
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
	"firewall policy {utm-status action scan-botnet-connections}" = %{
if { $CLI_GET_TD } {
	if { $CLI_IS_RESYNC && $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "learning-mode"] eq "enable" } {
			set a $CLI_CUR_NODE_NAME
			if { $a eq "utm-status" } {
				return "enable"
			} elseif { $a eq "action" } {
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
	"wireless-controller {inter-controller vap global setting log bonjour-profile region wids-profile ble-profile vap-group wtp-profile wtp-group qos-profile utm-profile snmp ap-status}" = %{
if { $CLI_GLOBAL_DEV } {
	if { $CLI_GET_RV } {
		if { $CLI_CUR_NODE_NAME eq "wireless-controller vap" && [cli_reserved_value_is "wifi"] } {
			return 0
		}
	}
	return 
}
	%}
	"firewall consolidated policy" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	set serial [cli_get_devinfo "sn"]
	if { [string first "FGVMXX" $serial] == 0 } {
		return "10,10,0"
	}
	return $CLI_CUR_VALUE
}
	%}
	"system interface forward-error-correction" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_ND } {
	if { ![cli_branchpt_start 700 276] } {
		return 0
	}
	return $CLI_CUR_VALUE
}
if { $CLI_GET_TD } {
	namespace import global::platform_digit_suffix
	set suffix [platform_digit_suffix [cli_get_devinfo "platform"]]
	if { [cli_branchpt_start 700 276] } {
		if { $CLI_SUPPORT_CDB_OPS } {
			cli_skip_cache
			## new option is "disable cl91-rs-fec cl74-fc-fec"
			namespace import global::sys_intf_is_media_iface
			set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
			set ifname [string trim $ifname \"]
			if { [sys_intf_is_media_iface $ifname]  } {
				set speed [cli_get_value $CLI_CUR_PARENT_NODE "" "" "speed"]
				if { $speed eq "25000full" || $speed eq "25000auto" || $speed eq "100Gfull" } {
					return "cl91-rs-fec"
				}
			}
			return "none"
		}
	} else {
		## old option is "enable disable"
		if { [regexp -nocase {1100E|1101E|2200E|2201E|3300E|3301E|3960E|3980E} $suffix] } {
			return "enable"
		}
		if { [regexp -nocase {3400E|3401E|3600E|3601E} $suffix] } {
			return "disable"
		}
	}
	return $CLI_CUR_VALUE
}
if { $CLI_GET_TN } {
	namespace import global::platform_digit_suffix
	set platform [cli_get_devinfo "platform"]
	set suffix [platform_digit_suffix $platform]
	if { [regexp -nocase {6000F|7000E|7000F} $suffix] } {
		if { $CLI_SUPPORT_CDB_OPS } {
			namespace import global::sys_intf_is_media_iface
			namespace import global::sys_intf_forward_error_correction_option
			set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
			set ifname [string trim $ifname \"]
			set speed [cli_get_value $CLI_CUR_PARENT_NODE "" "" "speed"]
			set mediatype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mediatype"]
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
		return $CLI_CUR_VALUE
	}
	if { [cli_branchpt_start 700 276] } {
		return "disable cl91-rs-fec cl74-fc-fec"
	} else {
		return "disable enable"
	}
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
	return $opts
}
	%}
	"firewall policy" = %{
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
	"firewall policy6" = %{
if { $CLI_GET_TO } {
	return 0
}
	%}
	"global header policy6" = %{
if { $CLI_GET_TO } {
	return 0
}
	%}
	"global footer policy6" = %{
if { $CLI_GET_TO } {
	return 0
}
	%}
	"firewall shaping-policy class-id" = %{
if { $CLI_GET_TT } {
	return "4294967295,0"
}
if { $CLI_GET_TD } {
	return "0"
}
	%}
	"firewall shaping-profile default-class-id" = %{
if { $CLI_GET_TT } {
	return "4294967295,0"
}
if { $CLI_GET_TD } {
	return "0"
}
	%}
	"firewall shaping-profile shaping-entries class-id" = %{
if { $CLI_GET_TT } {
	return "4294967295,0"
}
if { $CLI_GET_TD } {
	return "0"
}
	%}
	"firewall shaper traffic-shaper {exceed-class-id}" = %{
if { $CLI_GET_TT } {
	return "4294967295,0"
}
if { $CLI_GET_TD } {
	return "0"
}
	%}
    "firewall address" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_RV } {
	if { [cli_reserved_value_is "metadata-server"] } {
		set platform [cli_get_devinfo "platform"]
		if { ![string match -nocase $platform "FortiCarrier-VM64-AWS"] && 
		     ![string match -nocase $platform "Fortigate-VM64-AWS"] && 
		     ![string match -nocase $platform "FortiCarrier-VM64-AWSONDEMAND"] && 
		     ![string match -nocase $platform "Fortigate-VM64-AWSONDEMAND"] &&
		     ![string match -nocase $platform "Fortigate-ARM64-AWS"] &&  } {
			return 0
		}
	}
}
if { $CLI_GET_TM } {
	set plat [cli_get_devinfo "platform"]
	if { [cli_get_devinfo "VM"] eq "yes" } {
		set model_rank [cli_get_devinfo "model_rank"]
		if { $model_rank eq "HIGHEND"|| $model_rank eq "" } {
			if { [cli_branchpt_start 700 218] } {
				return "500000,100000,0"
			}
			return "100000,100000,0"
		}
	}
	namespace import global::platform_digit_between
	if { [platform_digit_between $plat "3600E" "5001E"] } {
			if { [cli_branchpt_start 700 218] } {
				return "500000,200000,0"
			}
			return "200000,200000,0"
	}
}
	%}
	"emailfilter profile mapi action" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_ND } {
	return 1
}
	%}
	"system vdom-exception object" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "system.gre-tunnel"]
		set opts [cli_update_opts 0 $opts "firewall.vip46" "firewall.vip64"]
	} else {
		set opts [cli_update_opts 0 $opts "system.gre-tunnel"]
		set opts [cli_update_opts 1 $opts "firewall.vip46" "firewall.vip64"]
	}
	return $opts
}
	%}
	"wireless-controller arrp-profile" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 267] } {
		return "0,32,0"
	} else {
		return "0,1,0"
	}
	return $CLI_CUR_VALUE
}
	%}
	"antivirus profile {cifs ftp http imap mapi nntp pop3 smtp ssh} fortiai" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
	if { [cli_branchpt_start 700 410] } {
		return 0
	}
	return 1
}
	%}
	"antivirus profile {external-blocklist-archive-scan}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"antivirus profile {fortiai-error-action}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
	if { [cli_branchpt_start 700 410] } {
		return 0
	}
	return 1
}
	%}
	"antivirus quarantine {drop-heuristic store-heuristic}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"antivirus quarantine {drop-machine-learning store-machine-learning}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"authentication scheme {user-cert}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"authentication setting {cert-auth cert-captive-portal cert-captive-portal-ip cert-captive-portal-port}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"endpoint-control fctems capabilities" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 296] } {
		set opts [cli_update_opts 1 $opts "common-tags-api"]
	} else {
		set opts [cli_update_opts 0 $opts "common-tags-api"]
	}
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "push-ca-certs" "websocket-malware"]
	} else {
		set opts [cli_update_opts 0 $opts "push-ca-certs" "websocket-malware"]
	}
	return $opts
}
	%}
	"endpoint-control fctems {preserve-ssl-session}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall access-proxy api-gateway ldb-method" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 0 $opts "least-rtt" "least-session"]
	} else {
		set opts [cli_update_opts 1 $opts "least-rtt" "least-session"]
	}
	return $opts
}
	%}
	"firewall access-proxy api-gateway realservers port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "443"
	}
	return "0"
}
	%}
	"firewall access-proxy api-gateway realservers {holddown-interval}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall access-proxy api-gateway service" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "https"
	}
	return ""
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 288] } {
		set opts [cli_update_opts 1 $opts "web-portal"]
	} else {
		set opts [cli_update_opts 0 $opts "web-portal"]
	}
	return $opts
}
	%}
	"firewall access-proxy6 api-gateway service" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 288] } {
		set opts [cli_update_opts 1 $opts "web-portal"]
	} else {
		set opts [cli_update_opts 0 $opts "web-portal"]
	}
	return $opts
}
	%}
	"firewall access-proxy api-gateway ssl-algorithm" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 0 $opts "custom"]
	} else {
		set opts [cli_update_opts 1 $opts "custom"]
	}
	return $opts
}
	%}
	"firewall access-proxy api-gateway ssl-cipher-suites cipher" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"]
	} else {
		set opts [cli_update_opts 0 $opts "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"]
	}
	return $opts
}
	%}
	"firewall access-proxy empty-cert-action" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "block"
	}
	return "accept"
}
	%}
	"firewall access-proxy realservers port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "443"
	}
	return "0"
}
	%}
	"firewall address sub-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 267] } {
		set opts [cli_update_opts 1 $opts "fortivoice-tag" "fortinac-tag"]
	} else {
		set opts [cli_update_opts 0 $opts "fortivoice-tag" "fortinac-tag"]
	}
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "swc-tag"]
	} else {
		set opts [cli_update_opts 0 $opts "swc-tag"]
	}
	return $opts
}
	%}
	"firewall central-snat-map {nat46 nat64}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall gtp {rat-timeout-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall {ippool ippool6} {nat64 add-nat64-route}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall pfcp" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall policy {uuid-idx nat64 nat46 sctp-filter-profile pfcp-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall policy46" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall policy64" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall profile-group {sctp-filter-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall proxy-policy {uuid-idx sctp-filter-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall security-policy {sctp-filter-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall service custom helper" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "pfcp"]
	} else {
		set opts [cli_update_opts 0 $opts "pfcp"]
	}
	return $opts
}
	%}
	"firewall ssl-ssh-profile {dot ftps https imaps pop3s smtps ssl} {unsupported-ssl-version}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 276] } {
		return "block"
	}
	return "allow"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 276] } {
		set opts [cli_update_opts 0 $opts "inspect"]
	} else {
		set opts [cli_update_opts 1 $opts "inspect"]
	}
	return $opts
}
	%}
	"firewall ssl-ssh-profile ssl {cert-probe-failure}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall vendor-mac {obsolete}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall vip realservers ip" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "::"
	}
	return "0.0.0.0"
}
	%}
	"firewall vip ssl-server-cipher-suites cipher" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"]
	} else {
		set opts [cli_update_opts 0 $opts "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"]
	}
	return $opts
}
	%}
	"firewall vip {nat44 nat46 add-nat46-route ipv6-mappedip ipv6-mappedport}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall vip46" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall vip6 ssl-cipher-suites cipher" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"]
	} else {
		set opts [cli_update_opts 0 $opts "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"]
	}
	return $opts
}
	%}
	"firewall vip6 ssl-server-cipher-suites cipher" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"]
	} else {
		set opts [cli_update_opts 0 $opts "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"]
	}
	return $opts
}
	%}
	"firewall vip6 {nat66 nat64 add-nat64-route embedded-ipv4-address ipv4-mappedip ipv4-mappedport}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall vip64" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall vipgrp46" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall vipgrp64" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"gtp rat-timeout-profile" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"icap profile {icap-block-log}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	} 
}
	%}
	"log disk setting uploadtype" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 290] } {
		set opts [cli_update_opts 0 $opts "ztna"]
	} else {
		set opts [cli_update_opts 1 $opts "ztna"]
	}
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "ztna"]
	} else {
		set opts [cli_update_opts 0 $opts "ztna"]
	}
	return $opts
}
	%}
	"log {disk fortianalyzer fortianalyzer-cloud fortianalyzer2 fortianalyzer3 fortiguard memory null-device syslogd syslogd2 syslogd3 syslogd4 webtrends} filter free-style category" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "ztna"]
	} else {
		set opts [cli_update_opts 0 $opts "ztna"]
	}
	return $opts
}
	%}
	"log {fortianalyzer fortianalyzer-cloud fortianalyzer2 fortianalyzer3 fortiguard syslogd syslogd2 syslogd3 syslogd4} override-filter free-style category" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
		if { [cli_branchpt_start 700 290] } {
		set opts [cli_update_opts 0 $opts "ztna"]
	} else {
		set opts [cli_update_opts 1 $opts "ztna"]
	}
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "ztna"]
	} else {
		set opts [cli_update_opts 0 $opts "ztna"]
	}
	return $opts
}
	%}
	"log {disk fortianalyzer fortianalyzer-cloud fortianalyzer2 fortianalyzer3 fortiguard memory null-device syslogd syslogd2 syslogd3 syslogd4 webtrends} filter {ztna-traffic}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 290] } {
		return 0
	}
}
	%}
	"log {fortianalyzer fortianalyzer-cloud fortianalyzer2 fortianalyzer3 fortiguard syslogd syslogd2 syslogd3 syslogd4} override-filte {ztna-traffic}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 290] } {
		return 0
	}
}
	%}
	"log threat-weight malware {fortiai}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
	if { [cli_branchpt_start 700 410] } {
		return 0
	}
	return 1
}
	%}
	"pfcp message-filter" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"router bgp neighbor {conditional-advertise6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"router bgp {vrf-leak6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"router key-chain key key-string" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 133] } {
		return "60"
	}
	return "35"
}
	%}
	"router key-chain key {algorithm}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"router ospf area virtual-link {keychain}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"router ospf area virtual-link {md5-keychain}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"router ospf ospf-interface {keychain}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"router ospf ospf-interface {md5-keychain}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"router static {sdwan-zone}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"router static {sdwan}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"router static6 {sdwan-zone}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"router static6 {sdwan}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"router static6 {vrf}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"sctp-filter profile" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"switch-controller fortilink-settings nac-ports {lan-segment nac-lan-interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"switch-controller fortilink-settings nac-ports {nac-segment-vlans}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"switch-controller global {dhcp-server-access-list}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0 
	}
}
	%}
	"switch-controller initial-config vlans default-vlan" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "_default"
	}
	return "default"
}
	%}
	"switch-controller initial-config vlans {nac-segment}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch ports {poe-standard poe-max-power}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch {dhcp-server-access-list}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system accprofile fwgrp-permission {others}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system cluster-sync {ike-seqjump-speed slave-add-ike-routes}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"system cluster-sync {secondary-add-ipsec-routes}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system dns {server-select-method alt-primary alt-secondary}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system dns64" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system fortiai" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
	if { [cli_branchpt_start 700 410] } {
		return 0
	}
	return 1
}
	%}
	"system global {pmtu-discovery speedtest-server ha-affinity cmdbsvr-affinity virtual-switch-vlan}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system gre-tunnel {sequence-number-transmission sequence-number-reception checksum-transmission checksum-reception key-outbound key-inbound}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system interface switch-controller-feature" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "nac-segment"]
	} else {
		set opts [cli_update_opts 0 $opts "nac-segment"]
	}
	return $opts
}
	%}
	"system interface {dhcp-classless-route-addition sw-algorithm trunk}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system interface {dhcp-snooping-server-list}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system isf-queue-profile {burst-bps-granularity burst-pps-granularity}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system isf-queue-profile {burst-control}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"system link-monitor http-get" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "/"
	}
	return ""
}
	%}
	"system link-monitor {server-config fail-weight update-policy-route}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system link-monitor {server-list}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system nat64" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"system netflow {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system npu {dedicated-management-affinity dedicated-management-cpu}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system npu {sw-eh-hash}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system physical-switch port {speed status}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"system saml service-providers sp-binding-protocol" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "post"
	}
	return "redirect"
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
			     [string match -nocase $platform "Fortigate-VM64-AWSONDEMAND"] ||
			     [string match -nocase $platform "FortiCarrier-ARM64-AWS"] ||
			     [string match -nocase $platform "Fortigate-ARM64-AWS"] } {
				return "enable"
			}
		} elseif { $type eq "oci" } {
			set platform [cli_get_devinfo "platform"]
			if { [string match -nocase $platform "FortiCarrier-VM64-OPC"] ||
			     [string match -nocase $platform "Fortigate-VM64-OPC"] ||
			     [string match -nocase $platform "FortiCarrier-ARM64-OPC"] ||
			     [string match -nocase $platform "Fortigate-ARM64-OPC"] } {
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
	"system sdn-connector {verify-certificate}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system sdwan health-check http-get" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "/"
	}
	return ""
}
	%}
	"system sdwan neighbor {mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system sdwan service {priority-zone}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system sdwan {speedtest-bypass-routing}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system session-helper name" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "pfcp"]
	} else {
		set opts [cli_update_opts 0 $opts "pfcp"]
	}
	return $opts
}
	%}
	"system settings {gui-nat46-64}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"system settings {pfcp-monitor-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system sflow {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system snmp sysinfo engine-id" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 133] } {
		return "54"
	}
	return "24"
}
	%}
	"system snmp sysinfo {engine-id-type}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system speed-test-schedule interface" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 133] } {
		return "35"
	}
	return "15"
}
	%}
	"system speed-test-schedule {dynamic-server}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system vdom-dns {server-select-method alt-primary alt-secondary}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"system vdom-netflow {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0 
	}
}
	%}
	"system vdom-sflow {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0 
	}
}
	%}
	"system virtual-switch port {speed status mediatype}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"system virtual-switch {vlan}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"user certificate" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"user fsso {logon-timeout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"user local {username-case-sensitivity}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"user local {username-sensitivity}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"user nac-policy {firewall-address}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"videofilter profile fortiguard-category filters action" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "monitor"
	}
	return "bypass"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "allow"]
		set opts [cli_update_opts 0 $opts "bypass"]
	} else {
		set opts [cli_update_opts 0 $opts "allow"]
		set opts [cli_update_opts 1 $opts "bypass"]
	}
	return $opts
}
	%}
	"videofilter profile {replacemsg-group}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"videofilter profile {youtube-restrict vimeo-restrict}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"videofilter youtube-channel-filter entries action" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "monitor"
	}
	return "bypass"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "allow"]
		set opts [cli_update_opts 0 $opts "bypass"]
	} else {
		set opts [cli_update_opts 0 $opts "allow"]
		set opts [cli_update_opts 1 $opts "bypass"]
	}
	return $opts
}
	%}
	"videofilter youtube-channel-filter {default-action log}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"videofilter youtube-key" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"vpn certificate setting {crl-verification}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"vpn certificate setting {strict-crl-check}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"vpn ipsec concentrator {id}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"vpn l2tp {hello-interval}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"vpn ocvpn overlays {assign-ip ipv4-start-ip ipv4-end-ip}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"vpn ocvpn {auto-discovery-shortcut-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"vpn ssl client {realm}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"vpn ssl settings {saml-redirect-port}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"vpn ssl web portal allow-user-access" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "web ftp smb sftp telnet ssh vnc rdp ping"
	}
	return "web ftp smb sftp telnet ssh vnc rdp ping citrix portforward"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 0 $opts "citrix" "portforward"]
	} else {
		set opts [cli_update_opts 1 $opts "citrix" "portforward"]
	}
	return $opts
}
	%}
	"vpn ssl web portal bookmark-group bookmarks preconnection-id" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "0"
	}
	return "2147483648"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 133] } {
		return "4294967295,0"
	}
	return "2147483648,0"
}
	%}
	"vpn ssl web portal bookmark-group bookmarks {send-preconnection-id restricted-admin color-depth}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"vpn ssl web portal bookmark-group bookmarks {listening-port remote-port show-status-window server-layout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"vpn ssl web portal use-sdwan" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] && ![cli_branchpt_start 700 182] } {
		return "enable"
	}
	return "disable"
}
	%}
	"vpn ssl web portal {clipboard}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"vpn ssl web user-bookmark bookmarks preconnection-id" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "0"
	}
	return "2147483648"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 133] } {
		return "4294967295,0"
	}
	return "2147483648,0"
}
	%}
	"vpn ssl web user-bookmark bookmarks {send-preconnection-id restricted-admin color-depth}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"vpn ssl web user-bookmark bookmarks {listening-port remote-port show-status-window server-layout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"vpn ssl web user-group-bookmark bookmarks preconnection-id" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "0"
	}
	return "2147483648"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 133] } {
		return "4294967295,0"
	}
	return "2147483648,0"
}
	%}
	"vpn ssl web user-group-bookmark bookmarks {send-preconnection-id restricted-admin color-depth}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"vpn ssl web user-group-bookmark bookmarks {listening-port remote-port show-status-window server-layout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"web-proxy explicit unknown-http-version" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 0 $opts "tunnel"]
	} else {
		set opts [cli_update_opts 1 $opts "tunnel"]
	}
	return $opts
}
	%}
	"web-proxy profile {header-x-forwarded-client-cert}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"webfilter profile web {youtube-restrict vimeo-restrict}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"wireless-controller global {tunnel-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"webfilter profile options" = %{
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "feature-set"] eq "flow" } {
		set opts [cli_update_opts 0 $opts "activexfilter" "javafilter" "jscript" "js" "vbs" "unknown" "intrinsic" "wf-referer" "wf-cookie" "per-user-bwl"]
	}
	return $opts
}
	%}
	"wireless-controller vap {local-standalone-dns local-standalone-dns-ip utm-status utm-log ips-sensor application-list antivirus-profile webfilter-profile scan-botnet-connections}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3 radio-4} {sam-cwp-username sam-cwp-password sam-cwp-test-url sam-cwp-match-string sam-cwp-success-string sam-cwp-failure-string sam-server-type sam-server-ip sam-server-fqdn}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3 radio-4} {sam-server}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 133] } {
		return 0
	}
	return 1
}
	%}
	"wireless-controller wtp-profile {esl-ses-dongle}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile {indoor-outdoor-deployment console-login}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
	%}
	"firewall central-snat-map" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	namespace import global::platform_digit_start
	set plat [cli_get_devinfo "platform"]
	if { [platform_digit_start $plat "100"] && ![platform_digit_start $plat "1000"] } {
		if { [cli_branchpt_start 700 133] } {
			return "2048,2048,0"
		} else {
			return "1024,1024,0"
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"firewall service custom" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	namespace import global::platform_digit_start
	set plat [cli_get_devinfo "platform"]
	if { [platform_digit_start $plat "3000"] && ![platform_digit_start $plat "6000"] } {
		if { [cli_branchpt_start 700 133] } {
			return "0,32768,0"
		} else {
			return "0,16384,0"
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"router static6" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	namespace import global::platform_digit_start
	set plat [cli_get_devinfo "platform"]
	if { [platform_digit_start $plat "600"] && ![platform_digit_start $plat "6000"] } {
		if { [cli_branchpt_start 700 133] } {
			return "0,2000,0"
		} else {
			return "0,500,0"
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"system dns-database" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 203] } {
		return "0,4096,0"
	} elseif { [cli_branchpt_start 700 133] } {
		return "0,1024,0"
	} else {
		return "512,256,0"
	}
	return $CLI_CUR_VALUE
}
	%}
	"wireless-controller wtp-profile ap-country" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 133] } {
		return "--"
	}
	return "NA"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 410] } {
		set opts [cli_update_opts 1 $opts "MN"]
	} else {
		set opts [cli_update_opts 0 $opts "MN"]
	}
	if { [cli_branchpt_start 700 133] } {
		set opts [cli_update_opts 1 $opts "--"]
	} else {
		set opts [cli_update_opts 0 $opts "--"]
	}
	return $opts
}
	%}
	"application name {max-scan-range}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0 
	}
}
	%}
	"authentication scheme {ems-device-owner}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 143] } {
		return 0
	}
	return 1
}
	%}
	"firewall access-proxy api-gateway realservers {ssh-host-key}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"firewall access-proxy api-gateway realservers {type ssh-client-cert ssh-host-key-validation}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"firewall access-proxy {api-gateway6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"firewall access-proxy {server-pubkey-auth ldb-method}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 143] } {
		return 0
	}
	return 1
}
	%}
	"firewall access-proxy {server-pubkey-auth-settings realservers}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 143] } {
		return 0
	}
	return 1
}
	%}
	"firewall access-proxy-ssh-client-cert" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"firewall access-proxy6" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"firewall policy {sgt-check}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"firewall policy {sgt}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"firewall proxy-policy {access-proxy6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"firewall ssh host-key {usage}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"firewall ssl-server ssl-max-version" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 143] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 203] } {
		return "tls-1.3"
	}
	return "tls-1.2"
}
	%}
	"firewall ssl-server ssl-min-version" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 143] } {
		set opts [cli_update_opts 1 $opts "tls-1.3"]
	} else {
		set opts [cli_update_opts 0 $opts "tls-1.3"]
	}
	return $opts
}
	%}
	"firewall ssl-ssh-profile {ssl-server-cert-log ssl-handshake-log}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"firewall vip server-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 143] } {
		set opts [cli_update_opts 0 $opts "ssh"]
	} else {
		set opts [cli_update_opts 1 $opts "ssh"]
	}
	return $opts
}
	%}
	"firewall vip6 type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 143] } {
		set opts [cli_update_opts 1 $opts "access-proxy"]
	} else {
		set opts [cli_update_opts 0 $opts "access-proxy"]
	}
	return $opts
}
	%}
	"switch-controller fortilink-settings nac-ports {parent-key member-change}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"system automation-action {delay required}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 143] } {
		return 0
	}
	return 1
}
	%}
	"system automation-stitch {actions}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"system automation-stitch {action}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 143] } {
		return 0
	}
	return 1
}
	%}
	"system dns {log}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"system federated-upgrade status" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 218] } {
		set opts [cli_update_opts 0 $opts "download-failed"]
	} else {
		set opts [cli_update_opts 1 $opts "download-failed"]
	}
	if { [cli_branchpt_start 700 203] } {
		set opts [cli_update_opts 1 $opts "upgrade-devices"]
	} else {
		set opts [cli_update_opts 0 $opts "upgrade-devices"]
	}
	if { [cli_branchpt_start 700 143] } {
		set opts [cli_update_opts 1 $opts "final-check"]
	} else {
		set opts [cli_update_opts 0 $opts "final-check"]
	}
	return $opts
}
	%}
	"system fortiguard {ddns-server-ip6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"system global management-port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 143] } {
		return "443"
	}
	return "0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 143] } {
		return "65535,1"
	}
	return "65535,0"
}
	%}
	"system global {management-port-use-admin-sport}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"system npu {gtp-enhanced-mode gtp-enhanced-cpu-range intf-shaping-offload}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"system ptp {server-interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"system ptp {server-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"vpn certificate setting {subject-set cn-allow-multi}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1 {ip-delay-interval}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1-interface {ip-delay-interval}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 143] } {
		return 0
	}
}
	%}
	"vpn ssl settings authentication-rule auth" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 143] } {
		set opts [cli_update_opts 1 $opts "peer"]
	} else {
		set opts [cli_update_opts 0 $opts "peer"]
	}
	return $opts
}
	%}
	"vpn ssl settings status" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 143] } {
		return "enable"
	}
	return "disable"
}
	%}
	"system sdwan zone" = %{
if { $CLI_GET_RV } {
	if { [cli_reserved_value_is "SASE"] } {
		if { $CLI_GLOBAL_DEV } {
			return 0
		}
		if { ![cli_branchpt_start 700 126] } {
			return 0
		}
		if { [cli_branchpt_start 700 337] } {
			return 0
		}
	}
}
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 287] } {
		return "0,1024,0"
	}
	return "512,256,0"
}
	%}
	"antivirus settings {cache-infected-result}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"certificate ca {ca-identifier}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"dnsfilter profile block-action" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 203] } {
		set opts [cli_update_opts 1 $opts "block-sevrfail"]
	} else {
		set opts [cli_update_opts 0 $opts "block-sevrfail"]
	}
	return $opts
}
	%}
	"extender-controller dataplan preferred-subnet" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 203] } {
		return "0"
	}
	return "32"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 203] } {
		return "32,0"
	}
	return "32,8"
}
	%}
	"extender-controller extender {controller-report modem1 modem2}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 203] } {
		return 0
	}
	return 1
}
	%}
	"extender-controller extender {device-id extension-type override-allowaccess allowaccess override-login-password-change login-password-change override-enforce-bandwidth enforce-bandwidth bandwidth-limit profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"extender-controller extender {wan-extension}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"extender-controller extender-profile" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"firewall access-proxy api-gateway realservers {addr-type}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"firewall access-proxy api-gateway6 realservers {addr-type}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"firewall access-proxy {decrypted-traffic-mirror}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"firewall access-proxy6 api-gateway realservers {addr-type}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"firewall access-proxy6 api-gateway6 realservers {addr-type}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"firewall access-proxy6 {decrypted-traffic-mirror}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"firewall policy sgt id" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 203] } {
		return "65535,1"
	}
	return "4294967295,0"
}
	%}
	"firewall profile-protocol-options http tunnel-non-http" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 203] } {
		return "enable"
	}
	return "disable"
}
	%}
	"firewall proxy-policy {ztna-tags-match-logic}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"firewall security-policy {nat46 nat64}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"firewall ssl-ssh-profile {ssl-anomalies-log ssl-exemptions-log}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 203] } {
		return 0
	}
	return 1
}
	%}
	"firewall ssl-ssh-profile {ssl-anomaly-log ssl-exemption-log}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"log setting {anonymization-hash}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"log tacacs+accounting filter" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"log tacacs+accounting setting" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"log tacacs+accounting2 filter" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"log tacacs+accounting2 setting" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"log tacacs+accounting3 filter" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"log tacacs+accounting3 setting" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"switch-controller fortilink-settings {fortilink}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch igmp-snooping {vlans}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch ports {export-tags}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 203] } {
		return 0
	}
	return 1
}
	%}
	"switch-controller managed-switch ports {interface-tags}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system admin gui-dashboard widget type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 218] } {
		set opts [cli_update_opts 1 $opts "ipam"]
	} else {
		set opts [cli_update_opts 0 $opts "ipam"]
	}
	if { [cli_branchpt_start 700 203] } {
		set opts [cli_update_opts 1 $opts "dns"]
	} else {
		set opts [cli_update_opts 0 $opts "dns"]
	}
	return $opts
}
	%}
	"system admin {gui-ignore-invalid-signature-version}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system automation-action {execute-security-fabric}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system csf {upstream-ip}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 203] } {
		return 0
	}
	return 1
}
	%}
	"system csf {upstream}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system dhcp6 server {delegated-prefix-iaid}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system federated-upgrade {failure-reason failure-device}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system fm" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 203] } {
		return 0
	}
	return 1
}
	%}
	"system fortimanager" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 203] } {
		return 0
	}
	return 1
}
	%}
	"system global {ssh-cbc-cipher ssh-hmac-md5 ssh-kex-sha1 ssh-mac-weak}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 203] } {
		return 0
	}
	return 1
}
	%}
	"system global {ssh-enc-algo ssh-mac-algo extender-controller-reserved-network fortiextender-discovery-lockdown}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system ha group-id" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 203] } {
		return "1023,0"
	}
	return "255,0"
}
	%}
	"system ha {uninterruptible-primary-wait}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 352] } {
		return "300,15"
	}
	return "300,1"
}
	%}
	"system interface ipv6 ip6-delegated-prefix-list {delegated-prefix-iaid}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system interface ipv6 {dhcp6-iapd-list}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system interface ipv6 {dhcp6-prefix-hint dhcp6-prefix-hint-plt dhcp6-prefix-hint-vlt}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 203] } {
		return 0
	}
	return 1
}
	%}
	"system interface ipv6 {ip6-delegated-prefix-iaid}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system interface type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 203] } {
		set opts [cli_update_opts 1 $opts "lan-extension"]
	} else {
		set opts [cli_update_opts 0 $opts "lan-extension"]
	}
	return $opts
}
	%}
	"system interface {system-id-type system-id}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system sdn-connector {forwarding-rule}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system sdwan service {passive-measurement}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system settings {ike-policy-route}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system sso-admin gui-dashboard widget type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 218] } {
		set opts [cli_update_opts 1 $opts "ipam"]
	} else {
		set opts [cli_update_opts 0 $opts "ipam"]
	}
	if { [cli_branchpt_start 700 203] } {
		set opts [cli_update_opts 1 $opts "dns"]
	} else {
		set opts [cli_update_opts 0 $opts "dns"]
	}
	return $opts
}
	%}
	"system sso-admin {gui-ignore-invalid-signature-version}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"system sso-forticloud-admin gui-dashboard widget type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 218] } {
		set opts [cli_update_opts 1 $opts "ipam"]
	} else {
		set opts [cli_update_opts 0 $opts "ipam"]
	}
	if { [cli_branchpt_start 700 203] } {
		set opts [cli_update_opts 1 $opts "dns"]
	} else {
		set opts [cli_update_opts 0 $opts "dns"]
	}
	return $opts
}
	%}
	"system sso-forticloud-admin {gui-ignore-invalid-signature-version}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"user fsso {ssl-server-host-ip-check}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"user ldap source-ip" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 203] } {
		return ""
	}
	return "0.0.0.0"
}
	%}
	"user setting {auth-ssl-max-proto-version auth-ssl-sigalgs}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"voip profile {msrp}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"vpn certificate ca {ca-identifier}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"web-proxy profile headers content" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 410] } {
		return "1023"
	}
	if { [cli_branchpt_start 700 203] } {
		return "511"
	}
	return "255"
}
	%}
	"webfilter profile antiphish inspection-entries fortiguard-category" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 203] } {
		return "0"
	}
	return "g21"
}
	%}
	"webfilter search-engine safesearch" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 203] } {
		set opts [cli_update_opts 1 $opts "yt-channel" "yt-video" "translate" "yt-scan" "yt-pattern"]
	} else {
		set opts [cli_update_opts 0 $opts "yt-channel" "yt-video" "translate" "yt-scan" "yt-pattern"]
	}
	return $opts
}
	%}
	"wireless-controller apcfg-profile command-list passwd-value" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 203] } {
		return "129"
	}
	return "123"
}
	%}
	"wireless-controller syslog-profile" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"wireless-controller vap ft-over-ds" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 203] } {
		return "disable"
	}
	return "enable"
}
	%}
	"wireless-controller vap {radius-mac-mpsk-auth beacon-advertising}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"wireless-controller vap {radius-mac-mpsk-timeout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 442] } {
		return "864000,300"
	}
	return "864000,1800"
}
	%}
	"wireless-controller wtp login-passwd" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 203] } {
		return "129"
	}
	return "31"
}
	%}
	"wireless-controller wtp-profile login-passwd" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 203] } {
		return "129"
	}
	return "31"
}
	%}
	"wireless-controller wtp-profile {syslog-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
	%}
	"endpoint-control client" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 203] } {
		return "550000,0,0"
	} else {
		return "330000,0,0"
	}
	return $CLI_CUR_VALUE
}
	%}
	"endpoint-control fctems" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 203] } {
		return "5,0,0"
	} else {
		return "3,0,0"
	}
	return $CLI_CUR_VALUE
}
	%}
	"switch-controller fortilink-settings" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 203] } {
		return "0,256,0"
	} else {
		return "512,256,0"
	}
	return $CLI_CUR_VALUE
}
	%}
	"switch-controller mac-policy" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 203] } {
		return "0,1000,0"
	} else {
		return "0,256,0"
	}
	return $CLI_CUR_VALUE
}
	%}
	"user nac-policy" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 203] } {
		return "0,1000,0"
	} else {
		return "0,256,0"
	}
	return $CLI_CUR_VALUE
}
	%}

	"antivirus profile {cifs ftp http imap mapi nntp pop3 smtp ssh} {archive-block archive-log}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 218] } {
		set opts [cli_update_opts 0 $opts "fileslimit"]
	} else {
		set opts [cli_update_opts 1 $opts "fileslimit"]
	}
	return $opts
}
	%}
	"antivirus profile {fortiai-timeout-action}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
	if { [cli_branchpt_start 700 410] } {
		return 0
	}
	return 1
}
	%}
	"emailfilter fortiguard" = %{
return 0
	%}
	"extender-controller extender-profile lan-extension backhaul-ip" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 218] } {
		return "63"
	}
	return "255"
}
	%}
	"firewall {access-proxy access-proxy6} {api-gateway api-gateway6} saml-redirect" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"firewall {access-proxy access-proxy6} log-blocked-traffic" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"firewall policy {fec}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"gtp message-filter-v2 {context-req-res-ack forward-relocation-req-res forward-relocation-cmp-notif-ack}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"icap profile {chunk-encap extension-feature scan-progress-interval}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"router rip {recv-buffer-size}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 218] } {
		return 0
	}
	return 1
}
	%}
	"system fortiguard update-server-location" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 218] } {
		return "automatic"
	}
	return "any"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 218] } {
		set opts [cli_update_opts 1 $opts "automatic" "eu"]
		set opts [cli_update_opts 0 $opts "any"]
	} else {
		set opts [cli_update_opts 0 $opts "automatic" "eu"]
		set opts [cli_update_opts 1 $opts "any"]
	}
	return $opts
}
	%}
	"system global ssh-kex-algo" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 218] } {
		return "diffie-hellman-group-exchange-sha256 curve25519-sha256@libssh.org ecdh-sha2-nistp256 ecdh-sha2-nistp384 ecdh-sha2-nistp521"
	}
	return "diffie-hellman-group-exchange-sha256 curve25519-sha256@libssh.org"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 218] } {
		set opts [cli_update_opts 1 $opts "ecdh-sha2-nistp256" "ecdh-sha2-nistp384" "ecdh-sha2-nistp521"]
	} else {
		set opts [cli_update_opts 0 $opts "ecdh-sha2-nistp256" "ecdh-sha2-nistp384" "ecdh-sha2-nistp521"]
	}
	return $opts
}
	%}
	"system global {admin-https-ssl-ciphersuites admin-https-ssl-banned-ciphers user-device-store-max-unified-mem}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"system global {fec-port fortiipam-integration}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 218] } {
		return 0
	}
	return 1
}
	%}
	"system interface managed-subnetwork-size" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 218] } {
		set opts [cli_update_opts 1 $opts "64" "32" "128"]
	} else {
		set opts [cli_update_opts 0 $opts "64" "32" "128"]
	}
	return $opts
}
	%}
	"system interface mode" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 218] } {
		set opts [cli_update_opts 1 $opts "pppoa"]
	} else {
		set opts [cli_update_opts 0 $opts "pppoa"]
	}
	return $opts
}
	%}
	"system interface {sfp-dsl sfp-dsl-autodetect sfp-dsl-adsl-fallback sfp-dsl-mac pvc-chan pvc-vlan-id pvc-vlan-tx-id pvc-vlan-rx-id pvc-vlan-tx-op pvc-vlan-rx-op pvc-crc pvc-atm-qos pvc-pcr pvc-scr}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
	return $CLI_CUR_VALUE
}
	%}
	"system ipam" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"user nac-policy {switch-group}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"user nac-policy {switch-scope}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 218] } {
		return 0
	}
	return 1
}
	%}
	"vpn ipsec fec" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1 fec-base" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 218] } {
		return "10"
	}
	return "20"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 218] } {
		return "20,1"
	}
	return "100,1"
}
	%}
	"vpn ipsec phase1 fec-codec" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 218] } {
		return "rs"
	}
	return "0"
}
if { $CLI_GET_ND } {
	if { ![cli_branchpt_start 700 287] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1 fec-receive-timeout" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 218] } {
		return "50"
	}
	return "5000"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 218] } {
		return "1000,1"
	}
	return "10000,1"
}
	%}
	"vpn ipsec phase1 fec-redundant" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 218] } {
		return "5,1"
	}
	return "100,0"
}
	%}
	"vpn ipsec phase1 fec-send-timeout" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 218] } {
		return "5"
	}
	return "8"
}
	%}
	"vpn ipsec phase1 {fec-health-check fec-mapping-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1 {network-overlay network-id loopback-asymroute}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 218] } {
		return 0
	}
	return 1
}
	%}
	"vpn ipsec phase1-interface fec-base" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 218] } {
		return "10"
	}
	return "20"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 218] } {
		return "20,1"
	}
	return "100,1"
}
	%}
	"vpn ipsec phase1-interface fec-codec" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 218] } {
		return "rs"
	}
	return "0"
}
if { $CLI_GET_ND } {
	if { ![cli_branchpt_start 700 287] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1-interface fec-receive-timeout" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 218] } {
		return "50"
	}
	return "5000"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 218] } {
		return "1000,1"
	}
	return "10000,1"
}
	%}
	"vpn ipsec phase1-interface fec-redundant" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 218] } {
		return "5,1"
	}
	return "100,0"
}
	%}
	"vpn ipsec phase1-interface fec-send-timeout" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 218] } {
		return "5"
	}
	return "8"
}
	%}
	"vpn ipsec phase1-interface {fec-health-check fec-mapping-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"vpn ssl settings servercert" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { ![cli_branchpt_start 700 227] } {
		if { [cli_get_devinfo "VM"] eq "yes" } {
			return "self-sign"
		}
		return "Fortinet_Factory"
	}
	return "''"
}
	%}
	"vpn ssl web realm {virtual-host-server-cert}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"web-proxy global {ldap-user-cache}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller apcfg-profile {ap-family}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller ble-profile eddystone-instance" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 218] } {
		return "12"
	}
	return "6"
}
	%}
	"wireless-controller ble-profile eddystone-namespace" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 218] } {
		return "20"
	}
	return "10"
}
	%}
	"wireless-controller global {nac-interval}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller hotspot20 anqp-venue-url" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller hotspot20 h2qp-advice-of-charge" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller hotspot20 h2qp-osu-provider-nai" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller hotspot20 h2qp-terms-and-conditions" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller hotspot20 hs-profile {release venue-url oper-icon advice-of-charge osu-provider-nai terms-and-conditions}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller setting {firmware-provision-on-authorization}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller vap {rates-11ax-ss12 rates-11ax-ss34 osen}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller wids-profile ap-bgscan-duration" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 218] } {
		return "30"
	}
	return "20"
}
	%}
	"wireless-controller wids-profile ap-bgscan-idle" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 218] } {
		return "20"
	}
	return "0"
}
	%}
	"wireless-controller wids-profile ap-bgscan-intv" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 218] } {
		return "3"
	}
	return "1"
}
	%}
	"wireless-controller wtp {firmware-provision-latest}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile lbs {fortipresence-server-addr-type fortipresence-server-fqdn}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-1 {bss-color-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-2 {bss-color-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-3 {bss-color-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-4 {bss-color-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile {wan-port-auth wan-port-auth-usrname wan-port-auth-password wan-port-auth-methods}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 218] } {
		return 0
	}
}
	%}
	"firewall {vip vip6} monitor" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 218] } {
		return "0,0,5"
	} else {
		return "5,5,5"
	}
	return $CLI_CUR_VALUE
}
	%}
	"firewall {vip vip6} realservers monitor" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 218] } {
		return "0,0,5"
	} else {
		return "5,5,5"
	}
	return $CLI_CUR_VALUE
}
	%}
	"log fortiguard {setting override-setting} {access-config}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 227] } {
		return 0
	}
}
	%}
	"log tap-device" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 227] } {
		return 0
	}
}
	%}
	"switch-controller dsl policy" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 227] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch ports {dsl-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 227] } {
		return 0
	}
}
	%}
	"system resource-limits {firewall-address}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	set plat [cli_get_devinfo "platform"]
	if { [cli_get_devinfo "VM"] eq "yes" } {
		set model_rank [cli_get_devinfo "model_rank"]
		if { $model_rank eq "HIGHEND" || $model_rank eq "" } {
			if { [cli_branchpt_start 700 218] } {
				return "500000"
			}
			return "100000"
		}
	}
	namespace import global::platform_digit_between
	if { [platform_digit_between $plat "3600E" "5001E"] } {
			if { [cli_branchpt_start 700 218] } {
				return "500000"
			}
			return "200000"
	}
}
	%}
	"extender-controller dataplan password" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 267] } {
		return "64"
	}
	return "27"
}
	%}
	"extender-controller dataplan username" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 267] } {
		return "127"
	}
	return "31"
}
	%}
	"firewall access-proxy {api-gateway api-gateway6} realservers {domain}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"firewall access-proxy6 {api-gateway api-gateway6} realservers {domain}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"firewall address {dirty tag-detection-level tag-type}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"firewall proxy-policy {block-notification}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"firewall {vip vip6} {ssl-accept-ffdhe-groups}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"router bgp {tag-resolve-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"router static priority" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 267] } {
		return "1"
	}
	return "0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 267] } {
		return "65535,1"
	}
	return "65535,0"
}
	%}
	"system global {proxy-cert-use-mgmt-vdom}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"system interface l2tp-client-settings priority" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 267] } {
		return "1"
	}
	return "0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 267] } {
		return "65535,1"
	}
	return "4294967295,0"
}
	%}
	"system interface priority" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 267] } {
		return "1"
	}
	return "0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 267] } {
		return "65535,1"
	}
	return "4294967295,0"
}
	%}
	"system interface {reachable-time}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"system npu {ipsec-local-uesp-port}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] || [cli_branchpt_start 700 296] } {
		return 0
	}
}
	%}
	"system sdn-connector {gcp-project-list}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"system sdn-connector {gcp-project}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 267] } {
		return 0
	}
	return 1
}
	%}

	"system sdwan members priority" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 267] } {
		return "1"
	}
	return "0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 367] } {
		return "65535,1"
	}
	return "65535,0"
}
	%}
	"vpn ipsec phase1 priority" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 267] } {
		return "1"
	}
	return "0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 267] } {
		return "65535,1"
	}
	return "4294967295,0"
}
	%}
	"vpn ipsec phase1-interface priority" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 267] } {
		return "1"
	}
	return "0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 267] } {
		return "65535,1"
	}
	return "4294967295,0"
}
	%}
	"vpn ssl client priority" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 267] } {
		return "1"
	}
	return "0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 267] } {
		return "65535,1"
	}
	return "4294967295,0"
}
	%}
	"wireless-controller arrp-profile {darrp-optimize-schedules}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"wireless-controller arrp-profile {override-darrp-optimize darrp-optimize}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"wireless-controller vap {vlan-name}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-1 {arrp-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-2 {arrp-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-3 {arrp-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-4 {arrp-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
	%}
	"firewall access-proxy {auth-portal auth-virtual-host}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 276] } {
		return 0
	}
}
	%}
	"firewall access-proxy6 {auth-portal auth-virtual-host}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 276] } {
		return 0
	}
}
	%}
	"firewall profile-protocol-options {cifs ftp http ssh} tcp-window-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 352] } {
		return "auto-tuning"
	}
	return "system"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 276] } {
		set opts [cli_update_opts 1 $opts "auto-tuning"]
	} else {
		set opts [cli_update_opts 0 $opts "auto-tuning"]
	}
	return $opts
}
	%}
	"firewall ssl-ssh-profile {ftps https ssl} {min-allowed-ssl-version}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 276] } {
		return 0
	}
}
	%}
	"firewall ssl-ssh-profile {dot imaps pop3s smtps} {min-allowed-ssl-version}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 276] || [cli_branchpt_start 700 287] } {
		return 0
	}
}
	%}
	"log eventfilter {rest-api}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 276] } {
		return 0
	}
}
	%}
	"log setting {rest-api-set rest-api-get}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 276] } {
		return 0
	}
}
	%}
	"router bgp {network network6} {network-import-check}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 276] } {
		return 0
	}
}
	%}
	"switch-controller dsl policy type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 276] } {
		return "Proscend"
	}
	return "Procend"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 276] } {
		set opts [cli_update_opts 1 $opts "Proscend"]
		set opts [cli_update_opts 0 $opts "Procend"]
	} else {
		set opts [cli_update_opts 0 $opts "Proscend"]
		set opts [cli_update_opts 1 $opts "Procend"]
	}
	return $opts
}
	%}
	"system ddns update-interval" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 276] } {
		return "0"
	}
	return "300"
}
	%}
	"system federated-upgrade {next-path-index}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 276] } {
		return 0
	}
}
	%}
	"system fortiai {source-ip interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 276] } {
		return 0
	}
}
	%}
	"system global {internet-service-database}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 276] } {
		return 0
	}
}
	%}
	"system interface mediatype" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 276] } {
		return "none"
	}
	namespace import global::platform_digit_suffix
	set suffix [platform_digit_suffix [cli_get_devinfo "platform"]]
	if { [regexp -nocase {1100E|1101E|2200E|2201E|3300E|3301E} $suffix] } {
		return "serdes-sfp"
	}
	if { [regexp -nocase {3400E|3401E|3600E|3601E} $suffix] } {
		return "sr"
	}
	if { [regexp -nocase {3960E|3980E} $suffix] } {
		return "qsfp28-sr4"
	}
	return $CLI_CUR_VALUE
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 276] } {
		set opts [cli_update_opts 1 $opts "sr4" "sgmii" "cr" "none" "lr4" "cr4" "lr" "sr" "gmii"]
		set opts [cli_update_opts 0 $opts "qsfp28-cr4" "qsfp28-sr4" "sgmii-sfp" "serdes-sfp" "serdes-copper-sfp" "qsfp28-lr4"]
	} else {
		set opts [cli_update_opts 0 $opts "sr4" "sgmii" "cr" "none" "lr4" "cr4" "lr" "sr" "gmii"]
		set opts [cli_update_opts 1 $opts "qsfp28-cr4" "qsfp28-sr4" "sgmii-sfp" "serdes-sfp" "serdes-copper-sfp" "qsfp28-lr4"]
	}
	return $opts
}
	%}
	"system interface {dhcp-relay-link-selection}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 276] } {
		return 0
	}
}
	%}
	"system sdn-connector {external-account-list}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 276] } {
		return 0
	}
}
	%}

	"icap profile response-req-hdr" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 287] } {
		return "enable"
	}
	return "disable"
}
	%}
	"switch-controller dynamic-port-policy policy {hw-vendor}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 287] } {
		return 0
	}
}
	%}
	"system csf {forticloud-account-enforcement}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 287] } {
		return 0
	}
}
	%}
	"system global {gui-cdn-usage gui-cdn-domain-override}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 287] } {
		return 0
	}
}
	%}
	"system interface ipv6 nd-cga-modifier" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 287] } {
		return "00000000000000002573282564293A20"
	}
	return "000000000000000073735B765D202573"
}
	%}
	"system interface {auth-cert auth-portal-addr}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 287] } {
		return 0
	}
}
	%}
	"user saml {clock-tolerance}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 287] } {
		return 0
	}
}
	%}
	"wireless-controller vap {auth-cert auth-portal-addr}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 287] } {
		return 0
	}
}
	%}
	"firewall {access-proxy access-proxy6} api-gateway6 service" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 288] } {
		set opts [cli_update_opts 1 $opts "web-portal"]
	} else {
		set opts [cli_update_opts 0 $opts "web-portal"]
	}
	return $opts
}
	%}
	"firewall {access-proxy access-proxy6} {api-gateway api-gateway6} {ssl-vpn-web-portal}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 288] } {
		return 0
	}
}
	%}
	"log fortianalyzer-cloud setting {certificate-verification}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 288] } {
		return 0
	}
}
	%}
	"log fortianalyzer-cloud setting {serial}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 288] } {
		return 0
	}
}
	%}
	"system interface {dns-server-protocol}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 288] } {
		return 0
	}
}
	%}
	"system sdn-connector ibm-region" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 288] } {
		return "dallas"
	}
	return "us-south"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 288] } {
		set opts [cli_update_opts 1 $opts "sydney" "washington-dc" "tokyo" "dallas" "london" "frankfurt" "osaka" "toronto" "sao-paulo"]
		set opts [cli_update_opts 0 $opts "us-east" "japan" "us-south" "great-britain" "germany" "australia"]
	} else {
		set opts [cli_update_opts 0 $opts "sydney" "washington-dc" "tokyo" "dallas" "london" "frankfurt" "osaka" "toronto" "sao-paulo"]
		set opts [cli_update_opts 1 $opts "us-east" "japan" "us-south" "great-britain" "germany" "australia"]
	}
	return $opts
}
	%}
	"system settings {h323-direct-model}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 288] } {
		return 0
	}
}
	%}
	"system global {forticarrier-bypass}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 296] } {
		return 0
	}
}
	%}
	"dpdk global {ipsec-offload}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"endpoint-control fctems {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"firewall internet-service-addition entry port-range {start-port end-port}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 352] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"firewall internet-service-custom entry port-range {start-port end-port}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 352] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"firewall internet-service-extension disable-entry port-range {start-port end-port}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 352] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"firewall internet-service-extension entry port-range {start-port end-port}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 352] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"firewall profile-protocol-options http {address-ip-rating}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"firewall ssl-ssh-profile {ssl-exemption-ip-rating}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"system acme {source-ip source-ip6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"system automation-action {headers}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"system automation-action {http-headers}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"system cluster-sync hb-interval" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 352] } {
		return "20,1"
	}
	return "10,1"
}
	%}
	"system cluster-sync hb-lost-threshold" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 352] } {
		return "10"
	}
	return "3"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 352] } {
		return "60,1"
	}
	return "10,1"
}
	%}
	"system federated-upgrade {ignore-signing-errors}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"system global {admin-host ipv6-allow-multicast-probe ipv6-allow-local-in-slient-drop early-tcp-npu-session ipsec-round-robin}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"system interface l2tp-client-settings {hello-interval}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"system interface tcp-mss" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 352] } {
		return "65535,48"
	}
	return "4294967295,0"
}
	%}
	"system interface {security-8021x-mode security-8021x-master security-8021x-dynamic-vlan-id}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"system lte-modem {sim1-pin sim2-pin override-gateway}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"system np6xlite {asicdos}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"system np6xlite {ipsec-throughput-msg-frequency ipsec-STS-timeout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"system settings gui-ztna" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 352] } {
		return "enable"
	}
	return "disable"
}
	%}
	"system vdom-link type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 352] } {
		set opts [cli_update_opts 1 $opts "npupair"]
	} else {
		set opts [cli_update_opts 0 $opts "npupair"]
	}
	return $opts
}
	%}
	"vpn ipsec phase1 {inbound-dscp-copy}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1-interface {inbound-dscp-copy}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"vpn ipsec phase2 {inbound-dscp-copy}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"vpn ipsec phase2-interface {inbound-dscp-copy}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"vpn ssl settings {web-mode-snat}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"vpn ssl web portal bookmark-group bookmarks height" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 352] } {
		return "0"
	}
	return "768"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 352] } {
		return "65535,0"
	}
	return "65535,480"
}
	%}
	"vpn ssl web portal bookmark-group bookmarks keyboard-layout" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 352] } {
		set opts [cli_update_opts 1 $opts "fr-apple"]
	} else {
		set opts [cli_update_opts 0 $opts "fr-apple"]
	}
	return $opts
}
	%}
	"vpn ssl web portal bookmark-group bookmarks width" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 352] } {
		return "0"
	}
	return "1024"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 352] } {
		return "65535,0"
	}
	return "65535,640"
}
	%}
	"vpn ssl web portal ip-mode" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 352] } {
		set opts [cli_update_opts 1 $opts "dhcp"]
	} else {
		set opts [cli_update_opts 0 $opts "dhcp"]
	}
	return $opts
}
	%}
	"vpn ssl web portal {dhcp-ip-overlap default-window-width default-window-height}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"vpn ssl web user-bookmark bookmarks height" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 352] } {
		return "0"
	}
	return "768"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 352] } {
		return "65535,0"
	}
	return "65535,480"
}
	%}
	"vpn ssl web user-bookmark bookmarks keyboard-layout" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 352] } {
		set opts [cli_update_opts 1 $opts "fr-apple"]
	} else {
		set opts [cli_update_opts 0 $opts "fr-apple"]
	}
	return $opts
}
	%}
	"vpn ssl web user-bookmark bookmarks width" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 352] } {
		return "0"
	}
	return "1024"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 352] } {
		return "65535,0"
	}
	return "65535,640"
}
	%}
	"vpn ssl web user-group-bookmark bookmarks height" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 352] } {
		return "0"
	}
	return "768"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 352] } {
		return "65535,0"
	}
	return "65535,480"
}
	%}
	"vpn ssl web user-group-bookmark bookmarks keyboard-layout" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 133] } {
		return 0
	}
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 352] } {
		set opts [cli_update_opts 1 $opts "fr-apple"]
	} else {
		set opts [cli_update_opts 0 $opts "fr-apple"]
	}
	return $opts
}
	%}
	"vpn ssl web user-group-bookmark bookmarks width" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 267] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 352] } {
		return "0"
	}
	return "1024"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 352] } {
		return "65535,0"
	}
	return "65535,640"
}
	%}
	"wanopt settings {tunnel-optimization}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"wireless-controller timers {auth-timeout rogue-ap-cleanup}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 352] } {
		return 0
	}
}
	%}
	"firewall shaper per-ip-shaper max-bandwidth" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	namespace import global::platform_digit_start
	if { [cli_branchpt_start 700 352] } {
		if { [platform_digit_start $plat "3400"] } {
			return "100000000,0"
		}
		return "80000000,0"
	}
	return "16776000,0"
}
	%}
	"firewall shaper traffic-shaper {exceed-bandwidth guaranteed-bandwidth maximum-bandwidth}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	namespace import global::platform_digit_start
	if { [cli_branchpt_start 700 352] } {
		if { [platform_digit_start $plat "3400"] } {
			return "100000000,0"
		}
		return "80000000,0"
	}
	return "16776000,0"
}
	%}
	"system interface {inbandwidth outbandwidth}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	namespace import global::platform_digit_start
	if { [cli_branchpt_start 700 352] } {
		if { [platform_digit_start $plat "3400"] } {
			return "100000000,0"
		}
		return "80000000,0"
	}
	return "16776000,0"
}
	%}
	"system snmp {community user} events" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 352] } {
		set opts [cli_update_opts 1 $opts "power-supply-failure" "voltage-alert" "pool-usage" "temperature-high"]
	} else {
		set opts [cli_update_opts 0 $opts "power-supply-failure" "voltage-alert" "pool-usage" "temperature-high"]
	}
	return $opts
}
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 352] } {
		set opts [cli_update_opts 1 $opts "power-supply-failure" "voltage-alert" "pool-usage" "temperature-high"]
	} else {
		set opts [cli_update_opts 0 $opts "power-supply-failure" "voltage-alert" "pool-usage" "temperature-high"]
	}
	return $opts
}
	%}
	"router bfd {multihop-template}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 357] } {
		return 0
	}
}
	%}
	"router bfd6 {multihop-template}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 357] } {
		return 0
	}
}
	%}
	"system global {gui-fortiguard-resource-fetch}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 357] } {
		return 0
	}
}
	%}
	"system settings {nat46-generate-ipv6-fragment-header}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 357] } {
		return 0
	}
}
	%}
	"videofilter youtube-channel-filter override-category" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 365] } {
		return "disable"
	}
	return "enable"
}
	%}
	"vpn ipsec phase1-interface { auto-discovery-shortcuts }" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 415] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable"] } {
		set opts [cli_update_opts 0 $opts "independent"]
	} else {
		set opts [cli_update_opts 1 $opts "independent"]
	}
	return $opts
}
	%}
	"system replacemsg-image" = %{
if { $CLI_GET_RV } {
	if { $CLI_GLOBAL_DEV } { return }
	if { [cli_reserved_value_is "logo_fortisase_sia"] } {
		if { [cli_get_devinfo "SASE"] eq "no" } {
			return 0
		}
	}
}
	%}
	"automation setting" = %{
## SASE-specific attribute, no global support
if { $CLI_GLOBAL_DEV } { return 0 }
if { $CLI_GET_TO } {
	if { [cli_get_devinfo "SASE"] eq "no" } {
		return 0
	}
}
	%}
	"automation setting fabric-sync" = %{
## SASE-specific attribute
if { $CLI_GLOBAL_DEV } { return 0 }
if { $CLI_GET_TO } {
	if { [cli_get_devinfo "SASE"] eq "no" } {
		return 0
	}
}
	%}
	"system global extender-ipam-reserved-network" = %{
## SASE-specific attribute
if { $CLI_GLOBAL_DEV } { return 0 }
if { $CLI_GET_TO } {
	if { [cli_get_devinfo "SASE"] eq "no" } {
		return 0
	}
}
	%}
	"antivirus profile {cifs ftp http imap mapi nntp pop3 smtp ssh} fortindr" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"antivirus profile http {unknown-content-encoding}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"antivirus profile {fortindr-error-action fortindr-timeout-action}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"antivirus settings {cache-clean-result}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 203] } {
		return 0
	}
	if { [cli_branchpt_start 700 410] } {
		return 0
	}
	return 1
}
	%}
	"endpoint-control fctems ems-id" = %{
if { $CLI_GET_TO } {
	## make sure new tabkey always supported, to compatibile old device export
	return 1
}
	%}
	"endpoint-control fctems {status dirty-reason serial-number out-of-sync-threshold}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"extender-controller extender-profile model" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 410] } {
		set opts [cli_update_opts 1 $opts "FX04DN" "FX04DI"]
	} else {
		set opts [cli_update_opts 0 $opts "FX04DN" "FX04DI"]
	}
	return $opts
}
	%}
	"firewall access-proxy-virtual-host {replacemsg-group}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"firewall ippool {subnet-broadcast-in-ippool}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"firewall profile-protocol-options ftp {explicit-ftp-tls}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"firewall vip6 {arp-reply}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"firewall vip6 {ndp-reply}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"log threat-weight malware {fortindr}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"router bgp neighbor {allowas-in allowas-in6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 410] } {
		return "3"
	}
	return "0"
}
	%}
	"router bgp neighbor-group {allowas-in allowas-in6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 410] } {
		return "3"
	}
	return "0"
}
	%}
	"switch-controller igmp-snooping {query-interval}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch ports speed" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 410] } {
		set opts [cli_update_opts 1 $opts "5000auto" "10000full" "40000full" "50000sr" "40000sr4" "25000sr" "50000cr" "40000cr4" "1000full-fiber" "25000cr"]
		set opts [cli_update_opts 0 $opts "40000" "10000" "25000sr4" "1000fiber" "5000full" "25000cr4"]
	} else {
		set opts [cli_update_opts 0 $opts "5000auto" "10000full" "40000full" "50000sr" "40000sr4" "25000sr" "50000cr" "40000cr4" "1000full-fiber" "25000cr"]
		set opts [cli_update_opts 1 $opts "40000" "10000" "25000sr4" "1000fiber" "5000full" "25000cr4"]
	}
	return $opts
}
	%}
	"system automation-trigger {ioc-level}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"system cluster-sync {ike-monitor ike-monitor-interval ike-heartbeat-interval ike-use-rfc6311}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"system dnp3-proxy {status}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"system external-resource user-agent" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 410] } {
		return ""
	}
	return "curl/7.58.0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 410] } {
		return "255"
	}
	return "127"
}
	%}
	"system external-resource {server-identity-check}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"system fortindr" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"system ftm-push server-cert" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 410] } {
		return "Fortinet_Factory"
	}
	return "self-sign"
}
	%}
	"system global {ip-fragment-mem-thresholds}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"system ha {hw-session-hold-time hw-session-sync-delay}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"system ha {hw-session-sync-dev}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"system sdn-connector external-account-list {external-id}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"system settings {nat46-force-ipv4-packet-forwarding nat64-force-ipv6-packet-forwarding trap-local-session}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"system settings {trap-session-flag session-insert-trial hyperscale-default-policy-action}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1 {fgsp-sync}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1-interface {fgsp-sync}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"wireless-controller vap {sae-h2e-only sae-pk sae-private-key sticky-client-threshold-6g}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 410] } {
		return 0
	}
}
	%}
	"wireless-controller wtp {radio-1 radio-2 radio-3 radio-4} band" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 410] } {
		set opts [cli_update_opts 1 $opts "802.11ax-6G"]
	} else {
		set opts [cli_update_opts 0 $opts "802.11ax-6G"]
	}
	return $opts
}
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3 radio-4} band" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 410] } {
		set opts [cli_update_opts 1 $opts "802.11ax-6G"]
	} else {
		set opts [cli_update_opts 0 $opts "802.11ax-6G"]
	}
	return $opts
}
	%}
	"user quarantine targets" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 410] } {
		return "0,4000,0"
	}
	return "512,256,0"
}
	%}
	"system speed-test-server host {distance latitude longitude}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 442] } {
		return 0
	}
}
	%}
%};
