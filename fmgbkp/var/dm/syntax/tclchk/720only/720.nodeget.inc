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
	set d [cli_feature_value "webproxy_user_limits"]
	if { $d > 0 } {
		return "$d"
	}
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiGate-500E"] } {
		return "8000"
	}
	if { [string match -nocase $platform "FortiGate-2200E"] } {
		return "16000"
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
	"system global {user-server-cert}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return "self-sign"
	} elseif { [cli_get_devinfo "LENC"] eq "yes" } {
		return "self-sign"
	}
}
	%}
	"system global {auth-cert}" = %{
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
	return $CLI_CUR_VALUE
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
	return $CLI_CUR_VALUE
}
	%}
	"router ospf area virtual-link authentication" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "md5"]
	}
	return $CLI_CUR_VALUE
}
	%}
	"router ospf ospf-interface authentication" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "md5"]
	}
	return $CLI_CUR_VALUE
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
	"extender-controller extender" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
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
if { $CLI_GET_TD } {
	namespace import global::platform_digit_suffix
	set suffix [platform_digit_suffix [cli_get_devinfo "platform"]]
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
	return $CLI_CUR_VALUE
}
if { $CLI_GET_TN} {
	if { $CLI_SUPPORT_CDB_OPS } {
		namespace import global::platform_digit_suffix
		namespace import global::sys_intf_is_media_iface
		set platform [cli_get_devinfo "platform"]
		set suffix [platform_digit_suffix $platform]
		set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
		set ifname [string trim $ifname \"]
		set speed [cli_get_value $CLI_CUR_PARENT_NODE "" "" "speed"]
		if { [regexp -nocase {6000F|7000E|7000F} $suffix] } {
			namespace import global::sys_intf_forward_error_correction_option
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
		return "disable cl91-rs-fec cl74-fc-fec"
	}
	return $CLI_CUR_VALUE
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
		if { [string first "AWS" $platform] == -1 } {
			return 0
		}
	}
}
	%}
	"emailfilter profile mapi action" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_ND } {
	return 1
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
	"webfilter profile options" = %{
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "feature-set"] eq "flow" } {
		set opts [cli_update_opts 0 $opts "activexfilter" "javafilter" "jscript" "js" "vbs" "unknown" "intrinsic" "wf-referer" "wf-cookie" "per-user-bwl"]
	}
	return $opts
}
	%}
	"vpn ssl settings servercert" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	return "''"
}
	%}
	"firewall policy diffserv-copy" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1178] } {
		return 0
	}
	return 1
}
	%}
	"antivirus settings {cache-clean-result}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"certificate ca {obsolete}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"certificate local {private-key-retain}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"endpoint-control fctems {name status dirty-reason serial-number interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"extender-controller dataplan" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"extender-controller extender-profile" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"extension-controller dataplan" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"extension-controller extender" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"extension-controller extender-profile" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"extension-controller fortigate" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"extension-controller fortigate-profile" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall access-proxy api-gateway service" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "saas"]
	} else {
		set opts [cli_update_opts 0 $opts "saas"]
	}
	return $opts
}
	%}
	"firewall access-proxy api-gateway {application}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall access-proxy api-gateway6 service" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "saas"]
	} else {
		set opts [cli_update_opts 0 $opts "saas"]
	}
	return $opts
}
	%}
	"firewall access-proxy api-gateway6 {application}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall access-proxy client-cert" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return "enable"
	}
	return "disable"
}
	%}
	"firewall access-proxy {add-vhost-domain-to-dnsdb}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall access-proxy-virtual-host {replacemsg-group}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall access-proxy6 api-gateway service" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "saas"]
	} else {
		set opts [cli_update_opts 0 $opts "saas"]
	}
	return $opts
}
	%}
	"firewall access-proxy6 api-gateway {application}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall access-proxy6 api-gateway6 service" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "saas"]
	} else {
		set opts [cli_update_opts 0 $opts "saas"]
	}
	return $opts
}
	%}
	"firewall access-proxy6 api-gateway6 {application}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall access-proxy6 client-cert" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return "enable"
	}
	return "disable"
}
	%}
	"firewall access-proxy6 {add-vhost-domain-to-dnsdb}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall global" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall internet-service {country6 region6 city6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall internet-service {ip6-range-number extra-ip6-range-number}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall internet-service-addition entry port-range end-port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1225] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"firewall internet-service-addition entry port-range start-port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1225] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"firewall internet-service-addition entry {addr-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall internet-service-append {addr-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall internet-service-custom entry port-range end-port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1225] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"firewall internet-service-custom entry port-range start-port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1225] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"firewall internet-service-custom entry {addr-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall internet-service-custom entry {dst6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall internet-service-extension disable-entry port-range end-port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1225] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"firewall internet-service-extension disable-entry port-range start-port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1225] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"firewall internet-service-extension disable-entry {addr-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall internet-service-extension disable-entry {ip6-range}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall internet-service-extension entry port-range end-port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1225] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"firewall internet-service-extension entry port-range start-port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1225] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"firewall internet-service-extension entry {addr-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall internet-service-extension entry {dst6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall ippool pba-timeout" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1225] } {
		return "86400,3"
	}
	return "300,3"
}
	%}
	"firewall policy {internet-service6 internet-service6-src reputation-minimum6 reputation-direction6 internet-service6-negate internet-service6-src-negate}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall policy {internet-service6-name internet-service6-group internet-service6-custom internet-service6-custom-group internet-service6-src-name internet-service6-src-group internet-service6-src-custom internet-service6-src-custom-group}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall profile-protocol-options cifs tcp-window-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return "auto-tuning"
	}
	return "system"
}
	%}
	"firewall profile-protocol-options ftp tcp-window-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return "auto-tuning"
	}
	return "system"
}
	%}
	"firewall profile-protocol-options ftp {explicit-ftp-tls}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall profile-protocol-options http tcp-window-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return "auto-tuning"
	}
	return "system"
}
	%}
	"firewall profile-protocol-options http {verify-dns-for-policy-matching}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall profile-protocol-options ssh tcp-window-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return "auto-tuning"
	}
	return "system"
}
	%}
	"firewall proxy-address type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "saas"]
	} else {
		set opts [cli_update_opts 0 $opts "saas"]
	}
	return $opts
}
	%}
	"firewall proxy-address {application}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"firewall shaping-policy {uuid uuid-idx}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"icap server max-connections" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1225] } {
		return "4294967295,0"
	}
	return "65535,1"
}
	%}
	"router bgp as" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	return "0"
}
	%}
	"router bgp neighbor local-as" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	return "0"
}
	%}
	"router bgp neighbor remote-as" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	return "0"
}
	%}
	"router bgp neighbor-group local-as" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	return "0"
}
	%}
	"router bgp neighbor-group remote-as" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	return "0"
}
	%}
	"router bgp {recursive-inherit-priority}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"router policy6 dst" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return ""
	}
	return "::/0"
}
	%}
	"router policy6 src" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return ""
	}
	return "::/0"
}
	%}
	"router policy6 {input-device-negate src-negate dst-negate action}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"router policy6 {srcaddr dstaddr internet-service-id internet-service-custom}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"router static6 {weight dstaddr}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"switch-controller dsl policy" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"switch-controller igmp-snooping {query-interval}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch ports {igmp-snooping-flood-reports mcast-snooping-flood-traffic dsl-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch ports {igmps-flood-reports igmps-flood-traffic}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"switch-controller switch-profile {revision-backup-on-logout revision-backup-on-upgrade}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system accprofile {system-execute-ssh system-execute-telnet}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system admin {radius-vdom-override}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system admin {vdom-override}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system automation-action action-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "system-actions"]
	} else {
		set opts [cli_update_opts 0 $opts "system-actions"]
	}
	return $opts
}
	%}
	"system automation-action {headers}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system automation-action {http-headers}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system automation-action {system-action}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system automation-trigger event-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "local-cert-near-expiry"]
	} else {
		set opts [cli_update_opts 0 $opts "local-cert-near-expiry"]
	}
	return $opts
}
	%}
	"system automation-trigger trigger-frequency" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "once"]
	} else {
		set opts [cli_update_opts 0 $opts "once"]
	}
	return $opts
}
	%}
	"system automation-trigger {trigger-datetime}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system central-management server-list server-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "iot-collect" "iot-query"]
	} else {
		set opts [cli_update_opts 0 $opts "iot-collect" "iot-query"]
	}
	return $opts
}
	%}
	"system cluster-sync" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system dhcp server exclude-range {vci-match}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system dhcp server exclude-range {vci-string}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system dhcp server ip-range {vci-match}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system dhcp server ip-range {vci-string}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system dhcp server options {vci-match}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system dhcp server options {vci-string}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system dns {fqdn-cache-ttl fqdn-min-refresh}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system dns-database view" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "shadow-ztna"]
	} else {
		set opts [cli_update_opts 0 $opts "shadow-ztna"]
	}
	return $opts
}
	%}
	"system external-resource user-agent" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return ""
	}
	return "curl/7.58.0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1225] } {
		return "255"
	}
	return "127"
}
	%}
	"system fortiguard proxy-server-ip" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return ""
	}
	return "0.0.0.0"
}
	%}
	"system fortiguard {auto-firmware-upgrade auto-firmware-upgrade-day auto-firmware-upgrade-start-hour auto-firmware-upgrade-end-hour}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system global admin-server-cert" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return "Fortinet_GUI_Server"
	}
	return "self-sign"
}
	%}
	"system global miglog-affinity" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1225] } {
		return "79"
	}
	return "19"
}
	%}
	"system global sslvpn-cipher-hardware-acceleration" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return "disable"
	}
	return "enable"
}
	%}
	"system global sslvpn-kxp-hardware-acceleration" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return "disable"
	}
	return "enable"
}
	%}
	"system global sslvpn-plugin-version-check" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return "disable"
	}
	return "enable"
}
	%}
	"system global {dst}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system global {gui-app-detection-sdwan admin-host ipv6-allow-multicast-probe ipv6-allow-local-in-slient-drop ipsec-round-robin}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system ha schedule" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 0 $opts "hub"]
	} else {
		set opts [cli_update_opts 1 $opts "hub"]
	}
	return $opts
}
	%}
	"system ha vcluster {pingserver-secondary-force-reset}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system ha vcluster {pingserver-slave-force-reset}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system ha {pingserver-secondary-force-reset}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system ha {pingserver-slave-force-reset}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system interface algorithm" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "Source-MAC"]
	} else {
		set opts [cli_update_opts 0 $opts "Source-MAC"]
	}
	return $opts
}
	%}
	"system interface fail-alert-interfaces name" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1225] } {
		return "15"
	}
	return "79"
}
	%}
	"system interface mode" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "pppoa"]
	} else {
		set opts [cli_update_opts 0 $opts "pppoa"]
	}
	return $opts
}
	%}
	"system interface {lacp-ha-slave}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system interface {switch-controller-netflow-collect lacp-ha-secondary aggregate-type vpi vci atm-protocol mux-type gwaddr phy-mode tc-mode retransmission vectoring sfp-dsl sfp-dsl-autodetect sfp-dsl-adsl-fallback sfp-dsl-mac pvc-chan pvc-vlan-id pvc-vlan-tx-id pvc-vlan-rx-id pvc-vlan-tx-op pvc-vlan-rx-op pvc-crc pvc-atm-qos pvc-pcr pvc-scr gateway-address}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system ipam {pool-subnet}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system ipam {pools rules}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system lte-modem {sim1-pin sim2-pin}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system netflow collector-ip" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return ""
	}
	return "0.0.0.0"
}
	%}
	"system netflow source-ip" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return ""
	}
	return "0.0.0.0"
}
	%}
	"system np6xlite {ipsec-throughput-msg-frequency ipsec-sts-timeout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system sdwan health-check detect-mode" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1366] } {
		set opts [cli_update_opts 1 $opts "agent-based"]
	} else {
		set opts [cli_update_opts 0 $opts "agent-based"]
	}
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "remote"]
	} else {
		set opts [cli_update_opts 0 $opts "remote"]
	}
	return $opts
}
	%}
	"system sdwan health-check sla {priority-in-sla priority-out-sla}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system sdwan health-check {embed-measured-health sla-id-redistribute}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system settings gui-ztna" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return "enable"
	}
	return "disable"
}
	%}
	"system settings vdom-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "lan-extension"]
	} else {
		set opts [cli_update_opts 0 $opts "lan-extension"]
	}
	return $opts
}
	%}
	"system settings {lan-extension-controller-addr nat46-generate-ipv6-fragment-header gui-advanced-wireless-features fqdn-session-check ext-resource-session-check dyn-addr-session-check}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system standalone-cluster {cluster-peer}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"system vdom-netflow collector-ip" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return ""
	}
	return "0.0.0.0"
}
	%}
	"system vdom-netflow source-ip" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return ""
	}
	return "0.0.0.0"
}
	%}
	"user ldap {two-factor-filter}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"user saml {auth-url}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"videofilter youtube-channel-filter {override-category}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"vpn certificate ca {obsolete}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"vpn certificate local {private-key-retain}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"vpn certificate setting {cert-expire-warning}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1 {rsa-signature-hash-override}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1-interface {rsa-signature-hash-override link-cost packet-redistribution}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"vpn ssl settings {ztna-trusted-client}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"vpn ssl web portal ip-mode" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1366] } {
		set opts [cli_update_opts 1 $opts "no-ip"]
	} else {
		set opts [cli_update_opts 0 $opts "no-ip"]
	}
	if { [cli_branchpt_start 700 1225] } {
		set opts [cli_update_opts 1 $opts "dhcp"]
	} else {
		set opts [cli_update_opts 0 $opts "dhcp"]
	}
	return $opts
}
	%}
	"vpn ssl web portal {dhcp-ip-overlap}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"wanopt settings {tunnel-optimization}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"web-proxy explicit {pac-file-through-https}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"webfilter override expires" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return "1969/12/31 16:00:00"
	}
	return "1969/12/31 17:00:00"
}
	%}
	"wireless-controller snmp user name" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1225] } {
		return ""
	}
	return "test"
}
	%}
	"wireless-controller vap radius-mac-mpsk-timeout" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1225] } {
		return "864000,300"
	}
	return "864000,1800"
}
	%}
	"wireless-controller vap {rates-11ac-ss12 rates-11ac-ss34 rates-11ax-ss12 rates-11ax-ss34}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"wireless-controller vap {sae-h2e-only sae-pk sae-private-key rates-11ac-mcs-map rates-11ax-mcs-map l3-roaming-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-1 {80211d}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-2 {80211d}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-3 {80211d}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile radio-4 {80211d}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1225] } {
		return 0
	}
}
	%}
	"user quarantine targets" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 1225] } {
		return "0,4000,0"
	}
	return "512,256,0"
}
	%}
	"emailfilter profile options" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1225] } {
		set feature_set [cli_get_value $CLI_CUR_PARENT_NODE "" "" "feature-set"]
		if { $feature_set eq "flow" } {
			set opts [cli_update_opts 0 $opts "spamfsip" "spamfssubmit" "spamfschksum" "spamfsurl" "spamhelodns" "spamraddrdns" "spamrbl" "spamfsphish"]
		} else {
			set opts [cli_update_opts 1 $opts "spamfsip" "spamfssubmit" "spamfschksum" "spamfsurl" "spamhelodns" "spamraddrdns" "spamrbl" "spamfsphish"]
		}
	}
	return $opts
}
	%}
	"antivirus profile http {unknown-content-encoding}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] || [cli_branchpt_start 700 1366] } {
		return 0
	}
	return 1
}
	%}
	"extension-controller extender {firmware-provision-latest}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"firewall {access-proxy access-proxy6} empty-cert-action" = %{
if { $CLI_GET_TN } {
if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1235] } {
		set opts [cli_update_opts 1 $opts "accept-unmanageable"]
	} else {
		set opts [cli_update_opts 0 $opts "accept-unmanageable"]
	}
	return $opts
}
	%}
	"firewall {access-proxy access-proxy6} user-agent-detect" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"firewall address6 {tenant epg-name sdn-tag}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"firewall network-service-dynamic" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"firewall network-service-src-dynamic" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"firewall policy {srcaddr6-negate dstaddr6-negate}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"firewall security-policy {internet-service6 internet-service6-name internet-service6-negate internet-service6-group internet-service6-custom internet-service6-custom-group internet-service6-src internet-service6-src-name internet-service6-src-negate internet-service6-src-group internet-service6-src-custom internet-service6-src-custom-group}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"firewall sniffer {ipv6 non-ip host port protocol vlan}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"gtp message-filter-v0v1 {ue-registration-query}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"gtp message-filter-v2 {remote-ue-report-notif-ack dlink-notif-failure stop-paging-indication pgw-dlink-notif-ack identification-req-resp forward-access-notif-ack relocation-cancel-req-resp configuration-transfer-tunnel detach-notif-ack cs-paging ran-info-relay alert-mme-notif-ack ue-activity-notif-ack isr-status ue-registration-query-req-resp create-forwarding-tunnel-req-resp create-indirect-forwarding-tunnel-req-resp delete-indirect-forwarding-tunnel-req-resp release-access-bearer-req-resp dlink-data-notif-ack reserved-for-earlier-version pgw-restart-notif-ack modify-access-req-resp mbms-session-start-req-resp mbms-session-update-req-resp mbms-session-stop-req-resp}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"system external-resource {update-method}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"system federated-upgrade node-list device-type" = %{
if { $CLI_GET_TN } {
if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1235] } {
		set opts [cli_update_opts 1 $opts "fortiextender"]
	} else {
		set opts [cli_update_opts 0 $opts "fortiextender"]
	}
	return $opts
}
	%}
	"system fortiguard {sandbox-inline-scan}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"system global {fortiextender-provision-on-authorization early-tcp-npu-session}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"system sdn-connector external-account-list {external-id}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"system sdn-connector type" = %{
if { $CLI_GET_TN } {
if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1235] } {
		set opts [cli_update_opts 1 $opts "sap"]
	} else {
		set opts [cli_update_opts 0 $opts "sap"]
	}
	return $opts
}
	%}
	"system settings {nat46-force-ipv4-packet-forwarding nat64-force-ipv6-packet-forwarding}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"system snmp {community user} events" = %{
if { $CLI_GET_TN } {
if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1235] } {
		set opts [cli_update_opts 1 $opts "pool-usage"]
	} else {
		set opts [cli_update_opts 0 $opts "pool-usage"]
	}
	return $opts
}
if { $CLI_GET_TD } {
	set opts $CLI_CUR_VALUE
	if { ![cli_branchpt_start 700 1235] } {
		set opts [cli_update_opts 0 $opts "pool-usage"]
	}
	return $opts
}
	%}
	"system standalone-cluster cluster-peer {ike-monitor ike-monitor-interval ike-heartbeat-interval ike-use-rfc6311}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"system vdom-link type" = %{
if { $CLI_GET_TN } {
if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1235] } {
		set opts [cli_update_opts 1 $opts "npupair"]
	} else {
		set opts [cli_update_opts 0 $opts "npupair"]
	}
	return $opts
}
	%}
	"user radius {mac-username-delimiter mac-password-delimiter mac-case}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"vpn ipsec {phase1-interface phase1} {fgsp-sync inbound-dscp-copy}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"vpn ipsec {phase2-interface phase2} {inbound-dscp-copy}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"wireless-controller vap {sticky-client-threshold-6g application-dscp-marking}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1235] } {
		return 0
	}
}
	%}
	"wireless-controller {wtp wtp-profile} {radio-1 radio-2 radio-3 radio-4}" = %{
if { $CLI_GET_TN } {
if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1235] } {
		set opts [cli_update_opts 1 $opts "802.11ax-6G"]
	} else {
		set opts [cli_update_opts 0 $opts "802.11ax-6G"]
	}
	return $opts
}
	%}
	"system interface {inbandwidth outbandwidth}" = %{
if { $CLI_GET_TT } {
	if { ![cli_branchpt_start 700 1235] } {
		namespace import global::platform_digit_start
		if { ![platform_digit_start $plat "FGT_4000D"] } {
			return "16776000,0"
		}
	}
}
	%}
	"router policy6" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { ![cli_branchpt_start 700 1235] } {
		return "512,256,0"
	}
}
	%}
	"firewall shaper per-ip-shaper max-bandwidth" = %{
if { $CLI_GET_TT } {
	if { ![cli_branchpt_start 700 1235] } {
		return "16776000,0"
	}
}
	%}
	"firewall shaper traffic-shaper {exceed-bandwidth guaranteed-bandwidth maximum-bandwidth}" = %{
if { $CLI_GET_TT } {
	if { ![cli_branchpt_start 700 1235] } {
		return "16776000,0"
	}
}
	%}
	"endpoint-control client {info2}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1238] } {
		return 0
	}
}
	%}
	"endpoint-control fctems {tenant-id}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1238] } {
		return 0
	}
}
	%}
	"endpoint-control fctems {capabilities}" = %{
if { $CLI_GET_TN } {
if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1238] } {
		set opts [cli_update_opts 1 $opts "tenant-id"]
	} else {
		set opts [cli_update_opts 0 $opts "tenant-id"]
	}
	return $opts
}
	%}
	"system sdwan zone" = %{
if { $CLI_GET_RV } {
	if { [cli_reserved_value_is "SASE"] } {
		if { $CLI_GLOBAL_DEV } {
			return 0
		}
		if { [cli_branchpt_start 700 1143] } {
			return 0
		}
	}
}
	%}
	"endpoint-control fctems ems-id" = %{
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1366] } {
		return "7,1"
	}
	return "5,1"
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
	"automation setting fabric-sync" = %{
## SASE-specific attribute, no global support
if { $CLI_GLOBAL_DEV } { return 0 }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1366] } {
		return 1
	}
	if { [cli_get_devinfo "SASE"] eq "no" } {
		return 0
	}
}
	%}
	"system global extender-ipam-reserved-network" = %{
## SASE-specific attribute, no global support
if { $CLI_GLOBAL_DEV } { return 0 }
if { $CLI_GET_TO } {
	if { [cli_get_devinfo "SASE"] eq "no" } {
		return 0
	}
}
	%}
	"antivirus exempt-list" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"application list options" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1366] } {
		set opts [cli_update_opts 0 $opts "allow-quic"]
	} else {
		set opts [cli_update_opts 1 $opts "allow-quic"]
	}
	return $opts
}
	%}
	"endpoint-control fctems {trust-ca-cn ca-cn-info}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"extension-controller extender authorized" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1366] } {
		return "discovered"
	}
	return "disable"
}
	%}
	"extension-controller fortigate authorized" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1366] } {
		return "discovered"
	}
	return "disable"
}
	%}
	"firewall access-proxy {api-gateway api-gateway6} {ssl-renegotiation}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall access-proxy {api-gateway api-gateway6} realservers {translate-host}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall {access-proxy access-proxy6} log-blocked-traffic" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1366] } {
		return "enable"
	}
	return "disable"
}
	%}
	"firewall {access-proxy access-proxy6} {http-supported-max-version svr-pool-multiplex svr-pool-ttl svr-pool-server-max-request}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall access-proxy6 {api-gateway api-gateway6} realservers {translate-host}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall access-proxy6 {api-gateway api-gateway6} {ssl-renegotiation}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall auth-portal {proxy-auth}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall internet-service-append append-port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1366] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"firewall internet-service-extension disable-entry ip6-range id" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1366] } {
		return "0"
	}
	return "67108864"
}
	%}
	"firewall ippool {exclude-ip}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall ippool {subnet-broadcast-in-ippool}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall {local-in-policy local-in-policy6} {virtual-patch}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall policy match-vip" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1366] } {
		return "enable"
	}
	return "disable"
}
	%}
	"firewall policy {ztna-device-ownership ztna-tags-match-logic policy-expiry-date-utc ztna-policy-redirect}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall profile-protocol-options http {unknown-content-encoding}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall proxy-address name" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1366] } {
		return "79"
	}
	return "35"
}
	%}
	"firewall proxy-address ua" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1366] } {
		set opts [cli_update_opts 1 $opts "ie" "edge"]
	} else {
		set opts [cli_update_opts 0 $opts "ie" "edge"]
	}
	return $opts
}
	%}
	"firewall proxy-address {ua-min-ver ua-max-ver}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall proxy-addrgrp name" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1366] } {
		return "79"
	}
	return "63"
}
	%}
	"firewall proxy-policy {internet-service6 internet-service6-negate}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall proxy-policy {internet-service6-name internet-service6-group internet-service6-custom internet-service6-custom-group}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall schedule onetime {start-utc end-utc}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall security-policy {srcaddr6-negate dstaddr6-negate}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall service custom {visibility}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall {vip vip6} realservers {translate-host}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall vip {http-multiplex-ttl http-multiplex-max-request http-supported-max-version ssl-server-renegotiation}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall vip6 {arp-reply}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"firewall vip6 {ndp-reply ssl-server-renegotiation}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"icap profile {comment}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"ips sensor entries last-modified" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1366] } {
		return ""
	}
	return "before 00/00/00"
}
	%}
	"log eventfilter {webproxy}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"log {tacacs+accounting tacacs+accounting2 tacacs+accounting3} setting {source-ip interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"router bgp {neighbor neighbor-group} {allowas-in allowas-in6 allowas-in-vpnv4}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1366] } {
		return "3"
	}
	return "0"
}
	%}
	"router bgp neighbor connect-timer" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1366] } {
		return "65535,1"
	}
	return "65535,0"
}
	%}
	"router bgp neighbor-group connect-timer" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1366] } {
		return "65535,1"
	}
	return "65535,0"
}
	%}
	"router bgp neighbor-group {password}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"router extcommunity-list" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"router route-map rule match-vrf" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1366] } {
		return "251,0"
	}
	return "63,0"
}
	%}
	"router route-map rule {match-extcommunity match-extcommunity-exact}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"router static vrf" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1366] } {
		return "-1"
	}
	return "0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1366] } {
		return "251,0"
	}
	return "63,0"
}
	%}
	"router static {tag}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"router static6 vrf" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1366] } {
		return "251,0"
	}
	return "63,0"
}
	%}
	"switch-controller managed-switch ports {link-status poe-mode-bt-cabable poe-port-mode poe-port-priority poe-port-power}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch {dhcp-snooping-static-client}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"switch-controller security-policy 802-1X {guest-vlanid auth-fail-vlanid}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"switch-controller system {dynamic-periodic-interval nac-periodic-interval}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1366] } {
		return "60"
	}
	return "15"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1366] } {
		return "180,5"
	}
	return "60,5"
}
	%}
	"system accprofile utmgrp-permission {data-leak-prevention}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system accprofile utmgrp-permission {data-loss-prevention}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system automation-trigger {ioc-level}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system central-management {fortigate-cloud-sso-default-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system csf trusted-list {index}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system device-upgrade" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system dhcp server ip-range" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 1366] } {
		return "0,0,10"
	}
	return "0,0,3"
}
	%}
	"system dhcp server {ip-range exclude-range} {uci-match lease-time}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system dhcp server {ip-range exclude-range} {uci-string}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system dhcp server options {uci-match}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system dhcp server options {uci-string}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system external-resource {server-identity-check}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system fabric-vpn" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system federated-upgrade failure-reason" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1366] } {
		set opts [cli_update_opts 1 $opts "node-failed" "config-error-log-nonempty"]
	} else {
		set opts [cli_update_opts 0 $opts "node-failed" "config-error-log-nonempty"]
	}
	return $opts
}
	%}
	"system federated-upgrade status" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1366] } {
		set opts [cli_update_opts 1 $opts "coordinating"]
	} else {
		set opts [cli_update_opts 0 $opts "coordinating"]
	}
	return $opts
}
	%}
	"system global cmdbsvr-affinity" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1366] } {
		return "1"
	}
	return "0"
}
	%}
	"system global ha-affinity" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1366] } {
		return "1"
	}
	return "0"
}
	%}
	"system global internet-service-database" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1375] } {
		set opts [cli_update_opts 1 $opts "on-demand"]
	} else {
		set opts [cli_update_opts 0 $opts "on-demand"]
	}
	return $opts
}
	%}
	"system global switch-controller-reserved-network" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1366] } {
		return "10.255.0.1 255.255.0.0"
	}
	return "10.255.0.0 255.255.0.0"
}
	%}
	"system global {proxy-re-authentication-mode admin-maintainer}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system global {wad-restart-mode wad-restart-start-time wad-restart-end-time proxy-keep-alive-mode proxy-re-authentication-time ip-fragment-mem-thresholds log-single-cpu-high admin-forticloud-sso-default-profile interface-subnet-usage sflowd-max-children-num syslog-affinity}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system interface ipv6 {dhcp6-relay-source-interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system interface vrf" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1366] } {
		return "251,0"
	}
	return "63,0"
}
	%}
	"system replacemsg custom-message" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system sdn-connector {alt-resource-ip server-cert server-ca-cert}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system sdwan health-check vrf" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1366] } {
		return "251,0"
	}
	return "63,0"
}
	%}
	"system sdwan service {agent-exclusive}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system settings {detect-unknown-esp gui-dlp-profile gui-proxy-inspection internet-service-database-cache}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system settings {gui-local-reports}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system speed-test-server host {longitude latitude distance}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"system sso-fortigate-cloud-admin" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"user ldap {account-key-upn-san}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"user radius {nas-id-type nas-id}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"vpn certificate setting {proxy proxy-port proxy-username proxy-password}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"vpn ssl client {ipv4-subnets ipv6-subnets}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"vpn ssl web portal bookmark-group bookmarks {vnc-keyboard-layout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"vpn ssl web portal {dhcp-ra-giaddr dhcp6-ra-linkaddr client-src-range}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"vpn ssl web {user-bookmark user-group-bookmark} bookmarks {vnc-keyboard-layout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"wanopt profile {cifs ftp http mapi tcp} log-traffic" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1366] } {
		return ""
	}
	return "enable"
}
	%}
	"wanopt profile ftp {ssl}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"web-proxy explicit {http-connection-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"web-proxy profile headers content" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 700 1366] } {
		return "1023"
	}
	return "511"
}
	%}
	"webfilter fortiguard {embed-image}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"webfilter urlfilter {ip4-mapped-ip6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"wireless-controller global {acd-process-count}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"wireless-controller vap voice-enterprise" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1366] } {
		return "enable"
	}
	return "disable"
}
	%}
	"wireless-controller vap {captive-portal-fw-accounting}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1366] } {
		return 0
	}
}
	%}
	"endpoint-control client" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 1366] } {
		return "770000,0,0"
	}
	return "550000,0,0"
}
	%}
	"system interface secondaryip" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 700 1366] } {
		return "0,0,256"
	}
	return "0,0,32"
}
	%}
	"antivirus exempt-list status" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1375] } {
		return "enable"
	}
	return "enabled"
}
	%}
	"system admin gui-dashboard widget type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1375] } {
		set opts [cli_update_opts 1 $opts "logs-sent"]
	} else {
		set opts [cli_update_opts 0 $opts "logs-sent"]
	}
	return $opts
}
	%}
	"system admin gui-dashboard widget {logging-source}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1375] } {
		return 0
	}
}
	%}
	"system sso-admin gui-dashboard widget type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1375] } {
		set opts [cli_update_opts 1 $opts "logs-sent"]
	} else {
		set opts [cli_update_opts 0 $opts "logs-sent"]
	}
	return $opts
}
	%}
	"system sso-admin gui-dashboard widget {logging-source}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1375] } {
		return 0
	}
}
	%}
	"system sso-forticloud-admin gui-dashboard widget type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1375] } {
		set opts [cli_update_opts 1 $opts "logs-sent"]
	} else {
		set opts [cli_update_opts 0 $opts "logs-sent"]
	}
	return $opts
}
	%}
	"system sso-forticloud-admin gui-dashboard widget {logging-source}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1375] } {
		return 0
	}
}
	%}
	"system sso-fortigate-cloud-admin gui-dashboard widget type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1375] } {
		set opts [cli_update_opts 1 $opts "logs-sent"]
	} else {
		set opts [cli_update_opts 0 $opts "logs-sent"]
	}
	return $opts
}
	%}
	"system sso-fortigate-cloud-admin gui-dashboard widget {logging-source}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1375] } {
		return 0
	}
}
	%}
	"wireless-controller arrp-profile include-dfs-channel" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1375] } {
		return "enable"
	}
	return "disable"
}
	%}
	"wireless-controller arrp-profile include-weather-channel" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1375] } {
		return "enable"
	}
	return "disable"
}
	%}
	"wireless-controller arrp-profile weight-dfs-channel" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1375] } {
		return "0"
	}
	return "500"
}
	%}
	"wireless-controller arrp-profile weight-weather-channel" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1375] } {
		return "0"
	}
	return "1000"
}
	%}
	"wireless-controller vap {radius-mac-auth-block-interval}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1375] } {
		return 0
	}
}
	%}
	"firewall address sub-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 700 1383] } {
		set opts [cli_update_opts 1 $opts "fortipolicy-tag"]
	} else {
		set opts [cli_update_opts 0 $opts "fortipolicy-tag"]
	}
	return $opts
}
	%}
	"system global gui-cdn-usage" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 700 1373] } {
		set model_rank [cli_get_devinfo "model_rank"]
		if { $model_rank eq "HIGHEND" && [cli_get_devinfo "VM"] eq "no" } {
			return "disable"
		}
	}
	return "enable"
}
	%}
	"system global http-request-limit" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1389] } {
		return 0
	}
}
	%}
	"system global http-unauthenticated-request-limit" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 1393] } {
		return 0
	}
}
	%}
%};
