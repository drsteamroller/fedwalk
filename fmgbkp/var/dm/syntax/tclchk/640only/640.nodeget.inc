nodeget %{
	"firewall {hyperscale-policy hyperscale-policy64} poolname" = %{
if { $CLI_GET_TM } {
	if { [scan $CLI_CUR_VALUE "%lu,%lu,%lu" g v t] ne 3 } {
		return
	}
	set t 1
	return [format "%lu,%lu,%lu" $g $v $t]
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
	"system replacemsg {mail http webproxy ftp nntp fortiguard-wf spam im alertmail admin sslvpn ec nac-quar traffic-quota mms device-detection-portal utm auth captive-portal-dflt mm1 mm3 mm4 mm7 icap} {buffer smil-part message html-part rsp-text subject from domain}" = %{
if { $CLI_GET_TD } {
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		set item [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
		return [cli_replmsg_defval $CLI_CUR_PARENT_NAME $item $CLI_CUR_NODE_NAME]
	}
}
	%}
	"system replacemsg {mail http webproxy ftp nntp fortiguard-wf spam im alertmail admin sslvpn ec nac-quar traffic-quota mms device-detection-portal utm auth captive-portal-dflt mm1 mm3 mm4 mm7 icap} {header format rsp-status class priority from-sender sender-visibility add-smil charset add-html addr-type allow-content-adaptation}" = %{
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
	"system resource-limits {webproxy}" = %{
if { $CLI_GET_TT } {
	set m [cli_feature_value "webproxy_user_limits"]
	if { $m > 0 } {
		return "$m,1"
	}
}
	%}
	"system resource-limits {proxy}" = %{
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
	if { [cli_branchpt_start 600 1773] } {
		set nopts [cli_update_opts 1 $nopts "U231F"]
	} else {
		set nopts [cli_update_opts 0 $nopts "U231F"]
	}
	if { [cli_branchpt_start 600 1700] } {
		set nopts [cli_update_opts 1 $nopts "231F"]
	} else {
		set nopts [cli_update_opts 0 $nopts "231F"]
	}
	if { [cli_branchpt_start 600 1708] } {
		set nopts [cli_update_opts 1 $nopts "23JF" "234F" "432F"]
	} else {
		set nopts [cli_update_opts 0 $nopts "23JF" "234F" "432F"]
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
	if { [cli_branchpt_start 600 1773] } {
		set nopts [cli_update_opts 1 $nopts "U231F"]
	} else {
		set nopts [cli_update_opts 0 $nopts "U231F"]
	}
	if { [cli_branchpt_start 600 1700] } {
		set nopts [cli_update_opts 1 $nopts "231F"]
	} else {
		set nopts [cli_update_opts 0 $nopts "231F"]
	}
	if { [cli_branchpt_start 600 1708] } {
		set nopts [cli_update_opts 1 $nopts "23JF" "234F" "432F"]
	} else {
		set nopts [cli_update_opts 0 $nopts "23JF" "234F" "432F"]
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
		return 1
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
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		return "15"
	}
	if { [cli_branchpt_start 600 1773] } {
		return "14 5"
	}
	return ""
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
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "md5"]
	}
}
	%}
	"router ospf area virtual-link authentication" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "md5"]
	}
}
	%}
	"router ospf ospf-interface authentication" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
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
	if { [cli_get_devinfo "hdd"] eq "yes" } {
		return "enable"
	}
	return "disable"
}
	%}
	"certificate {local crl}" = %{
if { $CLI_GET_TO } {
	if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
		return 1
	}
	return 0
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
		if { ![string match -nocase "FortiWiFi-40F*" $platform] && ![string match -nocase "FortiWiFi-60E*" $platform] && ![string match -nocase $platform "FortiWiFi-60F"] && ![string match -nocase $platform "FortiWiFi-61E"] && ![string match -nocase $platform "FortiWiFi-61F"] && ![string match -nocase "FortiWiFi-80F*" $platform] && ![string match -nocase "FortiWiFi-81F*" $platform] } {
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
if { $CLI_GLOBAL_DEV } { return }
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
	if { [cli_branchpt_start 600 1902] } {
		return 0
	}
}
	%}
	"ips sensor {filter override}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"log disk setting {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
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
if { $CLI_GET_TD } {
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		namespace import global::sys_intf_is_media_iface
		namespace import global::platform_digit_suffix
		namespace import global::is_platform_support_hyperscale
		set platform [cli_get_devinfo "platform"]
		set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
		set ifname [string trim $ifname \"]
		if { [is_platform_support_hyperscale] } {
			if { [sys_intf_is_media_iface $ifname] } {
				## make the default as empty, to force show value as no-default-value behaviour as FGT's
				return ""
			}
		}
	}
	return $CLI_CUR_VALUE
}
if { $CLI_GET_TN } {
	namespace import global::sys_intf_is_media_iface
	namespace import global::platform_digit_suffix
	if { $CLI_SUPPORT_CDB_OPS } {
		set platform [cli_get_devinfo "platform"]
		set suffix [platform_digit_suffix $platform]
		if { [regexp -nocase {6000F|7000E|7000F} $suffix] } {
			namespace import global::sys_intf_forward_error_correction_option
			set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
			set ifname [string trim $ifname \"]
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
	"firewall {policy policy64 policy46}" = %{
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
		if { ![string match -nocase $platform "FortiCarrier-VM64-AWS"] && ![string match -nocase $platform "Fortigate-VM64-AWS"] && ![string match -nocase $platform "FortiCarrier-VM64-AWSONDEMAND"] && ![string match -nocase $platform "Fortigate-VM64-AWSONDEMAND"] } {
			return 0
		}
	}
}
if { $CLI_GET_TM } {
	set plat [cli_get_devinfo "platform"]
	if { [cli_get_devinfo "VM"] eq "yes" } {
		set model_rank [cli_get_devinfo "model_rank"]
		if { $model_rank eq "HIGHEND" } {
			if { [cli_branchpt_start 600 1903] } {
				return "500000,100000,0"
			}
			return "100000,100000,0"
		}
	}
	namespace import global::platform_digit_between
	if { [platform_digit_between $plat "3600E" "5001E"] } {
			if { [cli_branchpt_start 600 1903] } {
				return "500000,200000,0"
			}
			return "200000,200000,0"
	}
}
	%}
	"application list entries {sub-category}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"application name {sub-category}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"emailfilter profile mapi action" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1616] } {
		return "pass"
	}
	return "discard"
}
if { $CLI_GET_ND } {
	return [expr [cli_branchpt_start 600 1700]]
}
	%}
	"endpoint-control fctems call-timeout" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1700] } {
		return "30"
	}
	if { [cli_branchpt_start 600 1616] } {
		return "30000"
	}
	return "5000"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1700] } {
		return "180,1"
	}
	if { [cli_branchpt_start 600 1616] } {
		return "180000,500"
	}
	return "50000,500"
}
	%}
	"file-filter profile" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
if { $CLI_GET_TM } {
	if { ![cli_branchpt_start 600 1636] } {
		return "512,256,0"
	}
	return $CLI_CUR_VALUE
}
	%}
	"firewall consolidated policy {file-filter-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"firewall internet-service-append" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"firewall policy {file-filter-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"firewall policy6 {file-filter-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"firewall profile-group {file-filter-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"firewall profile-protocol-options {feature-set}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"firewall proxy-policy {file-filter-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"firewall security-policy {file-filter-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"log fortianalyzer override-setting server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "127"
	}
	return "63"
}
	%}
	"log fortianalyzer setting server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "127"
	}
	return "63"
}
	%}
	"log fortianalyzer2 override-setting server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "127"
	}
	return "63"
}
	%}
	"log fortianalyzer2 setting server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "127"
	}
	return "63"
}
	%}
	"log fortianalyzer3 override-setting server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "127"
	}
	return "63"
}
	%}
	"log fortianalyzer3 setting server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "127"
	}
	return "63"
}
	%}
	"log memory global-setting max-size" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	set ret $CLI_CUR_VALUE
	set p [cli_get_devinfo "platform"]
	set lst_v640_b1712 [ list "FortiCarrier-3000D|675988561|675989053" "FortiCarrier-3100D|675988561|675989053" "FortiCarrier-3200D|675980615|675981107" "FortiCarrier-3800D|1352776089|1352776458" "FortiCarrier-3810D|1352776253|1352776622" "FortiCarrier-3815D|1352776253|1352776622" "FortiCarrier-5001D|337623695|337624186" "FortiCarrier-5001E1|676001955|676002324" "FortiCarrier-5001E|676001955|676002324" "Fortigate-1100E|168268349|168268718" "Fortigate-1101E|168267161|168267530" "Fortigate-2000E|337626767|337627258" "Fortigate-200E|41549905|41550233" "Fortigate-201E|41549905|41550233" "Fortigate-2500E|337627422|337627914" "Fortigate-3000D|675988561|675989053" "Fortigate-300D|83848560|83848929" "Fortigate-300E|83680010|83680542" "Fortigate-301E|83678822|83679354" "Fortigate-3100D|675988561|675989053" "Fortigate-3200D|675980615|675981107" "Fortigate-3800D|1352776089|1352776458" "Fortigate-3810D|1352776253|1352776622" "Fortigate-3815D|1352776253|1352776622" "Fortigate-400D|83848560|83848929" "Fortigate-400E|83677429|83677798" "Fortigate-401E|83676241|83676610" "Fortigate-5001D|337623695|337624186" "Fortigate-5001E1|676001955|676002324" "Fortigate-5001E|676001955|676002324" "Fortigate-500D|83848560|83848929" "Fortigate-500E|168273551|168274083" "Fortigate-501E|168272363|168272896" "Fortigate-600D|83843317|83843686" "Fortigate-600E|168100577|168100945" "Fortigate-601E|168099389|168099758" "Fortigate-800D|83849666|83850035" "Fortigate-90E|21077155|21077647" "Fortigate-91E|21077155|21077647" ]
	foreach plat $lst_v640_b1712 {
		set platname [ split $plat "|" ]
		set len [ string length $p ]
		if { [string compare -nocase -length $len $p [lindex $platname 0]] eq 0 } {
			if { [cli_branchpt_start 600 1712] } {
				set ret [lindex $platname 1]
				return $ret
			} else {
				set ret [lindex $platname 2]
			}
			break
		}
	}
	set lst_v640_b1700 [ list "FortiCarrier-3300E|1015711866|1015712030" "FortiCarrier-3301E|1015710720|1015710883" "Fortigate-101E|31870853|31870935" "Fortigate-1500DT|168435712|168435875" "Fortigate-1500D|168435712|168435875" "Fortigate-3300E|1015711866|1015712030" "Fortigate-3301E|1015710720|1015710883" "Fortigate-60E-DSLJ|19570442|19570524" "Fortigate-60E-DSL|19570442|19570524" "Fortigate-60E|19570442|19570524" "Fortigate-800D|83850035|83850199" "Fortigate-81E-POE|19567820|19567902" ]
	foreach plat $lst_v640_b1700 {
		set platname [ split $plat "|" ]
		set len [ string length $p ]
		if { [string compare -nocase -length $len $p [lindex $platname 0]] eq 0 } {
			if { [cli_branchpt_start 600 1700] } {
				set ret [lindex $platname 1]
				return $ret
			} else {
				set ret [lindex $platname 2]
			}
			break
		}
	}
	set lst_v640_b1619 [ list "FortiCarrier-3300E|1015712030|1015712235" "FortiCarrier-3301E|1015710883|1015711047" "FortiCarrier-3400E|1013679267|1013679595" "FortiCarrier-3401E|1013678080|1013678407" "FortiCarrier-3600E|1013644124|1013644451" "FortiCarrier-3601E|1013642936|1013643264" "FortiOS-VM64-HV|20999413|20999618" "FortiOS-VM64-KVM|10508206|10508369" "FortiOS-VM64-Xen|21041807|21041971" "FortiOS-VM64|21085306|21085470" "Fortigate-2200E|506390937|506391265" "Fortigate-2201E|506389749|506390118" "Fortigate-3300E|1015712030|1015712235" "Fortigate-3301E|1015710883|1015711047" "Fortigate-3400E|1013679267|1013679595" "Fortigate-3401E|1013678080|1013678407" "Fortigate-3600E|1013644124|1013644451" "Fortigate-3601E|1013642936|1013643264" ]
	foreach plat $lst_v640_b1619 {
		set platname [ split $plat "|" ]
		set len [ string length $p ]
		if { [string compare -nocase -length $len $p [lindex $platname 0]] eq 0 } {
			if { [cli_branchpt_start 600 1619] } {
				set ret [lindex $platname 1]
				return $ret
			} else {
				set ret [lindex $platname 2]
			}
			break
		}
	}
	set lst_v640_b1616 [ list "FortiCarrier-3400E|1013679595|1013682094" "FortiCarrier-3401E|1013678407|1013680906" "FortiCarrier-3600E|1013644451|1013646745" "FortiCarrier-3601E|1013643264|1013645598" "FortiOS-VM64-Xen|21041971|10451394" "FortiOS-VM64|21085470|10494935" "FortiWiFi-60E-DSLJ|19542261|19542302" "FortiWiFi-60E-DSL|19542261|19542302" "FortiWiFi-60E|19542261|19542302" "Fortigate-2500E|337627914|337627955" "Fortigate-3400E|1013679595|1013682094" "Fortigate-3401E|1013678407|1013680906" "Fortigate-3600E|1013644451|1013646745" "Fortigate-3601E|1013643264|1013645598" ]
	foreach plat $lst_v640_b1616 {
		set platname [ split $plat "|" ]
		set len [ string length $p ]
		if { [string compare -nocase -length $len $p [lindex $platname 0]] eq 0 } {
			if { [cli_branchpt_start 600 1616] } {
				set ret [lindex $platname 1]
				return $ret
			} else {
				set ret [lindex $platname 2]
			}
			break
		}
	}
	return $ret
}
	%}
	"log syslogd override-setting server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "127"
	}
	return "63"
}
	%}
	"log syslogd setting server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "127"
	}
	return "63"
}
	%}
	"log syslogd2 override-setting server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "127"
	}
	return "63"
}
	%}
	"log syslogd2 setting server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "127"
	}
	return "63"
}
	%}
	"log syslogd3 override-setting server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "127"
	}
	return "63"
}
	%}
	"log syslogd3 setting server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "127"
	}
	return "63"
}
	%}
	"log syslogd4 override-setting server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "127"
	}
	return "63"
}
	%}
	"log syslogd4 setting server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "127"
	}
	return "63"
}
	%}
	"router static {sdwan}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"router static {virtual-wan-link}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"router static6 {sdwan}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"router static6 {virtual-wan-link}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"switch-controller global quarantine-mode" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1616] } {
		return "by-vlan"
	}
	return "by-redirect"
}
	%}
	"switch-controller system iot-weight-threshold" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "255,0"
	}
	return "4294967295,0"
}
	%}
	"system central-management {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system dns {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system fortiguard {anycast-sdns-server-ip anycast-sdns-server-port interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system global {gui-firmware-upgrade-setup-warning}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system global {gui-firmware-upgrade-warning irq-time-accounting}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system interface ipv6 {unique-autoconf-addr interface-identifier}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system sdn-connector use-metadata-iam" = %{
if { $CLI_GET_TD } {
	if { $CLI_SUPPORT_CDB_OPS } {
		cli_skip_cache
		set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
		if { $type eq "" } {
			## Fixing mantis 814468, to solve the case when loading for the first time, "type" is "".
			return ""
		} elseif { $type eq "aws" } {
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
	"system sdn-connector route-table {subscription-id}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system sdn-connector type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1616] } {
		set opts [cli_update_opts 1 $opts "ibm"]
	} else {
		set opts [cli_update_opts 0 $opts "ibm"]
	}
	return $opts
}
	%}
	"system sdn-connector vmx-image-url" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1616] } {
		return "4095"
	}
	return "127"
}
	%}
	"system sdn-connector {vcenter-server vcenter-username vcenter-password api-key compute-generation}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system sdn-connector {ibm-region-gen1 ibm-region-gen2}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] || ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system sdwan" = %{
if { $CLI_GET_TO } {
	if { $CLI_ADOM_DEV } {
		## 6.4 template only support "sdwan"
		return $CLI_CUR_VALUE
	} elseif { $CLI_GLOBAL_DEV } {
		## dbcache need to support both "virtual-wan-link" and "sdwan"
		return $CLI_CUR_VALUE
	}
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system sdwan {service health-check zone neighbor}" = %{
if { $CLI_GET_TO } {
	if { $CLI_ADOM_DEV } {
		## 6.4 template only support "sdwan"
		return $CLI_CUR_VALUE
	} elseif { $CLI_GLOBAL_DEV } {
		## dbcache need to support both "virtual-wan-link" and "sdwan"
		return $CLI_CUR_VALUE
	}
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system sdwan members" = %{
if { $CLI_GET_TO } {
	if { $CLI_ADOM_DEV } {
		## 6.4 template only support "sdwan"
		return $CLI_CUR_VALUE
	} elseif { $CLI_GLOBAL_DEV } {
		## dbcache need to support both "virtual-wan-link" and "sdwan"
		return $CLI_CUR_VALUE
	}
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
if { $CLI_GET_TM } {
	if { $CLI_GLOBAL_DEV } { return }
	if { [cli_branchpt_start 600 1708] } {
		return "0,512,0"
	}
	return "0,256,0"
}
	%}
	"system sdwan {service health-check} sla" = %{
if { $CLI_GET_TO } {
	if { $CLI_ADOM_DEV } {
		## 6.4 template only support "sdwan"
		return $CLI_CUR_VALUE
	} elseif { $CLI_GLOBAL_DEV } {
		## dbcache need to support both "virtual-wan-link" and "sdwan"
		return $CLI_CUR_VALUE
	}
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system sdwan health-check members" = %{
if { $CLI_GET_TO } {
	if { $CLI_ADOM_DEV } {
		## 6.4 template only support "sdwan"
		return $CLI_CUR_VALUE
	} elseif { $CLI_GLOBAL_DEV } {
		## dbcache need to support both "virtual-wan-link" and "sdwan"
		return $CLI_CUR_VALUE
	}
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system sdwan service {dst dst6 src src6 groups health-check input-device priority-members users}" = %{
if { $CLI_GET_TO } {
	if { $CLI_ADOM_DEV } {
		## 6.4 template only support "sdwan"
		return $CLI_CUR_VALUE
	} elseif { $CLI_GLOBAL_DEV } {
		## dbcache need to support both "virtual-wan-link" and "sdwan"
		return $CLI_CUR_VALUE
	}
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system sdwan service {internet-service-app-ctrl-group internet-service-app-ctrl internet-service-custom-group internet-service-custom internet-service-group internet-service-name}" = %{
if { $CLI_GET_TO } {
	if { $CLI_ADOM_DEV } {
		## 6.4 template only support "sdwan"
		return $CLI_CUR_VALUE
	} elseif { $CLI_GLOBAL_DEV } {
		## dbcache need to support both "virtual-wan-link" and "sdwan"
		return $CLI_CUR_VALUE
	}
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system settings {gui-file-filter}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
if { $CLI_GET_TD } {
	namespace import global::platform_digit_suffix
	set platform [cli_get_devinfo "platform"]
	set suffix [platform_digit_suffix $platform]
	if { ![cli_branchpt_start 600 1950] && [regexp -nocase {80F|80F_BYPASS|81F} $suffix] } {
		return "enable"
	}
	return $CLI_CUR_VALUE
}
	%}
	"system smc-ntp" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system vdom-dns {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system virtual-wan-link" = %{
if { $CLI_GET_TO } {
	if { $CLI_ADOM_DEV } {
		## 6.4 template no longer uses "virtual-wan-link"
		return 0
	} elseif { $CLI_GLOBAL_DEV } {
		## dbcache need to support both "virtual-wan-link" and "sdwan"
		return $CLI_CUR_VALUE
	}
	if { [cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system virtual-wan-link {service health-check members neighbor}" = %{
if { $CLI_GET_TO } {
	if { $CLI_ADOM_DEV } {
		## 6.4 template no longer uses "virtual-wan-link"
		return 0
	} elseif { $CLI_GLOBAL_DEV } {
		## dbcache need to support both "virtual-wan-link" and "sdwan"
		return $CLI_CUR_VALUE
	}
	if { [cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system virtual-wan-link {service health-check} sla" = %{
if { $CLI_GET_TO } {
	if { $CLI_ADOM_DEV } {
		## 6.4 template no longer uses "virtual-wan-link"
		return 0
	} elseif { $CLI_GLOBAL_DEV } {
		## dbcache need to support both "virtual-wan-link" and "sdwan"
		return $CLI_CUR_VALUE
	}
	if { [cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system virtual-wan-link health-check members" = %{
if { $CLI_GET_TO } {
	if { $CLI_ADOM_DEV } {
		## 6.4 template no longer uses "virtual-wan-link"
		return 0
	} elseif { $CLI_GLOBAL_DEV } {
		## dbcache need to support both "virtual-wan-link" and "sdwan"
		return $CLI_CUR_VALUE
	}
	if { [cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system virtual-wan-link service {dst dst6 src src6 groups health-check input-device priority-members users}" = %{
if { $CLI_GET_TO } {
	if { $CLI_ADOM_DEV } {
		## 6.4 template no longer uses "virtual-wan-link"
		return 0
	} elseif { $CLI_GLOBAL_DEV } {
		## dbcache need to support both "virtual-wan-link" and "sdwan"
		return $CLI_CUR_VALUE
	}
	if { [cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system virtual-wan-link service {internet-service-app-ctrl-group internet-service-app-ctrl internet-service-custom-group internet-service-custom internet-service-group internet-service-name}" = %{
if { $CLI_GET_TO } {
	if { $CLI_ADOM_DEV } {
		## 6.4 template no longer uses "virtual-wan-link"
		return 0
	} elseif { $CLI_GLOBAL_DEV } {
		## dbcache need to support both "virtual-wan-link" and "sdwan"
		return $CLI_CUR_VALUE
	}
	if { [cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"system interface" = %{
if { $CLI_GET_RV } {
	if { [cli_reserved_value_is "virtual-wan-link"] } {
		if { ![cli_branchpt_start 600 1700] } {
			set caller [cli_get_caller_category]
			if { $caller eq "firewall shaping-policy" } {
				return 1
			}
		}
		return [expr ![cli_branchpt_start 600 1616]]
	}
}
	%}
	"system vne-tunnel" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"user ldap {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"user radius accounting-server {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"user radius {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"user tacacs+ {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"vpn certificate setting {cmp-key-usage-checking}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
		return 0
	}
}
	%}
	"vpn ssl web realm {virtual-host-only}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1616] } {
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
	"wireless-controller wtp-profile radio-1 band" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1616] } {
		set opts [cli_update_opts 1 $opts "802.11ac-2G"]
	} else {
		set opts [cli_update_opts 0 $opts "802.11ac-2G"]
	}
	return $opts
}
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3 radio-4} vap-all" = %{
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
	"wireless-controller wtp-profile radio-2 band" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1616] } {
		set opts [cli_update_opts 1 $opts "802.11ac-2G"]
	} else {
		set opts [cli_update_opts 0 $opts "802.11ac-2G"]
	}
	return $opts
}
	%}
	"wireless-controller wtp-profile radio-3 band" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1616] } {
		set opts [cli_update_opts 1 $opts "802.11ac-2G"]
	} else {
		set opts [cli_update_opts 0 $opts "802.11ac-2G"]
	}
	return $opts
}
	%}
	"wireless-controller wtp-profile radio-4 band" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1616] } {
		set opts [cli_update_opts 1 $opts "802.11ac-2G"]
	} else {
		set opts [cli_update_opts 0 $opts "802.11ac-2G"]
	}
	return $opts
}
	%}
	"switch-controller nac-device"  = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 600 1616] } {
		return "0,1000,0"
	}
	return "0,8000,0"
}
	%}
	"system {admin sso-admin} gui-dashboard widget type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1773] } {
		set opts [cli_update_opts 1 $opts "wanopt-monitor" "wanopt-cache" "wanopt-peer"]
	} else {
		set opts [cli_update_opts 0 $opts "wanopt-monitor" "wanopt-cache" "wanopt-peer"]
	}
	if { [cli_branchpt_start 600 1700] } {
		set opts [cli_update_opts 0 $opts "security-fabric-ranking"]
	} else {
		set opts [cli_update_opts 1 $opts "security-fabric-ranking"]
	}
	if { [cli_branchpt_start 600 1619] } {
		set opts [cli_update_opts 1 $opts "interfering-ssids"]
		set opts [cli_update_opts 0 $opts "interfering-aps"]
	} else {
		set opts [cli_update_opts 0 $opts "interfering-ssids"]
		set opts [cli_update_opts 1 $opts "interfering-aps"]
	}
	return $opts
}
	%}
	"system vdom-exception id" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1619] } {
		return "4096,1"
	}
	return "4294967295,0"
}
	%}
	"system admin gui-dashboard csf" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1622] } {
		return "enable"
	}
	return "disable"
}
	%}
	"system sso-admin gui-dashboard csf" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1622] } {
		return "enable"
	}
	return "disable"
}
	%}
	"system standalone-cluster group-member-id" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1622] } {
		return "15,0"
	}
	return "3,0"
}
	%}
	"system accprofile utmgrp-permission {file-filter}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1636] } {
		return 0
	}
}
	%}
	"system admin {gui-ignore-release-overview-version}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1636] } {
		return 0
	}
}
	%}
	"system admin {gui-new-feature-acknowledge}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1636] } {
		return 0
	}
}
	%}
	"system sso-admin {gui-ignore-release-overview-version}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1636] || [cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system sso-admin {gui-new-feature-acknowledge}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1636] } {
		return 0
	}
}
	%}
	"wireless-controller vap {dhcp-option43-insertion}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1636] } {
		return 0
	}
}
	%}
	"user local {username-case-insensitivity}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1637] } {
		return 0
	}
}
	%}
	"user local {username-case-sensitivity}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1637] || [cli_branchpt_start 600 1902] } {
		return 0
	}
}
	%}
	"{cifs credential-store} domain-controller domain-name" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1700] } {
		return "255"
	}
	return "79"
}
	%}
	"credential-store domain-controller {hostname}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"emailfilter profile {gmail imap mapi msn-hotmail pop3 smtp yahoo-mail} {log-all}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"emailfilter profile {gmail imap mapi msn-hotmail pop3 smtp yahoo-mail} {log}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"emailfilter profile {other-webmails}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"extender-controller dataplan" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"extender-controller extender description" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1700] } {
		return "255"
	}
	return "31"
}
	%}
	"extender-controller extender {admin ifname role mode dial-mode redial redundant-intf dial-status conn-status quota-limit-mb billing-start-day at-dial-script modem-passwd initiated-update modem-type ppp-username ppp-password ppp-auth-protocol ppp-echo-request wimax-carrier wimax-realm wimax-auth-protocol sim-pin access-point-name multi-mode roaming cdma-nai aaa-shared-secret ha-shared-secret primary-ha secondary-ha cdma-aaa-spi cdma-ha-spi}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"extender-controller extender {controller-report modem1 modem2}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"extender-controller extender {id authorized login-password}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"file-filter profile {extended-log}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"firewall {DoS-policy DoS-policy6} {name}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"firewall {acl acl6} {name}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"firewall address6 type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1700] } {
		set opts [cli_update_opts 1 $opts "mac"]
	} else {
		set opts [cli_update_opts 0 $opts "mac"]
	}
	return $opts
}
	%}
	"firewall address6 {start-mac end-mac}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"firewall gtp ie-remove-policy {sgsn-addr6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"firewall gtp ip-policy {srcaddr6 dstaddr6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"firewall gtp policy-v2 rat-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1700] } {
		set opts [cli_update_opts 1 $opts "nr" "ltem"]
	} else {
		set opts [cli_update_opts 0 $opts "nr" "ltem"]
	}
	return $opts
}
	%}
	"firewall gtp {handover-group6 authorized-sgsns6 invalid-sgsns6-to-log authorized-ggsns6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"firewall internet-service-append match-port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1700] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"firewall internet-service-custom {id}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"firewall {multicast-policy multicast-policy6} {name}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"firewall {policy46 policy64 proxy-policy} {name}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"firewall profile-protocol-options cifs {file-filter server-keytab}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"firewall profile-protocol-options cifs {server-credential-type domain-controller}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"firewall security-policy {srcaddr-negate dstaddr-negate}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"log {fortianalyzer fortianalyzer-cloud fortianalyzer2 fortianalyzer3} {override-setting setting} {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	return [expr [cli_branchpt_start 600 1700]]
}
	%}
	"log fortiguard setting {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"log {syslogd syslogd2 syslogd3 syslogd4} {override-setting setting} {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"router static priority" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1700] } {
		return "65535,0"
	}
	return "4294967295,0"
}
	%}
	"router static6 priority" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1700] } {
		return "1024"
	}
	return "0"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1700] } {
		return "65535,1"
	}
	return "4294967295,0"
}
	%}
	"switch-controller global https-image-push" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1700] } {
		return "enable"
	}
	return "disable"
}
	%}
	"switch-controller global {allow-multiple-interfaces}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"switch-controller mac-policy {drop}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch dynamic-capability" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1700] } {
		return "0x00000000000000000000000000000000"
	}
	return "0"
}
	%}
	"switch-controller managed-switch ports {ptp-policy aggregator-mode rpvst-port}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set plat [cli_get_devinfo "platform"]
	set plats "FortiGate-5001E FortiGate-5001E1 FortiGate-5001D"
	if { [lsearch -nocase [split $plats " "] $plat] == -1 } {
		if { ![cli_branchpt_start 600 1700] } {
			return 0
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"switch-controller ptp policy" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set plat [cli_get_devinfo "platform"]
	set plats "FortiGate-5001E FortiGate-5001E1 FortiGate-5001D"
	if { [lsearch -nocase [split $plats " "] $plat] == -1 } {
		return [expr [cli_branchpt_start 600 1700]]
	}
	return $CLI_CUR_VALUE
}
	%}
	"switch-controller ptp settings" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set plat [cli_get_devinfo "platform"]
	set plats "FortiGate-5001E FortiGate-5001E1 FortiGate-5001D"
	if { [lsearch -nocase [split $plats " "] $plat] == -1 } {
		return [expr [cli_branchpt_start 600 1700]]
	}
	return $CLI_CUR_VALUE
}
	%}
	"switch-controller qos queue-policy cos-queue {ecn}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set plat [cli_get_devinfo "platform"]
	set plats "FortiGate-5001E FortiGate-5001E1 FortiGate-5001D"
	if { [lsearch -nocase [split $plats " "] $plat] == -1 } {
		if { ![cli_branchpt_start 600 1700] } {
			return 0
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"switch-controller switch-group {fortilink}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set plat [cli_get_devinfo "platform"]
	set plats "FortiGate-5001E FortiGate-5001E1 FortiGate-5001D"
	if { [lsearch -nocase [split $plats " "] $plat] == -1 } {
		if { ![cli_branchpt_start 600 1700] } {
			return 0
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"switch-controller system iot-holdoff" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1700] } {
		return "10080,0"
	}
	return "4294967295,0"
}
	%}
	"switch-controller system iot-mac-idle" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1700] } {
		return "10080,0"
	}
	return "4294967295,0"
}
	%}
	"switch-controller system iot-scan-interval" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1700] } {
		return "10080,2"
	}
	return "4294967295,2"
}
	%}
	"system 3g-modem custom {modeswitch-string}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system admin gui-dashboard widget {region industry}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system automation-action action-type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1700] } {
		set opts [cli_update_opts 1 $opts "quarantine-fortinac"]
	} else {
		set opts [cli_update_opts 0 $opts "quarantine-fortinac"]
	}
	return $opts
}
	%}
	"system external-resource {user-agent interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system fortisandbox {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system global {gui-lines-per-page log-uuid-policy ipsec-hmac-offload ipsec-asic-offload}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] } { 
		return 0
	}
}
	%}
	"system global {sslvpn-ems-sn-check}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system interface {dhcp-relay-interface-select-method dhcp-relay-interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system interface {egress-queues}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system isf-queue-profile" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system link-monitor protocol" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1700] } {
		set opts [cli_update_opts 0 $opts "ping6"]
	} else {
		set opts [cli_update_opts 1 $opts "ping6"]
	}
	return $opts
}
	%}
	"system npu {isf-np-queues}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system npu {qos-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system ntp ntpserver {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system replacemsg device-detection-portal" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system replacemsg nntp" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system replacemsg-group {nntp device-detection-portal}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system sdn-connector {ibm-region}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system sdwan health-check port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1700] } {
		return "0"
	}
	return "80"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1700] } {
		return "65535,0"
	}
	return "65535,1"
}
	%}
	"system sdwan health-check probe-timeout" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1700] } {
		return "3600000,500"
	}
	return "5000,500"
}
	%}
	"system sdwan health-check protocol" = %{
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1684] } {
		set opts [cli_update_opts 1 $opts "ftp" "tcp-connect"]
		set opts [cli_update_opts 0 $opts "ping6"]
	} else {
		set opts [cli_update_opts 0 $opts "ftp" "tcp-connect"]
		set opts [cli_update_opts 1 $opts "ping6"]
	}
	return $opts
}
	%}
	"system sdwan health-check {quality-measured-method user ftp-mode ftp-file dns-match-ip}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system sdwan service {minimum-sla-meet-members hash-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system settings {dhcp-proxy-interface-select-method dhcp-proxy-interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system settings {gui-domain-ip-reputation}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system sso-admin gui-dashboard widget {region industry}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system switch-interface {mac-ttl}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"system vdom-exception object" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1878] } {
		set opts [cli_update_opts 1 $opts "system.gre-tunnel"]
	} else {
		set opts [cli_update_opts 0 $opts "system.gre-tunnel"]
	}
	if { [cli_branchpt_start 600 1700] } {
		set opts [cli_update_opts 1 $opts "system.sdwan"]
		set opts [cli_update_opts 0 $opts "system.virtual-wan-link"]
	} else {
		set opts [cli_update_opts 0 $opts "system.sdwan"]
		set opts [cli_update_opts 1 $opts "system.virtual-wan-link"]
	}
	if { [cli_branchpt_start 600 1708] } {
		set opts [cli_update_opts 1 $opts "system.saml"]
	} else {
		set opts [cli_update_opts 0 $opts "system.saml"]
	}
	if { [cli_branchpt_start 600 1768] } {
		set opts [cli_update_opts 1 $opts "router.policy6" "router.policy"]
	} else {
		set opts [cli_update_opts 0 $opts "router.policy6" "router.policy"]
	}
	return $opts
}
	%}
	"user fsso {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"user radius {switch-controller-service-type}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"vpn certificate setting {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"vpn l2tp {lcp-echo-interval lcp-max-echo-fails}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"vpn ssl web portal bookmark-group bookmarks {domain}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"vpn ssl web realm {radius-port}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"vpn ssl web user-bookmark bookmarks {domain}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"vpn ssl web user-group-bookmark bookmarks {domain}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"webfilter fortiguard cache-mem-percent" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1700] } {
		return "1"
	}
	return "2"
}
	%}
	"wireless-controller arrp-profile" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"wireless-controller global data-ethernet-II" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1700] } {
		return "enable"
	}
	return "disable"
}
	%}
	"wireless-controller vap {bss-color-partial}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"wireless-controller wtp {radio-1 radio-2 radio-3 radio-4} {override-analysis spectrum-analysis}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"wireless-controller wtp {uuid}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"wireless-controller wtp {radio-1 radio-2 radio-3 radio-4} band" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1700] } {
		set opts [cli_update_opts 1 $opts "802.11ac-2G"]
	} else {
		set opts [cli_update_opts 0 $opts "802.11ac-2G"]
	}
	return $opts
}
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3 radio-4} {bss-color}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3 radio-4} {spectrum-analysis}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1700] } {
		return 0
	}
}
	%}
	"emailfilter profile {imap pop3 smtp} action" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_ND } {
	return [expr [cli_branchpt_start 600 1700]]
}
	%}
	"switch-controller nac-settings inactive-timer" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1700] } {
		return "65535,0"
	}
	return "255,0"
}
	%}
	"system replacemsg-image" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	namespace import global::platform_digit_start
	set plat [cli_get_devinfo "platform"]
	set model_rank [cli_get_devinfo "model_rank"]
	if { [cli_branchpt_start 600 1750] } {
		if { [platform_digit_start $plat "FGT_1000D"] } {
			return "32,0,0"
		} elseif { [platform_digit_start $plat "FGT_100E"] } {
			return "20,0,0"
		} elseif { [platform_digit_start $plat "FGT_30E"] } {
			return "10,0,0"
		} else {
			return "32,0,0"
		}
	} elseif { [cli_branchpt_start 600 1700] } {
		if { [platform_digit_start $plat "FGT_3000D"] } {
			return "32,0,0"
		} elseif { [platform_digit_start $plat "FGT_100E"] } {
			return "17,0,0"
		} elseif { [platform_digit_start $plat "FGT_30E"] } {
			return "9,0,0"
		} else {
			return "32,0,0"
		}
	} else {
		if { [platform_digit_start $plat "FGT_3000D"] } {
			return "31,0,0"
		} elseif { [platform_digit_start $plat "FGT_100E"] } {
			return "16,0,0"
		} elseif { [platform_digit_start $plat "FGT_30E"] } {
			return "8,0,0"
		} else {
			return "31,0,0"
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"antivirus profile content-disarm {error-action}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"firewall policy block-notification" = %{
if { $CLI_GET_TD } {
	return "disable"
}
	%}
	"firewall profile-protocol-options http {fortinet-bar fortinet-bar-port}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"ips sensor entries {cve}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"router bgp {multipath-recursive-distance}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"switch-controller global {update-user-device}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"system admin gui-dashboard name" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1708] } {
		return "45"
	}
	return "35"
}
	%}
	"system ips" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"system sdwan members priority" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1708] } {
		return "65535,0"
	}
	return "4294967295,0"
}
	%}
	"system sdwan members seq-num" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1708] } {
		return "512,0"
	}
	return "255,0"
}
	%}
	"system sdwan {duplication-max-num}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"system sdwan {duplication}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"system settings {gui-multiple-utm-profiles}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"system sso-admin gui-dashboard name" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1708] } {
		return "45"
	}
	return "35"
}
	%}
	"wireless-controller arrp-profile threshold-ap" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1708] } {
		return "500,0"
	}
	return "4294967295,0"
}
	%}
	"wireless-controller arrp-profile {threshold-channel-load threshold-rx-errors}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1708] } {
		return "100,0"
	}
	return "4294967295,0"
}
	%}
	"wireless-controller arrp-profile threshold-tx-retries" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1708] } {
		return "1000,0"
	}
	return "4294967295,0"
}
	%}
	"wireless-controller arrp-profile {weight-channel-load weight-dfs-channel weight-managed-ap}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1708] } {
		return "2000,0"
	}
	return "65535,0"
}
	%}
	"wireless-controller arrp-profile {weight-noise-floor weight-rogue-ap weight-spectral-rssi weight-weather-channel}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1708] } {
		return "2000,0"
	}
	return "65535,0"
}
	%}
	"wireless-controller mpsk-profile" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"wireless-controller setting {device-weight device-holdoff device-idle}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"wireless-controller vap {mpsk mpsk-concurrent-clients}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"wireless-controller vap {mpsk-key}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"wireless-controller vap {mpsk-profile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"wireless-controller wtp lan {port-esl-mode port-esl-ssid}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile ap-country" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1878] } {
		set opts [cli_update_opts 1 $opts "MR" "CD" "FJ" "CG" "ZM" "IQ"]
		set opts [cli_update_opts 0 $opts "KP" "SY" "ZB" "SD" "IR"]
	} else {
		set opts [cli_update_opts 0 $opts "MR" "CD" "FJ" "CG" "ZM" "IQ"]
		set opts [cli_update_opts 1 $opts "KP" "SY" "ZB" "SD" "IR"]
	}
	if { [cli_branchpt_start 600 1708] } {
		set opts [cli_update_opts 1 $opts "MW" "BF" "SN" "MV" "TC" "CI" "TM" "GY" "CX" "GH" "KN" "KY" "VU" "FM" "UG" "VC" "LC"]
	} else {
		set opts [cli_update_opts 0 $opts "MW" "BF" "SN" "MV" "TC" "CI" "TM" "GY" "CX" "GH" "KN" "KY" "VU" "FM" "UG" "VC" "LC"]
	}
	return $opts
}
	%}
	"wireless-controller wtp-profile lan {port-esl-mode port-esl-ssid}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1708] } {
		return 0
	}
}
	%}
	"firewall address {obj-tag obj-type}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1710] } {
		return 0
	}
}
	%}
	"system csf {saml-configuration-sync}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1710] } {
		return 0
	}
}
	%}
	"system ips signature-hold-time" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1710] } {
		return "0h"
	}
	return "0"
}
	%}
	"system saml default-profile" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1710] } {
		return ""
	}
	return "admin_no_access"
}
	%}
	"user nac-policy category" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1710] } {
		set opts [cli_update_opts 1 $opts "ems-tag"]
	} else {
		set opts [cli_update_opts 0 $opts "ems-tag"]
	}
	return $opts
}
	%}
	"user nac-policy {ems-tag}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1710] } {
		return 0
	}
}
	%}
	"system saml service-providers" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 600 1710] } {
		return "512,256,0"
	}
	return "256,0,0"
}
	%}
	"log memory setting {diskfull}" = %{
if { $CLI_GLOBAL_DEV } { return }
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
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1712] } {
		return 0
	}
}
	%}
	"system csf trusted-list {name authorization-type certificate}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1712] } {
		return 0
	}
}
	%}
	"system csf {accept-auth-by-cert authorization-request-type certificate}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1712] } {
		return 0
	}
}
	%}
	"wireless-controller mpsk-profile mpsk-group mpsk-key pmk" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1715] } {
		return "65"
	}
	return "60"
}
	%}
	"wireless-controller mpsk-profile mpsk-group vlan-id" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1715] } {
		return "4094,1"
	}
	return "4094,0"
}
	%}
	"application list entries {exclusion}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1768] } {
		return 0
	}
}
	%}
	"ips global {intelligent-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1768] } {
		return 0
	}
}
	%}
	"system global {user-device-store-max-devices user-device-store-max-users}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1768] } {
		return 0
	}
}
	%}
	"system interface {switch-controller-source-ip}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1768] } {
		return 0
	}
}
	%}
	"system link-monitor port" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1768] } {
		return "0"
	}
	return "80"
}
	%}
	"system lte-modem {sim-auto-switch connection-auto-switch}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1768] } {
		return 0
	}
}
	%}
	"system lte-modem {sim-hot-swap connection-hot-swap}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1768] } {
		return 0
	}
}
	%}
	"system npu ipsec-mtu-override" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1768] } {
		return "disable"
	}
	return "enable"
}
	%}
	"system sdwan service {tie-break}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1768] } {
		return 0
	}
}
	%}
	"system sdwan zone {service-sla-tie-break}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1768] } {
		return 0
	}
}
	%}
	"vpn ssl web portal {use-sdwan}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1768] } {
		return 0
	}
}
	%}
	"wireless-controller vap {port-macauth port-macauth-timeout port-macauth-reauth-timeout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1768] } {
		return 0
	}
}
	%}
	"router bgp neighbor {next-hop-self-rr next-hop-self-rr6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1773] } {
		return 0
	}
}
	%}
	"router bgp neighbor-group {next-hop-self-rr next-hop-self-rr6}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1773] } {
		return 0
	}
}
	%}
	"system global {fortiipam-integration}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1773] } {
		return 0
	}
}
	%}
	"system interface {switch-controller-iot-scanning}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1773] } {
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
	"webfilter profile antiphish {check-username-only}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1773] } {
		return 0
	}
}
	%}
	"webfilter profile ftgd-wf {rate-image-urls}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1773] } {
		return 0
	}
}
	%}
	"wireless-controller arrp-profile {include-dfs-channel include-weather-channel}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1773] } {
		return "disable"
	}
	return "no"
}
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1773] } {
		set opts [cli_update_opts 1 $opts "enable" "disable"]
		set opts [cli_update_opts 0 $opts "no" "yes"]
	} else {
		set opts [cli_update_opts 0 $opts "enable" "disable"]
		set opts [cli_update_opts 1 $opts "no" "yes"]
	}
	return $opts
}
	%}
	"wireless-controller wtp {radio-1 radio-2 radio-3 radio-4} {auto-power-target}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1773] } {
		return 0
	}
}
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3 radio-4} {auto-power-target}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1773] } {
		return 0
	}
}
	%}
	"system ddns ddns-server-addr" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1823] } {
		return 0
	}
}
	%}
	"system ddns {addr-type server-type}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1823] } {
		return 0
	}
}
	%}
	"system ddns ddns-server-ip" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1823] } {
		return 0
	}
}
	%}
	"switch-controller managed-switch poe-pre-standard-detection" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1823] } {
		return "disable"
	}
	return "enable"
}
	%}
	"switch-controller managed-switch ports poe-pre-standard-detection" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1823] } {
		return "disable"
	}
	return "enable"
}
	%}
	"user nac-policy mac" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1823] } {
		return ""
	}
	return "00:00:00:00:00:00"
}
	%}
	"system ipip-tunnel" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 600 1823] } {
		return "1024,1024,0"
	}
	return "512,256,0"
}
	%}
	"system dhcp server reserved-address" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	namespace import global::platform_digit_start
	set plat [cli_get_devinfo "platform"]
	if { [cli_branchpt_start 600 1823] } {
		if { [platform_digit_start $plat "FGT_100E"] } {
			return "0,1024,0"
		} elseif { [platform_digit_start $plat "FGT_40F"] } {
			return "0,512,0"
		}
	} else {
		return "0,1024,0"
	}
	return $CLI_CUR_VALUE
}
	%}
	"certificate local {tmp-cert-file}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1878] } {
		return 0
	}
}
	%}
	"vpn certificate local {tmp-cert-file}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1878] } {
		return 0
	}
}
	%}
	"firewall policy {dynamic-shaping capture-packet}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1878] } {
		return 0
	}
}
	%}
	"log {syslogd syslogd2 syslogd3 syslogd4} override-setting format" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1878] } {
		set opts [cli_update_opts 1 $opts "rfc5424"]
	} else {
		set opts [cli_update_opts 0 $opts "rfc5424"]
	}
	return $opts
}
	%}
	"log {syslogd syslogd2 syslogd3 syslogd4} setting format" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1878] } {
		set opts [cli_update_opts 1 $opts "rfc5424"]
	} else {
		set opts [cli_update_opts 0 $opts "rfc5424"]
	}
	return $opts
}
	%}
	"monitoring npu-hpe" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1878] } {
		return 0
	}
}
	%}
	"system accprofile fwgrp-permission {others}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1878] } {
		return 0
	}
}
	%}
	"system automation-action {accprofile}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1878] } {
		return 0
	}
}
	%}
	"system global {pmtu-discovery}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1878] } {
		return 0
	}
}
	%}
	"system interface ipv6 {ra-send-mtu}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1878] } {
		return 0
	}
}
	%}
	"system np6 hpe {arp-max esp-max icmp-max ip-frag-max ip-others-max l2-others-max sctp-max pri-type-max}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1878] } {
		return "200000"
	}
	return "1000000"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1878] } {
		return "1000000000,1000"
	}
	return "4000000000,10000"
}
	%}
	"system np6 hpe {tcp-max tcpsyn-max udp-max}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1878] } {
		return "600000"
	}
	return "5000000"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1878] } {
		return "1000000000,1000"
	}
	return "4000000000,10000"
}
	%}
	"system np6 hpe {tcpsyn-ack-max tcpfin-rst-max}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1878] } {
		return 0
	}
}
	%}
	"system npu {uesp-offload}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1878] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1 fec-redundant" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1878] } {
		return "1"
	}
	return "10"
}
	%}
	"vpn ipsec phase1 {fec-codec}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1878] } {
		return 0
	}
}
	%}
	"vpn ipsec phase1-interface fec-redundant" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1878] } {
		return "1"
	}
	return "10"
}
	%}
	"vpn ipsec phase1-interface {fec-codec}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1878] } {
		return 0
	}
}
	%}
	"router static6" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	namespace import global::platform_digit_start
	set model_rank [cli_get_devinfo "model_rank"]
	set vm_cpu_limit 0
	if { [cli_get_devinfo "VM"] eq "yes" } {
		set vm_cpu_limit [cli_get_devinfo "cpu_limit"]
	}
	if { [platform_digit_start $platform "600" ] || $model_rank eq "HIGHEND" || vm_cpu_limit >= 2 } {
		if { [cli_branchpt_start 600 1878] } {
			return "0,2000,0"
		}
		return "0,500,0"
	}
	return $CLI_CUR_VALUE
}
	%}
	"system dns-database" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	if { [cli_branchpt_start 600 1950] } {
		return "0,4096,0"
	} elseif { [cli_branchpt_start 600 1878] } {
		return "0,1024,0"
	}
	return "512,256,0"
}
	%}
	"firewall service custom" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TM } {
	set model_rank [cli_get_devinfo "model_rank"]
	if { $model_rank eq "HIGHEND" } {
		if { [cli_branchpt_start 600 1878] } {
			return "0,32768,0"
		}
		return "0,16384,0"
	}
	return $CLI_CUR_VALUE
}
	%}
	"system gre-tunnel {sequence-number-transmission sequence-number-reception checksum-transmission checksum-reception key-outbound key-inbound}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set plat [cli_get_devinfo "platform"]
	set plats "FortiGateRugged-60F FortiGateRugged-60F-3G4G FortiGate-40F FortiGate-40F-3G4G FortiGate-60F FortiGate-61F FortiGate-80F FortiGate-80F-BYPASS FortiGate-81F FortiWifi-40F-3G4G FortiWifi-60F FortiWifi-61F"
	if { [lsearch -nocase [split $plats " "] $plat] != -1 } {
		if { ![cli_branchpt_start 600 1902] } {
			return 0
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"system interface type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	set plat [cli_get_devinfo "platform"]
	set plats "FortiGate-1100E FortiGate-1101E FortiGate-300E FortiGate-301E FortiGate-400E FortiGate-401E"
	if { [cli_branchpt_start 600 1902] || [lsearch -nocase [split $plats " "] $plat] == -1 } {
		set opts [cli_update_opts 1 $opts "hard-switch"]
	} else {
		set opts [cli_update_opts 0 $opts "hard-switch"]
	}
	return $opts
}
	%}
	"system interface {stp stp-ha-slave system-id-type system-id}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set plat [cli_get_devinfo "platform"]
	set plats "FortiGate-1100E FortiGate-1101E FortiGate-300E FortiGate-301E FortiGate-400E FortiGate-401E"
	if { [lsearch -nocase [split $plats " "] $plat] != -1 } {
		if { ![cli_branchpt_start 600 1902] } {
			return 0
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"system physical-switch" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set plat [cli_get_devinfo "platform"]
	set plats "FortiGate-1100E FortiGate-1101E FortiGate-300E FortiGate-301E FortiGate-400E FortiGate-401E"
	if { [lsearch -nocase [split $plats " "] $plat] != -1 } {
		return [expr [cli_branchpt_start 600 1902]]
	}
	return $CLI_CUR_VALUE
}
	%}
	"system physical-switch port {speed status}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1902] } {
		return 0
	}
}
	%}
	"system sdn-connector {gcp-project-list}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1902] } {
		return 0
	}
}
	%}
	"system sdn-connector {gcp-project}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1902] } {
		return 0
	}
	return 1
}
	%}
	"system settings {ike-policy-route}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1902] } {
		return 0
	}
}
	%}
	"system stp" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set plat [cli_get_devinfo "platform"]
	set plats "FortiGate-1100E FortiGate-1101E FortiGate-300E FortiGate-301E FortiGate-400E FortiGate-401E"
	if { [lsearch -nocase [split $plats " "] $plat] != -1 } {
		if { ![cli_branchpt_start 600 1902] } {
			return 0
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"system virtual-switch" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set plat [cli_get_devinfo "platform"]
	set plats "FortiGate-1100E FortiGate-1101E FortiGate-300E FortiGate-301E FortiGate-400E FortiGate-401E"
	if { [lsearch -nocase [split $plats " "] $plat] != -1 } {
		if { ![cli_branchpt_start 600 1902] } {
			return 0
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"system virtual-switch port {speed status}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	set plat [cli_get_devinfo "platform"]
	set plats "FortiCarrier-3800D FortigateRugged-60F FortigateRugged-60F-3G4G FortiGate-100E FortiGate-100EF FortiGate-100F FortiGate-101E FortiGate-101F FortiGate-140E FortiGate-140E-POE FortiGate-3800D FortiGate-40F FortiGate-40F-3G4G FortiGate-60E FortiGate-60E-DSL FortiGate-60E-DSLJ FortiGate-60E-POE FortiGate-60F FortiGate-61E FortiGate-61F FortiGate-80E FortiGate-80E-POE FortiGate-80F FortiGate-80F-BYPASS FortiGate-81E FortiGate-81E-POE FortiGate-81F FortiGate-90E FortiGate-91E FortiWiFi-40F FortiWiFi-40F-3G4G FortiWiFi-60E FortiWiFi-60E-DSL FortiWiFi-60E-DSLJ FortiWiFi-60F FortiWiFi-61E FortiWiFi-61F"
	if { [lsearch -nocase [split $plats " "] $plat] != -1 } {
		if { [cli_branchpt_start 600 1902] } {
			return 0
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"user fsso {logon-timeout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1902] } {
		return 0
	}
}
	%}
	"user local {username-sensitivity}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1902] } {
		return 0
	}
}
	%}
	"user saml group-name" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1902] } {
		return "255"
	}
	return "35"
}
	%}
	"user saml user-name" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1902] } {
		return "255"
	}
	return "35"
}
	%}
	"webfilter search-engine safesearch" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1902] } {
		set opts [cli_update_opts 1 $opts "yt-channel" "translate" "yt-pattern" "yt-scan" "yt-video"]
	} else {
		set opts [cli_update_opts 0 $opts "yt-channel" "translate" "yt-pattern" "yt-scan" "yt-video"]
	}
	return $opts
}
	%}
	"vpn ssl web portal allow-user-access" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1903] } {
		return "web ftp smb sftp telnet ssh vnc rdp ping"
	}
	return "web ftp smb sftp telnet ssh vnc rdp ping citrix portforward"
}
if { $CLI_GET_TN } {
	if { $CLI_GLOBAL_DEV } { return }
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1903] } {
		set opts [cli_update_opts 0 $opts "portforward" "citrix"]
	} else {
		set opts [cli_update_opts 1 $opts "portforward" "citrix"]
	}
	return $opts
}
	%}
	"vpn ssl web portal bookmark-group bookmarks preconnection-id" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1903] } {
		return "0"
	}
	return "2147483648"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1903] } {
		return "4294967295,0"
	}
	return "2147483648,0"
}
	%}
	"vpn ssl web portal bookmark-group bookmarks security" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1903] } {
		return "any"
	}
	return "rdp"
}
	%}
	"vpn ssl web portal bookmark-group bookmarks {keyboard-layout send-preconnection-id restricted-admin color-depth}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1903] } {
		return 0
	}
}
	%}
	"vpn ssl web portal bookmark-group bookmarks {listening-port remote-port show-status-window server-layout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1903] } {
		return 0
	}
}
	%}
	"vpn ssl web portal {clipboard}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1903] } {
		return 0
	}
}
	%}
	"vpn ssl web user-bookmark bookmarks preconnection-id" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1903] } {
		return "0"
	}
	return "2147483648"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1903] } {
		return "4294967295,0"
	}
	return "2147483648,0"
}
	%}
	"vpn ssl web user-bookmark bookmarks security" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1903] } {
		return "any"
	}
	return "rdp"
}
	%}
	"vpn ssl web user-bookmark bookmarks {keyboard-layout send-preconnection-id restricted-admin color-depth}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1903] } {
		return 0
	}
}
	%}
	"vpn ssl web user-bookmark bookmarks {listening-port remote-port show-status-window server-layout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1903] } {
		return 0
	}
}
	%}
	"vpn ssl web user-group-bookmark bookmarks preconnection-id" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1903] } {
		return "0"
	}
	return "2147483648"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1903] } {
		return "4294967295,0"
	}
	return "2147483648,0"
}
	%}
	"vpn ssl web user-group-bookmark bookmarks security" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1903] } {
		return "any"
	}
	return "rdp"
}
	%}
	"vpn ssl web user-group-bookmark bookmarks {keyboard-layout send-preconnection-id restricted-admin color-depth}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1903] } {
		return 0
	}
}
	%}
	"vpn ssl web user-group-bookmark bookmarks {listening-port remote-port show-status-window server-layout}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1903] } {
		return 0
	}
}
	%}
	"system npu hpe {arp-max esp-max icmp-max ip-frag-max ip-others-max l2-others-max pri-type-max sctp-max}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { ![cli_branchpt_start 600 1914] } {
		return "20000"
	} else {
		return "5000"
	}
}
if { $CLI_GET_TT } {
	if { ![cli_branchpt_start 600 1914] } {
		return "40000000,1000"
	} else {
		return "32000000,1000"
	}
}
	%}
	"firewall shaper per-ip-shaper max-bandwidth" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	namespace import global::platform_digit_start
	set plat [cli_get_devinfo "platform"]
	if { ![cli_branchpt_start 600 1950] } {
		if { ![platform_digit_start $plat "FGT_3800D"] } {
			return "16776000,0"
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"firewall shaper traffic-shaper {exceed-bandwidth guaranteed-bandwidth maximum-bandwidth}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	namespace import global::platform_digit_start
	set plat [cli_get_devinfo "platform"]
	if { ![cli_branchpt_start 600 1950] } {
		if { ![platform_digit_start $plat "FGT_3800D"] } {
			return "16776000,0"
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"system {affinity-interrupt affinity-packet-redistribution}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	namespace import global::platform_digit_suffix
	set platform [cli_get_devinfo "platform"]
	set suffix [platform_digit_suffix $platform]
	if { ![cli_branchpt_start 600 1950] && [regexp -nocase {1200D|1500D} $suffix] } {
		return 0
	}
	return $CLI_CUR_VALUE
}
	%}
	"system automation-action {verify-host-cert}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1950] } {
		return 0
	}
}
	%}
	"system global {early-tcp-npu-session}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1950] } {
		return 0
	}
}
	%}
	"system ha {uninterruptible-primary-wait}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1950] } {
		return 0
	}
}
	%}
	"system interface {dhcp-relay-request-all-server}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1950] } {
		return 0
	}
}
	%}
	"system netflow {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1950] } {
		return 0
	}
}
	%}
	"system np6xlite {asicdos}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	namespace import global::platform_digit_start
	set plat [cli_get_devinfo "platform"]
	if { ![cli_branchpt_start 600 1950] } {
		if { ![platform_digit_start $plat "FGT_300D"] } {
			return 1
		}
	}
}
	%}
	"system npu {lag-out-port-select}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	namespace import global::platform_digit_start
	set plat [cli_get_devinfo "platform"]
	if { ![cli_branchpt_start 600 1950] } {
		if { ![platform_digit_start $plat "FGT_3400E"] } {
			return 0
		}
	}
	return $CLI_CUR_VALUE
}
	%}
	"system npu {rps-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	namespace import global::platform_digit_suffix
	set platform [cli_get_devinfo "platform"]
	set suffix [platform_digit_suffix $platform]
	if { ![cli_branchpt_start 600 1950] && [regexp -nocase {1200D|1500D} $suffix] } {
		return 0
	}
	return $CLI_CUR_VALUE
}
	%}
	"system sdn-connector {verify-certificate}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1950] } {
		return 0
	}
}
	%}
	"system {sflow vdom-netflow vdom-sflow} {interface-select-method interface}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1950] } {
		return 0
	}
}
	%}
	"system snmp {community user} events" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	set opts $CLI_CUR_VALUE
	if { ![cli_branchpt_start 600 1950] } {
		if { [cli_get_devinfo "VM"] ne "yes" } {
			set opts [cli_update_opts 0 $opts "pool-usage"]
		}
	}
	return $opts
}
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { ![cli_branchpt_start 600 1950] } {
		if { [cli_get_devinfo "VM"] ne "yes" } {
			set opts [cli_update_opts 0 $opts "pool-usage"]
		}
	}
	return $opts
}
	%}
	"system vdom-link type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1879] } {
		set opts [cli_update_opts 1 $opts "npupair"]
	} else {
		set opts [cli_update_opts 0 $opts "npupair"]
	}
	return $opts
}
	%}
	"system vpn ipsec {phase1-interface phase1 phase2-interface phase2} inbound-dscp-copy" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1950] } {
		return 0
	}
}
	%}
	"vpn ssl settings banned-cipher" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { ![cli_branchpt_start 600 1950] } {
		set opts [cli_update_opts 0 $opts "AESCCM" "ARIA" "CHACHA20"]
	}
	return $opts
}
	%}
	"vpn ssl settings {status ciphersuite}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1950] } {
		return 0
	}
}
	%}
	"wireless-controller apcfg-profile {ap-family}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1950] } {
		return 0
	}
}
	%}
	"log slbc global-setting direct-log-mode" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1914] } {
		return ""
	}
}
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_branchpt_start 600 1914] } {
		set opts [cli_update_opts 0 $opts "disabled"]
	} else {
		set opts [cli_update_opts 0 $opts "faz-udp"]
	}
	return $opts
}
	%}
	"system interface {sfp-dsl sfp-dsl-autodetect sfp-dsl-adsl-fallback sfp-dsl-mac pvc-chan pvc-vlan-id pvc-vlan-tx-id pvc-vlan-rx-id pvc-vlan-tx-op pvc-vlan-rx-op pvc-crc pvc-atm-qos pvc-pcr pvc-scr}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 600 1950] } {
		return $CLI_CUR_VALUE
	}
	return 0
}
	%}
	"system np6xlite {ipsec-STS-timeout ipsec-throughput-msg-frequency}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1961] } {
		return 0
	}
}
	%}
	"system ftm-push server" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1996] } {
		return 0
	}
}
	%}
	"system replacemsg custom-message" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 1996] } {
		return 0
	}
}
	%}
	"system cluster-sync hb-lost-threshold" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 1996] } {
		return "10"
	}
	return "3"
}
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1996] } {
		return "20,1"
	}
	return "10,1"
}
	%}
	"system cluster-sync hb-interval" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 1996] } {
		return "20,1"
	}
	return "10,1"
}
	%}
	"system npu sse-ha-scan" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 600 2014] } {
		return 0
	}
}
	%}
	"system npu hw-ha-scan-interval" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 2014] } {
		return "0"
	}
	return "120"
}
	%}
	"firewall {hyperscale-policy hyperscale-policy46 hyperscale-policy6 hyperscale-policy64} tcp-timeout-pid" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 2020] } {
		return "47,5"
	}
	return "4294967295,0"
}
	%}
	"firewall {hyperscale-policy hyperscale-policy46 hyperscale-policy6 hyperscale-policy64} udp-timeout-pid" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TT } {
	if { [cli_branchpt_start 600 2020] } {
		return "63,5"
	}
	return "4294967295,0"
}
	%}
	"log npu-server server-group sw-log-flags" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { [cli_branchpt_start 600 2020] } {
		return "tcp-udp-only"
	}
	return "0"
}
	%}
%};
