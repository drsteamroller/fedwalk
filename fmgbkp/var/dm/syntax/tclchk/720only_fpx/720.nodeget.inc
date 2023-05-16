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
	"firewall profile-protocol-options http {options post-lang}" = %{
if { $CLI_GET_UN } {
	return 1
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
	"system resource-limits proxy" = %{
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
	"log {fortianalyzer2 fortianalyzer3} setting upload-option" = %{
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
	return 1
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
	"system interface allowaccess" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	set opts $CLI_CUR_VALUE
	if { [cli_get_devinfo "FIPS"] eq "yes" } {
		set opts [cli_update_opts 0 $opts "http" "telnet"]
	}
	if {[cli_is_match $CLI_GLOBAL_NODE 0 "system global" "admin-telnet" 0 "disable"]} {
		set opts [cli_update_opts 0 $opts "telnet"]
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
	if {[cli_is_match $CLI_GLOBAL_NODE 0 "system global" "admin-telnet" 0 "disable"]} {
		set opts [cli_update_opts 0 $opts "telnet"]
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
	if {[cli_is_match $CLI_GLOBAL_NODE 0 "system global" "admin-telnet" 0 "disable"]} {
		set opts [cli_update_opts 0 $opts "telnet"]
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
	"vpn ipsec {phase1-interface phase2-interface} dhgrp" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
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
	"firewall central-snat-map status" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "disable"
	}
}
	%}
	"firewall policy status" = %{
if { [cli_get_devinfo "FIPS"] eq "yes" } {
	if { $CLI_GET_TD } {
		return "disable"
	}
}
	%}
	"firewall sniffer logtraffic" = %{
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
}
	%}
	"firewall policy logtraffic-start" = %{
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
	"system resource-limits log-disk-quota" = %{
if { $CLI_GET_TD } {
	set quota [cli_get_devinfo "logdisk_size"]
	if { $quota > 0 } {
		return "$quota"
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
		return 1
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
	"firewall policy {wanopt webcache-https wanopt-profile wanopt-peer wanopt-passive-opt webcache}" = %{
if { $CLI_GET_TO } {
	if { $CLI_GLOBAL_DEV } { return }
	set serial [cli_get_devinfo "sn"]
	if { [string first "FPXWUL" $serial] == 0 } {
		return 0
	}
	if { [cli_has_feature "f_wanopt"] } {
		return 1
	}
	return 0
}
	%}
	"firewall policy {wanopt-detection reverse-cache}" = %{
if { $CLI_GET_TO } {
	if { $CLI_GLOBAL_DEV } { return }
	if { [cli_has_feature "f_wanopt"] } {
		return 1
	}
	return 0
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
	"firewall shaping-policy application" = %{
if { $CLI_GET_TM } {
	set g 0
	set v 0
	set t 0
	return [format "%lu,%lu,%lu" $g $v $t]
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
			if { [string match -nocase $platform "FortiProxy-AWS"] } {
				return "enable"
			}
		} elseif { $type eq "gcp" } {
			set platform [cli_get_devinfo "platform"]
			if { [string match -nocase $platform "FortiProxy-GCP"] } {
				return "enable"
			}
		} elseif { $type eq "azure" } {
			set platform [cli_get_devinfo "platform"]
			if { [string match -nocase $platform "FortiProxy-Azure"] } {
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
	"system global {send-pmtu-icmp honor-df ipv6-allow-anycast-probe}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 328] } {
		return 0
	}
}
	%}
	"system global update-tls-finger-print" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 328] } {
		return 0
	}
}
	%}
	"system vdom-link" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 328] } {
		return 0
	}
}
	%}
	"system interface type" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { ![cli_branchpt_start 700 328] } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "vdom-link"]
	}
}
	%}
	"system ha vdom" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_ND } {
	if { ![cli_branchpt_start 700 328] } {
		return 1
	}
	return $CLI_CUR_VALUE
}
	%}
	"firewall addrgrp category" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TN } {
	if { [cli_branchpt_start 700 328] } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "ztna-geo-tag"]
	}
}
	%}
	"web-proxy global log-policy-pending" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 328] } {
		return 0
	}
}
	%}
	"web-proxy explicit-proxy learn-dst-from-sni" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 328] } {
		return 0
	}
}
	%}
	"ftp-proxy explicit server-data-mode" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { ![cli_branchpt_start 700 328] } {
		return 0
	}
}
	%}
	"report setting {pdf-report fortiview}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { ![cli_branchpt_start 700 328] } {
		return "enable"
	}
}
	%}
	"firewall ssl-ssh-profile ssl-exempt fortiguard-category" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
	if { ![cli_branchpt_start 700 328] } {
		return "0"
	}
}
	%}
	"firewall policy {ztna-status ztna-geo-tag}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	if { [cli_branchpt_start 700 328] } {
		return 0
	}
}
	%}
%};
