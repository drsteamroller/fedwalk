nodeget %{
        "system global scanunit-count" = %{
if { $CLI_GLOBAL_DEV } { return }
set cpu [cli_get_devinfo "cpu"]
if { $cpu eq "0" } {
	return
}
if { $CLI_GET_TD } {
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
        "ips global socket-size" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TD } {
        set mem [cli_get_devinfo "mem"]
	if { $mem eq "0" } {
		return
	}
	if { $mem >= (65536-32) } {
		set default 4096
	} elseif { $mem >= (32768-32) } {
		set default 2048
	} elseif { $mem >= (16384-32) } {
		set default 1024
	} elseif { $mem >= (8192-32) } {
		set default 512
	} elseif { $mem >= (4096-32) } {
		set default 256
	} elseif { $mem >= (2048-32) } {
		set default 128
	} elseif { $mem >= (1024-32) } {
		set default 32
	} elseif { $mem >= (512-32) } {
		set default 4
	} elseif { $mem >= (256-32) } {
		set default 2
	} else {
		set default 1
	}
        return "$default"
}
if { $CLI_GET_TT } {
        set mem [cli_get_devinfo "mem"]
	if { $mem eq "0" } {
		return
	}
	if { $mem >= (65536-32) } {
		set limit 8192
	} elseif { $mem >= (32768-32) } {
		set limit 4096
	} elseif { $mem >= (16384-32) } {
		set limit 2048
	} elseif { $mem >= (8192-32) } {
		set limit 1024
	} elseif { $mem >= (4096-32) } {
		set limit 512
	} elseif { $mem >= (2048-32) } {
		set limit 256
	} else {
		set limit 128
	}
        return "$limit,1"
}
        %}
	"system global wad-worker-count" = %{
if { $CLI_GLOBAL_DEV } { return }
set cpu [cli_get_devinfo "cpu"]
if { $cpu eq "0" } {
	return
}
if { $CLI_GET_TD } {
        set default 1
        if { $cpu > 8 } {
                set default [expr ($cpu - 1)]
        } elseif { $cpu > 1 } {
                set default [expr ($cpu - 0)]
        }
        return "$default"
}
if { $CLI_GET_TT } {
        return "$cpu,1"
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
	"system global admin-https-redirect" = %{
if { $CLI_GET_TO } {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return 0
	}
	return 1
}
	%}
	"system central-management enc-algorithm" = %{
if { $CLI_GET_TD } {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return "low"
	}
}
	%}
        "vpn ipsec phase1-interface proposal" = %{
if { $CLI_GET_TD } {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return "des-md5 des-sha1"
	}
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
                return "3des-sha256 aes128-sha256"
        }
}
if { $CLI_GET_TN} {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return "des-md5 des-sha1 des-sha256 des-sha384 des-sha512"
	}
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return "3des-sha1 3des-sha256 3des-sha384 3des-sha512 aes128-sha1 aes128-sha256 aes128-sha384 aes128-sha512 aes192-sha1 aes192-sha256 aes192-sha384 aes192-sha512 aes256-sha1 aes256-sha256 aes256-sha384 aes256-sha512"
	}
}
	%}
        "vpn ipsec phase2-interface proposal" = %{
if { $CLI_GET_TD } {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return "des-md5 des-sha1"
	}
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
                return "3des-sha256 aes128-sha256"
        }
}
if { $CLI_GET_TN} {
	if {[cli_get_devinfo "LENC"] eq "yes"} {
		return "null-md5 null-sha1 null-sha256 null-sha384 null-sha512 des-null des-md5 des-sha1 des-sha256 des-sha384 des-sha512"
	}
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return "3des-sha1 3des-sha256 3des-sha384 3des-sha512 aes128-sha1 aes128-sha256 aes128-sha384 aes128-sha512 aes192-sha1 aes192-sha256 aes192-sha384 aes192-sha512 aes256-sha1 aes256-sha256 aes256-sha384 aes256-sha512 aria128-sha1 aria128-sha256 aria128-sha384 aria128-sha512 aria192-sha1 aria192-sha256 aria192-sha384 aria192-sha512 aria256-sha1 aria256-sha256 aria256-sha384 aria256-sha512 seed-sha1 seed-sha256 seed-sha384 seed-sha512"
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
	return 1
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
	"system global strong-crypto" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_RD } {
		return 1
	}
}
return $CLI_CUR_VALUE
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
	"system global admin-server-cert" = %{
if { $CLI_GET_TD } {
	if {[cli_get_devinfo "FIPS"] eq "yes"} {
		return "self-sign"
	} elseif {[cli_get_devinfo "LENC"] eq "yes"} {
		return "self-sign"
	}
	return "self-sign"
}
	%}
	"system interface allowaccess" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "http" "telnet"]
	}
}
	%}
	"system interface ipv6 ip6-allowaccess" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "http" "telnet"]
	}
}
	%}
	"system interface secondaryip allowaccess" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $opts "http" "telnet"]
	}
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
	"vpn ipsec {phase1-interface phase2-interface} dhgrp" = %{
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
	"firewall ssl-server ssl-algorithm" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TN } {
		return [cli_update_opts 0 $CLI_CUR_VALUE "medium" "low"]
	}
}
	%}
	"firewall {policy central-snat-map} status" = %{
if {[cli_get_devinfo "FIPS"] eq "yes"} {
	if { $CLI_GET_TD } {
		return "disable"
	}
}
	%}
	"firewall sniffer logtraffic" = %{
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
	"firewall policy logtraffic-start" = %{
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
	"system fortiguard {antispam-cache-ttl webfilter-cache-ttl}" =%{
if { $CLI_GET_TT } {
	return "86400,300"
}
	%}
	"user tacacs+ source-ip" =%{
if { $CLI_GET_TD } {
	return ""
}
	%}
	"system snmp community events" = %{
if { $CLI_GET_TN } {
	return [cli_update_opts 1 $CLI_CUR_VALUE "av-oversize-blocked" "faz-disconnect"]
}
if { $CLI_GET_TD } {
	set defval $CLI_CUR_VALUE
	if { [string first "av-oversize-blocked" $defval] == -1 } {
		append $defval " av-oversize-blocked"
	}
	if { [string first "faz-disconnect" $defval] == -1 } {
		append $defval " faz-disconnect"
	}
	return "$defval"
}
	%}
	"system snmp user events" = %{
if { $CLI_GET_TN } {
	return [cli_update_opts 1 $CLI_CUR_VALUE "av-oversize-blocked" "faz-disconnect"]
}
if { $CLI_GET_TD } {
	set defval $CLI_CUR_VALUE
	if { [string first "av-oversize-blocked" $defval] == -1 } {
		append $defval " av-oversize-blocked"
	}
	if { [string first "faz-disconnect" $defval] == -1 } {
		append $defval " faz-disconnect"
	}
	return "$defval"
}
	%}
	"firewall address sdn" = %{
if { $CLI_GET_TN } {
	return [cli_update_opts 1 $CLI_CUR_VALUE "azure"]
}
	%}
	"user radius {rsso-endpoint-attribute rsso-endpoint-block-attribute sso-attribute}" = %{
if { $CLI_GET_TN } {
	return [cli_update_opts 0 $CLI_CUR_VALUE "Acct-Authentic" "Acct-Delay-Time" "Acct-Input-Octets" "Acct-Input-Packets" "Acct-Link-Count" "Acct-Output-Octets" "Acct-Output-Packets" "Acct-Session-Time" "Acct-Status-Type" "Acct-Terminate-Cause" "CHAP-Challenge" "CHAP-Password" "Framed-AppleTalk-Link" "Framed-AppleTalk-Network" "Framed-Compression" "Framed-MTU" "Framed-Protocol" "Framed-Routing" "Idle-Timeout" "Login-LAT-Port" "Login-Service" "Login-TCP-Port" "NAS-Port" "NAS-Port-Type" "Port-Limit" "Service-Type" "Session-Timeout" "State" "Termination-Action" "User-Password"]
}
	%}
	"webfilter profile override profile-attribute}" = %{
if { $CLI_GET_TN } {
	return [cli_update_opts 0 $CLI_CUR_VALUE "Acct-Authentic" "Acct-Delay-Time" "Acct-Input-Octets" "Acct-Input-Packets" "Acct-Link-Count" "Acct-Output-Octets" "Acct-Output-Packets" "Acct-Session-Time" "Acct-Status-Type" "Acct-Terminate-Cause" "CHAP-Challenge" "CHAP-Password" "Framed-AppleTalk-Link" "Framed-AppleTalk-Network" "Framed-Compression" "Framed-MTU" "Framed-Protocol" "Framed-Routing" "Idle-Timeout" "Login-LAT-Port" "Login-Service" "Login-TCP-Port" "NAS-Port" "NAS-Port-Type" "Port-Limit" "Service-Type" "Session-Timeout" "State" "Termination-Action" "User-Password"]
}
	%}
	"system sdn-connector type"  = %{
if { $CLI_GET_TN } {
	return [cli_update_opts 1 $CLI_CUR_VALUE "azure" "gcp"]
}
	%}
	"system sdn-connector azure-region"  = %{
if { $CLI_GET_TN } {
	return [cli_update_opts 1 $CLI_CUR_VALUE "germany" "local" "usgov"]
}
	%}
	"system global ips-affinity" = %{
if { $CLI_GET_TT } {
	return "79"
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
	"router access-list rule prefix" = %{
if { $CLI_GET_ND } {
	return 1
}
	%}
	"firewall service custom" = %{
if { $CLI_GET_TM } {
	if { $CLI_GLOBAL_DEV } { return }
	namespace import global::platform_digit_start
	set platform [cli_get_devinfo "platform"]
	if { [cli_has_feature "f_model_HIG"] } {
		if { [cli_get_devinfo "VM"] eq "yes" } {
			return "0,16384,0"
		}
		if { [platform_digit_start $platform "6000" ] } {
			return $CLI_CUR_VALUE
		} elseif { [platform_digit_start $platform "3000" ] } {
			return "0,16384,0"
		} else {
			return "0,10240,0"
		}
	} elseif { [cli_has_feature "f_model_MED"] } {
		return "0,2048,0"
	} elseif { [cli_has_feature "f_model_LOW"] } {
		return "0,1024,0"
	}
}
	%}
	"system global {resigned-pkey-period max-img-cache-size img-cache-mode}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	return [expr [cli_branchpt_start 200 49]]
}
	%}
	"system dns {server-select-method alt-primary alt-secondary log}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	return [expr [cli_branchpt_start 200 49]]
}
	%}
	"web-proxy global use-dynamic-pkey" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	return [expr [cli_branchpt_start 200 49]]
}
	%}
	"system vdom-dns {server-select-method alt-primary alt-secondary}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	return [expr [cli_branchpt_start 200 49]]
}
	%}
	"certificate local {type nethsm-slot}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	return [expr [cli_branchpt_start 200 49]]
}
	%}
	"authentication rule web-proxy" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	return [expr [cli_branchpt_start 200 49]]
}
	%}
	"image-analyzer profile blocked-img-cache" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	return [expr [cli_branchpt_start 200 49]]
}
	%}
	"system nethsm" = %{
if { $CLI_GLOBAL_DEV } { return }
if { $CLI_GET_TO } {
	return [expr [cli_branchpt_start 200 49]]
}
	%}
%};
