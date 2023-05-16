nodecheck %{
	"firewall policy" = %{
namespace import global::fw_check_service
namespace import global::policy_ippool_visible
set srcintf [cli_get_value $CLI_CUR_NODE "" "" "srcintf"]
set dstintf [cli_get_value $CLI_CUR_NODE "" "" "dstintf"]
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
set opmode [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"]

## Mantis 433799 
if { [cli_is_match $CLI_CUR_NODE 0 "" "internet-service" 0 "enable"] } {
	set intsvc_id [cli_get_value $CLI_CUR_NODE "" "" "internet-service-id"]
	set intsvc_cus [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom"]
	if { ($intsvc_id eq "") && ($intsvc_cus eq "") } {
		cli_set_errmsg "Must set internet service or custom internet service since internet-service is enabled."
		return 0
	}
}

if { $srcintf eq "\"web-proxy\"" || $srcintf eq "web-proxy" || $dstintf eq "\"web-proxy\"" || $dstintf eq "web-proxy" } {
	set web_proxy [cli_get_node $CLI_CUR_VDOM_NODE "web-proxy explicit" "" ""]
	if { $web_proxy == 0 || [cli_get_value $web_proxy "" "" "status"] ne "enable" } {
		cli_set_errmsg "web_proxy MUST be explicitly enabled first"
		return 0
	}
}
if { $srcintf eq "\"ftp-proxy\"" || $srcintf eq "ftp-proxy" || $dstintf eq "\"ftp-proxy\"" || $dstintf eq "ftp-proxy" } {
	set ftp_proxy [cli_get_node $CLI_CUR_VDOM_NODE "ftp-proxy explicit" "" ""]
	if { $ftp_proxy == 0 || [cli_get_value $ftp_proxy "" "" "status"] ne "enable" } {
		cli_set_errmsg "ftp_proxy MUST be explicitly enabled first"
		return 0
	}
}
if {$CLI_IS_AUTOUPDATE == 0} {
	if { [cli_get_value $CLI_CUR_NODE "" "" "service"] eq ""} {
		if { [cli_is_match $CLI_CUR_NODE 0 "" "internet-service" 1 "enable"] } {
			cli_set_errmsg "service name not exist."
			return 0
		}
	}
}

set srcintf_sslvpn_policy 0
set sslvpn_web 0
set srcintfs_count 0
foreach intf $srcintf {
	incr srcintfs_count
	namespace import global::is_sslvpn_intf
	if { [is_sslvpn_intf $intf] } {
		set srcintf_sslvpn_policy 1
	}
	if { ($srcintfs_count > 1) && ($srcintf_sslvpn_policy) } {
		break
	}
}
if { $srcintf_sslvpn_policy } {
	if { $srcintfs_count > 1 } {
		cli_set_errmsg "Cannot use tunnel interface in multiple interfaces."
		return 0
	}
	if { [cli_has_feature "f_sslvpn"] } {
		set us [cli_get_value $CLI_CUR_NODE "" "" "users"]
		set gs [cli_get_value $CLI_CUR_NODE "" "" "groups"]
		namespace import global::is_sslvpn_policy_has_tunnel
		if { [is_sslvpn_policy_has_tunnel $us $gs 0] } {
			set sslvpn_web 1
		}
	}

	set vpn_ssl [cli_get_node $CLI_CUR_VDOM_NODE "vpn ssl settings" "" ""]
	set sz_authrule 0
	set sz_src_intf 0
	if { $vpn_ssl } {
		set authrules [cli_get_tbl_list $vpn_ssl "authentication-rule"]
		foreach auth $authrules {
			incr sz_authrule
			if { $sz_authrule >= 1 } {
				break;
			}
		}
		set src_intfs [cli_get_value $CLI_CUR_VDOM_NODE "vpn ssl settings" "" "source-interface"]
		foreach intf $src_intfs {
			incr sz_src_intf
			if { $sz_src_intf >= 1 } {
				break;
			}
		}
	}
	if { $sz_authrule == 0 && $sz_src_intf == 0 } {
		cli_set_errmsg "Please config vpn.ssl.settings.source-interface/authentication-rule"
		return 0
	}
}

if { $CLI_IS_AUTOUPDATE == 0 } {
	if { [cli_get_value $CLI_CUR_NODE "" "" "srcaddr"] eq "" } {
		if { !$sslvpn_web } {
			cli_set_errmsg "Must set source address name."
			return 0
		}
	}
	if { [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"] eq "" } {
		if { [cli_is_match $CLI_CUR_NODE 0 "" "internet-service" 1 "enable"] } {
			cli_set_errmsg "dstaddr address not exist. "
			return 0
		}
	}
}

set g [cli_get_value $CLI_CUR_NODE "" "" "replacemsg-override-group"]
if {$g ne ""} {
	set msgnode [cli_get_node $CLI_CUR_VDOM_NODE "system replacemsg-group" $g ""]
	if {$msgnode eq 0} {
		cli_set_errmsg "replacemsg-group $g not exist"
		return 0
	}
	set auth_type [cli_get_value $msgnode "" "" "group-type"]
	if {$auth_type ne "auth"} {
		cli_set_errmsg "replacemsg-group $g not for firewall policies."
		return 0
	}
}
if { [cli_get_value $CLI_CUR_NODE "" "" "utm-status"] eq "enable" } {
	if { [cli_get_value $CLI_CUR_NODE "" "" "profile-type"] eq "single" } {
		if { [cli_get_value $CLI_CUR_NODE "" "" "av-profile"] ne "" ||
		     [cli_get_value $CLI_CUR_NODE "" "" "webfilter-profile"] ne "" ||
		     [cli_get_value $CLI_CUR_NODE "" "" "spamfilter-profile"] ne "" ||
		     [cli_get_value $CLI_CUR_NODE "" "" "dlp-sensor"] ne "" ||
		     [cli_get_value $CLI_CUR_NODE "" "" "icap-profile"] ne "" } {
			if { [cli_get_value $CLI_CUR_NODE "" "" "profile-protocol-options"] eq "" } {
				cli_set_errmsg "Attribute 'profile-protocol-options' MUST be set."
				return 0
			}
		}
	}
}

if { [fw_check_service $CLI_CUR_NODE $CLI_CUR_VDOM_NODE] == 0 } {
	return 0
}

## Mantis 251352

set srcintf [cli_get_value $CLI_CUR_NODE "" "" "srcintf"]
set dstintf [cli_get_value $CLI_CUR_NODE "" "" "dstintf"]
set ifnodelist [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
foreach ifnode $ifnodelist {
	set vdom [cli_get_value $ifnode "" "" "vdom"]
	set vnode [cli_get_vdom_node $vdom]
	if {[cli_if_same_node $vnode $CLI_CUR_VDOM_NODE]} {
		if {[cli_get_value $ifnode "" "" "type"] eq "aggregate"} {
			set memintf [cli_get_value $ifnode "" "" "member"]
			foreach m $memintf {
				if {"\"$m\"" eq $srcintf || ([lsearch -exact $srcintf $m] >= 0)} {
					cli_set_errmsg "src interface \"$m\" can not be a member of aggregated interface"
					return 0
				}
				if {"\"$m\"" eq $dstintf || ([lsearch -exact $dstintf $m] >= 0)} {
					cli_set_errmsg "dst interface \"$m\" can not be a member of aggregated interface"
					return 0
				}
			}
		}
	}
}

## Mantis 271372
set schedule [cli_get_value $CLI_CUR_NODE "" "" "schedule"]
if { $schedule == 0 || $schedule eq "" } {
	cli_set_errmsg "Must set schedule."
	return 0
}
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name ne "" } {
	if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1 } {
		cli_set_errmsg "Duplicate policy name: $name."
		return 0
	} else {
		set n [string trim $name \"]
		if { $n ne $name } {
			if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $n] } {
				cli_set_errmsg "Duplicate policy name: $name."
				return 0
			}
		}
	}
}

return 1
	%}

    "firewall policy {srcaddr srcintf dstaddr dstintf}" = %{
set policy $CLI_CUR_PARENT_NODE
set node $CLI_CUR_NODE_NAME
namespace import global::policy_dstaddr_check
set policyid [cli_get_value $policy "" "" "policyid"]
set srcaddr [cli_get_value $policy "" "" "srcaddr" 1]
set dstaddr [cli_get_value $policy "" "" "dstaddr" 1]
set srcintf [cli_get_value $policy "" "" "srcintf" 1]
set dstintf [cli_get_value $policy "" "" "dstintf" 1]
set poltype [cli_get_value $policy "" "" "type"]
set value [cli_get_value $CLI_CUR_NODE "" "" ""]

if { $value eq "" && $node eq "srcintf" } {
	if { $poltype ne "explicit-web" && $poltype ne "explicit-ftp" } {
		cli_set_errmsg "$CLI_CUR_NODE_NAME in Policy \"$policyid\" cannot be empty."
		return 0
	}
} elseif { $value eq "" && $node ne "dstaddr" } {
	cli_set_errmsg "$CLI_CUR_NODE_NAME in Policy \"$policyid\" cannot be empty."
	return 0
} elseif { $value eq "" && $node eq "dstaddr" } {
	namespace import global::fw_dstaddr_visible
	if { [fw_dstaddr_visible $policy] } {
		cli_set_errmsg "$CLI_CUR_NODE_NAME in Policy \"$policyid\" cannot be empty."
		return 0
	}
}

if { $node eq "dstaddr" } {
	set msg [policy_dstaddr_check $policy]
	if { $msg ne 0 } {
		cli_set_errmsg $msg
		return 0
	}
}
if { $CLI_CUR_NODE_NAME eq "srcintf" || $CLI_CUR_NODE_NAME eq "dstintf" } {
    namespace import global::intf_dedicated_to_mgmt
    if { [intf_dedicated_to_mgmt] } {
        return 0
    }
}
return 1
	%}

	"firewall policy webcache-https" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value eq "disable" } {
	return 1
}

set ptype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "profile-type"]
if { $ptype eq "single" } {
	set sslprofname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ssl-ssh-profile"]
} else {
	set pgrp [cli_get_value $CLI_CUR_PARENT_NODE "" "" "profile-group"]
	if { $pgrp eq 0 } { return 0 }
	set sslprofname [cli_get_node $CLI_CUR_VDOM_NODE "firewall profile-group" $pgrp ""]
}

if { $sslprofname eq 0 || $sslprofname eq "" } {
	cli_set_errmsg "webcache-https cannot be enabled when ssl-ssh-profile is not available."
	return 0
}

set sslprof [cli_get_node $CLI_CUR_VDOM_NODE "firewall ssl-ssh-profile" $sslprofname ""]
if { $sslprof eq 0 } {
	cli_set_errmsg "webcache-https cannot be enabled when ssl-ssh-profile is not available."
	return 0
}

set httpstat [cli_get_value $sslprof "https" "" "status"]
if { $httpstat ne "deep-inspection" } {
	cli_set_errmsg "webcache-https cannot be enabled when deep-inspection for https is not enabled in ssl-ssh-profile."
	return 0
}
return 1
	%}
        "vpn ssl web portal os-check-list tolerance" = %{
set to [cli_get_value $CLI_CUR_NODE "" "" ""]
set lp [cli_get_value $CLI_CUR_PARENT_NODE "" "" "latest-patch-level"]
set to [string trim $to \"]
set lp [string trim $lp \"]
if { $to > $lp } {
        cli_set_errmsg "Error: Tolerance value could not be larger than latest OS patch level"
        return 0
}
return 1
        %}
        "vpn ssl web portal os-check-list latest-patch-level" = %{
set lp [cli_get_value $CLI_CUR_NODE "" "" ""]
set lp [string trim $lp \"]
if { $lp eq "disable" } {
        return 1
}
if { $lp < 0 || $lp > 255 } {
        cli_set_errmsg "Error: Patch level value valid range is 0 to 255"
        return 0
}
set to [cli_get_value $CLI_CUR_PARENT_NODE "" "" "tolerance"]
set to [string trim $to \"]
if { $to > $lp } {
        cli_set_errmsg "Error: Patch level value could not be smaller than tolerance value"
        return 0
}
return 1
        %}
        "vpn ssl web portal host-check-interval" = %{
set hci [cli_get_value $CLI_CUR_NODE "" "" ""]
set hci [string trim $hci \"]
if { $hci == 0 || (120 <= $hci && $hci <= 259200) } {
        return 1
}
cli_set_errmsg "The interval range is 0,120~259200 seconds(max 72 hours), 0 for disabled"
return 0
        %}
        "vpn ssl web portal widget bookmarks" = %{
if {$CLI_ACT ne "add"} {
	set sso [cli_get_value $CLI_CUR_NODE "" "" "sso"]
	if { $sso eq "static" } {
	        set nr [cli_get_tbl_cnt $CLI_CUR_NODE "form-data"]
	        if { $nr <= 0 } {
	                cli_set_errmsg "Please enter form data for SSO."
	                return 0
	        }
	}
}
return 1
        %}

	"system ntp ntpserver" = %{
set ntp [cli_get_parent $CLI_CUR_PARENT_NODE]
set value [cli_get_value $ntp "" "" "type"]
if { ![string match "*override*" [cli_get_clisrc]] && $value ne "custom" } {
	cli_set_errmsg "ntpserver only available when type is custom"
        return 0
}
return 1
        %}

        "firewall profile-protocol-options {http ftp imap pop3 smtp nntp}" = %{
namespace import global::profile_protocol_options_ports_valid
return [profile_protocol_options_ports_valid 0]
        %}
        "firewall profile-protocol-options {mapi dns}" = %{
namespace import global::profile_protocol_options_ports_valid
return [profile_protocol_options_ports_valid 1]
        %}

        "firewall ssl-ssh-profile {ssh https ftps imaps smtps pop3s}" = %{
namespace import global::deep_inspection_ports_valid
return [deep_inspection_ports_valid]
        %}

        "firewall profile-group" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" "av-profile"] ne "" ||
     [cli_get_value $CLI_CUR_NODE "" "" "webfilter-profile"] ne "" ||
     [cli_get_value $CLI_CUR_NODE "" "" "spamfilter-profile"] ne "" ||
     [cli_get_value $CLI_CUR_NODE "" "" "dlp-sensor"] ne "" ||
     [cli_get_value $CLI_CUR_NODE "" "" "icap-profile"] ne "" } {
        if { [cli_get_value $CLI_CUR_NODE "" "" "profile-protocol-options"] eq "" } {
                cli_set_errmsg "Attribute 'profile-protocol-options' MUST be set."
                return 0
        }
}
return 1
        %}

	"dlp sensor" = %{
namespace import global::DEFAULT_SNIFFER_PROFILE
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq [DEFAULT_SNIFFER_PROFILE] } {
	set flow [cli_get_value $CLI_CUR_NODE "" "" "flow-based"]
	if { $flow ne "enable" } {
		cli_set_errmsg "Flow-based should be enabled for default sniffer profile."
		return 0
	}
}
return 1
	%}
	"spamfilter profile" = %{
namespace import global::DEFAULT_SNIFFER_PROFILE
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq [DEFAULT_SNIFFER_PROFILE] } {
        set flow [cli_get_value $CLI_CUR_NODE "" "" "flow-based"]
        if { $flow ne "enable" } {
                cli_set_errmsg "Flow-based should be enabled for default sniffer profile."
                return 0
        }
}
return 1
	%}
        "system geoip-override country-id" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "" } { return 1 }
if { ![string match "*override*" [cli_get_clisrc]] } {
        cli_set_errmsg "Geoip override country-id is generated automatically and can not be set or unset manually."
        return 0
}
return 1
        %}
	"system virtual-wan-link service" = %{
set proto [cli_get_value $CLI_CUR_NODE "" "" "protocol"]
if { $proto eq 6 || $proto eq 17 || $proto eq 132 } {
	set spt [cli_get_value $CLI_CUR_NODE "" "" "start-port"]
	set ept [cli_get_value $CLI_CUR_NODE "" "" "end-port"]
	if { $spt > $ept } {
		cli_set_errmsg "Start port should not be larger than end port"
		return 0
	}
}
set mode [cli_get_value $CLI_CUR_NODE "" "" "mode"]
if { $mode eq "manual" } {
	set m [cli_get_value $CLI_CUR_NODE "" "" "member"]
	set m [string trim $m \"]
	if { $m eq 0 || $m eq "" } {
		cli_set_errmsg "Please assign a member"
		return 0
	}
}
if { $mode eq "auto" } {
	set q [cli_get_value $CLI_CUR_NODE "" "" "quality-link"]
	if { $q eq 0 || $q eq "" } {
		cli_set_errmsg "Please assign a quality-link"
		return 0
	}
}
if { $mode eq "auto" || $mode eq "priority" } {
	set h [cli_get_value $CLI_CUR_NODE "" "" "health-check"]
	set h [string trim $h \"]
	if { $h eq "" } {
		cli_set_errmsg "Please select a health-check"
		return 0
	}
}
if { $mode eq "priority" } {
	set pm [cli_get_value $CLI_CUR_NODE "" "" "priority-members"]
	if { $pm eq "" } {
		cli_set_errmsg "Please assign priority-member(s)"
		return 0
	}
}
set is [cli_get_value $CLI_CUR_NODE "" "" "internet-service"]
set isi [cli_get_value $CLI_CUR_NODE "" "" "internet-service-id"]
set isc [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom"]
set dst [cli_get_value $CLI_CUR_NODE "" "" "dst"]
if { ($is eq "enable") && ($isi eq "") && ($isc eq "") } {
	cli_set_errmsg "Please assign internet service or custom internet service since internet-service is enabled"
	return 0
}
if { ($is ne "enable") && ($dst eq "") } {
	cli_set_errmsg "Please assign a dst or internet-service"
	return 0
}

cli_schedule_post_check $CLI_CUR_PARENT_NODE $CLI_ACT

return 1
	%}
	"application internet-service-custom entry" = %{
if { ![string match "*gui*" [cli_get_clisrc]] } {
	set ns [cli_get_tbl_list $CLI_CUR_NODE "port-range"]
	if { $ns eq "" } {
		cli_set_errmsg "Please input one port range at least. In case matching all port, range is 1-65535"
		return 0
	}
}
return 1
	%}
%};
