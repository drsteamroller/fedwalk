nodecheck %{
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
	if { $pgrp eq 0 } {
		return 0
	}
	set sslprofname [cli_get_value $CLI_CUR_VDOM_NODE "firewall profile-group" $pgrp "ssl-ssh-profile"]
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
	"firewall policy {diffservcode-forward diffservcode-rev}" = %{
set servcode [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
if { $servcode ne "" } {
	if { [regexp {^[01]{6}$} $servcode] == 0 } {
		cli_set_errmsg "must be 6 bits binary, range 000000-111111"
		return 0
	}
}
return 1
	%}
	"firewall central-snat-map" = %{
set ctype [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $ctype eq "ipv4" } {
	set orig_addr [cli_get_value $CLI_CUR_NODE "" "" "orig-addr"]
	set dst_addr [cli_get_value $CLI_CUR_NODE "" "" "dst-addr"]
	if { $orig_addr eq "" || $dst_addr eq ""} {
		cli_set_errmsg "MUst set orig-addr and dst-addr if type is ipv4"
		return 0
	}
}
if { $ctype eq "ipv6" } {
	set orig_addr6 [cli_get_value $CLI_CUR_NODE "" "" "orig-addr6"]
	set dst_addr6 [cli_get_value $CLI_CUR_NODE "" "" "dst-addr6"]
	if { $orig_addr6 eq "" || $dst_addr6 eq ""} {
		cli_set_errmsg "MUst set orig-addr6 and dst-addr6 if type is ipv6"
		return 0
	}
}
return 1
	%}
	"user group" = %{
set grptype [cli_get_value $CLI_CUR_NODE "" "" "group-type"]
if { $grptype eq "sslvpn" } {
	# TP mode should not have sslvpn type
	set opmode [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"]
	if { $opmode eq "transparent" } {
		cli_set_errmsg "Transparent mode FGT can not have sslvpn type user group"
		return 0
	}
}
return 1
	%}
	"vpn ssl web portal widget" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $type eq "tunnel" } {
	set pool [cli_get_value $CLI_CUR_NODE "" "" "ip-pools"]
	set glbpool [cli_get_value $CLI_CUR_VDOM_NODE "vpn ssl settings" "" "tunnel-ip-pools"]
	if { $pool eq "" && $glbpool eq "" } {
		cli_set_errmsg "Please enter IP pools for this tunnel"
		return 0
	}
	set pool [cli_get_value $CLI_CUR_NODE "" "" "ipv6-pools"]
	set glbpool [cli_get_value $CLI_CUR_VDOM_NODE "vpn ssl settings" "" "tunnel-ipv6-pools"]
	if { $pool eq "" && $glbpool eq "" } {
		set pname [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "name"]
		set pol_list [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "firewall policy6" "action" 0 "ssl-vpn"]
		set match 0
		if { $match > 0 } {
			cli_set_errmsg "Please enter IP pools for this tunnel"
			return 0
		}
	}
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
if { $CLI_ACT ne "add" } {
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
if { [string match "*preload*" [cli_get_clisrc]] } {
	return 1
}
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
	"system settings central-nat" = %{
set pkg_cen_nat [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $pkg_cen_nat eq "enable" } {
	set policylist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall policy"]
	set fwviplist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall vip"]
	set fwvipnlist {}
	foreach fwvip $fwviplist {
		set fwvipname [cli_get_value $fwvip "" "" "name"]
		set fwvipname [string trim $fwvipname \"]
		lappend fwvipnlist $fwvipname
	}
	set fwvipgrplist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall vipgrp"]
	foreach fwvipgrp $fwvipgrplist {
		set fwvipgrpname [cli_get_value $fwvipgrp "" "" "name"]
		set fwvipgrpname [string trim $fwvipgrpname \"]
		lappend fwvipnlist $fwvipgrpname
	}
	foreach policy $policylist {
		set addrs [cli_get_value $policy "" "" "dstaddr"]
		foreach addr $addrs {
			set addr [string trim $addr \"]
			if { [lsearch -exact $fwvipnlist $addr] >= 0 } {
				cli_set_errmsg "Package central-nat cannot be enable when VIP ($addr) policy exsits."
				return 0
			}
		}
	}
}
return 1
	%}
	"webfilter profile" = %{
set wisp [cli_get_value $CLI_CUR_NODE "" "" "wisp"]
if { $wisp eq "enable" } {
	set wispsrv [cli_get_value $CLI_CUR_NODE "" "" "wisp-servers"]
	if { $wispsrv eq 0 || $wispsrv eq "" } {
		cli_set_errmsg "WISP server need to be configured."
		return 0
	}
}
return 1
	%}
	"firewall address type" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $type eq "url" } {
	namespace import global::nCfg_is_addr_used_except_explicit_policy
	if { [nCfg_is_addr_used_except_explicit_policy $CLI_CUR_PARENT_NODE] } {
		cli_set_errmsg "Can not be url address when it were used"
		return 0
	}
}
return 1
	%}
	"system geoip-override country-id" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "" } {
	return 1
}
if { ![string match "*override*" [cli_get_clisrc]] } {
	cli_set_errmsg "Geoip override country-id is generated automatically and can not be set or unset manually."
	return 0
}
return 1
	%}
	"vpn certificate remote" = %{
if { $CLI_IS_RESYNC || $CLI_ACT ne "add" } {
	return 1
}
if { [cli_get_devinfo "vdom-admin"] ne "yes" } {
	return 1
}
set range [cli_get_value $CLI_CUR_NODE "" "" "range"]
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set gnode [cli_get_node $CLI_GLOBAL_NODE "certificate remote" $name ""]
if { $range eq "vdom" && $gnode != 0 } {
	cli_set_errmsg "certificate remote with same name $name already exist in global."
	return 0;
} elseif { $range eq "global" && $gnode == 0 } {
	cli_set_errmsg "certificate remote with same name $name dose not exist in global."
	return 0;
}
return 1
	%}
	"system zone interface" = %{
set zname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set plist [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "firewall policy" "learning-mode" 0 "enable" "srcintf" 1 "any" "srcintf" 1 "virtual-wan-link"]
set exist 0
foreach p $plist {
	set intfs [cli_get_value $p "" "" "srcintf"]
	foreach intf $intfs {
		set intf [string trim $intf "\""]
		if { $intf eq $zname } {
			set exist 1
			break
		}
	}
	if { $exist == 1 } {
		break
	}
}
return 1
	%}
	"antivirus profile" = %{
set scan_mode [cli_get_value $CLI_CUR_NODE "" "" "scan-mode"]
if { $scan_mode eq "quick" || $scan_mode eq "default" } {
	set httpopt [cli_get_value $CLI_CUR_NODE "http" "" "options"]
	set ftpopt [cli_get_value $CLI_CUR_NODE "ftp" "" "options"]
	set pop3opt [cli_get_value $CLI_CUR_NODE "pop3" "" "options"]
	set smtpopt [cli_get_value $CLI_CUR_NODE "smtp" "" "options"]
	set cifsopt [cli_get_value $CLI_CUR_NODE "cifs" "" "options"]
	if { $httpopt eq "quarantine" ||
	     $httpopt eq "avquery" ||
	     $ftpopt eq "quarantine" ||
	     $ftpopt eq "avquery" ||
	     $pop3opt eq "quarantine" ||
	     $pop3opt eq "avquery" ||
	     $smtpopt eq "quarantine" ||
	     $smtpopt eq "avquery" ||
	     $cifsopt eq "quarantine" ||
	     $cifsopt eq "avquery" } {
		cli_set_errmsg "WARNING: Quarantine option is not supported in $scan_mode mode!"
		return 0
	}
}
return 1
	%}
	"firewall shaping-policy" =%{
if { [cli_is_match $CLI_CUR_NODE 0 "" "internet-service" 0 "enable"] } {
    set intsvc_id [cli_get_value $CLI_CUR_NODE "" "" "internet-service-name"]
    set intsvc_cus [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom"]
    set intsvc_id_grp [cli_get_value $CLI_CUR_NODE "" "" "internet-service-group"]
    set intsvc_cus_grp [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom-group"]
    if { $intsvc_id eq "" &&
         $intsvc_cus eq "" &&
         $intsvc_id_grp eq "" &&
         $intsvc_cus_grp eq "" } {
        cli_set_errmsg "Must set internet service (group) or custom internet service (group) when internet-service is enabled."
        return 0
    }
}
if { [cli_is_match $CLI_CUR_NODE 0 "" "internet-service-src" 0 "enable"] } {
    set intsvc_id [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src-name"]
    set intsvc_cus [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src-custom"]
    set intsvc_id_grp [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src-group"]
    set intsvc_cus_grp [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src-custom-group"]
    if { $intsvc_id eq "" &&
         $intsvc_cus eq "" &&
         $intsvc_id_grp eq "" &&
         $intsvc_cus_grp eq "" } {
        cli_set_errmsg "Must set internet service source (group) or custom internet service source (group) when internet-service-src is enabled."
        return 0
    }
}
return 1
	%}
	"credential-store domain-controller {domain-name username}" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value eq "" || $value == 0 } {
	cli_set_errmsg "node_check_object fail! for $CLI_CUR_NODE_NAME is empty. Attribute '$CLI_CUR_NODE_NAME' MUST be set."
	return 0
}
return 1
	%}
	"credential-store domain-controller hostname" = %{
if { [cli_branchpt_start 600 1700] } {
	set value [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $value eq "" || $value == 0 } {
		cli_set_errmsg "node_check_object fail! for $CLI_CUR_NODE_NAME is empty. Attribute '$CLI_CUR_NODE_NAME' MUST be set."
		return 0
	}
}
return 1
	%}
	"emailfilter block-allow-list" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name ne "" } {
	if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1 } {
		cli_set_errmsg "Duplicate email list name: $name."
		return 0
	} else {
		set n [string trim $name \"]
		if { $n ne $name } {
			if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $n] } {
				cli_set_errmsg "Duplicate email list name: $name."
				return 0
			}
		}
	}
}
return 1
	%}
%};