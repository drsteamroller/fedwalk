nodecheck %{
	"system settings vdom-type" = %{
set vdom_type [cli_get_value $CLI_CUR_NODE "" "" ""]
set opmode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "opmode"]
if { $vdom_type eq "admin" && $opmode eq "transparent" } {
	cli_set_errmsg "Can not change vdom-type to admin in transparent mode."
	return 0
}
if { $vdom_type eq "admin" } {
	set vdom_proplist [cli_get_tbl_list $CLI_GLOBAL_NODE "system vdom-property"]
	foreach vdprop $vdom_proplist {
		set vdname [cli_get_value $vdprop "" "" "name"]
		if { $vdname ne $CLI_CUR_VDOM_NAME } {
			set vdnode [cli_get_vdom_node $vdname]
			set vdtype [cli_get_value $vdnode "system settings" "" "vdom-type"]
			if { $vdtype eq "admin" } {
				cli_set_errmsg "VDOM \"$vdname\" is admin vdom-type already."
				return 0
			}
		}
	}
}
	%}
	"firewall consolidated policy" = %{
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
	set name [string trim $name \"]
	if { [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall policy" "name" 0 $name] ||
	     [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall policy" "name" 0 "\"$name\""] } {
		cli_set_errmsg "$name is already used by firewall.policy"
		return 0
	}
	if { [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall policy6" "name" 0 $name] ||
	     [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall policy6" "name" 0 "\"$name\""] } {
		cli_set_errmsg "$name is already used by firewall.policy6"
		return 0
	}
}
set srcintf [cli_get_value $CLI_CUR_NODE "" "" "srcintf"]
set dstintf [cli_get_value $CLI_CUR_NODE "" "" "dstintf"]
if { $srcintf eq "" } {
	cli_set_errmsg "srcintf not exist. "
	return 0
}
foreach sintf $srcintf {
	set sintf [string trim $sintf \"]
	set fzone_type 0
	if { $sintf eq "any" } {
		if { $fzone_type == 2 } {
			cli_set_errmsg "Cannot use multiple srcintf types."
			return 0
		}
		set fzone_type 1
	} else {
		if { $fzone_type == 1 } {
			cli_set_errmsg "Cannot use multiple srcintf types."
			return 0
		}
		set fzone_type 2
	}
}
if { $dstintf eq "" } {
	cli_set_errmsg "dstintf not exist. "
	return 0
}
return 1
	%}
	"firewall consolidated policy {diffservcode-forward diffservcode-rev}" = %{
set servcode [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
if { $servcode ne "" } {
	if { [regexp {^[01]{6}$} $servcode] == 0 } {
		cli_set_errmsg "must be 6 bits binary, range 000000-111111"
		return 0
	}
}
return 1
	%}
	"firewall policy" = %{
namespace import global::fw_check_service
namespace import global::policy_ippool_visible
namespace import global::policy_addr_intf_check
set srcintf [cli_get_value $CLI_CUR_NODE "" "" "srcintf" 1]
set dstintf [cli_get_value $CLI_CUR_NODE "" "" "dstintf" 1]
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
set opmode [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"]
if { [policy_addr_intf_check $CLI_CUR_NODE] eq 0 } {
	return 0
}
# Mantis 622129
set skip_dst 0
set skip_src 0
namespace import global::set_rep_dst
namespace import global::set_rep_src
if { [set_rep_dst $CLI_CUR_NODE] } {
	set skip_dst 1
} elseif { [set_rep_src $CLI_CUR_NODE] } {
	set skip_src 1
}
set rp_min [cli_get_value $CLI_CUR_NODE "" "" "reputation-minimum"]
set int_srv [cli_get_value $CLI_CUR_NODE "" "" "internet-service"]
set int_srv6 [cli_get_value $CLI_CUR_NODE "" "" "internet-service6"]
set int_srv_s [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src"]
set int_srv6_s [cli_get_value $CLI_CUR_NODE "" "" "internet-service6-src"]
set policyid [cli_get_value $CLI_CUR_NODE "" "" "policyid"]
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
set srcaddr [cli_get_value $CLI_CUR_NODE "" "" "srcaddr"]
set dstaddr6 [cli_get_value $CLI_CUR_NODE "" "" "dstaddr6"]
set srcaddr6 [cli_get_value $CLI_CUR_NODE "" "" "srcaddr6"]
# check reputation minimum
set rp_min [string trim $rp_min \"]
if { $rp_min ne "" } {
	if { $rp_min < 0 || $rp_min > 5} {
		cli_set_errmsg "'reputation-minimum' should be '1-5'"
		return 0
	}
}
# check dstaddr6 and srcaddr6
## Mantis 831796
set dstaddr6_negate [cli_get_value $CLI_CUR_NODE "" "" "dstaddr6-negate"]
set srcaddr6_negate [cli_get_value $CLI_CUR_NODE "" "" "srcaddr6-negate"]
if { (($int_srv ne "enable" && $int_srv_s ne "enable") && ($int_srv6 ne "enable" && $int_srv6_s ne "enable")) && ($rp_min == 0 || $rp_min eq "") } {
	if { $srcaddr6 == 0 || $srcaddr6 eq "" } {
		if { ($dstaddr == 0 || $dstaddr eq "") && ($srcaddr == 0 || $srcaddr eq "") } {
			cli_set_errmsg "srcadrr6 in Policy \"$policyid\" cannot be empty if dstaddr and srcaddr are not set"
			return 0
		}
		if { $dstaddr6 != 0 && $dstaddr6 ne "" } {
			cli_set_errmsg "srcaddr6 in Policy \"$policyid\" cannot be empty if dstaddr6 is set"
			return 0
		}
		if { [cli_branchpt_start 700 1228] } {
			if { $srcaddr6_negate eq "enable" } {
				cli_set_errmsg "srcaddr6 in Policy \"$policyid\" must be specified when srcaddr6-negate is enabled."
				return 0
			}
		}
	}
	if { $dstaddr6 == 0 || $dstaddr6 eq "" } {
		if { ($dstaddr == 0 || $dstaddr eq "") && ($srcaddr == 0 || $srcaddr eq "") } {
			cli_set_errmsg "dstadrr6 in Policy \"$policyid\" cannot be empty if dstaddr and srcaddr are not set"
			return 0
		}
		if { $srcaddr6 != 0 && $srcaddr6 ne "" } {
			cli_set_errmsg "dstaddr6 in Policy \"$policyid\" cannot be empty if srcaddr6 is set"
			return 0
		}
		if { [cli_branchpt_start 700 1228] } {
			if { $dstaddr6_negate eq "enable" } {
				cli_set_errmsg "dstaddr6 in Policy \"$policyid\" must be specified when dstaddr6-negate is enabled."
				return 0
			}
		}
	}
}
# check dstaddr and srcaddr
## Mantis 831796
set dstaddr_negate [cli_get_value $CLI_CUR_NODE "" "" "dstaddr-negate"]
set srcaddr_negate [cli_get_value $CLI_CUR_NODE "" "" "srcaddr-negate"]
if { !$skip_src && $int_srv_s ne "enable" && ($srcaddr == 0 || $srcaddr eq "") } {
	if { $int_srv ne "enable" && !$skip_dst} {
		if { ($dstaddr6 == 0 || $dstaddr6 eq "") && ($srcaddr6 == 0 && $srcaddr6 eq "") } {
			cli_set_errmsg "srcaddr in Policy \"$policyid\" cannot be empty if dstaddr6 and srcaddr6 are not set"
			return 0
		}
		if { $dstaddr != 0 && $dstaddr ne "" } {
			cli_set_errmsg "srcaddr in Policy \"$policyid\" cannot be empty if dstaddr is set"
			return 0
		}
		if { [cli_branchpt_start 700 1228] } {
			if { $srcaddr_negate eq "enable" } {
				cli_set_errmsg "srcaddr in Policy \"$policyid\" must be specified when srcaddr-negate is enabled."
				return 0
			}
		}
	} else {
		cli_set_errmsg "srcaddr in Policy \"$policyid\" cannot be empty"
		return 0
	}
}
if { !$skip_dst && $int_srv ne "enable" && ($dstaddr == 0 || $dstaddr eq "") } {
	if { $int_srv_s ne "enable" && !$skip_src} {
		if { ($dstaddr6 == 0 || $dstaddr6 eq "") && ($srcaddr6 == 0 && $srcaddr6 eq "") } {
			cli_set_errmsg "dstaddr in Policy \"$policyid\" cannot be empty if dstaddr6 and srcaddr6 are not set"
			return 0
		}
		if { $srcaddr != 0 && $srcaddr ne "" } {
			cli_set_errmsg "dstaddr in Policy \"$policyid\" cannot be empty if srcaddr is set"
			return 0
		}
		if { [cli_branchpt_start 700 1228] } {
			if { $dstaddr_negate eq "enable" } {
				cli_set_errmsg "dstaddr in Policy \"$policyid\" must be specified when dstaddr-negate is enabled."
				return 0
			}
		}
	} else {
		cli_set_errmsg "dstaddr in Policy \"$policyid\" cannot be empty"
		return 0
	}
}
## Mantis 298448
namespace import global::nCfg_policy_check_intf
set port_list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "system virtual-wire-pair"]
set nat [cli_get_value $CLI_CUR_NODE "" "" "nat"]
foreach port_node $port_list {
	set mem_list [cli_get_value $port_node "" "" "member"]
	if { [llength $mem_list] == 2 } {
		set m1 [lindex $mem_list 0]
		set m2 [lindex $mem_list 1]
		set m1_src [nCfg_policy_check_intf $CLI_CUR_NODE $m1 1]
		set m1_dst [nCfg_policy_check_intf $CLI_CUR_NODE $m1 0]
		set m2_src [nCfg_policy_check_intf $CLI_CUR_NODE $m2 1]
		set m2_dst [nCfg_policy_check_intf $CLI_CUR_NODE $m2 0]
		if { ($m1_src && !$m2_dst) ||
		     (!$m1_src && $m2_dst) ||
		     ($m1_dst && !$m2_src) ||
		     (!$m1_dst && $m2_src) } {
			cli_set_errmsg "srcintf and dstintf are not in the same port pair."
			return 0
		}
		if { ($m1_src && $m2_dst) || ($m1_dst && $m2_src) } {
##			if { [llength $srcintf] > 2 || [llength $dstintf] > 2 } {
##				cli_set_errmsg "Maximum interface number of port pair policy is two."
##				return 0
##			}
##			if { [llength $srcintf] == 2 || [llength $dstintf] == 2 } {
##				if { (!$m1_src && !$m2_dst) || (!$m1_dst && !$m2_src) } {
##					cli_set_errmsg "Invalid srcintf or dstintf for port pair policy."
##					return 0
##				}
##			}
		}
	}
}
namespace import global::nCfg_is_address_vip46
namespace import global::nCfg_is_address6_vip64
## Mantis 307632
if { [policy_ippool_visible $CLI_CUR_NODE] } {
	set ippool [cli_get_value $CLI_CUR_NODE "" "" "ippool"]
	if { $ippool eq "enable" } {
		set sys_settings [cli_get_node $CLI_CUR_VDOM_NODE "system settings" "" ""]
		set central_nat [cli_get_value $sys_settings "" "" "central-nat"]
		if { $central_nat ne "enable" } {
			set nat46 [cli_get_value $CLI_CUR_NODE "" "" "nat46"]
			set nat64 [cli_get_value $CLI_CUR_NODE "" "" "nat64"]
			if { $nat46 eq "enable" || $nat64 eq "enable" } {
				if { ($srcaddr == 0 || $srcaddr eq "") || ($dstaddr == 0 || $dstaddr eq "") || ($srcaddr6 == 0 || $srcaddr6 eq "") || ($dstaddr6 == 0 || $dstaddr6 eq "") } {
					cli_set_errmsg "Policy IPv4 and IPv6 addresses must be specified when NAT46/NAT64 is enable."
					return 0
				}
				if { $nat64 eq "enable" } {
					foreach addr6 $dstaddr6 {
						if { ![nCfg_is_address6_vip64 $addr6] } {
							cli_set_errmsg "Policy dstaddr6 must be vip6 when NAT64 is enabled."
							return 0
						}
					}
					foreach addr $dstaddr {
						if { [nCfg_is_address_vip46 $addr] } {
							cli_set_errmsg "Policy dstaddr must not be vip when NAT64 is enabled."
							return 0
						}
					}
				}
			}
			set poolname [cli_get_value $CLI_CUR_NODE "" "" "poolname"]
			set poolname6 [cli_get_value $CLI_CUR_NODE "" "" "poolname6"]
			if { ($poolname == 0 || $poolname eq "") && ($poolname6 == 0 || $poolname6 eq "") } {
				cli_set_errmsg "Policy ippool (ippool6) name cannot be empty."
				return 0
			}
			if { $poolname != 0 && $poolname != "" && $int_srv ne "enable" && ($dstaddr == 0 || $dstaddr eq "") } {
				cli_set_errmsg "poolname in Policy \"$policyid\" cannot be set if dstaddr is empty"
				return 0
			}
			if { $poolname6 != 0 && $poolname6 != "" && $int_srv ne "enable" && ($dstaddr6 == 0 || $dstaddr6 eq "") } {
				cli_set_errmsg "poolname6 in Policy \"$policyid\" cannot be set if dstaddr6 is empty"
				return 0
			}
			if { $nat eq "enable" && $nat46 eq "disable" && $nat64 eq "disable" } {
				set ippool_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall ippool" $poolname ""]
				if { $ippool_node ne 0 && $ippool_node ne "" } {
					set ippool_nat64 [cli_get_value $ippool_node "" "" "nat64"]
					if { $ippool_nat64 eq "enable" } {
						cli_set_errmsg "nat64 cannot be enable for poolname when nat is enable (policy \"$policyid\")"
						return 0
					}
				}
			}
		}
	}
}

## Mantis 232854
if { $srcintf eq "" } {
	cli_set_errmsg "srcintf not exist. "
	return 0
}
if { $dstintf eq "" } {
	cli_set_errmsg "dstintf not exist. "
	return 0
}
## Mantis 433799 
if { !$skip_dst && [cli_is_match $CLI_CUR_NODE 0 "" "internet-service" 0 "enable"] } {
	set intsvc_id [cli_get_value $CLI_CUR_NODE "" "" "internet-service-name"]
	set intsvc_cus [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom"]
	set intsvc_id_grp [cli_get_value $CLI_CUR_NODE "" "" "internet-service-group"]
	set intsvc_cus_grp [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom-group"]
	if { $intsvc_id eq "" &&
	     $intsvc_cus eq "" &&
	     $intsvc_id_grp eq "" &&
	     $intsvc_cus_grp eq "" } {
		cli_set_errmsg "Must set internet service (group) or custom internet service (group) since internet-service is enabled."
		return 0
	}
}
set chk_src_snif 0
set chk_dst_snif 0
if { [cli_get_value $CLI_GLOBAL_NODE "system interface" $srcintf "ips-sniffer-mode"] eq "enable" } {
	set chk_src_snif 1
}
if { [cli_get_value $CLI_GLOBAL_NODE "system interface" $dstintf "ips-sniffer-mode"] eq "enable" } {
	set chk_dst_snif 1
}
if { $chk_src_snif == 1 || $chk_dst_snif ==1 } {
	set fw_sniff_list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall sniffer"]
	foreach fws $fw_sniff_list {
		set fws_s [cli_get_value $fws "" "" "interface"]
		if { ($chk_src_snif == 1 && $fws_s eq $srcintf) ||
		     ($chk_dst_snif == 1 && $fws_s eq $dstintf) } {
			cli_set_errmsg "sniffer interface cannot be used by firewall policy"
			return 0
		}
	}
}
if { $srcintf eq "\"web-proxy\"" ||
     $srcintf eq "web-proxy" ||
     $dstintf eq "\"web-proxy\"" ||
     $dstintf eq "web-proxy" } {
	set web_proxy [cli_get_node $CLI_CUR_VDOM_NODE "web-proxy explicit" "" ""]
	if { $web_proxy == 0 || [cli_get_value $web_proxy "" "" "status"] ne "enable" } {
		cli_set_errmsg "web_proxy MUST be explicitly enabled first"
		return 0
	}
}
if { $srcintf eq "\"ftp-proxy\"" ||
     $srcintf eq "ftp-proxy" ||
     $dstintf eq "\"ftp-proxy\"" ||
     $dstintf eq "ftp-proxy" } {
	set ftp_proxy [cli_get_node $CLI_CUR_VDOM_NODE "ftp-proxy explicit" "" ""]
	if { $ftp_proxy == 0 || [cli_get_value $ftp_proxy "" "" "status"] ne "enable" } {
		cli_set_errmsg "ftp_proxy MUST be explicitly enabled first"
		return 0
	}
}
if { $CLI_IS_AUTOUPDATE == 0 } {
	if { !$skip_dst && [cli_get_value $CLI_CUR_NODE "" "" "service"] eq "" } {
		if { [cli_is_match $CLI_CUR_NODE 0 "" "internet-service" 1 "enable"] } {
			cli_set_errmsg "service name not exist."
			return 0
		}
	}
}
if { [cli_is_match $CLI_CUR_NODE 0 "" "action" 0 "ssl-vpn"] } {
	set ret 0
	set sys_global [cli_get_node $CLI_GLOBAL_NODE "system global" "" ""]
	set sslvpn_port [cli_get_value $sys_global "" "" "sslvpn-sport"]
	set admin_sport [cli_get_value $sys_global "" "" "admin-sport"]
	if { $sslvpn_port == $admin_sport } {
		set zone [cli_get_value $CLI_CUR_VDOM_NODE "system zone" $srcintf "interface"]
		if { $zone ne "" } {
			set intf_list $zone
		} else {
			set intf_list $srcintf
		}
		foreach intf $intf_list {
			set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" "$intf" ""]
			if { [cli_is_match $intf_node 0 "" "allowaccess" 0 "https"] } {
				set ret 1
			} else {
				set secip_list [cli_get_tbl_list $intf_node "secondaryip"]
				foreach item $secip_list {
					if { [cli_is_match $item 0 "" "allowaccess" 0 "https"] } {
						set ret 1
						break
					}
				}
			}
			if { $ret == 1 } {
				break
			}
		}
		if { $ret == 1 } {
			return 0
		}
	}
}
if { [expr {[cli_get_value $CLI_CUR_NODE "" "" "srcintf"] eq ""}] ||
     [expr {[cli_get_value $CLI_CUR_NODE "" "" "dstintf"] eq ""}] } {
	cli_set_errmsg "invalid interface"
	return 0
}
if { [expr {[cli_get_value $CLI_CUR_NODE "" "" "webcache"] eq "enable"}] } {
#TODO: not fit for this check, need update.
#	namespace import global::webcache_can_not_enable
#	if { [webcache_can_not_enable $CLI_CUR_NODE] } {
#		return 0
#	}
}
proc fw_pol_get_fdid {name} {
	global CLI_CUR_VDOM_NODE
	global CLI_GLOBAL_NODE
	set zone [cli_get_value $CLI_CUR_VDOM_NODE "system zone" $name "interface"]
	if { $zone ne "" } {
		set intf_list $zone
	} else {
		set intf_list $name
	}
	set intf [lindex $intf_list 0]
	return [cli_get_value $CLI_GLOBAL_NODE "system interface" $intf "forward-domain"]
}
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] == "transparent" } {
	if { $srcintf != "\"any\"" &&
	     $srcintf != "any" &&
	     $dstintf != "\"any\"" &&
	     $dstintf != "any" } {
		set src_fdid [fw_pol_get_fdid $srcintf]
		set dst_fdid [fw_pol_get_fdid $dstintf]
		if { $src_fdid eq "" || $dst_fdid eq "" || $src_fdid != $dst_fdid } {
			cli_set_errmsg "Interfaces must have the same forward domain ID in TP mode"
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
				break
			}
		}
		set src_intfs [cli_get_value $CLI_CUR_VDOM_NODE "vpn ssl settings" "" "source-interface"]
		foreach intf $src_intfs {
			incr sz_src_intf
			if { $sz_src_intf >= 1 } {
				break
			}
		}
	}
	if { $sz_authrule == 0 && $sz_src_intf == 0 } {
		cli_set_errmsg "Please config vpn.ssl.settings.source-interface/authentication-rule"
		return 0
	}

	# Mantis 634813
	namespace import global::addr_all_exist
	if { $srcaddr != 0 && $srcaddr ne "" && [addr_all_exist $dstaddr] } {
		namespace import global::FMG_is_sslvpn_policy_has_split_tunneling
		if { [FMG_is_sslvpn_policy_has_split_tunneling $CLI_CUR_NODE 0] } {
			cli_set_errmsg "SSL VPN portal has split-tunneling enable, which does not allow policy IPv4 destination address to be an all address."
			return 0
		}
	}
	if { $srcaddr6 != 0 && $srcaddr6 ne "" && [addr_all_exist $dstaddr6] } {
		namespace import global::FMG_is_sslvpn_policy_has_split_tunneling
		if { [FMG_is_sslvpn_policy_has_split_tunneling $CLI_CUR_NODE 1] } {
			cli_set_errmsg "SSL VPN portal has split-tunneling enable, which does not allow policy IPv6 destination address to be an all address."
			return 0
		}
	}
}

if { [cli_is_match $CLI_CUR_NODE 0 "" "action" 0 "ipsec"] } {
	set tunnel [cli_get_value $CLI_CUR_NODE "" "" "vpntunnel"]
	if { $tunnel eq "" } {
		cli_set_errmsg "Must set VPN tunnel name when action is ipsec."
		return 0
	}
	if { [cli_get_value $CLI_CUR_NODE "" "" "inbound"] ne "enable" &&
	     [cli_get_value $CLI_CUR_NODE "" "" "outbound"] ne "enable" } {
		cli_set_errmsg "Please set inbound or/and outbound setting."
		return 0
	}
	set srcintf [cli_get_value $CLI_CUR_NODE "" "" "srcintf"]
	set dstintf [cli_get_value $CLI_CUR_NODE "" "" "dstintf"]
	if { $srcintf eq "\"any\"" ||
	     $dstintf eq "\"any\"" ||
	     $srcintf eq "any" ||
	     $dstintf eq "any" } {
		cli_set_errmsg "srcintf and dstintf could not be \"any\""
		return 0
	}
	set dstintfs_count 0
	foreach intf $dstintf {
		incr dstintfs_count
		if { $dstintfs_count > 1 } {
			cli_set_errmsg "Cannot use tunnel interface in multiple interfaces."
			return 0
		}
	}
	set gw [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1" $tunnel ""]
	if { $gw == 0 } {
		set gw [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec manualkey" $tunnel ""]
		if { $gw == 0 } {
			cli_set_errmsg "Must set vpn ipsec phase1/manualkey gateway."
			return 0
		}
	}
	set dstintf [string trim $dstintf \"]
	set gwintf [cli_get_value $gw "" "" "interface"]
	set gwintf [string trim $gwintf \"]
	if { $gwintf ne "" && $dstintf ne "virtual-wan-link" } {
		set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $dstintf ""]
		if { $intf_node == 0 } {
			set zone_node [cli_get_node $CLI_CUR_VDOM_NODE "system zone" $dstintf ""]
			if { $zone_node == 0 } {
				cli_set_errmsg "invalid interface"
				return 0
			}
			set zone_intf [cli_get_value $zone_node "" "" "interface"]
			set match 0
			foreach zintf $zone_intf {
				set zintf [string trim $zintf \"]
				if { $zintf == $gwintf } {
					set match 1
					break
				}
			}
			if { $match == 0 } {
				cli_set_errmsg "interface binding contradiction"
				return 0
			}
		} else {
			if { $dstintf ne $gwintf } {
				cli_set_errmsg "interface binding contradiction"
				return 0
			}
		}
	}
}
if { [cli_is_match $CLI_CUR_NODE 0 "" "action" 0 "accept"] } {
	if { [cli_is_match $CLI_CUR_NODE 0 "" "inspection-mode" 0 "flow"] } {
		foreach addr $dstaddr {
			set addr_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $addr ""]
			set vip_type [cli_get_value $addr_node "" "" "type"]
			if { $addr_node && $vip_type eq "server-load-balance" } {
				set s_type [cli_get_value $addr_node "" "" "server-type"]
				if { $s_type ne "ip" && $s_type ne "tcp" && $s_type ne "ssh" && $s_type ne "udp" } {
					cli_set_errmsg "Virtual Server address (not L4 based load-balancing) is not allowed when inspection-mode is flow."
					return 0
				}
			}
		}
	}
}
if { ![cli_branchpt_start 700 234] } {
if { [cli_is_match $CLI_CUR_NODE 0 "" "action" 0 "deny"] } {
	foreach addr $dstaddr {
		set addr_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $addr ""]
		if { $addr_node } {
			set vip_type [cli_get_value $addr_node "" "" "type"]
			if { $vip_type eq "server-load-balance" } {
				cli_set_errmsg "Virtual Server address is not allowed when action is deny."
				return 0
			}
		}
	}
}
}
if { [cli_branchpt_start 700 234] } {
	set inspection_mode [cli_get_value $CLI_CUR_NODE "" "" "inspection-mode"]
	if { $inspection_mode eq "proxy" } {
		set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
		set vipnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $dstaddr ""]
		if { $vipnode ne 0 } {
			set type [cli_get_value $vipnode "" "" "type"]
			if { $type eq "access-proxy" } {
				cli_set_errmsg "vip address type cannot be access-proxy."
				return 0
			}
		}
	}
}
set g [string trim [cli_get_value $CLI_CUR_NODE "" "" "replacemsg-override-group"] \"]
if { $g ne "" } {
	if { [string match "g-*" $g] } {
		set msgnode [cli_get_node $CLI_GLOBAL_NODE "system replacemsg-group" $g ""]
	} else {
		set msgnode [cli_get_node $CLI_CUR_VDOM_NODE "system replacemsg-group" $g ""]
	}
	if { $msgnode eq 0 } {
		cli_set_errmsg "replacemsg-group $g not exist"
		return 0
	}
	set auth_type [cli_get_value $msgnode "" "" "group-type"]
	if { $auth_type ne "auth" } {
		cli_set_errmsg "replacemsg-group $g not for firewall policies."
		return 0
	}
}
set dynp [cli_get_value $CLI_CUR_NODE "" "" "dynamic-profile"]
if { $dynp eq "enable" } {
	if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "dynamic-profile" 0 "enable"] > 1 } {
		cli_set_errmsg "Can not duplicate enable Dynamic profile in different policies"
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

if { [cli_is_match $CLI_CUR_NODE 0 "" "action" 0 "accept"] } {
	if { [cli_is_match $CLI_CUR_NODE 0 "" "inspection-mode" 0 "proxy"] } {
		if { [cli_is_match $CLI_CUR_NODE 0 "" "videofilter-profile" 1 ""] } {
			# Mantis 0743649
			# FGT only checks if the status of the https profile is deep-inspection
			set ssl_ssh_profile_name [cli_get_value $CLI_CUR_NODE "" "" "ssl-ssh-profile"]
			set ssl_ssh_profile [cli_get_node $CLI_CUR_VDOM_NODE "firewall ssl-ssh-profile" $ssl_ssh_profile_name ""]
			set ssl_ssh_profile_https [cli_get_node $ssl_ssh_profile "https" "" ""]
			set status [cli_get_value $ssl_ssh_profile_https "" "" "status"]
			if { $status ne "deep-inspection" } {  
				# msg copied from FortiOS/fortinet/cmf/plugin/firewall/policy.c:firewall_policy_check (search 'video_filter_profile')
				cli_set_errmsg "\"deep-inspection\" must be enabled in https when there is a firewall policy with \"videofilter-profile\" enabled uses this profile. name:$ssl_ssh_profile_name node:$ssl_ssh_profile nodes:$ssl_ssh_profile_https status:$status "
				return 0
			}
		}
	}
}

set logtraffic [cli_get_value $CLI_CUR_NODE "" "" "logtraffic"]
set reputation [cli_get_value $CLI_CUR_VDOM_NODE "client-reputation profile" "" "status"]
if { ($reputation eq "enable" ) && ($logtraffic ne "all" ) } {
	cli_set_errmsg "logtraffic MUST be set to \"all\" when client reputation is enabled"
	return 0
}
if { ([cli_is_match $CLI_CUR_NODE 0 "" "logtraffic" 0 "all" ] ||
     [cli_is_match $CLI_CUR_NODE 0 "" "logtraffic" 0 "utm"] ) &&
     [cli_is_match $CLI_CUR_NODE 0 "" "action" 1 "deny"] } {
	if { [cli_get_value $CLI_CUR_NODE "" "" "capture-packet"] eq "enable" } {
		set hdd [cli_get_devinfo "hdd"]
		set g [cli_get_devinfo "is_logdisk_mounted"]
		if { $hdd eq "no" || $g eq "no" } {
			cli_set_errmsg "capture-packet cannot be enabled without storage disk."
			return 0
		}
	}
}
if { !$skip_dst && [fw_check_service $CLI_CUR_NODE $CLI_CUR_VDOM_NODE] == 0 } {
	return 0
}
## Mantis 251352
set srcintf [cli_get_value $CLI_CUR_NODE "" "" "srcintf"]
set dstintf [cli_get_value $CLI_CUR_NODE "" "" "dstintf"]
set ifnodelist [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
foreach ifnode $ifnodelist {
	set vdom [cli_get_value $ifnode "" "" "vdom"]
	set vnode [cli_get_vdom_node $vdom]
	if { [cli_if_same_node $vnode $CLI_CUR_VDOM_NODE] } {
		if { [cli_get_value $ifnode "" "" "type"] eq "aggregate" } {
			set memintf [cli_get_value $ifnode "" "" "member"]
			foreach m $memintf {
				if { "\"$m\"" eq $srcintf || ([lsearch -exact $srcintf $m] >= 0) } {
					cli_set_errmsg "src interface \"$m\" can not be a member of aggregated interface"
					return 0
				}
				if { "\"$m\"" eq $dstintf || ([lsearch -exact $dstintf $m] >= 0) } {
					cli_set_errmsg "dst interface \"$m\" can not be a member of aggregated interface"
					return 0
				}
			}
		}
	}
}
## Mantis 271372
namespace import global::ngfw_mode_policy
namespace import global::is_hyperscale_activated
if { ![ngfw_mode_policy] && !([cli_branchpt_start 700 1226] && [is_hyperscale_activated]) } {
	set schedule [cli_get_value $CLI_CUR_NODE "" "" "schedule"]
	if { $schedule == 0 || $schedule eq "" } {
		cli_set_errmsg "Must set schedule."
		return 0
	}
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
	set name [string trim $name \"]
	if { [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall policy6" "name" 0 $name] ||
	     [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall policy6" "name" 0 "\"$name\""] } {
		cli_set_errmsg "$name is already used by firewall.policy6"
		return 0
	}
}
namespace import global::cmf_firewall_policy_learn_enabled
namespace import global::cmf_firewall_validate_learning_src_dst
if { [cmf_firewall_policy_learn_enabled $CLI_CUR_NODE] &&
     ![cmf_firewall_validate_learning_src_dst $CLI_CUR_NODE] } {
	return 0
}
set addrs [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
foreach addr $addrs {
	set addr_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $addr ""]
	set type [cli_get_value $addr_node "" "" "type"]
	if { $type eq "mac" } {
		set opmode [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"]
		if { $opmode eq "nat" } {
			cli_set_errmsg "Destination address cannot be MAC type in NAT mode"
			return 0
		}
	}
}
if { !$skip_src &&
     [cli_is_match $CLI_CUR_NODE 0 "" "internet-service-src" 0 "enable"] } {
	set src_id [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src-name"]
	if { $src_id eq "" } {
		set src_group [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src-group"]
		if { $src_group eq "" } {
			set src_custom [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src-custom"]
			if { $src_custom eq "" } {
				set src_custom_grp [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src-custom-group"]
				if { $src_custom_grp eq "" } {
					cli_set_errmsg "Must set internet service source, internet service source group, custom internet service source or custom internet service source group."
					return 0
				}
			}
		}
	}
}
namespace import global::wildcard_fqdn_check
set srcaddr [cli_get_value $CLI_CUR_NODE "" "" "srcaddr"]
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
if { [wildcard_fqdn_check $srcaddr "src" 0] || [wildcard_fqdn_check $dstaddr "dst" 0] } {
    return 0
}
return 1
	%}
	"firewall policy {srcintf dstaddr dstintf}" = %{
set policy $CLI_CUR_PARENT_NODE
set node $CLI_CUR_NODE_NAME
namespace import global::set_rep_dst
set int_srv [cli_get_value $policy "" "" "internet-service"]
if { $node eq "dstaddr" } {
	if { [set_rep_dst $policy] } {
		return 1
	}
	if { $int_srv eq "enable" } {
		return 1
	}
}
set policyid [cli_get_value $policy "" "" "policyid"]
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value eq "" && $node ne "dstaddr" } {
	cli_set_errmsg "$CLI_CUR_NODE_NAME in Policy \"$policyid\" cannot be empty."
	return 0
} 
if { $node eq "dstaddr" } {
	set sys_settings [cli_get_node $CLI_CUR_VDOM_NODE "system settings" "" ""]
	if { [cli_get_value $sys_settings "" "" "central-nat"] eq "enable" } {
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
		set addrs [cli_get_value $CLI_CUR_NODE "" "" ""]
		foreach addr $addrs {
			set addr [string trim $addr \"]
			if { [lsearch -exact $fwvipnlist $addr] >= 0 } {
				cli_set_errmsg "Firewall policy dstaddr ($addr) cannot be a vip or vipgrp when central-nat is enabled."
				return 0
			}
		}
	}
}
if { $CLI_CUR_NODE_NAME ne "dstaddr" } {
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
set inspall [cli_get_value $sslprof "ssl" "" "inspect-all"]
if { $inspall ne "disable" } {
	cli_set_errmsg "webcache-https cannot be enabled when inspect-all for ssl is enabled in ssl-ssh-profile."
	return 0
}
set httpstat [cli_get_value $sslprof "https" "" "status"]
if { $httpstat ne "deep-inspection" } {
	cli_set_errmsg "webcache-https cannot be enabled when deep-inspection for https is not enabled in ssl-ssh-profile."
	return 0
}
return 1
	%}
	"firewall policy nat64" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]

if { $value eq "disable" } {
	set policy $CLI_CUR_PARENT_NODE
	set dstaddr6list [cli_get_value $policy "" "" "dstaddr6"]
	set dstaddr6nlist {}
	foreach addr6 $dstaddr6list {
		set addr6 [string trim $addr6 \"]
		lappend dstaddr6nlist $addr6
	}

	set fwvip6list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall vip6"]
	foreach fwvip6 $fwvip6list {
		set fwvip6name [cli_get_value $fwvip6 "" "" "name"]
		set fwvip6name [string trim $fwvip6name \"]
		if { [lsearch -exact $dstaddr6nlist $fwvip6name] >= 0 } {
			set fwvip6nat64 [cli_get_value $fwvip6 "" "" "nat64"]
			if { $fwvip6nat64 eq "enable" } {
				cli_set_errmsg "Firewall policy dstaddr6 ($fwvip6name) cannot be a vip6 or vipgrp6 with nat64 enabled when policy nat64 is disabled."
				return 0
			}
		}
	}

	set fwvipgrp6list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall vipgrp6"]
	foreach fwvipgrp6 $fwvipgrp6list {
		set fwvipgrp6name [cli_get_value $fwvipgrp6 "" "" "name"]
		set fwvipgrp6name [string trim $fwvipgrp6name \"]
		if { [lsearch -exact $dstaddr6nlist $fwvipgrp6name] >= 0 } {
			set fwvipgrp6nat64 [cli_get_value $fwvipgrp6 "" "" "nat64"]
			if { $fwvipgrp6nat64 eq "enable" } {
				cli_set_errmsg "Firewall policy dstaddr6 ($fwvip6name) cannot be a vip6 or vipgrp6 with nat64 enabled when policy nat64 is disabled."
				return 0
			}
		}
	}
}

 return 1
 	%}
	"firewall policy auto-asic-offload" = %{
set offload [cli_get_value $CLI_CUR_NODE "" "" ""]
set measurement [cli_get_value $CLI_CUR_PARENT_NODE "" "" "passive-wan-health-measurement"]
if { $measurement eq "enable" && $offload eq "enable" } {
	cli_set_errmsg "Firewall policy auto-asic-offload cannot be enabled when passive-wan-health-measurement is enabled"
	return 0
}

return 1
	%}
	"firewall {policy policy6} {diffservcode-forward diffservcode-rev}" = %{
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
	"wireless-controller vap split-tunneling" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "enable" } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "local-bridging"] eq "enable" } {
		set vapname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
		cli_set_errmsg "$vapname : split-tunneling can not be enabled due to local-bridging enabled "
		return 0
	} elseif { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mesh-backhaul"] eq "enable" } {
		set vapname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
		cli_set_errmsg "$vapname : split-tunneling can not be enabled due to mesh-backhaul enabled "
		return 0
	}
}
return 1
	%}
	"firewall {DoS-policy interface-policy} dstaddr" = %{
set addrs [cli_get_value $CLI_CUR_NODE "" "" ""]
foreach addr $addrs {
	set addr_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $addr ""]
	set type [cli_get_value $addr_node "" "" "type"]
	if { $type eq "mac" } {
		set opmode [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"]
		if { $opmode eq "nat" } {
			cli_set_errmsg "Destination address cannot be MAC type when in NAT mode"
			return 0
		}
	}
}
return 1
	%}
	"firewall {DoS-policy DoS-policy6} anomaly log" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] ne "enable" } {
	set status [cli_get_value $CLI_CUR_PARENT_NODE "" "" "status"]
	set cp_status [cli_get_value $CLI_CUR_VDOM_NODE "client-reputation profile" "" "status"]
	if { $status eq "enable" && $cp_status eq "enable" } {
		cli_set_errmsg "The value of log must be \"enable\" when client-reputation enabled."
		return 0
	}
}
return 1
	%}
	"router policy {src dst}" = %{
set name $CLI_CUR_NODE_NAME
set ip [cli_get_value $CLI_CUR_NODE "" "" ""]
set ippat1 {(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)}
set iplist [split $ip " "]
set total [llength $iplist]
foreach e $iplist {
	set e [string trim $e \"]
	set ipmask [split $e "/"]
	set len [llength $ipmask]
	if { $len == 1 } {
		if { (![regexp $ippat1 $ipmask match]) || ($ipmask ne $match) } {
			cli_set_errmsg "\"$name\" value \"$e\" not a valid IP"
			return 0
		}
		cli_set_errmsg "\"$name\" value \"$e\" not a valid IP/Mask."
		return 0
	} elseif { $len == 2 } {
		set ip [lindex $ipmask 0]
		if { (![regexp $ippat1 $ip match]) || ($ip ne $match) } {
			cli_set_errmsg "\"$name\" value \"$ip\" not a valid IP"
			return 0
		}
		set mask [lindex $ipmask 1]
		set mlen [llength [split $mask "."]]
		if { $mlen == 1 } {
			if { $mask < 0 || $mask > 32 } {
				cli_set_errmsg "\"$name\" mask \"$mask\" is invalid"
				return 0
			}
		} elseif { (![regexp $ippat1 $mask match]) || ($mask ne $match) } {
			cli_set_errmsg "\"$name\" value \"$mask\" not a valid IP"
			return 0
		}
	}
}
return 1
	%}
	"system settings inspection-mode" = %{
set mode [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $mode eq "flow" } {
	set explicit_policies [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall explicit-proxy-policy"]
	foreach policy $explicit_policies {
		set status [cli_get_value $policy "" "" "status"]
		if { $status eq "enable" } {
			cli_set_errmsg "inspection-mode can't be set to flow because the system has explicit proxy enabled!"
			return 0
		}
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
	"wireless-controller wtp-profile {radio-1 radio-2} {auto-power-low auto-power-high}" = %{
if { $CLI_CUR_PARENT_NAME eq "radio-1" } {
	set radio "1"
} elseif { $CLI_CUR_PARENT_NAME eq "radio-2" } {
	set radio "2"
} else {
	return 0
}
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
set band [cli_get_value $CLI_CUR_PARENT_NODE "" "" "band"]
set platform [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "platform" "" "type"]
if { $band ne "" && $platform ne "" } {
	set max [cli_get_devinfo "wl_radio_maxpower" $radio $platform $band]
	if { $max > 0 && ($value < 1 || $value > $max) } {
		cli_set_errmsg "value range from 1 to $max"
		return 0
	}
}
return 1
	%}
	"extender-controller extender {_modem1 _modem2}" = %{
set intfs [cli_get_value $CLI_CUR_NODE "" "" "ifname"]
foreach intf $intfs {
	set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" "$intf" ""]
	set type [cli_get_value $intf_node "" "" "type"]
	if { $type ne "fext-wan" } {
		set extender_vlan_mode [cli_get_value $CLI_GLOBAL_NODE "system global" "" "fortiextender-vlan-mode"]
		if { $type eq "vlan" && $extender_vlan_mode eq "enable" } {
			return 1
		}
		cli_set_errmsg "$intf type is not fext-wan"
		return 0
	}
}
return 1
	%}
	"firewall local-in-policy" = %{
namespace import global::ln_policy_intf_binding_contradiction
set srcaddr [cli_get_value $CLI_CUR_NODE "" "" "srcaddr"]
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
set intf [cli_get_value $CLI_CUR_NODE "" "" "intf"]
set policyid [cli_get_value $CLI_CUR_NODE "" "" "policyid"]
set msg [ln_policy_intf_binding_contradiction $srcaddr $intf $policyid 0]
if { $msg ne 0 } {
	cli_set_errmsg $msg
	return 0
}
set msg [ln_policy_intf_binding_contradiction $dstaddr $intf $policyid 1]
if { $msg ne 0 } {
	cli_set_errmsg $msg
	return 0
}
return 1
	%}
	"system sdwan service" = %{
set nm [cli_get_value $CLI_CUR_NODE "" "" "name"]
for {set i 0} {$i < [string length $nm]} {incr i} {
	set char [string index $nm $i]
	if { ![regexp {[ -~]} $char] || [regexp {[<>\"\'\(\)#\\\s]} $char] } {
		cli_set_errmsg "invalid character in name : $nm"
		return 0
	}
}
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
if { $mode eq "manual" || $mode eq "priority" || $mode eq "sla" || $mode eq "load-balance" } {
	set pm [cli_get_value $CLI_CUR_NODE "" "" "priority-members"]
	set pz [cli_get_value $CLI_CUR_NODE "" "" "priority-zone"]
	if { $pm eq "" && $pz eq "" } {
		cli_set_errmsg "Please assign priority-member(s) or priority-zone(s)"
		return 0
	}
}
set is [cli_get_value $CLI_CUR_NODE "" "" "internet-service"]
set isi [cli_get_value $CLI_CUR_NODE "" "" "internet-service-name"]
set isg [cli_get_value $CLI_CUR_NODE "" "" "internet-service-group"]
set isc [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom"]
set iscg [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom-group"]
set isct [cli_get_value $CLI_CUR_NODE "" "" "internet-service-app-ctrl"]
set isctg [cli_get_value $CLI_CUR_NODE "" "" "internet-service-app-ctrl-group"]
set isctc [cli_get_value $CLI_CUR_NODE "" "" "internet-service-app-ctrl-category"]
set dst [cli_get_value $CLI_CUR_NODE "" "" "dst"]
set dst6 [cli_get_value $CLI_CUR_NODE "" "" "dst6"]
set rtag [cli_get_value $CLI_CUR_NODE "" "" "route-tag"]
if { ($is eq "enable" ) &&
     ($isi eq "" ) &&
     ($isg eq "" ) &&
     ($isc eq "" ) &&
     ($iscg eq "" ) &&
     ($isct eq "" ) &&
     ($isctg eq "" ) &&
     ($isctc eq "" ) } {
	cli_set_errmsg "Please assign internet service or custom internet service since internet-service is enabled"
	return 0
}
if { $is ne "enable" && $rtag eq "0" } {
	set am [cli_get_value $CLI_CUR_NODE "" "" "addr-mode"]
	if { ($am eq "ipv4" && $dst eq "" ) || ($am eq "ipv6" && $dst6 eq "" ) } {
		cli_set_errmsg "Please assign a dst or internet-service"
		return 0
	}
}
cli_schedule_post_check $CLI_CUR_PARENT_NODE $CLI_ACT
return 1
	%}
	"system sdwan health-check" = %{
set proto [cli_get_value $CLI_CUR_NODE "" "" "protocol"]
set mode [cli_get_value $CLI_CUR_NODE "" "" "addr-mode"]
if { $mode eq "ipv6" && $proto eq "tcp-echo" } {
	cli_set_errmsg "tcp-echo protocol not available in ipv6"
	return 0
} elseif { $mode eq "ipv6" && $proto eq "http" } {
	cli_set_errmsg "http protocol not available in ipv6"
	return 0
} elseif { $mode eq "ipv6" && $proto eq "twamp" } {
	cli_set_errmsg "twamp protocol not available in ipv6"
	return 0
}
return 1
	%}
	"system sdwan neighbor" = %{
cli_schedule_post_check $CLI_CUR_PARENT_NODE $CLI_ACT
return 1
	%}
	"system sdwan" = %{
set svs [cli_get_tbl_list $CLI_CUR_NODE "service"]
set mbs [cli_get_tbl_list $CLI_CUR_NODE "members"]
set hcs [cli_get_tbl_list $CLI_CUR_NODE "health-check"]
set nbs [cli_get_tbl_list $CLI_CUR_NODE "neighbor"]
set dus [cli_get_tbl_list $CLI_CUR_NODE "duplication"]
set zones [cli_get_tbl_list $CLI_CUR_NODE "zone"]

foreach mb $mbs {
	set z [string trim [cli_get_value $mb "" "" "zone"] \"]
	set name [cli_get_value $mb "" "" "name"]
	if { $z ne "virtual-wan-link" } {
		set exist 0
		foreach zone $zones {
			set n [cli_get_value $zone "" "" "name"]
			if { $n eq $z } {
				set exist 1
				break
			}
		}
		if { $exist eq 0 } {
			cli_set_errmsg "$z is not a valid zone name for member $name"
			return 0
		}
	}
}

foreach sv $svs {
	set mode [cli_get_value $sv "" "" "mode"]
	set name [cli_get_value $sv "" "" "name"]
	set id [cli_get_value $sv "" "" "id"]
	set addrmode [cli_get_value $sv "" "" "addr-mode"]
	if { $name ne "" } {
		foreach sv2 $svs {
			set name2 [cli_get_value $sv2 "" "" "name"]
			if { $name2 eq $name } {
				set id2 [cli_get_value $sv2 "" "" "id"]
				if { $id2 ne $id } {
					cli_set_errmsg "Duplicate service name $name"
					return 0
				}
			}
		}
	}
	if { $mode eq "manual" || $mode eq "priority" || $mode eq "sla" || $mode eq "load-balance" } {
		set pm [cli_get_value $sv "" "" "priority-members"]
		set pz [cli_get_value $sv "" "" "priority-zone"]
		if { $pm eq "" && $pz eq "" } {
			cli_set_errmsg "Please assign priority-member(s) or priority-zone(s)"
			return 0
		}
		foreach m $pm {
			set m [string trim $m \"]
			set exist 0
			foreach mb $mbs {
				set n [cli_get_value $mb "" "" "seq-num"]
				if { $n eq $m } {
					set exist 1
					break
				}
			}
			if { $exist eq 0 } {
				cli_set_errmsg "$m is not a valid member seq number for service $name"
				return 0
			}
		}
	}
	if { $mode eq "auto" || $mode eq "priority" } {
		set h [cli_get_value $sv "" "" "health-check"]
		set h [string trim $h \"]
		if { $h eq "" } {
			cli_set_errmsg "Please select a health-check for service $name"
			return 0
		}
		set exist 0
		foreach hc $hcs {
			set n [cli_get_value $hc "" "" "name"]
			if { $n eq $h } {
				set exist 1
				set hcmode [cli_get_value $hc "" "" "addr-mode"]
				if { $hcmode ne $addrmode } {
					cli_set_errmsg "Invalid health check addr-mode for $h for sevice $name"
					return 0
				}
				break
			}
		}
		if { $exist eq 0 } {
			cli_set_errmsg "Bad health check name $h for sevice $name"
			return 0
		}
	}
	if { $mode eq "auto" } {
		set q [cli_get_value $sv "" "" "quality-link"]
		if { $q > [llength $mbs] } {
			cli_set_errmsg "Value for quality-link is more than the number of members for service $name"
			return 0
		}
	}
	if { $mode eq "sla" || $mode eq "load-balance" } {
		set slas [cli_get_tbl_list $sv "sla"]
		foreach sla $slas {
			set h [cli_get_value $sla "" "" "health-check"]
			set h [string trim $h \"]
			set id [cli_get_value $sla "" "" "id"]
			set exist 0
			foreach hc $hcs {
				set n [cli_get_value $hc "" "" "name"]
				if { $n eq $h } {
					set hcmode [cli_get_value $hc "" "" "addr-mode"]
					if { $hcmode ne $addrmode } {
						cli_set_errmsg "Invalid health check addr-mode for $h"
						return 0
					}
					set chk [cli_get_node $hc "sla" $id ""]
					if { $chk ne 0 } {
						set exist 1
					}
					break
				}
			}
			if { $exist eq 0 } {
				cli_set_errmsg "Invalid health check name $h or SLA id $id"
				return 0
			}
		}
	}
	set pz [cli_get_value $sv "" "" "priority-zone"]
	foreach z $pz {
		set z [string trim $z \"]
		if { $z ne "virtual-wan-link" } {
			set exist 0
			foreach zone $zones {
				set n [cli_get_value $zone "" "" "name"]
				if { $n eq $z } {
					set exist 1
					break
				}
			}
			if { $exist eq 0 } {
				cli_set_errmsg "$z is not a valid priority-zone name for service $name"
				return 0
			}
		}
	}
}
foreach hc $hcs {
	set name [cli_get_value $hc "" "" "name"]
	set m [cli_get_value $hc "" "" "member"]
	set m [string trim $m \"]
	if { $m ne 0 && $m ne "" } {
		set exist 0
		foreach mb $mbs {
			set n [cli_get_value $mb "" "" "seq-num"]
			if { $n eq $m } {
				set exist 1
				break
			}
		}
		if { $exist eq 0 } {
			cli_set_errmsg "$m is not a valid member seq number in health-check $name"
			return 0
		}
	}
}
foreach nb $nbs {
	set name [cli_get_value $nb "" "" "ip"]
	set mode [cli_get_value $nb "" "" "mode"]
	set ms [cli_get_value $nb "" "" "member"]
	set num_members [llength $ms]
	if { [cli_get_value $nb "" "" "minimum-sla-meet-members"] > $num_members } {
		cli_set_errmsg "The minimum-sla-meet-members should be no more than $num_members"
		return 0
	}
	foreach m $ms {
		set m [string trim $m \"]
		if { $m ne "" } {
			set exist 0
			foreach mb $mbs {
				set n [cli_get_value $mb "" "" "seq-num"]
				if { $n eq $m } {
					set exist 1
					break
				}
			}
			if { $exist eq 0 } {
				cli_set_errmsg "$m is not a valid member seq number in neighbor $name"
				return 0
			}
		}
	}
	if { $mode eq "sla" } {
		set h [cli_get_value $nb "" "" "health-check"]
		set h [string trim $h \"]
		set id [cli_get_value $nb "" "" "sla-id"]
		if { $h ne 0 && $h ne "" } {
			set exist 0
			foreach hc $hcs {
				set n [cli_get_value $hc "" "" "name"]
				if { $n eq $h } {
					if { $id eq 0 && [cli_get_tbl_cnt $hc "sla"] eq 0 } {
						set exist 1
					} else {
						set chk [cli_get_node $hc "sla" $id ""]
						if { $chk ne 0 } {
							set exist 1
						}
					}
					break
				}
			}
			if { $exist eq 0 } {
				cli_set_errmsg "Invalid health-check $h and sla-id $id for neighbor $name"
				return 0
			}
		} else {
			if { [cli_get_value $nb "" "" "mode"] ne "speedtest" } {
				cli_set_errmsg "health-check must be set for neighbor $name"
				return 0
			}
		}
	} elseif { $mode eq "speedtest" } {
		if { $num_members > 1 } {
			cli_set_errmsg "speedtest mode only support 1 member"
			return 0
		}
	}
}
foreach du $dus {
	set name [cli_get_value $du "" "" "id"]
	set ms [cli_get_value $du "" "" "service-id"]
	foreach m $ms {
		set m [string trim $m \"]
		set exist 0
		foreach sv $svs {
			set n [cli_get_value $sv "" "" "id"]
			if { $n eq $m } {
				set exist 1
				break
			}
		}
		if { $exist eq 0 } {
			cli_set_errmsg "$m is not a valid service-id in duplication $name"
			return 0
		}
	}
}
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
	"endpoint-control profile forticlient-winmac-settings" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" "forticlient-system-compliance"] eq "enable" &&
     [cli_get_value $CLI_CUR_NODE "" "" "os-av-software-installed"] eq "enable" &&
     [cli_get_value $CLI_CUR_NODE "" "" "av-realtime-protection"] eq "enable" } {
	cli_set_errmsg "Please disable 'os-av-software-installed' first"
	return 0
}
if { [cli_get_value $CLI_CUR_NODE "" "" "forticlient-application-firewall"] eq "enable" &&
     [cli_get_value $CLI_CUR_NODE "" "" "forticlient-application-firewall-list"] eq "" } {
	cli_set_errmsg "Please set the FortiClient application firewall rule list"
	return 0
}
return 1
	%}
	"system interface device-identification" = %{
set nv [cli_get_value $CLI_CUR_NODE "" "" ""]
set ov [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { $nv eq "disable" && $ov eq "enable" } {
	set intfname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	set zones [cli_get_tbl_list $CLI_CUR_VDOM_NODE "system zone"]
	set zname ""
	foreach zone $zones {
		set exist 0
		set intfs [cli_get_value $zone "" "" "interface"]
		foreach intf $intfs {
			set intf [string trim $intf "\""]
			if { $intf eq $intfname } {
				set exist 1
				break
			}
		}
		if { $exist } {
			set zname [cli_get_value $zone "" "" "name"]
			break
		}
	}
	set plist [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "firewall policy" "learning-mode" 0 "enable" "srcintf" 1 "any" "srcintf" 1 "virtual-wan-link"]
	foreach p $plist {
		set intfs [cli_get_value $p "" "" "srcintf"]
		foreach intf $intfs {
			set intf [string trim $intf "\""]
			if { $intf eq $intfname || (($zname ne "" ) && ($intf eq $zname)) } {
				cli_set_errmsg "Device-identification cannot be disable because interface $intfname is used as a source interface (or in a zone) in one or more policies with learning mode enabled."
				return 0
			}
		}
	}
}
return 1
	%}
	"system interface {switch-controller-nac switch-controller-dynamic}" = %{
set flset [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $flset eq "" } {
	return 1
}
set flsetnode [cli_get_node $CLI_CUR_VDOM_NODE "switch-controller fortilink-settings" $flset ""]
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set nac [cli_get_node $flsetnode "nac-ports" "" ""]
set vlan [cli_get_value $nac "" "" "onboarding-vlan"]
set vintf [cli_get_value $CLI_GLOBAL_NODE "system interface" $vlan "interface"]
set vintf [string map {\" {}} $vintf]
if { $name ne $vintf } {
	cli_set_errmsg "Fortilink-settings \"$flset\" onboarding-vlan $vlan fortilink mismatches with fortilink \"$name\""
	return 0
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
if { $exist } {
	namespace import global::cli_get_diff_opts
	set nintf [cli_get_value $CLI_CUR_NODE "" "" ""]
	set ointf [cli_get_org_value $CLI_CUR_NODE "" "" ""]
	set nopts [cli_get_diff_opts $nintf $ointf 1]
	foreach nopt $nopts {
		set nopt [string trim $nopt "\""]
		set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $nopt ""]
		set devid [cli_get_value $intfnode "" "" "device-identification"]
		if { $devid ne "enable" } {
			cli_set_errmsg "Device-identification disabled interface $nopt can not used in zone $zname which is used as source zone in one or more policies with learning mode enabled."
			return 0
		}
	}
}
return 1
	%}
    "switch-controller mac-policy" = %{
set fortilink [cli_get_value $CLI_CUR_NODE "" "" "fortilink"]
if { $fortilink eq "" } {
    cli_set_errmsg "fortilink must be set"
    return 0
}
return 1
    %}
	"switch-controller managed-switch ports" = %{
if { [string match "*upgrade*" [cli_get_clisrc]] } {
	## skip during migration, as we cannot predict the order of the data
	return 1
}
set name [cli_get_value $CLI_CUR_NODE "" "" "port-name"]
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set owner ""
if { $type eq "physical" } {
	set ret [cli_check_fsp_config $CLI_CUR_NODE]
	if { $ret != 0 } {
		return 0
	}
}
if { $type eq "trunk" } {
	set members [cli_get_value $CLI_CUR_NODE "" "" "members"]
	foreach m $members {
		set port [cli_get_node $CLI_CUR_PARENT_NODE "" $m ""]
		if { $port eq 0 } {
			cli_set_errmsg "invalid member $m for trunk $name"
			return 0
		}
	}
} else {
	set owner [cli_get_value $CLI_CUR_NODE "" "" "port-owner" 1]
	if { $owner ne 0 && $owner ne "" } {
		set trunk [cli_get_node $CLI_CUR_PARENT_NODE "" $owner ""]
		if { $trunk eq 0 } {
			cli_set_errmsg "invalid trunk $owner for member $name"
			return 0
		}
		set members [cli_get_value $trunk "" "" "members"]
		if { [lsearch $members $name] < 0 } {
			cli_set_errmsg "port $name is not one of trunk $owner member"
			return 0
		}
	}
}
if { $owner eq 0 || $owner eq "" } {
	set vlan_all [cli_get_value $CLI_CUR_NODE "" "" "allowed-vlans-all"]
	set native [cli_get_value $CLI_CUR_NODE "" "" "vlan"]
	set native [string trim $native \"]
	set mode [cli_get_value $CLI_CUR_NODE "" "" "access-mode"]
	if { $mode eq "normal" && ($native eq 0 || $native eq "") } {
		cli_set_errmsg "native vlan must be set"
		return 0
	}
}
set pp [cli_get_value $CLI_CUR_NODE "" "" "port-policy"]
if { $pp ne "" } {
	set dppintf [cli_get_value $CLI_CUR_VDOM_NODE "switch-controller dynamic-port-policy" $pp "fortilink"]
	set dppintf [string map {\" {}} $dppintf]
	set fsw [cli_get_parent $CLI_CUR_PARENT_NODE]
	set flink [cli_get_value $fsw "" "" "fsw-wan1-peer"]
	if { $flink eq "" } {
		set flink [cli_get_value $fsw "" "" "fsw-wan2-peer" ]
	}
	set flink [string trim $flink \"]
	if { $flink ne "" && $dppintf ne $flink } {
		set swid [cli_get_value $fsw "" "" "switch-id"]
		cli_set_errmsg "Dynamic port policy $pp FortiLink interface $dppintf mismatches with applied FortiSwitch $swid FortiLink interface $flink"
		return 0
	}
}
return 1
	%}
	"switch-controller managed-switch ports vlan" = %{
set access [cli_get_value $CLI_CUR_PARENT_NODE "" "" "access-mode"]
set vlan [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
if { $access eq "nac" && ![string match "*override*" [cli_get_clisrc]] } {
	set ovlan [string trim [cli_get_org_value $CLI_CUR_NODE "" "" ""] \"]
	if { $vlan ne $ovlan } {
		set fsw [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]]
		set nacvlan 0

		set flink [cli_get_value $fsw "" "" "fsw-wan1-peer" ]
		if { $flink eq "" } {
			set flink [cli_get_value $fsw "" "" "fsw-wan2-peer" ]
		}
		if { $flink ne "" } {
			set nacname [cli_get_value $CLI_GLOBAL_NODE "system interface" $flink "switch-controller-nac"]
			set nacset [cli_get_node $CLI_CUR_VDOM_NODE "switch-controller fortilink-settings" $nacname ""]
			if { $nacset ne 0 } {
				set nacvlan [string trim [cli_get_value $nacset "nac-ports" "" "onboarding-vlan"] \"]
			}
		}
		if { $vlan ne $nacvlan } {
			cli_set_errmsg "cannot change native vlan when port is in NAC mode"
			return 0
		}
	}
}
return 1
	%}
	"switch-controller managed-switch ports {allowed-vlans-all}" = %{
if { ![string match "*override*" [cli_get_clisrc]] } {
	set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "access-mode"]
	set omode [cli_get_org_value $CLI_CUR_PARENT_NODE "" "" "access-mode"]
	if { $mode eq "nac" && $omode eq "nac" } {
		set val [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
		set oval [string trim [cli_get_org_value $CLI_CUR_NODE "" "" ""] \"]
		if { $val ne $oval} {
			cli_set_errmsg "cannot be changed when port is in nac-mode"
			return 0
		}
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
	"switch-controller managed-switch ports untagged-vlans" = %{
set untags [cli_get_value $CLI_CUR_NODE "" "" ""]
set vlan [string trim [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vlan"] \"]
set port [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-name"]
foreach untag $untags {
	set untag [string trim $untag \"]
	if { $untag eq $vlan } {
		cli_set_errmsg "vlan $untag can not be both untagged-vlans and native vlan for $port"
		return 0
	}
}
return 1
	%}
	"switch-controller vlan-policy" = %{
set fortilink [cli_get_value $CLI_CUR_NODE "" "" "fortilink"]
if { $fortilink eq "" } {
	cli_set_errmsg "fortilink must be set"
	return 0
}

set allowed [cli_get_value $CLI_CUR_NODE "" "" "allowed-vlans"]
foreach allow $allowed {
	set intf [cli_get_value $CLI_GLOBAL_NODE "system interface" $allow "interface"]
	if { $intf ne $fortilink } {
		cli_set_errmsg "allowed-vlans: Vlan \"$allow\" interface ($intf) does not match fortilink ($fortilink)"
		return 0
	}
}
set untagged [cli_get_value $CLI_CUR_NODE "" "" "untagged-vlans"]
foreach untag $untagged {
	set intf [cli_get_value $CLI_GLOBAL_NODE "system interface" $untag "interface"]
	if { $intf ne $fortilink } {
		cli_set_errmsg "untagged-vlans: Vlan \"$untag\" interface ($intf) does not match fortilink ($fortilink)"
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
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value eq "" || $value == 0 } {
	cli_set_errmsg "node_check_object fail! for $CLI_CUR_NODE_NAME is empty. Attribute '$CLI_CUR_NODE_NAME' MUST be set."
	return 0
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
	"system virtual-switch port name" = %{
## manually perform reference check due to weakdatasrc
set intf [cli_get_value $CLI_CUR_NODE "" "" ""]
set node [cli_get_node $CLI_GLOBAL_NODE "system interface" $intf ""]
if { $node eq 0 } {
	cli_set_errmsg "Invalid interface $intf."
	return 0
}
return 1
	%}
	"system csf" = %{
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
if { $status eq "enable" } {
	set upstream [cli_get_value $CLI_CUR_NODE "" "" "upstream"]
	if { $upstream eq "" || $upstream eq "0.0.0.0" } {
		set grp_name [cli_get_value $CLI_CUR_NODE "" "" "group-name"]
		if { $grp_name eq "" } {
			cli_set_errmsg "Root Security Fabric FortiGate must define a group-name."
			return 0
		}
	} else {
		set mgmt_ip [cli_get_value $CLI_GLOBAL_NODE "system global" "" "management-ip"]
		set sync_mode [cli_get_value $CLI_CUR_NODE "" "" "configuration-sync"]
		set saml_sync [cli_get_value $CLI_CUR_NODE "" "" "saml-configuration-sync"]
		if { $sync_mode eq "default" && $saml_sync eq "default" && 
		     ($mgmt_ip eq "" || $mgmt_ip eq "0.0.0.0") } {
			cli_set_errmsg "To enable SAML sync, non-root members of Security fabric must have a valid management IP (\"system global.management-ip\")."
			return 0
		}
		set auth_mode [cli_get_value $CLI_CUR_NODE "" "" "authorization-request-type"]
		set cert [cli_get_value $CLI_CUR_NODE "" "" "certificate"]
		if { $auth_mode eq "certificate" && $cert eq "" } {
			cli_set_errmsg "Certificate name should be set if the authorization mode is set to certificate."
			return 0
		}
	}
}
return 1
	%}
	"system replacemsg-group" = %{
set group_name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set group_type [cli_get_value $CLI_CUR_NODE "" "" "group-type"]
if { $group_type eq "" || $group_type eq "default" } {
	if { $group_name ne "default" && $group_name ne "g-default" } {
		cli_set_errmsg "The group name must be default."
		return 0
	}
}
return 1
	%}
	"system replacemsg-group group-type" = %{
set ov [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set nv [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ($ov ne $nv) && ($ov eq "auth") } {
	set group_name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	if { [cli_get_match_nr $CLI_GLOBAL_NODE 1 "system interface" "replacemsg-override-group" 0 $group_name] } {
		cli_set_errmsg "Cannot change type when group is used by interface.replacemsg-override-group."
		return 0
	}
}
return 1
	%}
    "user nac-policy mac" = %{
set mac [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $mac ne "" } {
	set ret [cli_check_wildcard_mac $mac]
	if { $ret ne "" } {
		cli_set_errmsg $ret
		return 0
	}
}
return 1
    %}
	"user nac-policy src" = %{
namespace import global::check_src_string
if { [check_src_string [cli_get_value $CLI_CUR_NODE "" "" ""]] eq -1} {
	cli_set_errmsg "Invalid source string"
	return 0
}
return 1
	%}
	"user nac-policy" = %{
set cat [cli_get_value $CLI_CUR_NODE "" "" "category"]
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $cat eq "ems-tag" } {
	set tag [cli_get_value $CLI_CUR_NODE "" "" "ems-tag"]
	if { $tag ne "" && $status eq "enable"} {
		set pol_list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "user nac-policy"]
		foreach node $pol_list {
			set n [cli_get_value $node "" "" "name"]
			if { $name ne $n } {
				set cate [cli_get_value $node "" "" "category"]
				set stat [cli_get_value $node "" "" "status"]
				if { $cate eq "ems-tag" && $stat eq "enable" } {
					set etag [cli_get_value $node "" "" "ems-tag"]
					if { $etag eq $tag } {
						cli_set_errmsg "EMS Tag $tag already used in NAC policy \"$n\""
						return 0
					}
				}
			}
		}
	}
} elseif { $cat eq "firewall-user" && $status eq "enable" } {
	set usergroup [cli_get_value $CLI_CUR_NODE "" "" "user-group"]
	set pol_list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "user nac-policy"]
	foreach node $pol_list {
		set n [cli_get_value $node "" "" "name"]
		if { $name ne $n } {
			set cate [cli_get_value $node "" "" "category"]
			set stat [cli_get_value $node "" "" "status"]
			if { $cate eq "firewall-user" && $stat eq "enable" } {
				set ug [cli_get_value $node "" "" "user-group"]
				if { $usergroup eq $ug } {
					cli_set_errmsg "Firewall user group $usergroup already used in NAC policy \"$n\""
					return 0
				}
			}
		}
	}
}
return 1
	%}
	"switch-controller fortilink-settings nac-ports" = %{
set ovlan [cli_get_value $CLI_CUR_NODE "" "" "onboarding-vlan"]
if { $ovlan eq "" } {
	cli_set_errmsg "Onboarding VLAN must be set"
	return 0
}
set lan [cli_get_value $CLI_CUR_NODE "" "" "lan-segment"]
if { $lan eq "enabled" } {
	set intf [cli_get_value $CLI_CUR_NODE "" "" "nac-lan-interface"]
	if { $intf eq "" } {
		cli_set_errmsg "Primary VLAN must be set"
		return 0
	}
	set vlans [cli_get_value $CLI_CUR_NODE "" "" "nac-segment-vlans"]
	if { $vlans eq "" } {
		cli_set_errmsg "LAN segment members must be set"
		return 0
	}
	if { $intf eq $ovlan } {
		cli_set_errmsg "Primary VLAN cannot be the same as onboarding VLAN"
		return 0
	}
	set ovlan [string trim $ovlan \"]
	set intf [string trim $intf \"]
	foreach memb $vlans {
		if { $ovlan eq $memb } {
			cli_set_errmsg "Onboarding VLAN cannot be the same as lan segment member \"$memb\""
			return 0
		}
		if { $intf eq $memb } {
			cli_set_errmsg "Primary VLAN cannot be the same as lan segment member \"$memb\""
			return 0
		}
		set mvlanip [cli_get_value $CLI_GLOBAL_NODE "system interface" $memb "ip"]
		set mvlanmode [cli_get_value $CLI_GLOBAL_NODE "system interface" $memb "mode"]
		set mvlanallow [cli_get_value $CLI_GLOBAL_NODE "system interface" $memb "allowaccess"]
		if { ($mvlanip ne "" && $mvlanip ne "0.0.0.0" && $mvlanip ne "0.0.0.0 0.0.0.0") || $mvlanmode ne "static" || ($mvlanallow ne "" && $mvlanallow ne "0") } {
			cli_set_errmsg "Interface $memb may not have IP address or allowacess or non-static mode as member of a lan-segment group."
			return 0
		}
	}
	set ovlanip [cli_get_value $CLI_GLOBAL_NODE "system interface" $ovlan "ip"]
	set ovlanmode [cli_get_value $CLI_GLOBAL_NODE "system interface" $ovlan "mode"]
	set ovlanallow [cli_get_value $CLI_GLOBAL_NODE "system interface" $ovlan "allowaccess"]
	if { ($ovlanip ne "" && $ovlanip ne "0.0.0.0" && $ovlanip ne "0.0.0.0 0.0.0.0") || $ovlanmode ne "static" || ($ovlanallow ne "" && $ovlanallow ne "0") } {
		cli_set_errmsg "Interface onboarding may not have IP address or allowacess or non-static mode as member of a lan-segment group."
		return 0
	}
}
return 1
	%}
	"wireless-controller vap local-authentication" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "disable" } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "local-standalone"] eq "enable" } {
		cli_set_errmsg "Can't disable local-authentication due to local-standalone enabled "
		return 0
	}
}
return 1
	%}
	"system admin gui-dashboard widget {interface}" = %{
if { [cli_get_devinfo "SASE"] eq "no" && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tr-history"] } {
	set value [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $value eq "" || $value == 0 } {
		cli_set_errmsg "node_check_object fail! for $CLI_CUR_NODE_NAME is empty. Attribute '$CLI_CUR_NODE_NAME' MUST be set."
		return 0
	}
}
return 1
	%}
	"system admin gui-dashboard widget {fortiview-sort-by fortiview-timeframe}" = %{
if { [cli_get_devinfo "SASE"] eq "no" && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fortiview"] } {
	set value [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $value eq "" || $value == 0 } {
		cli_set_errmsg "node_check_object fail! for $CLI_CUR_NODE_NAME is empty. Attribute '$CLI_CUR_NODE_NAME' MUST be set."
		return 0
	}
}
return 1
	%}
%};
