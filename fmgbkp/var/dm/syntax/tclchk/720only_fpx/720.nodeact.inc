nodeact %{
	"system vdom" = %{
if { $CLI_ACT eq "add" } {
	set fullname [cli_get_value $CLI_CUR_NODE "" "" ""]
	set findex [string first "/" $fullname]
	if { $findex > 0 } {
		set vdname [string range $fullname 0 $findex-1 ]
	} else {
		set vdname $fullname
	}
	set opmode [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"]
	namespace import global::dmgmt_vdom_support
	set dmgmt [dmgmt_vdom_support]
	if { $dmgmt && ($vdname eq "dmgmt-vdom" ) } {
		# do nothing when vdom is "dmgmt-vdom"
	} else {
		set description "\"property limits for vdom "
		append description $vdname
		append description "\""
		set r [cli_exec_cmd $CLI_GLOBAL_NODE "config system vdom-property\nedit $vdname\nset description $description\nnext\nend\n"]
		if { $r ne 0 } {
			return 0
		}
		if { [cli_obj_support "system vdom-property" "snmp-index"] } {
			namespace import global::set_vdom_snmp_index
			set_vdom_snmp_index $vdname
		}
	}
	if { $opmode eq "nat" } {
		if { [cli_has_feature "f_sslvpn"] } {
			namespace import global::get_mux_tunnel_dev_name
			set intfname [get_mux_tunnel_dev_name $fullname]
			cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $intfname\nset vdom $vdname\nset type tunnel\nset alias \"SSL VPN interface\"\nnext\nend\n"
			if { [cli_obj_support "system interface" "snmp-index"] } {
				namespace import global::auto_set_snmp_index
				auto_set_snmp_index $intfname
			}
		}
	} elseif { $opmode eq "transparent" } {
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config router static\nedit 1\nnext\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config router static6\nedit 1\nnext\nend\n"
	}
	namespace import global::sync_certs_between_global_vdom
	set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate local"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate local\n$cmd\nend\n"
	set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate crl"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate crl\n$cmd\nend\n"
	set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate ca"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate ca\n$cmd\nend\n"
	set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate remote"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate remote\n$cmd\nend\n"

	if { [cli_has_feature "f_netx"] } {
		namespace import global::get_shadow_intf_name
		namespace import global::auto_set_snmp_index
		set nint [get_shadow_intf_name "" $vdname "-int"]
		set mac [cli_gen_macaddr]
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $nint\nset vdom $vdname\nset type physical\nset macaddr $mac\nset mtu-override enable\nset mtu 65521\nnext\nend\n"
		auto_set_snmp_index $nint
		set next [get_shadow_intf_name "" $vdname "-ext"]
		set mac [cli_gen_macaddr]
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $next\nset vdom $vdname\nset type physical\nset macaddr $mac\nset mtu-override enable\nset mtu 65521\nnext\nend\n"
		auto_set_snmp_index $next
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config system virtual-wire-pair\nedit $vdname\nset member \"$nint\" \"$next\"\nnext\nend\n"
	}
	set cmd  "config wireless-controller wtp-profile\nedit \"FAP220B-default\"\nconfig platform\nset type 220B\nend\nnext\nend\n"
	cli_exec_cmd  $CLI_CUR_VDOM_NODE $cmd
	set cmd  "config wireless-controller wtp-profile\nedit \"FAP221E-default\"\nconfig platform\nset type 221E\nend\nnext\nend\n"
	cli_exec_cmd  $CLI_CUR_VDOM_NODE $cmd
	if { [cli_obj_support "switch-controller auto-config default" "fgt-policy"] } {
		set cmd  "config switch-controller auto-config default\nset fgt-policy default\nset isl-policy default\nset icl-policy \"default-icl\"\nend\n"
		cli_exec_cmd  $CLI_CUR_VDOM_NODE $cmd
	}
}
cli_on_rlimit_change
return 1
	%}
	"user fsso-polling" = %{
set fsso [cli_get_node $CLI_CUR_VDOM_NODE "user fsso" "Local FSSO Agent" ""]
if { $fsso == 0 } {
	set server [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config user fsso\nedit \"Local FSSO Agent\"\nset ldap-server $server\nset server \"127.0.0.1\"\nnext\nend\n"
}
return 1
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
if { $status eq "enable" } {
	if { $fsso == 0 } {
		set server [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config user fsso\nedit	\"Local FSSO Agent\"\nset ldap-server $server\nset server \"127.0.0.1\"\nnext\nend\n"
	}
} else {
	if { $fsso != 0 } {
		set fssoldap [cli_get_value $fsso "" "" "ldap-server"]
		set curldap [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]
		if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "status" 0 "enable"] == 0 } {
			cli_delete_node $fsso
		} elseif { $curldap eq $fssoldap } {
			# select another node for the new new local fsso agent
			set list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
			foreach node $list {
				set status [cli_get_value $node "" "" "status"]
				set server [cli_get_value $node "" "" "ldap-server"]
				if { $server == 0 || $status ne "enable" } {
					continue
				}
				cli_exec_cmd $CLI_CUR_VDOM_NODE "config user fsso\nedit \"Local FSSO Agent\"\nset ldap-server $server\nset server \"127.0.0.1\"\nnext\nend\n"
				break
			}
		}
	}
}
return 1
	%}
	"wireless-controller wtp-profile split-tunneling-acl" = %{
set name [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "name" ]
set idx [cli_get_value $CLI_CUR_NODE "" "" "id" ]
set dstip [cli_get_value $CLI_CUR_NODE "" "" "dest-ip" ]
if { $dstip ne "" } {
	set newip [cli_format_ipmask $dstip 0]
	set cmd "config wireless-controller wtp-profile\nedit $name\nconfig split-tunneling-acl\nedit $idx\nset dest-ip $newip\nnext\nend\nnext\nend\n"
	cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
}
return 1
	%}
	"wireless-controller wtp-profile {radio-1 radio-2}" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" "vap-all"] eq "enable" } {
	cli_clear_value $CLI_CUR_NODE "" "" "vaps"
}
return 1
	%}
	"system interface" = %{
namespace import global::global_admin_https_redirected_valid
if { [global_admin_https_redirected_valid] } {
	if { [cli_is_match $CLI_GLOBAL_NODE 0 "system global" "admin-https-redirect" 0 "enable"] } {
		set allows [cli_get_value $CLI_CUR_NODE "" "" "allowaccess"]
		set http_exist 0
		set https_exist 0
		foreach a $allows {
			if { $a eq "http" } {
				set http_exist 1
			} elseif { $a eq "https" } {
				set https_exist 1
			}
		}
		if { $http_exist == 1 && $https_exist == 0 } {
			append allows " https"
			set name [cli_get_value $CLI_CUR_NODE "" "" ""]
			cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit \"$name\"\nset allowaccess $allows\nend\n"
		}
	}
}
if { [cli_obj_support "system interface" "snmp-index"] } {
	namespace import global::auto_set_snmp_index
	set intfname [cli_get_value $CLI_CUR_NODE "" "" "name"]
	auto_set_snmp_index $intfname
}
set old_speed [cli_get_org_value $CLI_CUR_NODE "" "" "speed"]
set speed [cli_get_value $CLI_CUR_NODE "" "" "speed"]
if { $old_speed ne $speed && ( $old_speed eq "25000full" || $speed eq "25000full" ) } {
	namespace import global::get_intf_speed_group
	set plat [cli_get_devinfo "platform"]
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set group [get_intf_speed_group $plat $name]
	if { $group ne "" } {
		set intfs [split $group " "]
		foreach intf $intfs {
			if { $intf ne $name } {
				cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit \"$intf\"\nset speed $speed\nend\n"
			}
		}
	}
}
return 1
	%}
	"system interface role" = %{
set role [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set old_role [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { $role eq $old_role } {
	return 1
}
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set cmd "config system interface\nedit $name\n"
if { $role eq "lan" } {
	append cmd "set lldp-transmission enable\n"
	append cmd "set device-identification enable\nend\n"
	if { $type ne "loopback" && $type ne "tunnel" } {
		cli_exec_cmd $CLI_GLOBAL_NODE $cmd
	}
} elseif { $role eq "wan" } {
	append cmd "set lldp-reception enable\nend\n"
	cli_exec_cmd $CLI_GLOBAL_NODE $cmd
}
return 1
	%}
	"firewall policy" = %{
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
set ippool [cli_get_value $CLI_CUR_NODE "" "" "ippool"]
set nat [cli_get_value $CLI_CUR_NODE "" "" "nat"]
set nat46 [cli_get_value $CLI_CUR_NODE "" "" "nat46"]
set hascmd 0
set cmd ""
if { $action eq "deny" } {
	set hascmd 1
	append cmd "unset traffic-shaper\nunset traffic-shaper-reverse\nunset utm-status\nunset poolname\nunset poolname6\nunset ippool\n"
} else {
	set ibp [cli_get_value $CLI_CUR_NODE "" "" "identity-based"]
	set ident_from [cli_get_value $CLI_CUR_NODE "" "" "identity-from"]
	if { $ibp ne "enable" || $ident_from ne "device" } {
		if { [cli_get_value $CLI_CUR_NODE "" "" "device-detection-portal"] eq "enable" } {
			set hascmd 1
			append cmd "unset device-detection-portal\n"
		}
	}
	if { ($nat eq "disable" && $nat46 eq "disable") || $ippool eq "disable"} {
		set hascmd 1
		append cmd "unset poolname\nunset poolname6\nunset ippool\n"
	}
}
if { $action ne "ipsec" && [cli_get_value $CLI_CUR_NODE "" "" "vpntunnel"] ne "" } {
	set hascmd 1
	append cmd "unset vpntunnel\n"
}
if { $hascmd } {
	cli_exec_cmd $CLI_CUR_NODE $cmd
}
return 1
	%}
	"system vdom-property {session ipsec-phase1 ipsec-phase2 ipsec-phase1-interface ipsec-phase2-interface dialup-tunnel firewall-policy firewall-address firewall-addrgrp custom-service service-group onetime-schedule recurring-schedule user user-group sslvpn proxy log-disk-quota}" = %{
set v [cli_get_value $CLI_CUR_NODE "" "" ""]
set len [llength [split $v " "]]
if { $len eq 1 } {
	set vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	cli_exec_cmd $CLI_GLOBAL_NODE "config system vdom-property\nedit $vdom\nset $CLI_CUR_NODE_NAME $v 0\nnext\nend\n"
}
return 1
	%}
	"log disk setting" = %{
set status [cli_get_value $CLI_CUR_PARENT_NODE "" "" "status"]
if { $status eq "disable" } {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config report setting\nset status disable\nend\n"
}
return 1
	%}
	"system geoip-override" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" "country-id"] eq "" } {
	set id [cli_gen_geoip_country_id]
	if { $id ne 0 } {
		set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
		cli_exec_cmd $CLI_GLOBAL_NODE "config system geoip-override\nedit $name\nset country-id $id\nnext\nend\n"
	}
}
return 1
	%}
	"firewall policy passive-wan-health-measurement" = %{
set measurement [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $measurement eq "enable" } {
	if { [cli_obj_support "firewall policy" "auto-asic-offload"] } {
		cli_set_value $CLI_CUR_PARENT_NODE "" "" "auto-asic-offload" "disable"
	}
}

return 1
        %}
	"certificate {local crl ca remote}" = %{
if { [string match "*override*" [cli_get_clisrc]] } {
	## let override pass as this is handled by handler
	return 1
}
if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set cname "vpn $CLI_CUR_NODE_NAME"
	set cmd [cli_export_node_attrs $CLI_CUR_NODE]
	set vdoms [cli_get_tbl_list $CLI_GLOBAL_NODE "system vdom-property"]
	foreach vd $vdoms {
		set vdname [cli_get_value $vd "" "" "name"]
		set vnode [cli_get_vdom_node $vdname]
		cli_exec_cmd $vnode "config $cname\nedit \"$name\"\n$cmd\nend\n"
	}
}
return 1
	%}
	"system vxlan" = %{
if { $CLI_ACT eq "add" } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set phy_devname [cli_get_value $CLI_CUR_NODE "" "" "interface"]
	if { $name ne "" && $phy_devname ne "" } {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $name\nset vdom $CLI_CUR_VDOM_NAME\nset type vxlan\nset interface $phy_devname\nnext\nend\n"
		if { [cli_obj_support "system interface" "snmp-index"] } {
			namespace import global::auto_set_snmp_index
			auto_set_snmp_index $name
		}
	}
}
return 1
	%}
	"system interface ipv6 ip6-extra-addr" = %{
set old_prefix [cli_get_value $CLI_CUR_NODE "" "" "prefix"]
if { [regexp {^::\d+\.\d+\.\d+\.\d+} $old_prefix] } {
	## since v6.2.1, FOS force convert "::192.168.141.165/120" to "::c0a8:8da5/120"
	set subs [regexp -inline -all {\d+} $old_prefix]
	set mask 128
	if { [llength $subs] == 5 } {
		set mask [lindex $subs 4]
	}
	set hex0 [format %x [lindex $subs 0]]
	set hex1 [format %02x [lindex $subs 1]]
	set hex2 [format %x [lindex $subs 2]]
	set hex3 [format %02x [lindex $subs 3]]
	set new_prefix "::$hex0$hex1:$hex2$hex3/$mask"
	cli_set_value $CLI_CUR_NODE "" "" "prefix" $new_prefix
}
return 1
	%}
	"switch-controller managed-switch ports access-mode" = %{
set mode [cli_get_value $cli_cur_node "" "" ""]
if { $mode eq "nac" } {
	set fsw [cli_get_parent [cli_get_parent $cli_cur_parent_node]]
	set flink [cli_get_value $fsw "" "" "fsw-wan1-peer" ]
	if { $flink eq "" } {
		set flink [cli_get_value $fsw "" "" "fsw-wan2-peer" ]
	}
	if { $flink eq "" } {
		cli_set_errmsg "invalid fortilink interface."
		return 0
	}
	set flset [cli_get_node $cli_cur_vdom_node "switch-controller fortilink-settings" $flink ""]
	if { $flset ne 0 } {
		set nacset [cli_get_node $flset "nac-ports" "" ""]
		if { $nacset ne 0 } {
			set vlan [cli_get_value $nacset "" "" "onboarding-vlan"]
			cli_set_value $cli_cur_parent_node "" "" "vlan" $vlan
			set nacintf [cli_get_value $nacset "" "" "nac-lan-interface"]
			set avlans [cli_get_value $cli_cur_parent_node "" "" "allowed-vlans"]
			set cmd "set allowed-vlans "
			foreach avlan $avlans {
				if { $avlan ne "" && $avlan ne $nacintf } {
					append cmd "\"$avlan\""
				}
			}
			append cmd "$nacintf\n"
			cli_exec_cmd $cli_cur_parent_node $cmd

			set uvlans [cli_get_value $cli_cur_parent_node "" "" "untagged-vlans"]
			set cmd "set untagged-vlans "
			foreach uvlan $uvlans {
				if { $uvlan ne "" && $uvlan ne $nacintf } {
					append cmd "\"$uvlan\""
				}
			}
			append cmd "$nacintf\n"
			cli_exec_cmd $cli_cur_parent_node $cmd
		}

		if { [string match "*gui*" [cli_get_clisrc]] } {
			## GUI should handle the logic of setting up correct parameter for nac mode
			return 1
		}

		cli_set_value $cli_cur_parent_node "" "" "loop-guard" "disable"
		cli_set_value $cli_cur_parent_node "" "" "lldp-status" "tx-rx"
		cli_set_value $cli_cur_parent_node "" "" "sample-direction" "both"
		cli_set_value $cli_cur_parent_node "" "" "sflow-counter-interval" "0"
		cli_set_value $cli_cur_parent_node "" "" "packet-sampler" "disable"
		cli_set_value $cli_cur_parent_node "" "" "edge-port" "enable"
		cli_set_value $cli_cur_parent_node "" "" "stp-bpdu-guard" "disable"
		cli_set_value $cli_cur_parent_node "" "" "stp-root-guard" "disable"
		cli_set_value $cli_cur_parent_node "" "" "stp-state" "enable"
		cli_set_value $cli_cur_parent_node "" "" "speed" "auto"
		cli_set_value $cli_cur_parent_node "" "" "port-security-policy" ""
		cli_set_value $cli_cur_parent_node "" "" "ptp-policy" "default"
		cli_set_value $cli_cur_parent_node "" "" "qos-policy" "default"
		cli_set_value $cli_cur_parent_node "" "" "lldp-profile" "default-auto-isl"
		cli_set_value $cli_cur_parent_node "" "" "discard-mode" "none"
		cli_set_value $cli_cur_parent_node "" "" "allowed-vlans-all" "disable"
		cli_set_value $cli_cur_parent_node "" "" "storm-control-policy" ""
	}
}
return 1
	%}
	"switch-controller fortilink-settings nac-ports" = %{
set nacname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set intflist [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
foreach intf $intflist {
	set intfnac [string trim [cli_get_value $intf "" "" "switch-controller-nac"] \"]
	set flink [cli_get_value $intf "" "" "name"]
	set status [cli_get_value $intf "" "" "fortilink"]
	if { $status ne "enable" || $intfnac ne $nacname } {
		continue
	}
	set vlan [cli_get_value $CLI_CUR_NODE "" "" "onboarding-vlan"]
	set swlist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "switch-controller managed-switch"]
	foreach sw $swlist {
		set wan1 [string trim [cli_get_value $sw "" "" "fsw-wan1-peer"] \"]
		set wan2 [string trim [cli_get_value $sw "" "" "fsw-wan2-peer"] \"]
		if { $wan1 ne $flink && $wan2 ne $flink} {
			continue
		}

		set portlist [cli_get_tbl_list $sw "ports"]
		foreach port $portlist {
			set access [cli_get_value $port "" "" "access-mode"]
			if { $access eq "nac" } {
				cli_set_value $port "" "" "vlan" $vlan
			}
		}
	}
}
return 1
	%}
	"system interface switch-controller-nac" = %{
set nac [cli_get_value $CLI_CUR_NODE "" "" ""]
set flink [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vdom"]
set vnode [cli_get_vdom_node $vdom]
if { $nac eq 0 || $nac eq "" } {
	set swlist [cli_get_tbl_list $vnode "switch-controller managed-switch"]
	foreach sw $swlist {
		set wan1 [string trim [cli_get_value $sw "" "" "fsw-wan1-peer"] \"]
		set wan2 [string trim [cli_get_value $sw "" "" "fsw-wan2-peer"] \"]
		if { $wan1 ne $flink && $wan2 ne $flink } {
			continue
		}

		set portlist [cli_get_tbl_list $sw "ports"]
		foreach port $portlist {
			set access [cli_get_value $port "" "" "access-mode"]
			if { $access eq "nac" } {
				cli_set_value $port "" "" "access-mode" "static"
			}
		}
	}
}
return 1
	%}
	"vpn ssl web portal" = %{
if { $CLI_ACT eq "add" } {
	set objs [list "windows-2000" "windows-7" "windows-8" "windows-8.1" "windows-10" "os-x-mavericks-10.9" "os-x-yosemite-10.10" "os-x-el-capitan-10.11" "macos-sierra-10.12" "macos-high-sierra-10.13" "macos-mojave-10.14" "macos-catalina-10.15"]
	set cmd ""
	foreach name $objs {
		append cmd "config os-check-list \"$name\"\nend\n"
	}
	cli_exec_cmd $CLI_CUR_NODE $cmd
}
return 1
	%}
	"authentication scheme domain-controller" = %{
set cur [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $cur ne 0 && $cur ne "" } {
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "fsso-agent-for-ntlm"
}
return 1
	%}
	"authentication scheme fsso-agent-for-ntlm" = %{
set cur [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $cur ne 0 && $cur ne "" } {
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "domain-controller"
}
return 1
	%}
	"system virtual-switch port" = %{
if {$CLI_ACT eq "add"} {
	set name [cli_get_value $CLI_CUR_NODE "" "" ""]
	set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
	if { $intfnode } {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $name\nunset ip\nnext\nend\n"
	}
}
return 1
	%}
%};
