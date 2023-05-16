nodeact %{
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
%};
