deletecheck %{
	"log npu-server server-info" = %{
set server_group_sz [cli_get_tbl_size "log npu-server server-group"]
if { $server_group_sz > 0 } {
	cli_set_errmsg "There are server_group, maybe refer to this server, so first delete the all server_group then can delete the server_info."
	return 0
}
return 1
	%}
	"system vdom" = %{
set fullname [cli_get_value $CLI_CUR_NODE "" "" ""]
set findex [string first "/" $fullname]
if { $findex > 0 } {
	set name [string range $fullname 0 $findex-1 ]
} else {
	set name $fullname
}
if { ![cli_ver_start 700 2] } {
namespace import global::cli_sys_global_split_vdom
if { [cli_sys_global_split_vdom] } {
	cli_set_errmsg "Can not delete reserved vdom $name in split-vdom mode."
	return 0
}
}
if {$name eq "dmgmt-vdom"} {
	namespace import global::dmgmt_vdom_support
	set dmgmt [dmgmt_vdom_support]
	if { $dmgmt } {
		cli_set_errmsg "'dmgmt-vdom' is reserved and cannot be deleted"
		return 0
	}
}
set hanode [cli_get_node $CLI_GLOBAL_NODE "system ha" "" ""]
set vdoms [cli_get_value $hanode "secondary-vcluster" "" "vdom"]
foreach m $vdoms {
	if {$name eq $m} {
		cli_set_errmsg "Vdom is used in secondary-vcluster and cannot be deleted"
		return 0
	}
}
return 1
	%}
	"system accprofile" = %{
set profilename [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $profilename eq "FGT_ha_acc_profile" } {
	cli_set_errmsg "used by system, cannot be deleted"
	return 0
}
return 1
	%}
	"system gre-tunnel remote-gw" = %{
cli_set_errmsg "cannot delete remote gateway in gre-tunnel"
return 0
	%}
	"system gre-tunnel local-gw" = %{
cli_set_errmsg "cannot delete local gateway in gre-tunnel"
return 0
	%}
	"system interface" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set name [string trim $name \"]
set vdom [cli_get_value $CLI_CUR_NODE "" "" "vdom"]
set vdom [string trim $vdom \"]
set elbc [cli_get_node $CLI_GLOBAL_NODE "system elbc" "" ""]
set mode [cli_get_value $elbc "" "" "mode"]
if { $mode eq "service-group" && $vdom eq "elbc-mgmt" } {
    cli_set_errmsg "cannot be deleted"
    return 0
}
if { [string match "*tcl*" [cli_get_clisrc]] } {
	return 1
}
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $type eq "switch" || $type eq "physical" } {
	cli_set_errmsg "\"$type\" type interface cannot be (directly) deleted"
	return 0
} elseif { $type eq "tunnel" } {
	set vdnode [cli_get_vdom_node $vdom]
	set phintf [cli_get_node $vdnode "vpn ipsec phase1-interface" $name ""]
	if { [cli_is_match $phintf 0 "" "aggregate-member" 0 "disable"] } {
		cli_set_errmsg "\"$type\" type interface cannot be (directly) deleted"
		return 0
	}
} elseif { $type eq "geneve" } {
        set vdnode [cli_get_vdom_node $vdom]
        set gintf [cli_get_node $vdnode "system geneve" $name ""]
        if { $gintf != 0 } {
                cli_set_errmsg "\"$type\" type interface cannot be (directly) deleted"
                return 0
        }
} elseif { $type eq "fctrl-trunk" } {
	cli_set_errmsg "fctrl-trunk type interface can not be manually deleted"
	return 0
} elseif { $type eq "wl-mesh" } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	if { $name eq "wl.mesh" } {
		cli_set_errmsg "Can not delete a static table entry"
		return 0
	}
}
return 1
	%}
	"firewall ldb-monitor type" = %{
cli_set_errmsg "empty value"
return 0
	%}
        "user fsso" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
#  set serv [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]
#  if { $name eq "Local FSSO Agent" } {
#          set fssopoll [cli_get_node $CLI_CUR_VDOM_NODE "user fsso-polling" "" ""]
#  
#          # due to potential bug on FOS, disable check and set it to read-only for now
#          cli_set_errmsg "Cannot delete: read only"
#          return 0
#  
#          if { [cli_get_match_nr $fssopoll 1 "" "status" 0 "enable"] > 0 &&
#               [cli_get_match_nr $fssopoll 1 "" "ldap-server" 0 $serv] > 0 } {
#                  cli_set_errmsg "Cannot delete: in use by a pull active directory server"
#                  return 0
#          }
#  }

set nodelist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "user adgrp"]
foreach node $nodelist {
        set server_name [cli_get_value $node "" "" "server-name"]
        if { $name ne $server_name } {
                continue
        }
        set adgrp [cli_get_value $node "" "" "name"]
        set uglist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "user group"]
        foreach ug $uglist {
                set member [cli_get_value $ug "" "" "member"]
                foreach m $member {
                        if { $m eq $adgrp } {
				cli_set_errmsg "Cannot delete server: one of the Directory Service groups on this server is being referenced by an authentication group"
                                return 0
                        }
                }
        }
}
return 1
        %}
	"wireless-controller vap" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [string match -nocase "mesh.*" $name] == 1 } {
	cli_set_errmsg "cannot be deleted"
	return 0
}
return 1
	%}

	"wireless-controller wtp-group" = %{
if { [cli_ver_start 500 6] } {
	set name [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { [cli_ver_start 600 2] } {
		set nodes [cli_get_tbl_list $CLI_CUR_VDOM_NODE "wireless-controller vap"]
	} else {
		set nodes [cli_get_tbl_list $CLI_GLOBAL_NODE "wireless-controller vap"]
	}
	foreach e $nodes {
		set pool [cli_get_value $e "" "" "vlan-pooling"]
		if { $pool ne "wtp-group" } {
			continue;
		}
		set vapname [cli_get_value $e "" "" "name"]
		set childnodes [cli_get_tbl_list $e "vlan-pool"]
		foreach ee $childnodes {
			set wgrp [cli_get_value $ee "" "" "wtp-group"]
			if { $wgrp ne "" } {
				set wgrp [string trim $wgrp \"]
			}
			if { $name eq $wgrp } {
				cli_set_errmsg "wtp-group, \"$name\", is being used by wireless-controller.vap \"$vapname\" "
				return 0
			}
		}
	}
}
return 1
	%}
	"system virtual-switch port" = %{
set vsmax [cli_feature_value "vs_max_allowed"]
if { $vsmax > 0 } {
	set CONFIG_VS_MAX_ALLOWED 50
	namespace import global::num_of_vs_and_intfs
	set vsttl [num_of_vs_and_intfs $vsmax]
	if { [expr ($vsttl + 1)] > $CONFIG_VS_MAX_ALLOWED } {
		cli_set_errmsg "Exceeding the maximum number (50) of virtual switches and interfaces."
		return 0
	}
}
if { [string match "*tcl*" [cli_get_clisrc]] } {
	return 1
}
if { [cli_get_tbl_cnt $CLI_CUR_PARENT_NODE ""] < 2 } {
	set name [cli_get_value $CLI_CUR_NODE "" "" ""]
	cli_set_errmsg "Cannot delete \"$name\" as virtual switch requires >= 2 ports"
}
return 1
	%}
	"system virtual-switch" = %{
set vsmax [cli_feature_value "vs_max_allowed"]
if { $vsmax > 0 } {
	set CONFIG_VS_MAX_ALLOWED 50
	namespace import global::num_of_vs_and_intfs
	set vsttl [num_of_vs_and_intfs $vsmax]
	set ports [cli_get_tbl_cnt $CLI_CUR_NODE "port"]
	if { [expr ($vsttl - 1 + $ports)] > $CONFIG_VS_MAX_ALLOWED } {
		cli_set_errmsg "Exceeding the maximum number (50) of virtual switches and interfaces."
		return 0
	}
}
return 1
	%}
	"user radius" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set rsso [cli_get_value $CLI_CUR_NODE "" "" "rsso"]
if { $rsso eq "enable" } {
	set vdom_rad [cli_get_node $CLI_GLOBAL_NODE "system vdom-radius-server" $CLI_CUR_VDOM_NAME ""]
	if { $vdom_rad ne 0 && [cli_get_value $vdom_rad "" "" "status"] eq "enable" } {
		## allow delete
	} elseif { ([cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall policy" "rsso" 0 "enable"] > 0) ||  ([cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall policy6" "rsso" 0 "enable"] > 0) } {
		cli_set_errmsg "Can not delete \"$name\" as rsso enabled in firewall policy(6)"
		return 0
	}
}

set schemes [cli_get_tbl_list $CLI_CUR_VDOM_NODE "authentication scheme"]
foreach sch $schemes {
	set method [cli_get_value $sch "" "" "method"]
	if { ([lsearch $method "rsso"] != -1)} {
		cli_set_errmsg "The radius server cannot be deleted because it is in use by proxy authentication scheme."
		return 0
	}
}
return 1
	%}
	"router bgp neighbor-group" = %{
set g [cli_get_value $CLI_CUR_NODE "" "" "name"]
set pns [cli_get_tbl_list [cli_get_parent $CLI_CUR_NODE] "neighbor-range"]
foreach n $pns {
        set gg [cli_get_value $n "" "" "neighbor-group"]
	set gg [string trim $gg \"]
        if { $gg eq $g } {
		cli_set_errmsg "\"$g\" is in use, can not be deleted"
                return 0
        }
}
return 1
	%}
	"system {virtual-wan-link swdan} members" = %{
cli_schedule_post_check $CLI_CUR_PARENT_NODE "edit"
return 1
	%}
	"system {virtual-wan-link swdan} health-check" = %{
cli_schedule_post_check $CLI_CUR_PARENT_NODE "edit"
return 1
	%}
	"user group" = %{
set grpname [cli_get_value $CLI_CUR_NODE "" "" "name"]
set grpname [string trim $grpname \"]
if { [cli_get_match_nr $CLI_GLOBAL_NODE 1 "system admin" "remote-auth" 0 "enable" "remote-group" 0 $grpname] ||
		[cli_get_match_nr $CLI_GLOBAL_NODE 1 "system admin" "remote-auth" 0 "enable" "remote-group" 0 \"$grpname\"] } {
	cli_set_errmsg "Can not delete user group \"$grpname\" as it is used in system admin remote-group"
	return 0
}
if { [cli_ver_start 600 2] && [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "wireless-controller vap" "radius-mac-auth" 0 "enable"] > 0 } {
	namespace import global::ncfg_is_user_group_used_by_vap
	if { [ncfg_is_user_group_used_by_vap 1 $CLI_CUR_VDOM_NODE $CLI_CUR_VDOM_NAME $grpname] } {
		cli_set_errmsg "Can not delete user group \"$grpname\" as it is used in wireless-controller vap"
		return 0
	}
} elseif { [cli_ver_start 600 0] && [cli_get_match_nr $CLI_GLOBAL_NODE 1 "wireless-controller vap" "vdom" 0 "\"$CLI_CUR_VDOM_NAME\"" "radius-mac-auth" 0 "enable"] > 0 } {
	namespace import global::ncfg_is_user_group_used_by_vap
	if { [ncfg_is_user_group_used_by_vap 0 $CLI_GLOBAL_NODE $CLI_CUR_VDOM_NAME $grpname] } {
		cli_set_errmsg "Can not delete user group \"$grpname\" as it is used in wireless-controller vap"
		return 0
	}
}
return 1
	%}
	"user fortitoken" = %{
if { [string match "*adom*" [cli_get_clisrc]] } {
	cli_set_errmsg "Do not delete fortitoken during adom to device copy."
	return 0
}
return 1
	%}
	"switch-controller lldp-profile" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "fortivoice" } {
	set sysglobal [cli_get_node $CLI_GLOBAL_NODE "system global" "" ""]
	set swc [cli_get_value $sysglobal "" "" "switch-controller"]
	if { $swc eq "enable" } {
		cli_set_errmsg "Cannot delete fortivoice lldp-profile when fortivoice is enabled."
		return 0
	}
}
return 1
	%}
	"switch-controller nac-device" = %{
cli_set_errmsg "User not allowed to set this command. It should be learned through NAC policy from managed FortiSwitch"
return 0
	%}
	"switch-controller fortilink-settings" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set intf [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
if { $intf ne 0 && [cli_get_value $intf "" "" "fortilink"] eq "enable" } {
	cli_set_errmsg "$name default fortilink-settings cannot be deleted when fortilink is enabled"
	return 0
}
return 1
	%}
	"switch-controller dynamic-port-policy" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set intf [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
if { $intf ne 0 && [cli_get_value $intf "" "" "fortilink"] eq "enable" } {
	cli_set_errmsg "$name default dynamic-port-policy cannot be deleted when fortilink is enabled"
	return 0
}
return 1
	%}
%};
