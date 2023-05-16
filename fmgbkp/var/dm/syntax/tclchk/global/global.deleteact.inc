deleteact %{
	"vpnmgr vpntable" = %{
set topology [cli_get_value $CLI_CUR_NODE "" "" "topology"]
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set intfname "vpnmgr_"
append intfname $name
foreach e {"_mesh" "_hub2spoke" "_spoke2hub"} {
    set intfnode [cli_get_node $CLI_CUR_VDOM_NODE "dynamic interface" ${intfname}${e} ""]
    if {($intfnode != 0) && ([cli_is_referenced $intfnode] != 0)} {
        cli_set_errmsg "VPN is being used"
        return 0
    }
}
set cmd "config dynamic interface\ndelete \"vpnmgr_${name}_mesh\"\nend\nconfig dynamic interface\ndelete \"vpnmgr_${name}_hub2spoke\"\nend\nconfig dynamic interface\ndelete \"vpnmgr_${name}_spoke2hub\"\nend\n"
cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
return 1
	%}

	"certificate template" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set dyn [cli_get_node $CLI_CUR_VDOM_NODE "dynamic certificate local" $name ""]
cli_delete_node $dyn
return 1
	%}

	"user nsx" = %{
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
set service [cli_get_value $CLI_CUR_NODE "" "" "service-id"]
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $status eq "enable" } {
	cli_set_errmsg "user nsx $name cannot be deleted when status is on"
	return 0
}
if { [llength $service] > 0 } {
	cli_set_errmsg "user nsx $name cannot be deleted before deleting all its services"
	return 0
}
return 1
	%}

	"wireless-controller vap" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set dynode [cli_get_node $CLI_CUR_VDOM_NODE "dynamic interface" $name ""]
if { $dynode && [cli_is_referenced $dynode] } {
	set msg "ssid $name is used"
	set rlist [cli_get_ref_list $dynode ]
	foreach ref $rlist {
		set node [cli_get_parent  $ref]
		set refname [cli_get_value $node "" "" "name"]
		append msg " by $refname"
		break
	}
	cli_set_errmsg "$msg, cannot be deleted"
	return 0
}

set svr_id [cli_get_value $CLI_CUR_NODE "" "" "_dhcp_svr_id"]
if { $svr_id ne "" } {
	set svr_id [string trim $svr_id \"]
	set node [cli_get_node $CLI_CUR_VDOM_NODE "system dhcp server" $svr_id ""] 
	if { $node } {
		cli_set_value $CLI_CUR_NODE "" "" "_dhcp_svr_id" ""
		if { $node && ![cli_is_referenced $node] } { cli_delete_node $node }
	}
}
return 1
	%}

	"wireless-controller wtp-group" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set nodes [cli_get_tbl_list $CLI_CUR_VDOM_NODE "wireless-controller vap"]
foreach e $nodes {
	set pool [cli_get_value $e "" "" "vlan-pooling"]
	if { $pool ne "wtp-group" } {
		continue;
	}
	set vapname [cli_get_value $e "" "" "name"]
	set childnodes [cli_get_tbl_list $e "vlan-pool"]
	foreach ee $childnodes {
		set grp [cli_get_value $ee "" "" "_wtp-group"]
		if { $grp ne "" } {
			set nlist [split $grp "\n"]
			set name2 [lindex $nlist 2]
			if { $name eq $name2 } {
				set idx [cli_get_value $ee "" "" "id"]
        			cli_set_errmsg "The wtp-group is being used by wireless-controller.vap \"$vapname\" vlan-pool.$idx"
				return 0
			}
		}
	}
}
return 1
	%}
	"switch-controller managed-switch ports" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $type eq "trunk" } {
	set swnode [cli_get_parent $CLI_CUR_PARENT_NODE]
	set swname [cli_get_value $swnode "" "" ""]
	set cmd ""
	set ports [cli_get_value $CLI_CUR_NODE "" "" "members"]

	if {[cli_ver_start 600 4]} {
		set defport "default"
	} else {
		set defport "default.vswport"
	}

	foreach port $ports {
		set portnode [cli_get_node $CLI_CUR_PARENT_NODE "" $port ""]
		if { $portnode ne 0 } {
			append cmd "edit $port\nunset port-owner\nset vlan \"$defport\"\nset qos-policy default\nnext\n"
		}
	}
	if { $cmd ne "" } {
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config switch-controller managed-switch\nedit $swname\nconfig ports\n$cmd\nend\nend\n"
	}
}
return 1
	%}

	"fsp vlan" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set dynode [cli_get_node $CLI_CUR_VDOM_NODE "dynamic interface" $name ""]
if { $dynode && [cli_is_referenced $dynode] } {
	cli_set_errmsg "Cannot delete FortiSwitch VLAN $name - mirror normalized interface $name is being used by policy package or objects."
	return 0
}

set cmd "config dynamic interface\ndelete \"$name\"\nend\n"
cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
return 1
	%}
%};
