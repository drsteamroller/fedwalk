deleteact %{
	"ips custom" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""] 
set customnode [cli_get_node $CLI_GLOBAL_NODE "ips group" "custom" ""]
set delnode [cli_get_node $customnode "" "rule" $name]
expr [cli_delete_node $delnode]
return 1
	%}

	"vpn ssl web bookmarks" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$name ne ""} {
	set match_list [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "vpn ssl web bookmarks-group" "bookmarks" 0 '*"$name"*']
	foreach e $match_list {
		set bookmarks [cli_get_value $e "" "" "bookmarks"]
		regsub "\"$name\"" $bookmarks {} bookmarks
		set grpname [cli_get_value $e "" "" "name"]
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn ssl web bookmarks-group\nedit $grpname\nset bookmarks $bookmarks\nend\n"
	}
}
return 1
	%}

	"system {gre-tunnel pppoe-interface geneve}" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
if {[cli_is_referenced $intfnode]} {
	cli_set_errmsg "interface is being used"
	return 0
}
if {$intfnode} {
	cli_delete_node $intfnode
}
return 1
	%}

	"system switch-interface" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
if { $intfnode } {
	if { [cli_is_match $intfnode 0 "" "type" 1 "switch"] } {
		cli_set_errmsg "no entry found in system interface"
		return 0
	}
	if {[cli_is_referenced $intfnode]} {
		cli_set_errmsg "interface $name is in use, cannot remove"
		return 0
	}
	cli_delete_node $intfnode
}
return 1
	%}
        "system virtual-switch port" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
if { $intfnode == 0 } {
	cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $name\nset type physical\nset vdom root\nnext\nend\n"
	if {[cli_obj_support "system interface" "snmp-index"]} {
		namespace import global::auto_set_snmp_index
		auto_set_snmp_index $name
	}
}
return 1
        %}

	"system vdom-link" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set nodelist {}
foreach e {"0" "1"} {
	set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" ${name}${e} ""]
	if {[cli_is_referenced $intfnode]} {
		cli_set_errmsg "used"
		return 0
	}
	lappend nodelist $intfnode
}
foreach e $nodelist {
	cli_delete_node $e
}
return 1
	%}

	"system ipv6-tunnel" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
if {[cli_is_referenced $intfnode]} {
	cli_set_errmsg "interface $name is being used"
	return 0
}
if {$intfnode} {
	cli_delete_node $intfnode
}
return 1
	%}

	"firewall policy6 srcintf" = %{
cli_exec_cmd $CLI_CUR_PARENT_NODE "unset action\n"
return 1
	%}
	"firewall policy6 dstintf" = %{
cli_exec_cmd $CLI_CUR_PARENT_NODE "unset action\n"
return 1
	%}

	"router multicast route-limit" = %{
set threshold [cli_get_value $CLI_CUR_PARENT_NODE "" "" "route-threshold"]
if {$threshold eq ""} {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config router multicast\nset route-threshold 2147483647\nend\n"
}
return 1
	%}

	"router multicast interface" = %{
set hascmd 0
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set holdtime [cli_get_value $CLI_CUR_NODE "" "" "hello-holdtime"]
set interval [cli_get_value $CLI_CUR_NODE "" "" "hello-interval"]
set cmd "config interface\nedit $name\n"
if {$holdtime eq ""} {
	set hold [expr int(30 * 3.5)]
	set hascmd 1
	append cmd "set hello-holdtime $hold\n"
}
if {$interval ne ""} {
	set hold [expr int($interval * 3.5)]
	if {$hold > 65535} {set hold 65535}
	set hascmd 1
	append cmd "set hello-holdtime $hold\n"
}
if {$hascmd} {
	append cmd "end\n"
	set node [cli_get_parent $CLI_CUR_PARENT_NODE]
	set node [cli_get_parent $node]
	cli_exec_cmd $node $cmd
}
return 1
	%}

	"wireless-controller vap vlan-pool" = %{
set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
set vapnode [cli_get_parent $CLI_CUR_PARENT_NODE]
set name [cli_get_value $vapnode "" "" "name"]
set vlan_name "$name.$id"
set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $vlan_name ""]
if {$intfnode} {
	if {[cli_is_referenced $intfnode] && [cli_is_used $intfnode "system zone" "interface"]} {
		set rlist [cli_get_ref_list $intfnode ]
		foreach ref $rlist {
			if { "system zone" eq [cli_get_node_name $ref] } {
				set zone [cli_get_value $ref "" "" "name"]
				set cmd "config system zone\nedit $zone\nunselect interface $vlan_name\nend\n"
				cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
			}
		}
	}
	cli_delete_node $intfnode
}
return 1
	%}

	"wireless-controller vap" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
if {$intfnode} {
	namespace import global::cli_is_quarantine_vap
	if { [cli_ver_start 600 2] } {
		set vapvdom [cli_get_value $intfnode "" "" "vdom"]
	} else {
		set vapvdom [cli_get_value $CLI_CUR_NODE "" "" "vdom"]
	}
	if { [cli_is_quarantine_vap $CLI_CUR_NODE $vapvdom] } {
		set cnt 0
		set path ""
		if {[cli_is_referenced $intfnode]} {
			set rlist [cli_get_ref_list $intfnode ]
			set cnt [llength $rlist]
			if { $cnt == 1 } {
				foreach ref $rlist {
					set path [cli_get_node_name $ref]
					break
				}
			}
		}
		if { $cnt > 1 || ($cnt == 1 && $path ne "" && $path ne "system interface") } {
			cli_set_errmsg "vap-switch interface \"$name\" is being used"
			return 0
		}
		namespace import global::cli_del_quarantine_intf
		cli_del_quarantine_intf $name $vapvdom
	}
	cli_delete_node $intfnode
}
return 1
	%}
	"certificate template" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set dyn_cert [cli_get_node $CLI_GLOBAL_NODE "dynamic certificate local" $name ""]
if { $dyn_cert } {
	cli_delete_node $dyn_cert
}
return 1
	%}
	"switch-controller managed-switch ports" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $type eq "trunk" } {
	set swnode [cli_get_parent $CLI_CUR_PARENT_NODE]
	set swname [cli_get_value $swnode "" "" ""]
	set cmd ""
	set defport ""

	set fortilink [cli_get_value $swnode "" "" "fsw-wan1-peer"]
	if { $fortilink eq 0 || $fortilink eq "" } {
		set fortilink [cli_get_value $swnode "" "" "fsw-wan2-peer"]
	}
	set fortilink [string trim $fortilink \"]

	if {[cli_ver_start 600 4]} {
		set intflist [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
		foreach intf $intflist {
			set parent [string trim [cli_get_value $intf "" "" "interface"] \"]
			set feature [cli_get_value $intf "" "" "switch-controller-feature"]
			if { $parent eq $fortilink && $feature eq "default-vlan" } {
				set defport [cli_get_value $intf "" "" "name"]
				break
			}
		}
		if { $defport eq "" } {
			set defport "default"
		}
	} else {
		set defport "vsw.$fortilink"
	}

	set ports [cli_get_value $CLI_CUR_NODE "" "" "members"]
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
%};
