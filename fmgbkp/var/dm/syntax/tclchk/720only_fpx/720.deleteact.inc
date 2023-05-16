deleteact %{
	"system vdom" = %{
set fullname [cli_get_value $CLI_CUR_NODE "" "" ""]
set findex [string first "/" $fullname]
if { $findex > 0 } {
	set vdname [string range $fullname 0 $findex-1 ]
} else {
	set vdname $fullname
}
set found 0
set vnew ""
set hanode [cli_get_node $CLI_GLOBAL_NODE "system ha" "" ""]
set vdoms [cli_get_value $hanode "" "" "vdom"]
foreach v $vdoms {
	if { $v != $vdname } {
		append vnew " "
		append vnew $v
	} else {
		set found 1
	}
}
if { $found == 0 } {
	set vnew ""
	set vdoms [cli_get_value $hanode "secondary-vcluster" "" "vdom"]
	foreach v $vdoms {
		if { $v != $vdname } {
			append vnew " "
			append vnew $v
		} else {
			set found 2
		}
	}
}
if { $found } {
	set cmd "config system ha\n"
	if { $found == 1 } {
		if { $vnew == "" } {
			append cmd "unset vdom\n"
		} else {
			append cmd "set vdom $vnew\n"
		}
	} else {
		if { $vnew == "" } {
			append cmd "config secondary-vcluster\nunset vdom\nend\n"
		} else {
			append cmd "config secondary-vcluster\nset vdom $vnew\nend\n"
		}
	}
	append cmd "end\n"
	cli_exec_cmd $CLI_GLOBAL_NODE $cmd
}
proc remove_intf_node { intfname } {
	global CLI_GLOBAL_NODE
	set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $intfname ""]
	if { [cli_is_referenced $intfnode] } {
		cli_delete_node $intfnode 1
		if { [cli_is_referenced $intfnode] } {
			cli_set_errmsg "interface $intfname is used"
			return 0
		}
	}
	cli_delete_node $intfnode
}
namespace import global::remove_auto_created_vdom_objs
if { [remove_auto_created_vdom_objs] } {
	cli_set_errmsg "delete vdom $vdname referenced object error"
	return 0
}
namespace import global::get_mux_tunnel_dev_name
set intfname [get_mux_tunnel_dev_name $fullname]
remove_intf_node $intfname
remove_intf_node [string map {ssl. naf.} $intfname]

if { [cli_has_feature "f_netx"] } {
	namespace import global::get_shadow_intf_name
	remove_intf_node [get_shadow_intf_name "" $vdname "-int"]
	remove_intf_node [get_shadow_intf_name "" $vdname "-ext"]
}
set vdomproperty [cli_get_node $CLI_GLOBAL_NODE "system vdom-property" $vdname ""]
cli_delete_node $vdomproperty

namespace import global::remove_sys_admin_gui_dashboard
remove_sys_admin_gui_dashboard $vdname
return 1
	%}
	"user fsso-polling" = %{
set fsso [cli_get_node $CLI_CUR_VDOM_NODE "user fsso" "Local FSSO Agent" ""]
if { $fsso != 0 } {
	set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
	if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "id" 1 $id] == 0 } {
		set list [cli_get_tbl_list $CLI_CUR_PARENT_NODE "user adgrp"]
		foreach node $list {
			set svrname [cli_get_value $node "" "" "server-name"]
			set svrname [string trim $svrname \"]
			if { $svrname eq "Local FSSO Agent" } {
				cli_delete_node $node 1
			}
		}
	}
}
return 1
# disable this block of code due to potential bug on FOS
set fsso [cli_get_node $CLI_CUR_VDOM_NODE "user fsso" "Local FSSO Agent" ""]
if { $fsso != 0 } {
	set fssoldap [cli_get_value $fsso "" "" "ldap-server"]
	set curldap [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]
	set curid [cli_get_value $CLI_CUR_NODE "" "" "id"]
	set curstatus [cli_get_value $CLI_CUR_NODE "" "" "status"]
	# filter out the node being deleted
	if { $curstatus eq "enable" } {
		set num 1
	} else {
		set num 0
	}
	# check if there's still active fsso-polling object
	if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "status" 0 "enable"] == $num } {
		cli_delete_node $fsso
	} elseif { $curldap eq $fssoldap } {
		# select another node for the new new local fsso agent
		set list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
		foreach node $list {
			set status [cli_get_value $node "" "" "status"]
			set server [cli_get_value $node "" "" "ldap-server"]
			set id [cli_get_value $node "" "" "id"]
			if { $server == 0 || $curid == $id || $status ne "enable" } {
				continue
			}
			cli_exec_cmd $CLI_CUR_VDOM_NODE "config user fsso\nedit \"Local FSSO Agent\"\nset ldap-server $server\nset server \"127.0.0.1\"\nnext\nend\n"
			break
		}
	}
}
return 1
	%}
	"system interface" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set dev_intfnode [cli_get_node $CLI_CUR_VDOM_NODE "device dynamic interface" $name ""]
if { $dev_intfnode } {
	cli_delete_node $dev_intfnode
}
return 1
	%}
	"certificate {local crl ca}" = %{
if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set cname "vpn $CLI_CUR_NODE_NAME"
	set vdoms [cli_get_tbl_list $CLI_GLOBAL_NODE "system vdom-property"]
	foreach vd $vdoms {
		set vdname [cli_get_value $vd "" "" "name"]
		set vnode [cli_get_vdom_node $vdname]
		cli_exec_cmd $vnode "config $cname\ndelete \"$name\"\nend\n"
	}
}
return 1
	%}
	"system vxlan" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
if { $intfnode } {
	if { [cli_is_referenced $intfnode] } {
		cli_set_errmsg "system interface $name is being used"
		return 0
	}
	cli_delete_node $intfnode
}
return 1
	%}
%};
