deletecheck %{
	"system replacemsg-group" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "default" } {
	cli_set_errmsg "Can not delete! This special group is reserved for system use."
	return 0
}
return 1
	%}
	"certificate {local crl ca}" = %{

proc used_in_vdom { vd src name } {
	set certs [cli_get_tbl_list $vd $src]
	foreach c $certs {
		if { [cli_get_value $c "" "" "name"] eq $name } {
			if { [cli_is_used $c] } {
				return 1
			}
		}
	}
	return 0
}
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set cname "vpn $CLI_CUR_NODE_NAME"
if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
	set vdoms [cli_get_tbl_list $CLI_GLOBAL_NODE "system vdom-property"]
	foreach vd $vdoms {
		set vdname [cli_get_value $vd "" "" "name"]
		set vnode [cli_get_vdom_node $vdname]
		if { [used_in_vdom $vnode $cname $name] } {
			cli_set_errmsg "$cname $name is used in $vdname vdom, can not be deleted"
			return 0
		}
	}
} else {
	if { [used_in_vdom $CLI_CUR_VDOM_NODE $cname $name] } {
		cli_set_errmsg "$cname $name is used, can not be deleted"
		return 0
	}
}
return 1
	%}
	"vpn certificate {local crl ca}" = %{
if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
	set rg [cli_get_value $CLI_CUR_NODE "" "" "range"]
	if { $rg eq "global" } {
		set cname $CLI_CUR_NODE_NAME
		cli_set_errmsg "Can't delete global range $cname in vdom"
		return 0
	}
}
return 1
	%}
	"application custom" = %{
set signature [cli_get_value $CLI_CUR_NODE "" "" "signature"]
if { $signature == 0 } {
	return 1
}
set rule_id [cli_get_signature_rule_id $signature "--vuln_id"]
if { $rule_id >= 1000 && $rule_id <= 9999 } {
	set application_group [cli_get_tbl_list $CLI_CUR_VDOM_NODE "application group"]
	foreach e $application_group {
		set application [cli_get_value $e "" "" "application"]
		foreach ap $application {
			if { $ap == $rule_id } {
				return 0
			}
		}
	}

	set sys_sdwan [cli_get_node $CLI_CUR_VDOM_NODE "system sdwan" "" ""]
	set sys_sdwan_srv [cli_get_tbl_list $sys_sdwan "service"]
	foreach e $sys_sdwan_srv {
		set service_ctrl [cli_get_value $e "" "" "internet-service-app-ctrl"]
		foreach sc $service_ctrl {
			if { $sc == $rule_id } {
				return 0
			}
		}
	}
}
set rule_id [cli_get_signature_rule_id $signature "--attack_id"]
if { $rule_id >= 1000 && $rule_id <= 9999 } {
	set application_group [cli_get_tbl_list $CLI_CUR_VDOM_NODE "application group"]
	foreach e $application_group {
		set application [cli_get_value $e "" "" "application"]
		foreach ap $application {
			if { $ap == $rule_id } {
				return 0
			}
		}
	}
	set sys_sdwan [cli_get_node $CLI_CUR_VDOM_NODE "system sdwan" "" ""]
	set sys_sdwan_srv [cli_get_tbl_list $sys_sdwan "service"]
	foreach e $sys_sdwan_srv {
		set service_ctrl [cli_get_value $e "" "" "internet-service-app-ctrl"]
		foreach sc $service_ctrl {
			if { $sc == $rule_id } {
				return 0
			}
		}
	}
}
return 1
	%}
	"user device" = %{
if { [string match "*adom*" [cli_get_clisrc]] } {
	cli_set_errmsg "user device is no longer managed by ADOM."
	return 0
}
return 1
	%}
%};
