deletecheck %{
	"system gre-tunnel remote-gw" = %{
cli_set_errmsg "cannot delete remote gateway in gre-tunnel"
return 0
	%}
	"system gre-tunnel local-gw" = %{
cli_set_errmsg "cannot delete local gateway in gre-tunnel"
return 0
	%}
        "user fsso" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
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
	"user group" = %{
set grpname [cli_get_value $CLI_CUR_NODE "" "" "name"]
set grpname [string trim $grpname \"]
if { [cli_get_match_nr $CLI_GLOBAL_NODE 1 "system admin" "remote-auth" 0 "enable" "remote-group" 0 $grpname] ||
		[cli_get_match_nr $CLI_GLOBAL_NODE 1 "system admin" "remote-auth" 0 "enable" "remote-group" 0 \"$grpname\"] } {
	cli_set_errmsg "Can not delete user group \"$grpname\" as it is used in system admin remote-group"
	return 0
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
%};
