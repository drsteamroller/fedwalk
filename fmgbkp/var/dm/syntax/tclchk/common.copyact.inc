copyact %{
        "antivirus profile" = %{
if { [cli_ver_start 500 4] } {
	namespace import global::inspection_mode_vdom_flow
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set im [cli_get_value $CLI_CUR_NODE "" "" "inspection-mode"]
	if { [inspection_mode_vdom_flow] } {
		if { $im ne "flow-based" } {
			set cmd "config antivirus profile\nedit \"$name\"\nset inspection-mode flow-based\nnext\nend\n"
			cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		}
	}
}
return 1
        %}
        "webfilter profile" = %{
if { [cli_ver_start 400 3] } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set wos [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "webfilter override" "old-profile" 0 "\"$name\""]
	foreach wo $wos {
		set n [cli_get_value $wo "" "" "new-profile"]
		if { [cli_switch] } {
			set node [cli_get_node $CLI_SRC_VDOM_NODE "webfilter profile" $n ""]
			if { $node && [cli_copy_src_node $node] } {
				cli_set_errmsg "copy source webfilter profile $n failed."
				return 0
			}
			cli_switch_end
		}
	}
}
if { [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
	namespace import global::inspection_mode_vdom_flow
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set im [cli_get_value $CLI_CUR_NODE "" "" "inspection-mode"]
	if { [inspection_mode_vdom_flow] } {
		if { $im ne "flow-based" } {
			set cmd "config webfilter profile\nedit \"$name\"\nset inspection-mode flow-based\nnext\nend\n"
			cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		}
	}
}
return 1
        %}
	"firewall policy6" = %{
if { [cli_ver_start 500 2] } {
	namespace import global::is_sslvpn_intf
	set intf [cli_get_value $CLI_CUR_NODE "" "" "srcintf"]
	set intf [string trim $intf \"]
	if { ![cli_has_feature "f_sslvpn"] } {
	} elseif { [is_sslvpn_intf $intf] } {
		set p [cli_get_value $CLI_CUR_VDOM_NODE "vpn ssl settings" "" "default-portal"]
		if { $p ne "" && [cli_switch] } {
			set node [cli_get_node $CLI_SRC_VDOM_NODE "vpn ssl web portal" $p ""]
			if { $node && [cli_copy_src_node $node] } {
				cli_set_errmsg "copy source vpn ssl web portal $p failed."
				return 0
			}
			cli_switch_end
		}
	}
}
if { [cli_ver_start 500 2] } {
} elseif { [cli_ver_start 500 0] } {
	set rsso [cli_get_value $CLI_CUR_NODE "" "" "rsso"]
	if { $rsso ne "enable" } {
	} elseif { 0 && [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "user radius" "rsso" 0 "enable"] } {
	} elseif { [cli_switch] } {
		set urs [cli_get_match_list $CLI_SRC_VDOM_NODE 1 "user radius" "rsso" 0 "enable"]
		if { [llength $urs] <= 0 } {
			set id [cli_get_value $CLI_CUR_NODE "" "" "policyid"]
			set e "$CLI_CUR_NODE_NAME with rsso enabled (policyid: $id)"
			append e " need one user radius entry with rsso enabled"
			cli_set_errmsg $e
			return 0
		}
# The RSSO agent will be copied by C code!
#		if { [cli_copy_src_node [lindex $urs 0]] } {
#			set un [cli_get_value [lindex $urs 0] "" "" "name"]
#			cli_set_errmsg "copy source user radius $un failed."
#			return 0
#		}
		cli_switch_end
	}
}
return 1
        %}
	"firewall explicit-proxy-policy" = %{
if { [cli_ver_start 500 2] } {
	set authmethod [cli_get_value $CLI_CUR_NODE "" "" "sso-auth-method"]
	if { $authmethod ne "rsso" } {
	} elseif { [cli_switch] } {
		set urs [cli_get_match_list $CLI_SRC_VDOM_NODE 1 "user radius" "rsso" 0 "enable"]
		if { [llength $urs] <= 0 } {
			set id [cli_get_value $CLI_CUR_NODE "" "" "policyid"]
			set e "$CLI_CUR_NODE_NAME with rsso enabled (policyid: $id)"
			append e " need one user radius entry with rsso enabled"
			cli_set_errmsg $e
			return 0
		}
		if { [cli_copy_src_node [lindex $urs 0]] } {
			set un [cli_get_value [lindex $urs 0] "" "" "name"]
			cli_set_errmsg "copy source user radius $un failed."
			return 0
		}
		cli_switch_end
	}
}
return 1
        %}
%};
