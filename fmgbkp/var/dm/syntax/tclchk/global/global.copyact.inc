copyact %{
	"webfilter profile" = %{
if { [cli_ver_start 400 3] } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	if { [cli_switch] } {
		set wos [cli_get_match_list $CLI_SRC_VDOM_NODE 1 "webfilter override" "old-profile" 0 "\"$name\""]
		foreach wo $wos {
			set n [cli_get_value $wo "" "" "new-profile"]
			if { [cli_copy_src_object "webfilter profile" $n] } {
				cli_set_errmsg "copy source webfilter profile $n failed."
				return 0
			}
		}
		cli_switch_end
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
		if { [cli_switch] } {
			set p [cli_get_value $CLI_SRC_VDOM_NODE "vpn ssl settings" "" "default-portal"]
			if { $p ne "" && [cli_copy_src_object "vpn ssl web portal" $p] } {
				cli_set_errmsg "copy source vpn ssl web portal $p failed."
				return 0
			}
			cli_switch_end
		}
	}
}
if { [cli_ver_start 500 2] } {
	set usrs [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "user radius" "rsso" 0 "enable"]
	if { [llength $usrs] > 0 } {
	} else {
		set rssogrp 0
		set groups [cli_get_value $CLI_CUR_NODE "" "" "groups"]
		foreach grp $groups {
			if { [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "user group" "name" 0 $grp "group-type" 0 "rsso"] } {
				set rssogrp 1
				break
			}
		}

		if { $rssogrp == 1 && [cli_switch]} {
			set usrs [cli_get_match_list $CLI_SRC_VDOM_NODE 1 "user radius" "rsso" 0 "enable"]
			if { [llength $usrs] > 0 && [cli_copy_src_node [lindex $usrs 0]] } {
				set un [cli_get_value [lindex $usrs 0] "" "" "name"]
				cli_set_errmsg "copy source user radius $un failed."
				return 0
			}
			cli_switch_end
		}
	}

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
	"firewall policy" = %{
if { [cli_ver_start 500 2] } {
	namespace import global::is_sslvpn_intf
	set intf [cli_get_value $CLI_CUR_NODE "" "" "srcintf"]
	set intf [string trim $intf \"]
	if { ![cli_has_feature "f_sslvpn"] } {
	} elseif { [is_sslvpn_intf $intf] } {
		if { [cli_switch] } {
			set p [cli_get_value $CLI_SRC_VDOM_NODE "vpn ssl settings" "" "default-portal"]
			if { $p ne "" && [cli_copy_src_object "vpn ssl web portal" $p] } {
				cli_set_errmsg "copy source vpn ssl web portal $p failed."
				return 0
			}
			cli_switch_end
		}
	}
}
if { [cli_ver_start 500 2] } {
	set usrs [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "user radius" "rsso" 0 "enable"]
	if { [llength $usrs] > 0 } {
	} else {
		set rssogrp 0
		set groups [cli_get_value $CLI_CUR_NODE "" "" "groups"]
		foreach grp $groups {
			if { [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "user group" "name" 0 $grp "group-type" 0 "rsso"] } {
				set rssogrp 1
				break
			}
		}

		if { $rssogrp == 1 && [cli_switch]} {
			set usrs [cli_get_match_list $CLI_SRC_VDOM_NODE 1 "user radius" "rsso" 0 "enable"]
			if { [llength $usrs] > 0 && [cli_copy_src_node [lindex $usrs 0]] } {
				set un [cli_get_value [lindex $usrs 0] "" "" "name"]
				cli_set_errmsg "copy source user radius $un failed."
				return 0
			}
			cli_switch_end
		}
	}

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
		if { [cli_copy_src_node [lindex $urs 0]] } {
			set un [cli_get_value [lindex $urs 0] "" "" "name"]
			cli_set_errmsg "copy source user radius $un failed."
			return 0
		}
		cli_switch_end
	}
}
proc copy_src_nodes_act { parent objtbl } {
	if { [cli_switch] } {
		set objs [cli_get_tbl_list $parent $objtbl]
		foreach obj $objs {
			if { [cli_copy_src_node [lindex $obj 0]] } {
				set name [cli_get_value $obj "" "" "name"]
				cli_set_errmsg "copy source $objtbl $name failed."
				return 0
			}
       		}
		cli_switch_end
	}
	return 1
}
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
set wanopt [cli_get_value $CLI_CUR_NODE "" "" "wanopt"]
set wdet [cli_get_value $CLI_CUR_NODE "" "" "wanopt-detection"]
if { $action eq "accept" && $wanopt eq "enable" && $wdet eq "passive" } {
	if { ![copy_src_nodes_act $CLI_SRC_VDOM_NODE "wanopt peer" ] } {
		return 0;
	}
	if { ![copy_src_nodes_act $CLI_SRC_VDOM_NODE "wanopt auth-group" ] } {
		return 0;
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
