%{
proc diff.purge-all {node arg} {
	conf_del_entry $node
}

proc diff.get-entry-list {node arg} {
	upvar $arg l
	lappend l $node
}

proc user.fsso {local remote action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR

	# the returned node name somehow got treated as a list, so we join them with space
	set name [join [conf_node_name $remote] " "]
	if { $name ne "Local FSSO Agent" } {
		return $CONF_RET_T_OK
	}

	return $CONF_RET_T_OK

	# disable this block of code due to potential bug on FGT
	# read-only
	return $CONF_RET_T_DONT

	set lldapserv [conf_attr_arg [conf_find_attr $local "ldap-server"] 0]
	set rldapserv [conf_attr_arg [conf_find_attr $remote "ldap-server"] 0]
	if { [conf_strcmp $lldapserv $rldapserv] == 0 } {
		return $CONF_RET_T_OK
	}

	set lpoll [conf_find_child [conf_node_root $local] "user fsso-polling"]
	if { $lpoll != 0 } {
		conf_foreach_entry $lpoll diff.purge-all 0
	}

	set rpoll [conf_find_child [conf_node_root $remote] "user fsso-polling"]
	if { $rpoll != 0 } {
		set list {}
		set serv [conf_attr_arg [conf_find_attr $remote "ldap-server"] 0]

		conf_foreach_entry $rpoll diff.get-entry-list list
		foreach node $list {
			if { [conf_strcmp [conf_attr_arg [conf_find_attr $node "ldap-server"] 0] $serv] == 0 } {
				set lentry [conf_add_entry $lpoll $node]
				conf_merge_entry_edit $lentry $node
				return $CONF_RET_T_DONT
			}
		}
	}
	return $CONF_RET_T_DONT
}

proc diff.check-rsso-server {node arg} {
	set rsso "disable"
	set rssoattr [conf_find_attr $node "rsso"]
	if { $rssoattr != 0 } {
		set rsso [conf_attr_arg $rssoattr 0]
	}
	set name [conf_node_name $node]
	set comp [conf_strcmp $name $arg]
	if { $rsso eq "enable" && $comp != 0 } {
		conf_del_entry $node
	}
}

proc diff.user.radius {local remote action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR

	set name [conf_node_name $remote]
	
	if { $local == 0 || $remote == 0 || $action == $CONF_ACT_T_DELETE } {
		return CONF_RET_T_OK
	}

	set rsso [conf_attr_arg [conf_find_attr $remote "rsso"] 0]

	if { $rsso ne "enable" } {
		return CONF_RET_T_OK
	}

	if {$action == $CONF_ACT_T_ADD} {
		set radius $local
	} else {
		set radius [conf_node_parent $local]
	}

	conf_foreach_entry $radius diff.check-rsso-server $name

	return $CONF_RET_T_OK
}

proc diff.firewall.ssh.local-key.private-key {lattr rattr action arg} {
	global CONF_RET_T_SKIP
	if { [conf_diff_is_builtin_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return [cert_private_key_compare $lattr $rattr $action $arg]
}
proc diff.firewall.ssh.local-key.public-key {lattr rattr action arg} {
	global CONF_RET_T_SKIP
	if { [conf_diff_is_builtin_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return [cert_private_key_compare $lattr $rattr $action $arg]
}
proc diff.firewall.ssh.local-key.password {lattr rattr action arg} {
        global CONF_RET_T_OK CONF_RET_T_SKIP CONF_ACT_T_DELETE
	if { [conf_diff_is_builtin_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	if { $action == $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_SKIP
	}
	return $CONF_RET_T_OK
}
proc diff.firewall.ssh.local-ca.private-key {lattr rattr action arg} {
	global CONF_RET_T_SKIP
	if { [conf_diff_is_builtin_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return [cert_private_key_compare $lattr $rattr $action $arg]
}
proc diff.firewall.ssh.local-ca.public-key {lattr rattr action arg} {
	global CONF_RET_T_SKIP
	if { [conf_diff_is_builtin_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return [cert_private_key_compare $lattr $rattr $action $arg]
}

proc diff.firewall.ssh.local-ca.password {lattr rattr action arg} {
        global CONF_RET_T_OK CONF_RET_T_SKIP CONF_ACT_T_DELETE
	if { [conf_diff_is_builtin_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	if { $action == $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_SKIP
	}
	return $CONF_RET_T_OK
}

proc firewall.ssl-ssh-profile {local remote action arg} {
	global CONF_ACT_T_ADD
	global CONF_ACT_T_EDIT 
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK
	global CONF_RET_T_DONT
	global CONF_RET_T_ERROR

	if { $action == $CONF_ACT_T_DELETE || $action == $CONF_ACT_T_EDIT} {
		set name [conf_node_name $local]
		set cmpresult [conf_strcmp "deep-inspection" $name]
		if { $cmpresult == 0 } {
			return CONF_RET_T_DONT
 		}
		set cmpresult [conf_strcmp "certificate-inspection" $name]
		if { $cmpresult == 0 } {
			return CONF_RET_T_DONT
 		}
	}
        return $CONF_RET_T_OK
}
proc firewall.profile-protocol-options {local remote action arg} {
	global CONF_ACT_T_ADD
	global CONF_ACT_T_EDIT 
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK
	global CONF_RET_T_DONT
	global CONF_RET_T_ERROR

	if { $action == $CONF_ACT_T_DELETE || $action == $CONF_ACT_T_EDIT} {
		set name [conf_node_name $local]
		set cmpresult [conf_strcmp "default" $name]
		if { $cmpresult == 0 } {
			return CONF_RET_T_DONT
 		}
	}
        return $CONF_RET_T_OK
}
proc diff.vpn.certificate.local {local remote action arg} {
	global CONF_RET_T_OK
	global CONF_RET_T_SKIP
	set rattr [conf_find_attr $remote "source"]
	if { $rattr != 0 } {
		set source [conf_attr_arg $rattr 0]
		if { $source eq "factory" } {
			return $CONF_RET_T_SKIP
		}
	}
	return $CONF_RET_T_OK
}
proc diff.vpn.certificate.remote { local remote action arg } {
	global CONF_ACT_T_DELETE
	global CONF_ACT_T_CLEAR
	global CONF_ACT_T_UNSET
	global CONF_RET_T_OK
	global CONF_RET_T_SKIP

	if { $action != $CONF_ACT_T_DELETE && $action != $CONF_ACT_T_CLEAR && $action != $CONF_ACT_T_UNSET } {
		return $CONF_RET_T_OK
	}
	set lattr [conf_find_attr $local "range"]
	if { $lattr == 0 } {
		return $CONF_RET_T_SKIP
	}
	if { $lattr != 0 } {
		set lrange [conf_attr_arg $lattr 0]
		if { $lrange eq "global" } {
			return $CONF_RET_T_SKIP
		}
	}
	return $CONF_RET_T_OK
}
proc diff.switch-controller.lldp-profile { local remote action arg } {
	global CONF_ACT_T_DELETE CONF_ACT_T_EDIT CONF_ACT_T_ADD
	global CONF_RET_T_OK CONF_RET_T_SKIP
	# add_action_var_name is used to determine whether this function is called after ADD action
	set add_action_var_name "lldp-profile-med-tlvs-add-cmd"  
	set key_val [conf_node_name $remote]

	if { $action eq $CONF_ACT_T_ADD } {
		if { $key_val ne "" } {
			conf_set_var $add_action_var_name $key_val
		}
	}

	if { $action eq $CONF_ACT_T_DELETE } {
		if { [conf_node_name $local] eq "fortivoice" } {
			return $CONF_RET_T_SKIP
		}
	} elseif { $action eq $CONF_ACT_T_EDIT } {
		set cur_key [conf_get_var $add_action_var_name]
		if { $cur_key eq $key_val } {
			# called after ADD action
			# only unset med-tlvs if the EDIT action is after the ADD
			set tlvs [conf_find_attr $remote "med-tlvs"]
			if { $tlvs eq 0 } {
				conf_add_script $local "unset med-tlvs" 1
			} else {
				set argc [conf_attr_argc $tlvs]
				if { $argc eq 0 } {
					conf_add_script $local "unset med-tlvs" 1
				}
			}
		}
		## reset the var
		conf_set_var $var_name ""
	}
	return $CONF_RET_T_OK
}
proc diff.switch-controller.managed-switch {local remote action arg} {
	global CONF_RET_T_OK
	global CONF_ACT_T_ADD

	if { $action == $CONF_ACT_T_ADD } {
		## exit the switch node, and enter again to add all port information
		conf_goto_node [conf_node_root $local]
	}
	return $CONF_RET_T_OK
}
proc skip_route_map_rule_unset {lattr rattr action arg} {
	global CONF_ACT_T_UNSET
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK
	global CONF_RET_T_SKIP

	if { $action == $CONF_ACT_T_UNSET || $action == $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_SKIP
	}
	if { $rattr == 0 } {
		return $CONF_RET_T_SKIP
	}
	set r_argc [conf_attr_argc $rattr]
	if { $r_argc eq 0 } {
		return $CONF_RET_T_SKIP
	}
	set rvalue [conf_attr_arg $rattr 0]
	if { ($rvalue eq "") || ($rvalue eq "0.0.0.0") || ($rvalue eq "::") } {
		return $CONF_RET_T_SKIP
	}
	return $CONF_RET_T_OK
}
proc diff.router.route-map.rule.set-ip-nexthop {lattr rattr action arg} {
	return [skip_route_map_rule_unset $lattr $rattr $action $arg]
}
proc diff.router.route-map.rule.set-ip6-nexthop {lattr rattr action arg} {
	return [skip_route_map_rule_unset $lattr $rattr $action $arg]
}
proc diff.router.route-map.rule.set-ip6-nexthop-local {lattr rattr action arg} {
	return [skip_route_map_rule_unset $lattr $rattr $action $arg]
}
proc diff.router.route-map.rule.set-originator-id {lattr rattr action arg} {
	return [skip_route_map_rule_unset $lattr $rattr $action $arg]
}
%}
