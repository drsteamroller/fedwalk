%{
proc diff.purge-all {node arg} {
	conf_del_entry $node
}

proc diff.get-entry-list {node arg} {
	upvar $arg l
	lappend l $node
}

proc diff.user.fsso {local remote action arg} {
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

proc diff.firewall.ssl-ssh-profile {local remote action arg} {
	global CONF_ACT_T_ADD
	global CONF_ACT_T_EDIT 
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK
	global CONF_RET_T_DONT
	global CONF_RET_T_ERROR

	if { $action == $CONF_ACT_T_DELETE || $action == CONF_ACT_T_EDIT} {
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
proc skip_sys_settings_gui_when_switch_inspection_mode {remote skip_mode} {
	global CONF_RET_T_OK
	global CONF_RET_T_DONT
	set mode [conf_attr_arg [conf_find_attr $remote "inspection-mode"] 0]
	if { $mode == $skip_mode } {
		return $CONF_RET_T_DONT
	}
	return $CONF_RET_T_OK
}
proc diff.system.settings.gui-icap {local remote action arg} {
	return [skip_sys_settings_gui_when_switch_inspection_mode $remote "flow"]
}
proc diff.system.settings.gui-spamfilter {local remote action arg} {
	return [skip_sys_settings_gui_when_switch_inspection_mode $remote "flow"]
}
proc diff.system.settings.gui-explicit-proxy {local remote action arg} {
	return [skip_sys_settings_gui_when_switch_inspection_mode $remote "flow"]
}
proc diff.system.settings.gui-dlp {local remote action arg} {
	return [skip_sys_settings_gui_when_switch_inspection_mode $remote "flow"]
}
proc diff.system.settings.gui-application-control {local remote action arg} {
	return [skip_sys_settings_gui_when_switch_inspection_mode $remote "proxy"]
}
proc diff.system.settings.gui-webfilter {local remote action arg} {
	return [skip_sys_settings_gui_when_switch_inspection_mode $remote "proxy"]
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
%}
