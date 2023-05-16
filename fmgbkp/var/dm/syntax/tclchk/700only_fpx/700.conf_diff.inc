%{
proc diff.purge-all { node arg } {
	conf_del_entry $node
}

proc diff.get-entry-list { node arg } {
	upvar $arg l
	lappend l $node
}

proc user.fsso { local remote action arg } {
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

proc diff.check-rsso-server { node arg } {
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

proc diff.user.radius { local remote action arg } {
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
	if { $action == $CONF_ACT_T_ADD } {
		set radius $local
	} else {
		set radius [conf_node_parent $local]
	}
	conf_foreach_entry $radius diff.check-rsso-server $name
	return $CONF_RET_T_OK
}

proc diff.firewall.ssh.local-key.private-key { lattr rattr action arg } {
	global CONF_RET_T_SKIP
	if { [conf_diff_is_builtin_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return [cert_private_key_compare $lattr $rattr $action $arg]
}

proc diff.firewall.ssh.local-key.public-key { lattr rattr action arg } {
	global CONF_RET_T_SKIP
	if { [conf_diff_is_builtin_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return [cert_private_key_compare $lattr $rattr $action $arg]
}

proc diff.firewall.ssh.local-key.password { lattr rattr action arg } {
	global CONF_RET_T_OK CONF_RET_T_SKIP CONF_ACT_T_DELETE
	if { [conf_diff_is_builtin_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	if { $action == $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_SKIP
	}
	return $CONF_RET_T_OK
}

proc diff.firewall.ssh.local-ca.private-key { lattr rattr action arg } {
	global CONF_RET_T_SKIP
	if { [conf_diff_is_builtin_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return [cert_private_key_compare $lattr $rattr $action $arg]
}

proc diff.firewall.ssh.local-ca.public-key { lattr rattr action arg } {
	global CONF_RET_T_SKIP
	if { [conf_diff_is_builtin_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return [cert_private_key_compare $lattr $rattr $action $arg]
}

proc diff.firewall.ssh.local-ca.password { lattr rattr action arg } {
	global CONF_RET_T_OK CONF_RET_T_SKIP CONF_ACT_T_DELETE
	if { [conf_diff_is_builtin_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	if { $action == $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_SKIP
	}
	return $CONF_RET_T_OK
}

proc firewall.ssl-ssh-profile { local remote action arg } {
	global CONF_ACT_T_ADD
	global CONF_ACT_T_EDIT
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK
	global CONF_RET_T_DONT
	global CONF_RET_T_ERROR
	if { $action == $CONF_ACT_T_DELETE || $action == $CONF_ACT_T_EDIT } {
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

proc firewall.profile-protocol-options { local remote action arg } {
	global CONF_ACT_T_ADD
	global CONF_ACT_T_EDIT
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK
	global CONF_RET_T_DONT
	global CONF_RET_T_ERROR
	if { $action == $CONF_ACT_T_DELETE || $action == $CONF_ACT_T_EDIT } {
		set name [conf_node_name $local]
		set cmpresult [conf_strcmp "default" $name]
		if { $cmpresult == 0 } {
			return CONF_RET_T_DONT
		}
	}
	return $CONF_RET_T_OK
}

proc diff.vpn.certificate.local { local remote action arg } {
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

proc diff.firewall.address { local remote action arg } {
	global CONF_ACT_T_DELETE CONF_RET_T_OK CONF_RET_T_DONT
	if { $action != $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_OK
	}
	set name [string map {\" ""} [conf_node_name $local]]
	if {$name ne "" && [regexp {^qtn\.mac_[0-9a-fA-F:]*$} $name] == 1} {
		return $CONF_RET_T_DONT
	}

	set type [conf_find_attr $local "type"]
	set stype [conf_find_attr $local "sub-type"]
	if { $type && $stype && ([conf_attr_arg $type 0] eq "dynamic" && [conf_attr_arg $stype 0] eq "ems-tag") } {
		return $CONF_RET_T_DONT
	}

	return $CONF_RET_T_OK
}

proc diff.firewall.policy { local remote action arg } {
	global CONF_RET_T_OK
	set rvdom [conf_node_root $remote]
	set lvdom [conf_node_root $local]

	set ret $CONF_RET_T_OK
	if { $rvdom == 0 || $lvdom == 0 } {
		return $ret
	}
	set rap_node [conf_find_child $rvdom "firewall access-proxy"]
	set lap_node [conf_find_child $lvdom "firewall access-proxy"]
	set dstaddr [conf_find_attr $remote "dstaddr"]
	set name [string trim [conf_attr_arg $dstaddr 0] \"]
	set rvip [conf_find_child $rvdom "firewall vip"]
	if { $rvip == 0 } {
		return $ret
	}
	set rvip_entry [conf_find_child $rvip $name]
	if { $rvip_entry == 0 } {
		return $ret
	}
	set rtype [conf_attr_arg [conf_find_attr $rvip_entry "type"] 0]
	if { $rtype ne "access-proxy" } {
		return $ret
	}

	set argc [conf_attr_argc $dstaddr]
	set i 0
	while { $i < $argc } {
		set name [string trim [conf_attr_arg $dstaddr $i] \"]
		set rap [conf_find_child $rap_node $name]
		set lap [conf_find_child $lap_node $name]
		if { $lap == 0 } {
			set lap [conf_add_entry $lap_node $rap]
		}
		conf_merge_entry_edit $lap $rap
		incr i
	}
	return $ret
}

## mantis#0733001
proc diff.authentication.scheme { local remote action arg } {
	global CONF_RET_T_OK

	if { $local eq 0 || $remote eq 0 } {
		return $CONF_RET_T_OK;
	}

	# polling new fafn, unset dc
	set remote_fafn [conf_attr_arg [conf_find_attr $remote "fsso-agent-for-ntlm"] 0]
	if { $remote_fafn ne 0 && $remote_fafn ne ""} { 
		conf_unset_attr [conf_find_attr $local "domain-controller"]
		return $CONF_RET_T_OK;
	}

	# polling new dc, unset fafn
	set remote_dc [conf_attr_arg [conf_find_attr $remote "domain-controller"] 0]
	if { $remote_dc ne 0 && $remote_dc ne ""} {
		conf_unset_attr [conf_find_attr $local "fsso-agent-for-ntlm"]
		return $CONF_RET_T_OK;
	}
		
	return $CONF_RET_T_OK;
}

%}
