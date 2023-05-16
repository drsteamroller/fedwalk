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
	if { $rvdom == 0 || $lvdom == 0 } {
		return $CONF_RET_T_OK
	}
	set rap_node [conf_find_child $rvdom "firewall access-proxy"]
	set lap_node [conf_find_child $lvdom "firewall access-proxy"]
	set dstaddr [conf_find_attr $remote "dstaddr"]
	set name [string trim [conf_attr_arg $dstaddr 0] \"]
	set rvip [conf_find_child $rvdom "firewall vip"]
	if { $rvip == 0 } {
		return $CONF_RET_T_OK
	}
	set rvip_entry [conf_find_child $rvip $name]
	if { $rvip_entry == 0 } {
		return $CONF_RET_T_OK
	}
	set rtype [conf_attr_arg [conf_find_attr $rvip_entry "type"] 0]
	if { $rtype ne "access-proxy" } {
		return $CONF_RET_T_OK
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
	return $CONF_RET_T_OK
}

proc diff.firewall.proxy-policy { local remote action arg } {
	global CONF_RET_T_OK
	set rvdom [conf_node_root $remote]
	set lvdom [conf_node_root $local]
	if { $rvdom == 0 || $lvdom == 0 } {
		return $CONF_RET_T_OK
	}
	set rap_node [conf_find_child $rvdom "firewall access-proxy"]
	set lap_node [conf_find_child $lvdom "firewall access-proxy"]
	set access_proxy [conf_find_attr $remote "access-proxy"]
	set name [string trim [conf_attr_arg $access_proxy 0] \"]
	set rvip [conf_find_child $rvdom "firewall vip"]
	if { $rvip == 0 } {
		return $CONF_RET_T_OK
	}
	set rvip_entry [conf_find_child $rvip $name]
	if { $rvip_entry == 0 } {
		return $CONF_RET_T_OK
	}
	set rtype [conf_attr_arg [conf_find_attr $rvip_entry "type"] 0]
	if { $rtype ne "access-proxy" } {
		return $CONF_RET_T_OK
	}

	set argc [conf_attr_argc $access_proxy]
	set i 0
	while { $i < $argc } {
		set name [string trim [conf_attr_arg $access_proxy $i] \"]
		set rap [conf_find_child $rap_node $name]
		set lap [conf_find_child $lap_node $name]
		if { $lap == 0 } {
			set lap [conf_add_entry $lap_node $rap]
		}
		conf_merge_entry_edit $lap $rap
		incr i
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

proc diff.switch-controller.managed-switch { local remote action arg } {
	global CONF_RET_T_OK
	global CONF_ACT_T_ADD
	if { $action == $CONF_ACT_T_ADD } {
		## exit the switch node, and enter again to add all port information
		conf_goto_node [conf_node_root $local]
	}
	return $CONF_RET_T_OK
}

proc diff.switch-controller.switch-group { local remote action arg } {
	global CONF_RET_T_OK
	global CONF_ACT_T_EDIT

	if { $action == $CONF_ACT_T_EDIT && $local ne 0 && $remote ne 0 } {
		set lflink [conf_find_attr $local "fortilink"]
		set rflink [conf_find_attr $remote "fortilink"]
		if { $lflink && $rflink && [conf_attr_arg $lflink 0] ne [conf_attr_arg $rflink 0] } {
			conf_del_entry_self $local
		}
	}
	return $CONF_RET_T_OK
}

proc diff.switch-controller.managed-switch.ports {local remote action arg} {
	global CONF_ACT_T_DELETE CONF_ACT_T_EDIT
	global CONF_RET_T_OK CONF_RET_T_SKIP

	set port_nac_svar "swc-controller-ports-svar"

	if { [conf_var_exist $port_nac_svar] ne 0 } {
		## prevent infinite loop
		return $CONF_RET_T_OK
	}

	if { $action == $CONF_ACT_T_EDIT } {
		## for nac mode, we will first unset it, to push configuration over, then set it again
		if { $local eq 0 || $remote eq 0 } {
			return $CONF_RET_T_OK
		}
		set need_unset_nac 0
		set lnac 0
		set rnac 0
		set lamode [conf_find_attr $local "access-mode"]
		set ramode [conf_find_attr $remote "access-mode"]

		if { $lamode ne 0 && [conf_attr_arg $lamode 0] eq "nac" } {
			set lnac 1
		}
		if { $ramode ne 0 && [conf_attr_arg $ramode 0] eq "nac" } {
			set rnac 1
		}

		if { $lnac eq 0 && $rnac eq 0 } {
			return $CONF_RET_T_OK
		}

		set lvdom [conf_node_root $local]
		set rvdom [conf_find_vdom [conf_node_name $lvdom] 1]
		set rswitch [conf_node_parent [conf_node_parent $remote]]
		set flink [conf_attr_arg [conf_find_attr $rswitch "fsw-wan1-peer"] 0]
		set fset [conf_find_child $rvdom "switch-controller fortilink-settings"]
		if { $fset ne 0 } {
			## fos auto add nac-lan-interface to allowed/untagged-vlans in nac mode, so we do not need to generate diff
			set fset [conf_find_child $fset $flink]
			if { $fset ne 0 } {
				set nacports [conf_find_child $fset "nac-ports"]
				set nli [conf_attr_arg [conf_find_attr $nacports "nac-lan-interface"] 0]
				## delete nac-lan-interface from attr before comparing
				if { $rnac eq 1 } {
					conf_attr_del_arg [conf_find_attr $remote "allowed-vlans"] $nli
					conf_attr_del_arg [conf_find_attr $remote "untagged-vlans"] $nli
				}
				if { $lnac eq 1 } {
					conf_attr_del_arg [conf_find_attr $local "allowed-vlans"] $nli
					conf_attr_del_arg [conf_find_attr $local "untagged-vlans"] $nli
				}
			}
		}

		if { [attr_cmp $local $remote "allowed-vlans"] } { set need_unset_nac 1 }
		if { [attr_cmp $local $remote "untagged-vlans"] } { set need_unset_nac 1 }

		if { $lnac eq 1 && $rnac eq 0 } {
			if { [attr_cmp $local $remote "vlan"] } { set need_unset_nac 1 }
			if { [attr_cmp $local $remote "allowed-vlans-all"] } { set need_unset_nac 1 }
		}

		if { $need_unset_nac eq 0 } {
			return $CONF_RET_T_OK
		}

		if { $lnac eq 1 } {
			conf_unset_attr $lamode
			conf_goto_node [conf_node_parent $local]
		}

		## prevent infinite loop
		conf_set_var $port_nac_svar [conf_node_name $local]

		conf_merge_entry_edit_chkdep $local $remote
		conf_unset_var $port_nac_svar

		if { $rnac eq 1 } {
			conf_goto_node [conf_node_parent $local]
			conf_set_attr $lamode "nac"
		}

		return $CONF_RET_T_OK
	} elseif { $action == $CONF_ACT_T_DELETE } {
		set type [conf_attr_arg [conf_find_attr $local "type"] 0]
		if { $type eq "trunk" } {
			return $CONF_RET_T_OK
		}

		set lvdom [conf_node_root $local]
		set rvdom [conf_find_vdom [conf_node_name $lvdom] 1]
		set lswitch [conf_node_parent [conf_node_parent $local]]
		set rswitch [conf_find_child $rvdom "switch-controller managed-switch"]
		if { $rswitch ne 0 } {
			set lname [conf_node_name $lswitch]
			set rswitch [conf_find_child $rswitch $lname]
		}
		if { $rswitch eq 0 } {
			## managed-switch node not found or switch not found, delete the switch in switch-controller
			conf_del_entry $lswitch
		}
		return $CONF_RET_T_SKIP
	}
}

proc diff.switch-controller.managed-switch.ports.access-mode {local remote action arg} {
	global CONF_RET_T_OK CONF_RET_T_SKIP

	set port_nac_svar "swc-controller-ports-svar"

	if { [conf_var_exist $port_nac_svar] ne 0 } {
		## controlled by parent object
		return $CONF_RET_T_SKIP
	}
	return $CONF_RET_T_OK
}
proc diff.switch-controller.managed-switch.ports.vlan {lattr rattr action arg} {
	global CONF_RET_T_OK CONF_RET_T_SKIP

	set raccess [conf_find_attr [conf_node_parent $rattr] "access-mode"]

	if { $raccess ne 0 && [conf_attr_arg $raccess 0] eq "nac" } {
		return $CONF_RET_T_SKIP
	}
	return CONF_RET_T_OK
}
proc diff.switch-controller.managed-switch.ports.allowed-vlans-all {lattr rattr action arg} {
	global CONF_RET_T_OK CONF_RET_T_SKIP

	set raccess [conf_find_attr [conf_node_parent $rattr] "access-mode"]

	if { $raccess ne 0 && [conf_attr_arg $raccess 0] eq "nac" } {
		return $CONF_RET_T_SKIP
	}
	return CONF_RET_T_OK
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

proc diff.switch-controller.fortilink-settings {handle nentry action arg} {
    global CONF_RET_T_OK
    set nac [conf_find_child $nentry "nac-ports"]
    set vlan [conf_attr_arg [conf_find_child $nac "onboarding-vlan"] 0]
    set vlan [string trim $vlan \"]
    set l_intf [conf_find_child [conf_global] "system interface"]
    set r_intf [conf_find_child [conf_global 1] "system interface"]
    set l_ifnode [conf_find_child $l_intf $vlan]
## if onboarding-vlan does not exist in system interface yet, need to add it first
    if { $l_ifnode eq 0 } {
        set r_ifnode [conf_find_child $r_intf $vlan]
        set l_ifnode [conf_add_entry $l_intf $r_ifnode]
        conf_merge_entry_edit $l_ifnode $r_ifnode
    }

    set nli [conf_attr_arg [conf_find_child $nac "nac-lan-interface"] 0]
    set nli [string trim $nli \"]
    set l_ifnode [conf_find_child $l_intf $nli]
    if { $l_ifnode eq 0 } {
        set r_ifnode [conf_find_child $r_intf $nli]
        set l_ifnode [conf_add_entry $l_intf $r_ifnode]
        conf_merge_entry_edit $l_ifnode $r_ifnode
    }

    set nsv [conf_find_child $nac "nac-segment-vlans"]
	set argc [conf_attr_argc $nsv]
	set i 0
	while { $i < $argc } {
		set vl [string trim [conf_attr_arg $nsv $i] \"]
		set l_ifnode [conf_find_child $l_intf $vl]
		if { $l_ifnode eq 0 } {
			set r_ifnode [conf_find_child $r_intf $vl]
			set l_ifnode [conf_add_entry $l_intf $r_ifnode]
			conf_merge_entry_edit $l_ifnode $r_ifnode
		}
		incr i
	}
    return $CONF_RET_T_OK
}
%}
