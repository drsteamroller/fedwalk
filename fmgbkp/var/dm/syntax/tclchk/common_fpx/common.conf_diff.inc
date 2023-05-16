%{

set CONF_ACT_T_NONE 0
set CONF_ACT_T_ADD 1
set CONF_ACT_T_DELETE 2
set CONF_ACT_T_EDIT 3
set CONF_ACT_T_MOVE 4
set CONF_ACT_T_CLEAR 5
set CONF_ACT_T_UNSET 6

set CONF_RET_T_SKIP 2
set CONF_RET_T_DONT 1
set CONF_RET_T_OK 0
set CONF_RET_T_ERROR -1

proc conf_diff_is_factory_cert {lattr rattr action arg} {
        global CONF_RET_T_OK CONF_RET_T_SKIP;  
        if { $rattr } {
		set lentry [conf_node_parent $rattr]
		set tattr [conf_find_attr $lentry "source"]
		if { $tattr != 0 } {
			set source [conf_attr_arg $tattr 0]
			if { $source == "factory" } {
				return $CONF_RET_T_SKIP
			}
		}
	}
        return $CONF_RET_T_OK
}

proc conf_diff_is_builtin_cert {lattr rattr action arg} {
	global CONF_RET_T_OK CONF_RET_T_SKIP;  
	if { $rattr } {
		set lentry [conf_node_parent $rattr]
		set tattr [conf_find_attr $lentry "source"]
		if { $tattr != 0 } {
			set source [conf_attr_arg $tattr 0]
			if { $source == "built-in" } {
				return $CONF_RET_T_SKIP
			}
		}
	} else {
		if { $lattr } {
			set lentry [conf_node_parent $lattr]
			set tattr [conf_find_attr $lentry "source"]
			if { $tattr != 0 } {
				set source [conf_attr_arg $tattr 0]
				if { $source == "built-in" } {
					return $CONF_RET_T_SKIP
				}
			}
		}
	}
	return $CONF_RET_T_OK
}

proc conf_diff_is_scep_cert { lattr rattr action arg } {
	global CONF_ACT_T_DELETE CONF_RET_T_OK CONF_RET_T_SKIP

	set v1 [conf_get_var "is_autoupdate"]
	if { $v1 && $v1 eq "1" } {
		return $CONF_RET_T_OK
	}
	set v2 [conf_get_var "skip_scep_check"]
	if { $v2 && $v2 eq "1" } {
		return $CONF_RET_T_OK
	}

	if {!$lattr && !$rattr} {
		return $CONF_RET_T_OK
	}

	if { $lattr } {
		set le [conf_node_parent $lattr]
	} 
	if { $rattr } {
		if { $action == $CONF_ACT_T_DELETE } {
			set re $rattr
		} else {
			set re [conf_node_parent $rattr]
		}
	}

	set ls [conf_find_attr $le "scep-url"]
	set rs [conf_find_attr $re "scep-url"]
	if { ($ls && $rs && ([conf_attr_arg $ls 0] eq [conf_attr_arg $rs 0])) } {
		return $CONF_RET_T_SKIP
	}

	return $CONF_RET_T_OK
}

proc cert_private_key_compare {local remote action arg} {
        global CONF_RET_T_OK CONF_RET_T_DONT

        if {!$local || !$remote} {
                return $CONF_ACT_T_OK
        }
        set lp [conf_node_parent $local]
        set rp [conf_node_parent $remote]
        set lpasswdn [conf_find_child $lp "password"]
        set rpasswdn [conf_find_child $rp "password"]
        set lpasswd [conf_attr_arg $lpasswdn 0 1]
        set rpasswd [conf_attr_arg $rpasswdn 0 1]
        set lkey [conf_attr_arg $local 0]
        set rkey [conf_attr_arg $remote 0]
        set rt [conf_diff_key $lkey $lpasswd $rkey $rpasswd]
        if {$rt == 1} {
                return $CONF_RET_T_DONT
        }
        return $CONF_RET_T_OK
}

proc diff.edit_vlan {attrname lentry nentry action} {
	global CONF_ACT_T_ADD CONF_ACT_T_DELETE;
	global CONF_ACT_T_EDIT CONF_ACT_T_MOVE;  
	global CONF_ACT_T_CLEAR CONF_ACT_T_UNSET;
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR;  

	if { $action != $CONF_ACT_T_EDIT } {
		return $CONF_RET_T_OK;
	}

	if { $lentry == 0 } {
		return $CONF_RET_T_OK;
	}
	set lvlan [conf_node_parent $lentry]
	if { $lvlan == 0 } {
		return $CONF_RET_T_OK;
	}
	if { $nentry == 0 } {
		return $CONF_RET_T_OK;
	}
	set nvlan [conf_node_parent $nentry]
	if { $nvlan == 0 } {
		return $CONF_RET_T_OK;
	}

	set lt [conf_find_child $lvlan "type"]
	if { $lt != 0 } {
		set ltype [conf_attr_arg $lt 0]
		if { $ltype != "vlan" } {
			return $CONF_RET_T_OK;
		}
	}

	set nattr [conf_attr_arg [conf_find_child $nvlan $attrname] 0]
	set lattr [conf_attr_arg [conf_find_child $lvlan $attrname] 0]
	if { $lattr != $nattr } {
		set parent [conf_node_parent $lvlan]
		conf_del_entry $lvlan
		set lvlan [conf_add_entry $parent $nvlan]
		conf_merge_entry_edit $lvlan $nvlan
		return $CONF_RET_T_DONT;
	}

	return $CONF_RET_T_OK;
}

proc diff.sys.intf.chkmember {entry1 entry2} {
	global CONF_RET_T_OK CONF_ACT_T_DONT CONF_RET_T_ERROR;  

	set tattr [conf_find_attr $entry1 "type"]
	if { $tattr == 0 } {
		return $CONF_RET_T_OK;
	}
	set type [conf_attr_arg $tattr 0]
	if { $type != "aggregate" && $type != "redundant" } {
		return $CONF_RET_T_OK;
	}

	set name [conf_node_name $entry1]
	set name2 [conf_node_name $entry2]
	if { [conf_strcmp $name $name2] } {
		set attr2 [conf_find_child $entry2 "member"]
		if { $attr2 == 0 } {
			return $CONF_RET_T_OK;
		}
		set argc2 [conf_attr_argc $attr2]

		set i 0 
		while { $i < $argc2 } {
			set value2 [conf_attr_arg $attr2 $i]

			set attr1 [conf_find_child $entry1 "member"]
			if { $attr1 == 0 } {
				return $CONF_RET_T_OK;
			}
			set argc1 [conf_attr_argc $attr1]

			set j 0
			while { $j < $argc1 } {
				set value1 [conf_attr_arg $attr1 $j]
				if { $value1 == $value2 } {
					conf_unset_attr $attr1
					return $CONF_RET_T_OK;
				}
				incr j;
			}
			incr i;
		}
		
	} else {
		set attr1 [conf_find_child $entry1 "member"]
		set attr2 [conf_find_child $entry2 "member"]
		if { $attr1 != 0 && $attr2 != 0 } {
			set argc1 [conf_attr_argc $attr1]
			set argc2 [conf_attr_argc $attr2]
			if { $argc1 != $argc2 } {
				return $CONF_ACT_T_DONT;
			} else {
				set i 0 
				while { $i < $argc2 } {
					set value2 [conf_attr_arg $attr2 $i]
					set j 0
					set found 0
					while { $j < $argc1 } {
						set value1 [conf_attr_arg $attr1 $j]
						if { ![conf_strcmp $value1 $value2] } {
							set found 1;
							break;
						}
						incr j;
					}
					if { $found == 0 } {
						return $CONF_ACT_T_DONT;
					}
					incr i;
				}
			}
		}
	}
	return $CONF_RET_T_OK;
}

proc diff.system.interface.member {lattr rattr action arg} {
	global CONF_ACT_T_EDIT;
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR;  

	if { $action != $CONF_ACT_T_EDIT || $rattr == 0 } {
		return $CONF_RET_T_OK;
	}

	set entry [conf_node_parent $rattr]
	set intf [conf_find_child [conf_global] "system interface"];
	if { $intf != 0 } {
		conf_foreach_entry $intf diff.sys.intf.chkmember $entry;
	}

	return $CONF_RET_T_OK;
}

proc diff.sys.intf.chkvdom {entry1 entry2} {
	global CONF_RET_T_OK CONF_ACT_T_DONT CONF_RET_T_ERROR;  

	set tattr [conf_find_attr $entry1 "type"]
	if { $tattr == 0 } {
		return $CONF_RET_T_OK;
	}
	set type [conf_attr_arg $tattr 0]
	if { $type != "aggregate" && $type != "redundant" } {
		return $CONF_RET_T_OK;
	}

	set name [conf_node_name $entry2]

	set attr1 [conf_find_child $entry1 "member"]
	if { $attr1 == 0 } {
		return $CONF_RET_T_OK;
	}
	set argc1 [conf_attr_argc $attr1]

	set i 0 
	while { $i < $argc1 } {
		set value1 [conf_attr_arg $attr1 $i]
		if { $value1 == $name } {
			conf_unset_attr $attr1
			return $CONF_RET_T_OK;
		}
		incr i;
	}
		
	return $CONF_RET_T_OK;
}

proc diff.system.interface.vdom {lattr rattr action arg} {
	global CONF_ACT_T_EDIT;
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR;  

	if { $action != $CONF_ACT_T_EDIT || $rattr == 0 || $lattr == 0 } {
		return $CONF_RET_T_OK;
	}

	set lentry [conf_node_parent $lattr]
	set tattr [conf_find_attr $lentry "type"]
	if { $tattr != 0 } {
		set type [conf_attr_arg $tattr 0]
		if { $type == "aggregate" || $type == "redundant" } {
			set lmember [conf_find_attr $lentry "member"]
			conf_unset_attr $lmember
			return $CONF_RET_T_OK;
		}
	}

	set intf [conf_find_child [conf_global] "system interface"];
	if { $intf != 0 } {
		conf_foreach_entry $intf diff.sys.intf.chkvdom $lentry;
	}

	return $CONF_RET_T_OK;
}

proc diff.system.interface.interface {handle nentry action arg} {
	global CONF_ACT_T_EDIT;  
	global CONF_RET_T_OK CONF_RET_T_DONT;  

	if { $action != $CONF_ACT_T_EDIT } {
		return $CONF_RET_T_OK;
	}
	if { $handle == 0 } {
		return $CONF_RET_T_OK;
	}
	set lvlan [conf_node_parent $handle]
	if { $lvlan == 0 } {
		return $CONF_RET_T_OK;
	}
	if { $nentry == 0 } {
		return $CONF_RET_T_OK;
	}
	set nvlan [conf_node_parent $nentry]
	if { $nvlan == 0 } {
		return $CONF_RET_T_OK;
	}

	set lt [conf_find_child $lvlan "type"]
	if { $lt != 0 } {
		set ltype [conf_attr_arg $lt 0]
		if { $ltype == "tunnel" } {
			return $CONF_RET_T_DONT
		}
	}
	return [diff.edit_vlan "interface" $handle $nentry $action]
}

proc diff.system.interface.vlanid {handle nentry action arg} {
	global CONF_RET_T_OK CONF_RET_T_DONT;  
	set ret [diff.edit_vlan "vlanid" $handle $nentry $action]

	if { $handle == 0 } {
		return $CONF_RET_T_OK;
	}
	set lentry [conf_node_parent $handle]
	set vdom [conf_find_attr $lentry "vdom"]
	if { $vdom == 0 } {
		conf_add_script $handle "set vdom root"
	}
	return $ret
}

proc build-list {node l} {
	upvar $l list
	lappend list $node
}

proc diff.del-phase1-interface {entry arg} {
	set name [conf_node_name $entry]

	# Also delete the interface table. 
	set intf [conf_find_child [conf_find_child [conf_global] "system interface"] $name]

	# Remove only. 
	conf_destroy_node $intf;		
	return $CONF_RET_T_OK;
}

proc diff.del-p1-p2-dependency {handle} {
	set p1name [conf_node_name $handle] 
	set vdom [conf_node_root $handle]
	if {$p1name == 0 || $vdom == 0} {
		return 0;
	}
	set p2node [conf_find_child $vdom "vpn ipsec phase2-interface"]
	if {$p2node != 0} {
		conf_del_dependency $handle $p2node
	}
}

proc peertype_any_force_push {local remote action arg} {
		set lv [conf_attr_arg [conf_find_attr $local "authmethod"] 0]
		set rv [conf_attr_arg [conf_find_attr $remote "authmethod"] 0]
		set lpn [conf_find_attr $local "peertype"]
		set lpv [conf_attr_arg [conf_find_attr $local "peertype"] 0]
		set rpn [conf_find_attr $remote "peertype"]
		set rpv [conf_attr_arg $rpn 0]
		if { ($rv eq "signature") && ($lv ne "signature") } {
			if { $lpv eq $rpv } {
				## fgt will automatically change peertype to "peer"
				## need to force push attr if we don't want to change
				conf_set_attr $lpn "peer" 1
			}
		}
}

proc diff.vpn.ipsec.phase1-interface {handle dummy action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_DELETE;
	global CONF_ACT_T_EDIT CONF_ACT_T_MOVE;  
	global CONF_ACT_T_CLEAR CONF_ACT_T_UNSET;
	global CONF_RET_T_OK CONF_ACT_T_DONT CONF_RET_T_ERROR;  

	if { $action == $CONF_ACT_T_EDIT || $action == $CONF_ACT_T_ADD } {
		peertype_any_force_push $handle $dummy $action $arg
		set ret [conf_vpn_ipsec_gw_dupcheck $dummy]
	}
	if { $action == $CONF_ACT_T_DELETE } {
		diff.del-phase1-interface $handle 0;
		return $CONF_RET_T_OK;
	} elseif { $action == $CONF_ACT_T_EDIT } {
		set lmode [conf_find_attr $handle "mode-cfg"]
		if {$lmode == 0} {
			set lm "";
		} else {
			set lm [conf_attr_arg $lmode 0]
		}
		set rmode [conf_find_attr $dummy "mode-cfg"]
		if {$rmode == 0} {
			set rm ""
		} else {
			set rm [conf_attr_arg $rmode 0]
		}
		if {$lm != $rm} {
			diff.del-p1-p2-dependency $handle
		}
#		return $CONF_RET_T_OK;
	} elseif { $action != $CONF_ACT_T_CLEAR } {
		return $CONF_RET_T_OK;
	}

	if { $action != $CONF_ACT_T_EDIT } {
		conf_foreach_entry $handle diff.del-phase1-interface 0;
	}

    return $CONF_RET_T_OK
}

proc reset_fw_policy_addr {local remote action addr} {
	global CONF_ACT_T_EDIT;
	global CONF_RET_T_OK;

	if { $action != $CONF_ACT_T_EDIT } {
		return $CONF_RET_T_OK;
	}

	if { $remote == 0 } {
		return $CONF_RET_T_OK;
	}

	set lpn [conf_node_parent $local]
	set rpn [conf_node_parent $remote]
	set laddrn [conf_find_child_node $lpn $addr]
	set raddrn [conf_find_child_node $rpn $addr]
	if {$laddrn == $raddrn} {
		return $CONF_RET_T_OK;
	}

	conf_add_script $local "set $addr all"
	return $CONF_RET_T_OK;
}

proc diff.firewall.policy.srcintf {local remote action arg} {
	global CONF_RET_T_OK;
	reset_fw_policy_addr $local $remote $action "srcaddr"
	return $CONF_RET_T_OK;
}

proc diff.firewall.policy.dstintf {local remote action arg} {
	global CONF_RET_T_OK;
	reset_fw_policy_addr $local $remote $action "dstaddr"
	return $CONF_RET_T_OK;
}

proc diff.check_dup_name {rtn remote} {
	set lid [conf_node_name $rtn]
	set rid [conf_node_name $remote]

	if {$lid == $rid} {
		return 0;
	}

	if { [diff_attr_val $rtn $remote "name"] } {
		return 0;
	}

	conf_del_entry $rtn
	return 0
}

proc diff.firewall.policy.name {local remote action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_EDIT;  
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR;  

	if {$action != $CONF_ACT_T_ADD && $action != $CONF_ACT_T_EDIT} {
		return $CONF_RET_T_OK;
	}
	if {!$remote} {
		return $CONF_RET_T_OK;
	}
	set lval [conf_attr_arg $remote 0]
	if { $lval == 0 } {
		return $CONF_RET_T_OK;
	}
	set rparent [conf_node_parent $remote]
	if { $local == 0 } {
		set parent $arg
	} else {
		set parent [conf_node_parent $local]
	}
	set lvvdom [conf_node_root $parent]

	if { $lvvdom == 0 } {
		return $CONF_RET_T_OK;
	}

	set policy_node [conf_find_child $lvvdom "firewall policy"]
	conf_foreach_entry $policy_node diff.check_dup_name $rparent

	return $CONF_RET_T_OK;
}

proc diff.check_zone_exclusive_intf {intf_node vdom_name} {
	if {$intf_node == 0} {
		return
	}

	set vdom [conf_find_vdom $vdom_name]
	if {$vdom == 0} {
		return
	}

	set addr_node [conf_find_child $vdom "firewall address"]
	if {$addr_node != 0} {
		conf_del_dependency $intf_node $addr_node
	}

	set policy_node [conf_find_child $vdom "firewall policy"]
	if {$policy_node != 0} {
		conf_del_dependency $intf_node $policy_node
	}

	set zone_node [conf_find_child $vdom "system zone"]
	if {$zone_node != 0} {
		conf_del_dependency $intf_node $zone_node
	}
}

proc diff.del_sniffer_policy_cb {entry arg} {
	global CONF_RET_T_OK

	set attr [conf_find_child $entry "interface"]
	set intf [string trim [conf_attr_arg $attr 0] \"]
	if { $attr != 0 && $arg == $intf } {
		conf_del_entry $entry;
	}
	return $CONF_RET_T_OK;
}

proc diff.del_sniffer_policy {intf_name vdom_name} {
	global CONF_RET_T_OK
	set vdom [conf_find_vdom $vdom_name]
	if {$vdom == 0} {
		return
	}

	set pol [conf_find_child $vdom "firewall sniffer"];
	if {$pol != 0} {
		conf_foreach_entry $pol diff.del_sniffer_policy_cb $intf_name;
	}
	return $CONF_RET_T_OK;
}

proc diff.system.zone.interface {local remote action arg} {
	global CONF_ACT_T_EDIT CONF_ACT_T_ADD
	global CONF_RET_T_OK

	if {$action != $CONF_ACT_T_EDIT && $action != $CONF_ACT_T_ADD} {
		return $CONF_RET_T_OK;
	}

	set vdom_node [conf_node_root $remote]
	set vdom_name [conf_node_name $vdom_node]

	set argc [conf_attr_argc $remote]
	set largc 0

	if {$local} {
		set largc [conf_attr_argc $local]
		set syszone [conf_node_parent $local]
		conf_set_dep_selfnode $syszone
	}

	set i 0
	while {$i < $argc} {
		set intf_name [conf_attr_arg $remote $i]
		set j 0
		set found 0
		while {$j < $largc} {
			if {$intf_name == [conf_attr_arg $local $j]} {
				set found 1
				break
			}
			incr j
		}
		if {$found == 0} {
			set intf [conf_find_child [conf_global] "system interface"]
			set intf_node [conf_find_child $intf $intf_name]
			diff.check_zone_exclusive_intf $intf_node $vdom_name

			diff.del_sniffer_policy $intf_name $vdom_name
		}
		incr i
	}

	conf_set_dep_selfnode 0 

	return $CONF_RET_T_OK;
}

proc diff.system.zone {local remote action arg} {
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK

	if {$action != $CONF_ACT_T_DELETE} {
		return $CONF_RET_T_OK;
	}

	set vdom_node [conf_node_root $local]
	set vdom_name [conf_node_name $vdom_node]
	set zone_name [conf_node_name $local]

	set sys_zones [conf_find_child $vdom_node "system zone"]
	set zone_node [conf_find_child $sys_zones $zone_name]
	diff.check_zone_exclusive_intf $zone_node $vdom_name

	return $CONF_RET_T_OK;
}

proc diff.firewall.vip.extintf {local remote action arg} {
	global CONF_ACT_T_EDIT
	global CONF_RET_T_OK
	
	if {$action != $CONF_ACT_T_EDIT} {
		return $CONF_RET_T_OK;
	}

	if { $local == 0 } {
		set parent $arg
	} else {
		set parent [conf_node_parent $local]
	}
	set lvvdom [conf_node_root $parent]

	if { $lvvdom == 0 } {
		return $CONF_RET_T_OK;
	}

	set is_added [conf_is_entry_added $parent]
	if { $is_added != 0 } {
		return $CONF_RET_T_OK;
	}

	set policy_node [conf_find_child $lvvdom "firewall policy"]
	if { $policy_node != 0 } {
		conf_del_dependency $parent $policy_node
	}
	set vipgrp_node [conf_find_child $lvvdom "firewall vipgrp"]
	if { $vipgrp_node != 0 } {
		conf_del_dependency $parent $vipgrp_node
	}
	return $CONF_RET_T_OK;
}

proc diff.firewall.vip {local remote action arg} {
	global CONF_ACT_T_EDIT
	global CONF_RET_T_OK
	
	if {$action != $CONF_ACT_T_EDIT} {
		return $CONF_RET_T_OK;
	}

	if { $local == 0 } {
		set parent $arg
	} else {
		set parent [conf_node_parent $local]
	}
	set lvvdom [conf_node_root $parent]

	if { $lvvdom == 0 } {
		return $CONF_RET_T_OK;
	}
	
	set ltype ""
	set rtype ""
	
	set lt [conf_find_attr $local "type"]
	if { $lt != 0 } {
		set ltype [conf_attr_arg $lt 0]
	}
	set rt [conf_find_attr $remote "type"]
	if { $rt != 0 } {
		set rtype [conf_attr_arg $rt 0]
	}
	if { $ltype ne $rtype } {	
		conf_del_entry_self $local		
	}

	return $CONF_RET_T_OK;
}

proc diff.firewall.vipgrp.interface {local remote action arg} {
	global CONF_ACT_T_EDIT
	global CONF_RET_T_OK

	if {$action != $CONF_ACT_T_EDIT} {
		return $CONF_RET_T_OK;
	}

	if { $local == 0 } {
		set parent $arg
	} else {
		set parent [conf_node_parent $local]
	}
	set lvvdom [conf_node_root $parent]

	if { $lvvdom == 0 } {
		return $CONF_RET_T_OK;
	}

	set is_added [conf_is_entry_added $parent]
	if { $is_added != 0 } {
		return $CONF_RET_T_OK;
	}

	set policy_node [conf_find_child $lvvdom "firewall policy"]
	if { $policy_node != 0 } {
		conf_del_dependency $parent $policy_node
	}
	return $CONF_RET_T_OK;
}

proc diff.firewall.address.associated-interface {local remote action arg} {
	global CONF_ACT_T_EDIT CONF_ACT_T_DELETE
	global CONF_RET_T_OK

	if {$action != $CONF_ACT_T_EDIT} {
		return $CONF_RET_T_OK;
	}

	if { $local == 0 } {
		set parent $arg
	} else {
		set parent [conf_node_parent $local]
	}
	set lvvdom [conf_node_root $parent]

	if { $lvvdom == 0 } {
		return $CONF_RET_T_OK;
	}

	set policy_node [conf_find_child $lvvdom "firewall policy"]
	if { $policy_node != 0 } {
		conf_del_dependency $parent $policy_node
	}

	return $CONF_RET_T_OK;
}

proc diff.firewall.address.type {local remote action arg} {
	global CONF_ACT_T_EDIT CONF_ACT_T_DELETE
	global CONF_RET_T_OK

	if {$action != $CONF_ACT_T_EDIT && $action != $CONF_ACT_T_DELETE} {
		return $CONF_RET_T_OK;
	}

	if { $local == 0 } {
		set parent $arg
	} else {
		set parent [conf_node_parent $local]
	}
	set lvvdom [conf_node_root $parent]

	if { $lvvdom == 0 } {
		return $CONF_RET_T_OK;
	}

	set policy_node [conf_find_child $lvvdom "firewall policy"]
	if { $policy_node != 0 } {
		conf_del_dependency $parent $policy_node
	}

	set addrgrp_node [conf_find_child $lvvdom "firewall addrgrp"]
	if { $addrgrp_node != 0 } {
		conf_del_dependency $parent $addrgrp_node
	}

	set vpnssl_node [conf_find_child $lvvdom "vpn ssl settings"]
	if { $vpnssl_node != 0 } {
		conf_del_dependency $parent $vpnssl_node
	}

	return $CONF_RET_T_OK;
}

proc diff.firewall.address.subnet {local remote action arg} {
	# Mantis#0744958: do not update FGT's interface-subnet
	global CONF_RET_T_SKIP CONF_RET_T_OK
	if { $local == 0 } {
		set parent $arg
	} else {
		set parent [conf_node_parent $local]
	}
	set type_attr [conf_find_attr $parent "type"]
	set type [conf_attr_arg $type_attr 0]
	set type [string trim $type \"]
	if { $type eq "interface-subnet" } {
		return $CONF_RET_T_SKIP;
	}
	return $CONF_RET_T_OK;
}

proc peer_remote_group_proc {local remote r_grpname} {
        global CONF_RET_T_OK

        set r_vdname [conf_attr_arg [conf_find_child $remote "vdom"] 0]

        # Find in local config, whether has this vdom and user group
        set l_vdom [conf_find_vdom $r_vdname]
        if { $l_vdom == 0 } {
                set l_grp [conf_find_child [conf_global] "user group"]
        } else {
                set l_grp [conf_find_child $l_vdom "user group"]
        }
        if { $l_grp != 0 } {
                set l_entry [conf_find_child $l_grp $r_grpname]
                if { $l_entry != 0 } {
                        return $CONF_RET_T_OK;
                }
        }

        # Local config dose not have this user group, need add it
        set r_vdom [conf_find_vdom $r_vdname 1]
        if { $r_vdom == 0 } {
                set r_grp [conf_find_child [conf_global 1] "user group"]
        } else {
                set r_grp [conf_find_child $r_vdom "user group"]
        }
        if { $r_grp == 0 } {
                # This must not happen
                return $CONF_RET_T_OK;
        }
        set r_entry [conf_find_child $r_grp $r_grpname]
        if { $r_entry == 0 } {
                # This also must not happen, if happen, means has bug in GUI
                return $CONF_RET_T_OK;
        }

        # Add new entry in local, then merge_entry
        if { $l_grp == 0 } {
                if { $l_vdom == 0 } {
                        set l_grp [conf_add_table [conf_global] $r_grp]
                } else {
                        set l_grp [conf_add_table $l_vdom $r_grp]
                }
        }
        set l_entry [conf_add_entry $l_grp $r_entry]
        conf_merge_entry_edit_chkdep $l_entry $r_entry

        return $CONF_RET_T_OK;
}

proc diff.system.admin {local remote action arg} {
        global CONF_ACT_T_ADD CONF_ACT_T_EDIT
        global CONF_ACT_T_DELETE
        global CONF_RET_T_OK

	if { $action == $CONF_ACT_T_DELETE } {
		set r_admin [conf_find_child [conf_global 1] "system admin"]
		set l_admin [conf_find_child [conf_global 0] "system admin"]
		set list {}
		conf_foreach_entry $r_admin build-list list
		foreach r_e $list {
			set r_name [conf_node_name $r_e]
			set l_e [conf_find_child $l_admin $r_name]
			if { $l_e == 0 } {
				set l_e [conf_add_entry $l_admin $r_e]
				conf_merge_entry_edit_chkdep $l_e $r_e
			}
		}
		return $CONF_RET_T_OK
	}

        if { $action != $CONF_ACT_T_ADD && $action != $CONF_ACT_T_EDIT } {
                return $CONF_RET_T_OK;
        }

        set r_remote_auth [conf_attr_arg [conf_find_attr $remote "remote-auth"] 0]
        if { $r_remote_auth == "enable" } {
		set r_grpname [conf_attr_arg [conf_find_child $remote "remote-group"] 0]
		peer_remote_group_proc $local $remote $r_grpname
	}
        set r_peer_auth [conf_attr_arg [conf_find_attr $remote "peer-auth"] 0]
        if { $r_peer_auth == "enable" } {
		set r_grpname [conf_attr_arg [conf_find_child $remote "peer-group"] 0]
		peer_remote_group_proc $local $remote $r_grpname
        }
	return $CONF_RET_T_OK;
}

proc deldep_system_admin {entry usrgrp} {
        global CONF_RET_T_OK

	set vdnode [conf_node_root $usrgrp]
	if { $vdnode == 0 } {
                return $CONF_RET_T_OK
	}
	set vdname2 [conf_node_name $vdnode]
	set vdname2 [string trim $vdname2 \"]

	set vdname1 [conf_attr_arg [conf_find_attr $entry "vdom"] 0]
	set vdname1 [string trim $vdname1 \"]

	if { $vdname1 != $vdname2 } {
		return $CONF_RET_T_OK
	}

        set grpname [conf_node_name $usrgrp]
        if { $grpname == 0 } {
                return $CONF_RET_T_OK
        }
        set grpname [string trim $grpname \"]

        set lvpeer [conf_find_attr $entry "peer-auth"]
        if { $lvpeer != 0 } {
                set peer_auth [conf_attr_arg $lvpeer 0]
                if { $peer_auth eq "enable" } {
                        set peer_grpname [conf_attr_arg [conf_find_attr $entry "peer-group"] 0]
                        set peer_grpname [string trim $peer_grpname \"]
                        if { $peer_grpname == $grpname } {
                                conf_del_entry $entry
                        }
                }
        }
}

proc usrgrp_is_in_use {admin usrgrp} {
	set list {}
        set grpname [conf_node_name $usrgrp]
        if { $grpname == 0 } {
                return 0
        }
        set grpname [string trim $grpname \"]
        conf_foreach_entry $admin build-list list
	foreach e $catlist {
        	set lvremote [conf_find_attr $e "remote-auth"]
		if { $lvremote != 0 } {
                	set remote_auth [conf_attr_arg $lvremote 0]
	                if { $remote_auth eq "enable" } {
        	                set remote_grpname [conf_attr_arg [conf_find_attr $e "remote-group"] 0]
                	        set remote_grpname [string trim $remote_grpname \"]
                        	if { $remote_grpname == $grpname } {
                                	return 1
	                        }
        	        }
        	}
	}
	return 0
}

proc diff.user.group {local remote action arg} {
        global CONF_ACT_T_DELETE
        global CONF_RET_T_OK CONF_RET_T_DONT

        if { $action != $CONF_ACT_T_DELETE } {
                return $CONF_RET_T_OK
        }

        set admin [conf_find_child [conf_global 0] "system admin"]
	set is_used [usrgrp_is_in_use $admin $local]
	if { $is_used == 1 } {
		return $CONF_RET_T_DONT
	}
        conf_foreach_entry $admin deldep_system_admin $local
        return $CONF_RET_T_OK
}

proc diff.system.vdom-property {local remote action arg} {
        global CONF_RET_T_OK CONF_RET_T_DONT
        return $CONF_RET_T_DONT
}

proc diff_attr_val {e1 e2 attr_name} {
	set a1 [conf_find_child $e1 $attr_name]
	if {$a1 == 0} {
		set v1 0
	} else {
		set v1 [conf_attr_arg $a1 0]
	}
	set a2 [conf_find_child $e2 $attr_name]
	if {$a2 == 0} {
		set v2 0
	} else {
		set v2 [conf_attr_arg $a2 0]
	}
	if {$v1 ne $v2} {
		return 1
	}
	return 0
}

proc diff.check_dup_usr_dev {rtn remote} {
	set lalias [conf_node_name $rtn]
	set ralias [conf_node_name $remote]

	if {$lalias == $ralias} {
		return 0;
	}

	if { [diff_attr_val $rtn $remote "mac"] } {
		return 0;
	}

	conf_force_del_entry $rtn
	return 0
}

proc diff.purge_node {node arg} {
	conf_del_entry $node
}

proc get_ha_unicast_peerip { remote } {
	set peerip ""
	set sysha [conf_find_child [conf_global $remote] "system ha"]
	if { $sysha } {
		set hb_en [conf_find_attr $sysha "unicast-hb"]
		if { $hb_en } {
			if { [conf_attr_arg $hb_en 0] eq "enable" } {
				set hb_peerip [conf_find_attr $sysha "unicast-hb-peerip"]
				if { $hb_peerip } {
					set peerip [conf_attr_arg $hb_peerip 0]
				}
			}
		}
	}
	return $peerip
}

proc diff.system.interface.ip {handle nentry action arg} {
	global CONF_RET_T_DONT CONF_RET_T_OK CONF_ACT_T_EDIT
	set parent [conf_node_parent $nentry]
	set vdom [conf_attr_arg [conf_find_child $parent "vdom"] 0]
	set vdom [string trim $vdom \"]
	if {$vdom eq "elbc-mgmt"} {
		return $CONF_RET_T_DONT;
	}
	set name [conf_node_name $parent]
	set name [string trim $name \"]
	set intfs {"base-mgmt" "elbc-base-ctrl" "elbc-ctrl/1" "elbc-ctrl/2"}
	foreach e $intfs {
		if {$name eq $e} {
			return $CONF_RET_T_DONT;
		}
	}

	if { $action == $CONF_ACT_T_EDIT } {
		set intf_ip [conf_attr_arg $nentry 0]
		set peerip0 [get_ha_unicast_peerip 0]
		set peerip1 [get_ha_unicast_peerip 1]
		 if { $intf_ip ne "" && ($intf_ip eq $peerip0 || $intf_ip eq $peerip1) } {
			return $CONF_RET_T_DONT
		}
	}

	return $CONF_RET_T_OK;
}

proc diff.system.interface.management-ip {handle nentry action arg} {
	global CONF_RET_T_DONT CONF_RET_T_OK

	set sysha [conf_find_child [conf_global 1] "system ha"]
	if { $sysha == 0 } {
                return $CONF_RET_T_OK
        }
	set hamode [conf_find_attr $sysha "mode"]
	if { $hamode == 0} {
                return $CONF_RET_T_OK
        }
	set mode [conf_attr_arg $hamode 0]
	if { $mode ne "standalone" } {
		return $CONF_RET_T_DONT;
	}
	return $CONF_RET_T_OK;
}

proc diff.md5-key.equal {lmd5 rmd5} {
	set lmd5 [string trim $lmd5 \"]
	set rmd5 [string trim $rmd5 \"]
	set llist [split $lmd5 " "]
	set rlist [split $rmd5 " "]
	if { [llength $llist] eq 2 } {
		set lmd5 [cli_get_devinfo "ospf_md5_key" "decode" [lindex $llist 1]]
	}
	if { [llength $rlist] eq 2 } {
		set rmd5 [cli_get_devinfo "ospf_md5_key" "decode" [lindex $rlist 1]]
	}
	if { $lmd5 eq $rmd5 } {
		return 1
	}
	return 0
}

proc diff.manual-key.equal {lmd5 lq rmd5 rq} {
        set lmd5 [string trim $lmd5 \"]
        set rmd5 [string trim $rmd5 \"]
	if { $lq eq 1 } {
		set n "\'ENC "
		append n $lmd5
		append n "\'"
		set lmd5 $n
	}
	if { $rq eq 1 } {
		set n "\'ENC "
		append n $rmd5
		append n "\'"
		set rmd5 $n
	}
        if { ![string compare -length 5 $lmd5 "\'ENC "] } {
                set lmd5 [cli_get_devinfo "ipsec_manualkey" "decode" $lmd5]
        }
        if { ![string compare -length 5 $rmd5 "\'ENC "] } {
                set rmd5 [cli_get_devinfo "ipsec_manualkey" "decode" $rmd5]
        }
        if { $lmd5 eq $rmd5 } {
                return 1
        }
        return 0
}
proc diff.manual-key.common.compare {local remote action arg} {
        global CONF_RET_T_SKIP CONF_RET_T_OK
        if { $local && $remote } {
                set lmd5 [conf_attr_arg $local 0]
                set rmd5 [conf_attr_arg $remote 0]
		set lq [conf_enc_quoted $local]
		set rq [conf_enc_quoted $remote]
                if { [diff.manual-key.equal $lmd5 $lq $rmd5 $rq] } {
                        return $CONF_RET_T_SKIP
                }
        }
        return $CONF_RET_T_OK
}

proc diff.certificate.local.password {lattr rattr action arg} {
        global CONF_RET_T_OK CONF_RET_T_SKIP CONF_ACT_T_DELETE
	if { [conf_diff_is_factory_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	if { $action == $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_SKIP
	}
	return $CONF_RET_T_OK
}

proc diff.certificate.local.password._skip {lattr rattr action arg} {
	return [diff.certificate.local.password $lattr $rattr $action $arg]
}

proc diff.certificate.local.private-key {lattr rattr action arg} {
	global CONF_RET_T_SKIP
	if { [conf_diff_is_factory_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	if { [conf_diff_is_scep_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return [cert_private_key_compare $lattr $rattr $action $arg]
}

proc diff.certificate.local.private-key._skip {lattr rattr action arg} {
	return [diff.certificate.local.private-key $lattr $rattr $action $arg]
}

proc diff.certificate.local.certificate {lattr rattr action arg} {
	global CONF_RET_T_SKIP
	if { [conf_diff_is_scep_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return [conf_diff_is_factory_cert $lattr $rattr $action $arg]
}

proc diff.certificate.local.certificate._skip {lattr rattr action arg} {
	return [diff.certificate.local.certificate $lattr $rattr $action $arg]
}

proc diff.certificate.local.csr {lattr rattr action arg} {
	global CONF_RET_T_OK CONF_RET_T_SKIP
	if { [conf_diff_is_scep_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return $CONF_RET_T_OK
}

proc diff.certificate.local.csr._skip {lattr rattr action arg} {
	return [diff.certificate.local.csr $lattr $rattr $action $arg]
}

proc diff.vpn.certificate.local.password {lattr rattr action arg} {
        global CONF_RET_T_OK CONF_RET_T_SKIP CONF_ACT_T_DELETE
	if { [conf_diff_is_factory_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	if { $action == $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_SKIP
	}
	return $CONF_RET_T_OK
}

proc diff.vpn.certificate.local.password._skip {lattr rattr action arg} {
	return [diff.vpn.certificate.local.password $lattr $rattr $action $arg]
}

proc diff.vpn.certificate.local.private-key {lattr rattr action arg} {
	global CONF_RET_T_SKIP
	if { [conf_diff_is_factory_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	if { [conf_diff_is_scep_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return [cert_private_key_compare $lattr $rattr $action $arg]
}

proc diff.vpn.certificate.local.private-key._skip {lattr rattr action arg} {
	return [diff.vpn.certificate.local.private-key $lattr $rattr $action $arg]
}

proc diff.vpn.certificate.local.certificate {lattr rattr action arg} {
	global CONF_RET_T_SKIP
	if { [conf_diff_is_scep_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return [conf_diff_is_factory_cert $lattr $rattr $action $arg]
}

proc diff.vpn.certificate.local.certificate._skip {lattr rattr action arg} {
	return [diff.vpn.certificate.local.certificate $lattr $rattr $action $arg]
}

proc diff.vpn.certificate.local.csr {lattr rattr action arg} {
	global CONF_RET_T_OK CONF_RET_T_SKIP
	if { [conf_diff_is_scep_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return $CONF_RET_T_OK
}

proc diff.vpn.certificate.local.csr._skip {lattr rattr action arg} {
	return [diff.vpn.certificate.local.csr $lattr $rattr $action $arg]
}

proc diff.certificate.ca.ca {lattr rattr action arg} {
	return [conf_diff_is_scep_cert $lattr $rattr $action $arg]
}

proc diff.certificate.ca.ca._skip {lattr rattr action arg} {
	return [conf_diff_is_scep_cert $lattr $rattr $action $arg]
}

proc diff.vpn.certificate.ca.ca {lattr rattr action arg} {
	return [conf_diff_is_scep_cert $lattr $rattr $action $arg]
}

proc certificate_skip_scep_crl {lattr rattr action arg} {
        global CONF_ACT_T_DELETE CONF_RET_T_OK CONF_RET_T_SKIP;  

	set v1 [conf_get_var "is_autoupdate"]
	if { $v1 && $v1 eq "1" } {
        	return $CONF_RET_T_OK
	}

        if {!$lattr && !$rattr} {
        	return $CONF_RET_T_OK
	}

        if { $lattr } {
		set e [conf_node_parent $lattr]
	} else {
		if { $action == $CONF_ACT_T_DELETE } {
			set e $rattr
		} else {
			set e [conf_node_parent $rattr]
		}
	}

	set s [conf_find_attr $e "scep-url"]
	set h [conf_find_attr $e "http-url"]
	set l [conf_find_attr $e "ldap-server"]
	if { ($l && ([conf_attr_arg $l 0] ne "")) ||
	     ($h && ([conf_attr_arg $h 0] ne "")) ||
	     ($s && ([conf_attr_arg $s 0] ne "")) } {
		return $CONF_RET_T_SKIP
	}

	return $CONF_RET_T_OK
}

proc diff.certificate.crl.crl {lattr rattr action arg} {
	return [certificate_skip_scep_crl $lattr $rattr $action $arg]
}

proc diff.certificate.crl.crl._skip {lattr rattr action arg} {
	return [certificate_skip_scep_crl $lattr $rattr $action $arg]
}

proc diff.log-threat-weight-cate-check {node cate} {
	set cate2 [conf_attr_arg [conf_find_attr $node "category"] 0]
	if { $cate2 eq $cate } {
		conf_del_entry $node
	}
	return $CONF_RET_T_OK
}

proc diff.log.threat-weight.web.category {local remote action arg} {
	global CONF_ACT_T_EDIT
	global CONF_RET_T_OK

	if { $action != $CONF_ACT_T_EDIT } {
		return $CONF_RET_T_OK
	}

	set cate [conf_attr_arg $remote 0]
	set list [conf_find_child [conf_node_parent [conf_node_parent [conf_node_parent $local]]] "web"]
	conf_foreach_entry $list diff.log-threat-weight-cate-check $cate

	return $CONF_RET_T_OK
}

proc diff.log.threat-weight.application.category {local remote action arg} {
	global CONF_ACT_T_EDIT
	global CONF_RET_T_OK

	if { $action != $CONF_ACT_T_EDIT } {
		return $CONF_RET_T_OK
	}

	set cate [conf_attr_arg $remote 0]
	set list [conf_find_child [conf_node_parent [conf_node_parent [conf_node_parent $local]]] "application"]
	conf_foreach_entry $list diff.log-threat-weight-cate-check $cate

	return $CONF_RET_T_OK
}

proc diff.log.threat-weight.geolocation.category {local remote action arg} {
	global CONF_ACT_T_EDIT
	global CONF_RET_T_OK

	if { $action != $CONF_ACT_T_EDIT } {
		return $CONF_RET_T_OK
	}

	set cate [conf_attr_arg $remote 0]
	set list [conf_find_child [conf_node_parent [conf_node_parent [conf_node_parent $local]]] "geolocation"]
	conf_foreach_entry $list diff.log-threat-weight-cate-check $cate

	return $CONF_RET_T_OK
}

proc attr_cmp {local remote attr} {
	set lattr [conf_find_attr $local $attr]
	set rattr [conf_find_attr $remote $attr]
	if { $rattr eq $lattr } {	## both not exist
		return 0
	} elseif { !$lattr || !$rattr } {
		return 1
	} else {
		return [conf_attr_comp $lattr $rattr]
	}
}

proc diff.vwl-member-check {node seq} {
	set member [conf_attr_arg [conf_find_attr $node "member"] 0]
	if { $member eq $seq } {
		conf_del_entry $node
	}

	set attr [conf_find_attr $node "priority-members"]
	if { $attr ne 0 } {
		set argc [conf_attr_argc $attr]
		set i 0
		while { $i < $argc } {
			set member [conf_attr_arg $attr $i]
			if { $member eq $seq } {
				conf_del_entry $node
				break
			}
			incr i
		}
	}
}

proc diff.vwl-member-pol-check {node name} {
	set attr [conf_find_attr $node "srcintf"]
	if { $attr ne 0 } {
		set intf [string trim [conf_attr_arg $attr 0] \"]
		if { $intf eq $name } {
			conf_del_entry $node
		}
	}
	set attr [conf_find_attr $node "dstintf"]
	if { $attr ne 0 } {
		set intf [string trim [conf_attr_arg $attr 0] \"]
		if { $intf eq $name } {
			conf_del_entry $node
		}
	}
}

proc diff.vwl-health-check {node name} {
	set mode [conf_attr_arg [conf_find_attr $node "mode"] 0]
	if { $mode eq "auto" || $mode eq "priority" } {
		set hcname [conf_attr_arg [conf_find_attr $node "health-check"] 0]
		if { $name eq [string trim $hcname \"] } {
			conf_del_entry $node
		}
	} elseif { $mode eq "sla" } {
		set sla_node [conf_find_child $node "sla"]
		set list {}
		conf_foreach_entry $sla_node build-list list
		foreach sla $list {
			set hcname [conf_node_name $sla]
			if { $name eq [string trim $hcname \"] } {
				conf_del_entry $node
				break
			}
		}
	}
}

proc app_cus_get_attr_value { attr sig } {
	set t [string first $attr $sig]
	if { $t == -1 } {
		return ""
	}
	set start [expr $t + [string length $attr]]
	set sig [string range $sig $start [string length $sig]]
	set sig [string trimleft $sig]
	set sig [regsub -all {\\\"} $sig "\""]
	if {[string index $sig 0] eq "\""} {
		set sig [string range $sig 1 [expr [string length $sig] - 1]]
		set t [string first "\"" $sig]
		if { $t == -1 } {
			return ""
		}
		set sig [string range $sig 0 [expr $t - 1]]
	} else {
		set t [string first ";" $sig 0]
		if { $t == -1 } {
			set t [string first ")" $sig 0]
			if { $t == -1 } {
				return ""
			}
		}
		set sig [string range $sig 0 $t]
		set sig [regsub {[\s\);]} $sig ""]
	}
	return $sig
}

proc diff.signature.app {lentry rattr} {
	global CONF_RET_T_OK

	set rentry [conf_node_parent $rattr]
	set rname [conf_node_name $rentry]
	set rcate [conf_node_name [conf_node_parent $rentry]]
	set rvdom [conf_node_name [conf_node_root $rentry]]
	set rsig [conf_attr_arg $rattr 0]
	set rvid [app_cus_get_attr_value "--vuln_id " $rsig]
	set raid [app_cus_get_attr_value "--attack_id " $rsig]

	set lname [conf_node_name $lentry]
	set lcate [conf_node_name [conf_node_parent $lentry]]
	set lvdom [conf_node_name [conf_node_root $lentry]]
	set lattr [conf_find_attr $lentry "signature"]
	set lvid 0
	set laid 0

	if { $lattr ne 0 } {
		set lsig [conf_attr_arg $lattr 0]
		set lvid [app_cus_get_attr_value "--vuln_id " $lsig]
		set laid [app_cus_get_attr_value "--attack_id " $lsig]
	}

	if { $rname eq $lname && $rcate eq $lcate && $rvdom eq $lvdom } {
		## if same node, FGT doesn't support swapping attack_id and vuln_id values
		if { $rvid ne "" && $rvid ne 0 && $rvid eq $laid } {
			conf_del_entry_self $lentry
		} elseif { $raid ne "" && $raid ne 0 && $raid eq $lvid } {
			conf_del_entry_self $lentry
		}
	} elseif { $rvid ne "" && $rvid ne 0 && ($rvid eq $lvid || $rvid eq $laid) } {
		conf_del_entry_self $lentry
	} elseif { $raid ne "" && $raid ne 0 && $raid eq $laid } {
		## if there is vuln_id, then attack_id can be duplicated
		if { $rvid eq "" || $rvid eq 0 || $lvid eq "" || $lvid eq 0 } {
			conf_del_entry_self $lentry
		}
	} elseif { $raid ne "" && $raid ne 0 && $raid eq $lvid } {
		conf_del_entry_self $lentry
	}

	return $CONF_RET_T_OK
}

proc diff.signature.vdom {vdom rattr} {
	global CONF_RET_T_OK 

	set cus [conf_find_child $vdom "application custom"];
	if { $cus ne 0 } {
		conf_foreach_entry $cus diff.signature.app $rattr;
	}

	set cus [conf_find_child $vdom "ips custom"];
	if { $cus ne 0 } {
		conf_foreach_entry $cus diff.signature.app $rattr;
	}

	return $CONF_RET_T_OK
}

proc diff.application.custom.signature {lattr rattr action arg} {
	global CONF_ACT_T_EDIT
	global CONF_RET_T_OK CONF_RET_T_ERROR

	if { $action != $CONF_ACT_T_EDIT } {
		return $CONF_RET_T_OK;
	}

	conf_foreach_entry [conf_vdom] diff.signature.vdom $rattr;

	return $CONF_RET_T_OK
}

proc diff.ips.custom.signature {lattr rattr action arg} {
	global CONF_ACT_T_EDIT
	global CONF_RET_T_OK CONF_RET_T_ERROR

	if { $action != $CONF_ACT_T_EDIT } {
		return $CONF_RET_T_OK;
	}

	conf_foreach_entry [conf_vdom] diff.signature.vdom $rattr;

	return $CONF_RET_T_OK
}

proc diff.system.vdom {local remote action arg} {
	global CONF_RET_T_DONT
	return $CONF_RET_T_DONT
}

proc diff.rename.shaping-entries {remote local} {
	global CONF_RET_T_OK
	set rclass_id_attr [conf_find_attr $remote "class-id"]
	if { $rclass_id_attr == 0 } {
		return $CONF_RET_T_OK
	}
	set rclass_id [conf_attr_arg $rclass_id_attr 0]
	set lclass_id_attr [conf_find_attr $local "class-id"]
	if { $lclass_id_attr == 0 } {
		return $CONF_RET_T_OK
	}
	set lclass_id [conf_attr_arg $lclass_id_attr 0]
	set cmpresult [conf_strcmp $rclass_id $lclass_id]
	if { $cmpresult == 0 } {
		conf_rename_entry $local $remote
	}
	return $CONF_RET_T_OK;
}

proc diff.firewall.shaping-profile.shaping-entries {local remote action arg} {
	global CONF_ACT_T_DELETE CONF_RET_T_OK CONF_RET_T_DONT
	if { $action != $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_OK
	}
	set lprof [conf_node_parent [conf_node_parent $local]]
	set dclass_id_attr [conf_find_attr $lprof "default-class-id"]
	if { $dclass_id_attr == 0 } {
		return $CONF_RET_T_OK
	}
	set dclass_id [conf_attr_arg $dclass_id_attr 0]
	set prof_name [conf_node_name $lprof]
	set lvdom [conf_node_root $local]
	if { $lvdom == 0 } {
		return $CONF_RET_T_OK;
	}
	set vdom_name [conf_node_name $lvdom]
	set rvdom [conf_find_vdom $vdom_name 1]
	if { $rvdom == 0 } {
		return $CONF_RET_T_OK;
	}
	set rprofl [conf_find_child $rvdom "firewall shaping-profile"]
	set rprof [conf_find_child $rprofl $prof_name]
	if { $rprof == 0 } {
		return $CONF_RET_T_OK;
	}
	set rclass_id_attr [conf_find_attr $rprof "default-class-id"]
	if { $rclass_id_attr == 0 } {
		return $CONF_RET_T_OK
	}
	set rdclass_id [conf_attr_arg $rclass_id_attr 0]
	set cmpresult [conf_strcmp $dclass_id $rdclass_id]
	if { $cmpresult != 0 } {
		conf_set_attr $dclass_id_attr $rdclass_id
	}
	set class_id_attr [conf_find_attr $local "class-id"]
	if { $class_id_attr == 0 } {
		return $CONF_RET_T_OK
	}
	set class_id [conf_attr_arg $class_id_attr 0]
	set cmpresult [conf_strcmp $class_id $rdclass_id]
	if { $cmpresult == 0 } {
		set rentries [conf_find_child $rprof "shaping-entries"]
		if { $rentries == 0 } {
			return $CONF_RET_T_OK;
		}
		conf_foreach_entry $rentries diff.rename.shaping-entries $local;
		return $CONF_RET_T_DONT
	}
	return $CONF_RET_T_OK
}

proc shift_certs_ahead_global_usage {remote attr cate} {
	set cert [conf_attr_arg [conf_find_attr $remote $attr] 0]
	set cert [string trim $cert "\""]
	if { $cert ne "" } {
		set r_global [conf_global 1]
		set l_global [conf_global 0]
		set rcerts [conf_find_child $r_global $cate]
		set lcerts [conf_find_child $l_global $cate]
		if { $lcerts == 0 } {
			set lcerts [conf_add_table $l_global $rcerts]
		}
		set rentry [conf_find_child $rcerts $cert]
		set lentry [conf_find_child $lcerts $cert]
		if { $lentry == 0 } {
			set lentry [conf_add_entry $lcerts $rentry]
		}
		conf_merge_entry_edit_chkdep $lentry $rentry
	}
}
proc diff.system.global {local remote action arg} {
	global CONF_RET_T_OK
		shift_certs_ahead_global_usage $remote "admin-server-cert" "certificate local"
		shift_certs_ahead_global_usage $remote "auth-cert" "certificate local"
		shift_certs_ahead_global_usage $remote "user-server-cert" "certificate local"
		shift_certs_ahead_global_usage $remote "wifi-certificate" "certificate local"
		shift_certs_ahead_global_usage $remote "wifi-ca-certificate" "certificate ca"
	return $CONF_RET_T_OK
}

proc skip_phase2_encapsulation {lattr rattr action arg} {
    global CONF_ACT_T_DELETE CONF_RET_T_OK CONF_RET_T_DONT
    if { $action != $CONF_ACT_T_DELETE } {
        return $CONF_RET_T_OK
    }
	if { $lattr } {
		set le [conf_node_parent $lattr]
	}
	set re $rattr
	set lencap [conf_find_attr $le "encapsulation"]
	set rencap [conf_find_attr $re "encapsulation"]
	if { $lencap && $rencap } {
		set lval [conf_attr_arg $lencap 0]
		set rval [conf_attr_arg $rencap 0]
		if {$lval == "transport-mode" && $rval == "transport-mode" } {
			return $CONF_RET_T_DONT
		}
	}
    return $CONF_RET_T_OK
}
proc diff.vpn.ipsec.phase2-interface.src-start-ip {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.src-end-ip {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.src-subnet {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.src-name {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.src-name6 {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.src-start-ip6 {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.src-endip6 {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.src-addr-type {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.dst-start-ip {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.dst-end-ip {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.dst-subnet {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.dst-name {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.dst-name6 {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.dst-start-ip6 {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.dst-endip6 {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}
proc diff.vpn.ipsec.phase2-interface.dst-addr-type {lattr rattr action arg} {
	return [skip_phase2_encapsulation $lattr $rattr $action $arg]
}

proc diff.firewall.internet-service-name {local remote action arg} {
	global CONF_RET_T_OK CONF_RET_T_DONT

	set lt [conf_find_attr $local "type"]
	if { $lt != 0 } {
		set ltype [conf_attr_arg $lt 0]
		if { $ltype != "default" } {
			return $CONF_RET_T_OK
		}
	}
	return $CONF_RET_T_DONT
}

proc normalize_ipv6_addr {addr} {
	set ret $addr
	if { [regexp {^::\d+\.\d+\.\d+\.\d+} $addr] } {
		set subs [regexp -inline -all {\d+} $addr]
		set mask 128
		if { [llength $subs] == 5 } {
			set mask [lindex $subs 4]
		}
		set hex0 [format %x [lindex $subs 0]]
		set hex1 [format %02x [lindex $subs 1]]
		set hex2 [format %x [lindex $subs 2]]
		set hex3 [format %02x [lindex $subs 3]]
		set ret "::$hex0$hex1:$hex2$hex3/$mask"
	}
	return $ret
}

proc diff.system.interface.ipv6.ip6-extra-addr { local remote action arg } {
## since v6.2.1, FOS force convert "::192.168.141.165/120" to "::c0a8:8da5/120"
## $local is fgt config, remote is device db config
	global CONF_ACT_T_ADD CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_SKIP

	if { $remote == 0 || $action == $CONF_ACT_T_DELETE } {
## $remote is 0 when action is delete
## so we need to go through from parent interface node
		set lprefix [conf_node_name $local]
		set lprefix [normalize_ipv6_addr $lprefix]
		set lip6_extra_addr [conf_node_parent $local]
		set lipv6 [conf_node_parent $lip6_extra_addr]
		set lintf [conf_node_parent $lipv6]
		set lintfname [string trim [conf_node_name $lintf] \"]

## find the remote parent interface node
		set rintf [conf_find_child [conf_find_child [conf_global 1] "system interface"] $lintfname]
		set ripv6 [conf_find_child $rintf "ipv6"]
		set rip6_extra_addr_list [cli_get_tbl_list $ripv6 "ip6-extra-addr"]
		foreach rip6_extra_addr $rip6_extra_addr_list {
			set rprefix [conf_node_name $rip6_extra_addr]
			set rprefix [normalize_ipv6_addr $rprefix]
			if { $rprefix eq $lprefix } {
				return $CONF_RET_T_SKIP
			}
		}
	}
	if { $local == 0 || $action == $CONF_ACT_T_ADD } {
## $local is 0 (or parent node) when action is add
## so we need to go through from parent interface node
		set rprefix [conf_node_name $remote]
		set rprefix [normalize_ipv6_addr $rprefix]
		set rip6_extra_addr [conf_node_parent $remote]
		set ripv6 [conf_node_parent $rip6_extra_addr]
		set rintf [conf_node_parent $ripv6]
		set rintfname [string trim [conf_node_name $rintf] \"]

## find the local parent interface node
		set lintf [conf_find_child [conf_find_child [conf_global 0] "system interface"] $rintfname]
		set lipv6 [conf_find_child $lintf "ipv6"]
		set lip6_extra_addr_list [cli_get_tbl_list $lipv6 "ip6-extra-addr"]
		foreach lip6_extra_addr $lip6_extra_addr_list {
			set lprefix [conf_node_name $lip6_extra_addr]
			set lprefix [normalize_ipv6_addr $lprefix]
			if { $rprefix eq $lprefix } {
				return $CONF_RET_T_SKIP
			}
		}
	}
	return $CONF_RET_T_OK
}
proc diff.system.ntp.interface {lattr rattr action arg} {
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR
	if { $action == $CONF_ACT_T_DELETE } {
		set server_mode [conf_find_attr [conf_node_parent $lattr] "server-mode"]
		conf_unset_attr $server_mode
		return $CONF_RET_T_DONT
	}
	return $CONF_RET_T_OK
}
%}
