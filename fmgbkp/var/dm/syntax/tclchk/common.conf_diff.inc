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

proc conf_diff_nochg_allowed {local remote action arg} {
        global CONF_RET_T_OK CONF_RET_T_SKIP
        if { $remote } {
                set rp [conf_node_parent $remote]
                set rpnm [conf_node_name $rp]
                set rpnm [string trim $rpnm \"]
                if {$rpnm eq "Fortinet_CA_SSLProxy" || $rpnm eq "Fortinet_Firmware" || $rpnm eq "Fortinet_SSLProxy" || $rpnm eq "Fortinet_Wifi" } {
                        return $CONF_RET_T_SKIP
                }
        }
        return $CONF_RET_T_OK
}

proc conf_diff_is_factory_cert {lattr rattr action arg} {
        global CONF_RET_T_OK CONF_RET_T_SKIP;  

	set v [cli_get_devinfo "version"]
	set b [cli_get_devinfo "branch"]

	if { $v eq 500 && $b <= 727 } {
		return [conf_diff_nochg_allowed $lattr $rattr $action $arg]
	}

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

	if {!$lattr || !$rattr} {
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

proc diff.wireless-controller.vap.access-control-list {local remote action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_EDIT CONF_ACT_T_DELETE;
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR;

	if { $action != $CONF_ACT_T_ADD && $action != $CONF_ACT_T_EDIT } {
		return $CONF_RET_T_OK;
	}

	set name [conf_attr_arg $remote 0]
	if { $name == "" } {
		return $CONF_RET_T_OK;
	}

	set rparent [conf_node_parent $remote]
	set rvdom [conf_node_root $rparent]
	if { $rvdom == 0 } {
		return $CONF_RET_T_OK;
	}
	if { $local == 0 } {
		set parent $arg
	} else {
		set parent [conf_node_parent $local]
	}
	set lvdom [conf_node_root $parent]
	if { $lvdom == 0 } {
		return $CONF_RET_T_OK;
	}

	set raclst [conf_find_child $rvdom "wireless-controller access-control-list"]
	set laclst [conf_find_child $lvdom "wireless-controller access-control-list"]
	set rentry [conf_find_child $raclst $name]
	set lentry [conf_find_child $laclst $name]
	if { $lentry == 0 } {
		### new entry, need to move wireless_controller_access_control_list before "wireless_controller_vap
		set lentry [conf_add_entry $laclst $rentry]
	}
	conf_merge_entry_edit_chkdep $lentry $rentry
	return $CONF_RET_T_OK;
}

proc diff.wireless-controller.vap {local remote action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_EDIT CONF_ACT_T_DELETE;
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR;

	if { $action == $CONF_ACT_T_DELETE } {
		set name [conf_node_name $local]
		set vdom [conf_attr_arg [conf_find_attr $local "vdom"] 0]
		set vdom [string trim $vdom \"]
		set vapname "mesh.$vdom"
		set cmpresult [conf_strcmp $vapname $name]
		if { $cmpresult == 0 } {
			return $CONF_RET_T_DONT;
 		}
		return $CONF_RET_T_OK;
	}
	set ver [cli_get_devinfo "version"]
	set mr [cli_get_devinfo "mr"]
	if { $ver > 600 || ($ver == 600 && $mr >= 2) } {
		set vdnode [conf_node_root $remote]
		if { $vdnode } {
			set vdname [conf_node_name $vdnode]
			set rvdom [conf_find_vdom $vdname 1]
			set lvdom [conf_find_vdom $vdname]
			if { $rvdom && $lvdom } {
				set rset [conf_find_child $rvdom "wireless-controller setting"]
				set lset [conf_find_child $lvdom "wireless-controller setting"]
				if { $lset && $rset } {
					conf_merge_entry_edit $lset $rset
				}
			}
		}
	}
	return $CONF_RET_T_OK;
} 

proc diff.wireless-controller.wtp-profile.handoff-sta-thresh {local remote action arg} {
	global CONF_ACT_T_EDIT;
	global CONF_RET_T_OK CONF_RET_T_SKIP;

	if { $action == $CONF_ACT_T_EDIT } {
		set ver [cli_get_devinfo "version"]
		set br [cli_get_devinfo "branch"]

		if { $ver > 600 || ($ver eq 600 && $br >= 200) } {
			set r_ho_sta [conf_attr_arg $remote 0]
			if { $r_ho_sta == 0 } {
				return $CONF_RET_T_SKIP;
			}
		}
	}
	return $CONF_RET_T_OK;
}

proc build-list {node l} {
	upvar $l list
	lappend list $node
}

proc diff.system.interface {handle nentry action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_DELETE;
	global CONF_ACT_T_EDIT CONF_ACT_T_MOVE;  
	global CONF_ACT_T_CLEAR CONF_ACT_T_UNSET;
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR;  

	set ver [cli_get_devinfo "version"]
	set mr [cli_get_devinfo "mr"]

	# ACT_DELETE: handle is local entry, nentry is NULL;
	if { $action == $CONF_ACT_T_DELETE } {
		set name [conf_node_name $handle]
		set elbc [conf_find_child [conf_global 1] "system elbc"]
		if { $elbc } {
			set mode [conf_attr_arg [conf_find_attr $elbc "mode"] 0]
			if {$mode ne "service-group"} {
				return $CONF_RET_T_OK;
			}
		}
		set vdom [conf_attr_arg [conf_find_attr $handle "vdom"] 0]
		set vdom [string trim $vdom \"]
		if {$vdom eq "elbc-mgmt"} {
			return $CONF_RET_T_DONT;
		}

		set type [conf_attr_arg [conf_find_child $handle "type"] 0]
		if { $type eq "wireless" } {
			set wireless [conf_find_child [conf_global 1] "system wireless settings"]
			set wlmode [conf_attr_arg [conf_find_attr $wireless "mode"] 0]
			if { $wlmode eq "SCAN" } {
				return $CONF_RET_T_DONT;
			}
		} elseif { $type eq "vdom-link" } {
			set end [expr [string length $name] - 3]
			set linkname [string range $name 0 $end]
			set vdlink [conf_find_child [conf_global] "system vdom-link"]
			if { $vdlink } {
				conf_del_entry [conf_find_child $vdlink $linkname]
			}
			return $CONF_RET_T_DONT;
		} elseif { $type eq "vap-switch" } {
			return $CONF_RET_T_DONT;
		} elseif { $type eq "hard-switch" } {
			### delete the virtual-switch first
			set lsw [conf_find_child [conf_global] "system virtual-switch"]
			set lentry [conf_find_child $lsw $name]
			if { $lentry != 0 } {
				conf_del_dependency $handle
				conf_del_entry $lentry
			}
			return $CONF_RET_T_DONT;
		} elseif { $type eq "switch" } {
			if { [string trim $name \"] eq "wqt.${vdom}" } {
				return $CONF_RET_T_DONT;
			}
			return $CONF_RET_T_SKIP
		} elseif { $type eq "physical" } {
			return $CONF_RET_T_DONT
		} elseif { $type eq "tunnel" } {
			### autoupdate, change vdom opmode to tp, need "system settings" first
			set v1 [conf_get_var "is_autoupdate"]
			if { $v1 && $v1 eq "1" } {
				set ssl_if "ssl.$vdom"
				set svdom [conf_get_device_vdom_shortname_by_name $vdom]
				set s_ssl_if "ssl.$svdom"
				if { [conf_strcmp $name $ssl_if] == 0 || [conf_strcmp $name $s_ssl_if] == 0 } {
					set rvdom [conf_find_vdom $vdom 1]
					set lvdom [conf_find_vdom $vdom]
					if { $rvdom && $lvdom } {
						set rset [conf_find_child $rvdom "system settings"]
						set lset [conf_find_child $lvdom "system settings"]
						if { $lset && $rset } {
							set ropmode [conf_attr_arg [conf_find_attr $rset "opmode"] 0]
							set lopmode [conf_attr_arg [conf_find_attr $lset "opmode"] 0]
							if { $ropmode eq "transparent" && ($lopmode eq "" ||  $lopmode ne $ropmode) } {
								conf_merge_entry_edit $lset $rset
							}
						}
					}
				}
			}
			if { $ver < 600 || ($ver == 600 && $mr < 2) } {
				return $CONF_RET_T_OK;
			}
			set rvdom [conf_find_vdom $vdom 1]
			if { $rvdom == 0 } {
				return $CONF_RET_T_OK;
			}
			set p1intf [conf_find_child $rvdom "vpn ipsec phase1-interface"]
			if { $p1intf == 0 } {
				set lvdom [conf_find_vdom $vdom]
				if { $lvdom == 0 } {
					return $CONF_RET_T_OK;
				}
				set lagg_table [conf_find_child $lvdom "system ipsec-aggregate"]
				set ragg_table [conf_find_child $rvdom "system ipsec-aggregate"]
				if { $lagg_table == 0 } {
					return $CONF_RET_T_OK;
				}
				set ragg 0
				if { $ragg_table != 0 } {
					set ragg [conf_find_child $ragg_table $name]
				}
				set lagg [conf_find_child $lagg_table $name]
				if { $lagg == 0 || $ragg != 0 } {
					return $CONF_RET_T_OK;
				}
				return $CONF_RET_T_DONT;
			}
			set p1intf_entry [conf_find_child $p1intf $name]
			if { $p1intf_entry == 0 } {
				### snmp-index is duplicate with new tunnel interface
				set snmp_index [conf_find_attr $handle "snmp-index"]
				set snmp_index_val [conf_attr_arg $snmp_index 0]
				set newlist {}
				conf_foreach_entry $p1intf build-list newlist
				set rintf_list [conf_find_child [conf_global 1] "system interface"]
				set found 0
				foreach p1node $newlist {
					set ifname [conf_node_name $p1node]
					set rintf [conf_find_child $rintf_list $ifname]
					if { $rintf } {
						set rsnmp_index_val [conf_attr_arg [conf_find_attr $rintf "snmp-index"] 0]
						if { $snmp_index_val == $rsnmp_index_val } {
							set found 1
							break;
						}
					}
				}
				if { $found } {
					set intf_list [conf_find_child [conf_global] "system interface"]
					set newlist {}
					conf_foreach_entry $intf_list build-list newlist
					foreach ifnode $newlist {
						if { $ifnode } {
							set rsnmp_index_val [conf_attr_arg [conf_find_attr $ifnode "snmp-index"] 0]
							if { $snmp_index_val <= $rsnmp_index_val } {
								set snmp_index_val [expr ($rsnmp_index_val+1)]
							}
						}
					}
					conf_set_attr $snmp_index $snmp_index_val
				}
				return $CONF_RET_T_OK;
			}
			set aggregate [conf_attr_arg [conf_find_attr $p1intf_entry "aggregate-member"] 0]
			if { $aggregate eq "enable" } {
				return $CONF_RET_T_DONT;
			}
		} elseif { $type eq "vlan" || $type eq "" } {
			# if interface is in zone, apply change (delete) first
			set lvdom [conf_find_vdom $vdom]
			set zone_list [conf_find_child $lvdom "system zone"]
			conf_foreach_entry $zone_list diff.zone-intf-check $name

			set name [string trim $name \"]
			set ifname ""
			if { [string match "qtn.*" $name] } {
				set ifname [string range $name 4 end]
			} elseif { $ver > 600 || ($ver == 600 && $mr >= 4) } {
				set swf [conf_attr_arg [conf_find_attr $handle "switch-controller-feature"] 0]
				if { $swf eq "quarantine" } {
					set ifname [string trim [conf_attr_arg [conf_find_attr $handle "interface"] 0] \"]
				}
			}
			if { $ifname ne "" } {
				set ifnode [conf_find_child [conf_find_child [conf_global 1] "system interface"] $ifname]
				if { $ifnode ne 0 } {
					## if interface still exist, check fortilink status
					set flink [conf_attr_arg [conf_find_child $ifnode "fortilink"] 0]
					if {$flink eq "enable"} {
						return $CONF_RET_T_DONT;
					}
				} else {
					## if interface is deleted, force disable fortilink first before delete
					conf_add_script [conf_global 1] "config system interface\nedit \"$ifname\"\nset fortilink disable\nend"
				}
			}
		} elseif { $type eq "geneve" } {
			return $CONF_RET_T_OK;
			### Return OK to update dbcache
			### "system geneve" node is not available at this moment, cannot do more checking
		}
		set flink [conf_attr_arg [conf_find_child $handle "fortilink"] 0]
		set tname [string trim $name \"]
		if { $flink eq "enable" } {
			set intflist "vsw.$tname qtn.$tname snf.$tname voi.$tname cam.$tname nac.$tname"
			set sysintf [conf_find_child [conf_global] "system interface"]
			if { $ver > 600 || ($ver == 600 && $mr >= 4) } {
				set newlist {}
				set intf [conf_find_child [conf_global] "system interface"];
				conf_foreach_entry $intf build-list newlist
				foreach ifnode $newlist {
					set ifname [conf_node_name $ifnode]
					set pintf [string trim [conf_attr_arg [conf_find_attr $ifnode "interface"] 0] \"]
					if {$pintf ne $tname} {
						continue
					}
					set swf [conf_attr_arg [conf_find_attr $ifnode "switch-controller-feature"] 0]
					if { $swf ne 0 && $swf ne "" } {
						lappend intflist $ifname
					}
				}
			}
			foreach ifname $intflist {
				set ifnode [conf_find_child $sysintf $ifname]
				if { $ifnode ne 0 } {
					conf_del_dependency $ifnode
				}
			}
		}
		return $CONF_RET_T_OK;
	}

	if {$action == $CONF_ACT_T_EDIT} {
		set elbc [conf_find_child [conf_global 1] "system elbc"]
		if { $elbc } {
			set mode [conf_attr_arg [conf_find_attr $elbc "mode"] 0]
			if {$mode eq "service-group"} {
				set vdom [conf_attr_arg [conf_find_child $nentry "vdom"] 0]
				set vdom [string trim $vdom \"]
				if {$vdom eq "elbc-mgmt"} {
					return $CONF_RET_T_DONT;
				}
			}
		}
		return $CONF_RET_T_OK;
	}

        # ACT_ADD: handle is local table, nentry is new entry
	if { $action != $CONF_ACT_T_ADD } {
		return $CONF_RET_T_OK;
	}
	set type [conf_attr_arg [conf_find_child $nentry "type"] 0]
	if { $type eq "geneve" } {
		set node_name [string map {"\"" ""}  [conf_node_name $nentry]]
		set vdname [conf_attr_arg [conf_find_child $nentry "vdom"] 0]
		set rvdom [conf_find_vdom $vdname 1]
		set ver [cli_get_devinfo "version"]
		set mr [cli_get_devinfo "mr"]
		if { $rvdom != 0 } {
			if { $ver > 600 || ($ver == 600 && $mr >= 2) } {
				return $CONF_RET_T_OK;
			}
			### Return OK to update dbcache
			### "system geneve" node is not available at this moment, cannot do more checking
		}
		return $CONF_RET_T_DONT;
	}

	### vlan quarantine interfaces: need to add vap-switch interface first
	if { ($type eq "" || $type eq "vlan") && $ver >= 600 } {
		set node_name [string trim [conf_node_name $nentry] \"]
		set vlanid [conf_attr_arg [conf_find_child $nentry "vlanid"] 0]
		if { $vlanid == 4093 && [regexp {(^|[\"])wqtn.*} $node_name] } {
			set intf_name [string trim [conf_attr_arg [conf_find_child $nentry "interface"] 0] \"]
			set r_intf [conf_find_child [conf_global 1] "system interface"]
			set l_intf [conf_find_child [conf_global] "system interface"]
			set rentry [conf_find_child $r_intf $intf_name]
			set lentry [conf_find_child $l_intf $intf_name]
			if { $lentry == 0 } {
				set lentry [conf_add_entry $l_intf $rentry]
			}
			conf_merge_entry_edit_chkdep $lentry $rentry
		}
		return $CONF_RET_T_OK;
	}

	### vap-switch type need add vap entry first
	if { $type == "vap-switch" } {
		if { $ver > 600 || ($ver == 600 && $mr >= 2) } {
			set vdname [conf_attr_arg [conf_find_child $nentry "vdom"] 0]
			set rvdom [conf_find_vdom $vdname 1]
			if { $rvdom == 0 } {
				return $CONF_RET_T_OK;
			}
			set rvap [conf_find_child $rvdom "wireless-controller vap"]
			set lvdom [conf_find_vdom $vdname]
			if { $lvdom == 0 } {
				return $CONF_RET_T_OK;
			}
			set lvap [conf_find_child $lvdom "wireless-controller vap"]
			if { $lvap == 0 } {
				set lvap [conf_add_table $lvdom $rvap]
			}
		} else {
			set rvap [conf_find_child [conf_global 1] "wireless-controller vap"]
			set lvap [conf_find_child [conf_global] "wireless-controller vap"]
			if { $lvap == 0 } {
				set lvap [conf_add_table [conf_global] $rvap]
			}
		}
		set name [conf_node_name $nentry]
		set rentry [conf_find_child $rvap $name]
		set lentry [conf_find_child $lvap $name]
		if { $lentry == 0 } {
			set lentry [conf_add_entry $lvap $rentry]
		}
		conf_merge_entry_edit_chkdep $lentry $rentry
		return $CONF_RET_T_OK;
	}

	### vxlan type need add system vxlan entry first
	if { $type == "vxlan" } {
		set vdname [conf_attr_arg [conf_find_child $nentry "vdom"] 0]
		## Find remote table:
		set rvdom [conf_find_vdom $vdname 1]
		if { $rvdom == 0 } {
			set rvxlan [conf_find_child [conf_global 1] "system vxlan"]
		} else  {
			set rvxlan [conf_find_child $rvdom "system vxlan"]
		}
		## Find local table:
		set lvdom [conf_find_vdom $vdname]
		if { $lvdom == 0 } {
			set lvxlan [conf_find_child [conf_global] "system vxlan"]
			if { $lvxlan == 0 } {
				set lvxlan [conf_add_table [conf_global] $rvxlan]
			}
		} else  {
			set lvxlan [conf_find_child $lvdom "system vxlan"]
			if { $lvxlan == 0 } {
				set lvxlan [conf_add_table $lvdom $rvxlan]
			}
		}
		set name [conf_node_name $nentry]
		set rentry [conf_find_child $rvxlan $name]
		set lentry [conf_find_child $lvxlan $name]
		if { $lentry == 0 } {
			set lentry [conf_add_entry $lvxlan $rentry]
		}
		conf_merge_entry_edit_chkdep $lentry $rentry
		return $CONF_RET_T_OK;
	}

	### switch type need add system switch-interface entry first
	if { $type == "switch" } {
		set rswintf [conf_find_child [conf_global 1] "system switch-interface"]
		set lswintf [conf_find_child [conf_global] "system switch-interface"]
		if { $lswintf == 0 } {
			set lswintf [conf_add_table [conf_global] $rswintf]
		}
		set name [conf_node_name $nentry]
		set rentry [conf_find_child $rswintf $name]
		if { $rentry != 0 } {
			set lentry [conf_find_child $lswintf $name]
			if { $lentry == 0 } {
				set lentry [conf_add_entry $lswintf $rentry]
			}
			conf_merge_entry_edit_chkdep $lentry $rentry
		}
		return $CONF_RET_T_OK;
	}

	if { $type != "tunnel" } {
		return $CONF_RET_T_OK;
	}

	set intf_name [conf_node_name $nentry]
	set vdname [conf_attr_arg [conf_find_child $nentry "vdom"] 0]
	set vdom1 [conf_find_vdom $vdname];
	
	if { $ver >= 600 } {
		set lvdom [conf_find_vdom $vdname]
		set gretun1 0
		if { $lvdom == 0 } {
			set lgretun [conf_find_child [conf_global] "system gre-tunnel"]
		} else {
			set lgretun [conf_find_child $lvdom "system gre-tunnel"]
		}

		set rvdom [conf_find_vdom $vdname 1]
		if { $rvdom == 0 } {
			set rgretun [conf_find_child [conf_global] "system gre-tunnel"]
		} else {
			set rgretun [conf_find_child $rvdom "system gre-tunnel"]
		}
		if { $rgretun != 0 } {
			set lgretunentry 0
			set rgretunentry [conf_find_child $rgretun $intf_name]

			if { $lgretun != 0 } {
				set lgretunentry [conf_find_child $lgretun $intf_name]
			}
			if { $lgretunentry == 0 } {
				set lgretunentry [conf_add_entry $lgretun $rgretunentry]
			}
			conf_merge_entry_edit_chkdep $lgretunentry $rgretunentry
		}
	}

	# Find local ipsec-interface table handle. 
	set agg1 0
	if { $vdom1 == 0 } {
		set phase1 [conf_find_child [conf_global] "vpn ipsec phase1-interface"];
		set mankey1 [conf_find_child [conf_global] "vpn ipsec manualkey-interface"];
		if { $ver > 600 || ($ver == 600 && $mr >= 2) } {
			set agg1 [conf_find_child [conf_global] "system ipsec-aggregate"];
		}
	} else  {
		set phase1 [conf_find_child $vdom1 "vpn ipsec phase1-interface"];
		set mankey1 [conf_find_child $vdom1 "vpn ipsec manualkey-interface"];
		if { $ver > 600 || ($ver == 600 && $mr >= 2) } {
			set agg1 [conf_find_child $vdom1 "system ipsec-aggregate"];
		}
	}

	if { $phase1 != 0 } {
		set entry [conf_find_child $phase1 $intf_name];
		if { $entry != 0 } {
			if { $ver < 600 || ($ver == 600 && $mr < 2) } {
				return $CONF_RET_T_OK;
			}
			set aggregate [conf_attr_arg [conf_find_attr $entry "aggregate-member"] 0]
			if { $aggregate eq "disable" } {
				return $CONF_RET_T_OK;
			}
		}
	}

	if { $mankey1 != 0 } {
		set entry [conf_find_child $mankey1 $intf_name];
		if { $entry != 0 } {
			return $CONF_RET_T_OK;
		}
	}

	if { $agg1 != 0 } {
		set entry [conf_find_child $agg1 $intf_name];
		if { $entry != 0 } {
			return $CONF_RET_T_OK;
		}
		### need to add "system ipsec-aggregate" entry first
		if { $ver > 600 || ($ver == 600 && $mr >= 2) } {
			set r_vdom1 [conf_find_vdom $vdname 1]
			if { $r_vdom1 } {
				set r_agg1 [conf_find_child $r_vdom1 "system ipsec-aggregate"];
				if { $r_agg1 } {
					set r_entry [conf_find_child $r_agg1 $intf_name];
					set entry [conf_add_entry $agg1 $r_entry]
					conf_merge_entry_edit_chkdep $entry $r_entry
				}
			}
		}
	}

	# Find nentry of ipsec-interface handle. 
	set vdom2 [conf_find_vdom $vdname 1]
	set agg1table 0
	if {  $vdom2 == 0 } {
		set np1table [conf_find_child [conf_global 1] "vpn ipsec phase1-interface"];
		set mk1table [conf_find_child [conf_global 1] "vpn ipsec manualkey-interface"];
		if { $ver > 600 || ($ver == 600 && $mr >= 2) } {
			set agg1table [conf_find_child [conf_global 1] "system ipsec-aggregate"];
		}
	} else {
		set np1table [conf_find_child $vdom2 "vpn ipsec phase1-interface"];
		set mk1table [conf_find_child $vdom2 "vpn ipsec manualkey-interface"];
		if { $ver > 600 || ($ver == 600 && $mr >= 2) } {
			set agg1table [conf_find_child $vdom2 "system ipsec-aggregate"];
		}
	}

	set in_manualkey 0
	set in_agg 0
	if { $np1table != 0 } {
		set np1entry [conf_find_child $np1table $intf_name];
	} else {
		set np1entry 0
	}
	
	if { $np1entry == 0 } {
		if { $mk1table != 0 } {
			set np1entry [conf_find_child $mk1table $intf_name];
		}

		if { $np1entry == 0 } {
			if { $agg1table != 0 } {
				set np1entry [conf_find_child $agg1table $intf_name];
				set in_agg 1
			}
			if { $np1entry == 0 } {
				return $CONF_RET_T_OK;
			}
		} else {
			set in_manualkey 1
		}
	}

	# Add/Edit ipsec-interface first. 
	if { $in_manualkey == 0 && $in_agg == 0 } {
		if { $phase1 == 0 } {
			if { $vdom1 == 0 } {
				set phase1 [conf_add_table [conf_global] $np1table];
			} else {
				set phase1 [conf_add_table $vdom1 $np1table];
			}
		}
		set lentry [conf_find_child $phase1 $intf_name];
		if { $lentry == 0 } {
			set lentry [conf_add_entry $phase1 $np1entry];
		}
		conf_merge_entry_edit_chkdep $lentry $np1entry;
	} elseif { $in_manualkey == 1 } {
		if { $mankey1 == 0 } {
			if { $vdom1 == 0 } {
				set mankey1 [conf_add_table [conf_global] $mk1table];
			} else {
				set mankey1 [conf_add_table $vdom1 $mk1table];
			}
		}
		set lentry [conf_add_entry $mankey1 $np1entry];
		conf_merge_entry_edit_chkdep $lentry $np1entry;
	} else {
		if { $ver < 600 || ($ver == 600 && $mr < 2) } {
			return $CONF_RET_T_OK;
		}
		if { $agg1 == 0 } {
			if { $vdom1 == 0 } {
				set agg1 [conf_add_table [conf_global] $agg1table];
			} else {
				set agg1 [conf_add_table $vdom1 $agg1table];
			}
		}
		set lentry [conf_add_entry $agg1 $np1entry];
		set memlist [conf_find_child $np1entry "member"]
		set argc [conf_attr_argc $memlist]
		set i 0 
		while { $i < $argc } {
			set value [conf_attr_arg $memlist $i]
			incr i
			set rp1entry [conf_find_child $np1table $value]
			if { $rp1entry == 0 } {
				continue
			}
			if { $phase1 == 0 } {
				if { $vdom1 == 0 } {
					set phase1 [conf_add_table [conf_global] $np1table];
				} else {
					set phase1 [conf_add_table $vdom1 $np1table];
				}
			}
			set lp1entry [conf_find_child $phase1 $value];
			if { $lp1entry == 0 } {
				set lp1entry [conf_add_entry $phase1 $rp1entry];
			}
			conf_merge_entry_edit_chkdep $lp1entry $rp1entry;
		}
		conf_merge_entry_edit_chkdep $lentry $np1entry;
	}

	return $CONF_RET_T_OK;
}

proc diff.system.interface.fortilink {local remote action arg} {
	global CONF_RET_T_OK

	set ver [cli_get_devinfo "version"]
	set mr [cli_get_devinfo "mr"]

	if { $ver < 600 || ($ver == 600 && $mr < 4) } {
		return $CONF_RET_T_OK
	}

	set val [conf_attr_arg $remote 0]
	if { $val != "enable" } {
		return $CONF_RET_T_OK;
	}

	set name [conf_node_name [conf_node_parent $remote]]
	set intflist {}
	set sysintf [conf_find_child [conf_global] "system interface"];
	set sysintf1 [conf_find_child [conf_global 1] "system interface"];

	conf_foreach_entry $sysintf1 build-list intflist

	foreach ifnode $intflist {
		set ifname [conf_node_name $ifnode]
		set pintf [string trim [conf_attr_arg [conf_find_attr $ifnode "interface"] 0] \"]
		if {$pintf ne $name} {
			continue
		}
		set swf [conf_attr_arg [conf_find_attr $ifnode "switch-controller-feature"] 0]
		if { $swf eq 0 || $swf eq "" } {
			continue
		}

		set ifnode [conf_find_child $sysintf $ifname]
		set ifnode1 [conf_find_child $sysintf1 $ifname]

		if { $ifnode eq 0 } {
			set ifnode [conf_add_entry $sysintf $ifnode1]
		}
		conf_merge_entry_edit_chkdep $ifnode $ifnode1
	}
	return $CONF_RET_T_OK;
}

proc diff.del-vxlan-interface {entry arg} {
	set name [conf_node_name $entry]

	# Also delete the interface table. 
	set intf [conf_find_child [conf_find_child [conf_global] "system interface"] $name]

	# Remove only. 
	conf_destroy_node $intf;		
	return $CONF_RET_T_OK;
}

proc diff.system.vxlan {handle dummy action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_DELETE
	global CONF_ACT_T_EDIT CONF_ACT_T_MOVE  
	global CONF_ACT_T_CLEAR CONF_ACT_T_UNSET
	global CONF_RET_T_OK CONF_ACT_T_DONT CONF_RET_T_ERROR

	if { $action == $CONF_ACT_T_DELETE } {
		diff.del-vxlan-interface $handle 0
		return $CONF_RET_T_OK
	} elseif { $action == $CONF_ACT_T_CLEAR } {
		conf_foreach_entry $handle diff.del-vxlan-interface 0
		return $CONF_RET_T_OK
	}

    	return $CONF_RET_T_OK
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
	set v [cli_get_devinfo "version"]
	set b [cli_get_devinfo "branch"]
	if { ($v eq 500 && 1016 <= $b) || $v >= 600 } {
		set lv [conf_attr_arg [conf_find_attr $local "authmethod"] 0]
		set rv [conf_attr_arg [conf_find_attr $remote "authmethod"] 0]
		set lpn [conf_find_attr $local "peertype"]
		set lpv [conf_attr_arg [conf_find_attr $local "peertype"] 0]
		set rpn [conf_find_attr $remote "peertype"]
		set rpv [conf_attr_arg $rpn 0]
		if { ($rv eq "signature") && ($lv ne "signature") } {
			if { $v eq 500 && $b < 1069 && $rpn == 0 } {
				## default value changed - default on fmg means "any"
				conf_add_attr $remote "peertype" "any"
			} elseif { $lpv eq $rpv } {
				## fgt will automatically change peertype to "peer"
				## need to force push attr if we don't want to change
				conf_set_attr $lpn "peer" 1
			}
		}
	}
}

proc diff.vpn.p1intf.conflict-remote-gw {entry arg} {
	set lremote_gw [conf_find_attr $entry "remote-gw"]
	set lremote_gw_arg [conf_attr_arg $lremote_gw 0]
	if { $lremote_gw_arg eq $arg } {
		set name [conf_node_name $entry]
		if { $name ne "" } {
			set vdom_node [conf_node_root $entry]
			set vdom_name [conf_node_name $vdom_node]
			set rvdom [conf_find_vdom $vdom_name 1]
			set rp1intf_table [conf_find_child $rvdom "vpn ipsec phase1-interface"]
			set rp1intf [conf_find_child $rp1intf_table $name]
			if { $rp1intf eq 0 } {
				conf_set_attr $lremote_gw "1.0.0.0"
			}
		}
	}
}

proc diff.vpn.ipsec.phase1-interface {handle dummy action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_DELETE;
	global CONF_ACT_T_EDIT CONF_ACT_T_MOVE;  
	global CONF_ACT_T_CLEAR CONF_ACT_T_UNSET;
	global CONF_RET_T_OK CONF_ACT_T_DONT CONF_RET_T_ERROR;  

	if { $action == $CONF_ACT_T_ADD } {
		set remote_gw [conf_attr_arg [conf_find_attr $dummy "remote-gw"] 0]
		set vdom_node [conf_node_root $dummy]
		set vdom_name [conf_node_name $vdom_node]
		set lvdom [conf_find_vdom $vdom_name]
		set p1intf [conf_find_child $lvdom "vpn ipsec phase1-interface"]
		conf_foreach_entry $p1intf diff.vpn.p1intf.conflict-remote-gw $remote_gw;
	}
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

proc diff.vpn.ipsec.phase1 {handle dummy action arg} {
    global CONF_ACT_T_ADD CONF_ACT_T_DELETE;
    global CONF_ACT_T_EDIT CONF_ACT_T_MOVE;
    global CONF_ACT_T_CLEAR CONF_ACT_T_UNSET;
    global CONF_RET_T_OK CONF_ACT_T_DONT CONF_RET_T_ERROR;

    if { $action != $CONF_ACT_T_ADD && $action != $CONF_ACT_T_EDIT} {
        return $CONF_RET_T_OK
    }

	peertype_any_force_push $handle $dummy $action $arg
	return [conf_vpn_ipsec_gw_dupcheck $dummy]
}

proc diff.system.modem.auto-dial {local remote action arg} {
	global CONF_ACT_T_EDIT;

	if { $action != $CONF_ACT_T_EDIT || $remote == 0 } {
		return $CONF_RET_T_OK;
	}

	set value1 [conf_attr_arg $remote 0]
	if { $value1 != "enable" } {
		return $CONF_RET_T_OK;
	}

	set lp [conf_node_parent $local]
	if { $lp != 0 } {
		set lattr [conf_find_attr $lp "dial-on-demand"]
		if { $lattr != 0 } {
			set value2 [conf_attr_arg $lattr 0]
			if { $value2 == "enable" } {
				conf_add_script $local "set dial-on-demand disable"
			}
		}
	}

	return $CONF_RET_T_OK;
}

proc diff.add-vdom {entry arg} {
	global CONF_RET_T_OK CONF_ACT_T_DONT CONF_RET_T_ERROR;  
	set name [conf_node_name $entry]
	if { $name == [conf_node_name $arg] } {
		set type [conf_attr_arg [conf_find_child $entry "type"] 0]
		if { $type != "physical" } {
			return $CONF_RET_T_ERROR;
		}
		conf_del_entry $entry;
	}
	return $CONF_RET_T_OK;
}

proc diff.del-vdom-4-intf {entry arg} {
	global CONF_RET_T_OK CONF_ACT_T_DONT CONF_RET_T_ERROR;  

	set vdom [conf_find_child $entry "vdom"]
	set vdname [conf_attr_arg $vdom 0]

	set cmpresult [conf_strcmp $vdname $arg]
	if { $cmpresult == 0 } {
		set attr [conf_find_child $entry "type"];
		set type [conf_attr_arg $attr 0]
		if { $type == "physical" } {
			conf_del_dependency $entry
			conf_set_attr $vdom "root";
			return $CONF_RET_T_OK;
		}
		conf_del_entry $entry;
	}
	return $CONF_RET_T_OK;
}

proc diff.del-entry {entry arg} {
	global CONF_RET_T_OK CONF_ACT_T_DONT CONF_RET_T_ERROR;  

	set name [conf_node_name $entry]
	set cmpresult [conf_strcmp $name $arg]
	if { $cmpresult == 0 } {
		conf_destroy_node $entry
	}

	return $CONF_RET_T_OK;
}

proc diff.delete_sys_ha_secondvdom {name} {
	global CONF_RET_T_OK CONF_ACT_T_DONT CONF_RET_T_ERROR;  
	set sysha [conf_find_child [conf_global] "system ha"]
	if { $sysha != 0 } {
		set secondvc [conf_find_child $sysha "secondary-vcluster"] 
		if { $secondvc != 0 } {
			set svdom [conf_find_attr $secondvc "vdom"]
			if { $svdom != 0 } {
				set vargc [conf_attr_argc $svdom]
				set found 0
				set i 0 
				while { $i < $vargc } {
					set value [conf_attr_arg $svdom $i]
					if { ![conf_strcmp $value $name] } {
						set found 1;
						break;
					}
					incr i
				}
				if { $found != 0 } {
					set j 0
					set script "unset vdom"
					while { $j < $vargc } {
						set value [conf_attr_arg $svdom $j]
						if { [conf_strcmp $value $name] } {
							append script "\nset vdom $value"
						}
						incr j
					}
					conf_add_script $svdom $script
				}
			}
		}
	}
	return $CONF_RET_T_OK;
}

proc diff.vdom {local remote action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_DELETE;
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR;  

	if { $action == $CONF_ACT_T_ADD } {
		set intf [conf_find_child [conf_global] "system interface"];
		conf_foreach_entry $intf diff.add-vdom $remote;
		return $CONF_RET_T_OK;
	} elseif { $action != $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_OK;
	}

	set name [conf_node_name $local];
	if { $name == "root" } {
		return $CONF_RET_T_ERROR;
	}

	diff.delete_sys_ha_secondvdom $name;

	set vapname "mesh.$name"
	set vaps [conf_find_child [conf_global] "wireless-controller vap"]
	conf_foreach_entry $vaps diff.del-entry $vapname

	set vp [conf_find_child [conf_global] "system vdom-property"];
	conf_foreach_entry $vp diff.del-entry $name;

	set intf [conf_find_child [conf_global] "system interface"];
	conf_foreach_entry $intf diff.del-vdom-4-intf $name;

	set intf [conf_find_child [conf_global] "system interface"];
	set name [conf_node_name $local];
	append name ".M"
	conf_foreach_entry $intf diff.del-entry $name;

	return $CONF_RET_T_OK;
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

proc diff.firewall.policy.nat46 {local remote action arg} {
	global CONF_ACT_T_DELETE;

	if { $action != $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_OK;
	}
	if { !$local } {
		return $CONF_RET_T_OK;
	}
	set lentry [conf_node_parent $local]
	set tattr [conf_find_attr $lentry "dstaddr"]
	if {$tattr != 0} {
		conf_unset_attr $tattr
	}

	return $CONF_RET_T_OK;
}

proc diff.firewall.policy.nat64 {local remote action arg} {
	global CONF_ACT_T_DELETE;

	if { $action != $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_OK;
	}
	if { !$local } {
		return $CONF_RET_T_OK;
	}
	set lentry [conf_node_parent $local]
	set tattr [conf_find_attr $lentry "dstaddr6"]
	if {$tattr != 0} {
		conf_unset_attr $tattr
	}

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

	set node [conf_find_child $vdom "firewall policy6"]
	if {$node != 0} {
		conf_del_dependency $intf_node $node
	}

	set node [conf_find_child $vdom "firewall interface-policy"]
	if {$node != 0} {
		conf_del_dependency $intf_node $node
	}

	set node [conf_find_child $vdom "firewall explicit-proxy-policy"]
	if {$node != 0} {
		conf_del_dependency $intf_node $node
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

proc diff.zone-intf-check {entry intf_name} {
	global CONF_RET_T_OK
	set lintf [conf_find_attr $entry "interface"]
	set argc [conf_attr_argc $lintf]
	set i 0
	while {$i < $argc} {
		set lintf_name [string trim [conf_attr_arg $lintf $i] \"]
		if { $lintf_name eq $intf_name } {
			set zone_name [conf_node_name $entry]
			set vdom_node [conf_node_root $entry]
			set vdom_name [conf_node_name $vdom_node]
			set rvdom [conf_find_vdom $vdom_name 1]
			set zones [conf_find_child $rvdom "system zone"]
			set rentry [conf_find_child $zones $zone_name]
			if { $rentry != 0 } {
				conf_merge_entry_edit_chkdep $entry $rentry
			}
			return $CONF_RET_T_OK
		}
		incr i
	}
	return $CONF_RET_T_OK
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
			if { $intf_node != 0 } {
				set lvdom [conf_find_vdom $vdom_name]
				set zone_list [conf_find_child $lvdom "system zone"]
				set intf_name [string trim $intf_name \"]
				conf_foreach_entry $zone_list diff.zone-intf-check $intf_name
			}
			diff.del_sniffer_policy $intf_name $vdom_name
		}
		incr i
	}

	conf_set_dep_selfnode 0 

	return $CONF_RET_T_OK;
}

proc diff.system.zone {local remote action arg} {
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_SKIP;

	if {$action != $CONF_ACT_T_DELETE} {
		return $CONF_RET_T_OK;
	}

	set vdom_node [conf_node_root $local]
	set vdom_name [conf_node_name $vdom_node]
	set zone_name [conf_node_name $local]

	set lvdom [conf_node_root $local]
	set rvdom [conf_find_vdom [conf_node_name $lvdom] 1]

	set newlist {}
	set zone_table_rvdom [conf_find_child $rvdom "system zone"]
	conf_foreach_entry $zone_table_rvdom build-list newlist

	foreach r_e $newlist {
		set r_zone_name [conf_node_name $r_e]

		if { $r_zone_name eq $zone_name } {
			return $CONF_RET_T_SKIP
		}
	}

	set sys_zones [conf_find_child $vdom_node "system zone"]
	set zone_node [conf_find_child $sys_zones $zone_name]
	diff.check_zone_exclusive_intf $zone_node $vdom_name

	return $CONF_RET_T_OK;
}

proc diff.system.switch-interface {local remote action arg} {
	global CONF_ACT_T_EDIT CONF_ACT_T_ADD
	global CONF_RET_T_OK

	if {$action != $CONF_ACT_T_EDIT && $action != $CONF_ACT_T_ADD} {
		return $CONF_RET_T_OK;
	}

	set l_intf [conf_find_child [conf_global] "system interface"]
	set r_intf [conf_find_child [conf_global 1] "system interface"]
	### local : fgt, remote : fmg
	set attr [conf_find_child $remote "member"]
	if { $l_intf == 0 || $r_intf == 0 || $attr == 0 } {
		return $CONF_RET_T_OK;
	}

	set argc [conf_attr_argc $attr]

	set members {}
	set i 0
	while {$i < $argc} {
		set intf_name [conf_attr_arg $attr $i]
		lappend members $intf_name
		set l_intf_node [conf_find_child $l_intf $intf_name]
		if { $i > 0 } {
			set r_intf [conf_find_child [conf_global 1] "system interface"]
		}
		set r_intf_node [conf_find_child $r_intf $intf_name]
		if { $l_intf_node != 0 } {
			conf_merge_entry_edit_chkdep $l_intf_node $r_intf_node
			set vdom_name [conf_attr_arg [conf_find_child $l_intf_node "vdom"] 0]
			diff.check_zone_exclusive_intf $vdom_name $intf_name
		} else {

			### member is a new vlan quarantine interface
			set cmd ""
			set type [conf_attr_arg [conf_find_child $r_intf_node "type"] 0]
			set ver [cli_get_devinfo "version"]
			if { ($type eq "" || $type eq "vlan") && $ver >= 600 } {
				set vlanid [conf_attr_arg [conf_find_child $r_intf_node "vlanid"] 0]
				if { $vlanid == 4093 && [regexp {(^|[\"])wqtn.*} $intf_name] } {
					set vapname [string trim [conf_attr_arg [conf_find_child $r_intf_node "interface"] 0] \"]
					set r_vapintf_node [conf_find_child $r_intf $vapname]
					set type [conf_attr_arg [conf_find_child $r_vapintf_node "type"] 0]
					if { $type == "vap-switch" } {
						set mr [cli_get_devinfo "mr"]
						if { $ver > 600 || ($ver == 600 && $mr >= 2) } {
							set vdom_name [conf_attr_arg [conf_find_child $r_vapintf_node "vdom"] 0]
                					set vdom_name [string trim $vdom_name \"]
							set rvdom [conf_find_vdom $vdom_name 1]
							set r_vap_nodes [conf_find_child $rvdom "wireless-controller vap"]
							set lvdom [conf_find_vdom $vdom_name]
							set l_vap_nodes [conf_find_child $lvdom "wireless-controller vap"]
						} else {
							set r_vap_nodes [conf_find_child [conf_global 1] "wireless-controller vap"]
							set l_vap_nodes [conf_find_child [conf_global] "wireless-controller vap"]
						}
						set r_vap_node [conf_find_child $r_vap_nodes $vapname]
						set l_vap_node [conf_find_child $l_vap_nodes $vapname]
 						set r_quaran [conf_attr_arg [conf_find_attr $r_vap_node "quarantine"] 0]
						if { $l_vap_node == 0 } {
 							set l_quaran ""
						} else {
 							set l_quaran [conf_attr_arg [conf_find_attr $l_vap_node "quarantine"] 0]
						}
 						if { $r_vap_node && ($r_quaran eq "" || $r_quaran eq "enable") && ($l_vap_node == 0 || $l_quaran ne "disable") } {
							conf_add_attr $r_vap_node "quarantine" "disable"
							if { $l_vap_node } { conf_merge_entry_edit_chkdep $l_vap_node $r_vap_node }
							set vdom_enable [cli_get_devinfo "vdom-admin"]
							if { $vdom_enable eq "yes" } { 
								if { $ver > 600 || ($ver == 600 && $mr >= 2) } {
									append cmd "config vdom\nedit $vdom_name\n" 
								} else {
									append cmd "config global\n" 
								}
							}
							append cmd "config wireless-controller vap\nedit \"$vapname\"\nunset quarantine\nnext\nend"
							if { $vdom_enable eq "yes" } { append cmd "\nend" }
 						}
					}
				}
			}

			set l_intf_node [conf_add_entry $l_intf $r_intf_node]
			conf_merge_entry_edit_chkdep $l_intf_node $r_intf_node
			if { $cmd ne "" } { conf_add_script [conf_global 1]  $cmd }
		}
		incr i
	}

	##get new intf members added and delete dependencies first 
	set attr [conf_find_child $local "member"]
	if { $attr ne 0 } {
		set argc [conf_attr_argc $attr]
		set i 0
		while {$i < $argc} {
			set intf_name [conf_attr_arg $attr $i]
			set idx [lsearch $members $intf_name]
			if { $idx != -1 } {
				set members [lreplace $members $idx $idx]
			}
			incr i
		}
	}
	set sysintf [conf_find_child [conf_global] "system interface"];
	foreach memb $members {
		puts "memb $memb"
		set ifnode [conf_find_child $sysintf $memb]
		if { $ifnode ne 0 } {
			puts "delete dep for $memb"
			conf_del_dependency $ifnode
		}
	}

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

proc diff.vpn.pptp.usrgrp {local remote action arg} {
        global CONF_ACT_T_DELETE
        global CONF_RET_T_OK CONF_RET_T_DONT
        if {$action != $CONF_ACT_T_DELETE} {
                return $CONF_RET_T_OK;
        }

        set lentry [conf_node_parent $local]
        set tattr [conf_find_attr $lentry "status"]
        if {$tattr != 0} {
                conf_unset_attr $tattr
        }
        return $CONF_RET_T_DONT;
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

proc select_admin_from_list {list} {
	if { [llength $list] eq 0 } {
		return ""
	}
	if { [llength $list] eq 1 } {
		return [lindex $list 0]
	}
	set cadmin [cli_get_devinfo "admin"]
	if { [lsearch -exact $list $cadmin] >= 0 } {
		return $cadmin
	}
	if { [lsearch -exact $list "admin"] >= 0 } {
		return "admin"
	}
	## if all case fails, return the first entry
	return [lindex $list 0]
}

proc get_super_admin {radmin ladmin} {
	set sadmin ""

	if { $radmin eq 0 } {
		set radmin [conf_find_child [conf_global 1] "system admin"]
	}
	if { $ladmin eq 0 } {
		set ladmin [conf_find_child [conf_global 0] "system admin"]
	}

	## step 1. if remote have super admin, then use the first one as super admin
	set rlist {}
	if { $radmin ne 0 } {
		conf_foreach_entry $radmin build-list rlist
	}

	foreach re $rlist {
		set accprof [conf_attr_arg [conf_find_child $re "accprofile"] 0]
		if { [string trim $accprof \"] eq "super_admin" } {
			set sadmin [conf_node_name $re]
			break
		}
	}

	## step 2. if no super admin from remote list, check local list
	set alist {}
	set blist {}
	if { $sadmin eq "" } {
		set llist {}
		if { $ladmin ne 0 } {
			conf_foreach_entry $ladmin build-list llist
		}

		foreach le $llist {
			set name [conf_node_name $le]
			set accprof [conf_attr_arg [conf_find_child $le "accprofile"] 0]
			if { [string trim $accprof \"] ne "super_admin" } {
				continue
			}

			## from step 1, rlist contains no super admin, so if admin is found in rlist, then it must NOT be super admin
			set re 0
			if { $radmin ne 0 } {
				set re [conf_find_child $radmin $name]
			}
			if { $re eq 0 } {
				lappend alist $name
			} else {
				lappend blist $name
			}
		}
	}

	## step 3. select admin within a list of remaining super-user after install
	if { $sadmin eq "" } {
		set sadmin [select_admin_from_list $alist]
	}

	## step 4. if no super-user left after install, prevent one admin from being demoted
	if { $sadmin eq "" } {
		set sadmin [select_admin_from_list $blist]
	}

	## cache result for performance
	conf_set_var "super-admin-name" $sadmin
	return $sadmin
}

proc diff.system.admin {local remote action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_EDIT
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_SKIP

	if { $action == $CONF_ACT_T_DELETE } {
		set r_admin [conf_find_child [conf_global 1] "system admin"]
		set l_admin [conf_find_child [conf_global 0] "system admin"]

		set name [conf_node_name $local]
		set sadmin ""
		if { [conf_var_exist "super-admin-name"] } {
			set sadmin [conf_get_var "super-admin-name"]
		}
		if { $sadmin eq "" || $sadmin eq 0 } {
			set sadmin [get_super_admin $r_admin $l_admin]
		}
		if { $sadmin eq $name } {
			return $CONF_RET_T_SKIP
		}

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

proc diff.system.admin.accprofile {local remote action arg} {
	global CONF_ACT_T_EDIT
	global CONF_RET_T_OK CONF_RET_T_SKIP

	set accprof ""
	if { [conf_attr_argc $local] > 0 } {
		set accprof [conf_attr_arg $local 0]
	}

	if { [string trim $accprof \"] eq "super_admin" } {
		set name [conf_node_name [conf_node_parent $local]]
		set sadmin ""
		if { [conf_var_exist "super-admin-name"] } {
			set sadmin [conf_get_var "super-admin-name"]
		}
		if { $sadmin eq "" || $sadmin eq 0 } {
			set sadmin [get_super_admin 0 0]
		}
		if { $sadmin eq $name } {
			return $CONF_RET_T_SKIP
		}
	}
	return $CONF_RET_T_OK
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

        set sysglobal [conf_find_child [conf_global 1] "system global"]
        if { $sysglobal == 0 } {
                return $CONF_RET_T_OK
        }
        set vdom [conf_find_attr $sysglobal "vdom-admin"]
        if { $vdom == 0 } {
		set vdom [conf_find_attr $sysglobal "vdom-mode"]
        }
        if { $vdom == 0 } {
                return $CONF_RET_T_DONT
        }
        set status [conf_attr_arg $vdom 0]
        if { $status eq "enable" } {
                return $CONF_RET_T_OK
        } elseif { $status eq "multi-vdom" || $status eq "split-vdom" } {
		return $CONF_RET_T_OK
	}
        return $CONF_RET_T_DONT
}

proc post.ips.DoS.anomaly {local remote action arg} {
	global CONF_RET_T_OK

	set log_st [conf_find_child $remote "log"]
	if {$log_st == 0} {
		set placebo [conf_find_child $local "threshold"]
		conf_add_script $placebo "unset log"
	}
	return $CONF_RET_T_OK
}

proc build_ftgd_list {entry1 entry2} {
	upvar $entry2 l
	set attr [conf_find_attr $entry1 "id"]
	if {$attr == 0} {
		return
	}
	set cat [conf_attr_arg $attr 0]
	lappend l $cat
}

proc create_ftgd_exclusive_attr {local ena_list attrname} {
	global CONF_RET_OK

	set local_cat [conf_find_child [conf_node_root $local] "webfilter ftgd-local-cat"]
	if {$local_cat == 0} {
		return $CONF_RET_OK
	}
	set catlist {}
	set unset_cmd ""
	conf_foreach_entry $local_cat build_ftgd_list catlist
	foreach e $catlist {
		set i [lsearch -exact -inline $ena_list $e]
		if {[lsearch -exact $ena_list $e] < 0} {
			append unset_cmd "$e "
		}
	}
	if {$unset_cmd ne ""} {
		conf_add_script $local "set $attrname $unset_cmd"
	}
	return $CONF_RET_OK
}

proc diff.firewall.profile.ftgd-wf-enable {local remote action arg} {
	set argc [conf_attr_argc $remote]
	set ena_list {}
	for {set i 0} {$i < $argc} {incr i} {
		set ena [conf_attr_arg $remote $i]
		set ena [string trim $ena \"]
		lappend ena_list $ena
	}
	create_ftgd_exclusive_attr $local $ena_list "ftgd-wf-disable"
}

proc diff.webfilter.profile.ftgd-wf {local remote action arg} {
	global CONF_RET_T_OK CONF_RET_T_DONT

	set ver [cli_get_devinfo "version"]
	set br [cli_get_devinfo "branch"]

	if { $ver > 600 || ($ver == 600 && $br >= 1700) } {
		if { $remote ne 0 } {
			set vdom [conf_node_root $remote]
		} else {
			set vdom [conf_find_vdom [conf_node_name [conf_node_root $local]] 1]
		}
		set sysset [conf_find_child $vdom "system settings"]
		set ngfw 0
		set mode "profile-based"
		if { $sysset ne 0 } {
			set ngfw [conf_find_attr $sysset "ngfw-mode"]
		}
		if { $ngfw ne 0 } {
			set mode [conf_attr_arg $ngfw 0]
		}
		if { $mode eq "policy-based" } {
			## skip ftgd-wf if mode is policy-based
			return $CONF_RET_T_DONT
		}
	}
}

proc diff.firewall.mms-profile.notification.msg-protocol {local remote action arg} {
        global CONF_ACT_T_ADD;
        global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR;

        if { $arg == 0 } {
                return $CONF_RET_T_OK;
        } 
        set rattr_msg_protocol [conf_find_attr [conf_node_parent $remote] "msg-protocol"]
	set rattr_msg_type [conf_find_attr [conf_node_parent $remote] "msg-type"]
        if { $rattr_msg_protocol==0 || $rattr_msg_type!=0 } {
                return $CONF_RET_T_OK;
	}
        set msg_protocol [conf_attr_arg $rattr_msg_protocol 0]
        if { $msg_protocol=="mm7" } {
                conf_add_script $remote "unset msg-type"
        }

        return $CONF_RET_T_OK; 
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

proc diff.user.device {local remote action arg} {
        global CONF_ACT_T_ADD CONF_ACT_T_EDIT;
        global CONF_RET_T_OK

	if {$action != $CONF_ACT_T_ADD && $action != $CONF_ACT_T_EDIT} {
		return $CONF_RET_T_OK;
	}
	if {!$remote} {
		return $CONF_RET_T_OK;
	}
	
	set lnode $local
	set rnode $remote

	if {$action == $CONF_ACT_T_ADD} {
		set rtn $lnode
	} else {
		set rtn [conf_node_parent $lnode]
	}
	
	conf_foreach_entry $rtn diff.check_dup_usr_dev $rnode
	return $CONF_RET_T_OK
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
proc diff.router.ospf.ospf-interface.md5-key {local remote action arg} {
	global CONF_RET_T_SKIP CONF_RET_T_OK
	if { $local && $remote } {
		set lc [conf_attr_argc $local]
		set rc [conf_attr_argc $remote]
		if { $lc eq $rc } {
			for { set i 0 } { $i < $lc } { incr i 2 } {
				set lkey [conf_attr_arg $local $i]
				for { set j 0 } { $j < $rc } { incr j 2 } {
					set rkey [conf_attr_arg $remote $j]
					if { $lkey eq $rkey } {
						set lmd5 [conf_attr_arg $local [expr ($i+1)]]
						set rmd5 [conf_attr_arg $remote [expr ($j+1)]]
						if { [diff.md5-key.equal $lmd5 $rmd5] } {
							break
						}
					}
				}
				if { $j == $rc } {
					break
				}
			}
			if { $i == $lc } {
				return $CONF_RET_T_SKIP
			}
		}
	}
	return $CONF_RET_T_OK
}
proc diff.router.ospf.area.virtual-link.md5-key {local remote action arg} {
	global CONF_RET_T_SKIP CONF_RET_T_OK
	if { $local && $remote } {
		set lc [conf_attr_argc $local]
		set rc [conf_attr_argc $remote]
                if { $lc eq $rc } {
                        for { set i 0 } { $i < $lc } { incr i 2 } {
                                set lkey [conf_attr_arg $local $i]
                                for { set j 0 } { $j < $rc } { incr j 2 } {
                                        set rkey [conf_attr_arg $remote $j]
                                        if { $lkey eq $rkey } {
                                                set lmd5 [conf_attr_arg $local [expr ($i+1)]]
                                                set rmd5 [conf_attr_arg $remote [expr ($j+1)]]
                                                if { [diff.md5-key.equal $lmd5 $rmd5] } {
                                                        break
                                                }
                                        }
                                }
                                if { $j == $rc } {
                                        break
                                }
                        }
                        if { $i == $lc } {
                                return $CONF_RET_T_SKIP
                        }
                }
	}
	return $CONF_RET_T_OK
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
proc diff.vpn.ipsec.manualkey.authkey {local remote action arg} {
	return [diff.manual-key.common.compare $local $remote $action $arg]
}
proc diff.vpn.ipsec.manualkey.enckey {local remote action arg} {
	return [diff.manual-key.common.compare $local $remote $action $arg]
}
proc diff.vpn.ipsec.manualkey-interface.auth-key {local remote action arg} {
	return [diff.manual-key.common.compare $local $remote $action $arg]
}
proc diff.vpn.ipsec.manualkey-interface.enc-key {local remote action arg} {
	return [diff.manual-key.common.compare $local $remote $action $arg]
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
	global CONF_RET_T_SKIP
	if { [conf_diff_is_scep_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return [conf_diff_is_factory_cert $lattr $rattr $action $arg]
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
	global CONF_RET_T_SKIP
	if { [conf_diff_is_scep_cert $lattr $rattr $action $arg] == $CONF_RET_T_SKIP } {
		return $CONF_RET_T_SKIP
	}
	return [conf_diff_is_factory_cert $lattr $rattr $action $arg]
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

proc diff.vpn.certificate.ca.ca._skip {lattr rattr action arg} {
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

proc diff.vpn.certificate.crl.crl {lattr rattr action arg} {
	return [certificate_skip_scep_crl $lattr $rattr $action $arg]
}

proc diff.vpn.certificate.crl.crl._skip {lattr rattr action arg} {
	return [certificate_skip_scep_crl $lattr $rattr $action $arg]
}

proc sessionsync_chk_port_range {local remote action} {
	global CONF_RET_T_OK CONF_RET_T_DONT
	global CONF_ACT_T_ADD CONF_ACT_T_EDIT

	if { $action == $CONF_ACT_T_EDIT || $action == $CONF_ACT_T_ADD } {
		set value [conf_attr_arg $remote 0]
		set range [split $value -]
		if { 1 == [llength $range] } {
			set lvalue [conf_attr_arg $local 0]
			set lrange [split $lvalue -]
			set port [lindex $range 0]
			if { 2 == [llength $lrange] && $port eq [lindex $lrange 0] && $port eq [lindex $lrange 1] } {
				return $CONF_RET_T_DONT
			}
			conf_set_attr $remote "$port-$port"
		}
	}
	return $CONF_RET_T_OK
}

proc diff.system.session-sync.filter.custom-service.src-port-range {local remote action arg} {
	return [sessionsync_chk_port_range $local $remote $action]
}

proc diff.system.session-sync.filter.custom-service.dst-port-range {local remote action arg} {
	return [sessionsync_chk_port_range $local $remote $action]
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

proc diff.switch-controller.unset-attr {parent attr} {
	if { $parent ne 0 } {
		set attr [conf_find_child $parent $attr]
		if { $attr ne 0 } {
			conf_unset_attr $attr
		}
	}
}

proc diff.switch-controller.qos.ip-dscp-map.map.diffserv {local remote action arg} {
	global CONF_ACT_T_EDIT
	global CONF_RET_T_OK

	if { $action != $CONF_ACT_T_EDIT } {
		return $CONF_RET_T_OK
	}

	set parent [conf_node_parent $local]
	diff.switch-controller.unset-attr $parent "ip-precedence"
	diff.switch-controller.unset-attr $parent "value"

	return $CONF_RET_T_OK
}

proc diff.switch-controller.qos.ip-dscp-map.map.ip-precedence {local remote action arg} {
	global CONF_ACT_T_EDIT
	global CONF_RET_T_OK

	if { $action != $CONF_ACT_T_EDIT } {
		return $CONF_RET_T_OK
	}

	set parent [conf_node_parent $local]
	diff.switch-controller.unset-attr $parent "diffserv"
	diff.switch-controller.unset-attr $parent "value"

	return $CONF_RET_T_OK
}

proc diff.switch-controller.qos.ip-dscp-map.map.values {local remote action arg} {
	global CONF_ACT_T_EDIT
	global CONF_RET_T_OK

	if { $action != $CONF_ACT_T_EDIT } {
		return $CONF_RET_T_OK
	}

	set parent [conf_node_parent $local]
	diff.switch-controller.unset-attr $parent "idiffserv"
	diff.switch-controller.unset-attr $parent "ip-precedence"

	return $CONF_RET_T_OK
}

proc diff.switch-controller.lldp-profile.med-network-policy {local remote action arg} {
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_SKIP

	if { $action != $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_OK
	}

	set lvdom [conf_node_root $local]
	set rvdom [conf_find_vdom [conf_node_name $lvdom] 1]
	set lprof [conf_node_parent [conf_node_parent $local]]
	set rprof [conf_find_child $rvdom "switch-controller lldp-profile"]
	if { $rprof ne 0 } {
		set lname [conf_node_name $lprof]
		set rprof [conf_find_child $rprof $lname]
	}
	if { $rprof eq 0 } {
		## lldp-profile node not found or profile not found, delete the entire profile
		conf_del_entry $lprof
	}
	return $CONF_RET_T_SKIP
}

proc diff.switch-controller.lldp-profile.med-location-service {local remote action arg} {
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_SKIP

	if { $action != $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_OK
	}

	set lvdom [conf_node_root $local]
	set rvdom [conf_find_vdom [conf_node_name $lvdom] 1]
	set lprof [conf_node_parent [conf_node_parent $local]]
	set rprof [conf_find_child $rvdom "switch-controller lldp-profile"]
	if { $rprof ne 0 } {
		set lname [conf_node_name $lprof]
		set rprof [conf_find_child $rprof $lname]
	}
	if { $rprof eq 0 } {
		## lldp-profile node not found or profile not found, delete the entire profile
		conf_del_entry $lprof
	}
	return $CONF_RET_T_SKIP
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

proc diff.switch-controller.dynamic-port-policy {local remote action arg} {
	global CONF_RET_T_OK CONF_RET_T_SKIP
	global CONF_ACT_T_DELETE

	if { $action == $CONF_ACT_T_DELETE } {
		set name [conf_node_name $local]
		set fnode [conf_find_attr $local "fortilink"]
		if { $fnode ne 0 } {
			set fortilink [conf_attr_arg $fnode 0]
			if { $fortilink eq $name } {
				set intfnode [conf_find_child [conf_find_child [conf_global] "system interface"] $name]
				set flink [conf_find_attr $intfnode "fortilink"]
				if { $flink ne 0 && [conf_attr_arg $flink 0] eq "enable" } {
					return $CONF_RET_T_SKIP
				}
			}
		}
	}

	return $CONF_RET_T_OK
}

proc diff.switch-controller.managed-switch.dynamic-capability {local remote action arg} {
	## this is read-only
	global CONF_RET_T_SKIP
	return $CONF_RET_T_SKIP
}

proc diff.system.interface.swc-first-create {local remote action arg} {
	## this is read-only
	global CONF_RET_T_SKIP
	return $CONF_RET_T_SKIP
}

proc diff.switch-controller.managed-switch {local remote action arg} {
	global CONF_ACT_T_ADD
	global CONF_RET_T_OK

	if { $action == $CONF_ACT_T_ADD } {
		## exit the switch node, and enter again to add all port information
		conf_goto_node [conf_node_root $local]
	}
	return $CONF_RET_T_OK
}

proc diff.switch-controller.nac-device {local remote action arg} {
	global CONF_ACT_T_ADD
	global CONF_ACT_T_DELETE
	global CONF_RET_T_DONT
	global CONF_RET_T_OK

	if { $action == $CONF_ACT_T_ADD || $action == $CONF_ACT_T_DELETE } {
		## do not allow add/remove through FMG
		return $CONF_RET_T_DONT
	}
	return $CONF_RET_T_OK
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

proc diff.system.virtual-wan-link.members {local remote action arg} {
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR

	if { $action == $CONF_ACT_T_DELETE } {
		set seq [conf_node_name $local]
		set list [conf_find_child [conf_node_parent [conf_node_parent $local]] "service"]
		conf_foreach_entry $list diff.vwl-member-check $seq
	}

	return $CONF_RET_T_OK
}

proc diff.system.sdwan.zone {local remote action arg} {
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR

	if { $action == $CONF_ACT_T_DELETE } {
		set ver [cli_get_devinfo "version"]
		set bpt [cli_get_devinfo "branch" ]
		if { $ver eq 700 && (($bpt >= 126 && $bpt < 337) || ($bpt >= 1082 && $bpt < 1143)) } {
			set name [conf_node_name $local]
			if { [conf_strcmp "SASE" $name] == 0 } {
				return $CONF_RET_T_DONT
			}
		}
	}
	return $CONF_RET_T_OK
}
proc diff.system.sdwan.members {local remote action arg} {
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR

	if { $action == $CONF_ACT_T_DELETE } {
		set seq [conf_node_name $local]
		set list [conf_find_child [conf_node_parent [conf_node_parent $local]] "service"]
		conf_foreach_entry $list diff.vwl-member-check $seq
	}

	return $CONF_RET_T_OK
}

proc diff.system.sdwan.members.interface {local remote action arg} {
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR

	if { $action == $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_OK
	}

	if { $local ne 0 } {
		set lvdom [conf_node_root $local]
	} else {
		set lvdom [conf_node_root $arg]
	}
	set member 0

	if { $remote != 0 } {
		set member [conf_attr_arg $remote 0]
	}
	if { $lvdom != 0 && $member != 0 && $member != "" } {
		set policy_node [conf_find_child $lvdom "firewall policy"]
		conf_foreach_entry $policy_node diff.vwl-member-pol-check $member
	}

	return $CONF_RET_T_OK
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

proc diff.system.virtual-wan-link.health-check {local remote action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR

	if { $action != $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_OK
	}

	set name [conf_node_name $local]
	set list [conf_find_child [conf_node_parent [conf_node_parent $local]] "service"]
	conf_foreach_entry $list diff.vwl-health-check $name

	return $CONF_RET_T_OK
}

proc diff.system.sdwan.health-check {local remote action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR

	if { $action != $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_OK
	}

	set name [conf_node_name $local]
	set list [conf_find_child [conf_node_parent [conf_node_parent $local]] "service"]
	conf_foreach_entry $list diff.vwl-health-check $name

	return $CONF_RET_T_OK
}

proc diff.system.sdwan.health-check.system-dns {lattr rattr action arg} {
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK

	if { $action == $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_OK
	}

	set ldns [conf_attr_arg $lattr 0]
	set rdns [conf_attr_arg $rattr 0]
	if { $ldns eq "enable" && $rdns eq "" } {
		set rparent [conf_node_parent $lattr]
		conf_add_script $lattr "set protocol dns"
	}

	return $CONF_RET_T_OK

}

proc diff.system.virtual-wan-link.neighbor {local remote action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR

	if { $action == $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_OK
	}

	set neighbor [conf_node_name $remote]
	set lbgp [conf_find_child [conf_node_root $local] "router bgp"]
	set rbgp [conf_find_child [conf_node_root $remote] "router bgp"]
	set lnbr [conf_find_child $lbgp "neighbor"]
	set rnbr [conf_find_child $rbgp "neighbor"]
	
	if { $lnbr == 0 } {
		set lnbr [conf_add_table $lbgp $rnbr]
	}

	set lentry [conf_find_child $lnbr $neighbor]
	set rentry [conf_find_child $rnbr $neighbor]
	if { $lentry == 0 } {
		set lentry [conf_add_entry $lnbr $rentry]
		conf_merge_entry_edit_chkdep $lentry $rentry
	}

	return $CONF_RET_T_OK
}

proc diff.system.sdwan.neighbor {local remote action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR

	if { $action == $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_OK
	}

	set neighbor [conf_node_name $remote]
	set lbgp [conf_find_child [conf_node_root $local] "router bgp"]
	set rbgp [conf_find_child [conf_node_root $remote] "router bgp"]
	set lnbr [conf_find_child $lbgp "neighbor"]
	set rnbr [conf_find_child $rbgp "neighbor"]
	
	if { $lnbr == 0 } {
		set lnbr [conf_add_table $lbgp $rnbr]
	}

	set lentry [conf_find_child $lnbr $neighbor]
	set rentry [conf_find_child $rnbr $neighbor]
	if { $lentry == 0 } {
		set lentry [conf_add_entry $lnbr $rentry]
		conf_merge_entry_edit_chkdep $lentry $rentry
	}

	return $CONF_RET_T_OK
}
proc diff.switch-controller.managed-switch.ports.port-owner {lattr rattr action arg} {
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_SKIP CONF_RET_T_ERROR;  

	if { $rattr == 0 } {
		return $CONF_RET_T_OK;
	}

	if { $action != $CONF_ACT_T_DELETE } {
		set trunk [conf_attr_arg $rattr 0]
		set rparent [conf_node_parent [conf_node_parent $rattr]]
	} else {
		set trunk [conf_attr_arg $lattr 0]
		set rparent [conf_node_parent $rattr]
	}
	set trunk [string trim $trunk \"]
	if { $lattr == 0 } {
		set lparent [conf_node_parent $arg]
	} else {
		set lparent [conf_node_parent [conf_node_parent $lattr]]
	}
	set rentry [conf_find_child $rparent $trunk]
	set lentry [conf_find_child $lparent $trunk]
	if { $lentry == 0 } {
		set lentry [conf_add_entry $lparent $rentry]
	}
	conf_merge_entry_edit_chkdep $lentry $rentry

	return $CONF_RET_T_SKIP;
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

proc shift_vpn_certs_ahead_global_usage {remote attr vpn} {
	set cert [conf_attr_arg [conf_find_attr $remote $attr] 0]
	set cert [string trim $cert "\""]
	if { $cert ne "" } {
		set rvdom [conf_find_vdom "root" 1]
		set lvdom [conf_find_vdom "root"]
		set rcerts [conf_find_child $rvdom $vpn]
		set lcerts [conf_find_child $lvdom $vpn]
		if { $lcerts == 0 } {
			set lcerts [conf_add_table $lvdom $rcerts]
		}
		set rentry [conf_find_child $rcerts $cert]
		set lentry [conf_find_child $lcerts $cert]
		if { $lentry == 0 } {
			set lentry [conf_add_entry $lcerts $rentry]
		}
		conf_merge_entry_edit_chkdep $lentry $rentry
	}
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
	if { [cli_get_devinfo "vdom-admin"] ne "yes" } {
		shift_vpn_certs_ahead_global_usage $remote "admin-server-cert" "vpn certificate local"
		shift_vpn_certs_ahead_global_usage $remote "auth-cert" "vpn certificate local"
		shift_vpn_certs_ahead_global_usage $remote "user-server-cert" "vpn certificate local"
		shift_vpn_certs_ahead_global_usage $remote "wifi-certificate" "vpn certificate local"
		shift_vpn_certs_ahead_global_usage $remote "wifi-ca-certificate" "vpn certificate ca"
	} else {
		shift_certs_ahead_global_usage $remote "admin-server-cert" "certificate local"
		shift_certs_ahead_global_usage $remote "auth-cert" "certificate local"
		shift_certs_ahead_global_usage $remote "user-server-cert" "certificate local"
		shift_certs_ahead_global_usage $remote "wifi-certificate" "certificate local"
		shift_certs_ahead_global_usage $remote "wifi-ca-certificate" "certificate ca"
	}
	return $CONF_RET_T_OK
}
proc diff.system.ddns {local remote action arg} {
	global CONF_RET_T_OK
	if { [cli_get_devinfo "vdom-admin"] ne "yes" } {
		shift_vpn_certs_ahead_global_usage $remote "ssl-certificate" "vpn certificate local"
	} else {
		shift_certs_ahead_global_usage $remote "ssl-certificate" "certificate local"
	}
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
proc diff.system.virtual-wan-link.neighbor.health-check {lattr rattr action arg} {
	if { $lattr } {
		set sla [conf_find_attr [conf_node_parent $lattr] "sla-id"]
		conf_unset_attr $sla
	}
	return $CONF_RET_OK
}

proc diff.system.sdwan.neighbor.health-check {lattr rattr action arg} {
	if { $lattr } {
		set sla [conf_find_attr [conf_node_parent $lattr] "sla-id"]
		conf_unset_attr $sla
	}
	return $CONF_RET_OK
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

proc diff.check_dup_prefix {local remote} {
	set lid [conf_node_name $local]
	set rid [conf_node_name $remote]

	if {$lid <= $rid} {
		return 0;
	}

	if { [diff_attr_val $local $remote "prefix"] } {
		return 0;
	}

	set rparent [conf_node_parent $remote]
	set rentry [conf_find_child $rparent $lid]
	if { $rentry eq 0 } {
		conf_del_entry $local
	} else {
		conf_merge_entry_edit $local $rentry
	}
	return 0
}

proc diff.router.bgp.network.prefix {local remote action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_EDIT;  
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR;  

	if {$action != $CONF_ACT_T_ADD && $action != $CONF_ACT_T_EDIT} {
		return $CONF_RET_T_OK;
	}
	if {!$remote} {
		return $CONF_RET_T_OK;
	}
	set rval [conf_attr_arg $remote 0]
	if { $rval == 0 } {
		return $CONF_RET_T_OK;
	}
	set rparent [conf_node_parent $remote]
	if { $local == 0 } {
		set parent $arg
	} else {
		set parent [conf_node_parent $local]
	}
	set lnetwork [conf_node_parent $parent]

	if { $lnetwork == 0 } {
		return $CONF_RET_T_OK;
	}

	conf_foreach_entry $lnetwork diff.check_dup_prefix $rparent

	return $CONF_RET_T_OK;
}

proc diff.sys.intf.delmember {entry name} {
	global CONF_RET_T_OK

	set attr [conf_find_attr $entry "type"]
	if { $attr == 0 } {
		return $CONF_RET_T_OK
	}
	set type [conf_attr_arg $attr 0]
	if { $type != "aggregate" && $type != "redundant" } {
		return $CONF_RET_T_OK
	}

	set attr [conf_find_child $entry "member"]
	if { $attr == 0 } {
		return $CONF_RET_T_OK
	}

	set i 0
	set argc [conf_attr_argc $attr]
	while { $i < $argc } {
		if { ![conf_strcmp [conf_attr_arg $attr $i] $name] } {
			set name [string trim [conf_node_name $entry] \"]
			set rentry [conf_find_child [conf_find_child [conf_global 1] "system interface"] $name]
			conf_merge_entry_edit $entry $rentry
			break
		}
		incr i
	}
	return $CONF_RET_T_OK
}

proc del.system.virtual-switch {local arg} {
	global CONF_RET_T_OK
	set name [string trim [conf_node_name $local] \"]
	set intf [conf_find_child [conf_find_child [conf_global] "system interface"] $name]
	conf_del_dependency $intf
	return $CONF_RET_T_OK
}

proc diff.system.virtual-switch {local remote action arg} {
	global CONF_ACT_T_EDIT CONF_ACT_T_DELETE CONF_ACT_T_CLEAR
	global CONF_RET_T_OK

	set curports ""
	set cmd ""

	if {$action == $CONF_ACT_T_EDIT} {
		set intflist [conf_find_child [conf_global] "system interface"];

		if {$local ne 0} {
			set portlist [cli_get_tbl_list $local "port"]
			foreach port $portlist {
				lappend curports [string trim [conf_node_name $port] \"]
			}
		}

		if {$remote ne 0} {
			set portlist [cli_get_tbl_list $remote "port"]
			foreach port $portlist {
				set ifname [string trim [conf_node_name $port] \"]
				if {[lsearch -exact $curports $ifname] < 0} {
					append cmd "edit \"$ifname\"\nunset ip\n"
					if { $intflist != 0 } {
						conf_foreach_entry $intflist diff.sys.intf.delmember $ifname
					}
				}
			}
		}

		if {$cmd ne ""} {
			if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
				conf_add_script [conf_global 1] "config global\nconfig system interface\n${cmd}end\nend"
			} else {
				conf_add_script [conf_global 1] "config system interface\n${cmd}end"
			}
		}
	} elseif {$action == $CONF_ACT_T_DELETE} {
		del.system.virtual-switch $local 0
	} elseif {$action == $CONF_ACT_T_CLEAR} {
		conf_foreach_entry $local del.system.virtual-switch 0
	}

	return $CONF_RET_T_OK
}

proc diff.sys.intf.fortilink {entry arg} {
	global CONF_RET_T_OK

	set attr [conf_find_attr $entry "fortilink"]
	if { $attr == 0 || [conf_attr_arg $attr 0] ne "enable"} {
		return $CONF_RET_T_OK
	}

	set name [string trim [conf_node_name $entry] \"]
	set rentry [conf_find_child [conf_find_child [conf_global 1] "system interface"] $name]
	conf_merge_entry_edit $entry $rentry

	return $CONF_RET_T_OK
}

proc diff.system.global.switch-controller {local remote action arg} {
	global CONF_ACT_T_EDIT
	global CONF_RET_T_OK

	set val [conf_attr_arg $local 0]
	if { $val != "enable" } {
		return $CONF_RET_T_OK;
	}

	set intflist [conf_find_child [conf_global] "system interface"];

	if { $intflist != 0 } {
		conf_foreach_entry $intflist diff.sys.intf.fortilink 0
	}

	return $CONF_RET_T_OK
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

proc diff.merge-interface-swc-sets {local remote action} {
	global CONF_ACT_T_ADD CONF_ACT_T_EDIT
	global CONF_RET_T_OK CONF_RET_T_SKIP

	if { $action != $CONF_ACT_T_ADD && $action != $CONF_ACT_T_EDIT } {
		return $CONF_RET_T_OK
	}

	set val [conf_attr_arg $remote 0]
	set intf [conf_node_parent $remote]
	set vdname [string trim [conf_attr_arg [conf_find_child $intf "vdom"] 0] \"]

	if { [cli_get_devinfo "version"] < "700" } {
		set rvdom [conf_find_vdom $vdname 1]
		set rnacset [conf_find_child $rvdom "switch-controller nac-settings"]
		set lvdom [conf_find_vdom $vdname]
		set lnacset [conf_find_child $lvdom "switch-controller nac-settings"]
	} else {
		set rvdom [conf_find_vdom $vdname 1]
		set rnacset [conf_find_child $rvdom "switch-controller fortilink-settings"]
		set lvdom [conf_find_vdom $vdname]
		set lnacset [conf_find_child $lvdom "switch-controller fortilink-settings"]
	}

	set rnac [conf_find_child $rnacset $val]
	set lnac [conf_find_child $lnacset $val]

	if { $lnac ne 0 && $rnac ne 0 } {
		conf_merge_entry_edit_chkdep $lnac $rnac
	}

	set vdom_enable [cli_get_devinfo "vdom-admin"]
	if { $vdom_enable eq "yes" } {
		set intfname [conf_node_name $intf]
		set attr [conf_node_name $remote]
		conf_add_script [conf_global 1] "config vdom\nedit $vdname\nconfig system interface\nedit $intfname\nset $attr $val\nend\nend"
		return $CONF_RET_T_SKIP
	}

	return $CONF_RET_T_OK
}

proc diff.system.interface.switch-controller-nac {local remote action arg} {
	return [diff.merge-interface-swc-sets $local $remote $action]
}

proc diff.system.interface.switch-controller-dynamic {local remote action arg} {
	return [diff.merge-interface-swc-sets $local $remote $action]
}

proc diff.vpn.ipsec.phase1-interface.fec-health-check {local remote action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_DONT CONF_RET_T_ERROR

	if { $action == $CONF_ACT_T_DELETE } {
		return $CONF_RET_T_OK
	}

	set hcheck [string trim [conf_attr_arg $remote 0] \"]
	if { $hcheck ne "" } {
		set lhcheck 0
		set r_root [conf_node_root $remote]
		set vdom_name [conf_node_name $r_root]
		if { $local != 0 } {
			set lsdwan [conf_find_child [conf_node_root $local] "system sdwan"]
			set lhealth_check [conf_find_child $lsdwan "health-check"]
			set lhcheck [conf_find_child $lhealth_check $hcheck]
		} else {
			set l_root [conf_find_vdom $vdom_name 0]
			set lsdwan [conf_find_child $l_root "system sdwan"]
			set lhealth_check [conf_find_child $lsdwan "health-check"]
			if { $lhealth_check != 0 } {
				set lhcheck [conf_find_child $lhealth_check $hcheck]
			}
		}
		if { $lhcheck == 0 } {
			set rsdwan [conf_find_child $r_root "system sdwan"]
			set rhealth_check [conf_find_child $rsdwan "health-check"]
			set rhcheck [conf_find_child $rhealth_check $hcheck]
			if { $lhealth_check == 0 } {
				set lhealth_check [conf_add_table $lsdwan $rhealth_check]
			}
			set lhcheck [conf_add_entry $lhealth_check $rhcheck]
			conf_merge_entry_edit $lhcheck $rhcheck
		}
	}

	return $CONF_RET_T_OK
}
proc diff.system.automation-stitch {local remote action arg} {
	global CONF_ACT_T_ADD CONF_ACT_T_EDIT
	global CONF_RET_T_OK CONF_RET_T_SKIP

	if { $action != $CONF_ACT_T_EDIT } {
		return $CONF_RET_T_OK
	}

	set lvdom [conf_node_root $local]
	set rvdom [conf_node_root $remote]

	set actlist {}
	conf_foreach_entry [conf_find_child $remote "actions"] build-list actlist

	foreach act $actlist {
		set action [string trim [conf_attr_arg [conf_find_attr $act "action"] 0] \"]
		set lactable [conf_find_child $lvdom "system automation-action"]
		set ractable [conf_find_child $rvdom "system automation-action"]
		if { $lactable eq 0 } {
			set lactable [conf_add_table $lvdom $ractable]
		}

		set lact [conf_find_child $lactable $action]
		set ract [conf_find_child $ractable $action]
		if { $lact eq 0 } {
			set lact [conf_add_entry $lactable $ract]
		}

		conf_merge_entry_edit $lact $ract
	}
}
proc vdom_property_resource_limit_cmp {lattr rattr action} {
	global CONF_ACT_T_EDIT
	global CONF_RET_T_OK
	if { $rattr ne 0 && $action == $CONF_ACT_T_EDIT } {
		##
		## Fortigate CLI only accepts the first integer in set command:
		## Therefore we ignore the rest of integers.
		##
		set r_first [conf_attr_arg $rattr 0]
		if { $r_first ne 0 } {
			conf_set_attr $rattr $r_first 1
		}
		if { $lattr ne 0 } {
			set l_first [conf_attr_arg $lattr 0]
			if { $l_first ne 0 } {
				conf_set_attr $lattr $l_first 1
			}
		}
	}
	return $CONF_RET_T_OK
}
proc diff.system.vdom-property.log-disk-quota {lattr rattr action arg} {
	return [vdom_property_resource_limit_cmp $lattr $rattr $action]
}

proc diff.system.sdwan.members.interface {lattr rattr action arg} {
	global CONF_ACT_T_DELETE
	global CONF_RET_T_OK CONF_RET_T_SKIP
	if { $action == $CONF_ACT_T_DELETE } {
		conf_set_attr $lattr "''"
		return $CONF_RET_T_SKIP
	}
	return $CONF_RET_T_OK
}
%}
