global_foo %{
namespace eval global {
	namespace export *
	proc identity_based_visib { parent } {
		set act [cli_get_value $parent "" "" "action"]
		if { [cli_ver_start 400 3] } {
			if { $act eq "accept" || $act eq "ssl-vpn" } { return 1 }
		} else {
			if { $act eq "accept" } { return 1 }
		}
		return 0
	}
	proc skip_if_nosplit { parent } {
		if { [cli_ver_start 400 3] } {
			if { [cli_is_match $parent 0 "" "srcintf" 0 "\"web-proxy\""] ||
			     [cli_is_match $parent 0 "" "srcintf" 0 "\"ftp-proxy\""] } {
				return 1
			}
			if {![identity_based_visib $parent]} {
				return 1
			}
			if {[cli_is_match $parent 0 "" "identity-based" 1 "enable"]} {
				return 1
			}
		} else {
			if { [cli_is_match $parent 0 "" "srcintf" 0 "\"web-proxy\""] } {
				return 1
			}
			if {[identity_based_visib $parent]} {
				if {[cli_is_match $parent 0 "" "identity-based" 1 "enable"]} {
					return 1
				}
			} elseif {[cli_is_match $parent 0 "" "action" 1 "ssl-vpn"]} {
				return 1
			}
		}
		return 0
	}
	proc skip_if_accept_nosplit { parent } {
		if {[skip_if_nosplit $parent]} {
			return 1
		}
		if {[cli_is_match $parent 0 "" "action" 1 "accept"]} {
			return 1
		}
		return 0
	}
	proc dmgmt_vdom_support { } {
                set platform [cli_get_devinfo "platform"]
                if {[string match -nocase "FortiProxy-*" $platform]} {
			if {[cli_obj_support "system dedicated-mgmt"]} {
				global CLI_GLOBAL_NODE
				set en [cli_get_value $CLI_GLOBAL_NODE "system dedicated-mgmt" "" "status"]
				if {$en eq "enable"} {
					return 1
				}
			}
                } elseif { [cli_ver_start 500 0] } {
			if { [cli_has_feature "f_dmgmt"] } {
				return 1
			}
		} else {
			if {[cli_obj_support "system dedicated-mgmt"]} {
				global CLI_GLOBAL_NODE
				set en [cli_get_value $CLI_GLOBAL_NODE "system dedicated-mgmt" "" "status"]
				if {$en eq "enable"} {
					return 1
				}
			}
		}
                return 0
	}
	proc vpn_invalid_tunnel_ip_pools_addrs { ippools addrnode } {
		set intf [cli_get_value $addrnode "" "" "associated-interface"]
		if { $intf ne "" && $intf ne "any" } {
			if {[string compare -length 4 $intf "ssl."] == 0} {
				cli_set_errmsg "the address $ippools with associated-interface $intf is invalid"
				return 1
			}
		}
		set type [cli_get_value $addrnode "" "" "type"]
		if { $type eq "ipmask" } {
			set subnet [cli_get_value $addrnode "" "" "subnet"]
			if { $subnet eq "0.0.0.0 0.0.0.0" } {
				cli_set_errmsg "the address $ippools with subnet $subnet is invalid"
				return 1
			}
		} elseif { $type eq "iprange" } {
			set start [cli_get_value $addrnode "" "" "start-ip"]
			set end [cli_get_value $addrnode "" "" "end-ip"]
			if { $start eq "0.0.0.0" && $end eq "0.0.0.0" } {
				cli_set_errmsg "the address $ippools with iprange $start - $end is invalid"
				return 1
			}
		} else {
			cli_set_errmsg "the address $ippools with type $type is invalid"
			return 1
		}
		return 0
	}
	proc vpn_invalid_tunnel_ip_pools { ippools } {
		global CLI_CUR_VDOM_NODE
		set addrnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $ippools ""]
		if { $addrnode } {
			if { [vpn_invalid_tunnel_ip_pools_addrs $ippools $addrnode] } {
				return 1
			}
		} else {
			set addrgrpnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp" $ippools ""]
			if { $addrgrpnode } {
				set grpmember [cli_get_value $addrgrpnode "" "" "member"]
				foreach m $grpmember {
					if { [vpn_invalid_tunnel_ip_pools $m] } {
						return 1
					}
				}
			}
		}
		return 0
	}
	proc webcache_can_not_enable_per_policy { cur_node }  {
		global CLI_CUR_VDOM_NODE
		set profileopt ""
		set mmsprof ""
		if { [cli_get_value $cur_node "" "" "utm-status"] ne "enable" } {
			return 0
		}
		set ptype [cli_get_value $cur_node "" "" "profile-type"]
		if { $ptype eq "single" } {
			set profileopt [cli_get_value $cur_node "" "" "profile-protocol-options"]
			if { [cli_obj_support "firewall policy" "mms-profile"] } {
				set mmsprof [cli_get_value $cur_node "" "" "mms-profile"]
			}
		} elseif { $ptype eq "group" } {
			set pgroup [cli_get_value $cur_node "" "" "profile-group"]
			if { $pgroup ne "" } {
				set node [cli_get_node $CLI_CUR_VDOM_NODE "firewall profile-group" $pgroup ""]
				if { $node } {
					set profileopt [cli_get_value $node "" "" "profile-protocol-options"]
					if { [cli_obj_support "firewall profile-group" "mms-profile"] } {
						set mmsprof [cli_get_value $node "" "" "mms-profile"]
					}
				}
			}
		}
		if { $profileopt ne "" } {
			set node [cli_get_node $CLI_CUR_VDOM_NODE "firewall profile-protocol-options" $profileopt ""]
			if { 0 != $node && [expr {[cli_get_value $node "http" "" "inspect-all"] eq "enable"}]} {
				cli_set_errmsg "Web cache cannot be enabled when inspect-all is enabled in http protocol option."
				return 1
			}
		}
		if { $mmsprof ne "" } {
			cli_set_errmsg "Web cache cannot be enabled when an mms-profile is set."
			return 1
		}
		return 0
	}
	proc webcache_can_not_enable { cur_node }  {
		global CLI_CUR_VDOM_NODE
		if { [cli_get_value $cur_node "" "" "identity-based"] ne "enable" } {
			if { [webcache_can_not_enable_per_policy $cur_node] } {
				return 1
			}
		} else {
			set ibp_list [cli_get_tbl_list $cur_node "identity-based-policy"]
			foreach ibp $ibp_list {
				if { [webcache_can_not_enable_per_policy $ibp] } {
					return 1
				}
			}
		}
		return 0
	}
        proc global_admin_https_redirected_valid { } {
                if {![cli_obj_support "system global" "admin-https-redirect"]} {
                       return 0
                }
                set lenc [cli_get_devinfo "LENC"]
                if {$lenc eq "yes"} {
                        return 0
                }
                set platform [cli_get_devinfo "platform"]
                set sn [cli_get_devinfo "sn"]
                if {[string match -nocase "*-VM*" $platform] && [string match -nocase "FGVMEV*" $sn]} {
                        retrun 0
                }
                if {[string match -nocase "*-LENC" $platform]} {
                        return 0
                }
                if {[string index $sn 0] == "L"} {
                        return 0
                }
                return 1
        }
        proc check_switch_intf { intf_node global_node } {
		set name [cli_get_value $intf_node "" "" "name"]
		set name [string trim $name \"]
		set nodelist [cli_get_tbl_list $global_node "system switch-interface"]
		foreach node $nodelist {
			set memberlist [cli_get_value $node "" "" "member"]
			foreach member $memberlist {
				set member [string trim $member \"]
				if {$name eq $member} {
					return 0
				}
       			}
		}
		return 1
	}
        proc nCfg_is_port_pair_member { intf_node } {
		set ifname [cli_get_value $intf_node "" "" "name"]
		set ifname [string trim $ifname \"]
		set vdom [cli_get_value $intf_node "" "" "vdom"]
		set vnode [cli_get_vdom_node $vdom]
		set nodelist [cli_get_tbl_list $vnode "system virtual-wire-pair"]
		foreach node $nodelist {
			set memberlist [cli_get_value $node "" "" "member"]
			foreach member $memberlist {
				set member [string trim $member \"]
				if {$ifname eq $member} {
					return 1
				}
			}
		}
		return 0
	}
	proc num_of_vs_and_intfs { vsmax } {
		global CLI_GLOBAL_NODE
		set vsttl 0
		set porttl 0
		set nodelist [cli_get_tbl_list $CLI_GLOBAL_NODE "system virtual-switch"]
		foreach node $nodelist {
			set ports [cli_get_tbl_cnt $node "port"]
			set porttl [expr ($porttl + $ports)]
			set vsttl [expr ($vsttl + 1)]
		}
		return [expr ($vsmax - $porttl + $vsttl)]
	}
	proc intf_is_ipsec_tunnel { node } {
                set ipsec_tunnel 0
                if { [cli_get_value $node "" "" "type"] eq "tunnel" } {
                        set name [cli_get_value $node "" "" "name"]
                        set vdom [cli_get_value $node "" "" "vdom"]
                        set vnode [cli_get_vdom_node $vdom]
                        if {[cli_get_match_nr $vnode 1 "vpn ipsec phase1-interface" "interface" 0 "\"$name\""] ||
                            [cli_get_match_nr $vnode 1 "vpn ipsec manualkey-interface" "interface" 0 "\"$name\""]} {
                                set ipsec_tunnel 1
                        }
                }
		return $ipsec_tunnel
	}
	proc intf_vxlan { node } {
		if { [cli_get_value $node "" "" "type"] ne "tunnel" } {
			return 0
		}
		set name [cli_get_value $node "" "" "name"]
		set vnode [cli_get_vdom_node [cli_get_value $node "" "" "vdom"]]
		if {[cli_get_match_nr $vnode 1 "vpn ipsec phase1-interface" "interface" 0 "\"$name\"" "encapsulation" 0 "vxlan"]} {
			return 1
		}
		return 0
	}
	proc sys_intf_mtu_override_visible { node } {
		global CLI_GLOBAL_NODE
		set type [cli_get_value $node "" "" "type"]
		if { $type ne "aggregate" && $type ne "redundant" && [cli_is_used $node "system interface" "member"] } {
			set name [cli_get_value $node "" "" "name"]
			set nodelist1 [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
			foreach node1 $nodelist1 {
				if { [cli_if_same_node $node1 $node] } {
						continue
				}
				set intftype [cli_get_value $node1 "" "" "type"]
				if {$intftype eq "aggregate"} {
					set members [string map {"\"" ""} [cli_get_value $node1 "" "" "member"]]
					set members [split $members " "]
					foreach member $members {
						if { $member eq $name } {
							return 0
						}
					}
				}
			}
		}
		if { [intf_is_ipsec_tunnel $node] } {
			return 0
		}
		if { $type eq "physical" || $type eq "hdlc" || $type eq "tdm" || $type eq "vlan" || $type eq "aggregate" || $type eq "redundant" || $type eq "fctrl-trunk" || $type eq "tunnel" || $type eq "wireless" || $type eq "vap-switch" || $type eq "switch" || $type eq "hard-switch" || $type eq "fext-wan" || $type eq "emac-vlan" || $type eq "vxlan" || $type eq "geneve" } {
			return 1
		}
		return 0
	}
	proc ip_class { ipstr } {
		set CLASSALOW    0x01000000
		set CLASSAHIGH    0x7EFFFFFF
		set CLASSBLOW    0x80000000
		set CLASSBHIGH    0xBFFFFFFF
		set CLASSCLOW    0xC0000000
		set CLASSCHIGH    0xDFFFFFFF
		set CLASSMCLOW    0xE0000000
		set CLASSMCHIGH    0xEFFFFFFF
		set iplist [split $ipstr .]
		if { [llength $iplist] ne 4 || ![string is digit [lindex $iplist 0]] || ![string is digit [lindex $iplist 1]] || ![string is digit [lindex $iplist 2]] ||![string is digit [lindex $iplist 3]] } {
			set class "N"
			return $class
		}
		set ipint [expr { (([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]) & 0xffffffff }]
		if { $CLASSALOW <= $ipint && $ipint <= $CLASSAHIGH } {
			set class "A"
		} elseif { $CLASSBLOW <= $ipint && $ipint <= $CLASSBHIGH } {
			set class "B"
		} elseif { $CLASSCLOW <= $ipint && $ipint <= $CLASSCHIGH } {
			set class "C"
		} elseif { $CLASSMCLOW <= $ipint && $ipint <= $CLASSMCHIGH } {
			set class "M"
		} else {
			set class "N"
		}
		return $class
	}
	proc vip_mappedip_invalid { ipstr } {
		proc ip_mappedip_invalid { addr } {
			set ippat {(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)}
                        if { (![regexp $ippat [lindex $addr 0] ip])|| ([lindex $addr 0] ne $ip)} {
                                return 1
                        }
                        if { ($ip eq "0.0.0.0") || ($ip eq "255.255.255.255") } {
                                return 1
                        }
			return 0
		}
		proc ip_to_value { addr } {
			set iplist [split $addr .]
			return [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
		}
		set iprange [split $ipstr -]
		if { 2 == [llength $iprange]} {
			set start_ip [lindex $iprange 0]
			set end_ip [lindex $iprange 1]
			if { [ip_mappedip_invalid $start_ip] } {
				return 1
			}
			if { [ip_mappedip_invalid $end_ip] } {
				return 1
			}
			if {[ip_to_value $start_ip] > [ip_to_value $end_ip]} {
				return 1
			}
			return 0
		}
		set ipmask [split $ipstr /]
		if {[llength $ipmask] == 2} {
			set ip [lindex $ipmask 0]
			set len [lindex $ipmask 1]
			if { [ip_mappedip_invalid $ip] } {
				return 1
			}
			if { $len<0 || $len> 32} {
				return 1
			}
			return 0
		}
		if { [ip_mappedip_invalid $ipstr] } {
			return 1
		}
		return 0
	}
        proc auto_set_snmp_index { intfname } {
		global CLI_GLOBAL_NODE
		set obj "system interface"
		set mid [cli_alloc_snmp_index $intfname $obj]
		if { $mid > 0 } {
			cli_exec_cmd $CLI_GLOBAL_NODE "config $obj\nedit \"$intfname\"\nset snmp-index $mid\nend\n"
		}
        }
	proc auto_update_vdom_link_macddr { name type } {
		global CLI_GLOBAL_NODE
		set intf1 "${name}0"
		set intf2 "${name}1"
		set cmd "config system interface\n"
		append cmd "edit $intf1\nset vdom \"root\"\nset type vdom-link\n"
		if { $type eq "ethernet" } {
			set macaddr [cli_get_value $CLI_GLOBAL_NODE "system interface" $intf1 "macaddr"]
			if { $macaddr == 0 || $macaddr eq "" || $macaddr eq "00:00:00:00:00:00" } {
				set mac [cli_gen_macaddr]
				append cmd "set macaddr $mac\n"
			}
		}
		append cmd "next\n"
		append cmd "edit $intf2\nset vdom \"root\"\nset type vdom-link\n"
		if { $type eq "ethernet" } {
			set macaddr [cli_get_value $CLI_GLOBAL_NODE "system interface" $intf2 "macaddr"]
			if { $macaddr == 0 || $macaddr eq "" || $macaddr eq "00:00:00:00:00:00" } {
				set mac [cli_gen_macaddr]
				append cmd "set macaddr $mac\n"
			}
		}
		append cmd "next\n"
		append cmd "end\n"
		set r [cli_exec_cmd $CLI_GLOBAL_NODE $cmd]
		if {[cli_obj_support "system interface" "snmp-index"]} {
			auto_set_snmp_index $intf1
			auto_set_snmp_index $intf2
		}
		return $r
	}
        proc get_mesh_intf_name { vdname } {
                set intfname "mesh.$vdname"
                set maxsize [cli_get_objlimit 0 "system interface" "name"]
                if { $maxsize > 0 } {
                        set intfname [string range $intfname 0 [expr $maxsize - 1]]
                }
                return $intfname
        }
        proc set_vdom_snmp_index { vdname } {
                global CLI_GLOBAL_NODE
		set obj "system vdom-property"
		set mid [cli_alloc_snmp_index $vdname $obj]
		if { $mid > 0 } {
			cli_exec_cmd $CLI_GLOBAL_NODE "config $obj\nedit $vdname\nset snmp-index $mid\nend\n"
		}
        }
	proc normalize_ip6_list {ip6list ip6} {
		upvar $ip6list l

		set l [split $ip6 :]
		set len [llength $l]
		set last [expr $len - 1]
		set tmp [lindex $l $last]

		if {[regexp {(\d+)\.(\d+)\.(\d+)\.(\d+)} $tmp dummy ip1 ip2 ip3 ip4] != 0} {
			set l [lreplace $l $last $last]
			lappend l $ip1 $ip2 $ip3 $ip4
			incr len 3
		}

		set tmp [lsearch $l {}]
		if {$tmp != -1} {
			set l [lreplace $l $tmp $tmp ]

			set missing [expr 9 - $len]
			for {set i 0} {$i < $missing} {incr i} {
				set l [linsert $l $tmp "0"]
			}
		}
	}
	proc verify_proxyid {dir name_count} {
		global CLI_CUR_NODE
		upvar $name_count count

		set atype "${dir}-addr-type"
		set addr_type [cli_get_value $CLI_CUR_NODE "" "" "${dir}-addr-type"]
		switch $addr_type {
			"" {
				set subnet [cli_get_value $CLI_CUR_NODE "" "" "${dir}-subnet"]
				if {$subnet eq "0.0.0.0 255.255.255.255"} {
					return -1
				}
			}
			"range" {
				set start_ip [cli_get_value $CLI_CUR_NODE "" "" "${dir}-start-ip"]
				set end_ip [cli_get_value $CLI_CUR_NODE "" "" "${dir}-end-ip"]
				if {$end_ip eq ""} {
					return -1
				}
				if {$start_ip ne ""} {
					set iplist [split $start_ip .]
					set sipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
					set iplist [split $end_ip .]
					set eipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
					if {$sipint > $eipint} {
						return -1
					}
				}
			}
			"ip" {
				set start_ip [cli_get_value $CLI_CUR_NODE "" "" "${dir}-start-ip"]
				if {$start_ip eq ""} {
					return -1
				}
			}
			"subnet6" {
				set subnet6 [cli_get_value $CLI_CUR_NODE "" "" "${dir}-subnet6"]
				if {$subnet6 eq ""} {
					return -1
				}
			}
			"ip6" {
				set start_ip6 [cli_get_value $CLI_CUR_NODE "" "" "${dir}-start-ip6"]
				if {$start_ip6 eq ""} {
					return -1
				}
			}
			"range6" {
				set start_ip6 [cli_get_value $CLI_CUR_NODE "" "" "${dir}-start-ip6"]
				set end_ip6 [cli_get_value $CLI_CUR_NODE "" "" "${dir}-end-ip6"]
				if {$end_ip6 eq ""} {
					return -1
				}
				set start_list {}
				set end_list {}
				normalize_ip6_list start_list $start_ip6
				normalize_ip6_list end_list $end_ip6
				for {set i 0} {$i < 8} {incr i} {
					set e1 [lindex $start_list $i]
					set e2 [lindex $end_list $i]
					if { $e1 eq "" || $e2 eq "" } {
						continue
					}
					set diff [expr $e1 - $e2]
					if {$diff != 0} {
						if {$diff > 0} {
							return -1
						}
						break
					}
				}
			}
			"name"  {
				incr count
			}
		}
		return 0
	}
	proc normalize_ip6_list {ip6list ip6} {
		upvar $ip6list l

		set l [split $ip6 :]
		set len [llength $l]
		set last [expr $len - 1]
		set tmp [lindex $l $last]

		if {[regexp {(\d+)\.(\d+)\.(\d+)\.(\d+)} $tmp dummy ip1 ip2 ip3 ip4] != 0} {
			set l [lreplace $l $last $last]
			lappend l $ip1 $ip2 $ip3 $ip4
			incr len 3
		}

		set tmp [lsearch $l {}]
		if {$tmp != -1} {
			set l [lreplace $l $tmp $tmp ]

			set missing [expr 9 - $len]
			for {set i 0} {$i < $missing} {incr i} {
				set l [linsert $l $tmp "0"]
			}
		}
	}
	proc auth_cert_not_exist { auth } {
		set auth [string trim $auth \"]
		if { $auth ne "" } {
			if { $auth eq "Fortinet_Factory" ||
			     $auth eq "Fortinet_Factory2" } {
				if { [cli_get_devinfo $auth] eq "no" } {
					return 1
				}
			}
		}
		return 0
	}
	proc ospf_md5key_valid { id enc v } {
		if { ![regexp {^[0-9]+$} $id] } {
			cli_set_errmsg "The id \"$id\" must be an integer."
			return 0
		}
		if { $id < 1 || $id > 255 } {
			cli_set_errmsg "The id \"$id\" must between 1-255."
			return 0
		}
		if { $enc ne "ENC" } {
			if {[string length $v] > 16} {
				cli_set_errmsg "The key is too long. The maximum length is 16."
				return 0
			}
		}
		return 1
	}
	proc ospf_md5key_check { id md5 } {
		set id [string trim $id \"]
		if {$md5 eq ""} {
			cli_set_errmsg "Please input the md5-key with right pattern. (Example: 1 \"abc\")"
			return 0
		}
		set md5 [string trim $md5 \"]
		set first_enc [string first "ENC " $md5]
		if {$first_enc == 0} {
			set enc "ENC"
			set md5 [string trimleft $md5 "ENC "]
		} else {
			set enc ""
		}
		if { ![ospf_md5key_valid $id $enc $md5] } {
			return 0
		}
		return 1
	}
	proc intf_used_by_other_zone { intf zone } {
		global CLI_CUR_VDOM_NODE
		set zonelist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "system zone"]
		foreach zonenode $zonelist {
			if { $zone ne "" && [cli_if_same_node $zone $zonenode] } {
                                continue
                        }
			set zoneintf [cli_get_value $zonenode "" "" "interface"]
			if { $zoneintf eq ""} {
				continue
			}
			if {("\"$intf\"" eq $zoneintf) || ([lsearch -exact $zoneintf $intf] >= 0)} {
				cli_set_errmsg "Zone member $intf is used by another zone"
				return 1
			}
		}
		return 0
	}
	proc invalid_zone_member { intf zone } {
		if { [intf_used_by_other_zone $intf $zone] } {
			return 1
		}
		return 0
	}
	proc sync_certs_between_global_vdom { sroot scat } {
		set certs {}
		set cmd ""
		if { $scat eq "certificate ca" } {
			set certs [cli_get_match_list $sroot 1 $scat "range" 0 "global" "source" 1 "factory" "source" 1 "bundle"]
		} else {
			set certs [cli_get_match_list $sroot 1 $scat "range" 0 "global"]
		}
                foreach c $certs {
			set a [cli_get_value $c "" "" "name"]
			if { $a eq "" || $a eq 0 } { continue }			
			append cmd "edit \"$a\"\n"
			append cmd [cli_export_node_attrs $c]
			append cmd "next\n"
                }
		return $cmd
	}
	proc ncfg_get_local_wtp_id { } {
                set sn [cli_get_devinfo "sn"]
                set reserved [string range $sn 0 5]
                append reserved "-WIFI0"
		return $reserved
	}
	proc capwap_mesh_enabled_vap_exist { vaps } {
		global CLI_GLOBAL_NODE
		global CLI_CUR_VDOM_NAME
		foreach vap $vaps {
			set vap [string trim $vap "\""]
			if { [cli_ver_start 600 2] } {
				set vdnode [cli_get_vdom_node $CLI_CUR_VDOM_NAME]
				if { $vdnode && [cli_get_match_nr $vdnode 1 "wireless-controller vap" "mesh-backhaul" 0 "enable" "name" 0 $vap] } {
					return 1
				}
			} elseif {[cli_get_match_nr $CLI_GLOBAL_NODE 1 "wireless-controller vap" "vdom" 0 $CLI_CUR_VDOM_NAME "mesh-backhaul" 0 "enable" "name" 0 $vap]} {
				return 1
			}
		}
		return 0
	}
	proc capwap_mesh_intf_auto_add { } {
		global CLI_GLOBAL_NODE
		global CLI_CUR_VDOM_NODE
		global CLI_CUR_VDOM_NAME
		if { ![cli_get_node $CLI_GLOBAL_NODE "system interface" "wl.mesh" ""] } {
			set cmd "config system interface\nedit \"wl.mesh\"\nset vdom \"$CLI_CUR_VDOM_NAME\"\nset ip 192.168.3.99 255.255.255.0\nset allowaccess ping capwap\nset type wl-mesh\nnext\nend\n"
			cli_exec_cmd $CLI_GLOBAL_NODE $cmd
			auto_set_snmp_index "wl.mesh"
		}
		if {[cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "system dhcp server" "interface" 0 "wl.mesh"] == 0} {
			set cmd "config system dhcp server\nedit 0\nset dns-service default\nset default-gateway 192.168.3.99\nset netmask 255.255.255.0\nset interface \"wl.mesh\"\nconfig ip-range\nedit 1\nset start-ip 192.168.3.110\nset end-ip 192.168.3.210\nnext\nend\nnext\nend\n"
			cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		}
	}
	proc capwap_mesh_intf_auto_del { } {
		global CLI_GLOBAL_NODE
		global CLI_CUR_VDOM_NODE
		set dhcps [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "system dhcp server" "interface" 0 "wl.mesh"]
		foreach d $dhcps {
			cli_delete_node $d
			break
		}
		set intf [cli_get_node $CLI_GLOBAL_NODE "system interface" "wl.mesh" ""]
		cli_delete_node $intf
	}
	proc capwap_mesh_intf_auto_add_check_pass { } {
		global CLI_GLOBAL_NODE
		global CLI_CUR_VDOM_NODE
		global CLI_CUR_VDOM_NAME
		if {[cli_get_match_nr $CLI_GLOBAL_NODE 1 "system interface" "name" 0 "wl.mesh" "vdom" 1 $CLI_CUR_VDOM_NAME]} {
			cli_set_errmsg "ERR: intf wl.mesh already exists."
			return 0
		}
		return 1
	}
	proc capwap_mesh_intf_auto_del_check_pass { } {
		return 1
	}
	proc check_hostname { host } {
		if { ![regexp {^[0-9a-zA-Z\.\-:]+$} $host] } {
			return 1
		}
		if { [string first ".." $host] >= 0 || [string first ".-" $host] >= 0 || [string first "-." $host] >= 0 } {
			return 1
		}
		if { [regexp {^[\.\-]} $host] || [regexp {[\.\-]$} $host] } {
			return 1
		}
		return 0
	}
	proc quick_check_ipv6 { ip } {
		if { ![regexp {^[0-9a-fA-F\.:]+$} $ip] } {
			return 1
		}
		return 0
	}
	proc scan_mode_full { node } {
		if { [cli_branchpt_start 600 954] } {
			return [cli_is_match $node 0 "" "scan-mode" 0 "legacy"]
		} else {
			return [cli_is_match $node 0 "" "scan-mode" 0 "full"]
		}
	}
	proc scan_mode_quick { node } {
		if { [cli_branchpt_start 600 954] } {
			return [cli_is_match $node 0 "" "scan-mode" 0 "default"]
		} else {
			return [cli_is_match $node 0 "" "scan-mode" 0 "quick"]
		}
	}
	# check if the ip address is a unicast address
	# from fgt src plugin_util.c:get_ip_type
	proc check_gw {gwstr} {
		if { $gwstr eq "" } {
			return -1
		}
		set gw [split $gwstr .]
		set gw_byte1 [lindex $gw 0]
		set gw_byte2 [lindex $gw 1]
		set gw_byte3 [lindex $gw 2]
		set gw_byte4 [lindex $gw 3]

		if { $gw_byte1==0 && $gw_byte2==0 && $gw_byte3==0 && $gw_byte4==0 } {
			return -1
		}
		if { $gw_byte1 == 127 || $gw_byte1 & 0xf0 == 0xe0 || ($gw_byte1==255 && $gw_byte2==255 && $gw_byte3==255 && $gw_byte4==255) } {
			return -1
		}
		return 0
	}

	proc check_src_string {string} {
		set allow [list "arp" "capwap" "cdp" "coap" "csf" "dhcp" "dns" "forticlient" "fortiguard" "ftp" "hpdi" "http" \
			"imap" "kerberos" "lldp" "llmnr" "lltd" "mac" "mapi" "mndp" "mwbs" "nbns" "none" "nspi" "onvif" "pop3" \
			"rpce" "rtsp" "sihsdp" "sip" "slp" "smb" "smtp" "snmp" "ssdp" "ssh" "tcp" "tls" "undp" "upnp" "swctl" "ttl"]
		if { $string eq "" } {
			return 0
		}
		if { [lsearch $allow $string] eq -1 } {
			return -1
		}
		return 0
	}
}
%};
