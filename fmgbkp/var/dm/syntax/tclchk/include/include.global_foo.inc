include_foo %{
namespace eval global {
	namespace export *
	proc bin2dec { bin } {
		if { $bin == 0 } {
			return 0
		} elseif { [string match -* $bin] } {
			set sign -
			set bin [string range $bin[set bin {}] 1 end]
		} else {
			set sign {}
		}
		return $sign[expr 0b$bin]
	}
	proc cli_check_admin_password_policy { policy passwd } {
		set status [cli_get_value $policy "" "" "status"]
		if { $status eq "disable" } {
			return 1
		}
		set minimum_length [cli_get_value $policy "" "" "minimum-length"]
		set min_lower_case_letter [cli_get_value $policy "" "" "min-lower-case-letter"]
		set min_upper_case_letter [cli_get_value $policy "" "" "min-upper-case-letter"]
		set min_non_alphanumeric [cli_get_value $policy "" "" "min-non-alphanumeric"]
		set min_number [cli_get_value $policy "" "" "min-number"]

		set retc [cli_check_password_policy_common $passwd $minimum_length $min_lower_case_letter $min_upper_case_letter $min_non_alphanumeric $min_number]
		return $retc
	}
	proc cli_check_admin_password_change { policy old_passwd new_passwd } {
		set status [cli_get_value $policy "" "" "status"]
		if { $status eq "disable" } {
			return 1
		}
		set change_4_characters [cli_get_value $policy "" "" "change-4-characters"]
		set reuse_password [cli_get_value $policy "" "" "reuse-password"]

		set retc [cli_check_password_change_common $old_passwd $new_passwd $change_4_characters $reuse_password]
		return $retc
	}
	proc addr_all_exist { dstaddr } {
		global CLI_CUR_VDOM_NODE
		foreach addr $dstaddr {
			set addr_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $addr ""]
			if { $addr_node  } {
				if {[cli_get_value $addr_node "" "" "type"] ne "ipmask"} {
					continue
				}
				if {[cli_get_value $addr_node "" "" "subnet"] ne "0.0.0.0 0.0.0.0"} {
					continue
				}
				return 1
			}
			set addrgrp_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp" $addr ""]
			if { $addrgrp_node == 0 } {
				continue
			}
			set addrgrp [cli_get_value $addrgrp_node "" "" "member" 1]
			if { [addr_all_exist $addrgrp] } {
				return 1
			}
		}
		return 0
	}
        proc is_addrgrp_contain_address_type { names types } {
                global CLI_CUR_VDOM_NODE
                foreach addr $names {
                        set addr_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $addr ""]
                        if { $addr_node  } {
				set type [cli_get_value $addr_node "" "" "type"]
				if { [lsearch $types $type] >= 0 } {
					return 1
                                }
                        } else {
                                set addrgrp_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp" $addr ""]
                                if { $addrgrp_node } {
                                        set addrgrp [cli_get_value $addrgrp_node "" "" "member"]
                                        if { [is_addrgrp_contain_address_type $addrgrp $types] } {
                                                return 1
                                        }
                                }
                        }
                }
                return 0
        }
        proc is_addrgrp_belongs_address_type { names types } {
                global CLI_CUR_VDOM_NODE
                foreach addr $names {
                        set addr_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $addr ""]
                        if { $addr_node  } {
				set type [cli_get_value $addr_node "" "" "type"]
				if { [lsearch $types $type] < 0 } {
					return 0
				}
                        } else {
                                set addrgrp_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp" $addr ""]
                                if { $addrgrp_node } {
                                        set addrgrp [cli_get_value $addrgrp_node "" "" "member"]
                                        if { [is_addrgrp_belongs_address_type $addrgrp $types] eq 0 } {
                                                return 0
                                        }
                                }
                        }
                }
                return 1
        }
	proc addr6_all_exist { dstaddr } {
                global CLI_CUR_VDOM_NODE
                foreach addr $dstaddr {
                        set addr_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall address6" $addr ""]
                        if { $addr_node  } {
                                if {[cli_get_value $addr_node "" "" "ip6"] ne "::/0"} {
                                        continue
                                }
                                return 1
                        }
                        set addrgrp_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp6" $addr ""]
                        if { $addrgrp_node == 0 } {
                                continue
                        }
                        set addrgrp [cli_get_value $addrgrp_node "" "" "member"]
                        if { [addr6_all_exist $addrgrp] } {
                                return 1
                        }
                }
                return 0
	}
	proc mime_field_format_check { proto profname tagmsg } {
		global CLI_CUR_VDOM_NODE
		set tagmsg [string trim $tagmsg \"]
		set tagmsg [string trim $tagmsg]
		set colon_pos [string first ":" $tagmsg]
		set sp_pos [string first " " $tagmsg]
		# FOS: append colon to the end if no colon or space in the string
		if { $sp_pos == -1 } {
			if { $colon_pos == -1 } {
				append tagmsg ":"
			}
			# FOS: add colon before the first space
		} elseif { $sp_pos < $colon_pos || $colon_pos == -1 } {
			set tagmsg [regsub " " $tagmsg ": "]
			# FOS: replace the remaining colons to spaces. Only one colon allowed in the tag-msg.
			if { $colon_pos != -1 } {
				set tagmsg [regsub -all -start $colon_pos ":" $tagmsg " "]
			}
		}
		set cmd "config spamfilter profile\nedit \"$profname\"\nconfig $proto\nset tag-msg \"$tagmsg\"\nend\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		return 1
	}
	proc deep_inspection_ports_valid { } {
		global CLI_CUR_NODE
		global CLI_CUR_PARENT_NODE
		global CLI_ACT
		global CLI_CUR_NODE_NAME
		global CLI_CUR_PARENT_NAME
		set ports [cli_get_value $CLI_CUR_NODE "" "" "ports"]
		if { $ports eq "" } {
			if { $CLI_ACT ne "add" } {
                                if { $CLI_CUR_NODE_NAME eq "ssh" } {
					if { [cli_has_feature "f_ssh_proxy"] } {
                                               set value [cli_get_value $CLI_CUR_NODE "" "" "inspect-all"]
                                               if { $value eq "disable" } {
                                                     cli_set_errmsg "Must set at least one port or enable ssh inspect-all."
                                                     return 0
                                               }
					}
				} elseif { [cli_get_value $CLI_CUR_NODE "" "" "status"] ne "disable" } {
					set node [cli_get_node $CLI_CUR_PARENT_NODE "ssl" "" ""]
					if { $node } {
						set value [cli_get_value $node "" "" "inspect-all"]
					} else {
						set value [cli_get_defvalue "$CLI_CUR_PARENT_NAME ssl" "inspect-all"]
					}
					if { $value eq "disable" } {
						if { $CLI_CUR_NODE_NAME eq "https" } {
							set defval 443
						} elseif { $CLI_CUR_NODE_NAME eq "ftps" } {
							set defval 990
						} elseif { $CLI_CUR_NODE_NAME eq "imaps" } {
							set defval 993
						} elseif { $CLI_CUR_NODE_NAME eq "pop3s" } {
							set defval 995
						} elseif { $CLI_CUR_NODE_NAME eq "smtps" } {
							set defval 465
						} elseif { $CLI_CUR_NODE_NAME eq "ssh" } {
							set defval 22
						}

						cli_set_errmsg "Must set at least one port (default port: $defval) or enable ssl inspect-all."
						return 0
					}
				}
			}
		} else {
			foreach port $ports {
				if { $port eq "0" } {
					cli_set_errmsg "The value should be in the range of 1-65535."
					return 0
				}
			}
		}
		return 1
	}
        proc profile_protocol_options_ports_valid { no_check_inspect_all } {
		global CLI_CUR_NODE
		global CLI_ACT
		if { [cli_ver_start 500 0] } {
			set p "ports"
		} elseif { [cli_ver_start 400 3] } {
			set p "port"
		} else {
			return 1
		}
                set ports [cli_get_value $CLI_CUR_NODE "" "" $p]
                if { $ports eq "" } {
			if { $CLI_ACT ne "add" } {
				if { $no_check_inspect_all } {
					cli_set_errmsg "Must set at least one port."
					return 0
				} elseif { [cli_get_value $CLI_CUR_NODE "" "" "inspect-all"] eq "disable" } {
					cli_set_errmsg "Must set at least one port or enable inspect-all."
					return 0
				}
			}
                } else {
                        foreach port $ports {
                                if { $port eq "0" } {
					cli_set_errmsg "The value should be in the range of 1-65535."
					return 0
                                }
                        }
                }
                return 1
        }
	proc mms_profile_notification_mmsc_port_valid { parent } {
		set prot [cli_get_value $parent "" "" "protocol"]
		set prot [string trim $prot \"]
		set msg_prot [cli_get_value $parent "" "" "msg-protocol"]
		set msg_prot [string trim $msg_prot \"]
		set dserver [cli_get_value $parent "" "" "detect-server"]
		set dserver [string trim $dserver \"]
		if { $prot eq "mm7" && $msg_prot eq "mm7" } {
			set msg_type [cli_get_value $parent "" "" "msg-type"]
			set msg_type [string trim $msg_type \"]
			if { ($msg_type eq "deliver-req") && ($dserver ne "disable") } {
				return 0
			}
		} elseif { ($prot eq $msg_prot) && ($dserver ne "disable") } {
			return 0
		}
		return 1
	}
        proc get_addr_intf { member vdom intfarray grplist } {
            upvar $intfarray intfs
            foreach m $member {
                set m [string trim $m \"]
                set addr [cli_get_node $vdom "firewall address" $m ""]
                set addrgrp [cli_get_node $vdom "firewall addrgrp" $m ""]
                if { $addr != 0 } {
                    set addr_intf [cli_get_value $addr "" "" "associated-interface"]
                    set addr_intf [string trim $addr_intf \"]
                    if {$addr_intf ne ""} {
                        set intfs($addr_intf) 1
                    } else {
                        set intfs("any") 1
                    }
                }
                if { $addrgrp != 0 } {
                    if { [lsearch $grplist $m] < 0 } {
                        ## avoid infinite loop
                        lappend grplist $m
                        set subgrp [cli_get_value $addrgrp "" "" "member" 1]
                        get_addr_intf $subgrp $vdom intfs $grplist
                    }
                }
            }
        }
        proc get_multicast_addr_intf { member vdom intfarray } {
            upvar $intfarray intfs
            foreach m $member {
                set m [string trim $m \"]
                set addr [cli_get_node $vdom "firewall multicast-address" $m ""]
                if { $addr != 0 } {
                    set addr_intf [cli_get_value $addr "" "" "associated-interface"]
                    set addr_intf [string trim $addr_intf \"]
                    if {$addr_intf ne ""} {
                        set intfs($addr_intf) 1
                    } else {
                        set intfs("any") 1
                    }
                }
            }
        }
	proc is_sdwan_zone { intfname } {
		global CLI_CUR_VDOM_NODE
		if { $intfname eq "virtual-wan-link" } {
			return 1
		} elseif { [cli_branchpt_start 600 1614] } {
			set sdwan [cli_get_node $CLI_CUR_VDOM_NODE "system sdwan" "" ""]
			set zones [cli_get_tbl_list $sdwan "zone"]
			foreach zone $zones {
				set name [cli_get_value $zone "" "" "name"]
				if { $intfname eq $name } {
					return 1
				}
			}
		}

		return 0
	}
	proc get_sdwan_intf { intfname } {
		global CLI_CUR_VDOM_NODE
		set retlist []

		if { [is_sdwan_zone $intfname] } {
			if { [cli_branchpt_start 600 1614] } {
				set sdwan [cli_get_node $CLI_CUR_VDOM_NODE "system sdwan" "" ""]
			} else {
				set sdwan [cli_get_node $CLI_CUR_VDOM_NODE "system virtual-wan-link" "" ""]
			}
			set members [cli_get_tbl_list $sdwan "members"]
			foreach m $members {
				set intf [cli_get_value $m "" "" "interface"]
				set intf [string trim $intf \"]
				set zonename [string trim [cli_get_value $m "" "" "zone"] \"]
				if { $zonename eq $intfname } {
					lappend retlist $intf
				}
			}
		}

		return $retlist
	}
        proc get_vip_intf { member vdom intfarray } {
            upvar $intfarray intfs
            foreach m $member {
                set m [string trim $m \"]
                set vip [cli_get_node $vdom "firewall vip" $m ""]
                set vipgrp [cli_get_node $vdom "firewall vipgrp" $m ""]
                if { $vip != 0 } {
                    set vip_intf [cli_get_value $vip "" "" "extintf"]
                    set vip_intf [string trim $vip_intf \"]
                    if {$vip_intf ne ""} {
                        set intfs($vip_intf) 1
                    } else {
                        set intfs("any") 1
                    }
                }
                if { $vipgrp != 0 } {
                    set vipgrp_intf [cli_get_value $vipgrp "" "" "interface"]
                    set vipgrp_intf [string trim $vipgrp_intf \"]
                    if {$vipgrp_intf ne ""} {
                        set intfs($vipgrp_intf) 1
                    } else {
                        set intfs("any") 1
                    }
                }
            }
        }
	proc is_vwl_member { intf } {
		global CLI_CUR_VDOM_NODE
		if { [cli_branchpt_start 600 1614] } {
			set vwl [cli_get_node $CLI_CUR_VDOM_NODE "system sdwan" "" ""]
		} else {
			set vwl [cli_get_node $CLI_CUR_VDOM_NODE "system virtual-wan-link" "" ""]
		}
		set intf [string trim $intf \"]

		if { $vwl } {
			set memblist [cli_get_tbl_list $vwl "members"]
			foreach memb $memblist {
				set memintf [cli_get_value $memb "" "" "interface"]
				set memintf [string trim $memintf \"]
				if { $intf eq $memintf } {
					return 1
				}
			}
		}
		return 0
	}
        proc intf_binding_contradiction { srcaddr dstaddr srcintf dstintf policyid id isMulticast } {
                global CLI_CUR_VDOM_NODE
		global CLI_GLOBAL_DEV

                array unset srcaddr_intf_array
                array unset srcvip_intf_array
                array unset grplist
                lappend grplist $srcaddr
                get_addr_intf $srcaddr $CLI_CUR_VDOM_NODE srcaddr_intf_array $grplist
                get_vip_intf $srcaddr $CLI_CUR_VDOM_NODE srcvip_intf_array
		if { $isMulticast == 0 } {
		set src "policyid: $policyid"
		} else {
		set src "multicast policyid: $policyid"
		}

		if {[array size srcvip_intf_array] > 0} {
			return "srcaddr($srcaddr) can not be vip/vipgrp ($src)"
		}
		array unset srcaddr_intf_array "any"
		array unset srcaddr_intf_array \"any\"
		set sz_srcaddr [array size srcaddr_intf_array]
		if {$sz_srcaddr > 1} {
			return "srcaddr($srcaddr) has different binding interfaces ($src)"
		} elseif {$sz_srcaddr == 1 } {
			foreach s $srcintf {
				set s1 [string trim $s \"]
				set s1 [regsub -all {\[} $s1 {\\[}]
				set s1 [regsub -all {\]} $s1 {\\]}]
				if { $s1 eq "any" } {
					return "srcaddr($srcaddr) binding interface must be (any) ($src)"
				}
				if {[llength [array get srcaddr_intf_array $s1]] == 0} {
					if { $CLI_GLOBAL_DEV } {
						return "srcaddr($srcaddr) binding interface not match srcintf($s) ($src)"
					}
					set zone [cli_get_value $CLI_CUR_VDOM_NODE "system zone" $s "interface"]
					set ret 0
					foreach intf $zone {
						set intf1 [string trim $intf \"]
						set intf1 [regsub -all {\[} $intf1 {\\[}]
						set intf1 [regsub -all {\]} $intf1 {\\]}]
						if {[llength [array get srcaddr_intf_array $intf1]] > 0} {
							set ret 1
							break
						}
					}
					if { $ret == 0 } {
						return "srcaddr($srcaddr) binding interface not match srcintf($s) ($src)"
					}
				}
			}
		}

                array unset dstaddr_intf_array
                array unset dstvip_intf_array
		if { $isMulticast == 0 } {
                array unset grplist
                lappend grplist $dstaddr
                get_addr_intf $dstaddr $CLI_CUR_VDOM_NODE dstaddr_intf_array $grplist
                get_vip_intf $dstaddr $CLI_CUR_VDOM_NODE dstvip_intf_array
		} else {
                get_multicast_addr_intf $dstaddr $CLI_CUR_VDOM_NODE dstaddr_intf_array
		set id 0
		}

                if { $id > 0 } {
                        set dst "policyid: $policyid, identity-based: $id"
                } else {
			if { $isMulticast == 0 } {
                        set dst "policyid: $policyid"
			} else {
			set dst "multicast policyid: $policyid"
			}
                }
		if {[array size dstaddr_intf_array] > 0 &&
		    [array size dstvip_intf_array] > 0} {
			return "dstaddr($dstaddr) can not multiple use addr/adrgrp and vip/vipgrp ($dst)"
		}
		array unset dstvip_intf_array "any"
		array unset dstvip_intf_array \"any\"
		array unset dstaddr_intf_array "any"
		array unset dstaddr_intf_array \"any\"
                set sz_dstaddr [array size dstaddr_intf_array]
                set sz_dstvip [array size dstvip_intf_array]
		if {$sz_dstvip > 0} {
			set ret 0
			foreach s $srcintf {
				set s [string trim $s \"]
				set s [regsub -all {\[} $s {\\[}]
				set s [regsub -all {\]} $s {\\]}]
				if { $s eq "any" } {
					return "dstaddr($dstaddr) binding interface must be (any) ($dst)"
				}
				if {[llength [array get dstvip_intf_array $s]] == 0} {
					if { $CLI_GLOBAL_DEV } {
						continue
					}
					set zone [cli_get_value $CLI_CUR_VDOM_NODE "system zone" $s "interface"]
					foreach intf $zone {
						set intf [string trim $intf \"]
						if {[llength [array get dstvip_intf_array $intf]] > 0} {
							set ret 1
							break
						}
					}

					if { $ret == 0 && $s eq "virtual-wan-link"} {
						set vwl 1
						foreach vipintf [array names dstvip_intf_array] {
							if { [is_vwl_member $vipintf] == 0 } {
								set vwl 0
								break;
							}
						}
						if { $vwl == 1 } {
							set ret 1
						}
					}
				} else {
					set ret 1
				}
				if {$ret == 1} {
					break
				}
			}
			if { $ret == 0 } {
				return "dstaddr($dstaddr) extintf(s)/interface(s) must bind to srcintf($srcintf) ($dst)"
			}
		} elseif {$sz_dstaddr > 0 } {
			if { $id > 0 } {
				set ret 0
				foreach s $dstintf {
					set s1 [string trim $s \"]
					set s1 [regsub -all {\[} $s1 {\\[}]
					set s1 [regsub -all {\]} $s1 {\\]}]
					if { $s1 eq "any" } {
						return "dstaddr($dstaddr) binding interface must be (any) ($dst)"
					}
					if {[llength [array get dstaddr_intf_array $s1]] == 0} {
						if { $CLI_GLOBAL_DEV } {
							continue
						}
						set zone [cli_get_value $CLI_CUR_VDOM_NODE "system zone" $s "interface"]
						foreach intf $zone {
							set intf1 [string trim $intf \"]
							set intf1 [regsub -all {\[} $intf1 {\\[}]
							set intf1 [regsub -all {\]} $intf1 {\\]}]
							if {[llength [array get dstaddr_intf_array $intf1]] > 0} {
								set ret 1
								break
							}
						}
					} else {
						set ret 1
					}
					if {$ret == 1} {
						break
					}
				}
				if { $ret == 0 } {
					return "dstaddr($dstaddr) associate-interface must bind to dstintf($dstintf) ($dst)"
				}
			} else {
				if { $sz_dstaddr > 1 } {
					return "dstaddr($dstaddr) has different binding interfaces ($dst)"
				} elseif { $sz_dstaddr == 1 } {
					foreach s $dstintf {
						set s1 [string trim $s \"]
						set s1 [regsub -all {\[} $s1 {\\[}]
						set s1 [regsub -all {\]} $s1 {\\]}]
						if { $s eq "any" } {
							return "dstaddr($dstaddr) binding interface must be (any) ($dst)"
						}
						if {[llength [array get dstaddr_intf_array $s1]] == 0} {
							if { $CLI_GLOBAL_DEV } {
							return "dstaddr($dstaddr) binding interface not match dstintf($s) ($dst)"
							}
							set zone [cli_get_value $CLI_CUR_VDOM_NODE "system zone" $s "interface"]
							set ret 0
							foreach intf $zone {
								set intf1 [string trim $intf \"]
								set intf1 [regsub -all {\[} $intf1 {\\[}]
								set intf1 [regsub -all {\]} $intf1 {\\]}]
								if {[llength [array get dstaddr_intf_array $intf1]] > 0} {
									set ret 1
									break
								}
							}
							if { $ret == 0 } {
						return "dstaddr($dstaddr) binding interface not match dstintf($s) ($dst)"
							}
						}
					}
				}
			}
		}
                return 0
        }

	proc ln_policy_intf_binding_contradiction { addr intf policyid isdst } {
		global CLI_CUR_VDOM_NODE

		if { $isdst == 0 } {
			set attr "srcaddr"
		} else {
			set attr "dstaddr"
		}

		array unset grplist
		lappend grplist $addr
		get_addr_intf $addr $CLI_CUR_VDOM_NODE addr_intf_array $grplist
		array unset addr_intf_array "any"
		array unset addr_intf_array \"any\"
		set sz_addr [array size addr_intf_array]
		if {$sz_addr > 1} {
			return "$attr($addr) has different binding interfaces (policyid: $policyid)"
		} elseif {$sz_addr == 1} {
			set intf [string trim $intf \"]
			if { $intf eq "any" } {
				return "$attr($addr) binding interface must be (any) (policyid: $policyid)"
			}
			if {[llength [array get addr_intf_array $intf]] == 0} {
				return "$attr($addr) binding interface not match intf($intf) (policyid: $policyid)"
			}
		}
		return 0
	}
        proc get_shadow_intf_name { head vdname tail } {
                set intfname $head
                append intfname $vdname
		append intfname $tail
                set maxsize [cli_get_objlimit 0 "system interface" "name"]
                if { $maxsize > 0 } {
                        set intfname [string range $intfname 0 [expr $maxsize - 1]]
                }
                return $intfname
        }
        proc get_mux_tunnel_dev_name { vdname } {
		set stname [cli_get_device_vdom_shortname_by_name $vdname]
		if { $stname != 0 && $stname ne "" } {
			return [get_shadow_intf_name "ssl." $stname ""]
		} else {
			return [get_shadow_intf_name "ssl." $vdname ""]
		}
        }
	proc is_sslvpn_intf { nam } { # TODO: not looking for relationships in table, loose, might need rework
		global CLI_CUR_VDOM_NAME
		global CLI_GLOBAL_DEV
		set name [string trim $nam \"]
		if { $CLI_GLOBAL_DEV } {
			set n [string range $name 0 2]
			# Mantis 634813: "ssl" instead of "ssl."" since sslvpn_tun_intf should be a sslvpn policy interface (via dynamic mapping)
			if { $n eq "ssl" } {
				return 1
			}
		} else {
			set muxname [get_mux_tunnel_dev_name $CLI_CUR_VDOM_NAME]
			if { $name eq $muxname } {
				return 1
			}
		}
		return 0
	}
	proc is_sslvpn_policy { policy } {
		set srcintf [cli_get_value $policy "" "" "srcintf"]
		return [is_sslvpn_intf $srcintf]
	}
	proc is_sslvpn_portal_has_tunnel { name ipv6 } {
		global CLI_CUR_VDOM_NODE
		set node [cli_get_node $CLI_CUR_VDOM_NODE "vpn ssl web portal" $name ""]
		if { $node } {
			if { $ipv6 } {
				if { [cli_get_value $node "" "" "ipv6-tunnel-mode"] eq "enable" } {
					return 1
				}
			} else {
				if { [cli_get_value $node "" "" "tunnel-mode"] eq "enable" } {
					return 1
				}
			}
			return 0
		}
		return 0
	}
	proc is_sslvpn_portal_has_split_tunneling { name ipv6 } {
		global CLI_CUR_VDOM_NODE

		if { [is_sslvpn_portal_has_tunnel $name $ipv6] } {
			set node [cli_get_node $CLI_CUR_VDOM_NODE "vpn ssl web portal" $name ""]
			if { $node } {
				if { $ipv6 } {
					if { [cli_get_value $node "" "" "ipv6-split-tunneling"] eq "enable" } {
						return 1
					}
				} else {
					if { [cli_get_value $node "" "" "split-tunneling"] eq "enable" } {
						return 1
					}
				}
				return 0
			}
		}
		return 0
	}
	proc sslvpn_policy_match_auth_usrgrp { users groups rus rgs } {
		if { $users ne "" && $rus ne "" } {
			foreach u $users {
				foreach ru $rus {
					if { $u eq $ru } {
						return 1
					}
				}
			}
		}
		if { $groups ne "" && $rgs ne "" } {
			foreach g $groups {
				foreach rg $rgs {
					if { $g eq $rg } {
						return 1
					}
				}
			}
		}
		return 0
	}
	proc is_sslvpn_policy_has_tunnel { users groups ipv6 } {
		global CLI_CUR_VDOM_NODE
		if { $users eq "" && $groups eq "" } {
			return 1
		}
                set s [cli_get_node $CLI_CUR_VDOM_NODE "vpn ssl settings" "" ""]
		set ars [cli_get_tbl_list $s "authentication-rule"]
		if { $ars == 0 || 0 == [llength $ars] } {
			set p [cli_get_value $s "" "" "default-portal"]
			if { [is_sslvpn_portal_has_tunnel $p $ipv6] } {
				return 1
			}
		} else {
			foreach a $ars {
				set rus [cli_get_value $a "" "" "users"]
				set rgs [cli_get_value $a "" "" "groups"]
				if { [sslvpn_policy_match_auth_usrgrp $users $groups $rus $rgs] } {
					set portal [cli_get_value $a "" "" "portal"]
					if { [is_sslvpn_portal_has_tunnel $portal $ipv6] } {
						return 1
					}
				}
			}
		}
		return 0
	}
	proc is_sslvpn_policy_has_split_tunneling { users groups ipv6 } {
	global CLI_CUR_VDOM_NODE
	if { $users eq "" && $groups eq "" } {
		return 0
	}
	set s [cli_get_node $CLI_CUR_VDOM_NODE "vpn ssl settings" "" ""]
	set ars [cli_get_tbl_list $s "authentication-rule"]
	foreach a $ars {
		set rus [cli_get_value $a "" "" "users"]
		set rgs [cli_get_value $a "" "" "groups"]
		if { [sslvpn_policy_match_auth_usrgrp $users $groups $rus $rgs] } {
			set portal [cli_get_value $a "" "" "portal"]
			if { [is_sslvpn_portal_has_split_tunneling $portal $ipv6] } {
				return 1
			}
		}
	}
		return 0
	}
	proc FMG_is_sslvpn_policy_has_tunnel { policy } {
		global CLI_GLOBAL_DEV
		if { $CLI_GLOBAL_DEV } {
			return 1
		}
		set pname [cli_get_node_name $policy]
		if { $pname eq "firewall policy" } {
			set ipv6 0
		} elseif { $pname eq "firewall policy6" } {
			set ipv6 1
		} else {
			cli_set_errmsg "should NOT be here!"
			return 0

		}
		set us [cli_get_value $policy "" "" "users"]
		set gs [cli_get_value $policy "" "" "groups"]
		return [is_sslvpn_policy_has_tunnel $us $gs $ipv6]
	}
	proc FMG_is_sslvpn_policy_has_split_tunneling { policy ipv6 } {
		set us [cli_get_value $policy "" "" "users"]
		set gs [cli_get_value $policy "" "" "groups"]
		return [is_sslvpn_policy_has_split_tunneling $us $gs $ipv6]
	}
        proc aps_policy_normal { policy } {
                set action [cli_get_value $policy "" "" "action"]
                if { $action eq "accept" || $action eq "deny" } {
                        return 1
                }
                return 0
        }
        proc aps_policy_auth_identity_based { policy } {
                set users [cli_get_value $policy "" "" "users"]
                set groups [cli_get_value $policy "" "" "groups"]
                set fgroups [cli_get_value $policy "" "" "fsso-groups"]
                if { [aps_policy_normal $policy] && (($users ne "") || ($groups ne "") || ($fgroups ne "")) } {
                        return 1
                }
                return 0
        }
        proc aps_policy_device_identity_based { policy } {
                set devices [cli_get_value $policy "" "" "devices"]
                if { [aps_policy_normal $policy] && ($devices ne "") } {
                        return 1
                }
                return 0
        }
        proc fw_policy_log_enable { policy } {
                global CLI_CUR_VDOM_NODE
                set cp_status [cli_get_value $CLI_CUR_VDOM_NODE "client-reputation profile" "" "status"]
                set pl_status [cli_get_value $policy "" "" "status"]
                if { $cp_status eq "enable" && $pl_status eq "enable" } {
                        return 1
                }
                set utm_status [cli_get_value $policy "" "" "utm-status"]
                set action [cli_get_value $policy "" "" "action"]
                if { $action eq "deny" && $utm_status eq "enable" } {
                        return 1
                }
                return 0
        }
        proc nCfg_cw_wlan_security_cp_or_wpa { vap } {
                global CLI_CUR_VDOM_NAME
                set vv [cli_get_value $vap "" "" "vdom"]
                set vv [string trim $vv \"]
		set vn $CLI_CUR_VDOM_NAME
                if { $vv eq $vn } {
                        set seq [cli_get_value $vap "" "" "security"]
                        if { $seq eq "captive-portal" || $seq eq "wpa-only-enterprise" ||
                             $seq eq "wpa2-only-enterprise" || $seq eq "wpa-enterprise" } {
                                return 1
                        }
                }
                return 0
        }
        proc nCfg_cw_wlan_exist_security_cp_or_wpa { name } {
                global CLI_GLOBAL_NODE
		set vap 0
		set name [string trim $name \"]
		if { [cli_ver_start 600 2] } {
			set intf [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
			if { $intf } {
				set vapvdom [cli_get_value $intf "" "" "vdom"]
				set vdnode [cli_get_vdom_node $vapvdom]
                		if { $vdnode } { set vap [cli_get_node $vdnode "wireless-controller vap" $name ""] }
			}
		} else {
                	set vap [cli_get_node $CLI_GLOBAL_NODE "wireless-controller vap" $name ""]
		}
                if { $vap && [nCfg_cw_wlan_security_cp_or_wpa $vap] } {
                        return 1
                }
                return 0
        }
	## ncfg_cw_wlan_sec_enterprise @ migbase/migapi/ncfg_capwap.c
	proc nCfg_cw_wlan_sec_enterprise { security } {
		return [expr {[string match "*enterprise*" $security] || $security eq "osen"}]
	}
	## ncfg_cw_wlan_sec_psk @ migbase/migapi/ncfg_capwap.c
	proc nCfg_cw_wlan_sec_psk { security } {
		if { $security eq "wpa-only-personal" ||
		     $security eq "wpa2-only-personal" ||
		     $security eq "wpa-personal" } {
			return 1
		}
		return 0
	}
	## ncfg_cw_wlan_sec_sae @ migbase/migapi/ncfg_capwap.c
	proc nCfg_cw_wlan_sec_sae { security } {
		if { $security eq "wpa3-sae" || $security eq "wpa3-sae-transition" } {
			return 1
		}
		return 0
	}
	## ncfg_cw_wlan_sec_wpa3_enterprise @ migbase/migapi/ncfg_capwap.c
	proc nCfg_cw_wlan_sec_wpa3_enterprise { security } {
		if { $security eq "wpa3-enterprise" ||
		     $security eq "wpa3-only-enterprise" ||
		     $security eq "wpa3-enterprise-transition" } {
			return 1
		}
		return 0
	}
	## ncfg_cw_wlan_sec_cpauth @ migbase/migapi/ncfg_capwap.c
	proc nCfg_cw_wlan_sec_cpauth { security } {
		if {[string match "*captive-portal" $security]} {
			return 1
		}
		return 0
	}
	## IS_AUTH_SKIP(wl) @ cmf/plugin/capwap/cw_wlan.c
	proc is_wlan_auth_skip { wlan } {
		set security [cli_get_value $wlan "" "" "security"]
		if { ![nCfg_cw_wlan_sec_enterprise $security] && $security ne "osen" } {
			return 1
		}
		return 0
	}
	## IS_LOCAL_AUTH_SKIP(wl) @ cmf/plugin/capwap/cw_wlan.c
	proc is_wlan_local_auth_skip { wlan } {
		set local_bridge [cli_get_value $wlan "" "" "local-bridging"]
		set security [cli_get_value $wlan "" "" "security"]
		if { $local_bridge ne "enable" || ($security ne "open" && $security ne "owe" && ![nCfg_cw_wlan_sec_sae $security] && ![nCfg_cw_wlan_sec_psk $security]) } {
			return 1
		}
		return 0
	}
	## IS_ENCRYPT_SKIP(wl) @ cmf/plugin/capwap/cw_wlan.c
	proc is_wlan_encrypt_skip { wlan } {
		set security [cli_get_value $wlan "" "" "security"]
		if { ![nCfg_cw_wlan_sec_psk $security] &&
		     ![nCfg_cw_wlan_sec_enterprise $security] &&
		     $security ne "wpa-personal+captive-portal" &&
		     $security ne "wpa-only-personal+captive-portal" &&
		     $security ne "wpa2-only-personal+captive-portal" &&
		     ![nCfg_cw_wlan_sec_sae $security] &&
		     $security ne "owe" } {
			return 1
		}
		return 0
	}
	## IS_PMF_SKIP(wl) @ cmf/plugin/capwap/cw_wlan.c
	proc is_wlan_pmf_skip { wlan } {
		set security [cli_get_value $wlan "" "" "security"]
		set encrypt [cli_get_value $wlan "" "" "encrypt"]
		if { [is_wlan_encrypt_skip $wlan] ||
		      $encrypt ne "AES" ||
		      ($security ne "wpa2-only-personal" &&
		       $security ne "wpa2-only-enterprise" &&
		       $security ne "wpa2-only-personal+captive-portal" &&
		       ![nCfg_cw_wlan_sec_wpa3_enterprise $security] &&
		       ![nCfg_cw_wlan_sec_sae $security] &&
		       $security ne "owe") } {
			return 1
		}
		return 0
	}
	## IS_MESH_BH_SKIP(wl) @ cmf/plugin/capwap/cw_wlan.c
	proc is_wlan_mesh_bh_skip { wlan } {
		set security [cli_get_value $wlan "" "" "security"]
		if { $security ne "open" && ![nCfg_cw_wlan_sec_psk $security] } {
			return 1
		}
		return 0
	}
	## IS_MESH_BH_ENABLED(wl) @ cmf/plugin/capwap/cw_wlan.c
	proc is_wlan_mesh_bh_enabled { wlan } {
		set mesh_bh [cli_get_value $wlan "" "" "mesh-backhaul"]
		if { ![is_wlan_mesh_bh_skip $wlan] && $mesh_bh eq "enable" } {
			return 1
		}
		return 0
	}
	## IS_LOCAL_ST_SKIP(wl) @ cmf/plugin/capwap/cw_wlan.c
	proc is_wlan_local_st_skip { wlan } {
		set auth [cli_get_value $wlan "" "" "auth"]
		set security [cli_get_value $wlan "" "" "security"]
		if { [nCfg_cw_wlan_sec_enterprise $security] && ![is_wlan_auth_skip $wlan] && $auth eq "usergroup" } {
			return 1
		}
		return 0
	}
	## IS_FAST_BSS_TRANS_SKIP(wl) @ cmf/plugin/capwap/cw_wlan.c
	proc is_wlan_fast_bss_trans_skip { wlan } {
		set local_st [cli_get_value $wlan "" "" "local-standalone"]
		if { [is_wlan_pmf_skip $wlan] ||
		     [is_wlan_mesh_bh_enabled $wlan] ||
		     ( ![is_wlan_local_st_skip $wlan] && $local_st eq "enable") } {
			return 1
		}
		return 0
	}
	proc nCfg_find_base_cw_wlan_intf_by_name { name } {
		global CLI_GLOBAL_NODE
		set dest 0
		set intf [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
		if { $intf } {
			set type [cli_get_value $intf "" "" "type"]
			set vdnode 0
			if { [cli_ver_start 600 2] } {
				set vapvdom [cli_get_value $intf "" "" "vdom"]
				set vdnode [cli_get_vdom_node $vapvdom]
			}
			if { $type eq "vap-switch" } {
                		if { $vdnode } {
					set dest [cli_get_node $vdnode "wireless-controller vap" $name ""]
				} else {
					set dest [cli_get_node $CLI_GLOBAL_NODE "wireless-controller vap" $name ""]
				}
			} elseif { $type eq "vlan" } {
				set name [cli_get_value $intf "" "" "interface"]
                		if { $vdnode } {
					set dest [cli_get_node $vdnode "wireless-controller vap" $name ""]
				} else {
					set dest [cli_get_node $CLI_GLOBAL_NODE "wireless-controller vap" $name ""]
				}
			}
		}
		return $dest
	}
	proc nCfg_cw_intf_wsso_capable { name } {
		global CLI_GLOBAL_NODE
		set vap [nCfg_find_base_cw_wlan_intf_by_name $name]
		if { $vap } {
			return [nCfg_cw_wlan_security_cp_or_wpa $vap]
		}
		if { $name eq "any" } {
			if { [cli_ver_start 600 2] } {
				set nodes  [cli_get_match_list $CLI_GLOBAL_NODE 1 "system interface" "type" 0 "vap-switch"]
				foreach intf $nodes {
					set vapvdom [cli_get_value $intf "" "" "vdom"]
					set name [cli_get_value $intf "" "" "name"]
                			set name [string trim $name \"]
					set vdnode [cli_get_vdom_node $vapvdom]
					set vap [cli_get_node $vdnode "wireless-controller vap" $name ""]
					if { $vap && [nCfg_cw_wlan_security_cp_or_wpa $vap] } {
						return 1
					}
				}
			} else {
				set vaps [cli_get_tbl_list $CLI_GLOBAL_NODE "wireless-controller vap"]
				foreach vap $vaps {
					if { [nCfg_cw_wlan_security_cp_or_wpa $vap] } {
						return 1
					}
				}
			}
			return 0
		}
		return 0
	}
	proc nCfg_cw_policy_wsso_capable { policy } {
		if { ![aps_policy_auth_identity_based $policy] } {
			return 0
		}
		set srcintfs [cli_get_value $policy "" "" "srcintf"]
		foreach intf $srcintfs {
			if { [nCfg_cw_intf_wsso_capable $intf] } {
				return 1
			}
		}
		return 0
	}
	proc is_enterprise_vap_intf { vap } {
		set sec [cli_get_value $vap "" "" "security"]
		set auth [cli_get_value $vap "" "" "auth"]
                if { $auth eq "radius" && ($sec eq "wpa-only-enterprise" ||
                     $sec eq "wpa2-only-enterprise" || $sec eq "wpa-enterprise") } {
                     return 1
                }
		return 0
	}
	proc is_srcintf_enterprise_vap { name } {
		global CLI_GLOBAL_NODE
		global CLI_CUR_VDOM_NODE
		if { $name eq "any" } {
			if { [cli_ver_start 600 2] } {
				set nodes  [cli_get_match_list $CLI_GLOBAL_NODE 1 "system interface" "type" 0 "vap-switch"]
				foreach intf $nodes {
					set vapvdom [cli_get_value $intf "" "" "vdom"]
					set name [cli_get_value $intf "" "" "name"]
                			set name [string trim $name \"]
					set vdnode [cli_get_vdom_node $vapvdom]
					set vap [cli_get_node $vdnode "wireless-controller vap" $name ""]
					if { $vap && [is_enterprise_vap_intf $vap] } {
						return 1
					}
				}
			} else {
				set vaps [cli_get_tbl_list $CLI_GLOBAL_NODE "wireless-controller vap"]
				foreach vap $vaps {
					if { [is_enterprise_vap_intf $vap] } {
						return 1
					}
				}
			}
			return 0
		}
		set zone [cli_get_node $CLI_CUR_VDOM_NODE "system zone" $name ""]
		if { $zone } {
		        set mlist [cli_get_value $zone "" "" "interface"]
		        foreach m $mlist {
				set mvap [nCfg_find_base_cw_wlan_intf_by_name $m]
	                	if { $mvap } {
        	                	return [is_enterprise_vap_intf $mvap]
                		}
	        	}
        		return 0
		}
		set vap [nCfg_find_base_cw_wlan_intf_by_name $name]
		if { $vap } {
			return [is_enterprise_vap_intf $vap]
		}
		return 0
	}
	proc is_policy_enterprise_vap { policy } {
		set srcintfs [cli_get_value $policy "" "" "srcintf"]
		foreach intf $srcintfs {
			if { [is_srcintf_enterprise_vap $intf] } {
				return 1
			}
		}
		return 0
	}
        proc options_exact_match { ss es } {
                foreach s $ss {
                        set s [string trim $s \"]
                        set match 0
                        foreach e $es {
                                set e [string trim $e \"]
                                if { $s eq $e } {
                                        set match 1
                                        break
                                }
                        }
                        if { !$match } {
                                return 0
                        }
                }
                foreach e $es {
                        set e [string trim $e \"]
                        set match 0
                        foreach s $ss {
                                set s [string trim $s \"]
                                if { $e eq $s } {
                                        set match 1
                                        break
                                }
                        }
                        if { !$match } {
                                return 0
                        }
                }
                return 1
        }
        proc ftgd_wf_cat_exact_match { ss es } {
		return [options_exact_match $ss $es]
	}
	proc nCfg_is_interface_used_by_switchctl { name } {
		# since FSW is centrally managed, we used a relaxed check to only see if the interface of the vlan have fortilink enabled
		global CLI_GLOBAL_NODE
		set intfnode1 [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
		if { $intfnode1 eq 0 } {
			return 0
		}
		set intf1 [cli_get_value $intfnode1 "" "" "interface"]
		if { $intf1 eq 0 || $intf1 eq "" } {
			return 0
		}
		set intfnode2 [cli_get_node $CLI_GLOBAL_NODE "system interface" $intf1 ""]
		if { $intfnode2 eq 0 } {
			return 0
		}
		set fortilink [cli_get_value $intfnode2 "" "" "fortilink"]
		if { $fortilink ne "enable" } {
			return 0
		}
		return 1
	}
	proc nCfg_get_proxy_filesize_limit_bounds { } {
		global CLI_GLOBAL_DEV
		if { $CLI_GLOBAL_DEV } { return 0 }
		set tr [cli_get_devinfo "totalram"]
		set th [cli_get_devinfo "totalhigh"]
		set mu [cli_get_devinfo "mem_unit"]
		return [expr (((($tr/10) + ($th/10 * 3))*$mu) >> 20)]
	}
	proc fw_dstaddr_visible { policy } {
		if { [cli_ver_start 500 6] } {
			if { [cli_is_match $policy 0 "" "internet-service" 0 "enable"] } {
				return 0
			}
			return 1
		} elseif { [cli_ver_start 500 2] } {
			return 1
		} elseif { [cli_ver_start 500 0] } {
			set intf [cli_get_value $policy "" "" "srcintf"]
			set intf [string trim $intf \"]
			if { [cli_is_match $policy 0 "" "action" 0 "accept"] &&
			     [cli_is_match $policy 0 "" "identity-based" 0 "enable"] &&
			     $intf ne "web-proxy" && $intf ne "ftp-proxy"} {
				return 0
			}
			return 1
		}
		return 1
	}
	proc fw_dstaddr6_visible { policy } {
		if { ![cli_ver_start 600 4] } {
			return [fw_dstaddr_visible $policy]
		}
		if { ![cli_branchpt_start 700 1180] } {
        		if { [cli_is_match $policy 0 "" "internet-service" 0 "enable"] ||
                		[cli_is_match $policy 0 "" "internet-service-src" 0 "enable"] } {
                		return 0
        		}
		}
		if { [cli_branchpt_start 700 1228] } {
        		if { [cli_is_match $policy 0 "" "internet-service6" 0 "enable"] } {
                		return 0
        		}
		}
		return 1
	}
	proc fw_ident_dstaddr_visible { policy } {
		if { [cli_ver_start 500 2] } {
			return 0
		} elseif { [cli_ver_start 500 0] } {
			set intf [cli_get_value $policy "" "" "srcintf"]
			set intf [string trim $intf \"]
			if { $intf eq "web-proxy" || $intf eq "ftp-proxy" || $intf eq "wanopt" } {
				return 0
			}
			return 1
		}
		return 0
	}
	proc fw_ident_users_visible { policy } {
		if { [cli_ver_start 500 2] } {
			return 0
		} elseif { [cli_ver_start 500 0] } {
			set intf [string trim [cli_get_value $policy "" "" "srcintf"] \"]
			set ident_from [string trim [cli_get_value $policy "" "" "identity-from"] \"]
			if { ($ident_from ne "auth") || ($intf eq "web-proxy" && [cli_get_value $policy "" "" "active-auth-method"] ne "basic") } {
				return 0
			}
			return 1
		}
		return 0
	}
	proc fw_ident_groups_visible { policy } {
		if { [cli_ver_start 500 2] } {
			return 0
		} elseif { [cli_ver_start 500 0] } {
			set action [string trim [cli_get_value $policy "" "" "action"] \"]
			set ident_from [string trim [cli_get_value $policy "" "" "identity-from"] \"]
			if { ($ident_from ne "auth") || ($action ne "accept" && $action ne "ssl-vpn") } {
				return 0
			}
			return 1
		}
		return 0
	}
	proc fw_active_auth_method_visible { policy opt } {
		set intf [string trim [cli_get_value $policy "" "" "srcintf"] \"]
		set ident [string trim [cli_get_value $policy "" "" "identity-based"] \"]
		set tfa [string trim [cli_get_value $policy "" "" "require-tfa"] \"]
		set action [string trim [cli_get_value $policy "" "" "action"] \"]
		set ip_auth [string trim [cli_get_value $policy "" "" "ip-based"] \"]
		if { $opt eq "ntlm" } {
			if { ($action ne "accept") || ($ident ne "enable") || ($intf eq "ftp-proxy") || ($intf ne "web-proxy") || ($tfa eq "enable") } {
				return 0
			}
		} elseif { $opt eq "form" } {
			if { ($action ne "accept") || ($ident ne "enable") || ($intf eq "ftp-proxy") || ($intf ne "web-proxy") || ($ip_auth eq "disable") } {
				return 0
			}
		} elseif { $opt eq "basic" } {
			if { ($action ne "accept") || ($ident ne "enable") ||
					($intf ne "web-proxy" && $intf ne "ftp-proxy") ||
					($intf eq "web-proxy" && $tfa eq "enable") } {
				return 0
			}
		}
		return 1
	}
	proc fw_sso_auth_method_visible { policy } {
		set intf [string trim [cli_get_value $policy "" "" "srcintf"] \"]
		set ident [string trim [cli_get_value $policy "" "" "identity-based"] \"]
		set tfa [string trim [cli_get_value $policy "" "" "require-tfa"] \"]
		set action [string trim [cli_get_value $policy "" "" "action"] \"]
		set ip_auth [string trim [cli_get_value $policy "" "" "ip-based"] \"]
		if { ($intf ne "web-proxy" && $intf ne "ftp-proxy") || ($action ne "accept") || ($ident ne "enable") || ($ip_auth eq "disable") || ($tfa eq "enable") } {
			return 0
		}
		return 1
	}
	proc fw_service_visible { policy } {
		if { [cli_ver_start 500 6] } {
			if { [cli_is_match $policy 0 "" "internet-service" 0 "enable"] } {
				return 0
			}
			return 1
		} elseif { [cli_ver_start 500 2] } {
			return 1
		} elseif { [cli_ver_start 500 0] } {
			set intf [string trim [cli_get_value $policy "" "" "srcintf"] \"]
			if { $intf eq "web-proxy" } {
				return 1
			} elseif { $intf eq "ftp-proxy" } {
				return 0
			}
			expr [cli_is_match $policy 0 "" "action" 1 "ssl-vpn"] && [cli_is_match $policy 0 "" "identity-based" 1 "enable"]
		} elseif { [cli_ver_start 400 3] } {
			expr [cli_is_match $policy 0 "" "action" 1 "ssl-vpn"] && [cli_is_match $policy 0 "" "identity-based" 1 "enable"] && [cli_is_match $policy 0 "" "srcintf" 1 "\"ftp-proxy\""]
		} elseif { [cli_ver_start 400 2] } {
			expr [cli_is_match $policy 0 "" "action" 1 "ssl-vpn"] && [cli_is_match $policy 0 "" "identity-based" 1 "enable"] && [cli_is_match $policy 0 "" "srcintf" 1 "\"web-proxy\""]
		}
	}
	proc fw_check_service { policy vdom } {
		set svc_list [cli_get_value $policy "" "" "service"]
		if { [fw_service_visible $policy] == 1 && [string length $svc_list] == 0 } {
			cli_set_errmsg "service must be set."
			return 0
		}
		if { [cli_ver_start 500 0] } {
			if { [llength $svc_list] > 1 } {
				foreach svc $svc_list {
					set cust_node [cli_get_node $vdom "firewall service custom" $svc ""]
					if { $cust_node != 0 } {
						set prot [cli_get_value $cust_node "" "" "protocol"]
						set num [cli_get_value $cust_node "" "" "protocol-number"]
						if { $prot eq "IP" && $num == 0 } {
							cli_set_errmsg "$svc (protocol:IP, protocol-number:0) can not be combined with other services."
							return 0
						}
					}
				}
			}
		}
		return 1
	}
	proc fw_ip_based_visible { policy } {
		if { [cli_ver_start 500 0] } {
			set intf [string trim [cli_get_value $policy "" "" "srcintf"] \"]
			set ident [string trim [cli_get_value $policy "" "" "identity-based"] \"]
			set action [string trim [cli_get_value $policy "" "" "action"] \"]
			if { ($intf eq "web-proxy" || $intf eq "ftp-proxy") && ($action eq "accept") && ($ident eq "enable") } {
				return 1
			}
		} elseif { [cli_ver_start 400 2] } {
			set intf [string trim [cli_get_value $policy "" "" "srcintf"] \"]
			if { $intf eq "ftp-proxy" || $intf eq "web-proxy" } {
				return 1
			}
		}
		return 0
	}
	proc fw_check_ip_based { policy } {
		if { [fw_ip_based_visible $policy] == 1 && [cli_ver_start 500 0] } {
			set active_auth_method [string trim [cli_get_value $policy "" "" "active-auth-method"] \"]
			set sso_auth_method [string trim [cli_get_value $policy "" "" "sso-auth-method"] \"]
			set ip_based [string trim [cli_get_value $policy "" "" "ip-based"] \"]
			if { $ip_based eq "disable" } {
				if { $active_auth_method eq "form" } {
					cli_set_errmsg "Cannot disable IP-based authentication when active-auth-method is FORM"
					return 0
				}
				if { $active_auth_method eq "" && $sso_auth_method ne "" } {
					cli_set_errmsg "Cannot disable IP-based authentication when sso-auth-method is set"
					return 0
				}
			}
		}
		return 1
	}
	proc fw_member_flag { flags key op} {
		array set const {
			HAS_LDAP  1
			HAS_RADIUS  2
			HAS_TAC_PLUS  4
			HAS_FSAE  8
			HAS_PEER	16
			HAS_LOCAL_RAD	32
			HAS_LOCAL_TAC_PLUS	64
			HAS_LOCAL_LDAP	128
			HAS_LOCAL	256
		}
		if { $op eq "" } {
			return $const($key)
		} elseif { $op eq "==" } {
			return [expr {$flags == $const($key)}]
		} elseif { $op eq "&" } {
			return [expr {$flags & $const($key)}]
		} elseif { $op eq "|" } {
			return [expr {$flags | $const($key)}]
		}
		return 0
	}
	proc fw_set_memb_flag { member vdom usr_cat flags key } {
		upvar 1 $flags f
		if { [fw_member_flag $f $key "&"] == 0 } {
			set node [cli_get_node $vdom $usr_cat $member ""]
			if { $node } {
				set f [fw_member_flag $f $key "|"]
				return $f
			}
		}
		return 0
	}
	proc fw_web_proxy_group_filter { key auth_method grp_name grp_type flags } {
		if { $auth_method eq "fsso" } {
			if { [fw_member_flag $flags HAS_FSAE "=="] == 0 && $grp_name ne "FSSO_Guest_Users" } {
				cli_set_errmsg "$key is \"$auth_method\" while user group $grp_name is not FSSO_Guest_Users and its type-of-members is not HAS_FSAE"
				return 0
			}
		} elseif { $auth_method eq "ntlm" } {
			if { [fw_member_flag $flags HAS_FSAE "=="] == 0 } {
				cli_set_errmsg "$key is \"$auth_method\" while user group $grp_name 's type-of-members is not HAS_FSAE"
				return 0
			}
		} elseif { $auth_method eq "digest" } {
			if { [fw_member_flag $flags HAS_LOCAL "=="] == 0 } {
				cli_set_errmsg "$key is \"$auth_method\" while user group $grp_name 's type-of-members is not HAS_LOCAL"
				return 0
			}
		} elseif { $auth_method eq "form" || $auth_method eq "basic" } {
			if { [fw_member_flag $flags HAS_FSAE "&"] == 1 || $grp_name eq "FSSO_Guest_Users" || $grp_type eq "rsso" } {
				cli_set_errmsg "$key is \"$auth_method\" while user group $grp_name 's type-of-members is HAS_FSAE or name is FSSO_Guest_Users or group-type is rsso"
				return 0
			}
		} elseif { $auth_method eq "rsso" } {
			if { $grp_type ne "rsso" } {
				cli_set_errmsg "$key is \"$auth_method\" while user group $grp_name 's group-type is rsso"
				return 0
			}
		} else {
			cli_set_errmsg "$key is \"$auth_method\", group $grp_name is not allowed"
			return 0
		}
		return 1
	}
	proc fw_ftp_proxy_group_filter { key auth_method grp_name grp_type flags } {
		if { $auth_method eq "fsso" } {
			if { [fw_member_flag $flags HAS_FSAE "=="] == 0 && $grp_name ne "FSSO_Guest_Users" } {
				cli_set_errmsg "$key is \"$auth_method\" while user group $grp_name is not FSSO_Guest_Users and its type-of-members is not HAS_FSAE"
				return 0
			}
		} elseif { $auth_method eq "basic" } {
			if { [fw_member_flag $flags HAS_FSAE "&"] == 1 || $grp_name eq "FSSO_Guest_Users" || $grp_type eq "rsso" } {
				cli_set_errmsg "$key is \"$auth_method\" while user group $grp_name 's type-of-members is HAS_FSAE or name is FSSO_Guest_Users or group-type is rsso"
				return 0
			}
		} elseif { $auth_method eq "rsso" } {
			if { $grp_type ne "rsso" } {
				cli_set_errmsg "$key is \"$auth_method\" while user group $grp_name 's group-type is rsso"
				return 0
			}
		} else {
			cli_set_errmsg "$key is \"$auth_method\", group $grp_name is not allowed"
			return 0
		}
		return 1
	}
	proc fw_ident_check_usrs_grps { ident_pol groups policy } {
		set ident_from [string trim [cli_get_value $policy "" "" "identity-from"] \"]
		set action [string trim [cli_get_value $policy "" "" "action"] \"]
		set grps_len 0
		set usrs_len 0
		if { [fw_ident_users_visible $policy] } {
			set users [cli_get_value $ident_pol "" "" "users"]
			set usrs_len [string length $users]
		}
		if { [fw_ident_groups_visible $policy] } {
			set grps_len [string length $groups]
		}
		if { (([cli_has_feature "f_sslvpn"] && $action eq "ssl-vpn") || ($action eq "accept")) &&
			($ident_from ne "device") && ($grps_len == 0) && ($usrs_len == 0) } {
				set id [cli_get_value $ident_pol "" "" ""]
				cli_set_errmsg "Must set groups or users (identity-based-policy $id)"
		}
	}
	proc fw_check_usrgrp { group policy vdom } {
		if { $group == 0 } {
			cli_set_errmsg "user group $group does not exist"
			return 0
		}
		set action [cli_get_value $policy "" "" "action"]
		set grp_name [string trim [cli_get_value $group "" "" "name"] \"]
		set grp_type [cli_get_value $group "" "" "group-type"]
		if { $action eq "ssl-vpn" } {
			if { $grp_type ne "firewall" } {
				cli_set_errmsg "user group $group 's group-type must be firewall when policy action is ssl-vpn"
				return 0
			}
		} else {
			set intf [string trim [cli_get_value $policy "" "" "srcintf"] \"]
			if { $intf eq "web-proxy" || $intf eq "ftp-proxy" } {
				set flags 0
				set member_list [cli_get_value $group "" "" "member"]
				foreach m $member_list {
					if { [fw_set_memb_flag $m $vdom "user ldap" flags HAS_LDAP] == 0 &&
							[fw_set_memb_flag $m $vdom "user radius" flags HAS_RADIUS] == 0 &&
							[fw_set_memb_flag $m $vdom "user tacacs+" flags HAS_TAC_PLUS] == 0 &&
							[fw_set_memb_flag $m $vdom "user adgrp" flags HAS_FSAE] == 0 &&
							[fw_set_memb_flag $m $vdom "user peer" flags HAS_PEER] == 0 } {
						set auth_user [cli_get_node $vdom "user local" $m ""]
						if { $auth_user } {
							set type [cli_get_value $auth_user "" "" "type"]
 							if { $type eq "radius" } {
 								set flags [fw_member_flag $flags HAS_LOCAL_RAD "|"]
  							} elseif { $type eq "tacacs+" } {
  								set flags [fw_member_flag $flags HAS_LOCAL_TAC_PLUS "|"]
   							} elseif { $type eq "ldap" } {
   								set flags [fw_member_flag $flags HAS_LOCAL_LDAP "|"]
 							} else {
 								set flags [fw_member_flag $flags HAS_LOCAL "|"]
 							}
 						}
					}
				}
				set active_auth_method [string trim [cli_get_value $policy "" "" "active-auth-method"] \"]
				set sso_auth_method [string trim [cli_get_value $policy "" "" "sso-auth-method"] \"]
				if { ($intf eq "web-proxy"  &&
							[fw_web_proxy_group_filter "active-auth-method" $active_auth_method $grp_name $grp_type $flags] == 0 &&
							[fw_web_proxy_group_filter "sso-auth-method" $sso_auth_method $grp_name $grp_type $flags] == 0) ||
							($intf eq "ftp-proxy" &&
							[fw_ftp_proxy_group_filter "active-auth-method" $active_auth_method $grp_name $grp_type $flags] == 0 &&
							[fw_ftp_proxy_group_filter "sso-auth-method" $sso_auth_method $grp_name $grp_type $flags] == 0) } {
						cli_set_errmsg "Group $grp_name is not allowed by the combination of active-auth-method and sso-auth-method."
						return 0
				}
			}
		}
		return 1
	}
	proc user_group_ipsec_used { group_name } {
		global CLI_CUR_VDOM_NODE
		set ipsec_phase1 [cli_get_tbl_list $CLI_CUR_VDOM_NODE "vpn ipsec phase1"]
		foreach ipsec $ipsec_phase1 {
			set usrgrp [cli_get_value $ipsec "" "" "usrgrp"]
			if { $group_name eq $usrgrp } {
				return 1
			}
		}
		return 0
	}
	proc user_group_check_type { type_node group_node } {
		set gtype [cli_get_value $type_node "" "" ""]
		set old_gtype [cli_get_org_value $type_node "" "" ""]
		if { $gtype ne $old_gtype } {
			set gname [cli_get_value $group_node "" "" "name"]
			if {[cli_is_referenced $group_node]} {
				cli_set_errmsg "The type cannot be changed because the user group $gname is used by other settings."
				return 0
			}
		}
		return 1
	}
	proc user_group_match_check_member { match_node group_node } {
		global CLI_CUR_VDOM_NODE
		set svrname [cli_get_value $match_node "" "" "server-name"]
		set members [cli_get_value $group_node "" "" "member" 1]
		foreach member $members {
			set name ""
			set auth_user [cli_get_node $CLI_CUR_VDOM_NODE "user local" $member ""]
			if { $auth_user != 0 } {
				set auth_type [cli_get_value $auth_user "" "" "type"]
				if { $auth_type eq "radius" } {
					set name [cli_get_value $auth_user "" "" "radius-server"]
				} elseif { $auth_type eq "ldap" } {
					set name [cli_get_value $auth_user "" "" "ldap-server"]
				} elseif { $auth_type eq "tacacs+" } {
					set name [cli_get_value $auth_user "" "" "tacacs+-server"]
				}
			} else {
				set name $member
			}
			if { $name ne "" && ($name eq $svrname || $name eq [lindex $svrname 0]) } {
				return 1
			}
		}
		set usr_radius [cli_get_tbl_list $CLI_CUR_VDOM_NODE "user radius"]
		foreach radius_svr $usr_radius {
			if { [cli_get_value $radius_svr "" "" "all-usergroup"] eq "enable" } {
				set name [cli_get_value $radius_svr "" "" "name"]
				if { $name eq $svrname || $name eq [lindex $svrname 0] } {
					return 1
				}
			}
		}
		cli_set_errmsg  "user group match is not a member. svrname:$svrname members:$members name:$name member:$member"
		return 0
	}

        proc is_explicit_webproxy { intf } {
                if { [cli_has_feature "f_webproxy"] } {
                        if { $intf eq "\"web-proxy\"" || $intf eq "web-proxy" } {
                                return 1
                        }
                }
                return 0
        }
        proc is_explicit_ftpproxy { intf } {
                if { [cli_has_feature "f_webproxy"] } {
                        if { $intf eq "\"ftp-proxy\"" || $intf eq "ftp-proxy" } {
                                return 1
                        }
                }
                return 0
        }
        proc is_wanopt_tunnel { intf } {
                if { [cli_has_feature "f_wanopt"] } {
                        if { $intf eq "\"wanopt\"" || $intf eq "wanopt" } {
                                return 1
                        }
                }
                return 0
        }
        proc is_wad_intf { intf } {
                if { [is_explicit_webproxy $intf] || [is_explicit_ftpproxy $intf] || [is_wanopt_tunnel $intf] } {
                        return 1
                }
                return 0
        }
        proc is_multiple { msg } {
                set count 0
                foreach m $msg {
                        incr count
                        if { $count > 1 } {
                                return 1
                        }
                }
                return 0
        }
        proc is_multiple_intf { intfs } {
		return [is_multiple $intfs]
        }
        proc is_intf_exist { intfs tgt } {
                foreach intf $intfs {
			set intf [string trim $intf \"]
                        if { $intf eq $tgt } {
                                return 1
                        }
                }
                return 0
        }
        proc is_ssl_tunnel_intf { intfs } {
		global CLI_CUR_VDOM_NAME
		global CLI_GLOBAL_DEV
		if { $CLI_GLOBAL_DEV } {
			foreach intf $intfs {
				set intf [string trim $intf \"]
				set n [string range $intf 0 3]
				if { $n eq "ssl." } {
					return 1
				}
			}
		} else {
			if { [is_intf_exist $intfs [get_mux_tunnel_dev_name $CLI_CUR_VDOM_NAME]] } {
				return 1
			}
		}
		return 0
	}
	proc policy_action_sslvpn_visible { policy } {
		global CLI_GLOBAL_DEV
		global CLI_CUR_VDOM_NODE
		set srcintf [cli_get_value $policy "" "" "srcintf"]
		set dstintf [cli_get_value $policy "" "" "dstintf"]
		set opmode [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"]
		set e 0
		if { ![cli_has_feature "f_sslvpn"] } {
			set e "model not support sslvpn feature"
		} elseif { (!$CLI_GLOBAL_DEV && ($opmode eq "transparent")) } {
			set e "opmode is transparent"
		} elseif { [is_multiple_intf $srcintf] } {
			set e "srcintf has multiple interface"
		} elseif { [is_multiple_intf $dstintf] } {
			set e "dstintf has multiple interface"
		} elseif { [is_ssl_tunnel_intf $srcintf] } {
			set e "srcintf is ssl tunnel interface"
		} elseif { [is_wad_intf $srcintf] } {
			set e "srcintf is wanopt interface"
		}
		return $e
	}
        proc policy_nat_visible { policy } {
		global CLI_CUR_VDOM_NODE
		if { [cli_ver_start 600 0] } {
			if { [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "central-nat" 0 "enable"] } {
				return 0
			}
			if { [ngfw_mode_policy] } {
				return 0
			}
			if { [cli_is_match $policy 0 "" "learning-mode" 0 "enable"] } {
				return 1
			}
		}
		set action [cli_get_value $policy "" "" "action"]
		if { $action eq "accept" } {
			return 1
		} elseif { $action eq "deny"} {
			if { [cli_has_feature "f_sslvpn"] } {
				if { [is_sslvpn_policy $policy] } {
					if { [FMG_is_sslvpn_policy_has_tunnel $policy] } {
						return 1
					} else {
						return 0
					}
				}
			}
		}
		return 0
	}
	proc policy_ippool_visible { policy } {
		global CLI_GLOBAL_DEV
		global CLI_CUR_VDOM_NODE
		set action [cli_get_value $policy "" "" "action"]
		if { $action eq "accept" } {
			if { [cli_branchpt_start 700 133] } {
				if { !$CLI_GLOBAL_DEV } {
					set sys_settings [cli_get_node $CLI_CUR_VDOM_NODE "system settings" "" ""]
					set central_nat [cli_get_value $sys_settings "" "" "central-nat"]
					if { $sys_settings != 0 && $central_nat eq "enable" } {
						return 0
					}
				}
				if { [cli_is_match $policy 0 "" "nat" 0 "enable"] ||
				     [cli_is_match $policy 0 "" "nat46" 0 "enable"] ||
				     [cli_is_match $policy 0 "" "nat64" 0 "enable"] } {
					return 1
				}
			} else {
				if { [cli_is_match $policy 0 "" "nat" 0 "enable"] } {
					return 1
				}
			}
		} elseif { $action eq "deny"} {
			if { [cli_has_feature "f_sslvpn"] } {
				if { [is_sslvpn_policy $policy] } {
					if { [FMG_is_sslvpn_policy_has_tunnel $policy] } {
						if { [cli_is_match $policy 0 "" "nat" 0 "enable"] } {
							return 1
						}
					} else {
						return 0
					}
				}
			}
		}
		return 0
	}

	proc nCfg_is_address6_vip64 { name } {
		global CLI_GLOBAL_NODE
		global CLI_GLOBAL_DEV
		global CLI_CUR_VDOM_NODE
		set vip6 [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip6" $name ""]
		if { $vip6 } {
			return 1
		}

		set vipgrp6 [cli_get_node $CLI_CUR_VDOM_NODE "firewall vipgrp6" $name ""]
		if { $vipgrp6 } {
			return 1
		}
		return 0
	}
	proc nCfg_is_address_vip46 { name } {
		global CLI_GLOBAL_NODE
		global CLI_CUR_VDOM_NODE
		set vip [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $name ""]
		if { $vip } {
			return 1
		}

		set vipgrp [cli_get_node $CLI_CUR_VDOM_NODE "firewall vipgrp" $name ""]
		if { $vipgrp } {
			return 1
		}
		return 0
	}
	proc nCfg_is_addr_used_except_explicit_policy { node } {
		if { ![cli_is_referenced $node] } { return 0 }
		if { [cli_is_used $node "firewall explicit-proxy-policy" "srcaddr"] ||
		     [cli_is_used $node "firewall policy" "srcaddr"] ||
		     [cli_is_used $node "firewall policy" "dstaddr"] ||
		     [cli_is_used $node "firewall consolidated policy" "srcaddr4"] ||
		     [cli_is_used $node "firewall consolidated policy" "dstaddr4"] ||
		     [cli_is_used $node "endpoint-control profile" "src-addr"] ||
		     [cli_is_used $node "endpoint-control profile" "on-net-addr"] ||
		     [cli_is_used $node "user security-exempt-list rule" "srcaddr"] ||
		     [cli_is_used $node "firewall ttl-policy" "srcaddr"] ||
		     [cli_is_used $node "firewall DoS-policy" "srcaddr"] ||
		     [cli_is_used $node "firewall DoS-policy" "dstaddr"] ||
		     [cli_is_used $node "firewall DoS-policy6" "srcaddr"] ||
		     [cli_is_used $node "firewall DoS-policy6" "dstaddr"] ||
		     [cli_is_used $node "firewall interface-policy" "srcaddr"] ||
		     [cli_is_used $node "firewall interface-policy" "dstaddr"] ||
		     [cli_is_used $node "firewall local-in-policy" "srcaddr"] ||
		     [cli_is_used $node "firewall local-in-policy" "dstaddr"] ||
		     [cli_is_used $node "firewall multicast-policy" "srcaddr"] ||
		     [cli_is_used $node "firewall gtp" "handover-group"] ||
		     [cli_is_used $node "firewall gtp" "authorized-sgsns"] ||
		     [cli_is_used $node "firewall gtp" "invalid-sgsns-to-log"] ||
		     [cli_is_used $node "firewall gtp" "authorized-ggsns"] ||
		     [cli_is_used $node "firewall gtp ie-remove-policy" "sgsn-addr"] ||
		     [cli_is_used $node "firewall gtp ip-policy" "srcaddr"] ||
		     [cli_is_used $node "firewall gtp ip-policy" "dstaddr"] ||
		     [cli_is_used $node "firewall policy64" "dstaddr"] ||
		     [cli_is_used $node "firewall central-nat" "orig-addr"] ||
		     [cli_is_used $node "firewall central-snat-map" "orig-addr"] ||
		     [cli_is_used $node "firewall central-snat-map" "dst-addr"] ||
		     [cli_is_used $node "firewall local-in-policy" "srcaddr"] ||
		     [cli_is_used $node "firewall local-in-policy" "dstaddr"] ||
		     [cli_is_used $node "vpn ipsec phase2" "src-name"] ||
		     [cli_is_used $node "vpn ipsec phase2" "dst-name"] ||
		     [cli_is_used $node "vpn ipsec phase2-interface" "src-name"] ||
		     [cli_is_used $node "vpn ipsec phase2-interface" "dst-name"] ||
		     [cli_is_used $node "vpn ssl web portal" "split-tunneling-routing-address"] } {
			  return 1
		}
		return 0
	}
	proc nCfg_is_interface_used_by_vwl { ifname } {
		global CLI_GLOBAL_NODE
		set ifnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $ifname ""]
		if { $ifnode == 0 } {
			return 0
		}

		if { [cli_branchpt_start 600 1614] } {
			if { [cli_is_referenced $ifnode] && [cli_is_used $ifnode "system sdwan" "members"] } {
				return 1
			}
		} else {
			if { [cli_is_referenced $ifnode] && [cli_is_used $ifnode "system virtual-wan-link" "members"] } {
				return 1
			}
		}

		return 0
	}
	proc nCfg_policy_check_intf_by_member_name { iflist ifname } {
		set s2 [string trim $ifname \"]
		foreach member $iflist {
			set s1 [string trim $member \"]
			if { $s1 eq $s2 } {
				return 1
			}
			if { $s1 eq "virtual-wan-link" } {
				return [nCfg_is_interface_used_by_vwl $ifname]
			}
		}
		return 0
	}
	proc nCfg_policy_check_intf { policy ifname from } {
		if { $from == 1 } {
			set iflist [cli_get_value $policy "" "" "srcintf" 1]
			return [nCfg_policy_check_intf_by_member_name $iflist $ifname]
		} else {
			set iflist [cli_get_value $policy "" "" "dstintf" 1]
			return [nCfg_policy_check_intf_by_member_name $iflist $ifname]
		}
		return 0
	}

	proc cli_ip2val { ip } {
		set iplist [split $ip .]
		return [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
	}
	proc cli_val2ip { val } {
		set a [expr $val & 255]
		set b [expr ($val>>8) & 255]
		set c [expr ($val>>16) & 255]
		set d [expr ($val>>24) & 255]
		return "$d.$c.$b.$a"
	}
	proc find_sdn_conn_type_by_name { name } {
		global CLI_GLOBAL_NODE
		global CLI_GLOBAL_DEV
		global CLI_CUR_VDOM_NODE
		if { $CLI_GLOBAL_DEV } {
			set sdn [cli_get_node $CLI_CUR_VDOM_NODE "system sdn-connector" $name ""]
		} else {
			set sdn [cli_get_node $CLI_GLOBAL_NODE "system sdn-connector" $name ""]
		}
		if { $sdn } {
			return [cli_get_value $sdn "" "" "type"]
		}
		return ""
	}
	proc check_fw_address { node addr_type } {
		global CLI_GLOBAL_DEV
		if {$addr_type eq "iprange"} {
		  set addr_start_ip [cli_get_value $node "" "" "start-ip"]
		  set addr_end_ip [cli_get_value $node "" "" "end-ip"]
		  if {$addr_start_ip eq ""} {
			set addr_start_ip "0.0.0.0"
		  }
		  if {$addr_end_ip eq "" || $addr_end_ip eq "0.0.0.0"} {
				cli_set_errmsg "invalid end_ip"
				return 0
		  }
		  set iplist [split $addr_start_ip .]
		  set ipint1 [expr { (([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]) & 0xffffffff }]
		  set iplist [split $addr_end_ip .]
		  set ipint2 [expr { (([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]) & 0xffffffff }]
		  if {$ipint1 > $ipint2} {
			   cli_set_errmsg "invalid ip range"
			   return 0
		  }
		}
		if {$addr_type eq "fqdn"} {
		  set addr_fqdn [cli_get_value $node "" "" "fqdn"]
		  if {$addr_fqdn eq ""} {
			  cli_set_errmsg "empty value"
			  return 0
		  }
		}
		if {$addr_type eq "wildcard-fqdn"} {
		  set addr_fqdn [cli_get_value $node "" "" "wildcard-fqdn"]
		  if {$addr_fqdn eq ""} {
			  cli_set_errmsg "empty value"
			  return 0
		  }
		}
		if {$addr_type eq "geography"} {
		  set country_id [cli_get_value $node "" "" "country"]
		  set country_id [string trim $country_id \"]
		  if {$country_id eq ""} {
			  cli_set_errmsg "empty value"
			  return 0
		  }
		}
		if {$addr_type eq "ipmask"} {
		  set subnet [cli_get_value $node "" "" "subnet"]
		  if {$subnet eq "" || $subnet eq "0.0.0.0 0.0.0.0"} {
		  } else {
			if {[scan $subnet "%d.%d.%d.%d %d.%d.%d.%d" a a a a m1 m2 m3 m4] != 8} {
					cli_set_errmsg "invalid subnet ip and mask"
					return 0
			}
			set m [format "0x%x" [expr ~(($m1<<24)|($m2<<16)|($m3<<8)|$m4)]]
			set m [format "0x%x" [expr (0x00000000ffffffff & $m)]]
			set n [expr ($m + 1)]
			if {[expr ($n & $m)] != 0} {
				cli_set_errmsg "invalid mask"
				return 0
			}
		  }
		}
		set stype [cli_get_value $node "" "" "sub-type"]
		if {$addr_type eq "dynamic" && $stype ne "ems-tag"
				&& $stype ne "fsso" && $stype ne "clearpass-spt"
				&& $stype ne "swc-tag" && $stype ne "fortinac-tag" && $stype ne "fortivoice-tag"} {
			set sdn [cli_get_value $node "" "" "sdn"]
			set has_flt 0
			set sdntype ""
			if { [cli_ver_start 600 2] } {
				if { $sdn eq "" } {
					cli_set_errmsg "sdn cannot be empty for dynamic firewall address"
					return 0
				}
				set sdntype [find_sdn_conn_type_by_name $sdn]
				if { $sdntype eq "" } {
					if { [string match "*postcheck*" [cli_get_clisrc]] } {
						cli_set_errmsg "SDN $sdn does not exist"
						return 0
					} else {
						cli_schedule_post_check $node "edit"
						return 1
					}
				}
				set allow [list "alicloud" "aws" "azure" "gcp" "oci" "kubernetes" "openstack" "vmware" "sepm" "aci-direct"]
				if { [lsearch $allow $sdntype] != -1 } {
					set has_flt 1
				}
			} else {
				if {$sdn eq "aws" || $sdn eq "azure" || $sdn eq "gcp" || $sdn eq "oci" || $sdn eq "openstack"} {
					set has_flt 1
				}
			}
			if { $has_flt == 1} {
				set is_wildcard 0
				set flt [cli_get_value $node "" "" "filter"]
				set flt [string trim $flt \"]
				if { $flt eq "" && $sdntype ne "sepm" } {
					cli_set_errmsg "Filter must be set"
					return 0
				}
				if { $CLI_GLOBAL_DEV } {
					if {[cli_ver_start 600 2]} {
						set is_wildcard 1
					}
				} elseif { [cli_branchpt_start 600 1033] } {
					set is_wildcard 1
				}
				if { $flt ne "" && [cli_check_addrflt $flt $is_wildcard] } {
					cli_set_errmsg "invalid filter $flt."
					return 0
				}
			}
		}
		if {$addr_type eq "dynamic" && $stype eq "fsso"} {
			set fsso_grp [cli_get_value $node "" "" "fsso-group"]
			if { $fsso_grp eq "" } {
				cli_set_errmsg "fsso-group cannot be empty for dynamic firewall address with sub-type fsso"
				return 0
			}
		}
		return 1
	}
	proc check_fw_multicast_policy { mc_policy } {
		#        	global CLI_CUR_VDOM_NODE
		#		set dstintf [cli_get_value $mc_policy "" "" "dstintf"]
		#		set srcintf [cli_get_value $mc_policy "" "" "srcintf"]
		#		set node1 [cli_get_node $CLI_CUR_VDOM_NODE "dynamic interface" $dstintf ""]
		#		set node2 [cli_get_node $CLI_CUR_VDOM_NODE "dynamic interface" $srcintf ""]
		#		if {$node1 != 0} {
		#			set single_intf1 [cli_get_value $node1 "" "" "single-intf"]
		#			if { $single_intf1 eq "disable"} {
		#				cli_set_errmsg "zone $dstintf is not allowed as firewall multicast policy dstintf."
		#				return 0
		#			}
		#		}
		#		if {$node2 != 0} {
		#			set single_intf2 [cli_get_value $node2 "" "" "single-intf"]
		#			if { $single_intf2 eq "disable"} {
		#				cli_set_errmsg "zone $srcintf is not allowed as firewall multicast policy srcintf."
		#				return 0
		#			}
		#		}
		return 1
	}
	proc check_fw_multicast_address { mc_addr } {
		set addr_type [cli_get_value $mc_addr "" "" "type"]
		if {$addr_type eq "multicastrange"} {
			set start_ip [cli_get_value $mc_addr "" "" "start-ip"]
			set iplist [split $start_ip .]
			set value [lindex $iplist 0]
			if { ($value < 224) || ($value > 239) } {
				cli_set_errmsg "start-ip is not a valid multicast address"
				return 0
			}
			set end_ip [cli_get_value $mc_addr "" "" "end-ip"]
			set iplist2 [split $end_ip .]
			set value [lindex $iplist2 0]
			if { ($value < 224) || ($value > 239) } {
				cli_set_errmsg "end-ip is not a valid multicast address"
				return 0
			}
			set start_ipint [cli_ip2val $start_ip]
			set end_ipint [cli_ip2val $end_ip]
			if {$end_ipint < $start_ipint} {
				cli_set_errmsg "end-ip is smaller than start-ip"
				return 0
			}
		} elseif {$addr_type eq "broadcastmask"} {
		}
		return 1
	}
	proc is_multicast_address { addr } {
		set iplist [split $addr .]
		set value [lindex $iplist 0]
		if { ($value < 224) || ($value > 239) } {
			return 0
		}
		return 1
	}
	proc channel_is_invalid {c clist isdfs} {
		set clist [string map {"," " "} $clist]
		foreach cs $clist {
			set csm [string map {"-" ""} $cs]
			set csm [string map {"+" ""} $csm]
			set csm [string map {"*" ""} $csm]
			if { $c ne $csm } {
				continue
			}
			if { $isdfs eq "yes" } { return 0 }
			if { [string last "*" $cs] eq -1 } { return 0 }
			break
		}
		return 1
	}
	proc addr_iprange_or_ipmask { dstaddr addrgrp } {
        global CLI_CUR_VDOM_NODE
        if { [string length $dstaddr] == 0 } {
        	cli_set_errmsg "dstaddr for policy46 or policy 64 cannot be empty"
        	return 0
        }
        foreach addr $dstaddr {
                set addr_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $addr ""]
                if { $addr_node  } {
                        if {([cli_get_value $addr_node "" "" "type"] ne "ipmask") &&
                            ([cli_get_value $addr_node "" "" "type"] ne "iprange")} {
                                if { $addrgrp ne "" } {
                                        cli_set_errmsg "address \"$addr\" in group \"$addrgrp\" type not iprange or ipmask"
                                } else {
                                        cli_set_errmsg "address \"$addr\" type not iprange or ipmask"
                                }
                                return 0
                        }
                } else {
                        set addrgrp_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp" $addr ""]
                        if { $addrgrp_node } {
                                set addrgrp [cli_get_value $addrgrp_node "" "" "member"]
                                if { ![addr_iprange_or_ipmask $addrgrp $addr] } {
                                        return 0
                                }
                        }
                }
        }
        return 1
	}
        proc DEFAULT_SNIFFER_PROFILE { } {
                return "sniffer-profile"
        }
        proc ncfg_is_cw_wtpprof_used { profname } {
                global CLI_CUR_VDOM_NODE
                if {[cli_is_match $CLI_CUR_VDOM_NODE 1 "wireless-controller wtp" "wtp-profile" 0 '*$profname*']} {
                        return 1
                }
                return 0
        }
	proc ncfg_is_fapc_platform { type } {
		if { ($type eq "C220C") || ($type eq "C225C") || ($type eq "C221E") || ($type eq "C226E") || ($type eq "C23JD") || ($type eq "C24JE") || ($type eq "C21D") } {
			return 1
		}
		return 0
	}
	proc ncfg_is_fapc_support_ctry { country } {
		if { ($country eq "CN") || ($country eq "SG") } {
			return 1
		}
		return 0
	}
	proc ncfg_add_default_fapc_wtpprof { country } {
		global CLI_CUR_VDOM_NODE
		set cmd "config wireless-controller wtp-profile\nedit \"FAPC220C-default\"\n"
		append cmd "set ap-country $country\n"
		append cmd "config platform\nset type C220C\nend\n"
		append cmd "config radio-1\nset band 802.11n\nend\n"
		append cmd "config radio-2\nset band 802.11ac\nend\n"
		append cmd "next\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		set cmd "config wireless-controller wtp-profile\nedit \"FAPC225C-default\"\n"
		append cmd "set ap-country $country\n"
		append cmd "config platform\nset type C225C\nend\n"
		append cmd "config radio-1\nset band 802.11n\nend\n"
		append cmd "config radio-2\nset band 802.11ac\nend\n"
		append cmd "next\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
	      if { ![cli_branchpt_start 500 1528] } {
		set cmd "config wireless-controller wtp-profile\nedit \"FAPC221E-default\"\n"
		append cmd "set ap-country $country\n"
		append cmd "config platform\nset type C221E\nend\n"
		append cmd "config radio-1\nset band 802.11n\nend\n"
		append cmd "config radio-2\nset band 802.11ac\nend\n"
		append cmd "next\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		set cmd "config wireless-controller wtp-profile\nedit \"FAPC226E-default\"\n"
		append cmd "set ap-country $country\n"
		append cmd "config platform\nset type C226E\nend\n"
		append cmd "config radio-1\nset band 802.11n\nend\n"
		append cmd "config radio-2\nset band 802.11ac\nend\n"
		append cmd "next\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
	      }
		set cmd "config wireless-controller wtp-profile\nedit \"FAPC23JD-default\"\n"
		append cmd "set ap-country $country\n"
		append cmd "config platform\nset type C23JD\nend\n"
		append cmd "config radio-1\nset band 802.11n\nend\n"
		append cmd "config radio-2\nset mode disabled\nend\n"
		append cmd "next\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		set cmd "config wireless-controller wtp-profile\nedit \"FAPC24JE-default\"\n"
		append cmd "set ap-country $country\n"
		append cmd "config platform\nset type C24JE\nend\n"
		append cmd "config radio-1\nset band 802.11n\nend\n"
		append cmd "config radio-2\nset band 802.11ac\nend\n"
		append cmd "next\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
	      if { ![cli_branchpt_start 500 1528] } {
		set cmd "config wireless-controller wtp-profile\nedit \"FAPC21D-default\"\n"
		append cmd "set ap-country $country\n"
		append cmd "config platform\nset type C21D\nend\n"
		append cmd "config radio-1\nset band 802.11n\nend\n"
		append cmd "config radio-2\nset mode disabled\nend\n"
		append cmd "next\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
	      }
	      return 1
	}
	proc cwAc_fapc_cleanup { } {
		global CLI_CUR_VDOM_NODE
		set list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "wireless-controller wtp-group"]
		set cmd "config wireless-controller wtp-group\n"
		foreach n $list {
			set name [cli_get_value $n "" "" "name"]
			set type [cli_get_value $n "" "" "platform-type"]
			if { [ncfg_is_fapc_platform $type] } {
				append cmd "delete \"$name\"\n"
			}
		}
		append cmd "end\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd

		set list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "wireless-controller wtp-profile"]
		set cmd "config wireless-controller wtp-profile\n"
		foreach n $list {
			set name [cli_get_value $n "" "" "name"]
			set platform [cli_get_node $n "platform" "" ""]
			if { $platform ne 0 } {
				set type [cli_get_value $platform "" "" "type"]
				if { [ncfg_is_fapc_platform $type] } {
					append cmd "delete \"$name\"\n"
				}
			}
		}
		append cmd "end\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		return 1
	}
	proc cmf_firewall_policy_learn_enabled { p } {
		if { [cli_get_value $p "" "" "learning-mode"] eq "enable" } {
			return 1
		}
		return 0
	}
	proc cmf_firewall_unset_learning_policy { p } {
		cli_set_value $p "" "" "scan-botnet-connections" "disable"
		cli_set_value $p "" "" "utm-status" "disable"
		cli_unset_value $p "" "" "logtraffic"
	}
	proc cmf_firewall_set_learning_policy { p } {
		cli_set_value $p "" "" "logtraffic" "all"
		cli_set_value $p "" "" "utm-status" "enable"
		cli_set_value $p "" "" "action" "accept"
		cli_set_value $p "" "" "scan-botnet-connections" "monitor"
	}
	proc ip_invalid { addr chk_boundry } {
		set ippat {(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)}
		if { (![regexp $ippat [lindex $addr 0] ip])|| ([lindex $addr 0] ne $ip)} {
			return 1
		}
		if { $chk_boundry == 1 && (($ip eq "0.0.0.0") || ($ip eq "255.255.255.255")) } {
			return 1
		}
		return 0
	}
	proc iprange_invalid { ipstr err_not_range } {
		proc ip_to_value { addr } {
			set iplist [split $addr .]
			return [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
		}
		set ipstr [string map {"\"" ""} $ipstr]
		set iprange [split $ipstr -]
		if { 2 == [llength $iprange]} {
			set start_ip [lindex $iprange 0]
			set end_ip [lindex $iprange 1]
			if { [ip_invalid $start_ip 1] } {
				return 1
			}
			if { [ip_invalid $end_ip 1] } {
				return 1
			}
			if {[ip_to_value $start_ip] > [ip_to_value $end_ip]} {
				return 1
			}
			return 0
		}

		if { $err_not_range == 1 } {
			return 1
		}

		return 0
	}
	proc iprange_invalid2 { ipstr err_not_range } {
		proc ip_to_value { addr } {
			set iplist [split $addr .]
			return [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
		}
		set ipstr [string map {"\"" ""} $ipstr]
		set iprange [split $ipstr -]
		if { 2 == [llength $iprange]} {
			set start_ip [lindex $iprange 0]
			set end_ip [lindex $iprange 1]
			if { [ip_invalid $start_ip 0] } {
				return 1
			}
			if { [string is integer $end_ip] } {
				set lstart_ip [split $start_ip .]
				set last_digit [lindex $lstart_ip 3]
				if { $last_digit > $end_ip } {
					return 1
				}
				return 0
			}
			if { [ip_invalid $end_ip 0] } {
				return 1
			}
			if {[ip_to_value $start_ip] > [ip_to_value $end_ip]} {
				return 1
			}
			return 0
		}

		if { $err_not_range == 1 } {
			return 1
		}

		return 0
	}
        proc prof_protocol_options_act { p } {
                global CLI_CUR_NODE
                global CLI_CUR_PARENT_NODE
                global CLI_CUR_VDOM_NODE
                global CLI_ACT
                if {$CLI_ACT eq "add"} { return 1 }
                set cmd ""
                set np ""
                set o_opts [cli_get_org_value $CLI_CUR_NODE "" "" "options"]
                set n_opts [cli_get_value $CLI_CUR_NODE "" "" "options"]
                if {[string first "no-content-summary" $o_opts] != -1 &&
                    [string first "no-content-summary" $n_opts] == -1} {
                        append np "no-content-summary"
                }
                if { ![cli_branchpt_start 500 1019] } {
                    if {[string first "splice" $o_opts] != -1 &&
                        [string first "splice" $n_opts] == -1} {
                        append np " splice"
                    }
                }
                if { $np ne "" } {
                        set opts ""
                        append opts "$n_opts $np"
                        append cmd "config $p \nset options $opts\nend\n"
                }
                if { $cmd ne "" } {
                        set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
                        cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall profile-protocol-options\nedit \"$name\"\n$cmd\nnext\nend\n"
                }
                return 1
        }
	proc nCfg_get_inspection_mode {} {
		global CLI_GLOBAL_DEV
		global CLI_CUR_PKG_NODE
		global CLI_CUR_VDOM_NODE
		if { $CLI_GLOBAL_DEV } {
			set sys_settings [cli_get_node $CLI_CUR_PKG_NODE "policy package settings" "" ""]
		} else {
			set sys_settings [cli_get_node $CLI_CUR_VDOM_NODE "system settings" "" ""]
		}
		return [cli_get_value $sys_settings "" "" "inspection-mode"]
	}
	proc inspection_mode_vdom_flow {} {
		return [expr {[nCfg_get_inspection_mode] eq "flow" }]
	}
	proc nCfg_get_ngfw_mode {} {
		global CLI_GLOBAL_DEV
		global CLI_CUR_PKG_NODE
		global CLI_CUR_VDOM_NODE
		if { $CLI_GLOBAL_DEV } {
			set sys_settings [cli_get_node $CLI_CUR_PKG_NODE "policy package settings" "" ""]
		} else {
			set sys_settings [cli_get_node $CLI_CUR_VDOM_NODE "system settings" "" ""]
		}
		return [cli_get_value $sys_settings "" "" "ngfw-mode"]
	}
	proc ngfw_mode_policy {} {
		if { [nCfg_get_ngfw_mode] eq "policy-based" } {
			return 1
		}
		return 0
	}
	proc vdom_get_ngfw_mode { vdom_name } {
		set vnode [cli_get_vdom_node $vdom_name]
		if { $vnode } {
			set sys_settings [cli_get_node $vnode "system settings" "" ""]
			return [cli_get_value $sys_settings "" "" "ngfw-mode"]
		}
		return ""
	}
	proc vdom_ngfw_mode_policy { vdom_name } {
		if { [vdom_get_ngfw_mode $vdom_name] eq "policy-based" } {
			return 1
		}
		return 0
	}
	proc hyperscale_policy_offload_level {} {
		global CLI_GLOBAL_DEV
		global CLI_CUR_PKG_NODE
		global CLI_CUR_VDOM_NODE
		if { $CLI_GLOBAL_DEV } {
			set sys_settings [cli_get_node $CLI_CUR_PKG_NODE "policy package settings" "" ""]
		} else {
			set sys_settings [cli_get_node $CLI_CUR_VDOM_NODE "system settings" "" ""]
		}
		return [cli_get_value $sys_settings "" "" "policy-offload-level"]
	}
	proc is_hyperscale_activated {} {
		global CLI_GLOBAL_DEV
		if { $CLI_GLOBAL_DEV } {
			set npd_op_level [hyperscale_policy_offload_level]
			if { $npd_op_level eq "full-offload" } {
				return 1
			}
		} else {
			if { [is_platform_support_hyperscale] } {
				if { [cli_get_devinfo "hyperscale"] eq "yes" } {
					set npd_op_level [hyperscale_policy_offload_level]
					if { $npd_op_level eq "full-offload" } {
						return 1
					}
				}
			}
		}
		return 0
	}
	proc consolidated_fw_mode_enabled {} {
		global CLI_GLOBAL_DEV
		global CLI_CUR_PKG_NODE
		global CLI_CUR_VDOM_NODE
		if { $CLI_GLOBAL_DEV } {
			set sys_settings [cli_get_node $CLI_CUR_PKG_NODE "policy package settings" "" ""]
		} else {
			set sys_settings [cli_get_node $CLI_CUR_VDOM_NODE "system settings" "" ""]
		}
		set consolidated_fw_mode [cli_get_value $sys_settings "" "" "consolidated-firewall-mode"]
		return [expr {$consolidated_fw_mode eq "enable"}]
	}
        proc disk_log_default_enabled { } {
                if { [cli_in_featurelist "e_DISK_LOG_DEFAULT_DISABLE"] } {
                        if { [cli_has_feature "e_DISK_LOG_DEFAULT_DISABLE"] } {
                                return 0
                        }
                }
                set g [cli_get_devinfo "get_log_disk_info"]
                if { $g eq "NA" } {
                        set g [cli_get_devinfo "hdd"]
                }
                if { $g eq "no" } {
                        return 0
                }
                set i [cli_get_devinfo "is_support_log_on_boot_device"]
                set d [cli_get_devinfo "fgt_disk_mgr_sata_disk"]
                if { (($i eq "yes") && ($d ne "yes")) } {
                        return 0
                }
                return 1
        }
        proc storage_log_disk_get_wanopt_size { } {
                return 0
        }
        proc cli_feature_value_rtp_advanced { } {
                if { [cli_branchpt_start 500 272] } {
                        return 0
                }
                set platform [cli_get_devinfo "platform"]
                if { [string match -nocase $platform "Fortigate-60D-3G4G-VZW"] ||
                     [string match -nocase $platform "FortiWiFi-60D-3G4G-VZW"] ||
                     [string match -nocase $platform "FortigateRugged-60D"] } {
                        return 1
                }
                return 0
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
        proc ips_invalid_cate { catid } {
		foreach cat $catid {
			if { ![cli_valid_ips_catid $cat 0] } {
				cli_set_errmsg "invalid category $cat"
				return 1
			}
		}
		return 0
	}
	proc ips_invalid_cate_app { catid appid } {
		global CLI_CUR_VDOM_NODE
		foreach app $appid {
			if { $catid ne "" } {
				set v 0
				foreach cat $catid {
					if { [cli_valid_ips_catid $cat $app] } {
						set v 1
						break
					}
			if {[cli_is_match $CLI_CUR_VDOM_NODE 1 "application custom" "signature" 0 "'*--attack_id $app;*'"] &&
			    [cli_is_match $CLI_CUR_VDOM_NODE 1 "application custom" "signature" 0 "'*--app_cat $cat;*'"] } {
						set v 1
						break
					}
				}
				if { $v eq 0 } {
					cli_set_errmsg "invalid application $app under app-category $catid"
					return 1
				}
			} else {
				if { ![cli_valid_ips_catid 0 $app] } {
			if {![cli_is_match $CLI_CUR_VDOM_NODE 1 "application custom" "signature" 0 "'*--attack_id $app;*'"]} {
						cli_set_errmsg "invalid application $app"
						return 1
					}
				}
			}
		}
		return 0
	}
	proc intf_exist_and_device_id_not_enabled { name } {
                global CLI_GLOBAL_NODE
		set intf [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
		if { $intf } {
			if { [cli_get_value $intf "" "" "device-identification"] ne "enable" } {
				return -1
			}
			return 1
		}
		return 0
	}
	proc cmf_firewall_validate_learning_src_dst { p } {
                global CLI_CUR_VDOM_NODE
		global CLI_GLOBAL_DEV
		set e_any "Can't use wildcard for source or destination interfaces when learning mode is enabled"
		set e_intf "For learning mode, device identification should be enabled in source interface:"
		set e_zone "For learning mode, device identification should be enabled on all interfaces in zone:"
		set e_vwl  "For learning mode, device identification should be enabled on all interfaces that are members of:"
		set srcintfs [cli_get_value $p "" "" "srcintf"]
		set dstintfs [cli_get_value $p "" "" "dstintf"]
		foreach dstintf $dstintfs {
			set dstintf [string trim $dstintf \"]
			if { $dstintf eq "any" } {
				cli_set_errmsg $e_any
				return 0
			}
		}
		foreach srcintf $srcintfs {
			set srcintf [string trim $srcintf \"]
			if { $srcintf eq "any" } {
				cli_set_errmsg $e_any
				return 0
			}
			if { $CLI_GLOBAL_DEV } {
				continue
			}
			set r [intf_exist_and_device_id_not_enabled $srcintf]
			if { $r } {
				if { $r == -1 } {
					cli_set_errmsg "$e_intf $srcintf"
					return 0
				}
				continue
			}
			set zone [cli_get_node $CLI_CUR_VDOM_NODE "system zone" $srcintf ""]
			if { $zone } {
				set intfs [cli_get_value $zone "" "" "interface"]
				foreach intf $intfs {
					set r [intf_exist_and_device_id_not_enabled $intf]
					if { $r == -1 } {
						cli_set_errmsg "$e_zone $srcintf"
						return 0
					}
				}
				continue
			}
			if { $srcintf eq "virtual-wan-link" } {
				if { [cli_branchpt_start 600 1614] } {
					set vwls [cli_get_node $CLI_CUR_VDOM_NODE "system sdwan" "" ""]
				} else {
					set vwls [cli_get_node $CLI_CUR_VDOM_NODE "system virtual-wan-link" "" ""]
				}
				set vwls [cli_get_tbl_list $vwls "members"]
				foreach vwl $vwls {
					set intf [cli_get_value $vwl "" "" "interface"]
					if { $intf eq "" } {
						continue
					}
					set r [intf_exist_and_device_id_not_enabled $intf]
					if { $r == -1 } {
						cli_set_errmsg "$e_vwl virtual-wan-link"
						return 0
					}
				}
			} else {
				cli_set_errmsg "$srcintf is not supported for learning mode"
				return 0
			}
		}
		return 1
	}
	proc cli_get_diff_opts { nopts oopts act } {
		set out ""
		if { $act == 1 } {
			foreach n $nopts {
				set n [string trim $n "\""]
				set exist 0
				foreach o $oopts {
					set o [string trim $o "\""]
					if { $o eq $n } {
						set exist 1
						break
					}
				}
				if { $exist == 0 } {
					append out "$n "
				}
			}
		} elseif { $act == 0 } {
			foreach o $oopts {
				set o [string trim $o "\""]
				set exist 0
				foreach n $nopts {
					set n [string trim $n "\""]
					if { $n eq $o } {
						set exist 1
						break
					}
				}
				if { $exist == 0 } {
					append out "$o "
				}
			}
		}
		return $out
	}
	proc cli_invalid_ipv4 { ip } {
		set ippattern {(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)}
		if { (![regexp $ippattern $ip match]) || ($ip ne $match)} {
			return 1
		}
		return 0
	}
	proc cli_invalid_ipv6 { ip } {
		set ippattern {^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$}
		if { (![regexp $ippattern $ip match]) || ($ip ne $match)} {
			return 1
		}
		return 0
	}
	proc cli_invalid_maskv4 { subnet } {
		if { [cli_invalid_ipv4 $subnet] } {
			return 1
		}
		if {[scan $subnet "%d.%d.%d.%d" m1 m2 m3 m4] != 4} {
			return 1
		}
		set m [format "0x%x" [expr ~(($m1<<24)|($m2<<16)|($m3<<8)|$m4)]]
		set m [format "0x%x" [expr (0x00000000ffffffff & $m)]]
		set n [expr ($m + 1)]
		if {[expr ($n & $m)] != 0} {
			return 1
		}
		return 0
	}
	proc cli_invalid_email { email } {
		set pattern {^([a-zA-Z0-9_\.\-\\])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,})$}
		if {[regexp $pattern $email] == 0} {
			return 1
		}
		return 0
	}
	proc queue_policy_add_act { node } {
		global CLI_CUR_VDOM_NODE
		set name [cli_get_value $node "" "" "name"]
		set schedule [cli_get_value $node "" "" "schedule"]
		set cmd "config switch-controller qos queue-policy\nedit $name\nset schedule $schedule\n"
		append cmd "config cos-queue\n"
		append cmd "edit \"queue-0\"\nnext\n"
		append cmd "edit \"queue-1\"\nnext\n"
		append cmd "edit \"queue-2\"\nnext\n"
		append cmd "edit \"queue-3\"\nnext\n"
		append cmd "edit \"queue-4\"\nnext\n"
		append cmd "edit \"queue-5\"\nnext\n"
		append cmd "edit \"queue-6\"\nnext\n"
		append cmd "edit \"queue-7\"\nnext\n"
		append cmd "end\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		return 0
	}
	proc lldp_profile_add_act { node } {
		global CLI_CUR_VDOM_NODE
		set name [cli_get_value $node "" "" "name"]
		set tlvs [cli_get_value $node "" "" "med-tlvs"]

		set cmd "config switch-controller lldp-profile\nedit $name\n"
		append cmd "config med-network-policy\n"

		if { [string match "*network-policy*" $tlvs] } {
			append cmd "edit \"voice\"\nnext\n"
			append cmd "edit \"voice-signaling\"\nnext\n"
			append cmd "edit \"guest-voice\"\nnext\n"
			append cmd "edit \"guest-voice-signaling\"\nnext\n"
			append cmd "edit \"softphone-voice\"\nnext\n"
			append cmd "edit \"video-conferencing\"\nnext\n"
			append cmd "edit \"streaming-video\"\nnext\n"
			append cmd "edit \"video-signaling\"\nnext\n"
		} else {
			append cmd "purge\n"
		}
		append cmd "end\n"

		if { [cli_branchpt_start 600 900] } {
			append cmd "config med-location-service\n"

			if { [string match "*location-identification*" $tlvs] } {
				append cmd "edit \"coordinates\"\nnext\n"
				append cmd "edit \"address-civic\"\nnext\n"
				append cmd "edit \"elin-number\"\nnext\n"
			} else {
				append cmd "purge\n"
			}
			append cmd "end\n"
		}
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		return 0
	}
	proc ngfw_mode_set_policy_mode { cnfw_mode parent } {
                global CLI_CUR_VDOM_NODE
		set prof_group_list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall profile-group"]
		foreach pg $prof_group_list {
			set cmd "unset webfilter-profile\n"
			append cmd "unset application-list\n"
			append cmd "unset ssl-ssh-profile\n"
			cli_exec_cmd $pg $cmd
		}
		if {$cnfw_mode eq "enable"} {
			set policy_list [cli_get_tbl_list $parent "firewall consolidated policy"]
			foreach policy $policy_list {
				set profile_type [cli_get_value $policy "" "" "profile-type"]
				if {$profile_type eq "single"} {
					set cmd "unset webfilter-profile\n"
					append cmd "unset application-list\n"
					append cmd "unset ssl-ssh-profile\n"
					cli_exec_cmd $policy $cmd
				}
			}
		} else {
			set policy_list [cli_get_tbl_list $parent "firewall policy"]
			foreach policy $policy_list {
				set profile_type [cli_get_value $policy "" "" "profile-type"]
				if {$profile_type eq "single"} {
					set cmd "unset webfilter-profile\n"
					append cmd "unset application-list\n"
					append cmd "unset ssl-ssh-profile\n"
					cli_exec_cmd $policy $cmd
				}
			}
			set policy_list [cli_get_tbl_list $parent "firewall policy6"]
			foreach policy $policy_list {
				set profile_type [cli_get_value $policy "" "" "profile-type"]
				if {$profile_type eq "single"} {
					set cmd "unset webfilter-profile\n"
					append cmd "unset application-list\n"
					append cmd "unset ssl-ssh-profile\n"
					cli_exec_cmd $policy $cmd
				}
			}
		}
	}
	proc ngfw_mode_set_profile_mode { cnfw_mode parent } {
                global CLI_CUR_VDOM_NODE
		set prof_group_list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall profile-group"]
		foreach pg $prof_group_list {
			set deep_opts [cli_get_value $pg "" "" "ssl-ssh-profile"]
			if {$deep_opts == 0 || $deep_opts eq ""} {
				set cmd "set ssl-ssh-profile \"certificate-inspection\"\n"
				cli_exec_cmd $pg $cmd
			}
		}
		if {$cnfw_mode eq "enable"} {
			set policy_list [cli_get_tbl_list $parent "firewall consolidated policy"]
			foreach policy $policy_list {
				set profile_type [cli_get_value $policy "" "" "profile-type"]
				if {$profile_type eq "single"} {
					set utm_status [cli_get_value $policy "" "" "utm-status"]
					if {$utm_status eq "enable"} {
						set deep_opts [cli_get_value $policy "" "" "ssl-ssh-profile"]
						if {$deep_opts == 0 || $deep_opts eq ""} {
							set cmd "set ssl-ssh-profile \"certificate-inspection\"\n"
							cli_exec_cmd $policy $cmd
						}
					}
					set cmd "unset application\n"
					append cmd "unset app-category\n"
					append cmd "unset url-category\n"
					append cmd "unset app-group\n"
					cli_exec_cmd $policy $cmd
				}
			}
		} else {
			set policy_list [cli_get_tbl_list $parent "firewall policy"]
			foreach policy $policy_list {
				set profile_type [cli_get_value $policy "" "" "profile-type"]
				if {$profile_type eq "single"} {
					set utm_status [cli_get_value $policy "" "" "utm-status"]
					if {$utm_status eq "enable"} {
						set deep_opts [cli_get_value $policy "" "" "ssl-ssh-profile"]
						if {$deep_opts == 0 || $deep_opts eq ""} {
							set cmd "set ssl-ssh-profile \"certificate-inspection\"\n"
							cli_exec_cmd $policy $cmd
						}
					}
					set cmd "unset application\n"
					append cmd "unset app-category\n"
					append cmd "unset url-category\n"
					append cmd "unset app-group\n"
					cli_exec_cmd $policy $cmd
				}
			}
			set policy_list [cli_get_tbl_list $parent "firewall policy6"]
			foreach policy $policy_list {
				set profile_type [cli_get_value $policy "" "" "profile-type"]
				if {$profile_type eq "single"} {
					set utm_status [cli_get_value $policy "" "" "utm-status"]
					if {$utm_status eq "enable"} {
						set deep_opts [cli_get_value $policy "" "" "ssl-ssh-profile"]
						if {$deep_opts == 0 || $deep_opts eq ""} {
							set cmd "set ssl-ssh-profile \"certificate-inspection\"\n"
							cli_exec_cmd $policy $cmd
						}
					}
					set cmd "unset application\n"
					append cmd "unset app-category\n"
					append cmd "unset url-category\n"
					append cmd "unset app-group\n"
					cli_exec_cmd $policy $cmd
				}
			}
		}
	}
	proc check_recur_group_members { grplist cate members vdom } {
		foreach m $members {
			if { [cli_get_node $vdom $cate $m ""] != 0 } {
				if { [lsearch $grplist $m] >= 0  || [lsearch $grplist "\"$m\""] >= 0 } {
					cli_set_errmsg "recursively nested $cate ($m) in member list is detected."
					return 0
				}
				lappend grplist "$m"
				set memlist [cli_get_value $vdom $cate $m "member" 1]
				set ret [check_recur_group_members $grplist $cate $memlist $vdom]
				set grplist [lreplace $grplist end end]
				if { $ret eq 0 } {
					return 0
				}
			}
		}
		return 1
	}
	proc cli_is_quarantine_vap { vapnode vapvdom } {
		set vdnode [cli_get_vdom_node $vapvdom]
		if { !$vapnode || !$vdnode || ![cli_ver_start 600 0] } { return 0 }
		if { [cli_get_value $vdnode "system settings" "" "opmode"] eq "nat" && [cli_get_value $vdnode "user quarantine" "" "quarantine"] eq "enable" && [cli_get_value $vapnode "" "" "local-bridging"] eq "disable" && [cli_get_value $vapnode "" "" "mesh-backhaul"] eq "disable" } { return 1 }
		return 0
	}
	proc cli_add_quarantine_intf { vapname vapvdom } {
		global CLI_GLOBAL_NODE

		set vapname [string trim $vapname \"]
		set vapvdom [string trim $vapvdom \"]
		set vdnode [cli_get_vdom_node $vapvdom]
		if { $vdnode == 0 } { return 0; }

		set wqtn_intf ""
		set nodes  [cli_get_match_list $CLI_GLOBAL_NODE 1 "system interface" "interface" 0 "\"$vapname\"" "type" 0 "vlan" "vlanid" 0 4093]
		foreach node $nodes {
			set wqtn_intf [cli_get_value $node "" "" "name"]
			break
		}

		if { $wqtn_intf eq "" } {
			set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $vapname ""]
			if { !$intf_node } { return 0; }
			set idx [cli_get_value $intf_node "" "" "snmp-index"]
			if { $idx <= 0 } { return 0; }

			set wqtn_intf [get_shadow_intf_name "wqtn" ".$idx." $vapname]
			set wqtn_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $wqtn_intf ""]
			if { $wqtn_node == 0 } {
				set cmd "config system interface\nedit \"$wqtn_intf\"\nset vdom $vapvdom\nset interface \"$vapname\"\nset type vlan\nset vlanid 4093\n"
				append cmd "set description \"Quarantine VLAN\"\n"
				append cmd "set security-mode captive-portal\n"
 				append cmd "set device-identification enable\n"
				if { [cli_obj_support "system interface" "device-identification-active-scan"] } {
					append cmd "set device-identification-active-scan enable\n"
				}
				append cmd "next\nend\n"
				cli_exec_cmd $CLI_GLOBAL_NODE $cmd
				auto_set_snmp_index $wqtn_intf
			}
		}

		set wqt_intf "wqt.$vapvdom"

		set switch_node [cli_get_node $CLI_GLOBAL_NODE "system switch-interface" \"$wqt_intf\" ""]
		set cmd ""
		if { $switch_node == 0 } {
			set cmd "config system switch-interface\nedit \"$wqt_intf\"\n"
			append cmd "set vdom $vapvdom\nset type switch\nset member \"$wqtn_intf\"\n"
		} else {
			set members [cli_get_value $switch_node "" "" "member"]
			if {[lsearch $members $wqtn_intf] < 0 && [lsearch $members "\"$wqtn_intf\""] < 0} {
				set cmd "config system switch-interface\nedit \"$wqt_intf\"\n"
				append cmd "append member \"$wqtn_intf\"\n"
			}
		}
		if {$cmd ne ""} {
			append cmd "next\nend"
			cli_exec_cmd $CLI_GLOBAL_NODE $cmd
		}

		set wqt_node [cli_get_node $CLI_GLOBAL_NODE "system interface" \"$wqt_intf\" ""]
		if { $wqt_node == 0 } {
			set node [cli_get_node $vdnode "system replacemsg-group" "\"auth-intf-$wqt_intf\"" ""]
			if { $node == 0 } {
				set cmd "config system replacemsg-group\nedit \"auth-intf-$wqt_intf\"\n"
				append cmd "set comment \"This is quarantine notification replacement message for quarantine VLAN interface\"\n"
				append cmd "set group-type auth\n"
				append cmd "config auth\n"
				append cmd "edit auth-disclaimer-page-1\n"
				set htmlcmd "<!DOCTYPE html PUBLIC \\\"-//W3C//DTD HTML 4.01//EN\\\">\n<html><head><meta http-equiv=\\\"Content-Type\\\" content=\\\"text/html; charset=UTF-8\\\"><style type=\\\"text/css\\\">html,body{height:100%;padding:0;margin:0;}.oc{display:table;width:100%;height:100%;}.ic{display:table-cell;vertical-align:middle;height:100%;}form{display:block;background:#ccc;border:2px solid red;padding:0 0 25px 0;width:500px;font-family:helvetica,sans-serif;font-size:14px;margin:10px auto;}.fel,.fer,.fec{text-align:center;width:350px;margin:0 auto;padding:10px;}.fel{text-align:left;}.fer{text-align:right;}h1{font-weight:bold;font-size:21px;margin:0;padding:20px 10px;text-align:center;}p{margin:15px auto;width:75%;text-align:left;}ul{margin:15px auto;width:75%;}h2{margin:25px 10px;font-weight:bold;text-align:center;}label,h2{font-size:16px;}.logo{background:#eee center 25px url(%%IMAGE:logo_fw_auth%%) no-repeat;padding-top:80px;}</style><title>Firewall Quarantine Notification</title></head><body><div class=\\\"oc\\\"><div class=\\\"ic\\\"><form action=\\\"%%DISCLAIMER_ACT%%\\\" method=\\\"%%DISCLAIMER_METHOD%%\\\"><input type=\\\"hidden\\\" name=\\\"%%REDIRID%%\\\" value= \\\"%%PROTURI%%\\\"><input type=\\\"hidden\\\" name=\\\"%%MAGICID%%\\\" value=\\\"%%MAGICVAL%%\\\"><input type=\\\"hidden\\\" name=\\\"%%ANSWERID%%\\\" value=\\\"%%DECLINEVAL%%\\\"><h1 class=\\\"logo\\\">Quarantine Notification</h1><p>Your network access has been restricted due to detection of potentially malicious traffic. Please contact your network administrator for further information.</p><h2>Acknowledge your quarantine for limited network access.</h2><div class=\\\"fec\\\"><input type=\\\"submit\\\" value= \\\"Accept\\\" onclick=\\\"sb(\'%%AGREEVAL%%\')\\\"><input type=\\\"submit\\\" value= \\\"Decline\\\" onclick=\\\"sb(\'%%DECLINEVAL%%\')\\\"></div></form></div></div><script>function sb(val) { document.forms\[0\].%%ANSWERID%%.value = val; document.forms\[0\].submit(); }</script></body></html>"
				append cmd "set buffer \"$htmlcmd\"\n"
				append cmd "set header http\nset format html\nnext\n"
            			append cmd "edit auth-disclaimer-page-2\nset buffer ''\nset header http\nset format html\nnext\n"
            			append cmd "edit auth-disclaimer-page-3\nset buffer ''\nset header http\nset format html\nnext\n"
            			append cmd "edit auth-reject-page\n"
				set htmlcmd "<!DOCTYPE html PUBLIC \\\"-//W3C//DTD HTML 4.01//EN\\\">\n<html><head><meta http-equiv=\\\"Content-Type\\\" content=\\\"text/html; charset=UTF-8\\\"><style type=\\\"text/css\\\">html,body{height:100%;padding:0;margin:0;}.oc{display:table;width:100%;height:100%;}.ic{display:table-cell;vertical-align:middle;height:100%;}form{display:block;background:#ccc;border:2px solid red;padding:0 0 25px 0;width:500px;font-family:helvetica,sans-serif;font-size:14px;margin:10px auto;}.fel,.fer,.fec{text-align:center;width:350px;margin:0 auto;padding:10px;}.fel{text-align:left;}.fer{text-align:right;}h1{font-weight:bold;font-size:21px;margin:0;padding:20px 10px;text-align:center;}p{margin:15px auto;width:75%;text-align:left;}ul{margin:15px auto;width:75%;}h2{margin:25px 10px;font-weight:bold;text-align:center;}label,h2{font-size:16px;}.logo{background:#eee center 25px url(%%IMAGE:logo_fw_auth%%) no-repeat;padding-top:80px;}</style><title>Firewall Quarantine Declined</title></head><body><div class=\\\"oc\\\"><div class=\\\"ic\\\"><form action=\\\"/\\\" method=\\\"post\\\"><input type=\\\"hidden\\\" name=\\\"%%REDIRID%%\\\" value= \\\"%%PROTURI%%\\\"><input type=\\\"hidden\\\" name=\\\"%%MAGICID%%\\\" value=\\\"%%MAGICVAL%%\\\"><h1 class=\\\"logo\\\">Quarantine</h1><p>By failing to acknowledge the terms of Quarantine, your access may be more severely restricted until acknowledged.</p><div class=\\\"fec\\\"><input type=\\\"submit\\\" value= \\\"Return to Quarantine Notification\\\"></div></form></div></div></body></html>"
				append cmd "set buffer \"$htmlcmd\"\n"
				append cmd "set header http\nset format html\nnext\nend\n"
				append cmd "next\nend\n"
				cli_exec_cmd $vdnode $cmd
			}

			set cmd "config system interface\nedit \"$wqt_intf\"\nset vdom $vapvdom\nset type switch\n"
			append cmd "set ip 10.253.255.254 255.255.240.0\n"
 			append cmd "set description \"Quarantine Soft Switch\"\n"
 			append cmd "set security-mode captive-portal\n"
 			append cmd "set replacemsg-override-group \"auth-intf-$wqt_intf\"\n"
 			append cmd "set device-identification enable\n"
			if { [cli_obj_support "system interface" "device-identification-active-scan"] } {
 				append cmd "set device-identification-active-scan enable\n"
			}
 			append cmd "next\nend"
			cli_exec_cmd $CLI_GLOBAL_NODE $cmd
			auto_set_snmp_index $wqt_intf

			set dhcpnodes [cli_get_tbl_list $vdnode "system dhcp server"]
			set svrid 0
			foreach e $dhcpnodes {
				set eid [cli_get_value $e "" "" "id"]
				if { $eid > $svrid } {
					set svrid $eid
				}
			}
			set svrid [expr $svrid + 1]
			set cmd "config system dhcp server\n"
			append cmd "edit $svrid\nset dns-service default\nset default-gateway 10.253.255.254\nset netmask 255.255.240.0\n"
			append cmd "set interface \"$wqt_intf\"\nset timezone-option default\n"
			append cmd "config ip-range\nedit 1\nset start-ip 10.253.240.1\nset end-ip 10.253.255.253\nnext\nend\n"
			append cmd "next\nend\n"
			cli_exec_cmd $vdnode $cmd
		}
		return 1
	}
	proc cli_del_quarantine_intf { vapname vapvdom } {
                global CLI_GLOBAL_NODE

		set vapname [string trim $vapname \"]
		set vapvdom [string trim $vapvdom \"]
		set wqt_intf "wqt.$vapvdom"
		set switch_node 0
		set wqtn_intf ""
		set vdnode [cli_get_vdom_node $vapvdom]
		set nodes  [cli_get_match_list $CLI_GLOBAL_NODE 1 "system interface" "interface" 0 "\"$vapname\"" "type" 0 "vlan" "vlanid" 0 4093]
		foreach node $nodes {
			set wqtn_intf [cli_get_value $node "" "" "name"]
			set wqtn_intf [string trim $wqtn_intf \"]
			if { $wqtn_intf eq "" } { continue; }
			set switch_node [cli_get_node $CLI_GLOBAL_NODE "system switch-interface" $wqt_intf ""]
			if { $switch_node } {
				set memb [cli_get_value $switch_node "" "" "member"]
				if { $memb ne "" && [llength $memb] > 1 } {
					set cmd "config system switch-interface\nedit \"$wqt_intf\"\nunselect member \"$wqtn_intf\"\nnext\nend\n"
					cli_exec_cmd $CLI_GLOBAL_NODE $cmd
				} else {
					set dhcp_nodes [cli_get_match_list $vdnode 1 "system dhcp server" "interface" 0 "\"$wqt_intf\""]
					foreach e $dhcp_nodes {
						if { [cli_is_referenced $e] } {
							set name [cli_get_value $e "" "" "id"]
							cli_set_errmsg "dhcp server id [$name] is in use, cannot remove"
							return 0
						}
						cli_delete_node $e
					}
					cli_exec_cmd $CLI_GLOBAL_NODE "config system switch-interface\ndelete $wqt_intf\nnext\nend\n"
					cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\ndelete $wqt_intf\nnext\nend\n"
					cli_exec_cmd $vdnode  "config system replacemsg-group\ndelete auth-intf-$wqt_intf\nnext\nend\n"
				}
			}
			cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\ndelete $wqtn_intf\nnext\nend\n"
		}
		if { [cli_ver_start 600 2] && [cli_get_match_nr $vdnode 1 "wireless-controller vap" "quarantine" 0 "enable" "local-bridging" 0 "disable" "mesh-backhaul" 0 "disable"] > 0 } {
			return 1
		} elseif { ![cli_ver_start 600 2] && [cli_get_match_nr $CLI_GLOBAL_NODE 1 "wireless-controller vap" "vdom" 0 "\"$vapvdom\"" "quarantine" 0 "enable" "local-bridging" 0 "disable" "mesh-backhaul" 0 "disable"] > 0 } {
			return 1
		} elseif { [cli_ver_start 600 0] } {
			set nodes [cli_get_match_list $vdnode 1 "system dhcp server" "interface" 0 "\"$wqt_intf\""]
			foreach e $nodes {
				if { [cli_is_referenced $e] } {
					set name [cli_get_value $e "" "" "id"]
					cli_set_errmsg "dhcp server id [$name] is in use, cannot remove"
					return 0
				}
				cli_delete_node $e
			}
			cli_exec_cmd $CLI_GLOBAL_NODE "config system switch-interface\ndelete $wqt_intf\nnext\nend\n"
			cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\ndelete $wqt_intf\nnext\nend\n"
			cli_exec_cmd $vdnode  "config system replacemsg-group\ndelete auth-intf-$wqt_intf\nnext\nend\n"
		}
		return 1
	}
	proc platform_digit_suffix { plat } {
		if { $plat eq "" } {
			return 0
		}
		if { [string first "VM" $plat] != -1 || [string first "ARM64" $plat] != -1 } {
			return 0
		}
		regexp {\d+[\w-]*} $plat suffix
		return $suffix
	}
	proc platform_digit_start { plat start } {
		if { [string first "VM" $plat] != -1 || [string first "ARM64" $plat] != -1 } {
			return 0
		}
		if { [string first "VM" $start] != -1 || [string first "ARM64" $plat] != -1} {
			return 0
		}
		if { ![regexp {\d+} $plat plat_int] || ![regexp {\d+} $start start_int] } {
			return 0
		}
		if { $plat_int < $start_int } {
			return 0
		}
		return 1
	}
	proc platform_digit_between { plat start end } {
		if { [string first "VM" $plat] != -1 || [string first "ARM64" $plat] != -1} {
			return 0
		}
		if { [string first "VM" $start] != -1 || [string first "ARM64" $plat] != -1} {
			return 0
		}
		if { [string first "VM" $end] != -1 || [string first "ARM64" $plat] != -1} {
			return 0
		}
		if { ![regexp {\d+} $plat plat_int] || ![regexp {\d+} $start start_int] || ![regexp {\d+} $end end_int] } {
			return 0
		}
		if { $plat_int < $start_int } {
			return 0
		}
		if { $plat_int > $end_int } {
			return 0
		}
		return 1
	}
	proc cli_sys_global_vdom_enable { } {
		global CLI_GLOBAL_NODE
		set vdom_enable 0
		if { [cli_branchpt_start 600 787] } {
			set vdom_mode [cli_get_value $CLI_GLOBAL_NODE "system global" "" "vdom-mode"]
			if { $vdom_mode eq "multi-vdom" || $vdom_mode eq "split-vdom" } {
				set vdom_enable 1
			}
		} else {
			set vdom_enable [cli_is_match $CLI_GLOBAL_NODE 0 "system global" "vdom-admin" 0 "enable"]
		}
		return $vdom_enable
	}
	proc cli_sys_global_split_vdom { } {
		global CLI_GLOBAL_NODE
		if { [cli_branchpt_start 600 787] } {
			set vdom_mode [cli_get_value $CLI_GLOBAL_NODE "system global" "" "vdom-mode"]
			if { $vdom_mode eq "split-vdom" } {
				return 1
			}
		}
		return 0
	}
	proc fw_policy_inspection_flow { policy } {
		global CLI_CUR_VDOM_NODE
		global CLI_GLOBAL_DEV
		global CLI_CUR_PKG_NODE
		if { $CLI_GLOBAL_DEV } {
			set node $CLI_CUR_PKG_NODE
		} else {
			set node $CLI_CUR_VDOM_NODE
		}
		set fw_consolidated [cli_get_node $node "firewall consolidated policy" "" ""]
		set fw_policy [cli_get_node $node "firewall policy" "" ""]
		set fw_policy6 [cli_get_node $node "firewall policy6" "" ""]
		set fw_proxy_policy [cli_get_node $node "firewall proxy-policy" "" ""]
		set parent [cli_get_parent $policy]
		if { [cli_if_same_node $parent $fw_consolidated] } {
			return [cli_is_match $policy 0 "" "inspection-mode" 1 "proxy"]
		}
		if { [cli_if_same_node $parent $fw_policy] } {
			return [cli_is_match $policy 0 "" "inspection-mode" 1 "proxy"]
		}
		if { [cli_if_same_node $parent $fw_policy6] } {
			return [cli_is_match $policy 0 "" "inspection-mode" 1 "proxy"]
		}
		if { [cli_if_same_node $parent $fw_proxy_policy] } {
			return 0
		}
		return 1
	}
	proc fw_policy_utm_profile_type { policy } {
		global CLI_CUR_VDOM_NODE
		set fw_policy [cli_get_node $CLI_CUR_VDOM_NODE "firewall policy" "" ""]
		set parent [cli_get_parent $policy]
		if { [cli_if_same_node $parent $fw_policy] && [cli_is_match $policy 0 "" "learning-mode" 0 "enable"] } {
			return ""
		}
		if { [cli_is_match $policy 0 "" "utm-status" 0 "enable"] } {
			set action [cli_get_value $policy "" "" "action"]
			if { $action eq "accept" || $action eq "ipsec" || $action eq "isolate" } {
				return [cli_get_value $policy "" "" "profile-type"]
			}
		}
		return ""
	}

        proc policy_dstaddr_check { policy } {
		global CLI_GLOBAL_NODE
                global CLI_CUR_VDOM_NODE
		global CLI_GLOBAL_DEV
		set policyid [cli_get_value $policy "" "" "policyid"]
		set dstaddr [cli_get_value $policy "" "" "dstaddr" 1]
		set srcintf [cli_get_value $policy "" "" "srcintf" 1]

                array unset dstaddr_intf_array
                array unset dstvip_intf_array
                array unset grplist
                lappend grplist $dstaddr
                get_addr_intf $dstaddr $CLI_CUR_VDOM_NODE dstaddr_intf_array $grplist
                get_vip_intf $dstaddr $CLI_CUR_VDOM_NODE dstvip_intf_array

                if { [aps_policy_auth_identity_based $policy] } {
                        set dst "policyid: $policyid, identity-based: $policyid"
                } else {
                        set dst "policyid: $policyid"
                }
		if {[array size dstaddr_intf_array] > 0 &&
		    [array size dstvip_intf_array] > 0} {
			return "dstaddr($dstaddr) can not multiple use addr/adrgrp and vip/vipgrp ($dst)"
		}

		if { !$CLI_GLOBAL_DEV } {
			set src_intf_list [list]
			foreach s $srcintf {
				set intf [cli_get_node $CLI_GLOBAL_NODE "system interface" $s ""]
				set zone [cli_get_node $CLI_CUR_VDOM_NODE "system zone" $s ""]
				set sdwan [is_sdwan_zone $s]

				if { $intf != 0 } {
					lappend src_intf_list $s
				} elseif { $zone != 0 } {
					set zoneintfs [cli_get_value $CLI_CUR_VDOM_NODE "system zone" $s "interface"]
					set src_intf_list [concat $src_intf_list $zoneintfs]
				} elseif { $sdwan != 0 } {
					set src_intf_list [concat $src_intf_list [get_sdwan_intf $s]]
				}
			}

			if { [array size dstvip_intf_array] > 0 } {
				foreach key [array names dstvip_intf_array] {
					if { $key eq "any" } {
						continue
					} elseif { [lsearch -exact $src_intf_list $key] < 0 } {
						return "policy dstaddr's vip/vipgrp interface $key not found from policy srcintf"
					}
				}
			}
		}

                return 0
        }
	proc policy_addr_intf_check { policy } {
		set policyid [cli_get_value $policy "" "" "policyid"]
		set srcaddr [cli_get_value $policy "" "" "srcaddr" 1]
		set o_srcaddr [cli_get_org_value $policy "" "" "srcaddr" 1]
		set srcintf [cli_get_value $policy "" "" "srcintf" 1]
		set o_srcintf [cli_get_org_value $policy "" "" "srcintf" 1]
		set dstaddr [cli_get_value $policy "" "" "dstaddr" 1]
		set o_dstaddr [cli_get_org_value $policy "" "" "dstaddr" 1]
		set dstintf [cli_get_value $policy "" "" "dstintf" 1]
		set o_dstintf [cli_get_org_value $policy "" "" "dstintf" 1]
		if { $srcaddr eq $o_srcaddr && $srcintf eq $o_srcintf && $dstaddr eq $o_dstaddr && $dstintf eq $o_dstintf } {
			return 1
		}

		if { [cli_ver_start 500 2] } {
			set msg [policy_dstaddr_check $policy]
			if { $msg ne 0 } {
				cli_set_errmsg $msg
				return 0
			}
		} elseif { [cli_ver_start 500 0] } {
			if { [fw_dstaddr_visible $policy] } {
				set msg [intf_binding_contradiction $srcaddr $dstaddr $srcintf $dstintf $policyid 0 0]
				if { $msg ne 0 } {
					cli_set_errmsg $msg
					return 0
				}
			} else {
				set idp [cli_get_value $policy "" "" "identity-based"]
				set action [cli_get_value $policy "" "" "action"]
				if { $action eq "accept" && $idp eq "enable"} {
					if { [string match "*script*" [cli_get_clisrc]] } {
						set ibp_list [cli_get_tbl_list $policy "identity-based-policy"]
						foreach ibp $ibp_list {
							set id [cli_get_value $ibp "" "" "id"]
							set msg [intf_binding_contradiction $srcaddr $dstaddr $srcintf $dstintf $policyid $id 0]
							if { $msg ne 0 } {
								cli_set_errmsg $msg
								return 0
							}
						}
					}
				}
			}
		}
		return 1
	}
	proc check_obj_tagging { node } {
		global CLI_CUR_VDOM_NODE

		set cate [cli_get_value $node "" "" "category"]
		set tags [cli_get_value $node "" "" "tags" 1]
		set catenode [cli_get_node $CLI_CUR_VDOM_NODE "system object-tagging" $cate ""]
		if { $catenode eq 0 } {
			cli_set_errmsg "invalid tagging category $cate"
			return 0
		}
		set newtags [lsort -unique $tags]
		if { [llength $newtags] ne [llength $tags] } {
			cli_set_errmsg "duplicated tags"
			return 0
		}
		set multi [cli_get_value $catenode "" "" "multiple"]
		if { $multi ne "enable" && [llength $tags] > 1 } {
			cli_set_errmsg "multiple tags not allowed for category $cate"
			return 0
		}
		set ctags [cli_get_value $catenode "" "" "tags" 1]
		foreach t $tags {
			if { [lsearch -exact $ctags $t] == -1 } {
				cli_set_errmsg "invalid tag $t"
				return 0
			}
		}
		return 1
	}
	proc fix_datetime_format { expiry } {
		set dt ""
		regexp {((\d+)d)?((\d+)h)?((\d+)m)?} $expiry matched dummy1 day dummy2 hr dummy3 min
		regsub {^[0]*} $day {\1} day
		if { $day != "" } {
			set dt ${dt}${day}d
		}
		regsub {^[0]*} $hr {\1} hr
		if { $hr != "" } {
			set dt ${dt}${hr}h
		}
		regsub {^[0]*} $min {\1} min
		if { $min != "" } {
			set dt ${dt}${min}m
		}
		return $dt
	}
	proc phase1_unset_proposal { ikever } {
		set defval ""
		if {[cli_get_devinfo "LENC"] eq "yes"} {
			append defval " 3des-md5"
			if {[cli_get_devinfo "FIPS"] eq "yes"} {
				append defval " 3des-sha256"
			} else {
				append defval " 3des-sha1"
			}
		} else {
			append defval " aes128-sha256 aes256-sha256"
			if {[cli_get_devinfo "FIPS"] eq "yes"} {
			} else {
				if { $ikever eq "1" } {
					if { [cli_branchpt_start 600 120] } {
						append defval " aes128-sha1 aes256-sha1"
					} else {
						append defval " 3des-sha256 aes128-sha1 aes256-sha1 3des-sha1"
					}
				} else {
					if { [cli_branchpt_start 600 120] } {
						append defval " aes128gcm-prfsha256 aes256gcm-prfsha384 chacha20poly1305-prfsha256"
					} else {
						append defval " 3des-sha256 aes128-sha1 aes256-sha1 3des-sha1"
					}
				}
			}
		}
		return [string trim $defval]
	}
	proc phase2_unset_proposal { } {
		set defval ""
		if {[cli_get_devinfo "LENC"] eq "yes"} {
			append defval " 3des-md5"
			if {[cli_get_devinfo "FIPS"] eq "yes"} {
				append defval " 3des-sha256"
			} else {
				append defval " 3des-sha1"
			}
		} else {
			append defval " aes128-sha256 aes256-sha256"
			if {[cli_get_devinfo "FIPS"] eq "yes"} {
			} else {
				append defval " aes128-sha1 aes256-sha1"
				if { [cli_branchpt_start 600 120] } {
					append defval " aes128gcm aes256gcm chacha20poly1305"
				} else {
					append defval " 3des-sha256 3des-sha1"
				}
			}
		}
		return [string trim $defval]
	}
	proc sys_intf_is_media_iface { intf_name } {
		set port_num ""
		regexp {\d+} $intf_name port_num
		set plat_name [cli_get_devinfo "platform"]
		set plat_suff [platform_digit_suffix $plat_name]
		if { $port_num ne "" && [string match "port$port_num" $intf_name] } {
			set iface_begin 0
			set iface_end 0
			set iface_begin2 0
			set iface_end2 0
			if { [lsearch {"1000D" "900D"} $plat_suff] >= 0 } {
				set iface_begin 1
				set iface_end 8
				set iface_begin2 17
				set iface_end2 24
			} elseif { [lsearch {"1100E" "1101E"} $plat_suff] >= 0 } {
				set iface_begin 29
				set iface_end 32
			} elseif { [lsearch {"1200D" "1500D" "1500DT"} $plat_suff] >= 0 } {
				set iface_begin 1
				set iface_end 16
			} elseif { [lsearch {"200E" "201E"} $plat_suff] >= 0 } {
				set iface_begin 15
				set iface_end 18
			} elseif { [lsearch {"2200E" "2201E"} $plat_suff] >= 0 } {
				set iface_begin 13
				set iface_end 28
			} elseif { [lsearch {"300D"} $plat_suff] >= 0 } {
				set iface_begin 5
				set iface_end 8
			} elseif { [lsearch {"3300E" "3301E"} $plat_suff] >= 0 } {
				set iface_begin 17
				set iface_end 30
			} elseif { [lsearch {"3400E" "3401E"} $plat_suff] >= 0 } {
				set iface_begin 1
				set iface_end 26
			} elseif { [lsearch {"3600E" "3601E"} $plat_suff] >= 0 } {
				set iface_begin 1
				set iface_end 36
			} elseif { [lsearch {"3800D" "3815D"} $plat_suff] >= 0 } {
				set iface_begin 1
				set iface_end 4
			} elseif { [lsearch {"3810D"} $plat_suff] >= 0 } {
				set iface_begin 1
				set iface_end 6
			} elseif { [lsearch {"3960E"} $plat_suff] >= 0 } {
				set iface_begin 17
				set iface_end 22
			} elseif { [lsearch {"3980E"} $plat_suff] >= 0 } {
				set iface_begin 17
				set iface_end 26
			} elseif { [lsearch {"400D" "500D" "600D"} $plat_suff] >= 0 } {
				set iface_begin 1
				set iface_end 8
			} elseif { [lsearch {"3600E" "3601E"} $plat_suff] >= 0 } {
				set iface_begin 1
				set iface_end 36
			} elseif { [lsearch {"3400E" "3401E"} $plat_suff] >= 0 } {
				set iface_begin 1
				set iface_end 26
			} elseif { [lsearch {"1100E" "1101E"} $plat_suff] >= 0 } {
				set iface_begin 29
				set iface_end 32
			} elseif { [lsearch {"1800F" "1801F"} $plat_suff] >= 0 } {
				if { [cli_ver_start 600 2] } {
					set iface_begin 25
					set iface_end 40
				} else {
					set iface_begin 25
					set iface_end 36
				}
			} elseif { [lsearch {"2600F" "2601F"} $plat_suff] >= 0 } {
				set iface_begin 17
				set iface_end 36
			} elseif { [lsearch {"3000F" "3001F"} $plat_suff] >= 0 } {
				set iface_begin 17
				set iface_end 36
			} elseif { [lsearch {"3500F" "3501F"} $plat_suff] >= 0 } {
				set iface_begin 1
				set iface_end 36
			} elseif { [lsearch {"4200F" "4201F"} $plat_suff] >= 0 } {
				set iface_begin 1
				set iface_end 24
			} elseif { [lsearch {"4400F" "4401F"} $plat_suff] >= 0 } {
				set iface_begin 1
				set iface_end 28
 			}
			if { $iface_begin && $port_num >= $iface_begin && $port_num <= $iface_end } {
				return 1
			}
			if { $iface_begin2 && $port_num >= $iface_begin2 && $port_num <= $iface_end2 } {
				return 1
			}
		} elseif { $intf_name eq "ha1" || $intf_name eq "ha2" } {
			if { [lsearch {"3400E" "3401E" "3600E" "3601E" "4200F" "4201F" "4400F" "4401F"} $plat_suff] >= 0 } {
				return 1
			}
		} elseif { $intf_name eq "aux1" || $intf_name eq "aux2" } {
			if { [lsearch {"4200F" "4201F" "4400F" "4401F"} $plat_suff] >= 0 } {
				return 1
			}
		}
		return 0
	}

	proc ncfg_is_user_group_used_by_vap { is_v62 root_node vdom_name group_name } {
		set nodelist [cli_get_tbl_list $root_node "wireless-controller vap"]
		foreach node $nodelist {
			if { $is_v62 == 0 } {
				set vap_vdom [cli_get_value $node "" "" "vdom"]
				set vap_vdom [string trim $vap_vdom \"]
				if { $vap_vdom ne $vdom_name } {
					continue
				}
			}
			set auth [cli_get_value $node "" "" "radius-mac-auth"]
			if { $auth ne "enable" } {
				continue
			}
			set grps [cli_get_value $node "" "" "radius-mac-auth-usergroups" 1]
			if { $grps eq "" || [llength $grps] < 1 } {
				continue
			}
			foreach grp $grps {
				set grp [string trim $grp \"]
				if { $grp eq $group_name } {
					return 1
				}
			}
		}
		return 0
	}

	proc wireless_controller_tunnel_vap_valid { prof_node prof_name radio } {
		global CLI_CUR_VDOM_NODE
		global CLI_GLOBAL_NODE
		if { $radio eq "radio-1" } {
			if { [cli_get_value $prof_node $radio "" "mode"] eq "disabled" } {
				return 1
			}
		} elseif { $radio eq "radio-2" } {
			set type [cli_get_value $prof_node "platform" "" "type"]
			if { [cli_get_devinfo "pm2_wl_radio_enabled" "2" $type] eq "no" } {
				return 1
			}
			if { [cli_get_value $prof_node $radio "" "mode"] eq "disabled" } {
				return 1
			}
		}
		set vap_all [cli_get_value $prof_node $radio "" "vap-all"]
		if { $vap_all eq "enable" } {
			cli_set_errmsg "Cannot set WTP remote mode due to Auto SSID enabled in wtp-profile, \"$prof_name\", $radio "
			return 0
		} else {
			set is_v62 [cli_ver_start 600 2]
			set vaps [cli_get_value $prof_node $radio "" "vaps"]
			foreach vap $vaps {
				set vap [string trim $vap \"]
				if { $is_v62 } {
					set vap_node [cli_get_node $CLI_CUR_VDOM_NODE "wireless-controller vap" $vap ""]
				} else {
					set vap_node [cli_get_node $CLI_GLOBAL_NODE "wireless-controller vap" $vap ""]
				}
				if { $vap_node } {
					set m [cli_get_value $vap_node "" "" "mesh-backhaul"]
					set b [cli_get_value $vap_node "" "" "local-bridging"]
					if { $m eq "disable" && $b eq "disable" } {
						cli_set_errmsg "Cannot set WTP remote mode due to a tunnel SSID, \"$vap\", used in wtp-profile, \"$prof_name\", $radio"
						return 0
					}
				}
			}
		}
		return 1
	}
	proc wireless_controller_wtp_mode_valid { mode prof_name } {
		global CLI_CUR_VDOM_NODE
		if { $mode ne "remote" || $prof_name eq "" } {
			return 1
		}
		set prof_name [string trim $prof_name \"]
		set prof_node [cli_get_node $CLI_CUR_VDOM_NODE "wireless-controller wtp-profile" $prof_name ""]
		if { !$prof_node } {
			return 1
		}
		if { ![wireless_controller_tunnel_vap_valid $prof_node $prof_name "radio-1"] } {
			return 0
		}
		if { ![wireless_controller_tunnel_vap_valid $prof_node $prof_name "radio-2"] } {
			return 0
		}
		return 1
	}

	proc sys_intf_fec_media_speed_key { ifname mediatype speed } {
		set split ""
		if { [string first / $ifname ] != -1 } {
			set split "4x"
		}
		set speed_num ""
		if { [regexp -nocase {400Gfull|400Gauto} $speed] } {
			set speed_num "400G"
		} elseif { [regexp -nocase {100Gfull|100Gauto} $speed] } {
			set speed_num "100G"
		} elseif { [regexp -nocase {40000full|40000auto} $speed] } {
			set speed_num "40G"
		} elseif { [regexp -nocase {25000full|25000auto} $speed] } {
			set speed_num "25G"
		} elseif { [regexp -nocase {10000full|10000auto} $speed] } {
			set speed_num "10G"
		}
		return "$mediatype|$split$speed_num|"
	}

	proc sys_intf_forward_error_correction_option_7000f { ifname mediatype speed } {
		# the combination of interface type, media type and speed refers to 716714
		set opts "disable"
		set port [regexp -inline -nocase {\-\w\d+} $ifname]
		set port_group [regexp -inline -nocase {\w} $port]
		set port_num [regexp -inline -nocase {\d+} $port]
		set media_speed [sys_intf_fec_media_speed_key $ifname $mediatype $speed]

		set M1_M2_fecs [ list "qsfp+|sr|4x10G|" "qsfp+|sr|40G|base-r-fec" "qsfp+|cr|40G|" "qsfp+|lr|40G|" "qsfp28|sr|100G|rs-fec" "qsfp28|sr|4x25G|base-r-fec rs-fec" "qsfp28|sr|4x10G|" "qsfp28|cr|4x25G|base-r-fec rs-fec" "qsfp28|cr|4x10G|" "qsfp28|cr|100G|rs-fec" "qsfp28|lr|100G|base-r-fec" ]
		set M3_M4_fecs [ list "sfp+|sr|10G|base-r-fec" "sfp+|lr|10G|base-r-fec" "sfp+|cr|10G|base-r-fec" "sfp28|sr|25G|rs-fec" "sfp28|cr|25G|base-r-fec rs-fec" "sfp28|lr|25G|rs-fec" ]
		set P1_P18_fecs [ list "qsfp+|sr|40G|base-r-fec" "qsfp+|sr|4x10G|" "qsfp+|cr|40G|base-r-fec" "qsfp+|lr|40G|base-r-fec" "qsfp28|sr|100G|rs-fec" "qsfp28|sr|4x25G|base-r-fec rs-fec" "qsfp28|sr|4x10G|" "qsfp28|cr|100G|rs-fec" "qsfp28|cr|4x25G|base-r-fec rs-fec" "qsfp28|lr|100G|rs-fec" ]
		set P19_P20_fecs [ list "qsfp+|sr|40G|" "qsfp+|cr|40G|" "qsfp+|lr|40G|" "qsfp28|sr|100G|rs-fec" "qsfp28|sr|4x25G|rs-fec" "qsfp28|sr|4x100G|" "qsfp28|cr|100G|base-r-fec" "qsfp28|cr|4x25G|base-r-fec rs-fec" "qsfp28|cr|4x10G|" "qsfp28|lr|100G|" "qsfp-dd|sr|400G|rs-544" "qsfp-dd|lr|400G|rs-544" "qsfp-dd|cr|400G|rs-544" ]

		set select_fecs ""
		if { $port_group eq "P" && ( $port_num >= 1 && $port_num <= 18 ) } {
			set select_fecs $P1_P18_fecs
		} elseif { $port_group eq "P" && ( $port_num >= 19 && $port_num <= 20 ) } {
			set select_fecs $P19_P20_fecs
		} elseif { $port_group == "M" && ( $port_num >= 1 && $port_num <= 2 ) } {
			set select_fecs $M1_M2_fecs
		} elseif { $port_group == "M" && ( $port_num >= 3 && $port_num <= 4 ) } {
			set select_fecs $M3_M4_fecs
		}
		if { $select_fecs ne "" } {
			foreach item $select_fecs {
				if { [string first $media_speed $item ] != -1 } {
					append opts " " [lindex [ split $item "|" ] 3 ]
					break
				}
			}
		}
		return $opts
	}

	proc sys_intf_forward_error_correction_option { list platform ifname mediatype speed } {
		upvar $list option

		if { [regexp -nocase {7000F} $platform] } {
			set option [sys_intf_forward_error_correction_option_7000f $ifname $mediatype $speed ]
			if { [llength $option] > 0 } {
				return 1
			}
			return 0
		}

		set iftype ""
		if { [string match -nocase $platform "FortiGate-6000F"] || [string match -nocase $platform "FortiCarrier-6000F"] } {
			regexp {\d+} $ifname port_num
			if { $port_num && [string match "port$port_num" $ifname] } {
				if { $port_num >= 1 && $port_num <= 24 } {
					set iftype "SFP28"
				} elseif { $port_num >= 25 && $port_num <= 28 } {
					set iftype "QSFP28"
				}
			}
		} elseif { [string match -nocase $platform "FortiGate-7000E"] || [string match -nocase $platform "FortiCarrier-7000E"] } {
			set module_sn [cli_get_devinfo "module_serial"]
			if { [string first "FIM20E" $module_sn] == 0 } {
				regexp {\d+} $ifname port_num
				if { $port_num && [string match "C$port_num" $ifname] } {
					if { $port_num >= 1 && $port_num <= 8 } {
						set iftype "QSFP28"
					}
				}
			}
			lappend option "disable"
			lappend option "enable"

			return 1
		}
		if { $iftype eq "SFP28" } {
			if { ($mediatype eq "cr") && ($speed eq "1000auto" || $speed eq "1000full" || $speed eq "10000auto" || $speed eq "10000full") } {
				lappend option "disable"
			} elseif { ($mediatype eq "cr") && ($speed eq "25000auto" || $speed eq "25000full") } {
				lappend option "base-r-fec"
				lappend option "rs-fec"
				lappend option "disable"
			} elseif { ($mediatype eq "lr") && ($speed eq "1000full" || $speed eq "10000full" || $speed eq "25000full") } {
				lappend option "disable"
			} elseif { ($mediatype eq "sr") && ($speed eq "1000full" || $speed eq "10000full") } {
				lappend option "disable"
			} elseif { ($mediatype eq "sr") && ($speed eq "25000full") } {
				lappend option "rs-fec"
				lappend option "disable"
			}
		} elseif { $iftype eq "QSFP28" } {
			if { ($mediatype eq "cr") && ($speed eq "40000auto" || $speed eq "40000full") } {
				lappend option "disable"
			} elseif { ($mediatype eq "cr") && ($speed eq "100Gauto" || $speed eq "100Gfull") } {
				lappend option "rs-fec"
				lappend option "disable"
			} elseif { ($mediatype eq "sr") && ($speed eq "40000full") } {
				lappend option "disable"
			} elseif { ($mediatype eq "sr") && ($speed eq "100Gfull") } {
				lappend option "rs-fec"
				lappend option "disable"
			} elseif { ($mediatype eq "lr") && ($speed eq "40000full" || $speed eq "100Gfull") } {
				lappend option "disable"
			}
		}
		if { [llength $option] > 0 } {
			return 1
		}
		return 0
	}
	proc is_carrier_platform { } {
		set platform [cli_get_devinfo "platform"]
		if { [string first "FortiCarrier" $platform] == 0 } {
			return 1
		}
		return 0
	}
	proc fw_policy_mms_enabled { policy } {
		if { [is_carrier_platform]  } {
			set mms_prof [cli_get_value $policy "" "" "mms-profile"]
			if { $mms_prof ne "" } {
				return 1
			}
			return 0
		}
		return 0
	}
	proc find_zone_by_phase1intf { vdom_node ph1intf } {
		set ret 0
		set zone_list [cli_get_tbl_list $vdom_node "system zone"]
		foreach zone $zone_list {
			set intfs [cli_get_value $zone "" "" "interface"]
			if { [lsearch $intfs $ph1intf] >= 0} {
				set ret $zone
				break
			}
		}
		return $ret
	}
	proc fsso_local_agent_skip { } {
		global CLI_CUR_PARENT_NODE
		set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
		set server [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server"]
		if { $name eq "Local FSSO Agent" ||
			$name eq "\"Local FSSO Agent\"" ||
			[string match -nocase $server "localhost"] ||
			[string match -nocase $server "\"localhost\""] ||
			$server eq "127.0.0.1" ||
			$server eq "\"127.0.0.1\""} {
			return 1
		}
		return 0
	}
	proc wtp_profile_platform { prof_node } {
		set plat [cli_get_value $prof_node "platform" "" "type"]
		if { $plat eq "" } {
			if { [cli_branchpt_start 600 1051] } {
				set plat "221E"
			} else {
				set plat "220B"
			}
		}
		return $plat
	}
	proc set_rep_dst { policy } {
		set rp_min [cli_get_value $policy "" "" "reputation-minimum"]
		if {$rp_min > 0} {
			set rp_dir [cli_get_value $policy "" "" "reputation-direction"]
			if {$rp_dir eq "destination"} {
				return 1
			}
		}
		return 0
	}
	proc set_rep_src { policy } {
		set rp_min [cli_get_value $policy "" "" "reputation-minimum"]
		if {$rp_min > 0} {
			set rp_dir [cli_get_value $policy "" "" "reputation-direction"]
			if {$rp_dir eq "source"} {
				return 1
			}
		}
		return 0
	}
	proc check_ip_any_or_all { ip name type } {
		if { $type eq 4 } {
			if { $ip eq "0.0.0.0" || $ip eq "255.255.255.255"} {
				cli_set_errmsg "$name IP cannot start with 0.0.0.0 or 255.255.255.255"
				return 1
			}
		} elseif { $type eq 6 } {
			if { $ip eq "::" || $ip eq "0::0" || $ip eq "ff:ff:ff:ff:ff:ff:ff:ff"} {
				cli_set_errmsg "$name IP cannot start with 0::0 or FF:FF:FF:FF:FF:FF:FF:FF"
				return 1
			}
		}
		return 0
	}
	proc sys_sdn_conn_attr_visible { type attr } {
		if { $type eq "alicloud" } {
			set alist {access-key secret-key region}
		} elseif { $type eq "aws" } {
			set alist {access-key secret-key region vpc-id use-metadata-iam}
			if { [cli_branchpt_start 700 270] } {
				lappend alist "external-account-list"
			}
		} elseif { $type eq "azure" } {
			set alist {ha-status use-metadata-iam tenant-id client-id client-secret subscription-id resource-group azure-region nic route-table}
		} elseif { $type eq "oci" } {
			set alist {ha-status use-metadata-iam tenant-id oci-region-type user-id oci-region compartment-id oci-cert oci-fingerprint}
		} elseif { $type eq "gcp" } {
			set alist {ha-status use-metadata-iam external-ip route gcp-project private-key service-account key-passwd}
			if { [cli_branchpt_start 700 261] ||
			     (![cli_ver_start 700 0] && [cli_branchpt_start 600 1902]) } {
				set alist [lreplace $alist 4 4]
				lappend alist "gcp-project-list"
			}
		} elseif { $type eq "openstack" } {
			set alist {username password server domain}
			if { [cli_branchpt_start 700 116] } {
				lappend alist "verify-certificate"
			}
		} elseif { $type eq "kubernetes" } {
			set alist {server server-port secret-token}
			if { [cli_branchpt_start 700 116] } {
				lappend alist "verify-certificate"
			}
		} elseif { $type eq "vmware" } {
			set alist {username password server}
			if { [cli_branchpt_start 700 116] } {
				lappend alist "verify-certificate"
			}
		} elseif { $type eq "sepm" } {
			set alist {username password server server-port domain group-name}
		} elseif { $type eq "nsx" } {
			set alist {username password server}
			if { [cli_branchpt_start 600 1606] } {
				lappend alist "vcenter-server" "vcenter-username" "vcenter-password"
			}
			if { [cli_branchpt_start 700 18] } {
				lappend alist rest-interface rest-sport rest-password rest-ssl vmx-service-name vmx-image-url nsx-cert-fingerprint
			}
			if { [cli_branchpt_start 700 116] } {
				lappend alist "verify-certificate"
			}
		} elseif { $type eq "aci-direct" } {
			set alist {username password server}
			if { [cli_branchpt_start 600 1796] } {
				set alist [lreplace $alist 2 2]
				lappend alist "server-list"
			}
			if { [cli_branchpt_start 700 116] } {
				lappend alist "verify-certificate"
			}
		} elseif { $type eq "ibm" } {
			set alist {api-key compute-generation ibm-region}
		} elseif { $type eq "nutanix" } {
			set alist {username password server server-port}
			if { [cli_branchpt_start 700 116] } {
				lappend alist "verify-certificate"
			}
		} elseif { $type eq "sap" } {
			set alist {username password server server-port verify-certificate}
		} elseif { $type eq "aci" } {
			set alist {username password server server-port}
			if { [cli_branchpt_start 700 259] || 
			     (![cli_ver_start 700 0] && [cli_branchpt_start 600 1945]) } {
				set alist [lreplace $alist 2 2]
				lappend alist "server-list"
			}
		} elseif { $type eq "nuage" } {
			set alist {username password server server-port}
			if { [cli_branchpt_start 700 259] || 
			     (![cli_ver_start 700 0] && [cli_branchpt_start 600 1945]) } {
				set alist [lreplace $alist 2 2]
				lappend alist "server-list"
			}
		} else {
			set alist {username password server server-port}
		}
		if { [lsearch $alist $attr] != -1 } {
			return 1
		}
		return 0
	}
	proc intf_used_by_composite { name } {
		global CLI_GLOBAL_NODE
		set agglist [cli_get_match_list $CLI_GLOBAL_NODE 1 "system interface" "type" 0 "aggregate"]
		foreach intf $agglist {
			set memb [cli_get_value $intf "" "" "member"]
			foreach m $memb {
				if { $name eq [string trim $m \"] } {
					return 1
				}
			}
		}
		set switchlist [cli_get_tbl_list $CLI_GLOBAL_NODE "system switch-interface"]
		foreach intf $switchlist {
			set memb [cli_get_value $intf "" "" "member"]
			foreach m $memb {
				if { $name eq [string trim $m \"] } {
					return 1
				}
			}
		}
		return 0
	}
	proc ha_mgmt_intf_check { intf } {
		global CLI_GLOBAL_NODE
		global CLI_CUR_NODE
		set ha_only [cli_get_value $CLI_CUR_NODE "" "" "ha-mgmt-intf-only"]
		set ha [cli_get_node $CLI_GLOBAL_NODE "system ha" "" ""]
		set mgmt_intf [cli_get_tbl_list $ha "ha-mgmt-interfaces"]
		set intf [string map {"\"" ""} $intf]
		if { $ha_only eq "enable" && $intf ne "any" } {
			set found 0
			foreach i $mgmt_intf {
				set name [cli_get_value $i  "" "" "interface"]
				set name [string map {"\"" ""} $name]
				if { $name eq $intf } {
					set found 1
				}
			}
			if { $found == 0 } {
				cli_set_errmsg "Interface must be an HA managed interface or \"any\""
				return 0
			}
		}
		return 1
	}
    proc intf_dedicated_to_mgmt { } {
        global CLI_GLOBAL_NODE
		global CLI_CUR_NODE
		set intfs [cli_get_value $CLI_CUR_NODE "" "" ""]
		foreach intf $intfs {
			set d [cli_get_value $CLI_GLOBAL_NODE "system interface" $intf "dedicated-to"]
			if { $d eq "management" } {
				cli_set_errmsg "$intf cannot be assigned because it is a dedicated management port"
				return 1
			}
		}
		return 0
	}
	proc get_intf_speed_group { plat intf } {
		set suffix [platform_digit_suffix $plat]
		if { [regexp -nocase {1100E|1101E} $suffix] } {
			set groups [ list "port25 port26 port27 port28" "port29 port30 port31 port32" ]
		} elseif { [regexp -nocase {1800F|1801F} $suffix] } {
			set groups [ list "port25 port26 port27 port28" "port29 port30 port31 port32" "port33 port34 port35 port36" "port37" "port38" "port39" "port40" ]
		} elseif { [regexp -nocase {2200E|2201E} $suffix] } {
			set groups [ list "port13 port14 port15 port16" "port17 port18 port19 port20" "port21 port22 port23 port24" "port25 port26 port27 port28" ]
		} elseif { [regexp -nocase {2600F|2601F} $suffix] } {
			set groups [ list "port17 port18 port19 port20" "port21 port22 port23 port24" "port25 port26 port27 port28" "port29 port30 port31 port32" ]
		} elseif { [regexp -nocase {3300E|3301E} $suffix] } {
			set groups [ list "port17 port18 port19 port20" "port21 port22 port23 port24" "port25 port26 port27 port28" ]
		} elseif { [regexp -nocase {3400E|3401E} $suffix] } {
			set groups [ list "port1 port2 ha1 ha2" "port3 port4 port5 port6" "port7 port8 port9 port10" "port11 port12 port13 port14" "port15 port16 port17 port18" "port19 port20 port21 port22" ]
		} elseif { [regexp -nocase {3500F|3501F} $suffix] } {
			set groups [ list "port1 port2 ha1 ha2" "port3 port4 port5 port6" "port7 port8 port9 port10" "port11 port12 port13 port14" "port15 port16 port17 port18" "port19 port20 port21 port22" "port23 port24 port25 port26" "port27 port28 port29 port30" ]
		} elseif { [regexp -nocase {3600E|3601E} $suffix] } {
			set groups [ list "port1 port2 ha1 ha2" "port3 port4 port5 port6" "port7 port8 port9 port10" "port11 port12 port13 port14" "port15 port16 port17 port18" "port19 port20 port21 port22" "port23 port24 port25 port26" "port27 port28 port29 port30" ]
		} elseif { [regexp -nocase {4200F|4201F} $suffix] } {
			set groups [ list "ha1 ha2 aux1 aux2" "port1 port2 port3 port4" "port5 port6 port7 port8" "port9 port10 port11 port12" "port13 port14 port15 port16" ]
		} elseif { [regexp -nocase {4400F|4401F} $suffix] } {
			set groups [ list "ha1 ha2 aux1 aux2" "port1 port2 port3 port4" "port5 port6 port7 port8" "port9 port10 port11 port12" "port13 port14 port15 port16" ]
		} else {
			return ""
		}
		foreach group $groups {
			set ports [split $group " "]
			if { [lsearch $ports $intf] != -1 } {
				return $ports
			}
		}
		return ""
	}
	proc deep_inspection_check { parent attr } {
		if { $attr ne "server-cert-mode" && [cli_ver_start 600 2] } {
			set node [cli_get_parent $parent]
			set certmode [cli_get_value $node "" "" "server-cert-mode"]
			if { $certmode eq "replace" } {
				return 0
			}
		}
		set ssl [cli_get_node $parent "ssl" "" ""]
		if { $ssl eq 0 } {
			set ins [cli_get_defvalue "firewall ssl-ssh-profile ssl" "inspect-all"]
		} else {
			set ins [cli_get_value $ssl "" "" "inspect-all"]
		}
		if { $ins eq "disable" } {
			set di { "ssl" "https" "ftps" "imaps" "pop3s" "smtps" "ssh" }
			foreach d $di {
				set ssl [cli_get_node $parent $d "" ""]
				set sta [cli_get_value $ssl "" "" "status"]
				if { $d eq "https" || $d eq "imaps" || $d eq "smtps" || $d eq "pop3s" || $d eq "ftps" } {
					if { $sta eq "deep-inspection" } {
						return 1
					}
				}
			}
		} elseif { $ins eq "deep-inspection" } {
			return 1
		}
		return 0
	}
	proc is_platform_support_hyperscale { } {
		global CLI_GLOBAL_DEV
		if { $CLI_GLOBAL_DEV } {
			return 0
		}
		set suffix [platform_digit_suffix [cli_get_devinfo "platform"]]
		if { [regexp -nocase {1800F|1801F|2600F|2601F|3000F|3001F|3500F|3501F|4200F|4201F|4400F|4401F} $suffix] } {
			return 1
		}
		return 0
	}
	proc valid_router_community_name { name } {
		if { [regexp -nocase {\d+:\d+} $name] == 1 } {
			set nums [split $name ":"]
			foreach num $nums {
				if { $num < 0 || $num > 65535 } {
					return 0
				}
			}
			return 1
		}
		if { [regexp -nocase {\d+} $name] == 1 } {
			if { $name < 0 || $name > 65535 } {
				return 0
			}
			return 1
		}
		set known_names {"internet" "local-AS" "no-advertise" "no-export" "none"}
		if { [lsearch $known_names $name] >= 0 } {
			return 1
		}
		return 0
	}
	proc if_skip_in_global_context_and_ngfw {} {
		global CLI_CUR_PARENT_NODE
		global CLI_GLOBAL_NODE
		if { [cli_sys_global_vdom_enable] && [cli_get_parent $CLI_CUR_PARENT_NODE] == $CLI_GLOBAL_NODE } {
			return 0
		}
		if { [nCfg_get_ngfw_mode] ne "policy-based" } {
			return 0
		}
		return 1
	}
	proc wildcard_fqdn_check { addrs atype proxy} {
		global CLI_CUR_VDOM_NODE
		global CLI_CUR_NODE

		foreach addr $addrs {
			set grpnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp" $addr ""]
			if { $grpnode ne 0 } {
				set members [cli_get_value $grpnode "" "" "member" 1]
			} else {
				set members { }
				lappend members $addr
			}
			foreach m $members {
				set fqdn [cli_get_value $CLI_CUR_VDOM_NODE "firewall address" $m "wildcard-fqdn"]
				set type [cli_get_value $CLI_CUR_VDOM_NODE "firewall address" $m "type"]
				if { $fqdn ne "" && ($type eq "" || $type eq "wildcard-fqdn") } {
					if { $atype eq "dst" && $proxy eq 1 } {
						if { [cli_branchpt_start 600 1010] } {
							cli_set_errmsg "Cannot use wildcard FQDN type firewall address \"$m\""
							return 1
						} else {
							set ptype [cli_get_value $CLI_CUR_NODE "" "" "proxy"]
							if { $ptype ne "explicit-web" && $ptype ne "transparent-web" } {
									cli_set_errmsg "Cannot use wildcard FQDN type firewall address \"$m\""
									return 1
							}
						}
					} else {
						cli_set_errmsg "Cannot use wildcard FQDN type firewall address \"$m\""
						return 1
					}
				}
			}
		}
		return 0
	}
	proc is_zone_member { intf_name } {
		global CLI_CUR_VDOM_NODE
		set zonelist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "system zone"]
		set intf_name [string trim $intf_name "\""]
		foreach zone $zonelist {
			set intfs [cli_get_value $zone "" "" "interface"]
			if { [lsearch $intfs $intf_name] >= 0} {
				return 1
			}
		}
		return 0
	}
	proc remove_auto_created_vdom_objs {} {
		global CLI_CUR_VDOM_NODE
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall address\nedit \"SSLVPN_TUNNEL_ADDR1\"\nunset associated-interface\nnext\nend\n"
		return 0
	}
	proc remove_sys_admin_gui_dashboard { vdom_name } {
		global CLI_GLOBAL_NODE
		set admin_list [cli_get_tbl_list $CLI_GLOBAL_NODE "system admin"]
		foreach admin_node $admin_list {
			set to_be_deleted {}
			set dashboard_list [cli_get_tbl_list $admin_node "gui-dashboard"]
			foreach dashboard_node $dashboard_list {
				set vdom [cli_get_value $dashboard_node "" "" "vdom"]
				if { $vdom eq $vdom_name } {
					lappend to_be_deleted $dashboard_node
				}
			}
			foreach dashboard_node $to_be_deleted {
				cli_delete_node $dashboard_node
			}
		}
		return 0
	}
	proc ipsec_peertype_state_apply {} {
		global CLI_CUR_NODE
		set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
		set peertype [cli_get_value $CLI_CUR_NODE "" "" "peertype"]
		set authmethod [cli_get_value $CLI_CUR_NODE "" "" "authmethod"]
		set mode [cli_get_value $CLI_CUR_NODE "" "" "mode"]
		set authremote [cli_get_value $CLI_CUR_NODE "" "" "authmethod-remote"]
		set ike [cli_get_value $CLI_CUR_NODE "" "" "ike-version"]
		set aggressive_mode 0

		if { $ike eq "1" && $mode eq "aggressive" } {
			set aggressive_mode 1
		}

		if { $type ne "dynamic" && $authmethod eq "psk" && (!$aggressive_mode || $ike eq "2") } {
			if { $peertype eq "one" } {
				cli_set_value $CLI_CUR_NODE "" "" "peertype" "any"
			}
		}

		if { $type ne "dynamic" || ($authmethod eq "signature" && $authremote eq "") || $authremote  eq "signagure" || ($ike eq "1" && !$aggressive_mode) } {
			if { $peertype eq "dialup" } {
				cli_set_value $CLI_CUR_NODE "" "" "peertype" "any"
			}
		}

		if { ($authmethod eq "psk" && $authremote eq "") || $authremote eq "psk" } {
			if { $peertype eq "peer" || $peertype eq "peergrp" } {
                                cli_set_value $CLI_CUR_NODE "" "" "peertype" "any"
                        }
		}

		return 0
	}
}
%};
