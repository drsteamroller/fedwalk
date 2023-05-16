nodecheck %{
	"ips global" = %{
set count [cli_get_value $CLI_CUR_NODE "" "" "engine-count"]
set max_ips_engines $count
if { [cli_get_devinfo "VM"] eq "yes" } {
	set cpu_limit [cli_get_devinfo "cpu_limit"]
	set max_ips_engines [expr ($cpu_limit * 2)]
} else {
	set nprocess [cli_get_devinfo "cpu"]
	set ips_def_engine_count [expr $nprocess]
	set nturbo_users_max [cli_get_devinfo "nturbo_users_max"]
	if { ($nturbo_users_max ne "0") && ($ips_def_engine_count > [expr $nturbo_users_max]) } {
		set ips_def_engine_count [expr $nturbo_users_max]
	}
	set max_ips_engines [expr ($ips_def_engine_count * 2)]
}
if { $max_ips_engines < 8 } {
	set max_ips_engines 8
}
if { $max_ips_engines > 256 } {
	set max_ips_engines 256
}
if { ($max_ips_engines > 0) && ($count > $max_ips_engines) } {
	cli_set_errmsg "The number of IPS engines cannot be greater than $max_ips_engines"
	return 0
}
return 1
	%}
	"certificate crl" = %{
if {$CLI_ACT ne "add"} {
	if { [string match "*override*" [cli_get_clisrc]] } { return 1 }
	set crl [cli_get_value $CLI_CUR_NODE "" "" "crl"]
	if { $crl ne "" } {
		set n [cli_get_value $CLI_CUR_NODE "" "" "name"]
		set l [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]
		set h [cli_get_value $CLI_CUR_NODE "" "" "http-url"]
		set s [cli_get_value $CLI_CUR_NODE "" "" "scep-url"]
		if { $l ne "" || $h ne "" || $s ne "" } {
			cli_set_errmsg "CRL \"$n\" is not allowed to be set"
			return 0
		}
	}
}
return 1
	%}
	"certificate local password" = %{
if { $CLI_ACT ne "add" && ![string match "*test*" [cli_get_clisrc]] && ![string match "*preload*" [cli_get_clisrc]] } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "source"] eq "factory" } {
		cli_set_errmsg "Build-in certificate is not allowed to change password"
		return 0
	}
}
return 1
	%}
	"vpn certificate local password" = %{
if { $CLI_ACT ne "add" && ![string match "*test*" [cli_get_clisrc]] && ![string match "*preload*" [cli_get_clisrc]] } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "source"] eq "factory" } {
		cli_set_errmsg "Build-in certificate is not allowed to change password"
		return 0
	}
}
return 1
	%}
	"vpn certificate crl" = %{
if {$CLI_ACT ne "add"} {
	if { [string match "*override*" [cli_get_clisrc]] } { return 1 }
	set crl [cli_get_value $CLI_CUR_NODE "" "" "crl"]
	if { $crl ne "" } {
		set n [cli_get_value $CLI_CUR_NODE "" "" "name"]
		set l [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]
		set h [cli_get_value $CLI_CUR_NODE "" "" "http-url"]
		set s [cli_get_value $CLI_CUR_NODE "" "" "scep-url"]
		if { $l ne "" || $h ne "" || $s ne "" } {
			cli_set_errmsg "CRL \"$n\" is not allowed to be set"
			return 0
		}
	}
}
if { $CLI_IS_RESYNC || $CLI_ACT ne "add" } {
	return 1
}
if { [cli_get_devinfo "vdom-admin"] ne "yes" } {
	return 1
}
set range [cli_get_value $CLI_CUR_NODE "" "" "range"]
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set gnode [cli_get_node $CLI_GLOBAL_NODE "certificate crl" $name ""]
if { $range eq "vdom" && $gnode != 0 } {
	cli_set_errmsg "certificate crl with same name $name already exist in global."
	return 0;
} elseif { $range eq "global" && $gnode == 0 } {
	cli_set_errmsg "certificate crl with same name $name dose not exist in global."
	return 0;
}
return 1
	%}
	"vpn certificate local" = %{
if { $CLI_IS_RESYNC || $CLI_ACT ne "add" } {
	return 1
}
if { [cli_get_devinfo "vdom-admin"] ne "yes" } {
	return 1
}
set range [cli_get_value $CLI_CUR_NODE "" "" "range"]
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set gnode [cli_get_node $CLI_GLOBAL_NODE "certificate local" $name ""]
if { $range eq "vdom" && $gnode != 0 } {
	cli_set_errmsg "certificate local with same name $name already exist in global."
	return 0;
} elseif { $range eq "global" && $gnode == 0 } {
	cli_set_errmsg "certificate local with same name $name dose not exist in global."
	return 0;
}
return 1
	%}
	"system switch-interface" = %{
proc get_intf_name { node } {
	set intfname [cli_get_value $node "" "" "interface"]
	if { $intfname == 0 || $intfname == "" } {
		set intfname [cli_get_value $node "" "" "name"]
	}
	return $intfname
}
proc intf_not_static_or_ip_is_set { node } {
	if { ![cli_is_match $node 0 "" "mode" 0 "static"] } {
		return 1
	}
	set ip [cli_get_value $node "" "" "ip"]
	if { $ip eq "" || $ip eq "0.0.0.0 0.0.0.0" } {
		return 0
	}
	return 1
}
proc intf_in_vwp { node } {
	if { [cli_ver_start 500 4] } {
		namespace import global::nCfg_is_port_pair_member
		if { [nCfg_is_port_pair_member $node] } {
			return 1
		}
	}
	return 0
}

proc intf_name_allowed { node } {
	if { [cli_is_match $node 0 "" "name" 0 "dmz"] } {
		return 0
	}
	return 1
}

set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1} {
	cli_set_errmsg "invalid value"
	return 0
}
if { ![string compare $name "vsys_ha"] || ![string compare $name "vsys_fgfm"] } {
	cli_set_errmsg "conflict with system"
	return 0
}

set vsswitchintflist {}
if { [cli_obj_support "system virtual-switch"] } {
	set nodelist [cli_get_tbl_list $CLI_GLOBAL_NODE "system virtual-switch"]
	foreach node $nodelist {
		set portlist [cli_get_tbl_list $node "port"]
		foreach port $portlist {
			set portname [cli_get_value $port "" "" "name"]
			lappend vsswitchintflist $portname
		}
	}
}

# FGT Source: cmf/plugin/base/sys_switch_interface.c:member_set(void*, void*, int)
namespace import global::intf_is_ipsec_tunnel
set i -1
set memintf [cli_get_value $CLI_CUR_NODE "" "" "member"]
foreach m $memintf {
	incr i
	set node [cli_get_node $CLI_GLOBAL_NODE "system interface" $m ""]
	if { !$node } { continue }
	set intfname [get_intf_name $node]
	set j -1
	foreach n $memintf {
		incr j
		if { $i >= $j } { continue }
		set node1 [cli_get_node $CLI_GLOBAL_NODE "system interface" $n ""]
		if { !$node1 } { continue }
		set type1 [cli_get_value $node1 "" "" "type"]
		# skip base interface check for vxlan, IPSec tunnel or lan-extension.
		if { $type1 eq "vxlan" || $type1 eq "lan-extension"} {
			continue
		}
		if { $type1 eq "tunnel" && [intf_is_ipsec_tunnel $node1] } {
			continue
		}
		if { $intfname eq [get_intf_name $node1] } {
			cli_set_errmsg "\"$m\" and \"$n\" have the same base interface."
			return 0
		}
	}

	if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
		cli_set_errmsg "Switch Interface cannot be enabled in Virtual Domain($vdom) with transparent mode."
		return 0
    }

	# Filter out any interface with an IP address.
	if { [intf_not_static_or_ip_is_set $node] } {
		cli_set_errmsg "\"$intfname\" mode is not static or ip is set. intf must be static and ip must not be set for switch interface."
		return 0
	}

	# Filter out any interface used by a virtual wire pair.
	if { [intf_in_vwp $node] } {
		cli_set_errmsg "\"$intfname\" must not be a Virtual Wire Pair member."
		return 0
	}

	# used by other composite
	namespace import global::nCfg_is_interface_used_by_switchctl
	if { [nCfg_is_interface_used_by_switchctl $intfname] } {
		cli_set_errmsg "\"$intfname\" is used by switchctl."
		return 0
	}

	# check vdom
	if { [cli_is_match $node 0 "" "vdom" 0 $CLI_CUR_VDOM_NAME] } {
		set intf_vdom [cli_get_value $node "" "" "vdom"]
		cli_set_errmsg "\"$intfname\" (vdom: $intf_vdom) does not belong in current vdom ($CLI_CUR_VDOM_NAME)."
		return 0
	}

	if { ![intf_name_allowed $node] } { # didn't see in fgt code
		set intf_name [cli_get_value $node "" "" "name"]
		cli_set_errmsg "\"$intfname\" name ($intf_name) is not allowed in software switch interface."
		return 0
	}

	if { [cli_obj_support "system virtual-switch"] } {
		set nodelist [cli_get_tbl_list $CLI_GLOBAL_NODE "system virtual-switch"]
		foreach node $nodelist {
			set portlist [cli_get_tbl_list $node "port"]
			foreach port $portlist {
				if { [cli_is_match $port 0 "" "name" 0 "$intfname"] } {
					set port_name [cli_get_value $port "" "" "name"]
					cli_set_errmsg "\"$intfname\" is used in virtual-switch port port_name."
					return 0
				}
			}
		}
	}
	if { [lsearch -exact $vsswitchintflist $intfname] >= 0 } {
		cli_set_errmsg "\"$intfname\" is used in virtual-switch port port_name."
		return 0
	}
}

return 1
	%}

	"system proxy-arp" = %{
set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "ip" 0 $ip] > 1} {
	cli_set_errmsg "duplicate"
	return 0
}
return 1
	%}

        "system interface wifi-ssid" = %{
set ssid [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [string compare -length 1 $ssid " "] == 0 } {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}

        "system interface wifi-security" = %{
set security [cli_get_value $CLI_CUR_NODE "" "" ""]
set wlmode [cli_get_value $CLI_GLOBAL_NODE "system wireless settings" "" "mode"]
if { $wlmode eq "CLIENT" } {
        if { $security eq "WPA2" || $security eq "WPA2_AUTO" } {
                cli_set_errmsg "invalid value"
                return 0
        }
}
return 1
        %}

        "system interface wifi-auth" = %{
set auth [cli_get_value $CLI_CUR_NODE "" "" ""]
set wlmode [cli_get_value $CLI_GLOBAL_NODE "system wireless settings" "" "mode"]
if { $wlmode eq "CLIENT" && $auth eq "RADIUS" } {
        cli_set_errmsg "invalid value"
        return 0
}
return 1
        %}

        "system interface wifi-passphrase" = %{
set pass [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [string compare -length 4 $pass "ENC "] != 0 } {
	regsub -all {(\\)+([\'\"\\])} $pass { } pass
	set len [string length $pass]
	if { $len < 8 || $len > 63 } {
		cli_set_errmsg "The wifi-passphrase must be 8 to 63 characters long"
		return 0
	}
}
return 1
	%}

	"system interface wifi-networks wifi-passphrase" = %{
set pass [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [string compare -length 4 $pass "ENC "] != 0 } {
	regsub -all {(\\)+([\'\"\\])} $pass { } pass
	set len [string length $pass]
	if { $len < 8 || $len > 63 } {
		cli_set_errmsg "The wifi-passphrase must be 8 to 63 characters long"
		return 0
	}
}
return 1
	%}
	"wireless-controller vap passphrase" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"] eq "open" } {
	return 1
}
set min_pass_len 8
if { [cli_branchpt_start 600 891] && ![cli_branchpt_start 600 1045] } {
	set wfa [cli_get_value $CLI_CUR_VDOM_NODE "wireless-controller setting" "" "wfa-compatibility"]
	if { $wfa ne "enable" } {
		set min_pass_len 12
	}
}
set pass [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [string compare -length 4 $pass "ENC "] != 0 } {
	regsub -all {(\\)+([\'\"\\])} $pass { } pass
	set len [string length $pass]
	if { $len == 64 } {
		set res [string is xdigit $pass]
		if { $res != 1 } {
			cli_set_errmsg "The passphrase must be $min_pass_len to 63 characters long or 64 hexadecimal digits"
			return 0
		}
	} elseif { $len < $min_pass_len || $len > 63 } {
		cli_set_errmsg "The passphrase must be $min_pass_len to 63 characters long or 64 hexadecimal digits"
		return 0
	}
}
return 1
	%}

    "wireless-controller timers client-idle-timeout" = %{
set timeout [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $timeout > 0 && $timeout < 20 } {
	cli_set_errmsg "Value out of range, must be in range 20-3600 or 0"
	return 0
}
return 1
	%}

        "system interface mode" = %{
if { $CLI_ACT ne "unset" } {
	set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	set mode [cli_get_value $CLI_CUR_NODE "" "" ""]

	if { ($ifname eq "modem") && [cli_has_feature "f_modem"] && ($mode eq "dhcp") } {
		cli_set_errmsg "modem interface not support dhcp mode"
		return 0
	}
}
return 1
        %}
        "system interface ip" = %{
set ha_mgmt_stat [cli_get_value $CLI_GLOBAL_NODE "system ha" "" "ha-mgmt-status"]
if { $ha_mgmt_stat ne "enable" } {
	return 1
}
set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set ifname [string trim $ifname \"]
set ip [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [cli_ver_start 500 6] } {
    if { [cli_is_used $CLI_CUR_PARENT_NODE "system ha ha-mgmt-interfaces" "interface"] } {
        cli_set_errmsg "system interface \"$ifname\" set ip $ip \[HA configuration is not allowed to be changed in HA mode\]"
        return 0
    }
} else {
    set ha_mgmt_intf [cli_get_value $CLI_GLOBAL_NODE "system ha" "" "ha-mgmt-interface"]
    set ha_intf_name [string trim $ha_mgmt_intf \"]
    if { $ha_intf_name eq $ifname } {
        cli_set_errmsg "system interface \"$ifname\" set ip $ip \[HA configuration is not allowed to be changed in HA mode\]"
        return 0
    }
}
return 1
        %}
	"system interface" = %{
set vdom [cli_get_value $CLI_CUR_NODE "" "" "vdom"]
if {$CLI_ACT ne "add"} {
	set vdname [string trim $vdom \"]
	set elbc [cli_get_node $CLI_GLOBAL_NODE "system elbc" "" ""]
	set mode [cli_get_value $elbc "" "" "mode"]
	if { $mode eq "service-group" && $vdom eq "elbc-mgmt" } {
		cli_set_errmsg "cannot be edited"
	    return 0
	}
} else {
	if { [cli_ver_start 500 0] } {
		#217986/add VLAN support for 30D
	} else {
		set m [cli_get_devinfo "platform"]
		if { $m eq "FortiGate-30D" || $m eq "FortiWiFi-30D" } {
			cli_set_errmsg "Not support for model \"$m\""
			return 0
		}
	}
}
set vnode [cli_get_vdom_node $vdom]
set ifname [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $ifname eq ""} {
	cli_set_errmsg "invalid value"
	return 0
}
if {[string trim $ifname] ne $ifname} {
	cli_set_errmsg "interface name cannot have leading or trailing spaces"
	return 0
}
if {[string first "%" $ifname] != -1} {
	cli_set_errmsg "illegal name"
	return 0
}
if {[cli_get_vdom_node $ifname] ne 0} {
	cli_set_errmsg "vlan name same as vdom"
	return 0
}
if {[cli_is_match $vnode 1 "system zone" "name" 0 $ifname]} {
	cli_set_errmsg "entry exists"
	return 0
}
if {$CLI_ACT ne "add"} {
        set wl_mode [cli_get_value $CLI_GLOBAL_NODE "system wireless settings" "" "mode"]
	if { $wl_mode eq "SCAN" && $ifname eq "wlan" } {
		cli_set_errmsg "Wireless interface \"wlan\" is not editable while in scan mode!"
		return 0
	}
}
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if {$type eq "fctrl-trunk"} {
	if { $CLI_ACT eq "add" } {
		cli_set_errmsg "fctrl-trunk type interface can not be manually created"
		return 0
	}
}

set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
set ipnode [cli_get_node $CLI_CUR_NODE "" "" "ip"]
if {$vnode != 0 && $ipnode != 0} {
	if {[cli_get_value $vnode "system settings" "" "allow-subnet-overlap"] eq "disable"} {
		set ha_mgmt_stat [cli_get_value $CLI_GLOBAL_NODE "system ha" "" "ha-mgmt-status"]
		set iflist ""
		set is_haif 0
		set sifname [string trim $ifname \"]
		if { $ha_mgmt_stat ne "enable" } {
			# nothing
		} elseif { [cli_ver_start 500 6] } {
			set hanode [cli_get_node $CLI_GLOBAL_NODE "system ha" "" ""]
			set ha_mgmt_intfs [cli_get_tbl_list $hanode "ha-mgmt-interfaces"]
			foreach e $ha_mgmt_intfs {
				set tifname [cli_get_value $e "" "" "interface"]
				set tifname [string trim $tifname \"]
				if {$sifname ne $tifname} {
					append iflist $tifname
				} else {
					set is_haif 1
					break
				}
			}
		} else {
			set tifname [cli_get_value $CLI_GLOBAL_NODE "system ha" "" "ha-mgmt-interface"]
			set tifname [string trim $tifname \"]
			if {$sifname ne $tifname} {
				set iflist $tifname
			} else {
				set is_haif 1
				break
			}
		}
		if { $is_haif != 1 } {
			set vdom [string trim $vdom \"]
			set tip1 [list $CLI_GLOBAL_NODE "system interface" 1 "ip" "name" 0 0 1 "vdom" $vdom "name" $iflist]
			set tip2 [list 0 "secondaryip" 1 "ip" "id" 0 1 0 "" ""]
			set msg [cli_check_overlapip $CLI_CUR_NODE $sifname $ip $tip1 $tip2]
			if {$msg != 0} {
				cli_set_errmsg "$msg"
				return 0
			}
		}
	}
}

set remoteip [cli_get_value $CLI_CUR_NODE "" "" "remote-ip"]
set sslvpn_sport [cli_get_value $CLI_GLOBAL_NODE "system global" "" "sslvpn-sport"]
set admin_sport [cli_get_value $CLI_GLOBAL_NODE "system global" "" "auth-https-port"]
if {$sslvpn_sport eq $admin_sport} {
	if {[cli_is_match $CLI_CUR_NODE 0 "" "allowaccess" 0 "'*https*'"] ||
	    [cli_is_match $CLI_CUR_NODE 1 "secondaryip" "allowaccess" 0 "'*https*'"]} {
		    if {[cli_is_match $vnode 1 "firewall policy" "srcintf" 0 $ifname]} {
			    cli_set_errmsg "sslvpn policy srcintf https"
			    return 0
		    }
	    }
}

if { $type eq "tunnel" } {
	set ip [split [cli_get_value $CLI_CUR_NODE "" "" "ip"]]
	set rip [split $remoteip]

	if { ([lindex $ip 0] ne "0.0.0.0" && [lindex $ip 1] ne "255.255.255.255") } {
		cli_set_errmsg "A tunnel IP must have a mask of 255.255.255.255"
		return 0
	}

	if { ([lindex $rip 0] ne "0.0.0.0" || ([llength $rip] > 1 && [lindex $rip 1] ne "0.0.0.0")) && [lindex $ip 0] eq "0.0.0.0" } {
		cli_set_errmsg "IP must be set if remote-ip is defined"
		return 0
	}
}

if {[cli_is_match $CLI_CUR_NODE 0 "" "dhcp-relay-service" 0 "enable"]} {
	if { [cli_ver_start 500 0] } {
		set status "status"
	} else {
		set status "enable"
	}
	set relay_type [cli_get_value $CLI_CUR_NODE "" "" "dhcp-relay-type"]
        if {[cli_get_value $CLI_CUR_NODE "" "" "mode"] ne "static"} {
		if {$relay_type eq "regular"} {
			if {[cli_get_match_nr $vnode 1 "system dhcp server" "server-type" 0 "regular" "interface" 0 "\"$ifname\"" $status 0 "enable"]} {
				cli_set_errmsg "dhcp relay conflict"
				return 0
			}
		} else {
			if {[cli_is_match $vnode 1 "system dhcp server" "server-type" 0 "ipsec" "interface" 0 "\"$ifname\"" $status 0 "enable"]} {
				cli_set_errmsg "dhcp relay conflict"
				return 0
			}
		}
	}

	set relay_ips [cli_get_value $CLI_CUR_NODE "" "" "dhcp-relay-ip"]
	set ip_list {}
	foreach rip $relay_ips {
		if { $rip eq "0.0.0.0" } {
			cli_set_errmsg "invalid value"
			return 0
		}
		if { [lsearch $ip_list $rip] >= 0 } {
			cli_set_errmsg "duplicate ip in the list"
			return 0
		}
		lappend ip_list $rip
	}
}
if { [cli_get_value $vnode "system settings" "" "opmode"] eq "transparent" } {
	set mode [cli_get_value $CLI_CUR_NODE "" "" "mode"]
	if { $mode eq "dhcp" || $mode eq "pppoa" || $mode eq "pppoe" } {
		cli_set_errmsg "interface cannot be in $mode mode when Virtual Domain ($vdom) is transparent mode."
		return 0
	}
}
if {$type eq "vlan" || $type eq "emac-vlan"} {
    if { [string compare $ifname "wlan"] != 0 && [string compare $ifname "modem"] != 0 } {
	set vlanid [cli_get_value $CLI_CUR_NODE "" "" "vlanid"]
        if {$type eq "vlan"} {
                if {$vlanid < 1 || $vlanid > 4094} {
                    cli_set_errmsg "VLAN id must between 1 to 4094"
                        return 0
                }
        } else {
                if {$vlanid != 0 && ($vlanid < 1 || $vlanid > 4094) } {
                    cli_set_errmsg "VLAN id must be 0 or between 1 to 4094"
                        return 0
                }
        }
	set phyname [cli_get_value $CLI_CUR_NODE "" "" "interface"]
	if {$phyname eq ""} {
		cli_set_errmsg "invalid interface"
		return 0
	}
	if {$type eq "vlan" || $vlanid != 0} {
	set nodelist [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
	foreach e $nodelist {
		if { [cli_if_same_node $e $CLI_CUR_NODE] } {
			continue
		}
		set evlanid [cli_get_value $e "" "" "vlanid"]
		set ephyname [cli_get_value $e "" "" "interface"]
		if {$evlanid eq $vlanid && $ephyname eq $phyname} {
			set vlname [cli_get_value $e "" "" "name"]
			cli_set_errmsg "vlanid $vlanid and physical interface $phyname are already used by VLAN $vlname; vlanid and physical interface must be a unique pair"
			return 0
		}
	}
	}
	if {$CLI_ACT ne "add"} {
		set ovlanid [cli_get_org_value $CLI_CUR_NODE "" "" "vlanid"]
		set ophyname [string trim [cli_get_org_value $CLI_CUR_NODE "" "" "interface"] \"]
		set phyname [string trim $phyname \"]
		if { $ovlanid ne "" && $ovlanid != $vlanid } {
			cli_set_errmsg "VLAN ID cannot be changed once a VLAN has been created."
			return 0
		} elseif { $ophyname ne "" && $ophyname ne $phyname } {
			cli_set_errmsg "physical interface cannot be changed once a VLAN has been created."
			return 0
		}
	}
    }
    if { [cli_get_value $vnode "system settings" "" "opmode"] eq "transparent" && [cli_is_match $CLI_CUR_NODE 0 "" "allowaccess" 0 "'*auto-ipsec*'"] } {
	cli_set_errmsg "Auto IPsec cannot be enabled in Virtual Domain($vdom) with transparent mode."
	return 0
    }
	if { [cli_ver_start 500 0] } {
		set vsmax [cli_feature_value "max_vlan_num"]
		if { $vsmax > 0 } {
			set pintf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
			set nr [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "interface" 0 $pintf "type" 0 "vlan"]
			if { $nr > $vsmax } {
				cli_set_errmsg "$pintf already got maximum vlan entries (max is $vsmax)"
				return 0
			}
		}
	}
	if { [cli_ver_start 500 4] } {
		set phyname [cli_get_value $CLI_CUR_NODE "" "" "interface"]
		set pnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $phyname ""]
		namespace import global::nCfg_is_port_pair_member
		if {[nCfg_is_port_pair_member $pnode]} {
			cli_set_errmsg "Can not create vlan interface on Virtual Wire Pair members."
			return 0
		}
	}
}

if {$type eq "tunnel"} {
	if {$ip ne "" && $remoteip eq ""} {
		cli_set_errmsg "tunnel remote ip"
		return 0
	}
	if {$ip eq "" && $remoteip ne ""} {
		cli_set_errmsg "tunnel local ip"
		return 0
	}

	if {$CLI_ACT ne "add"} {
		set ovdom [cli_get_org_value $CLI_CUR_NODE "" "" "vdom"]
## Mantis 540937
		if { $ovdom ne "" } {
			set nvdom [cli_get_value $CLI_CUR_NODE "" "" "vdom"]
			set ovdom [string trim $ovdom \"]
			set nvdom [string trim $nvdom \"]
			if { $ovdom ne $nvdom } {
				cli_set_errmsg "cannot change vdom for tunnel interface"
				return 0
			}
		}
	}

	set gwdetect [cli_get_value $CLI_CUR_NODE "" "" "gwdetect"]
	if { $ip eq "0.0.0.0" && $gwdetect eq "enable" } {
		cli_set_errmsg "gwdetect should be disabled"
		return 0
	}
}

if {$type eq "wireless"} {
	set auth [cli_get_value $CLI_CUR_NODE "" "" "wifi-auth"]
	set security [cli_get_value $CLI_CUR_NODE "" "" "wifi-security"]
	switch $security {
		"WPA" -
		"WPA2" -
		"WPA2_AUTO" {
			if {$auth eq "PSK"} {
				set pass [cli_get_value $CLI_CUR_NODE "" "" "wifi-passphrase"]
				if {$pass eq "" } {
					cli_set_errmsg "invalid value"
					return 0
				}
			}
			if {$auth eq "RADIUS"} {
				set radsrv [cli_get_value $CLI_CUR_NODE "" "" "wifi-radius-server"]
				if {$radsrv eq ""} {
					cli_set_errmsg "invalid value"
					return 0
				}
			}
		}
		"WEP64" -
		"WEP128" {
			set wepkey [cli_get_value $CLI_CUR_NODE "" "" "wifi-key"]
			if { $wepkey eq "" } {
				cli_set_errmsg "invalid value"
				return 0
			}
		}
	}

	set wl_mode [cli_get_value $CLI_GLOBAL_NODE "system wireless settings" "" "mode"]
	set max_wlif 4
	if {$wl_mode eq "CLIENT" || $wl_mode eq "SCAN"} {
		set max_wlif 1
	}
	set nr_wlif [cli_get_match_nr $CLI_GLOBAL_NODE 1 "system interface" "type" 0 "wireless"]
	if {$nr_wlif > $max_wlif} {
		cli_set_errmsg "wireless interface reach to MAX"
		return 0
	}
}

if {[cli_is_match $CLI_CUR_NODE 0 "" "l2tp-client" 0 "enable"]} {
	set l2tp_peer [cli_get_value $CLI_CUR_NODE "l2tp-client-settings" "" "peer-host"]
	set l2tp_user [cli_get_value $CLI_CUR_NODE "l2tp-client-settings" "" "user"]
	if {$l2tp_peer eq "" || $l2tp_user eq ""} {
		cli_set_errmsg "empty value"
		return 0
	}
}

if {$type eq "dhcp" || $type eq "pppoe"} {
	if { [cli_get_value $CLI_GLOBAL_NODE "system ha" "" "mode"] ne "standalone"} {
		cli_set_errmsg "intf error mode"
		return 0
	}
}

if {$CLI_ACT ne "add"} {
	set ovdom [cli_get_org_value $CLI_CUR_NODE "" "" "vdom"]
	set ovdom [string trim $ovdom \"]
	set vdom [string trim $vdom \"]
	if {$ovdom ne "" && $vdom ne "" && $ovdom ne $vdom} {
		if {[cli_is_referenced $CLI_CUR_NODE $ovdom]} {
			cli_set_errmsg "used"
			return 0
		}
		if {$type eq "vap-switch"} {
			cli_set_errmsg "Virtual domain can not be changed for VAP interface"
			return 0
		}
		if {$type eq "switch"} {
			cli_set_errmsg "Make sure the interface is not used in the other settings"
			return 0
		}
	}
        set otype [cli_get_org_value $CLI_CUR_NODE "" "" "type"]
        if {$otype ne "" && $type ne "" && $otype ne $type} {
                if {$otype eq "switch"} {
                        cli_set_errmsg "switch type can not be changed"
                        return 0
                }
        }
} else {
	if {$type eq "vap-switch" && ![cli_ver_start 600 0] } {
		set name [cli_get_value $CLI_CUR_NODE "" "" ""]
		for {set i 0} {$i < [string length $name]} {incr i} {
			set char [string index $name $i]
			if {![regexp {[a-zA-Z0-9[:space:]._-]} $char]} {
				cli_set_errmsg "illegal name: $name"
				return 0
			}
		}
	}
}
if {$type eq "loopback" && $vdom eq "" } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	cli_set_errmsg "system interface, $name: attribute, \"vdom\", must be set"
	return 0
}
if {$type eq "aggregate"} {
	set memintf [cli_get_value $CLI_CUR_NODE "" "" "member"]
	foreach m $memintf {
		set polist [cli_get_tbl_list $vnode "firewall policy"]
		foreach p $polist {
			set srcintf [cli_get_value $p "" "" "srcintf"]
			set dstintf [cli_get_value $p "" "" "dstintf"]
			if {("\"$m\"" eq $srcintf) || ([lsearch -exact $srcintf $m] >= 0)} {
				cli_set_errmsg "member interface \"$m\" is used in srcintf by policy"
				return 0
			}
			if {("\"$m\"" eq $dstintf) || ([lsearch -exact $dstintf $m] >= 0)} {
				cli_set_errmsg "member interface \"$m\" is used in dstintf by policy"
				return 0
			}
		}
		set zonelist [cli_get_tbl_list $vnode "system zone"]
		foreach zonenode $zonelist {
			set zoneintf [cli_get_value $zonenode "" "" "interface"]
			if {("\"$m\"" eq $zoneintf) || ([lsearch -exact $zoneintf $m] >= 0)} {
				set zname [cli_get_value $zonenode "" "" "name"]
				foreach p $polist {
					set srcintf [cli_get_value $p "" "" "srcintf"]
					set dstintf [cli_get_value $p "" "" "dstintf"]
					if {("\"$zname\"" eq $srcintf) || ([lsearch -exact $srcintf $zname] >= 0)} {
						cli_set_errmsg "member interface \"$m\" is used in zone \"$zname\" as part of srcintf in a policy"
						return 0
					}
					if {("\"$zname\"" eq $dstintf) || ([lsearch -exact $dstintf $zname] >= 0)} {
						cli_set_errmsg "member interface \"$m\" is used in zone \"$zname\" as part of dstintf in a policy"
						return 0
					}
				}
			}
		}
	}
}
if { [cli_ver_start 600 0] } {
	set old_speed [cli_get_org_value $CLI_CUR_NODE "" "" "speed"]
	set speed [cli_get_value $CLI_CUR_NODE "" "" "speed"]
	if { $old_speed ne $speed } {
		namespace import global::get_intf_speed_group
		set plat [cli_get_devinfo "platform"]
		set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
		set group [get_intf_speed_group $plat $name]
		if { $group ne "" } {
			set intfs [split $group " "]
			foreach intf $intfs {
				set grp_table($intf) 1
			}
			set ifnodelist [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
			foreach ifnode $ifnodelist {
				set vdom [cli_get_value $ifnode "" "" "vdom"]
				set vnode [cli_get_vdom_node $vdom]
				if {[cli_if_same_node $vnode $CLI_CUR_VDOM_NODE] && [cli_get_value $ifnode "" "" "type"] eq "aggregate"} {
					set memintf [cli_get_value $ifnode "" "" "member"]
					foreach m $memintf {
						if { [info exists grp_table($m)] } {
							if { $m eq $name } {
								cli_set_errmsg "Interface speed cannot be set for aggregated interfaces"
							} else {
								cli_set_errmsg "Interface speed cannot be changed when there's aggregated interface in same group"
							}
							return 0
						}
					}
				}
			}
		}
	}
}
return 1
	%}

	"system interface mtu" = %{
proc report_mtu_range_notpass { mtu min max mode } {
        if { (($min > 0) && ($mtu < $min)) || (($max > 0) && ($mtu > $max)) } {
                cli_set_errmsg "MTU size not valid. Should be in the range of $min - $max in $mode mode."
                return 1
        }
        return 0
}
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
set mtu [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mtu"]
set mto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mtu-override"]
if { [cli_ver_start 500 0] } {
	if { $mto eq "enable" } {
                set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
                set ng [cli_get_intf_mtu [string trim $name \"]]
                if { $ng eq 0 || $ng eq "" } {
                        set min 0
                        set max 0
                } elseif { [scan $ng "%lu-%lu" min max] ne 2 } {
                        set min 0
                        set max 0
                }
		switch $mode {
		"dhcp" { if { [report_mtu_range_notpass $mtu 576 $max "DHCP"] } { return 0 } }
		"pppoe" { if { [report_mtu_range_notpass $mtu 576 [expr ($max-8)] "PPPoE"] } { return 0 } }
		"static" { if { [report_mtu_range_notpass $mtu $min $max "static"] } { return 0 } }
		"ipoa" { if { [report_mtu_range_notpass $mtu 68 65527 "IPoA"] } { return 0 } }
		"pppoa" { if { [report_mtu_range_notpass $mtu 576 1500 "PPPoA"] } { return 0 } }
		}
	}
} else {
        switch $mode {
        "dhcp" { if { [report_mtu_range_notpass $mtu 576 1500 "DHCP"] } { return 0 } }
        "pppoe" { if {$mto eq "enable"} { if { [report_mtu_range_notpass $mtu 576 1492 "PPPoE"] } { return 0 } } }
        "static" { if {$mto eq "enable"} { if { [report_mtu_range_notpass $mtu 68 0 "static"] } { return 0 } } }
        "ipoa" { if { [report_mtu_range_notpass $mtu 68 65527 "IPoA"] } { return 0 } }
        "pppoa" { if {$mto eq "enable"} { if { [report_mtu_range_notpass $mtu 576 1500 "PPPaA"] } { return 0 } } }
        }
}
return 1
	%}

	"system interface vlanid" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if {$type ne "vlan"} {
	return 1
}

if {$type eq "emac-vlan"} {
	set vlanid [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $vlanid == 0 } {
		return 1
	}
}
if {$CLI_ACT eq "add"} {
        set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
	if {$type eq "vlan" || $type eq "emac-vlan"} {
		set vlanid [cli_get_value $CLI_CUR_NODE "" "" ""]
		set phyintf [cli_get_value $CLI_CUR_PARENT_NODE "" "" "interface"]
		set nr [cli_get_match_nr $CLI_GLOBAL_NODE 1 "system interface" "vlanid" 0 $vlanid "interface" 0 $phyintf "type" 0 "vlan"]
		if {$nr > 1} {
			cli_set_errmsg "The VLAN id $vlanid already been used"
			return 0
		}
		set nr [cli_get_match_nr $CLI_GLOBAL_NODE 1 "system interface" "vlanid" 0 $vlanid "interface" 0 $phyintf "type" 0 "emac-vlan"]
		if {$nr > 1} {
			cli_set_errmsg "The VLAN id $vlanid already been used"
			return 0
		}
	}
}
return 1
	%}

	"system interface vdom" = %{
proc get_vcluster_by_vdom { vdom } {
	global CLI_GLOBAL_NODE
	set ha_node [cli_get_node $CLI_GLOBAL_NODE "system ha" "" ""]
	if { [cli_ver_start 700 2] } {
		if { [cli_get_value $ha_node "" "" "vcluster-status"] ne "enable" } {
			return 0
		}
		set vc_list [cli_get_tbl_list $ha_node "vcluster"]
		foreach vc $vc_list {
			set vdom_list [cli_get_value $vc "" "" "vdom"]
			if {[lsearch -exact $vdom_list $vdom] >= 0} {
				return [cli_get_value $vc "" "" "vcluster-id"]
			}
		}
	} else {
		set vdom_list [cli_get_value $ha_node "" "" "vdom"]
		if {[lsearch -exact $vdom_list $vdom] >= 0} {
			return 1
		}
		if { [cli_is_match $CLI_GLOBAL_NODE 0 "system ha" "vcluster2" 0 "enable"] } {
			set vdom_list [cli_get_value $ha_node "secondary-vcluster" "" "vdom"]
			if { [lsearch -exact $vdom_list $vdom] >= 0 } {
				return 2
			}
		}

	}
	return 0
}
set vdom [cli_get_value $CLI_CUR_NODE "" "" ""]
set vdom [string trim $vdom \"]
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set type [string trim $type \"]
set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
if {$vdom ne "root" && $ifname eq "adsl"} {
	cli_set_errmsg "invalid value"
	return 0
}
if {$CLI_ACT eq "add"} {
	if {[cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent"} {
		if { [cli_get_match_nr $CLI_GLOBAL_NODE 1 "system interface" "vdom" 0 $vdom] > 255} {
			cli_set_errmsg "too many interfaces"
			return 0
		}
	}
}
if {$type eq "vdom-link"} {
	# find pair interface
	set intf_list [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
	foreach memb $intf_list {
		set memb_type [cli_get_value $memb "" "" "type"]
		set memb_type [string trim $memb_type \"]
		if { $memb_type eq "vdom-link" } {
			set memb_name [cli_get_value $memb "" "" "name"]
			set prefix [string range $ifname 0 [string length $ifname]-2]
			if { $memb_name ne $ifname && [string match $prefix* $memb_name]} {
				# check vdom
				set memb_vdom [cli_get_value $memb "" "" "vdom"]
				set memb_vdom [string trim $memb_vdom \"]
				set vcluster [get_vcluster_by_vdom $vdom]
				set memb_vcluster [get_vcluster_by_vdom $memb_vdom]
				if { $vcluster ne $memb_vcluster } {
					cli_set_errmsg "Cannot change vdom because vdom-link pair's vdoms must belong to the same virtual cluster. ($vdom=vcluster$vcluster, $memb_vdom=vcluster$memb_vcluster)"
					return 0
				}
				break
			}
		}
	}
	if { [cli_get_value [cli_get_vdom_node $vdom] "system settings" "" "opmode"] eq "transparent" } {
		if { ![cli_ver_start 500 0] } {
			cli_set_errmsg "vdom-link interface can not belongs to a TP vdom"
			return 0
		}
	}
}
if {$CLI_ACT ne "add"} {
	if {$type eq "vap-switch"} {
		set old [cli_get_org_value $CLI_CUR_NODE "" "" ""]
		set old [string trim $old \"]
		if { $old ne "" && $vdom ne "" && $vdom ne $old } {
			cli_set_errmsg "Virtual domain can not be changed for VAP interface"
			return 0
		}
	}
	if {$type eq "wl-mesh"} {
		set o [cli_get_org_value $CLI_CUR_NODE "" "" ""]
		set n [cli_get_value $CLI_CUR_NODE "" "" ""]
		if { $o ne $n } {
			cli_set_errmsg "Virtual domain can not be changed for wlan mesh interface"
			return 0
		}
	}
	if {$type eq "aggregate" || $type eq "redundant" } {
		set old [cli_get_org_value $CLI_CUR_NODE "" "" ""]
		set old [string trim $old \"]
		if { $old ne $vdom } {
			cli_set_errmsg "Virtual domain must be same as virtual domain ($old) for all aggregate/redundant interfaces"
			return 0
		}
	}
}
return 1
	%}
        "system interface type" = %{
if {$CLI_ACT ne "add"} {
	set type [cli_get_value $CLI_CUR_NODE "" "" ""]
	set otype [cli_get_org_value $CLI_CUR_NODE "" "" ""]
        if {$type ne $otype && ($type eq "fctrl-trunk" || $otype eq "fctrl-trunk")} {
                cli_set_errmsg "fctrl-trunk type can not be changed or manually set"
                return 0
        }
}
return 1
        %}

	"system interface forward-domain" = %{
set fwd_domain [cli_get_value $CLI_CUR_NODE "" "" ""]
set fwd_domain_org [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { $fwd_domain_org eq "" } {
	set fwd_domain_org [cli_get_defvalue "system interface" "forward-domain"]
}
if { $fwd_domain == $fwd_domain_org } {
	return 1
}
set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
set vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vdom"]
set vnode [cli_get_vdom_node $vdom]

if {[cli_get_node $vnode "system zone" $ifname ""]} {
	cli_set_errmsg "interface $ifname is used"
	return 0
}
if {[cli_is_match $vnode 1 "firewall policy" "srcintf" 0 "\"$ifname\""]} {
	cli_set_errmsg "interface $ifname is used"
	return 0
}
return 1
	%}

	"system interface vrrp" = %{
set vrid [cli_get_value $CLI_CUR_NODE "" "" "vrid"]
if {$vrid <= 0} {
    cli_set_errmsg "vrid out of range"
    return 0
}
set ip4 [cli_get_value $CLI_CUR_NODE "" "" "vrip"]
if { $ip4 eq "0.0.0.0" } {
	cli_set_errmsg "invalid vrip value \"$ip4\""
	return 0
}
return 1
%}

	"system interface secondaryip" = %{
set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
set ipnode [cli_get_node $CLI_CUR_NODE "" "" "ip"]
set ifnode [cli_get_parent $CLI_CUR_PARENT_NODE]
set ifname [cli_get_value $ifnode "" "" "name"]
set vdom [cli_get_value $ifnode "" "" "vdom"]
set vnode [cli_get_vdom_node $vdom]
set ifip [cli_get_value $ifnode "" "" "ip"]
if { $ifip eq "" || $ifip eq "0.0.0.0 0.0.0.0" } {
	cli_set_errmsg "Please configure primary IP address first"
	return 0
}
if {$vnode != 0 && $ipnode != 0} {
	if {[cli_get_value $vnode "system settings" "" "allow-subnet-overlap"] eq "disable"} {
		set ha_mgmt_stat [cli_get_value $CLI_GLOBAL_NODE "system ha" "" "ha-mgmt-status"]
		set iflist ""
		set is_haif 0
		set sifname [string trim $ifname \"]
		if { $ha_mgmt_stat ne "enable" } {
			# nothing
		} elseif { [cli_ver_start 500 6] } {
			set hanode [cli_get_node $CLI_GLOBAL_NODE "system ha" "" ""]
			set ha_mgmt_intfs [cli_get_tbl_list $hanode "ha-mgmt-interfaces"]
			foreach e $ha_mgmt_intfs {
				set tifname [cli_get_value $e "" "" "interface"]
				set tifname [string trim $tifname \"]
				if {$sifname ne $tifname} {
					append iflist $tifname
				} else {
					set is_haif 1
					break
				}
			}
		} else {
			set tifname [cli_get_value $CLI_GLOBAL_NODE "system ha" "" "ha-mgmt-interface"]
			set tifname [string trim $tifname \"]
			if {$sifname ne $tifname} {
				set iflist $tifname
			} else {
				set is_haif 1
				break
			}
		}
		if { $is_haif != 1 } {
			set vdom [string trim $vdom \"]
			set tip1 [list $CLI_GLOBAL_NODE "system interface" 1 "ip" "name" 0 0 1 "vdom" $vdom "name" $iflist]
			set tip2 [list 0 "secondaryip" 1 "ip" "id" 0 1 0 "" ""]
			set msg [cli_check_overlapip $CLI_CUR_NODE $sifname $ip $tip1 $tip2]
			if {$msg != 0} {
				cli_set_errmsg "$msg"
				return 0
			}
		}
	}
}
return 1
	%}

        "system interface ips-sniffer-mode" = %{
if { ![cli_is_referenced $CLI_CUR_PARENT_NODE] } {
        return 1;
}
set mode_new [cli_get_value $CLI_CUR_NODE "" "" ""]
set mode_org [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { $mode_org eq "" } {
	set mode_org [cli_get_defvalue "system interface" "ips-sniffer-mode"]
}
if { $mode_new eq $mode_org } {
	return 1
}

## If this interface used by zone/policy/ipsec, then can not change this attr
set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
set vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vdom"]
set vnode [cli_get_vdom_node $vdom]
if {[cli_get_match_nr $vnode 1 "system zone" "interface" 0 '*$ifname*']} {
        cli_set_errmsg "interface $ifname is used by system zone:interface"
        return 0;
}
if {[cli_get_match_nr $vnode 1 "firewall policy" "srcintf" 0 "\"$ifname\""]} {
        cli_set_errmsg "interface $ifname is used by firewall policy:srcintf"
        return 0
}
if {[cli_get_match_nr $vnode 1 "firewall policy" "dstintf" 0 "\"$ifname\""]} {
         cli_set_errmsg "interface $ifname is used by firewall policy:dstintf"
         return 0
}
if {[cli_get_match_nr $vnode 1 "vpn ipsec phase1" "interface" 0 "\"$ifname\""]} {
         cli_set_errmsg "interface $ifname is used by vpn ipsec phase1:interface"
         return 0
}
if {[cli_get_match_nr $vnode 1 "router static" "device" 0 "\"$ifname\""]} {
        cli_set_errmsg "interface $ifname is used by router static:device"
        return 0
}
if {[cli_get_match_nr $CLI_GLOBAL_NODE 1 "system interface" "interface" 0 "\"$ifname\""]} {
        cli_set_errmsg "interface $ifname is used by system interface:interface"
        return 0
}
return 1
        %}
	"system interface security-groups" = %{
set urgrps [cli_get_value $CLI_CUR_NODE "" "" ""]
set vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vdom"]
if { $vdom eq "" } {
	cli_set_errmsg "system interface vdom not set"
	return 0
}
set vnode [cli_get_vdom_node $vdom]
if { $vnode == 0 } {
	cli_set_errmsg "can not find vdom $vdom"
	return 0
}
foreach urgrp $urgrps {
	set unode [cli_get_node $vnode "user group" $urgrp ""]
	if { $unode == 0 } {
		### User group might be copied from adom level later
		continue;
	}
	set gtype [cli_get_value $unode "" "" "group-type"]
	if { $gtype eq "fsso-service" } {
		cli_set_errmsg "user group $urgrp type can not be fsso-service"
		return 0
	}
}
return 1
	%}
	"system interface security-mode" = %{
set mode [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $mode ne "802.1X" } {
	return 1
}
if { [cli_has_feature "f_caputp_ac"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "switch-vlan"] } {
	return 1
}
if { [cli_has_feature "f_vs_802_1x"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "hard-switch"] } {
	return 1
}
if { [cli_has_feature "f_sw_802_1x"] } {
	set intfname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	if { [cli_feature_value "sw_intf_name"] eq $intfname } {
		return 1
	}
}
cli_set_errmsg "The device does not have support for 802.1X"
return 0
	%}
	"system interface snmp-index" = %{
set idx [cli_get_value $CLI_CUR_NODE "" "" ""]
if {[cli_get_match_nr $CLI_GLOBAL_NODE 1 "system interface" "snmp-index" 0 $idx] > 1} {
	cli_set_errmsg "duplicate"
	return 0
}
return 1
	%}
	"system accprofile" = %{
set profilename [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $profilename eq "" ||
     $profilename eq "FGT_ha_acc_profile" ||
     $profilename eq "prof_fmgr_access" ||
     $profilename eq "super_admin" ||
     $profilename eq "super_admin_readonly" } {
     cli_set_errmsg "invalid profile name"
     return 0
}
return 1
	%}
	
	"firewall proxy-policy internet-service-custom" = %{
set ov [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set nv [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $ov ne $nv && $nv ne "" && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] } {
	### FOS internet_svc_custom_filter(): IPPROTO_TCP
	set cus_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall internet-service-custom" $nv ""]
	if { $cus_node } {
		set cus_entries [cli_get_tbl_list $cus_node "entry"]
		foreach ent $cus_entries {
			if { $ent && [cli_get_value $ent "" "" "protocol"] ne 6 } {
				set id [cli_get_value $CLI_CUR_PARENT_NODE "" "" "policyid"]
				cli_set_errmsg "Only IPPROTO_TCP internet-service-custom can be used in a firewall proxy-policy, policyid: $id"
				return 0
			}
		}
	}
}
return 1
	%}

	"firewall proxy-policy" = %{
namespace import global::wildcard_fqdn_check
if { [cli_get_value $CLI_CUR_NODE "" "" "utm-status"] eq "enable" } {
    if { [cli_get_value $CLI_CUR_NODE "" "" "profile-type"] eq "single" } {
        if { [cli_get_value $CLI_CUR_NODE "" "" "profile-protocol-options"] eq "" } {
            cli_set_errmsg "Attribute 'profile-protocol-options' MUST be set."
            return 0
        }
	}
}
set srcaddr [cli_get_value $CLI_CUR_NODE "" "" "srcaddr"]
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
set srcaddr6 [cli_get_value $CLI_CUR_NODE "" "" "srcaddr6"]
if { $srcaddr eq "" && $srcaddr6 eq "" } {
	set id [cli_get_value $CLI_CUR_NODE "" "" ""]
	cli_set_errmsg "srcaddr/srcaddr6 in proxy policy \"$id\" cannot be empty"
	return 0
}

if { [cli_ver_start 500 6] } {
	if { [cli_is_match $CLI_CUR_NODE 0 "" "proxy" 0 "wanopt"] && ![cli_has_feature "f_wanopt"] } {
		cli_set_errmsg "This device does not support WAN optimization"
		return 0
	}
}
if { [cli_ver_start 600 2] } {
	if { [cli_is_match $CLI_CUR_NODE 0 "" "internet-service" 1 "enable"] &&
	     [cli_is_match $CLI_CUR_NODE 0 "" "proxy" 1 "ftp"] &&
	     [cli_is_match $CLI_CUR_NODE 0 "" "proxy" 1 "ssh"] &&
	     [cli_is_match $CLI_CUR_NODE 0 "" "proxy" 1 "access-proxy"] } {
		if { [cli_get_value $CLI_CUR_NODE "" "" "service"] eq "" } {
			cli_set_errmsg "Must set service."
			return 0
		}
	}
}
if { [cli_ver_start 700 0] } {
	if { [cli_is_match $CLI_CUR_NODE 0 "" "proxy" 0 "access-proxy"] } {
		set access_proxy [cli_get_value $CLI_CUR_NODE "" "" "access-proxy"]
		set access_proxy6 [cli_get_value $CLI_CUR_NODE "" "" "access-proxy6"]
		if { $access_proxy eq ""  && $access_proxy6 eq ""} {
			cli_set_errmsg "Must set access-proxy/access_proxy6 address."
			return 0
		}
	}
}
if { [wildcard_fqdn_check $srcaddr "src" 1] || [wildcard_fqdn_check $dstaddr "dst" 1] } {
	return 0
}
return 1;
	%}
	"firewall explicit-proxy-policy" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" "identity-based"] ne "enable" } {
	if { [cli_get_value $CLI_CUR_NODE "" "" "utm-status"] eq "enable" } {
		if { [cli_get_value $CLI_CUR_NODE "" "" "profile-type"] eq "single" } {
			if { [cli_get_value $CLI_CUR_NODE "" "" "profile-protocol-options"] eq "" } {
				cli_set_errmsg "Attribute 'profile-protocol-options' MUST be set."
				return 0
			}
		}
	}
}

## Mantis 271372
if {[cli_is_match $CLI_CUR_NODE 0 "" "proxy" 0 "wanopt"] || [cli_is_match $CLI_CUR_NODE 0 "" "identity-based" 1 "enable"]} {
	set schedule [cli_get_value $CLI_CUR_NODE "" "" "schedule"]
	if { $schedule == 0 || $schedule eq "" } {
		cli_set_errmsg "Must set schedule."
		return 0
	}
}

## Mantis 0399280
set service [cli_get_value $CLI_CUR_NODE "" "" "service"]
if { ![cli_is_match $CLI_CUR_NODE 0 "" "proxy" 0 "ftp"] && $service eq "" } {
	cli_set_errmsg "Must set service."
	return 0
}

return 1;
	%}

	"firewall explicit-proxy-policy identity-based-policy" = %{
## Mantis 271372
	set schedule [cli_get_value $CLI_CUR_NODE "" "" "schedule"]
	if { $schedule == 0 || $schedule eq "" } {
		cli_set_errmsg "Must set schedule."
		return 0
	}

if { [cli_get_value $CLI_CUR_NODE "" "" "utm-status"] eq "enable" } {
    if { [cli_get_value $CLI_CUR_NODE "" "" "profile-type"] eq "single" } {
        if { [cli_get_value $CLI_CUR_NODE "" "" "profile-protocol-options"] eq "" } {
            cli_set_errmsg "Attribute 'profile-protocol-options' MUST be set."
            return 0
        }
	}
}
return 1
	%}

	"{antivirus webfilter} profile inspection-mode" = %{
set om [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set nm [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $om != "flow-based" && $nm eq "flow-based" } {
	set match ""
	if { $CLI_CUR_PARENT_NAME eq "antivirus profile" } {
		set match "av-profile"
	} elseif { $CLI_CUR_PARENT_NAME eq "webfilter profile" } {
		set match "webfilter-profile"
	}
	if { $match ne "" &&
	     ([cli_is_used $CLI_CUR_PARENT_NODE "firewall explicit-proxy-policy" $match] ||
	      [cli_is_used $CLI_CUR_PARENT_NODE "firewall explicit-proxy-policy identity-based-policy" $match]) } {
		cli_set_errmsg "Profile in use in explicit proxy policy. Cannot change to flow-based"
		return 0
	}
}
return 1
	%}

	"dlp sensor flow-based" = %{
set om [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set nm [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $om eq "disable" && $nm eq "enable" } {
	set match "dlp-sensor"
	if { ([cli_is_used $CLI_CUR_PARENT_NODE "firewall explicit-proxy-policy" $match] ||
	      [cli_is_used $CLI_CUR_PARENT_NODE "firewall explicit-proxy-policy identity-based-policy" $match]) } {
		cli_set_errmsg "Profile in use in explicit proxy policy. Cannot change to flow-based"
		return 0
	}
}
return 1
	%}

	"firewall policy service" = %{
namespace import global::set_rep_dst
if { [cli_ver_start 600 2] } {
	if { [set_rep_dst $CLI_CUR_PARENT_NODE] } {
		return 1
	}
}
set service [cli_get_value $CLI_CUR_NODE "" "" ""]
set is [cli_get_value $CLI_CUR_PARENT_NODE "" "" "internet-service"]
if { $is ne "enable" && $service eq "" } {
	set id [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
	cli_set_errmsg "service in Policy \"$id\" cannot be empty."
	return 0
}
return 1
	%}

	"firewall policy schedule" = %{
namespace import global::ngfw_mode_policy
if { [cli_branchpt_start 600 1545] && [ngfw_mode_policy] } {
	return 1
}
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 343] && [is_hyperscale_activated] } {
       return 1
}
set schedule [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $schedule eq "" } {
	set id [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
	cli_set_errmsg "schedule in Policy \"$id\" cannot be empty."
	return 0
}
return 1
	%}

	"firewall policy auth-cert" = %{
set auth [cli_get_value $CLI_CUR_NODE "" "" ""]
namespace import global::auth_cert_not_exist
if { [auth_cert_not_exist $auth] } {
	cli_set_errmsg "Certificate $auth does not exist"
	return 0
}
return 1
	%}

        "firewall policy endpoint-check" = %{
set check [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $check eq "enable" } {
        if {[cli_get_value $CLI_CUR_VDOM_NODE "user setting" "" "auth-secure-http"] eq "enable"} {
                cli_set_errmsg "Cannot enable forticlient-check because authentication is redirected to https"
                return 0
        }
}
return 1
        %}

	"firewall policy av-profile" = %{
if { [cli_ver_start 500 2] } {
} elseif { ![cli_has_feature "f_single_avdb"] } {
} else {
	set avprof [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $avprof ne "" } {
		set avsets [cli_get_node $CLI_CUR_VDOM_NODE "antivirus settings" "" ""]
		if { $avsets } {
			set defaultdb [cli_get_value $avsets "" "" "default-db"]
		} else {
			set defaultdb [cli_get_defvalue "antivirus settings" "default-db"]
		}
		set inspectmode [cli_get_value $CLI_CUR_VDOM_NODE "antivirus profile" $avprof "inspection-mode"]
		if { $defaultdb eq "extended" && $inspectmode eq "flow-based" } {
			cli_set_errmsg "Flow-based AntiVirus database is not available when the extended AntiVirus database is in use"
			return 0
		}
	}
}
return 1
	%}

        "firewall policy endpoint-keepalive-interface" = %{
set intf [cli_get_value $CLI_CUR_NODE "" "" ""]
set intf [string trim $intf \"]
if { $intf eq "any" || $intf eq "ftp-proxy" || $intf eq "web-proxy" } {
	cli_set_errmsg "endpoint-keepalive-interface value is invalid."
	return 0
}
return 1
        %}

	"firewall sniff-interface-policy" = %{
if {[expr {[cli_get_value $CLI_CUR_NODE "" "" "interface"] eq ""}]} {
	cli_set_errmsg "invalid interface"
	return 0
}
set intf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $intf ""]
if {[expr {[cli_get_value $intf_node "" "" "ips-sniffer-mode"] ne "enable"}]} {
	cli_set_errmsg "invalid sniffer mode interface "
	return 0
}
return 1
        %}

        "firewall {interface-policy DoS-policy DoS-policy6}" = %{
namespace import global::wildcard_fqdn_check
set intf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
if { $intf eq "" } {
        cli_set_errmsg "invalid interface"
        return 0
}

if { $intf eq "any" || $intf eq "\"any\"" } {
        cli_set_errmsg "interface 'any' cannot be found in datasource"
        return 0
}

set srcaddr [cli_get_value $CLI_CUR_NODE "" "" "srcaddr"]
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
set service [cli_get_value $CLI_CUR_NODE "" "" "service"]
if { [cli_ver_start 600 2] } {
	if { $srcaddr eq "" } {
		cli_set_errmsg "srcaddr MUST be set"
        return 0
	}
	if { $dstaddr eq "" } {
		cli_set_errmsg "dstaddr MUST be set"
        return 0
	}
	if { $service eq "" } {
		cli_set_errmsg "service MUST be set"
        return 0
	}
}
if { $CLI_CUR_NODE_NAME eq "firewall DoS-policy" } {
	if { [wildcard_fqdn_check $srcaddr "src" 0] || [wildcard_fqdn_check $dstaddr "dst" 0]} {
			return 0
	}
} elseif { $CLI_CUR_NODE_NAME eq "firewall interface-policy" } {
	if { [cli_branchpt_start 600 1010] } {
		if { [wildcard_fqdn_check $srcaddr "src" 0] || [wildcard_fqdn_check $dstaddr "dst" 0]} {
				return 0
		}
	}
}
return 1
	%}

        "firewall {interface-policy6}" = %{
set intf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
if { $intf eq "" } {
        cli_set_errmsg "invalid interface"
        return 0
}

if { $intf eq "any" || $intf eq "\"any\"" } {
        cli_set_errmsg "interface 'any' cannot be found in datasource"
        return 0
}
set srcaddr6 [cli_get_value $CLI_CUR_NODE "" "" "srcaddr6"]
set dstaddr6 [cli_get_value $CLI_CUR_NODE "" "" "dstaddr6"]
set service6 [cli_get_value $CLI_CUR_NODE "" "" "service6"]
if { [cli_ver_start 600 2] } {
	if { $srcaddr6 eq "" } {
		cli_set_errmsg "srcaddr6 MUST be set"
        return 0
	}
	if { $dstaddr6 eq "" } {
		cli_set_errmsg "dstaddr6 MUST be set"
        return 0
	}
	if { $service6 eq "" } {
		cli_set_errmsg "service6 MUST be set"
        return 0
	}
}
return 1
	%}

        "firewall address" = %{
namespace import global::check_fw_address
### firewall address name check ###
set ipname [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $ipname eq ""} {
    cli_set_errmsg "empty value"
    return 0
}
set grpnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp" $ipname ""]
if { 0 != $grpnode } {
          cli_set_errmsg "entry exists"
          return 0
}
set vipnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $ipname ""]
if { 0 != $vipnode } {
          cli_set_errmsg "entry exists"
          return 0
}
set vipgrpnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall vipgrp" $ipname ""]
if { 0 != $vipgrpnode } {
          cli_set_errmsg "entry exists"
          return 0
}
set fqdnnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall wildcard-fqdn custom" $ipname ""]
if { 0 != $fqdnnode } {
          cli_set_errmsg "Name '$ipname' conflict: 'wildcard FQDN custom' and 'address' cannot be the same name."
          return 0
}
### firewall address format ###
set addr_type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set addr_type_org [cli_get_org_value $CLI_CUR_NODE "" "" "type"]
if {$CLI_ACT ne "add" && $addr_type ne $addr_type_org} {
	if { [cli_ver_start 500 2] } {
		if { $type ne "ipmask" && ([cli_get_value $CLI_CUR_NODE "" "" "allow-routing"] eq "enable") } {
			cli_set_errmsg "cannot change the type if it is enabled for routing"
			return 0
		}
	} else {
	    cli_set_errmsg "cannot change address type"
	    return 0
	}
}
# cannot edit the subnet of an existing interface-subnet in device db
# the subnet can only be updated by the VLAN nodeact
set addr_subnet [cli_get_value $CLI_CUR_NODE "" "" "subnet"]
set addr_subnet_org [cli_get_org_value $CLI_CUR_NODE "" "" "subnet"]
if {![string match "*override*" [cli_get_clisrc]] && $CLI_ACT eq "edit" && $addr_type eq "interface-subnet" && $addr_subnet ne $addr_subnet_org} {
	cli_set_errmsg "cannot edit the subnet if the type is 'interface-subnet'. it will be automatically updated with the interface."
	return 0
}
if { $addr_type eq "interface-subnet" } {
	set intf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
	if { $intf eq "" } {
		cli_set_errmsg "Attribute 'interface' MUST be set."
		return 0
	}
}
return [check_fw_address $CLI_CUR_NODE $addr_type]
     %}

      "firewall multicast-address" = %{
namespace import global::check_fw_multicast_address
return [check_fw_multicast_address $CLI_CUR_NODE]
      %}

### firewall address interface ###
### (address,interface) in address must be consistent with the policy
      "firewall address associated-interface" = %{
if {$CLI_IS_CLONE_CAT == 1} {
	return 1
}

if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "interface-subnet"] } {
    return 1
}

set ipname [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
set ipinterface [cli_get_value $CLI_CUR_NODE "" "" ""]
set ipinterface_org [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set intf_new [string trim $ipinterface \"]
set intf_old [string trim $ipinterface_org \"]

if { $intf_new == $intf_old || $intf_old eq "" } {
	return 1
}

if {$CLI_ACT ne "add" && [cli_is_referenced $CLI_CUR_PARENT_NODE]} {
	cli_set_errmsg "firewall address $ipname is used"
	return 0
}
if {$intf_new eq "any"} {
	return 1
}
if {[cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall policy" "srcaddr" 0 $ipname]} {
  if { 0 == [cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall policy" "srcintf" 0 $ipinterface] } {
       cli_set_errmsg "interface binding contradiction"
       return 0
   }
}
if {[cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall multicast-policy" "srcaddr" 0 $ipname]} {
  if { 0 == [cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall multicast-policy" "srcintf" 0 $ipinterface] } {
       cli_set_errmsg "interface binding contradiction"
       return 0
   }
}
if {[cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall policy" "dstaddr" 0 $ipname]} {
  if { 0 == [cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall policy" "dstintf" 0 $ipinterface] } {
       cli_set_errmsg "interface binding contradiction"
       return 0
   }
}

return 1
      %}

      "firewall addrgrp" = %{
namespace import global::check_recur_group_members
set grpname [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $grpname eq ""} {
    cli_set_errmsg "empty value"
    return 0
}
set ipnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $grpname ""]
if { 0 != $ipnode } {
          cli_set_errmsg "entry exists"
          return 0
}
set vipnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $grpname ""]
if { 0 != $vipnode } {
          cli_set_errmsg "entry exists"
          return 0
}
set vipgrpnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall vipgrp" $grpname ""]
if { 0 != $vipgrpnode } {
          cli_set_errmsg "entry exists"
          return 0
}
set grpmember [cli_get_value $CLI_CUR_NODE "" "" "member" 1]
if { ![cli_ver_start 700 2] } {
if { $grpmember eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
}
set grplist [list "$grpname"]
if { [check_recur_group_members $grplist "firewall addrgrp" $grpmember $CLI_CUR_VDOM_NODE] eq 0 } {
	return 0
}
proc addrgrp_intf_check { member prtnode vdom intfarray } {
  upvar $intfarray intfs
  foreach m $member {
        set ipnode [cli_get_node $vdom "firewall address" $m ""]
        if { 0 != $ipnode } {
                set addr_intf [cli_get_value $ipnode "" ""  "associated-interface"]
		if {[string index $addr_intf 0] != "\""} {
			set addr_intf \"$addr_intf\"
		}
                if {$addr_intf ne "" && $addr_intf ne "\"any\""} {
                        set intfs($addr_intf) 1
                }
        } else {
                set subgrp [cli_get_value $vdom "firewall addrgrp" $m "member" 1]
                addrgrp_intf_check $subgrp $prtnode $vdom intfs
        }
  }
}
set grpmember [cli_get_value $CLI_CUR_NODE "" "" "member" 1]
if { ![cli_ver_start 700 2] } {
if { $grpmember eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
}
array unset intf_array
addrgrp_intf_check $grpmember $CLI_CUR_NODE $CLI_CUR_VDOM_NODE intf_array

if {[array size intf_array] > 1} {
        cli_set_errmsg "address"
        return 0
}
return 1
       %}

       "firewall vip" = %{
if {$CLI_IS_CLONE_CAT == 1} {
	return 1
}
set vipname [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$vipname eq ""} {
    cli_set_errmsg "empty value"
    return 0
}
if {$CLI_ACT eq "add"} {
	set ntype [cli_get_value $CLI_CUR_NODE "" "" "type"]
	if { $ntype eq "server-load-balance" } {
		set vdom_list [cli_get_tbl_list $CLI_VDOM_NODE ""]
		if {$vdom_list eq ""} {
			set vdom_list [list $CLI_CUR_VDOM_NODE]
		}
		set cnt 0
		foreach e $vdom_list {
			set cnt [expr ([cli_get_match_nr $e 1 "firewall vip" "type" 0 "server-load-balance"] + $cnt)]
		}
		set sz [cli_feature_value "max_vip_vs"]
		if { $sz > 0 && $cnt > $sz } {
			cli_set_errmsg "Virtual server limit reached! Limit is $sz"
			return 0
		}
		set server_type [cli_get_value $CLI_CUR_NODE "" "" "server-type"]
		if { $server_type eq "" } {
			cli_set_errmsg "node_check_object fail! Attribute server-type must be set"
			return 0
		}
	}

	if {($vipname eq "FGh_FtMngr") || ($vipname eq "FGh_FtiLog1") || ($vipname eq	"FGh_FtiLog2") || ($vipname eq "FGh_FtiLog3")} {
	    cli_set_errmsg "internal error"
	    return 0
	}
	set ipnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $vipname ""]
	if { 0 != $ipnode } {
	          cli_set_errmsg "entry exists"
	          return 0
	}
	set grpnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp" $vipname ""]
	if { 0 != $grpnode } {
	          cli_set_errmsg "entry exists"
	          return 0
	}
	set vipgrpnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall vipgrp" $vipname ""]
	if { 0 != $vipgrpnode } {
	          cli_set_errmsg "entry exists"
	          return 0
	}
	if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $vipname] > 1} {
		cli_set_errmsg "entry exists"
		return 0
	}
} else {
	set ntype [cli_get_value $CLI_CUR_NODE "" "" "type"]
	set otype [cli_get_org_value $CLI_CUR_NODE "" "" "type"]
	if {[string compare $ntype $otype]} {
		cli_set_errmsg "invalid value"
		return 0
	}
}

set intf [cli_get_value $CLI_CUR_NODE "" "" "extintf"]
set intf [string trim $intf \"]
if {$intf eq ""} {
	cli_set_errmsg "firewall vip $vipname: invalid extintf"
	return 0
}

set viptype [cli_get_value $CLI_CUR_NODE "" "" "type"]
set extip [cli_get_value $CLI_CUR_NODE "" "" "extip"]
if {($intf == "\"any\"") || ($intf == "any")} {
	if { $viptype eq "fqdn" } {
		set extaddr [cli_get_value $CLI_CUR_NODE "" "" "extaddr"]
		if {$extip == "0.0.0.0" && ($extaddr == 0 || $extaddr eq "")} {
			cli_set_errmsg "firewall vip $vipname: when extintf is $intf and extaddr is null, extip $extip is invalid"
			return 0
		}
	} else {
		if {$extip == "0.0.0.0"} {
			cli_set_errmsg "firewall vip $vipname: when extintf is $intf, extip $extip is invalid"
			return 0
		}
	}
}

if {$intf != "any" || ![cli_branchpt_start 400 233]} {
	if {[cli_get_node $CLI_GLOBAL_NODE "system interface" $intf ""] == 0} {
		cli_set_errmsg "system interface \"$intf\" not exist"
		return 0
	}
}

if { $viptype eq "access-proxy" } {
	set scert [cli_get_value $CLI_CUR_NODE "" "" "ssl-certificate"]
	if { $scert eq "" } {
		cli_set_errmsg "Attribute 'ssl-certificate' MUST be set."
		return 0
	}
}

# Mantis 98554: should not change extintf if used by policy
set previntf [cli_get_org_value $CLI_CUR_NODE "" "" "extintf"]
set previntf [string trim $previntf \"]
if {($previntf != $intf) &&
    ([cli_is_used $CLI_CUR_NODE "firewall policy" "dstaddr"] ||
	 [cli_is_used $CLI_CUR_NODE "firewall policy" "srcaddr"])} {
         cli_set_errmsg "extintf is changed and vip $vipname is used by policy"
         return 0
}

if {$extip != "0.0.0.0"} {
	set sys_settings [cli_get_node $CLI_CUR_VDOM_NODE "system settings" "" ""]
	set central_nat [cli_get_value $sys_settings "" "" "central-nat"]
	if { $central_nat ne "enable" && ![cli_ver_start 700 2] && [cli_check_overlapvip $CLI_CUR_NODE] } {
		cli_set_errmsg "conflict value"
		return 0
	}
}

if { $CLI_CUR_NODE_NAME ne "dynamic_mapping" } {
	set nat44 [cli_get_value $CLI_CUR_NODE "" "" "nat44"]
	if { $nat44 eq "enable" } {
		set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
		if { $type eq "static-nat" || $type eq "load-balance" || $type eq "dns-translation" } {
			set mappedip [cli_get_value $CLI_CUR_NODE "" "" "mappedip"]
			if { $mappedip eq "" } {
				cli_set_errmsg "mappedip must be set when nat44 is enabled."
				return 0
			}
		}
	}
	set nat46 [cli_get_value $CLI_CUR_NODE "" "" "nat46"]
	if { $nat46 eq "enable" } {
		set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
		if { $type eq "static-nat" || $type eq "load-balance" || $type eq "dns-translation" } {
			set ipv6mappedip [cli_get_value $CLI_CUR_NODE "" "" "ipv6-mappedip"]
			if { $ipv6mappedip eq "" } {
				cli_set_errmsg "ipv6-mappedip must be set when nat46 is enabled."
				return 0
			}
		}
	}
}
return 1
      %}

	"firewall vip mappedip" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "server-load-balance" || $type eq "fqdn" } {
	return 1
}
set ipranges [cli_get_value $CLI_CUR_NODE "" "" ""]
foreach iprange $ipranges {
	set iprange [string trim $iprange \"]
	set iprangetrim [string map {" " ""} $iprange]
	namespace import global::vip_mappedip_invalid
	if { $iprange ne $iprangetrim || [vip_mappedip_invalid $iprange] } {
		set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
		cli_set_errmsg "Firewall VIP \"$name\" mappedip \"$iprange\" is invalid"
		return 0
	}
}
return 1
%}
           "firewall vip mappedport" = %{
if { [cli_ver_start 500 2] } {
	set proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
	if { $proto eq "icmp" } {
		return 1
	}
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "portforward"] eq "disable" } {
        return 1
}
set portrange [cli_get_value $CLI_CUR_NODE "" "" ""]
set result [regexp -all {\d{1,5}} $portrange end_port]
if {1 == $result} {
	set start_port $end_port
} else {
	if { 2 == $result } {
	    regexp {\d{1,5}} $portrange start_port
	} else {
	    cli_set_errmsg "invalid value"
	    return 0
	}
}
if { ($start_port > $end_port) || ($end_port > 65535) || ($start_port < 1) } {
    cli_set_errmsg "beyond the boundary"
    return 0
}
return 1
%}

	"firewall vip realservers" = %{
namespace import global::cli_invalid_ipv4
namespace import global::cli_invalid_ipv6
set port [cli_get_value $CLI_CUR_NODE "" "" "port"]
set server_type [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "server-type"]
if { $server_type ne "ip" } {
if { $port < 1 || $port > 65535 } {
	cli_set_errmsg "The realserver port range should be 1-65535"
	return 0
}
}
set rtype [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { ([cli_ver_start 600 4] && $rtype eq "ip") || ![cli_ver_start 600 4] } {
	set nat46 [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "nat46"]
	set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
	if { $ip eq "0.0.0.0" || $ip eq "255.255.255.255" } {
		cli_set_errmsg "Realserver IP cannot be 0.0.0.0 or 255.255.255.255"
		return 0
	}

	if { [cli_invalid_ipv4 $ip] && [cli_invalid_ipv6 $ip] } {
		cli_set_errmsg "Invalid Realserver IP ($ip)"
		return 0
	}

	if { [string first ":" $ip] == -1 } {
		# ipv4
		if { $nat46 eq "enable" } {
			cli_set_errmsg "ipv4 cannot be used when nat46 is enable"
			return 0
		}
	} else {
		# ipv6
		if { $nat46 eq "disable" } {
			cli_set_errmsg "ipv6 cannot be used when nat46 is disable"
			return 0
		}
		if { [string match "*upgrade*" [cli_get_clisrc]] } {
			return 1
		}
		set l [split $ip :]
		set len [llength $l]
		set period [string first "." $ip]
		set zero_count 0
		for {set i 0} {$i < $len} {incr i} {
			set segment [lindex $l $i]
			if { $i == 0 && [string compare -nocase -length 2 $segment "ff"] eq 0 } {
				cli_set_errmsg "Realserver IP cannot be any or multicast."
				return 0
			}
			if { $segment == 0 || $segment eq "" } {
				incr zero_count
				continue
			}
			if { $i eq ($len - 1) && ($period != -1 && ($zero_count eq ($len - 1)) && $segment eq "0.0.0.0" || $zero_count eq $len) } {
				cli_set_errmsg "Realserver IP cannot be any or multicast."
				return 0
			}
		}
		if { $zero_count eq $len } {
			cli_set_errmsg "Realserver IP cannot be any or multicast."
			return 0
		}
	}

	set client_ip [cli_get_value $CLI_CUR_NODE "" "" "client-ip"]
	set is_range [string first "-" $client_ip]
	if { $is_range != -1 } {
		set client_ip_range [split $client_ip -]
	}
	if {
		!($client_ip eq "" || $client_ip == 0) && ((($is_range == -1 && [cli_invalid_ipv4 $client_ip]) || ($is_range != -1 && ([cli_invalid_ipv4 [lindex $client_ip_range 0]] || [cli_invalid_ipv4 [lindex $client_ip_range 1]]))))
	} {
		cli_set_errmsg "Invalid client-ip range $client_ip"
		return 0
	}

	if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "ip" 0 $ip] > 1} {
		if { ![cli_ver_start 600 4] } {
			cli_set_errmsg "Duplicate realserver ip found: ip-$ip"
			return 0
		}
		set vtype [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "type"]
		set ldbm [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "ldb-method"]
		if { $vtype ne "server-load-balance" || $ldbm ne "http-host"} {
			cli_set_errmsg "Duplicate realserver ip found: ip-$ip"
			return 0
		}
		set http_host [cli_get_value $CLI_CUR_NODE "" "" "http-host"]
		set list [cli_get_match_list $CLI_CUR_PARENT_NODE 1 "" "ip" 0 $ip]
		foreach e $list {
			if { ![cli_if_same_node $e $CLI_CUR_NODE] } {
				set ahttp_host [cli_get_value $e "" "" "http-host"]
				if { $http_host eq $ahttp_host } {
					cli_set_errmsg "Duplicate realserver ip found: ip-$ip"
					return 0
				}
			}
		}
	}
}
set interval [cli_get_value $CLI_CUR_NODE "" "" "holddown-interval"]
if { $interval ne "" && ($interval < 30 || $interval > 65535)} {
        cli_set_errmsg "invalid holddown interval"
        return 0
}
return 1
	%}

	"firewall vip6 realservers" = %{
namespace import global::cli_invalid_ipv4
namespace import global::cli_invalid_ipv6
set port [cli_get_value $CLI_CUR_NODE "" "" "port"]
set server_type [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "server-type"]
if { $server_type ne "ip" } {
if { $port < 1 || $port > 65535 } {
	cli_set_errmsg "The realserver port range should be 1-65535"
	return 0
}
}
set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
set nat64 [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "nat64"]

if { $ip eq "0.0.0.0" || $ip eq "255.255.255.255" } {
	cli_set_errmsg "Realserver IP cannot be 0.0.0.0 or 255.255.255.255"
	return 0
}
if { [cli_invalid_ipv4 $ip] && [cli_invalid_ipv6 $ip] } {
	cli_set_errmsg "Invalid Realserver IP ($ip)"
	return 0
}

if { [string first ":" $ip] == -1 } {
	# ipv4
	if { $nat64 eq "disable" } {
		cli_set_errmsg "ipv4 cannot be used when nat64 is disable"
		return 0
	}
} else {
	# ipv6
	if { $nat64 eq "enable" } {
		cli_set_errmsg "ipv6 cannot be used when nat64 is enable"
		return 0
	}
	if { [string match "*upgrade*" [cli_get_clisrc]] } {
		return 1
	}
	set l [split $ip :]
	set len [llength $l]
	set period [string first "." $ip]
	set zero_count 0
	for {set i 0} {$i < $len} {incr i} {
		set segment [lindex $l $i]
		if { $i == 0 && [string compare -nocase -length 2 $segment "ff"] eq 0 } {
			cli_set_errmsg "Realserver IP cannot be any or multicast."
			return 0
		}
		if { $segment == 0 || $segment eq "" } {
			incr zero_count
			continue
		}
		if { $i eq ($len - 1) && $period != -1 && ($zero_count eq ($len - 1)) && $segment eq "0.0.0.0" } {
			cli_set_errmsg "Realserver IP cannot be any or multicast."
			return 0
		}
	}
	if { $zero_count eq $len } {
		cli_set_errmsg "Realserver IP cannot be any or multicast."
		return 0
	}
}

set client_ip [cli_get_value $CLI_CUR_NODE "" "" "client-ip"]
set is_range [string first "-" $client_ip]
if { $is_range != -1 } {
	set client_ip_range [split $client_ip -]
}
if {
	!($client_ip eq "" || $client_ip == 0) && (($is_range == -1 && [cli_invalid_ipv6 $client_ip]) || ($is_range != -1 && ([cli_invalid_ipv6 [lindex $client_ip_range 0]] || [cli_invalid_ipv6 [lindex $client_ip_range 1]])))
} {
	cli_set_errmsg "Invalid client-ip range $client_ip"
	return 0
}
return 1
	%}
	"firewall vip realservers monitor" = %{
set lmonitor [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [llength $lmonitor] > 5 } {
	cli_set_errmsg "too many monitors"
	return 0
}
foreach m $lmonitor {
	set match 0
	foreach n $lmonitor {
		if { $m eq $n } {
			incr match
		}

		if {$match > 1} {
			cli_set_errmsg "duplicate monitors found"
			return 0
		}
	}
}
return 1
	%}

	"firewall vip src-filter" = %{
namespace import global::iprange_invalid
namespace import global::iprange_invalid2
namespace import global::ip_invalid

set filters [cli_get_value $CLI_CUR_NODE "" "" ""]
set newfilters [lsort -unique $filters]
if { [llength $newfilters] ne [llength $filters] } {
	cli_set_errmsg "duplicated filter entry"
	return 0
}

foreach filter $filters {
	set filter [string trim $filter \"]
	if { $filter eq "0.0.0.0" } {
		cli_set_errmsg "invalid ip: $filter"
		return 0
	} elseif { [string first "/" $filter] != -1 } {
		set ip [string range $filter 0 [expr {[string first "/" $filter] - 1}]]
		set mask [string range $filter [expr {[string first "/" $filter] + 1}] end]
		if { $mask < 0 || $mask > 32 || [ip_invalid $ip 0] eq 1 } {
			cli_set_errmsg "invalid ip subnet format: $filter"
			return 0
		}
	} elseif { [string first "-" $filter] != -1 } {
		if { [iprange_invalid2 $filter 0] eq 1 } {
			cli_set_errmsg "invalid ip range format: $filter"
			return 0
		}
	} else {
		if { [ip_invalid $filter 0] eq 1 } {
			cli_set_errmsg "invalid ip: $filter"
			return 0
		}
	}
}
return 1
	%}

	"firewall vipgrp6" = %{
set member [cli_get_value $CLI_CUR_NODE "" "" "member"]
if { $member eq "" } {
	cli_set_errmsg "Attribute 'member' MUST be set."
	return 0
}
foreach m $member {
	set m [string trim $m \"]
	if {$m eq ""} {
	        cli_set_errmsg "invalid member"
	        return 0
	}
	set m_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip6" $m ""]
	if { 0 == $m_node } {
	        cli_set_errmsg "invalid member"
	        return 0
	}
}
return 1
	%}

	"firewall vipgrp46" = %{
set member [cli_get_value $CLI_CUR_NODE "" "" "member"]
if { $member eq "" } {
	cli_set_errmsg "Attribute 'member' MUST be set."
	return 0
}
foreach m $member {
	set m [string trim $m \"]
	if {$m eq ""} {
	        cli_set_errmsg "invalid member"
	        return 0
	}
	set m_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip46" $m ""]
	if { 0 == $m_node } {
	        cli_set_errmsg "invalid member"
	        return 0
	}
}
return 1
	%}

	"firewall vipgrp64" = %{
set member [cli_get_value $CLI_CUR_NODE "" "" "member"]
if { $member eq "" } {
	cli_set_errmsg "Attribute 'member' MUST be set."
	return 0
}
foreach m $member {
	set m [string trim $m \"]
	if {$m eq ""} {
                cli_set_errmsg "invalid member"
                return 0
	}
	set m_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip64" $m ""]
        if { 0 == $m_node } {
                cli_set_errmsg "invalid member"
                return 0
	}
}
return 1
	%}

	"firewall vipgrp" = %{
if {[cli_get_value $CLI_CUR_NODE "" "" "member"] eq ""} {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
if {[cli_get_value $CLI_CUR_NODE "" "" "interface"] eq ""} {
        cli_set_errmsg "empty interface is not allowed"
        return 0
}
if {$CLI_ACT eq "add"} {
	set vipgrp [cli_get_value $CLI_CUR_NODE "" "" ""]
	set ipnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $vipgrp ""]
	if { 0 != $ipnode } {
		cli_set_errmsg "entry exists"
		return 0
	}
	set grpnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp" $vipgrp ""]
	if { 0 != $grpnode } {
		cli_set_errmsg "entry exists"
		return 0
	}
	set vipnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $vipgrp ""]
	if { 0 != $vipnode } {
		cli_set_errmsg "entry exists"
		return 0
	}
	if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $vipgrp] > 1} {
		cli_set_errmsg "entry exists"
		return 0
	}
}
return 1
      %}

        "firewall vipgrp member" = %{
set vipmember [cli_get_value $CLI_CUR_NODE "" "" "" 1]
set intf [cli_get_value $CLI_CUR_PARENT_NODE "" "" "interface"]
set intf [string trim $intf \"]
foreach m $vipmember {
	set m [string trim $m \"]
	set vipnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $m ""]
        if { ( 0 == $vipnode) } {
                cli_set_errmsg "invalid value"
                return 0
        }
	set viptype [cli_get_value $CLI_CUR_VDOM_NODE "firewall vip" $m "type"]
	if { $viptype eq "server-load-balance" } {
		cli_set_errmsg "invalid VIP member type"
		return 0
	}
	set port [cli_get_value $CLI_CUR_VDOM_NODE "firewall vip" $m "extintf"]
	set port [string trim $port \"]
	if { ( $intf ne $port) } {
                if {$intf != "any" && $port != "any" || ![cli_branchpt_start 400 233]} {
                        set found 0
                        set d [cli_get_node $CLI_CUR_VDOM_NODE "device dynamic interface" $intf ""]
                        if { $d } {
                                set local [cli_get_value $d "" "" "local-intf"]
                                foreach lm $local {
                                        set lm [string trim $lm \"]
                                        if { $lm eq $port } {
                                                set found 1
                                                break
                                        }
                                }
                        }
                        if { !$found } {
                                cli_set_errmsg "vipgrp interface \"$intf\" not match with vip extintf \"$port\""
                                return 0
                        }
                }
		if { $port != "any" && [cli_ver_start 600 0] } {
			cli_set_errmsg "vipgrp interface \"$intf\" not match with vip extintf \"$port\""
			return 0
		}
	}
}
return 1
      %}

       "firewall vipgrp interface" = %{
if {$CLI_ACT ne "add"} {
	set intf [cli_get_value $CLI_CUR_NODE "" "" ""]
	set grpname [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
	if {[cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall policy" "dstaddr" 0 $grpname]} {
		cli_set_errmsg "vipgrp $grpname is used by firewall policy:dstaddr"
		return 0
	}
	set vipmember [cli_get_value $CLI_CUR_PARENT_NODE "" "" "member"]
	if {$vipmember eq ""} {
		cli_set_errmsg "member is empty"
		return 0
	}
}
return 1
       %}

       "ips group rule exempt-ip" = %{
set src [cli_get_value $CLI_CUR_NODE "" "" "src-ip"]
set dst [cli_get_value $CLI_CUR_NODE "" "" "dst-ip"]

proc ipadressAndMaskCheck {addr} {
  regsub -all {/} $addr " " addr
  if { 2 != [llength $addr] } {
    return 0
  }

set ipList [split [lindex $addr 0] .]
set maskList [split [lindex $addr 1] .]
# mask can be one integer like 24, or ip address format like 255.255.0.0
if { (1 != [llength $maskList]) && ( 4 != [llength $maskList]) } {
    return 0
}
# mask is one integer,which will be converted into ip address format
if { 1 == [llength $maskList] } {
     set value [lindex $maskList 0]
     if { ($value < 1) || ($value > 32) } {
       cli_set_errmsg "invalid ips data"
       return 0
     }
     set base [expr ($value / 8)]
     set offset [expr ($value % 8)]
     set maskList [list]
     for { set i 0 } { $i < $base } {incr i} {
       lappend maskList 255
     }
     if { $offset > 0 } {
       lappend maskList [expr (pow(2,$offset)-1)*pow(2,8-offset)]
     }
     if {[llength $maskList] < 4} {
       for {set i [expr [llength $maskList]+1]} {$i <= 4} {incr i} {
         lappend maskList 0
       }
     }
}
set ipaddr 0
for {set i 0} { $i < 4} {incr i} {
  set ip [lindex $ipList $i]
  set mask [lindex $maskList $i]
  if { 0 == $ipaddr} {
    set ipaddr [expr $ip & $mask]
  } else {
    set ipaddr [expr ($ipaddr << 8)]
    set ipaddr [expr ($ipaddr + ($ip & $mask))]
  }
}
if { (0 == $ipaddr) || (-1 == $ipaddr) } {
   return 0
}
return 1
}
if { (0 == [ipadressAndMaskCheck $src]) && (0 == [ipadressAndMaskCheck $dst]) } {
   cli_set_errmsg "invalid ips data"
   return 0
}

return 1
       %}
      "ips custom" = %{
set tag [cli_get_value $CLI_CUR_NODE "" "" ""]
set signature [cli_get_value $CLI_CUR_NODE "" "" "signature"]
set signature [string trim $signature \"]
if {[cli_check_ips_custom_rule $signature $tag]} {
	cli_set_errmsg "invalid ips data"
	return 0
}
proc ips_cus_get_attr_value { attr sig } {
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
set attack_key "--attack_id "
set attack_id [ips_cus_get_attr_value $attack_key $signature]
if {$attack_id ne ""} {
        if { $attack_id < 1000 || $attack_id > 9999 } {
                cli_set_errmsg "invalid ips data"
                return 0
        }
        set nodelist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "ips custom"]
	set total_matched 0
        foreach node $nodelist {
		set this_sig [cli_get_value $node "" "" "signature"]
		set this_id [ips_cus_get_attr_value $attack_key $this_sig]
		if {($this_id ne "") && ($this_id == $attack_id)} {
			incr total_matched
			if {$total_matched > 1} {
			cli_set_errmsg "invalid ips data"
			return 0
			}
		}
        }
}
return 1
%}
	"log memory global-setting" = %{
set first [cli_get_value $CLI_CUR_NODE "" "" "full-first-warning-threshold"]
set second [cli_get_value $CLI_CUR_NODE "" "" "full-second-warning-threshold"]
set final [cli_get_value $CLI_CUR_NODE "" "" "full-final-warning-threshold"]
if {$first < $second && $second < $final} {
} else {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"log custom-field" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set value [cli_get_value $CLI_CUR_NODE "" "" "value"]
if {$name eq "" || $value eq ""} {
	cli_set_errmsg "empty value"
	return 0
}

set name [string trim $name \"]
if {[regexp {^([a-zA-Z])([0-9a-zA-Z_]*)$} $name] == 0} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"log fortiguard setting" = %{
if { [cli_ver_start 500 0] } {
} else {
	set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
	if {$status eq "enable"} {
		set log_fortilog [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "status"]
		set log_fortilog2 [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer2 setting" "" "status"]
		set log_fortilog3 [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer3 setting" "" "status"]
		set sys_fortilog [cli_get_value $CLI_GLOBAL_NODE "system fortianalyzer" "" "status"]
		set sys_fortilog2 [cli_get_value $CLI_GLOBAL_NODE "system fortianalyzer2" "" "status"]
		set sys_fortilog3 [cli_get_value $CLI_GLOBAL_NODE "system fortianalyzer3" "" "status"]
		if {$log_fortilog eq "enable" || $log_fortilog2 eq "enable" || $log_fortilog3 eq "enable" ||
		    $sys_fortilog eq "enable" || $sys_fortilog2 eq "enable" || $sys_fortilog3 eq "enable"} {
			cli_set_errmsg "FortiGuard Analysis Service is not available when FortiAnalyzer is enabled"
			return 0
		}
	}
}
return 1
	%}
	"log {fortianalyzer fortianalyzer2 fortianalyzer3} {setting}" = %{
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
set ipv6addr 0
if {$status eq "enable"} {
	if { [cli_ver_start 500 0] } {
	} else {
		set log_ftgd [cli_get_value $CLI_GLOBAL_NODE "log fortiguard setting" "" "status"]
		if {$log_ftgd eq "enable"} {
			cli_set_errmsg "FortiAnalyzer is not available when FortiGuard Analysis Service is enabled"
			return 0
		}
	}
	set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
	set server [string trim $server \"]
	if { $server eq "" || $server eq "0.0.0.0" } {
		cli_set_errmsg "Please set server ip address"
		return 0
	}
	if { [cli_ver_start 500 4] } {
		if { $server eq "::" } {
			cli_set_errmsg "Please set server ip address"
			return 0
		}
		if { [string first ":" $server] > -1 } {
			set ipv6addr 1
		}
	}
	if { $ipv6addr eq 0 && ![cli_ver_start 500 6] } {
		namespace import global::ip_class
		set class [ip_class $server]
		if { !($class eq "A" || $class eq "B" || $class eq "C") } {
			cli_set_errmsg "IP address must be a class A, B, or C IP"
			return 0
		}
	}
	if { [cli_ver_start 500 0] } {
		set vdomlist [cli_get_tbl_list $CLI_VDOM_NODE ""]
		foreach vdom $vdomlist {
			if { [cli_get_value $vdom "log fortianalyzer override-setting" "" "override"] eq "enable" } {
				if { [cli_get_value $vdom "log fortianalyzer override-setting" "" "status"] eq "enable" } {
					if { $server eq [cli_get_value $vdom "log fortianalyzer override-setting" "" "server"] } {
						cli_set_errmsg "VDOM level Log Setting using same FAZ IP as the one defined globally"
						return 0
					}
				}
			}
		}
	}
}
if { [cli_obj_support "log remote setting"] } {
	set vdom_list [cli_get_tbl_list $CLI_VDOM_NODE ""]
	if {$vdom_list eq ""} {
		set vdom_list [list $CLI_CUR_VDOM_NODE]
	}
	foreach e $vdom_list {
		set remote_status [cli_get_value $e "log remote setting" "" "status"]
		set remote_dst [cli_get_value $e "log remote setting" "" "destination"]
		if {($remote_status eq "enable" && $remote_dst eq "FAZ")} {
			set logdisk_status [cli_get_value $e "log disk setting" "" "status"]
			if {($status eq "disable")} {
				cli_set_errmsg "conflict value with log.remote.setting"
				return 0
			} elseif {$logdisk_status eq "disable"} {
				set uploadopt [cli_get_value $CLI_CUR_NODE "" "" "upload-option"]
				if {![cli_branchpt_start 400 522] || ($uploadopt eq "store-and-upload")} {
					cli_set_errmsg "conflict value with log.disk.setting"
					return 0
				}
			}
		}
	}
}
return 1
	%}
	"log fortianalyzer setting interface" = %{
## manually perform reference check due to weakdatasrc
set intf [cli_get_value $CLI_CUR_NODE "" "" ""]
set node [cli_get_node $CLI_GLOBAL_NODE "system interface" $intf ""]
if { $node eq 0 } {
	cli_set_errmsg "Invalid interface $intf."
	return 0
}
return 1
	%}
	"log fortianalyzer override-setting" = %{
	if { [cli_ver_start 500 0] && ![cli_branchpt_start 500 1510]} {
		if { [cli_get_value $CLI_CUR_NODE "" "" "override"] eq "enable" } {
			if { [cli_get_value $CLI_CUR_NODE "" "" "status"] eq "enable" } {
				set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
				if { $server eq "0.0.0.0" } {
					cli_set_errmsg "Please set server ip address"
					return 0
				}
				if { [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "status"] eq "enable" } {
					if { $server eq [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "server"] } {
						cli_set_errmsg "VDOM level log setting using same FAZ IP as the one defined in global fortianalyzer"
						return 0
					}
				}
				if { [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer2 setting" "" "status"] eq "enable" } {
					if { $server eq [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer2 setting" "" "server"] } {
						cli_set_errmsg "VDOM level log setting using same FAZ IP as the one defined in global fortianalyzer2"
						return 0
					}
				}
				if { [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer3 setting" "" "status"] eq "enable" } {
					if { $server eq [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer3 setting" "" "server"] } {
						cli_set_errmsg "VDOM level log setting using same FAZ IP as the one defined in global fortianalyzer3"
						return 0
					}
				}
			}
		}
	}
return 1
	%}

        "antivirus filepattern" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "" } {
      cli_set_errmsg "Name must be set"
      return 0
}
set numName [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name]
if { $numName > 1 } {
      cli_set_errmsg "duplicate"
      return 0
}
return 1
%}
         "antivirus quarantine quar-to-fortianalyzer" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value eq "enable" } {
	set status [cli_get_value $CLI_GLOBAL_NODE "system fortianalyzer" "" "status"]
	if { $status ne "enable" } {
		cli_set_errmsg "fortianalyzer server unavailable"
		return 0
	}
	if { [cli_ver_start 500 0] } {
	} else {
		set amode [cli_get_value $CLI_GLOBAL_NODE "system fortianalyzer" "" "address-mode"]
		if { $amode eq "auto-discovery" } {
			set fdpdev [cli_get_value $CLI_GLOBAL_NODE "system fortianalyzer" "" "fdp-device"]
			if { $fdpdev eq "" } {
				cli_set_errmsg "fortianalyzer server unavailable"
				return 0
			}
		}
	}
	if { $amode eq "static" } {
		set svrip [cli_get_value $CLI_GLOBAL_NODE "system fortianalyzer" "" "server"]
		if { ($svrip eq "") || ($svrip eq "0.0.0.0") } {
			cli_set_errmsg "fortianalyzer server unavailable"
			return 0
		}
	}
}
return 1
%}
         "antivirus quarantine destination" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value eq "FortiAnalyzer" } {
	set status [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "status"]
	if { $status ne "enable" } {
		cli_set_errmsg "fortianalyzer server unavailable"
		return 0
	}
	set amode [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "address-mode"]
	if { [cli_ver_start 500 0] } {
	} else {
		if { $amode eq "auto-discovery" } {
			set fdpdev [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "fdp-device"]
			if { $fdpdev eq "" } {
				cli_set_errmsg "fortianalyzer server unavailable"
				return 0
			}
		}
	}
        if { $amode eq "static" } {
                set svrip [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "server"]
                if { ($svrip eq "") || ($svrip eq "0.0.0.0") } {
                        cli_set_errmsg "fortianalyzer server unavailable"
                        return 0
                }
        }
}
return 1
%}

         "antivirus service port" = %{
set portlist [cli_get_value $CLI_CUR_NODE "" "" ""]
set numport [llength $portlist]
if { $numport >= 20 } {
	cli_set_errmsg "max entry"
	return 0
}
foreach port $portlist {

### the port can not be duplicated in the current port list
	if { [llength [lsearch $portlist $port]] > 1 } {
		cli_set_errmsg "duplicate"
		return 0
	}

### the port can not appear in other service
  	set svrnode $CLI_CUR_PARENT_NODE
	set svrnodelist [cli_get_tbl_list $CLI_GLOBAL_NODE "antivirus service"]
	foreach node $svrnodelist {
		if { ![cli_if_same_node $node $svrnode] } {
			set prtlist [cli_get_value $node "" ""  "port"]
			if { [lsearch $prtlist $port] >= 0 } {
				cli_set_errmsg "entry exists"
				return 0
			}
		}
	}
}
return 1
%}
             "user local type" = %{
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
set type [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ($type eq "radius") || ($type eq "ldap") || ($type eq "tacacs+")} {
#####phase 1 ##############
    set ipsec_ph1_ndlt [cli_get_tbl_list $CLI_CUR_VDOM_NODE "vpn ipsec phase1"]
    foreach node $ipsec_ph1_ndlt {
       set urgrp [cli_get_value $node "" "" "usrgrp"]
       set members [cli_get_value $CLI_CUR_VDOM_NODE "user group" $urgrp "member"]
       foreach member $members {
         if {$member eq $name} {
            cli_set_errmsg "invalid value"
            return 0
         }
       }
    }
###### phase 1 interface #############
    set ipsec_ph1_ndlt [cli_get_tbl_list $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface"]
    foreach node $ipsec_ph1_ndlt {
       set urgrp [cli_get_value $node "" "" "usrgrp"]
       set members [cli_get_value $CLI_CUR_VDOM_NODE "user group" $urgrp "member"]
       foreach member $members {
         if {$member eq $name} {
            cli_set_errmsg "invalid value"
            return 0
         }
       }
    }

}
return 1
%}
	"user local" = %{
set two_factor [cli_get_value $CLI_CUR_NODE "" "" "two-factor"]
if {$two_factor eq "fortitoken"} {
        set ftk [cli_get_value $CLI_CUR_NODE "" "" "fortitoken"]
	set ftk [string trim $ftk \"]
        if {$ftk eq ""} {
                cli_set_errmsg "You must specify a FortiToken."
                return 0
        }
	if { [cli_ver_start 500 0] } {
		if { [cli_is_ftm $ftk] } {
			set server [cli_get_value $CLI_CUR_NODE "" "" "sms-server"]
			set prov [cli_get_value $CLI_CUR_NODE "" "" "sms-custom-server"]
			set phone [cli_get_value $CLI_CUR_NODE "" "" "sms-phone"]
			set mail [cli_get_value $CLI_CUR_NODE "" "" "email-to"]
			if { ($server eq "custom" && ($prov eq "" || $phone eq "")) || ($mail eq "" && $phone eq "") } {
				cli_set_errmsg "You must specify a phone number or email address.\n"
				return 0
			}
		}
	}
} elseif {$two_factor eq "email"} {
        set email [cli_get_value $CLI_CUR_NODE "" "" "email-to"]
        set email [string trim $email \"]
        if {$email eq ""} {
                cli_set_errmsg "You must specify an email address."
                return 0
        }
        namespace import global::cli_invalid_email
        if { [cli_invalid_email $email] } {
                cli_set_errmsg "$email is not a valid email address."
                return 0
        }
} elseif {$two_factor eq "sms"} {
	if {[cli_ver_start 500 0]} {
		if {[cli_get_value $CLI_CUR_NODE "" "" "sms-phone"] eq ""} {
		        cli_set_errmsg "You must specify an SMS phone number."
		        return 0
		}
	} else {
		if {([cli_get_value $CLI_CUR_NODE "" "" "sms-provider"] eq "") ||
		    ([cli_get_value $CLI_CUR_NODE "" "" "sms-phone"] eq "")} {
		        cli_set_errmsg "You must specify an SMS provider and phone number."
		        return 0
		}
	}
}
return 1
%}
        "user peer" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ($name eq "") || ($name eq "FGh_FtMngr") || ($name eq "FGh_FtiLog1") ||
     ($name eq "FGh_FtiLog2") || ($name eq "FGh_FtiLog3")} {
      cli_set_errmsg "invalid value"
      return 0
}
set local_node [cli_get_node $CLI_CUR_VDOM_NODE "user local" $name ""]
if { 0 != $local_node } {
   cli_set_errmsg "Duplicate name in user local"
   return 0
}
set radius_node [cli_get_node $CLI_CUR_VDOM_NODE "user radius" $name ""]
if { 0 != $radius_node } {
   cli_set_errmsg "Duplicate name in user RADIUS"
   return 0
}
set tacplus_node [cli_get_node $CLI_CUR_VDOM_NODE "user tacacs+" $name ""]
if { 0 != $tacplus_node } {
   cli_set_errmsg "Duplicate name in user TACACS+"
   return 0
}
set ldap_node [cli_get_node $CLI_CUR_VDOM_NODE "user ldap" $name ""]
if { 0 != $ldap_node } {
   cli_set_errmsg "Duplicate name in user LDAP"
   return 0
}
set usrgrp_node [cli_get_node $CLI_CUR_VDOM_NODE "user group" $name ""]
if { 0 != $usrgrp_node } {
   cli_set_errmsg "Duplicate name in user group"
   return 0
}
set peergrp_node [cli_get_node $CLI_CUR_VDOM_NODE "user peergrp" $name ""]
if { 0 != $peergrp_node } {
   cli_set_errmsg "Duplicate name in user peergroup"
   return 0
}
return 1
%}
       "user peergrp" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set usrgrp_node [cli_get_node $CLI_CUR_VDOM_NODE "user group" $name ""]
if { 0 != $usrgrp_node } {
   cli_set_errmsg "Duplicate name in user group"
   return 0
}
set peer_node [cli_get_node $CLI_CUR_VDOM_NODE "user peer" $name ""]
if { 0 != $peer_node } {
   cli_set_errmsg "Duplicate name in user peer"
   return 0
}
set member [cli_get_value $CLI_CUR_NODE "" "" "member"]
foreach e $member {
	set e [string trim $e \"]
	if {($e eq "FGh_FtMngr") || ($e eq "FGh_FtiLog1") || ($e eq "FGh_FtiLog2") || ($e eq "FGh_FtiLog3")} {
	    cli_set_errmsg "invalid value"
	    return 0
	}
}
return 1
%}
         "user ldap" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set local_node [cli_get_node $CLI_CUR_VDOM_NODE "user local" $name ""]
if { 0 != $local_node } {
   cli_set_errmsg "Duplicate name in user local"
   return 0
}
set radius_node [cli_get_node $CLI_CUR_VDOM_NODE "user radius" $name ""]
if { 0 != $radius_node } {
   cli_set_errmsg "Duplicate name in user RADIUS"
   return 0
}
set tacplus_node [cli_get_node $CLI_CUR_VDOM_NODE "user tacacs+" $name ""]
if { 0 != $tacplus_node } {
   cli_set_errmsg "Duplicate name in user TACACS+"
   return 0
}
set peer_node [cli_get_node $CLI_CUR_VDOM_NODE "user peer" $name ""]
if { 0 != $peer_node } {
   cli_set_errmsg "Duplicate name in user peer"
   return 0
}
set svr [cli_get_value $CLI_CUR_NODE "" "" "server"]
if { $svr eq "" } {
	set if_no_default [cli_get_value $CLI_CUR_NODE "" "" "_if_no_default"]
	if { $if_no_default != 1} {
		cli_set_errmsg "Server cannot be empty."
		return 0
	}
}
if { [cli_ver_start 500 4] } {
	set dn [cli_get_value $CLI_CUR_NODE "" "" "dn"]
	if { $dn eq "" } {
		cli_set_errmsg "Distinguished name cannot be empty."
		return 0
	}
}
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $type eq "regular" } {
    set usrname [cli_get_value $CLI_CUR_NODE "" "" "username"]
    if { $usrname eq "" } {
       cli_set_errmsg "Username must be set"
       return 0
    }
}
return 1
%}
        "user radius" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set local_node [cli_get_node $CLI_CUR_VDOM_NODE "user local" $name ""]
if { 0 != $local_node } {
   cli_set_errmsg "Duplicate name in user local"
   return 0
}
set tacplus_node [cli_get_node $CLI_CUR_VDOM_NODE "user tacacs+" $name ""]
if { 0 != $tacplus_node } {
   cli_set_errmsg "Duplicate name in user TACACS+"
   return 0
}
set ldap_node [cli_get_node $CLI_CUR_VDOM_NODE "user ldap" $name ""]
if { 0 != $ldap_node } {
   cli_set_errmsg "Duplicate name in user LDAP"
   return 0
}
set peer_node [cli_get_node $CLI_CUR_VDOM_NODE "user peer" $name ""]
if { 0 != $peer_node } {
   cli_set_errmsg "Duplicate name in user peer"
   return 0
}
set svr [cli_get_value $CLI_CUR_NODE "" "" "server"]
set rsso [cli_get_value $CLI_CUR_NODE "" "" "rsso"]
if { $svr eq "" &&  $rsso ne "enable" } {
   cli_set_errmsg "server cannot be empty."
   return 0
}
if { [cli_ver_start 500 4] } {
	set scrt [cli_get_value $CLI_CUR_NODE "" "" "secret"]
	if { $scrt eq "" } {
		cli_set_errmsg "secret cannot be empty."
		return 0
	}
}
if { [cli_ver_start 500 0] } {
	set rsso [cli_get_value $CLI_CUR_NODE "" "" "rsso"]
	if { $rsso eq "enable" } {
		if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "rsso" 0 "enable"] > 1} {
			cli_set_errmsg "only one RSSO agent is allowed"
			return 0
		}
	}
} else {
	set dynp [cli_get_value $CLI_CUR_NODE "" "" "dynamic-profile"]
	if { $dynp eq "enable" } {
		if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "dynamic-profile" 0 "enable"] > 1} {
			cli_set_errmsg "Can not duplicate enable Dynamic profile"
			return 0
		}
	}
}
return 1
%}
        "user radius source-ip" = %{
set srcip [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $srcip eq "" } {
	return 1
}
set intf_list [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
foreach memb $intf_list {
	set vdom [cli_get_value $memb "" "" "vdom"]
	set vdom [string trim $vdom \"]
	if { $vdom eq $CLI_CUR_VDOM_NAME} {
		set ip [cli_get_value $memb "" "" "ip"]
		set output [string range $ip 0 [expr {[string first " " $ip] - 1}]]
		if { $output eq $srcip } {
			return 1
		}
		if { [cli_is_match $memb 0 "" "secondary-IP" 0 "enable"] } {
			set ip2_list [cli_get_tbl_list $memb "secondaryip"]
			foreach ip2 $ip2_list {
				set ip [cli_get_value $ip2 "" "" "ip"]
				set output [string range $ip 0 [expr {[string first " " $ip] - 1}]]
				if { $output eq $srcip } {
					return 1
				}
			}
		}
	}
}
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
cli_set_errmsg "user radius, $name, source-ip, $srcip, must match FGT's interface"
return 0
	%}
        "user radius server" = %{
set svr1 [cli_get_value $CLI_CUR_NODE "" "" ""]
set svr2 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "secondary-server"]
if { $svr1 ne "" && $svr2 ne "" } {
	if { $svr1 eq $svr2 } {
	   cli_set_errmsg "Primary and secondary server cannot be the same"
	   return 0
	}
}
if { [regexp {^([0-9])$} $svr1] && [scan $svr1 "%d.%d.%d.%d/%d.%d.%d.%d" a a a a m1 m2 m3 m4] != 4 } {
	cli_set_errmsg "Invalid user radius server IP. (Mask is not allowed.)"
	return 0
}
return 1
%}
        "user radius secondary-server" = %{
set svr2 [cli_get_value $CLI_CUR_NODE "" "" ""]
set svr1 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server"]
if { $svr1 ne "" && $svr2 ne "" } {
	if { $svr1 eq $svr2 } {
	   cli_set_errmsg "Primary and secondary server cannot be the same"
	   return 0
	}
}
return 1
%}

	"user saml" = %{
if { [cli_ver_start 700 0] } {
	set adfs [cli_get_value $CLI_CUR_NODE "" "" "adfs-claim"]
	if { $adfs ne "enable"} {
		set uname [cli_get_value $CLI_CUR_NODE "" "" "user-name"]
		if { $uname == 0 || $uname eq "" } {
			set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
			cli_set_errmsg "user saml \"$name\" cannot have empty user-name."
			return 0
		}
	}
}
set idp_single_sign_on_url [cli_get_value $CLI_CUR_NODE "" "" "idp-single-sign-on-url"]
if { $idp_single_sign_on_url == 0 || $idp_single_sign_on_url eq "" } {
	cli_set_errmsg "user saml \"$name\" cannot have empty idp-single-sign-on-url."
	return 0
}
return 1
%}

	"user quarantine targets macs" = %{
set macs [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
set cur_target_node [cli_get_parent $CLI_CUR_PARENT_NODE]
set name [cli_get_value $cur_target_node "" "" ""]
set targets [cli_get_tbl_list [cli_get_parent $cur_target_node] ""]
foreach m $macs {
    set mac [cli_get_value $m "" "" "mac"]
    set mac_table($mac) $name
}
foreach t $targets {
    set entry [ cli_get_value $t "" "" "entry"]
    if { $entry ne $name } {
        set macs [cli_get_tbl_list  $t "macs"]
        foreach m $macs {
            set mac [cli_get_value $m "" "" "mac"]
            if { [info exists mac_table($mac)] && $mac_table($mac) ne $entry } {
				if { [string match "*postcheck*" [cli_get_clisrc]] } {
                	cli_set_errmsg "Mac address $mac duplicated within entries $entry and $name"
					return 0
				} else {
					cli_schedule_post_check $CLI_CUR_NODE "edit"
				}
            }
        }
    }
}
return 1
%}

        "user tacacs+" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set local_node [cli_get_node $CLI_CUR_VDOM_NODE "user local" $name ""]
if { 0 != $local_node } {
   cli_set_errmsg "Duplicate name in user local"
   return 0
}
set radius_node [cli_get_node $CLI_CUR_VDOM_NODE "user radius" $name ""]
if { 0 != $radius_node } {
   cli_set_errmsg "Duplicate name in user RADIUS"
   return 0
}
set ldap_node [cli_get_node $CLI_CUR_VDOM_NODE "user ldap" $name ""]
if { 0 != $ldap_node } {
   cli_set_errmsg "Duplicate name in user LDAP"
   return 0
}
set peer_node [cli_get_node $CLI_CUR_VDOM_NODE "user peer" $name ""]
if { 0 != $peer_node } {
   cli_set_errmsg "Duplicate name in user peer"
   return 0
}
set key [cli_get_value $CLI_CUR_NODE "" "" "key"]
set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
if {$key eq "" || $server eq ""} {
	cli_set_errmsg "invalid setting"
	return 0
}
return 1
%}
	"user fortitoken" = %{
set sn [cli_get_value $CLI_CUR_NODE "" "" "serial-number"]
if {[cli_check_ftk_sn $sn]} {
	cli_set_errmsg "Wrong FortiToken serial number."
	return 0
}
return 1
%}
	"user setting" = %{
set auth_sec_http [cli_get_value $CLI_CUR_NODE "" "" "auth-secure-http"]
set auth_type [cli_get_value $CLI_CUR_NODE "" "" "auth-type"]
if {$auth_sec_http eq "enable"} {
	if {$auth_type eq ""} {
		cli_set_errmsg "conflict value"
		return 0
	}
	if {[string first "https" $auth_type] == -1} {
		cli_set_errmsg "conflict value"
		return 0
	}

        if {[cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall policy" "endpoint-check" 0 "enable"]} {
                cli_set_errmsg "Cannot enable https redirect because forticlient-check is enabled in some policy"
                return 0
        }
}
set auth [cli_get_value $CLI_CUR_NODE "" "" "auth-cert"]
namespace import global::auth_cert_not_exist
if { [auth_cert_not_exist $auth] } {
        cli_set_errmsg "Certificate $auth does not exist"
        return 0
}
return 1
	%}

         "user fsae server" = %{
set server [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$server eq ""} {
	cli_set_errmsg "empty value"
	return 0
}
return 1
	%}

	"user group group-type" = %{
namespace import global::user_group_check_type
set gname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set gname [string trim $gname \"]
if { ($gname eq "SSO_Guest_Users") && [cli_ver_start 500 2] } {
	return 1
}
set gtype [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$gtype eq "fsso-service"} {
	set members [cli_get_value $CLI_CUR_PARENT_NODE "" "" "member" 1]
	foreach m $members {
		if { [cli_get_node $CLI_CUR_VDOM_NODE "user local" $m ""] != 0 } {
			cli_set_errmsg "local user $m cannot be assigned to a group of type fsso-service"
			return 0
		}
	}
}
return [user_group_check_type $CLI_CUR_NODE $CLI_CUR_PARENT_NODE]
	%}

	"user group member" = %{
namespace import global::user_group_ipsec_used
set grpname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set grpname [string trim $grpname \"]
set gtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "group-type"]
if {$gtype eq "fsso-service"} {
	if {($grpname eq "SSO_Guest_Users") && [cli_ver_start 500 2]} {
		return 1
	}
	set members [cli_get_value $CLI_CUR_NODE "" "" "" 1]
	foreach m $members {
		if { [cli_get_node $CLI_CUR_VDOM_NODE "user local" $m ""] != 0 } {
			cli_set_errmsg "local user $m cannot be assigned to a group of type fsso-service"
			return 0
		}
	}
} else {
	set members [cli_get_value $CLI_CUR_NODE "" "" ""]
	set grpname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	set check_if_used_ipsec [user_group_ipsec_used $grpname]
	foreach m $members {
		if { [cli_get_node $CLI_CUR_VDOM_NODE "user adgrp" $m ""] != 0 } {
			cli_set_errmsg "fsso group $m cannot be assigned to a group of type other than fsso-server"
			return 0
		}
		if { $check_if_used_ipsec } {
			if { [cli_get_node $CLI_CUR_VDOM_NODE "user ldap" $m ""] ||
			     [cli_get_node $CLI_CUR_VDOM_NODE "user radius" $m ""] ||
			     [cli_get_node $CLI_CUR_VDOM_NODE "user pop3" $m ""] ||
			     [cli_get_node $CLI_CUR_VDOM_NODE "user tacacs+" $m ""] ||
			     [cli_get_node $CLI_CUR_VDOM_NODE "user peer" $m ""] ||
			     [cli_get_node $CLI_CUR_VDOM_NODE "user adgrp" $m ""] } {
				cli_set_errmsg "remote group member $m cannot be assigned to $grpname if this group is used by ipsec phase1"
				return 0
			} else {
				set user [cli_get_node $CLI_CUR_VDOM_NODE "user local" $m ""];
				if { $user != 0 } {
					set utype [cli_get_value $user "" "" "type"]
					if { $utype eq "radius" || $utype eq "ldap" || $utype eq "tacacs+" } {
						cli_set_errmsg "remote group member $m cannot be assigned to $grpname if this group is used by ipsec phase1"
						return 0
					}
				}
			}
		}

		set admin_user [cli_get_tbl_list $CLI_GLOBAL_NODE "system admin"]
		foreach user $admin_user {
			set remote_auth [cli_get_value $user "" "" "remote-auth"]
			if { $remote_auth eq "enable" } {
				set usrgrp_name [cli_get_value $user "" "" "remote-group"]
				if { $grpname eq $usrgrp_name } {
					if { ![cli_get_node $CLI_CUR_VDOM_NODE "user ldap" $m ""] &&
					     ![cli_get_node $CLI_CUR_VDOM_NODE "user radius" $m ""] &&
					     ![cli_get_node $CLI_CUR_VDOM_NODE "user tacacs+" $m ""] } {
						cli_set_errmsg "local group member $m cannot be assigned to a remote auth group $grpname"
						return 0
					}
				}
			}
			set peer_auth [cli_get_value $user "" "" "peer-auth"]
			if { $peer_auth eq "enable" } {
				set peergrp_name [cli_get_value $user "" "" "peer-group"]
				if { $grpname eq $peergrp_name } {
					if { ![cli_get_node $CLI_CUR_VDOM_NODE "user peer" $m ""] } {
						cli_set_errmsg "none peer group member $m cannot be assigned to a peer auth group $grpname"
						return 0
					}
				}
			}
		}
	}
}
return 1
	%}

	"user group match" = %{
namespace import global::user_group_match_check_member
if { [cli_ver_start 500 4] } {
	set usrgrp_node [cli_get_parent $CLI_CUR_PARENT_NODE]
	set gr_type [cli_get_value $usrgrp_node "" "" "group-type"]
	if { $gr_type ne "firewall" } {
		return 1
	}
	set gr_name [cli_get_value $CLI_CUR_NODE "" "" "group-name"]
	if { $gr_name eq "" } {
		cli_set_errmsg "Group name is required."
		return 0
	}
	set is_member [user_group_match_check_member $CLI_CUR_NODE $usrgrp_node]
	if { $is_member == 0 } {
		return 0
	}
}
return 1
	%}

        "router rip interface" = %{
set mode [cli_get_value $CLI_CUR_NODE "" "" "auth-mode"]
set txt [cli_get_value $CLI_CUR_NODE "" "" "auth-string"]
set key [cli_get_value $CLI_CUR_NODE "" "" "auth-keychain"]
if { (($mode eq "md5")||($mode eq "text")) && ($key eq "") && ($txt eq "") } {
    cli_set_errmsg "invalid value"
    return 0
}

return 1
%}
        "router rip network" = %{
proc covertMaskList { mask } {
     set masklist [list]
     set value [lindex $mask 0]
     if { ($value < 1) || ($value > 32) } {
       return masklist
     }
     set base [expr ($value / 8)]
     set offset [expr ($value % 8)]
     for { set i 0 } { $i < $base } {incr i} {
       lappend masklist 255
     }
     if { $offset > 0 } {
       lappend masklist [expr (pow(2,$offset)-1)*pow(2,8-offset)]
     }
     if {[llength $masklist] < 4} {
       for {set i [expr [llength $masklist]+1]} {$i <= 4} {incr i} {
         lappend masklist 0
       }
     }
    return $masklist
}
proc generateIpMaskList { prefix } {
    if { 1 == [llength $prefix]} {
       set prefix [split $prefix /]
    }
    if { 2 == [llength $prefix] } {
       set ip [lindex $prefix 0]
       set mask [lindex $prefix 1]
   } else {
       return [list]
   }

   set iplist [split $ip .]
   set ipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]

   set netmasklist [split $mask .]
   if {1 == [llength $netmasklist]} {
     set netmasklist [covertMaskList $netmasklist]
   }
   if { 4 != [llength $netmasklist] } {
      return [list]
   }
    set netmaskint [expr ([lindex $netmasklist 0]<<24)+([lindex $netmasklist 1]<<16)+([lindex $netmasklist 2]<<8)+[lindex $netmasklist 3]]
    return [list $ipint $netmaskint]
}
set prefix [cli_get_value $CLI_CUR_NODE "" "" "prefix"]
set ipmasklist [generateIpMaskList $prefix]
if { 0 == [llength $ipmasklist] } {
    cli_set_errmsg "invalid value"
    return 0
}
set prefixnode [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
    foreach node $prefixnode {
       if { ![cli_if_same_node $node $CLI_CUR_NODE] } {
           set old_prefix [cli_get_value $node "" "" "prefix"]
           set old_ipmasklist [generateIpMaskList $old_prefix]
           if { (([lindex $ipmasklist 0] & [lindex $ipmasklist 1]) == ([lindex $old_ipmasklist 0] & [lindex $old_ipmasklist 1])) && ([lindex $ipmasklist 1] == [lindex $old_ipmasklist 1])} {
              cli_set_errmsg "entry exists"
              return 0
           }
       }
    }

return 1
%}
        "router rip distance" = %{
set distance [cli_get_value $CLI_CUR_NODE "" "" "distance"]
if { $distance eq "" } {
    cli_set_errmsg "empty value"
    return 0
}
set num_global_prefix 0
set prefixnode [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
    foreach node $prefixnode {
        set prefix [cli_get_value $node "" "" "prefix"]
        if { $prefix eq "" } {
            incr num_global_prefix
            if { $num_global_prefix > 1 } {
               cli_set_errmsg "invalid value"
               return 0
            }
        }
    }

return 1
%}
        "router rip distribute-list" = %{
set listname [cli_get_value $CLI_CUR_NODE "" "" "listname"]
if {$listname eq ""} {
	cli_set_errmsg "invalid value"
	return 0
}
if {[regexp {[^[[:alnum:]]]|\s} $listname] != 0} {
        cli_set_errmsg "invalid value"
        return 0
}
return 1
	%}
	"router access-list rule" = %{
if { [cli_ver_start 600 0] } {
	set prefix [cli_get_value $CLI_CUR_NODE "" "" "prefix"]
	set wildcard [cli_get_value $CLI_CUR_NODE "" "" "wildcard"]
	if { $wildcard ne "" && $prefix ne "" } {
		cli_set_errmsg "only one of wildcard and prefix can be set."
		return 0
	}
}
return 1
%}
	"router access-list rule prefix" = %{
set prefix [cli_get_value $CLI_CUR_NODE "" "" ""]
set wildcard [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wildcard"]
set ippat1 {(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)}

if { 2 == [llength $prefix] } {
   if { (![regexp $ippat1 [lindex $prefix 0] match]) || ([lindex $prefix 0]
ne $match)} {
     cli_set_errmsg "invalid ip"
     return 0
   }
   if { (![regexp $ippat1 [lindex $prefix 1] match]) || ([lindex $prefix 1]
ne $match)} {
     cli_set_errmsg "invalid mask"
     return 0
   }
} elseif {$prefix eq "" && $wildcard ne ""} {
    # accept it when wildcard is used
} elseif {! [string compare $prefix "any"]} {
    # accept it because mapping converts 0.0.0.0/0 to "any"
} else {
   set prefix [split $prefix /]
   if { 2 == [llength $prefix] } {
       if { (![regexp $ippat1 [lindex $prefix 0] match])|| ([lindex $prefix 0] ne $match)} {
          cli_set_errmsg "invalid ip"
          return 0
       }
       if { [lindex $prefix 1]<0 || [lindex $prefix 1] > 32} {
          cli_set_errmsg "invalid mask"
          return 0
       }
   } else {
      cli_set_errmsg "invalid ip"
      return 0
   }
}
return 1
%}
        "router access-list" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {[regexp {[^[[:alnum:]]]|\s} $name] != 0} {
        cli_set_errmsg "invalid value"
        return 0
}
set prefix_node [cli_get_node $CLI_CUR_VDOM_NODE "router prefix-list" $name ""]
if { 0 != $prefix_node } {
   cli_set_errmsg "invalid value"
   return 0
}
return 1
%}
          "router access-list rule wildcard" = %{
set wildcard [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $wildcard eq "" } {
   set prefix [cli_get_value $CLI_CUR_PARENT_NODE "" "" "prefix"]
   if { $prefix ne "" } {
      return 1
   } else {
      cli_set_errmsg "invalid ip"
      return 0
   }
}
set ippat1 {(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)}
if { 2 != [llength $wildcard]} {
   cli_set_errmsg "invalid value"
   return 0
}
if { (![regexp $ippat1 [lindex $wildcard 0] match]) || ([lindex $wildcard 0]
ne $match) } {
   cli_set_errmsg "invalid ip"
   return 0
}
if { (![regexp $ippat1 [lindex $wildcard 1] match]) || ([lindex $wildcard 1]
ne $match) } {
      cli_set_errmsg "invalid mask"
      return 0
}
return 1
%}
	"router auth-path" = %{
set device [cli_get_value $CLI_CUR_NODE "" "" "device"]
set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $device ""]
if {$intf_node == 0} {
        cli_set_errmsg "invalid value"
        return 0
}
	%}
	"firewall profile" = %{
proc check_spamtag {name} {
	global CLI_CUR_NODE
	set tagmsg "${name}-spamtagmsg"
	append name "-spamtagtype"
	set spamtag [cli_get_value $CLI_CUR_NODE "" "" $name]
	if {$spamtag ne ""} {
		set tagpat {[[:<:]]header[[:>:]]}
		set part1pat {[()<>@,\\/\[\]?=]}
		set part2pat {[[:cntrl:]]}
		set msg [cli_get_value $CLI_CUR_NODE "" "" $tagmsg]

		if {[regexp $tagpat $spamtag]} {
			if {[regexp {(.*)[: ]} $msg match part1] == 0} {
				set part1 $msg
			}
			if {[regexp $part1pat $part1]} {
				return -1
			}

			if {[regexp {[: ](.*)} $msg match part2]} {
				if {[regexp $part2pat $part2]} {
					return -1
				}
			}
		}
	}
	return 0
}
if {[check_spamtag "smtp"] == -1} {
	cli_set_errmsg "unexpected input"
	return 0
}
if {[check_spamtag "pop3"] == -1} {
	cli_set_errmsg "unexpected input"
	return 0
}
if {[check_spamtag "imap"] == -1} {
	cli_set_errmsg "unexpected input"
	return 0
}

if {[cli_get_value $CLI_CUR_NODE "" "" "application-list-status"] eq "enable" && [cli_get_value $CLI_CUR_NODE "" "" "application-list"] eq ""} {
        cli_set_errmsg "the application-list must be set"
        return 0
}
return 1
       %}

       "firewall service custom" = %{
set srv_name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$srv_name eq ""} {
    cli_set_errmsg "empty value"
    return 0
}
if {[cli_get_node $CLI_CUR_VDOM_NODE "firewall service group" $srv_name ""]} {
	cli_set_errmsg "entry exists"
	return 0
}
if { [cli_ver_start 500 0] } {
} else {
	if {[cli_get_node $CLI_GLOBAL_NODE "firewall service predefined" $srv_name ""]} {
		cli_set_errmsg "entry exists"
		return 0
	}
}

return 1
	%}

	"firewall service custom {tcp-portrange udp-portrange sctp-portrange}" = %{
set vallist [cli_get_value $CLI_CUR_NODE "" "" ""]
foreach value $vallist {
	set rangelist [split $value ":"]
	for {set i 0} {$i < 2} {incr i} {
		set portrange [lindex $rangelist $i]
		if { $portrange eq "" } {
			if { $i == 0 } {
				cli_set_errmsg "\<dstport_low\> must be set, \"$CLI_CUR_NODE_NAME\" invalid value \[$value\]"
				return 0
			} else {
				continue
			}
		}
		set portlist [split $portrange "-"]
		set port_low [lindex $portlist 0]
		set port_high [lindex $portlist 1]
		if { $port_low eq "" } {
			cli_set_errmsg "\"$CLI_CUR_NODE_NAME\" invalid value \[$value\]"
			return 0
		}
		if { $port_high eq "" } {
			set port_high $port_low
		}
		if { ($port_low > $port_high) || ($port_high > 65535) || ($port_low < 0) } {
			cli_set_errmsg "\"$CLI_CUR_NODE_NAME\" beyond the boundary \[$value\]"
			return 0
		}
	}
}
return 1
	%}

       "firewall service group" = %{
### service group name check ###
set grp_name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$grp_name eq ""} {
    cli_set_errmsg "empty value"
    return 0
}
if {[cli_get_node $CLI_CUR_VDOM_NODE "firewall service custom" $grp_name ""]} {
	cli_set_errmsg "entry exists"
	return 0
}
if { [cli_ver_start 500 0] } {
	if {$CLI_ACT ne "add"} {
		set ntype [cli_get_value $CLI_CUR_NODE "" "" "explicit-proxy"]
		set otype [cli_get_org_value $CLI_CUR_NODE "" "" "explicit-proxy"]
		if {[string compare $ntype $otype]} {
			cli_set_errmsg "Cannot change whether this service group is used for explicit proxy, once the group is created"
			return 0
		}
	}
} else {
	if {[cli_get_node $CLI_GLOBAL_NODE "firewall service predefined" $grp_name ""]} {
		cli_set_errmsg "entry exists"
		return 0
	}
}
return 1
	%}

       "firewall {service schedule} group member" = %{
set grpmember [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $grpmember eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
return 1
	%}

	"vpn ipsec phase1-interface" = %{
set interface [cli_get_value $CLI_CUR_NODE "" "" "interface"]
proc check_id_conflict {node path peerID localID peertype} {
	global CLI_CUR_NODE
	global interface
	set localgw [cli_get_value $CLI_CUR_NODE "" "" "local-gw"]

	if {$localgw ne ""} {
		if {$peerID ne "" && $peertype ne "" && ($peertype ne "dialup"  && $peertype ne "any")} {
			set match_nr [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"local-gw\" 0 $localgw \"peerid\" 0 $peerID]
			if {$match_nr != 0} {
				set match_nr_w_peertype [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"local-gw\" 0 $localgw \"peerid\" 0 $peerID  \"peertype\" 1 \"dialup\"]
				if {$match_nr == $match_nr_w_peertype} {
					return -1
				}
			}
		}
		if {$localID ne ""} {
			set match_nr [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"local-gw\" 0 $localgw \"peerid\" 0 $localID]
			if {$match_nr != 0} {
				set match_nr_w_peertype [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"local-gw\" 0 $localgw \"peerid\" 0 $localID  \"peertype\" 1 \"dialup\"]
				if {$match_nr == $match_nr_w_peertype} {
					return -1
				}
			}
		}
	} else {
		if {$peerID ne "" && $peertype ne "" && ($peertype ne "dialup"  && $peertype ne "any")} {
			set match_nr [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"peerid\" 0 $peerID]
			if {$match_nr != 0} {
				set match_nr_w_peertype [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"peerid\" 0 $peerID  \"peertype\" 1 \"dialup\"]
				if {$match_nr == $match_nr_w_peertype} {
					return -1
				}
			}
		}
		if {$localID ne ""} {
			set match_nr [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"peerid\" 0 $localID]
			if {$match_nr != 0} {
				set match_nr_w_peertype [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"peerid\" 0 $localID  \"peertype\" 1 \"dialup\"]
				if {$match_nr == $match_nr_w_peertype} {
					return -1
				}
			}
		}
	}
	return 0
}
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set peerID [cli_get_value $CLI_CUR_NODE "" "" "peerid"]
set localID [cli_get_value $CLI_CUR_NODE "" "" "localid"]
set peertype [cli_get_value $CLI_CUR_NODE "" "" "peertype"]
set authmethod [cli_get_value $CLI_CUR_NODE "" "" "authmethod"]
set mode [cli_get_value $CLI_CUR_NODE "" "" "mode"]
set ike [cli_get_value $CLI_CUR_NODE "" "" "ike-version"]
set authremote [cli_get_value $CLI_CUR_NODE "" "" "authmethod-remote"]
if { $type ne "dynamic" } {
	if { $peertype eq "one" && $authmethod eq "psk"} {
		if { $mode eq "main" } {
			cli_set_errmsg "Peer type cannot be set to \"One peer id\" when authentication method is pre-share key and mode is main"
			return 0
		} elseif { $ike eq "2" } {
			cli_set_errmsg "Peer type cannot be set to \"One peer id\" when authentication method is pre-share key and IKE version is 2"
			return 0
		}
	}
	if { $peertype eq "dialup" } {
		cli_set_errmsg "Peer type cannot be dialup when remote gateway is not dialup user"
		return 0
	}
}
if { ($peertype eq "peer" || $peertype eq "peergrp") && ($authmethod eq "psk" || $authremote eq "psk")} {
	cli_set_errmsg "Peer type cannot be $peertype when authentication method is pre-share key"
	return 0
}
if {$peertype eq "one"} {
	if {$peerID eq ""} {
		cli_set_errmsg "peer ID must be set"
		return 0
	}
}
if {$peerID ne "" || $localID ne ""} {
	if {[check_id_conflict $CLI_CUR_VDOM_NODE "vpn ipsec phase1" $peerID $localID $peertype] ne 0} {
		cli_set_errmsg "same peer/local ID"
		return 0
	}
	if {[check_id_conflict $CLI_CUR_PARENT_NODE "" $peerID $localID $peertype] ne 0} {
		cli_set_errmsg "same peer/local ID"
		return 0
	}
}

proc dup_gw_check { nodes } {
	global CLI_CUR_NODE
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set ipv [cli_get_value $CLI_CUR_NODE "" "" "ip-version"]
	set network_id [cli_get_value $CLI_CUR_NODE "" "" "network-id"]
	set network_overlay [cli_get_value $CLI_CUR_NODE "" "" "network-overlay"]
	if { $network_overlay eq "disable" } {
		set network_id 0
	}
	foreach node $nodes {
		set n_type [cli_get_value $node "" "" "type"]
		set n_name [cli_get_value $node "" "" "name"]
		set n_ipv [cli_get_value $node "" "" "ip-version"]
		set n_network_id [cli_get_value $node "" "" "network-id"]
		set n_network_overlay [cli_get_value $node "" "" "network-overlay"]
		if { $n_network_overlay eq "disable" } {
			set n_network_id 0
		}
		if { $n_type eq "static" && $n_ipv eq $ipv && $n_name ne $name } {
			if { [cli_ver_start 600 2] } {
				if { $n_network_id eq $network_id || $network_overlay eq "disable" || $n_network_overlay eq "disable"} {
					return $n_name
				}
			} else {
				return $n_name
			}
		}
	}
	return ""
}

if { ($type eq "static") && [cli_ver_start 500 0] } {
        set ipversion [cli_get_value $CLI_CUR_NODE "" "" "ip-version"]
        if {$ipversion eq "4"} {
                set remote_gw [cli_get_value $CLI_CUR_NODE "" "" "remote-gw"]
				set local_gw [cli_get_value $CLI_CUR_NODE "" "" "local-gw"]
				set nodes [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "vpn ipsec phase1" "interface" 0 $interface "remote-gw" 0 $remote_gw "local-gw" 0 $local_gw]
				set dup_name [dup_gw_check $nodes]
				if { $dup_name ne ""} {
					cli_set_errmsg "The remote gateway is a duplicate of another IPsec gateway entry ($dup_name)"
					return 0
				}
				set nodes [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "vpn ipsec phase1-interface" "interface" 0 $interface "remote-gw" 0 $remote_gw "local-gw" 0 $local_gw]
				set dup_name [dup_gw_check $nodes]
				if { $dup_name ne "" } {
					cli_set_errmsg "The remote gateway is a duplicate of another IPsec gateway entry ($dup_name)"
					return 0
				}
                if { $remote_gw eq "0.0.0.0" } {
                        cli_set_errmsg "IP address cannot be 0.0.0.0"
                        return 0
                }
        } else {
				set remote_gw6 [cli_get_value $CLI_CUR_NODE "" "" "remote-gw6"]
				set local_gw6 [cli_get_value $CLI_CUR_NODE "" "" "local-gw6"]
				set nodes [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "vpn ipsec phase1" "interface" 0 $interface "ip-version" 0 "6" "remote-gw6" 0 $remote_gw6 "local-gw" 0 $local_gw6]
				set dup_name [dup_gw_check $nodes]
				if { $dup_name ne ""} {
					cli_set_errmsg "The remote gateway is a duplicate of another IPsec gateway entry ($dup_name)"
					return 0
				}
				set nodes [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "vpn ipsec phase1-interface" "interface" 0 $interface "ip-version" 0 "6" "remote-gw6" 0 $remote_gw6 "local-gw" 0 $local_gw6]
				set dup_name [dup_gw_check $nodes]
				if { $dup_name ne ""} {
					cli_set_errmsg "The remote gateway is a duplicate of another IPsec gateway entry ($dup_name)"
					return 0
				}
        }
} elseif {$type eq "dynamic"} {
	set extra_errmsg 0
	set modecfg [cli_get_value $CLI_CUR_NODE "" "" "mode-cfg"]
	set assignip [cli_get_value $CLI_CUR_NODE "" "" "assign-ip"]
	set asipfrom [cli_get_value $CLI_CUR_NODE "" "" "assign-ip-from"]
	if {$modecfg eq "enable" && $assignip eq "enable" && $asipfrom eq "range"} {
		set mode_cfg_ipver [cli_get_value $CLI_CUR_NODE "" "" "mode-cfg-ip-version"]
		set ipver [cli_get_value $CLI_CUR_NODE "" "" "ip-version"]

		if { $mode_cfg_ipver eq "6" || $ipver eq "6" } {
			set startip [cli_get_value $CLI_CUR_NODE "" "" "ipv6-start-ip"]
			set endip [cli_get_value $CLI_CUR_NODE "" "" "ipv6-end-ip"]
			if {$startip eq "" || $startip eq "::" || $endip eq "" || $endip eq "::" } {
				set startip [cli_get_value $CLI_CUR_NODE "" "" "ipv4-start-ip"]
				set endip [cli_get_value $CLI_CUR_NODE "" "" "ipv4-end-ip"]
				if {$startip eq "" || $startip eq "0.0.0.0" || $endip eq "" || $endip eq "0.0.0.0"} {
					cli_set_errmsg "must set at least 1 of ipv4-start-ip/ipv4-end-ip or ipv6-start-ip/ipv6-end-ip pair."
					return 0
				}
			}
		} else {
			set startip [cli_get_value $CLI_CUR_NODE "" "" "ipv4-start-ip"]
			set endip [cli_get_value $CLI_CUR_NODE "" "" "ipv4-end-ip"]
			if {$startip eq "" || $startip eq "0.0.0.0" || $endip eq "" || $endip eq "0.0.0.0"} {
				cli_set_errmsg "ipv4-start-ip/ipv4-end-ip must not be 0.0.0.0"
				return 0
			}
		}
		set addroute [cli_get_value $CLI_CUR_NODE "" "" "add-route"]
		if {[cli_ver_start 500 6] && [cli_branchpt_start 500 1513]} {
			set netdev [cli_get_value $CLI_CUR_NODE "" "" "net-device"]
			set extra_errmsg 1
		} else {
			set netdev "enable"
		}
		if {$addroute eq "disable" && $netdev eq "enable"} {
			set startiplist [split $startip .]
			set endiplist [split $endip .]
			set ipchk [expr ([lindex $startiplist 3] & 3)+(([lindex $endiplist 3]+1) & 3)]
			if {$ipchk && $extra_errmsg eq 1} {
				cli_set_errmsg "when net-device enabled, ipv4-start-ip/ipv4-end-ip must be a multiple of a /30 subnet"
				return 0
			} elseif {$ipchk} {
				cli_set_errmsg "ipv4-start-ip/ipv4-end-ip must be a multiple of a /30 subnet"
				return 0
			}
		}
	}
	if { $peertype eq "dialup" } {
		if { $authmethod eq "signature" || $authremote eq "signature" } {
			cli_set_errmsg "Peer type cannot be dialup when authentication method is signature"
			return 0
		} elseif { $ike eq "1" && $mode ne "aggressive" } {
			cli_set_errmsg "Peer type cannot be dialup when IKE version is 1 and mode is not aggressive"
			return 0
		}
	}
}

set xauth_type [cli_get_value $CLI_CUR_NODE "" "" "xauthtype"]
if {$xauth_type eq "client"} {
       if {$type eq "dynamic"} {
		cli_set_errmsg "xauthtype can not be client while remote gateway is dialup"
		return 0
	}
	set xauth_usr_node [cli_get_node $CLI_CUR_NODE "" "" "authusr"]
	if {$xauth_usr_node == 0} {
		cli_set_errmsg "authusr must be set"
		return 0
	}
}
set xauth_usrgrp [cli_get_value $CLI_CUR_NODE "" "" "authusrgrp"]
if {$xauth_type eq "pap" || $xauth_type eq "chap" || $xauth_type eq "auto"} {
	if {$type ne "dynamic"} {
		cli_set_errmsg "invalid xauth type"
		return 0
	}
	if {[cli_ver_start 500 2]} {
	} else {
		if {$xauth_usrgrp eq ""} {
			cli_set_errmsg "empty user group"
			return 0
		}
	}
}
### User group might be copied from adom level later
#if {$xauth_usrgrp ne ""} {
#	set xauth_usrgrp_datasrc [cli_get_node $CLI_CUR_VDOM_NODE "user group" $xauth_usrgrp ""]
#	if {$xauth_usrgrp_datasrc == 0} {
#		cli_set_errmsg "user group name"
#		return 0
#	}
#}
set usrgrp [cli_get_value $CLI_CUR_NODE "" "" "usrgrp"]
### User group might be copied from adom level later
#if {$usrgrp ne ""} {
#	set usrgrp_datasrc [cli_get_node $CLI_CUR_VDOM_NODE "user group" $usrgrp ""]
#	if {$usrgrp_datasrc == 0} {
#		cli_set_errmsg "user group name"
#		return 0
#	}
#}
if { ![cli_ver_start 500 2] } {
	set mode [cli_get_value $CLI_CUR_NODE "" "" "mode"]
	if {$type ne "dynamic" && $mode eq "aggressive"} {
		set dhgrp [cli_get_value $CLI_CUR_NODE "" "" "dhgrp"]
		set dhgrp_list [split $dhgrp]
		if {[llength $dhgrp_list] > 1} {
			cli_set_errmsg "Can only select one Diffie-Hellman group when mode is aggressive"
			return 0
		}
	}
}

if { $authmethod eq "psk" } {
    set psk [cli_get_value $CLI_CUR_NODE "" "" "psksecret"]
    if { [string compare $psk [cli_get_defvalue $CLI_CUR_NODE_NAME "psksecret"] ] == 0 } {
        cli_set_errmsg "Pre-share key must be set"
        return 0
    }
} elseif { $authmethod eq "signature" && [cli_is_match $CLI_CUR_NODE 0 "" "certificate" 0 ""]} {
    cli_set_errmsg "Certificate must be set"
    return 0
}

return 1
	%}
	"vpn ipsec phase1-interface name" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set zone_node [cli_get_node $CLI_CUR_VDOM_NODE "system zone" $name ""]
if {$zone_node != 0} {
	cli_set_errmsg "entry exists"
	return 0
}
set phase1_node [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1" $name ""]
if {$phase1_node != 0} {
	cli_set_errmsg "entry exists"
	return 0
}
set manualkey_node [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec manualkey" $name ""]
if {$manualkey_node != 0} {
	cli_set_errmsg "entry exists"
	return 0
}
set manualkey_interface_node [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec manualkey-interface" $name ""]
if {$manualkey_interface_node != 0} {
	cli_set_errmsg "entry exists"
	return 0
}
set interface_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
if {$interface_node != 0} {
	set interface_type [cli_get_value $interface_node "" "" "type"]
	set interface_vdom [string trim [cli_get_value $interface_node "" "" "vdom"] \"]
	if {$interface_type ne "tunnel"} {
		cli_set_errmsg "entry exists"
		return 0
	}
	if {$interface_vdom ne $CLI_CUR_VDOM_NAME} {
		cli_set_errmsg "entry exists"
		return 0
	}
	## for rename check
	set intflist [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
	set match_nr 0
	foreach intf $intflist {
		set iname [cli_get_value $intf "" "" "name"]
		if { $name eq $iname } {
			incr match_nr
		}
	}
	if { $match_nr > 1 } {
		cli_set_errmsg "entry exists"
		return 0
	}
}
return 1
	%}
        "vpn ipsec phase1-interface interface" = %{
set intf [cli_get_value $CLI_CUR_NODE "" "" ""]
set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $intf ""]
if {[cli_get_value $intfnode "" "" "type"] eq "tunnel" && [cli_get_value $intfnode "" "" "mode"] ne "pppoe"} {
        cli_set_errmsg "Interface cannot be tunnel type"
        return 0
}
if {$CLI_ACT ne "add" && $intf ne $CLI_ORG_ATTR} {
	set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	if {[cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall policy" "action" 0 "ipsec" "vpntunnel" 0 "\"$name\"" "dstintf" 0 $CLI_ORG_ATTR]} {
		cli_set_errmsg "phase1-interface $name is used by policy:vpntunnel"
		return 0
	}
}
return 1
	%}
	"vpn ipsec phase1-interface remote-gw" = %{
if { ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"] || ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "static"] } {
	return 1
}

set remote_gw [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $remote_gw eq "0.0.0.0" } {
	cli_set_errmsg "Attribute 'remote-gw' value '0.0.0.0' checkingfail"
	return 0
}

set gw_list [split $remote_gw .]
set gw_byte1 [lindex $gw_list 0]
if {$gw_byte1 & 0x0ff == 127 && $gw_byte1 & 0xf0 == 0xe0} {
	cli_set_errmsg "invalid gateway"
	return 0
}
return 1
	%}
	"vpn ipsec phase1-interface {local-gw6 remote-gw6}" = %{
set addr6 [cli_get_value $CLI_CUR_NODE "" "" ""]
## "::" is default value
if { $addr6 eq "::" } {
	return 1
}
set errmsg [cli_check_ipv6_addr $addr6]
if { $errmsg ne ""} {
	cli_set_errmsg "$errmsg"
	return 0
}
return 1
	%}
        "vpn ipsec phase1-interface peer" = %{
if { ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peertype" 0 "peer"] } {
	return 1
}
if { ![cli_branchpt_start 500 1100] } {
	set peertype [cli_get_col_value $CLI_CUR_PARENT_NODE "" "peertype" ""]
	if { $peertype eq "" } {
		return 1
	}
}
set peer [cli_get_value $CLI_CUR_NODE "" "" ""]
if {($peer eq "") || ($peer eq "FGh_FtMngr") || ($peer eq "FGh_FtiLog1") ||
    ($peer eq "FGh_FtiLog2") || ($peer eq "FGh_FtiLog3")} {
        cli_set_errmsg "peer invalid value"
        return 0
}
return 1
        %}
	"vpn ipsec phase1-interface peergrp" = %{
set peergrp [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$peergrp ne ""} {
	set authusr_node [cli_get_node $CLI_CUR_VDOM_NODE "user group" $peergrp ""]
	return 1
	if {$authusr_node == 0} {
		cli_set_errmsg "invalid value"
		return 0
	}
	set usrs [cli_get_value $authusr_node "" "" "member"]
	if {$usrs eq ""} {
		cli_set_errmsg "invalid value"
		return 0
	}
	set found 0
	foreach e $usrs {
		set usr_node [cli_get_node $CLI_CUR_VDOM_NODE "user local" $e ""]
		if {$usr_node != 0} {
			if {[cli_is_match $usr_node 0 "" "type" 0 "password"]} {
				set found 1
				break
			}
		}
	}
	if {$found == 0} {
		cli_set_errmsg "invalid value"
		return 0
	}
}
return 1
	%}

	"vpn ipsec phase1-interface peertype" = %{
set peertype [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $peertype eq "dialup" } {
	set usergrp [cli_get_value $CLI_CUR_PARENT_NODE "" "" "usrgrp"]
	if { $usergrp eq "" } {
		cli_set_errmsg "User group must be set"
		return 0
	}
}
return 1
	%}

	"vpn ipsec phase1-interface monitor-phase1" = %{
set monitor [cli_get_value $CLI_CUR_NODE "" "" ""]
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "name" ""]
set monitor [string trim $monitor \"]
if {$monitor eq $name} {
	cli_set_errmsg "monitor-phase1 invalid value"
	return 0
}
set match_nr [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "vpn ipsec phase1-interface" "monitor-phase1" 0 $monitor]
if {$match_nr > 1} {
        cli_set_errmsg "monitor-phase1 02 invalid value"
        return 0
}
return 1
	%}
        "vpn ipsec phase1-interface dpd-retryinterval" = %{
set retryinterval [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$retryinterval eq ""} {
        cli_set_errmsg "dpd-retryinterval value can not be empty"
        return 0
}
set count 1
set max_retryinterval 60
if { [cli_ver_start 600 0] } {
	set max_retryinterval 3600
}
foreach digit $retryinterval {
        if {$count == 1} {
                if {($digit < 0) || ($digit > $max_retryinterval)} {
                        cli_set_errmsg "dpd-retryinterval seconds out of range 0 to $max_retryinterval"
                        return 0
                }
        } elseif {$count == 2} {
                if {($digit < 0) || ($digit > 999)} {
                        cli_set_errmsg "dpd-retryinterval milliseconds out of range 0 to 999"
                        return 0
                }
        } else {
                cli_set_errmsg "dpd-retryinterval only accept 2 values as seconds and milliseconds"
                return 0
        }
        incr count
}
return 1
        %}
	"vpn ipsec {phase1 phase1-interface} usrgrp" = %{
set usrgrp [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$usrgrp ne ""} {
	set usrgrp_datasrc [cli_get_node $CLI_CUR_VDOM_NODE "user group" $usrgrp ""]
	if {$usrgrp_datasrc == 0} {
### User group might be copied from adom level later
#		cli_set_errmsg "user group not exist"
		return 1
	}
	set grpmember [cli_get_value $usrgrp_datasrc "" "" "member"]
	set match 0
	foreach member $grpmember {
		set member [string trim $member \"]
		if {![cli_is_match $CLI_CUR_VDOM_NODE 1 "user local" "name" 0 $member]} {
### All members of user group should be local. Installation will fail otherwise.
			cli_set_errmsg "not a local user"
			return 0
#			set match 1
#			break
		}
	}
#	if {$match == 0} {
#		cli_set_errmsg "not a local user"
#		return 0
#	}
}
return 1
	%}
	"vpn ipsec {phase1 phase1-interface} {xauthtype authusrgrp ike-version eap}" = %{
set eap [cli_get_value $CLI_CUR_PARENT_NODE "" "" "eap"]
set ikeversion [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ike-version"]
set authusrgrp [cli_get_value $CLI_CUR_PARENT_NODE "" "" "authusrgrp"]
set xauthtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "xauthtype"]
if {$eap eq "enable" && $ikeversion != 2} {
	cli_set_errmsg "vpn ipsec phase1-interface eap: ike-version must be 2"
	return 0
}
if {$eap eq "enable" && ($authusrgrp eq "")} {
	cli_set_errmsg "vpn ipsec phase1-interface authusrgrp must be set when eap is enable"
	return 0
}
if {$authusrgrp ne ""} {
	set usrgrp_datasrc [cli_get_node $CLI_CUR_VDOM_NODE "user group" $authusrgrp ""]
	if {$usrgrp_datasrc == 0} {
### User group might be copied from adom level later
#		cli_set_errmsg "user group not exist"
		return 1
	}
	set grptype [cli_get_value $usrgrp_datasrc "" "" "group-type"]
	if { $grptype ne "firewall" } {
		cli_set_errmsg "only firewall-type group is allowed for authusrgrp"
		return 0
	}
}
return 1
	%}
	"vpn ipsec {phase1 phase1-interface} psksecret" = %{
if { ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authmethod" 0 "psk"] } {
	return 1
}
set pass [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [string compare -length 4 $pass "ENC "] } {
	if { [string length $pass] < 6 } {
		cli_set_errmsg "Minimum psksecret length is 6"
			return 0
	}
} elseif { [string compare $pass [cli_get_defvalue $CLI_CUR_PARENT_NAME "psksecret"] ] == 0 } {
	cli_set_errmsg "Minimum psksecret length is 6"
		return 0
}
return 1
	%}
	"vpn ipsec {phase1 phase1-interface} psksecret-remote" = %{
if { ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authmethod-remote" 0 "psk"] } {
	return 1
}
set pass [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [string compare -length 4 $pass "ENC "] } {
	if { [string length $pass] < 6 } {
		cli_set_errmsg "Minimum psksecret length is 6"
			return 0
	}
} elseif { [string compare $pass [cli_get_defvalue $CLI_CUR_PARENT_NAME "psksecret-remote"] ] == 0 } {
	cli_set_errmsg "Minimum psksecret length is 6"
		return 0
}
return 1
	%}
	"vpn ipsec phase1" = %{
set interface [cli_get_value $CLI_CUR_NODE "" "" "interface"]
proc check_id_conflict {node path peerID localID peertype} {
	global CLI_CUR_NODE
	global interface
	set localgw [cli_get_value $CLI_CUR_NODE "" "" "local-gw"]

	if {$localgw ne ""} {
		if {$peerID ne "" && $peertype ne "" && ($peertype ne "dialup"  && $peertype ne "any")} {
			set match_nr [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"local-gw\" 0 $localgw \"peerid\" 0 $peerID]
			if {$match_nr != 0} {
				set match_nr_w_peertype [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"local-gw\" 0 $localgw \"peerid\" 0 $peerID  \"peertype\" 1 \"dialup\"]
				if {$match_nr == $match_nr_w_peertype} {
					return -1
				}
			}
		}
		if {$localID ne ""} {
			set match_nr [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"local-gw\" 0 $localgw \"peerid\" 0 $localID]
			if {$match_nr != 0} {
				set match_nr_w_peertype [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"local-gw\" 0 $localgw \"peerid\" 0 $localID  \"peertype\" 1 \"dialup\"]
				if {$match_nr == $match_nr_w_peertype} {
					return -1
				}
			}
		}
	} else {
		if {$peerID ne "" && $peertype ne "" && ($peertype ne "dialup"  && $peertype ne "any")} {
			set match_nr [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"peerid\" 0 $peerID]
			if {$match_nr != 0} {
				set match_nr_w_peertype [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"peerid\" 0 $peerID  \"peertype\" 1 \"dialup\"]
				if {$match_nr == $match_nr_w_peertype} {
					return -1
				}
			}
		}
		if {$localID ne ""} {
			set match_nr [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"peerid\" 0 $localID]
			if {$match_nr != 0} {
				set match_nr_w_peertype [cli_get_match_nr $node 1 $path \"interface\" 0 $interface \"peerid\" 0 $localID  \"peertype\" 1 \"dialup\"]
				if {$match_nr == $match_nr_w_peertype} {
					return -1
				}
			}
		}
	}
	return 0
}
set peerID [cli_get_value $CLI_CUR_NODE "" "" "peerid"]
set localID [cli_get_value $CLI_CUR_NODE "" "" "localid"]
set peertype [cli_get_value $CLI_CUR_NODE "" "" "peertype"]
if {$peertype eq "one"} {
	if {$peerID eq ""} {
		cli_set_errmsg "empty value"
		return 0
	}
}
if {$peerID ne "" || $localID ne ""} {
	if {[check_id_conflict $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $peerID $localID $peertype] ne 0} {
		cli_set_errmsg "same peer/local ID"
		return 0
	}
	if {[check_id_conflict $CLI_CUR_PARENT_NODE "" $peerID $localID $peertype] ne 0} {
		cli_set_errmsg "same peer/local ID"
		return 0
	}
}
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { ($type eq "static") && [cli_ver_start 500 0] } {
        set ipversion [cli_get_value $CLI_CUR_NODE "" "" "ip-version"]
        if {$ipversion eq "4"} {
                set remote_gw [cli_get_value $CLI_CUR_NODE "" "" "remote-gw"]
                if {[cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "vpn ipsec phase1" "interface" 0 $interface "remote-gw" 0 $remote_gw] > 1} {
                        cli_set_errmsg "duplicate remote gateway"
                        return 0
                }
                if {[cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "vpn ipsec phase1-interface" "interface" 0 $interface "remote-gw" 0 $remote_gw] > 0} {
                        cli_set_errmsg "duplicate remote gateway"
                        return 0
                }
        } else {
                set remote_gw6 [cli_get_value $CLI_CUR_NODE "" "" "remote-gw6"]
                if {[cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "vpn ipsec phase1" "interface" 0 $interface "ip-version" 0 "6" "remote-gw6" 0 $remote_gw6] > 1} {
                        cli_set_errmsg "duplicate remote gateway"
                        return 0
                }
                if {[cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "vpn ipsec phase1-interface" "interface" 0 $interface "ip-version" 0 "6" "remote-gw6" 0 $remote_gw6] > 0} {
                        cli_set_errmsg "duplicate remote gateway"
                        return 0
                }
        }
}
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set xauth_type [cli_get_value $CLI_CUR_NODE "" "" "xauthtype"]
if {$xauth_type eq "client"} {
	if {$type eq "dynamic"} {
		cli_set_errmsg "xauthtype can not be client while remote gateway is dialup"
		return 0
	}
	set xauth_usr_node [cli_get_node $CLI_CUR_NODE "" "" "authusr"]
	if {$xauth_usr_node == 0} {
		cli_set_errmsg "authusr must be set"
		return 0
	}
}
set xauth_usrgrp [cli_get_value $CLI_CUR_NODE "" "" "authusrgrp"]
if {$xauth_type eq "pap" || $xauth_type eq "chap" || $xauth_type eq "auto"} {
	if {$type ne "dynamic"} {
		cli_set_errmsg "invalid setting"
		return 0
	}
	if {$xauth_usrgrp eq ""} {
		cli_set_errmsg "empty user group"
		return 0
	}
}
### User group might be copied from adom level later
#if {$xauth_usrgrp ne ""} {
#	set xauth_usrgrp_datasrc [cli_get_node $CLI_CUR_VDOM_NODE "user group" $xauth_usrgrp ""]
#	if {$xauth_usrgrp_datasrc == 0} {
#		cli_set_errmsg "user group name"
#		return 0
#	}
#}
set usrgrp [cli_get_value $CLI_CUR_NODE "" "" "usrgrp"]
### User group might be copied from adom level later
#if {$usrgrp ne ""} {
#	set usrgrp_datasrc [cli_get_node $CLI_CUR_VDOM_NODE "user group" $usrgrp ""]
#	if {$usrgrp_datasrc == 0} {
#		cli_set_errmsg "user group name"
#		return 0
#	}
#}
if { ![cli_ver_start 500 2] } {
	set mode [cli_get_value $CLI_CUR_NODE "" "" "mode"]
	if {$type ne "dynamic" && $mode eq "aggressive"} {
		set dhgrp [cli_get_value $CLI_CUR_NODE "" "" "dhgrp"]
		set dhgrp_list [split $dhgrp]
		if {[llength $dhgrp_list] > 1} {
			cli_set_errmsg "Can only select one Diffie-Hellman group when mode is aggressive"
			return 0
		}
	}
}

set authmethod [cli_get_value $CLI_CUR_NODE "" "" "authmethod"]
if { $authmethod eq "psk" } {
	set psk [cli_get_value $CLI_CUR_NODE "" "" "psksecret"]
	if { [string compare $psk [cli_get_defvalue $CLI_CUR_NODE_NAME "psksecret"] ] == 0 } {
		cli_set_errmsg "Pre-share key must be set"
		return 0
	}
} elseif { $authmethod eq "signature" && [cli_is_match $CLI_CUR_NODE 0 "" "certificate" 0 ""]} {
	cli_set_errmsg "Certificate must be set"
	return 0
}

return 1
	%}
	"vpn ipsec phase1 name" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set node [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $name ""]
if {$node == 0} {
	set node [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec manualkey" $name ""]
}
if {$node == 0} {
	set node [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec manualkey-interface" $name ""]
}
if {$node != 0} {
	cli_set_errmsg "entry exists"
	return 0
}
return 1
	%}
	"vpn ipsec phase1 remote-gw" = %{
if { ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "static"] } {
	return 1
}
set remote_gw [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $remote_gw eq "0.0.0.0" } {
	cli_set_errmsg "Attribute 'remote-gw' value '0.0.0.0' checkingfail"
	return 0
}

set gw_list [split $remote_gw .]
set gw_byte1 [lindex $gw_list 0]
if {$gw_byte1 & 0x0ff == 127 && $gw_byte1 & 0xf0 == 0xe0} {
	cli_set_errmsg "invalid gateway"
	return 0
}
return 1
	%}
	"vpn ipsec phase1 peer" = %{
if { ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peertype" 0 "peer"] } {
	return 1
}
set peer [cli_get_value $CLI_CUR_NODE "" "" ""]
if {($peer eq "") || ($peer eq "FGh_FtMngr") || ($peer eq "FGh_FtiLog1") ||
    ($peer eq "FGh_FtiLog2") || ($peer eq "FGh_FtiLog3")} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"vpn ipsec phase1 interface" = %{
set intf [cli_get_value $CLI_CUR_NODE "" "" ""]
if {[cli_get_value $CLI_GLOBAL_NODE "system interface" $intf "type"] eq "tunnel"} {
	cli_set_errmsg "invalid value"
	return 0
}
if {$CLI_ACT ne "add" && $intf ne $CLI_ORG_ATTR} {
	set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	if {[cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall policy" "action" 0 "ipsec" "vpntunnel" 0 "\"$name\"" "dstintf" 0 $CLI_ORG_ATTR]} {
		cli_set_errmsg "phase1 $name is used by policy:vpntunnel"
		return 0
	}
}
return 1
	%}
	"vpn ipsec phase1 dpd-retryinterval" = %{
set retryinterval [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$retryinterval eq ""} {
	cli_set_errmsg "invalid value"
	return 0
}
set count 1
foreach digit $retryinterval {
	if {$count == 1} {
		if {($digit < 0) || ($digit > 60)} {
			cli_set_errmsg "invalid value"
			return 0
		}
	} elseif {$count == 2} {
		if {($digit < 0) || ($digit > 999)} {
			cli_set_errmsg "invalid value"
			return 0
		}
	} else {
		cli_set_errmsg "invalid value"
		return 0
	}
	incr count
}
return 1
	%}
	"vpn ipsec phase2-interface" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ($name eq "") || ($name eq "FGh_FtMngr") || ($name eq "FGh_FtiLog1") ||
     ($name eq "FGh_FtiLog2") || ($name eq "FGh_FtiLog3")} {
      cli_set_errmsg "invalid value"
      return 0
}
namespace import global::verify_proxyid
set name_count 0
set ret [verify_proxyid "src" name_count]
set is_src_name $name_count
if {$ret < 0} {
	cli_set_errmsg "invalid src ip"
	return 0
}
set ret [verify_proxyid "dst" name_count]
if {$ret < 0} {
	cli_set_errmsg "invalid dst ip"
	return 0
}
if {$name_count == 1} {
	if {$is_src_name == 1} {
		set msg "src"
	} else {
		set msg "dst"
	}
	cli_set_errmsg "cannot use named address for only $msg"
	return 0
}
if { [cli_branchpt_start 600 1761] } {
	namespace import global::bin2dec
	set dfcode [cli_get_value $CLI_CUR_NODE "" "" "diffservcode"]
	if { $dfcode ne "" } {
		set val [bin2dec $dfcode]
		if { $val >= 64 || $val < 0 } {
			cli_set_errmsg "diffservcode out of range, the range is binary between 000000 and 111111."
			return 0
		}
	}
}
return 1
	%}
        "vpn ipsec phase2-interface phase1name" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ($name eq "") || ($name eq "FGh_FtMngr") || ($name eq "FGh_FtiLog1") ||
     ($name eq "FGh_FtiLog2") || ($name eq "FGh_FtiLog3")} {
      cli_set_errmsg "invalid value"
      return 0
}
return 1
	%}
	"vpn ipsec phase2" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ($name eq "") || ($name eq "FGh_FtMngr") || ($name eq "FGh_FtiLog1") ||
     ($name eq "FGh_FtiLog2") || ($name eq "FGh_FtiLog3")} {
      cli_set_errmsg "invalid value"
      return 0
}
namespace import global::verify_proxyid
set name_count 0
set ret [verify_proxyid "src" name_count]
if {$ret < 0} {
	cli_set_errmsg "invalid ip"
	return 0
}
set is_src_name $name_count
set ret [verify_proxyid "dst" name_count]
if {$ret < 0} {
	cli_set_errmsg "invalid ip"
	return 0
}
if {$name_count == 1} {
	if {$is_sr_name == 1} {
		set msg "src"
	} else {
		set msg "dst"
	}
	cli_set_errmsg "cannot use named address for only $msg"
	return 0
}
set phase1 [cli_get_value $CLI_CUR_NODE "" "" "phase1name"]
if { $phase1 eq "" } {
	cli_set_errmsg "Phase 1 must be set"
	return 0
}
if { [cli_branchpt_start 600 1761] } {
	namespace import global::bin2dec
	set dfcode [cli_get_value $CLI_CUR_NODE "" "" "diffservcode"]
	if { $dfcode ne "" } {
		set val [bin2dec $dfcode]
		if { $val >= 64 || $val < 0 } {
			cli_set_errmsg "diffservcode out of range, the range is binary between 000000 and 111111."
			return 0
		}
	}
}
return 1
	%}
	"vpn ipsec phase2 phase1name" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ($name eq "") || ($name eq "FGh_FtMngr") || ($name eq "FGh_FtiLog1") ||
     ($name eq "FGh_FtiLog2") || ($name eq "FGh_FtiLog3")} {
      cli_set_errmsg "invalid value"
      return 0
}
return 1
	%}

	"vpn ipsec manualkey-interface" = %{
set auth_alg [cli_get_value $CLI_CUR_NODE "" "" "auth-alg"]
set enc_alg [cli_get_value $CLI_CUR_NODE "" "" "enc-alg"]
if {$auth_alg ne ""} {
	set auth_key [cli_get_value $CLI_CUR_NODE "" "" "auth-key"]
	if {$auth_key eq ""} {
		cli_set_errmsg "invalid auth key"
		return 0
	}
}
if {$enc_alg ne ""} {
	set enc_key [cli_get_value $CLI_CUR_NODE "" "" "enc-key"]
	if {$enc_key eq ""} {
		cli_set_errmsg "invalid auth key"
		return 0
	}
}
set interface [cli_get_value $CLI_CUR_NODE "" "" "interface"]
if {$interface eq ""} {
	cli_set_errmsg "invalid dev index"
	return 0
}
if {[cli_get_value $CLI_GLOBAL_NODE "system interface" $interface "type"] eq "tunnel"} {
        cli_set_errmsg "interface $interface type can not be \"tunnel\""
        return 0
}
return 1
	%}
	"vpn ipsec manualkey-interface remote-gw" = %{
set remote_gw [cli_get_value $CLI_CUR_NODE "" "" ""]
set gw_list [split $remote_gw .]
set gw_byte1 [lindex $gw_list 0]
if {$gw_byte1 & 0x0ff == 127 && $gw_byte1 & 0xf0 == 0xe0} {
	cli_set_errmsg "invalid gateway"
	return 0
}
return 1
	%}
	"vpn ipsec manualkey-interface name" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set chknode [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1" $name ""]
if {$chknode == 0} {
	set chknode [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $name ""]
}
if {$chknode == 0} {
	set chknode [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec manualkey" $name ""]
}
if {$chknode != 0} {
	cli_set_errmsg "entry exists"
	return 0
}
set chknode [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
if {$chknode != 0} {
	set interface_type [cli_get_value $chknode "" "" "type"]
	if {$interface_type ne "tunnel"} {
		cli_set_errmsg "entry exists"
		return 0
	}
}
return 1
	%}

	"vpn ipsec manualkey" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ($name eq "") || ($name eq "FGh_FtMngr") || ($name eq "FGh_FtiLog1") ||
     ($name eq "FGh_FtiLog2") || ($name eq "FGh_FtiLog3")} {
      cli_set_errmsg "invalid value"
      return 0
}
if {$name ne ""} {
        if {[cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1" $name ""]} {
                cli_set_errmsg "entry exists"
                return 0
        }
        if {[cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $name ""]} {
                cli_set_errmsg "entry exists"
                return 0
        }
        if {[cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec manualkey-interface" $name ""]} {
                cli_set_errmsg "entry exists"
                return 0
        }
}

set intf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
if {$intf eq ""} {
	cli_set_errmsg "local interface must be set"
	return 0
}
set remote_gw [cli_get_value $CLI_CUR_NODE "" "" "remote-gw"]
if {$remote_gw eq ""} {
	cli_set_errmsg "remote gateway must be set"
	return 0
}
namespace import global::check_gw
if {[check_gw $remote_gw] == -1} {
	cli_set_errmsg "invalid gateway, must be unicast ip addr"
	return 0
}

set auth_alg [cli_get_value $CLI_CUR_NODE "" "" "authentication"]
set enc_alg [cli_get_value $CLI_CUR_NODE "" "" "encryption"]

if {$auth_alg eq "null" && $enc_alg eq "null"} {
	cli_set_errmsg "at least one of authentication and encryption has to be set"
	return 0
}
if {$auth_alg ne "null"} {
	set auth_key [cli_get_value $CLI_CUR_NODE "" "" "authkey"]
	if { $auth_key eq "" || $auth_key eq "-" } {
		cli_set_errmsg "invalid authkey. key must be set (16 hex characters)."
		return 0
	}
}
if {$enc_alg ne "null"} {
	set enc_key [cli_get_value $CLI_CUR_NODE "" "" "enckey"]
	if { $enc_key eq "" || $enc_key eq "-" } {
		cli_set_errmsg "invalid enckey. key must be set (16 hex characters)."
		return 0
	}
}
set remote_gw [cli_get_value $CLI_CUR_NODE "" "" "remote-gw"]
set localspi [cli_get_value $CLI_CUR_NODE "" "" "localspi"]
set remotespi [cli_get_value $CLI_CUR_NODE "" "" "remotespi"]
set match_nr [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "vpn ipsec manualkey" "remote-gw" 0 $remote_gw "localspi" 0 $localspi]
if {$match_nr > 1} {
	cli_set_errmsg "duplicate"
	return 0
}
set match_nr [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "vpn ipsec manualkey" "remote-gw" 0 $remote_gw "remotespi" 0 $remotespi]
if {$match_nr > 1} {
	cli_set_errmsg "duplicate"
	return 0
}
return 1
	%}
	"vpn ipsec manualkey {localspi remotespi}" = %{
set spi [cli_get_value $CLI_CUR_NODE "" "" ""]

if {[regexp {^0[xX][0-9a-fA-F]{3,8}$} $spi] eq 0 } {
	cli_set_errmsg "$CLI_CUR_NODE_NAME must be hexidecimal between 0x100 to 0xffffffff"
	return 0
}
return 1
	%}
	"vpn ipsec manualkey remote-gw" = %{
set remote_gw [cli_get_value $CLI_CUR_NODE "" "" ""]

if {$remote_gw eq ""} {
	cli_set_errmsg "remote gateway must be set"
	return 0
}
set gw_list [split $remote_gw .]
set gw_byte1 [lindex $gw_list 0]
if {$gw_byte1 & 0x0ff == 127 && $gw_byte1 & 0xf0 == 0xe0} {
	cli_set_errmsg "invalid gateway"
	return 0
}
return 1
	%}
	"vpn ipsec manualkey interface" = %{
set intf [cli_get_value $CLI_CUR_NODE "" "" ""]

if {$intf eq ""} {
	cli_set_errmsg "local interface must be set"
	return 0
}
if {[cli_get_value $CLI_GLOBAL_NODE "system interface" $intf "type"] eq "tunnel"} {
        cli_set_errmsg "interface $intf type can not be \"tunnel\""
        return 0
}
if {$CLI_ACT ne "add"} {
	if {[cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall policy" "action" 0 "ipsec" "vpntunnel" 0 $CLI_ORG_ATTR]} {
		cli_set_errmsg "used by firewall policy"
		return 0
	}
}
return 1
	%}

	"vpn ipsec concentrator" = %{
set member [cli_get_value $CLI_CUR_NODE "" "" "member"]
foreach e $member {
	set match_nr [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "vpn ipsec concentrator" "member" 0 '*$e*']
	if {$match_nr > 1} {
		cli_set_errmsg "svrgrp"
		return 0
	}
}
return 1
	%}

	"vpn pptp" = %{
set sip [cli_get_value $CLI_CUR_NODE "" "" "sip"]
set eip [cli_get_value $CLI_CUR_NODE "" "" "eip"]
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
set iplist [split $sip .]
set sipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
set iplist [split $eip .]
set eipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
if {$sipint > $eipint} {
	cli_set_errmsg "start ip is larger"
	return 0
}
if {$status eq "enable"} {
	if {($sipint & 0xFFFFFF00) != ($eipint & 0xFFFFFF00)} {
		cli_set_errmsg "invalid ip range"
		return 0
	}
	if {($sipint & 0x000000FF) == 0 || ($sipint & 0x000000FF) == 0x000000FF} {
		cli_set_errmsg "invalid ip range"
		return 0
	}
	if {($eipint & 0x000000FF) == 0 || ($eipint & 0x000000FF) == 0x000000FF} {
		cli_set_errmsg "invalid ip range"
		return 0
	}
}
set l2tp_status [cli_get_value $CLI_CUR_VDOM_NODE "vpn l2tp" "" "status"]
set l2tp_sip [cli_get_value $CLI_CUR_VDOM_NODE "vpn l2tp" "" "sip"]
set l2tp_eip [cli_get_value $CLI_CUR_VDOM_NODE "vpn l2tp" "" "eip"]
if {$l2tp_status eq "enable" && $l2tp_sip ne "" && $l2tp_eip ne ""} {
	set iplist [split $l2tp_sip .]
	set l2tp_sipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
	set iplist [split $l2tp_eip .]
	set l2tp_eipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
	if {($sipint & 0xFFFF0000) == ($l2tp_sipint & 0xFFFF0000)} {
		if {$sipint >= $l2tp_sipint && $sipint <= $l2tp_eipint} {
			cli_set_errmsg "pptp/l2tp overlap"
			return 0
		}
		if {$eipint >= $l2tp_sipint && $eipint <= $l2tp_eipint} {
			cli_set_errmsg "pptp/l2tp overlap"
			return 0
		}
	}
}
set usrgrp [cli_get_value $CLI_CUR_NODE "" "" "usrgrp"]
if {$usrgrp ne ""} {
	set grpnode [cli_get_node $CLI_CUR_VDOM_NODE "user group" $usrgrp ""]
	if {$grpnode == 0} {
		cli_set_errmsg "user group not exist"
		return 0
	}
	set type [cli_get_value $grpnode "" "" "group-type"]
	if {$type ne "firewall"} {
		cli_set_errmsg "user group type"
		return 0
	}
}
return 1
	%}

	"vpn ssl settings tunnel-ip-pools" = %{
namespace import global::vpn_invalid_tunnel_ip_pools
set ippools [cli_get_value $CLI_CUR_NODE "" "" ""]
foreach ip $ippools {
	if { [vpn_invalid_tunnel_ip_pools $ip] } {
		return 0
	}
}
return 1
	%}
	"vpn ssl settings" = %{
if { ![cli_is_traffic_vdom] } {
	cli_set_errmsg "Device vdom-mode is set to split-vdom, which does not allow ssl vpn change."
	return 0
}

set tunnel_startip [cli_get_value $CLI_CUR_NODE "" "" "tunnel-startip"]
set tunnel_endip [cli_get_value $CLI_CUR_NODE "" "" "tunnel-endip"]
if {$tunnel_startip ne ""} {
	set iplist [split $tunnel_startip .]
	set tunnel_startipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
} else {
	set tunnel_startipint 0
}
if {$tunnel_endip ne ""} {
	set iplist [split $tunnel_endip .]
	set tunnel_endipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
} else {
	set tunnel_endipint 0
}
if {$tunnel_startipint > $tunnel_endipint} {
	cli_set_errmsg "invalid ip range"
	return 0
}
if {$tunnel_startipint == 0} {
	set sslvpn_grps [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "user group" "group-type" 0 "sslvpn" "sslvpn-tunnel" 0 "enable"]
	foreach e $sslvpn_grps {
		set grp_sip [cli_get_value $e "" "" "sslvpn-tunnel-startip"]
		if {$grp_sip == 0} {
			cli_set_errmsg "invalid ip range"
			return 0
		}
	}
}
set auth [cli_get_value $CLI_CUR_NODE "" "" "servercert"]
namespace import global::auth_cert_not_exist
if { [auth_cert_not_exist $auth] } {
        cli_set_errmsg "Certificate $auth does not exist"
        return 0
}
return 1
	%}

	"vpn ssl settings authentication-rule" = %{
if { [cli_ver_start 500 2] } {
	set node [cli_get_node $CLI_CUR_VDOM_NODE "vpn ssl settings" "" ""]
	if { !$node } {
		cli_set_errmsg "Invalid node for vpn ssl settings."
		return 0
	}
	set s_srcintf [cli_get_value $node "" "" "source-interface"]
	set r_srcintf [cli_get_value $CLI_CUR_NODE "" "" "source-interface"]
	if { $s_srcintf eq "" } {
		if { $r_srcintf eq "" } {
			cli_set_errmsg "Please set at least one source-interface, and save."
			return 0
		}
	}
	if { $r_srcintf ne "" } {
		set srcaddr  [cli_get_value $CLI_CUR_NODE "" "" "source-address"]
		set srcaddr6 [cli_get_value $CLI_CUR_NODE "" "" "source-address6"]
		if { $srcaddr eq "" && $srcaddr6 eq "" } {
			cli_set_errmsg "Please set source-address or source-address6."
			return 0
		}
	}
	set r_users  [cli_get_value $CLI_CUR_NODE "" "" "users"]
	set r_groups [cli_get_value $CLI_CUR_NODE "" "" "groups"]
	if { $r_users eq "" && $r_groups eq "" } {
		cli_set_errmsg "Please set users or groups."
		return 0
	}
	set r_portal [cli_get_value $CLI_CUR_NODE "" "" "portal"]
	if { $r_portal eq "" } {
		cli_set_errmsg "Please set portal."
		return 0
	}
}
return 1
	%}

	"vpn certificate crl ldap-server" = %{
set ldap_server [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]
if {$ldap_server ne ""} {
	set vdom [cli_get_value $CLI_CUR_NODE "" "" "update-vdom"]
	set vnode [cli_get_vdom_node $vdom]
	if {[cli_get_node $vnode "user ldap" $ldap_server ""] == 0} {
		cli_set_errmsg "invalid value"
		return 0
	}
}
return 1
	%}
	"vpn certificate crl http-url" = %{
set http_url [cli_get_value $CLI_CUR_NODE "" "" ""]
set http_url [string trim $http_url \"]
if {$http_url ne "" && [string match {http://*} $http_url] == 0} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"vpn certificate crl scep-url" = %{
set scep_url [cli_get_value $CLI_CUR_NODE "" "" ""]
set scep_url [string trim $scep_url \"]
if {$scep_url ne "" && [string match {http://*} $scep_url] == 0} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"vpn certificate crl update-vdom" = %{
set uv [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$CLI_ACT ne "add"} {
	if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "ldap-server"] ne ""} {
		cli_set_errmsg "conflict value"
		return 0
	}
}
return 1
	%}

	"vpn ipsec forticlient usergroupname" = %{
set usergroup [cli_get_value $CLI_CUR_NODE "" "" ""]
set node [cli_get_node $CLI_CUR_VDOM_NODE "user group" $usergroup ""]
if {$node == 0} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"vpn ipsec forticlient phase2name" = %{
set phase2name [cli_get_value $CLI_CUR_NODE "" "" ""]
set phase2 [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase2" $phase2name ""]
if {$phase2 == 0} {
	set phase2 [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase2-interface" $phase2name ""]
}
if {$phase2 == 0} {
	cli_set_errmsg "tunnel not exist"
	return 0
}
set phase1name [cli_get_value $phase2 "" "" "phase1name"]
set phase1 [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1" $phase1name ""]
if {$phase1 == 0} {
	set phase1 [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $phase1name ""]
}
if {$phase1 == 0} {
	cli_set_errmsg "tunnel not exist"
	return 0
}
if {[cli_is_match $phase1 0 "" "type" 0 "dynamic"] == 0} {
	cli_set_errmsg "not dialup tunnel"
	return 0
}
return 1
	%}

	"vpn l2tp" = %{
set sip [cli_get_value $CLI_CUR_NODE "" "" "sip"]
set eip [cli_get_value $CLI_CUR_NODE "" "" "eip"]
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
if {$sip ne ""} {
	set iplist [split $sip .]
	set sipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
} else {
	set sipint 0
}
if {$eip ne ""} {
	set iplist [split $eip .]
	set eipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
} else {
	set eipint 0
}
if {$sipint > $eipint} {
	cli_set_errmsg "start ip is larger"
	return 0
}
if {$status eq "enable"} {
	if {($sipint & 0xFFFF0000) != ($eipint & 0xFFFF0000)} {
		cli_set_errmsg "invalid ip range: start and end IPs must be in the same 16-bit subnet (x.x.0.1 - x.x.255.254)"
		return 0
	}
	if {($sipint & 0x000000FF) == 0 || ($sipint & 0x000000FF) == 0x000000FF} {
		cli_set_errmsg "invalid ip range: start ip must be (x.x.0.1 - x.x.255.254)"
		return 0
	}
	if {($eipint & 0x000000FF) == 0 || ($eipint & 0x000000FF) == 0x000000FF} {
		cli_set_errmsg "invalid ip range: end ip must be (x.x.0.1 - x.x.255.254)"
		return 0
	}
}
set pptp_status [cli_get_value $CLI_CUR_VDOM_NODE "vpn pptp" "" "status"]
set pptp_sip [cli_get_value $CLI_CUR_VDOM_NODE "vpn pptp" "" "sip"]
set pptp_eip [cli_get_value $CLI_CUR_VDOM_NODE "vpn pptp" "" "eip"]
if {$pptp_status eq "enable" && $pptp_sip ne "" && $pptp_eip ne ""} {
	set iplist [split $pptp_sip .]
	set pptp_sipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
	set iplist [split $pptp_eip .]
	set pptp_eipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
	if {($sipint & 0xFFFF0000) == ($pptp_sipint & 0xFFFF0000)} {
		if {$sipint >= $pptp_sipint && $sipint <= $pptp_eipint} {
			cli_set_errmsg "pptp/l2tp overlap"
			return 0
		}
		if {$eipint >= $pptp_sipint && $eipint <= $pptp_eipint} {
			cli_set_errmsg "pptp/l2tp overlap"
			return 0
		}
	}
}
set usrgrp [cli_get_value $CLI_CUR_NODE "" "" "usrgrp"]
if {$usrgrp ne ""} {
	set grpnode [cli_get_node $CLI_CUR_VDOM_NODE "user group" $usrgrp ""]
	if {$grpnode == 0} {
		cli_set_errmsg "user group not exist"
		return 0
	}
}
return 1
	%}

	"system admin" = %{
set admin_vdom [cli_get_value $CLI_CUR_NODE "" "" "vdom"]
set vnode [cli_get_vdom_node $admin_vdom]
set a 1
if {[cli_ver_start 500 0]} {
	set gauth [cli_get_value $CLI_CUR_NODE "" "" "guest-auth"]
	if { $gauth eq "enable" } {
		set a 0
	}
}
if { $a == 1 } {
	set accprofile [cli_get_value $CLI_CUR_NODE "" "" "accprofile"]
	if {$accprofile eq ""} {
		cli_set_errmsg "empty value"
		return 0
	}
}
if {$CLI_IS_RESYNC} {
	return 1
}
if {[cli_is_match $CLI_CUR_NODE 0 "" "peer-auth" 0 "enable"]} {
	set peer_group [cli_get_value $CLI_CUR_NODE "" "" "peer-group"]
	set peergrp_node [cli_get_node $vnode "user group" $peer_group ""]
	if {$peergrp_node} {
		set grp_member [cli_get_value $peergrp_node "" "" "member"]
		foreach e $grp_member {
			if {[cli_get_node $vnode "user peer" $e ""] == 0} {
				cli_set_errmsg "invalid value"
				return 0
			}
		}
	}
}
set radius_auth [cli_get_value $CLI_CUR_NODE "" "" "remote-auth"]
if {[cli_is_match $CLI_CUR_NODE 0 "" "remote-auth" 0 "enable"]} {
	set radius_group [cli_get_value $CLI_CUR_NODE "" "" "remote-group"]
	set radiusgrp_node [cli_get_node $vnode "user group" $radius_group ""]
	if {$radiusgrp_node} {
		set grp_member [cli_get_value $radiusgrp_node "" "" "member"]
		foreach e $grp_member {
			if {[cli_get_node $vnode "user radius" $e ""] == 0 &&
			    [cli_get_node $vnode "user ldap" $e ""] == 0 &&
			    [cli_get_node $vnode "user tacacs+" $e ""] == 0} {
				cli_set_errmsg "invalid value"
				return 0
			}
		}
	}
	if {[cli_is_match $CLI_CUR_NODE 0 "" "wildcard" 0 "enable"]} {
		set match_nr [cli_get_match_nr $CLI_GLOBAL_NODE 1 "system admin" "vdom" 0 $admin_vdom "wildcard" 0 "enable" "remote-group" 0 $radius_group]
		if {$match_nr > 1} {
			cli_set_errmsg "duplicate"
			return 0
		}
	}
}
set two_factor [cli_get_value $CLI_CUR_NODE "" "" "two-factor"]
if {$two_factor eq "fortitoken"} {
	if {[cli_get_value $CLI_CUR_NODE "" "" "fortitoken"] eq ""} {
		cli_set_errmsg "You must specify a FortiToken."
		return 0
	}
	set email [cli_get_value $CLI_CUR_NODE "" "" "email-to"]
	set email [string trim $email \"]
	set sms [cli_get_value $CLI_CUR_NODE "" "" "sms-phone"]
	if {$email eq "" && $sms eq ""} {
		cli_set_errmsg "You must specify an email or SMS phone number."
		return 0
	}
} elseif { $two_factor eq "email" } {
	set email [cli_get_value $CLI_CUR_NODE "" "" "email-to"]
	set email [string trim $email \"]
	if {$email eq ""} {
		cli_set_errmsg "You must specify an email address."
		return 0
	}
	namespace import global::cli_invalid_email
	if { [cli_invalid_email $email] } {
		cli_set_errmsg "$email is not a valid email address."
		return 0
	}
} elseif {$two_factor eq "sms"} {
	if {[cli_ver_start 500 0]} {
		if {[cli_get_value $CLI_CUR_NODE "" "" "sms-phone"] eq ""} {
		        cli_set_errmsg "You must specify an SMS phone number."
		        return 0
		}
	} else {
		if {([cli_get_value $CLI_CUR_NODE "" "" "sms-provider"] eq "") ||
		    ([cli_get_value $CLI_CUR_NODE "" "" "sms-phone"] eq "")} {
		        cli_set_errmsg "You must specify an SMS provider and phone number."
		        return 0
		}
	}
} elseif { $two_factor eq "fortitoken-cloud" } {
	set email [cli_get_value $CLI_CUR_NODE "" "" "email-to"]
	set email [string trim $email \"]
	if {$email eq ""} {
		cli_set_errmsg "You must specify an email address."
		return 0
	}
	namespace import global::cli_invalid_email
	if { [cli_invalid_email $email] } {
		cli_set_errmsg "$email is not a valid email address."
		return 0
	}

	if {[cli_get_value $CLI_CUR_NODE "" "" "sms-phone"] eq ""} {
		cli_set_errmsg "You must specify an SMS phone number and have a '+' in front of country code of phone number."
		return 0
	}

	if {[cli_get_value $CLI_CUR_NODE "" "" "accprofile"] eq ""} {
		cli_set_errmsg "You must specify an accprofile."
		return 0
	}
}
return 1
	%}
	"system admin password" = %{
set password [cli_get_value $CLI_CUR_NODE "" "" ""]
set len [string length $password]
if { $len == 0 } {
	cli_set_errmsg "Password must be set"
	return 0
}
if {[string compare -length 4 $password "ENC "] == 0} {
	if {$len != 180 && $len > 129} {
		cli_set_errmsg "Encrypted password length exceeds maximum length"
		return 0
	}
} else {
	if {[cli_is_match $CLI_GLOBAL_NODE 0 "system global" "CC-mode" 0 "enable"]} {
		if {$len < 8 || $len > 128} {
			cli_set_errmsg "Password must be between 8 and 128 characters long"
			return 0
		}
	} else {
		if { $len > 128} {
			cli_set_errmsg "Password exceeds maximum length (128)"
			return 0
		}
	}
}

##
## system admin password policy check
##
namespace import global::cli_check_admin_password_policy
namespace import global::cli_check_admin_password_change

set new_passwd [cli_get_value $CLI_CUR_NODE "" "" ""]
set old_passwd [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { $new_passwd eq $old_passwd } {
	return 1
}
set is_guest [cli_get_value $CLI_CUR_PARENT_NODE "" "" "guest-auth"]
set policynode ""
if { $is_guest eq "enable" } {
	set policynode [cli_get_node $CLI_GLOBAL_NODE "system password-policy-guest-admin" "" ""]
} else {
	set policynode [cli_get_node $CLI_GLOBAL_NODE "system password-policy" "" ""]
}
if { $policynode ne "" && $policynode != 0 } {
	set p_mode [cli_get_value $policynode "" "" "apply-to"]
	foreach m $p_mode {
		if { $m eq "admin-password" || $m eq "guest-admin-password" } {
			if { [string compare -length 4 $new_passwd "ENC "] != 0 } {
				if { [cli_check_admin_password_policy $policynode $new_passwd] == 0 } {
					cli_set_errmsg "New password must conform to the password policy enforced on this device."
					return 0
				}
			}
			if { $old_passwd != 0 && $old_passwd ne "" && [string compare -length 4 $new_passwd "ENC "] != 0 && [string compare -length 4 $old_passwd "ENC "] != 0 } {
				if { [cli_check_admin_password_change $policynode $new_passwd $old_passwd] == 0 } {
					cli_set_errmsg "New password must conform to the password policy enforced on this device."
					return 0
				}
			}
		}
	}
}

return 1
	%}
	"system admin ssh-public-key1" = %{
set pkey [cli_get_value $CLI_CUR_NODE "" "" ""]

if { [string length $pkey] > 8190 } {
	cli_set_errmsg "value too long"
	return 0
}

if { [string first "\n" $pkey] >= 0 } {
	cli_set_errmsg "invalid value(key should be only one line)"
	return 0
}

if {[regexp {^\s*\"?(ssh-rsa|ssh-dss)\s*AAAAB3NzaC1} $pkey] == 0} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"system admin ssh-public-key2" = %{
set pkey [cli_get_value $CLI_CUR_NODE "" "" ""]

if { [string length $pkey] > 8190 } {
	cli_set_errmsg "value too long"
	return 0
}

if { [string first "\n" $pkey] >= 0 } {
	cli_set_errmsg "invalid value(key should be only one line)"
	return 0
}

if {[regexp {^\s*\"?(ssh-rsa|ssh-dss)\s*AAAAB3NzaC1} $pkey] == 0} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"system admin ssh-public-key3" = %{
set pkey [cli_get_value $CLI_CUR_NODE "" "" ""]

if { [string length $pkey] > 8190 } {
	cli_set_errmsg "value too long"
	return 0
}

if { [string first "\n" $pkey] >= 0 } {
	cli_set_errmsg "invalid value(key should be only one line)"
	return 0
}

if {[regexp {^\s*\"?(ssh-rsa|ssh-dss)\s*AAAAB3NzaC1} $pkey] == 0} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"system autoupdate override" = %{
if {[cli_is_match $CLI_CUR_NODE 0 "" "status" 0 "enable"]} {
	if {[cli_get_value $CLI_CUR_NODE "" "" "address"] eq ""} {
		cli_set_errmsg "address"
		return 0
	}
}
return 1
	%}
	"system autoupdate push-update" = %{
if {[cli_is_match $CLI_CUR_NODE 0 "" "status" 0 "enable"]} {
	if {[cli_get_value $CLI_CUR_NODE "" "" "address"] eq ""} {
		return 0
	}
}
return 1
	%}
	"system autoupdate schedule time" = %{
set time [cli_get_value $CLI_CUR_NODE "" "" ""]
set time [string map {\" ""} $time]
if { $time eq "" } {
	cli_set_errmsg "invalid value"
	return 0
}
set para_num [scan $time "%d:%d" hh mm]
if { $para_num != 2 } {
	cli_set_errmsg "invalid value"
	return 0
}
# min=60 means random time on FGT
if { $hh < 0 || $hh > 23 || $mm < 0 || ($mm > 60 && $mm != 240)} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"system autoupdate tunneling" = %{
if {[cli_is_match $CLI_CUR_NODE 0 "" "status" 0 "enable"]} {
	if {[cli_get_value $CLI_CUR_NODE "" "" "address"] eq ""} {
		cli_set_errmsg "empty value"
		return 0
	}
	if {[cli_get_value $CLI_CUR_NODE "" "" "port"] eq ""} {
		cli_set_errmsg "empty value"
		return 0
	}
}
return 1
	%}
	"system autoupdate clientoverride" = %{
if {[cli_is_match $CLI_CUR_NODE 0 "" "status" 0 "enable"]} {
	if {[cli_get_value $CLI_CUR_NODE "" "" "address"] eq ""} {
		cli_set_errmsg "empty value"
		return 0
	}
}
return 1
	%}

	"system settings manageip" = %{
set ip [cli_get_value $CLI_CUR_NODE "" "" ""]
set ippat1 {(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)}
set iplist [split $ip " "]
set number 0
foreach e $iplist {
	if {$e eq ""} {
		continue;
	}
	set ipmask [split $e "/"]
	if { 2 != [llength $ipmask] } {
		puts "invalid value"
		return 0
	}

	if { $number == 2 } {
		puts "invalid value"
		return 0
	}

	set ip [lindex $ipmask 0]
   	if { (![regexp $ippat1 $ip match]) || ($ip ne $match) } {
		puts "invalid value"
		return 0
	}

	set mask [lindex $ipmask 1]
	if { (![regexp $ippat1 $mask match] && ($mask<0 ||$mask>32)) || ([regexp $ippat1 $mask match] && ($mask ne $match)) } {
		puts "invalid value"
		return 0
	}
	incr number
}
return 1
	%}
	"system settings opmode" = %{
set opmode [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$opmode eq "transparent"} {
	if {[cli_is_match $CLI_GLOBAL_NODE 1 "system interface" "vdom" 0 "\"$CLI_CUR_VDOM_NAME\"" "type" 0 "vdom-link"]} {
		cli_set_errmsg "invalid value"
		return 0
	}
	if {[cli_is_match $CLI_GLOBAL_NODE 1 "system interface" "vdom" 0 "\"$CLI_CUR_VDOM_NAME\"" "type" 0 "loopback"]} {
		cli_set_errmsg "invalid value"
		return 0
	}
	if { [cli_ver_start 700 2] } {
		set vdom_type [cli_get_value $CLI_CUR_NODE "" "" ""]
		if { $vdom_type eq "admin" } {
			cli_set_errmsg "Can not change vdom-type to admin in transparent mode."
			return 0
		}
	}
	set csf_en [cli_get_value $CLI_GLOBAL_NODE "system csf" "" "status"]
	if { $csf_en eq "enable" } {
		cli_set_errmsg "Cannot set opmode to transparent while Cooperative Security Fabric is enabled."
		return 0
	}
}
return 1
	%}
	"system settings gateway" = %{
set gateway [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $gateway eq "" || [string compare $gateway "0.0.0.0"] == 0 } {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"system console baudrate" = %{
set baudrate [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $baudrate <= 0 } {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"system dhcp server" = %{
if { [cli_ver_start 500 0] } {
	set status "status"
} else {
	set status "enable"
}
if {[cli_is_match $CLI_CUR_NODE 0 "" $status 0 "enable"]} {
	set intf [string map {"\"" ""} [cli_get_value $CLI_CUR_NODE "" "" "interface"]]
	set svr_type [cli_get_value $CLI_CUR_NODE "" "" "server-type"]
	if { $svr_type eq "regular" } {
		if {[cli_is_match $CLI_GLOBAL_NODE 1 "system interface" "dhcp-relay-type" 0 "regular" "name" 0 "$intf" "dhcp-relay-service" 0 "enable" "mode" 1 "static"]} {
			cli_set_errmsg "DHCP server conflict with relay"
			return 0
		}
	} else {
		if {[cli_is_match $CLI_GLOBAL_NODE 1 "system interface" "dhcp-relay-type" 0 "ipsec" "name" 0 "$intf" "dhcp-relay-service" 0 "enable" "mode" 1 "static"]} {
			cli_set_errmsg "DHCP server conflict with relay"
			return 0
		}
	}
}
return 1
	%}
	"system dhcp server lease-time" = %{
set lease_time [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$lease_time ne "" && $lease_time != 0} {
	if {$lease_time < 300 || $lease_time > 8640000} {
		cli_set_errmsg "lease-time must be in range \[300,8640000\] or 0 for unlimited"
		return 0
	}
}
return 1
	%}
	"system dhcp server exclude-range" = %{
set startip [cli_get_value $CLI_CUR_NODE "" "" "start-ip"]
set endip [cli_get_value $CLI_CUR_NODE "" "" "end-ip"]
if {$startip eq ""} {set startip "0.0.0.0"}
if {$endip eq ""} {set endip "0.0.0.0"}
set iplist [split $startip .]
set startipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
set iplist [split $endip .]
set endipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
if {$startipint > $endipint} {
	cli_set_errmsg "startip greater than endip"
	return 0
}
set match_nr [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "start-ip" 0 $startip "end-ip" 0 $endip]
if {$match_nr > 1} {
	cli_set_errmsg "duplicate"
	return 0
}

return 1
	%}

	"system dhcp reserved-address" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]

set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
if {$ip eq "" || $ip eq "0.0.0.0"} {
	cli_set_errmsg "invalid ip"
	return 0
}

set mac [cli_get_value $CLI_CUR_NODE "" "" "mac"]
if { $mac eq "" || $mac eq "00:00:00:00:00:00" } {
	cli_set_errmsg "invalid mac"
	return 0
}

set tbllist [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach e $tbllist {
	if { [cli_if_same_node $e $CLI_CUR_NODE] } {
		continue
	}
	set eip [cli_get_value $e "" "" "ip"]
	set etype [cli_get_value $e "" "" "type"]
	if {$eip eq $ip && $etype eq $type} {
		cli_set_errmsg "duplicate"
		return 0
	}
}
return 1
	%}

        "system dhcp server reserved-address" = %{
if { [cli_ver_start 500 0] } {
	if { [cli_get_value $CLI_CUR_NODE "" "" "action"] ne "reserved" } {
		return 1
	}
}
set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
if {$ip eq "" || $ip eq "0.0.0.0"} {
        cli_set_errmsg "IP address can not be 0"
        return 0
}
if { [cli_get_value $CLI_CUR_NODE "" "" "type"] eq "mac" } {
	set mac [cli_get_value $CLI_CUR_NODE "" "" "mac"]
	if { $mac eq "" || $mac eq "00:00:00:00:00:00" } {
		cli_set_errmsg "MAC address can not be 0"
		return 0
	}
}
set tbllist [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach e $tbllist {
        if { [cli_if_same_node $e $CLI_CUR_NODE] } {
                continue
        }
	if { [cli_ver_start 500 0] } {
		if { [cli_get_value $e "" "" "action"] ne "reserved" } {
			continue
		}
	}
        set eip [cli_get_value $e "" "" "ip"]
        if {$eip eq $ip} {
                cli_set_errmsg "Can not set duplicate entry."
                return 0
        }
}
return 1
        %}

	"system dns" = %{
set domain [cli_get_value $CLI_CUR_NODE "" "" "domain"]
set domain [string trim $domain \"]
# the test is looser than the one on FGT
set subs [regexp -inline -all -- {\S+} $domain]
foreach sub $subs {
	if {$sub != "" && $sub != "\"\"" && ! [regexp {^[-a-zA-Z0-9]+(\.[-a-zA-Z0-9]+)*$} $sub]} {
		cli_set_errmsg "domain \"$sub\" is illegal"
		return 0
	}
}
	%}

	"system dns-database" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
# these chars are FGT cmf/cli/commands.c XSS_CHARS
if {[regexp {[<>()#\"']} $name]} {
    cli_set_errmsg "illegal name"
    return 0
}
set domain [cli_get_value $CLI_CUR_NODE "" "" "domain"]
# the test is looser than the one on FGT
if {! [regexp {^\"[-a-zA-Z0-9_]+(\.[-a-zA-Z0-9_]+)*\"$} $domain] && ! [regexp {^[-a-zA-Z0-9_]+(\.[-a-zA-Z0-9_]+)*$} $domain]} {
    cli_set_errmsg "illegal name"
    return 0
}
if {1 < [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "domain" 0 $domain]} {
    cli_set_errmsg "duplicate"
    return 0
}
return 1
	%}

	"system dns-database source-ip" = %{
set source [cli_get_value $CLI_CUR_NODE "" "" ""]
set intflist [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
foreach intf $intflist {
    set vdom [string map {\" ""} [cli_get_value $intf "" "" "vdom"]]
    if { $vdom ne $CLI_CUR_VDOM_NAME } {
            continue
    }
    set ip [lindex [split [cli_get_value $intf "" "" "ip"] " "] 0]
    if { $ip eq $source } {
		return 1
    }
    set secondarylist [cli_get_tbl_list $intf "secondaryip"]
    foreach secondaryip $secondarylist {
	set ip [lindex [split [cli_get_value $secondaryip "" "" "ip"] " "] 0]
	if { $ip eq $source } {
		return 1
	}
    }
}
cli_set_errmsg "Source-ip $source does not match any interface ip in vdom $CLI_CUR_VDOM_NAME"
return 0
	%}

	"system dns-database dns-entry" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set hostname [cli_get_value $CLI_CUR_NODE "" "" "hostname"]
if { $type == "CNAME" } {
    if {1 < [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "hostname" 0 $hostname]} {
        cli_set_errmsg "duplicate"
        return 0
    }
} elseif { $type eq "A" } {
    set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
    if {$ip eq "0.0.0.0"} {
        cli_set_errmsg "invalid ip"
	return 0
    }
}
return 1
        %}

	"system dns fwdintf" = %{
set allintf [cli_get_value $CLI_CUR_NODE "" "" ""]
foreach intf $allintf {
	set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $intf ""]
	if {$intf_node == 0} {
		cli_set_errmsg "invalid value"
		return 0
	}
	set ip [cli_get_value $intf_node "" "" "ip"]
	set vdom [cli_get_value $intf_node "" "" "vdom"]
	set vdom_node [cli_get_vdom_node $vdom]
	if { $ip eq "" || $ip eq "0.0.0.0" || [cli_is_match $vdom_node 0 "system settings" "opmode" 0 "transparent"] } {
		cli_set_errmsg "invalid value"
		return 0
	}
}
return 1
	%}

	"system dns dns-cache-limit" = %{
set limit [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $limit < 0} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}

	"system fortiguard port" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] == 541 } {
	cli_set_errmsg "invalid port number"
	return 0
}
set port [cli_get_value $CLI_CUR_NODE "" "" ""]
set aport [cli_get_value $CLI_GLOBAL_NODE "system global" "" "admin-port"]
set asport [cli_get_value $CLI_GLOBAL_NODE "system global" "" "admin-sport"]
set sshport [cli_get_value $CLI_GLOBAL_NODE "system global" "" "admin-ssh-port"]
set telnetport [cli_get_value $CLI_GLOBAL_NODE "system global" "" "admin-telnet-port"]
set sslvpnport [cli_get_value $CLI_GLOBAL_NODE "system global" "" "sslvpn-sport"]
set authport [cli_get_value $CLI_GLOBAL_NODE "system global" "" "auth-http-port"]
set authsport [cli_get_value $CLI_GLOBAL_NODE "system global" "" "auth-https-port"]
if {$port == $aport || $port == $asport || $port == $sshport || $port == $telnetport || $port == $sslvpnport || $port == $authport || $port == $authsport} {
	cli_set_errmsg "port number is used"
	return 0
}

return 1
	%}

	"system fortiguard central-mgmt-status" = %{
set status [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$status eq "enable" && [cli_get_value $CLI_GLOBAL_NODE "system fortimanager" "" "ip"] ne "0.0.0.0"} {
	cli_set_errmsg "internal error"
	return 0
}
return 1
	%}

	"system ha" = %{
proc check_interface_heartbeatable {intf} {
	global CLI_GLOBAL_NODE
	global CLI_CUR_VDOM_NODE

	set name [cli_get_value $intf "" "" "name"]
	set type [cli_get_value $intf "" "" "type"]
	set mode [cli_get_value $intf "" "" "mode"]

	# sys_elbc_mode_is_haoc
	if { [cli_has_feature "f_haoc"] } {
		set elbc [cli_get_node $CLI_GLOBAL_NODE "system elbc" "" ""]
		set elbc_mode [cli_get_value $elbc "" "" "mode"]
		# "content-cluster" == CHLB_MODE_HAOC
		if { $elbc_mode eq "content-cluster" } {
			if { $name eq "elbc-base" || $name eq "mgmt1" } {
				return 1
			}
			cli_set_errmsg "invalid heartbeat interface (HAOC heartbeat device must be elbc-base or mgmt1)"
			return 0
		}
	}

	if { $type ne "physical" } {
		cli_set_errmsg "invalid heartbeat interface (must be physical)"
		return 0
	}

	if { $mode eq "pppoe" && $type eq "tunnel" } {
		cli_set_errmsg "invalid heartbeat interface (tunnel interface must not be pppoe)"
		return 0
	}

	# HAVE_VIRTUAL_SWITCH_VLAN -> cannot enable trunk
	if { [cli_has_feature "f_vlan_sw"]} {
		if { [cli_get_value $intf "" "" "trunk"] eq "enable" } {
			cli_set_errmsg "invalid heartbeat interface (must disable trunk)"
			return 0
		}
	}

	# HAVE_BACKPLANE_INTF (skipped because of the lack of syntax support for backplane)

	# cannot be used by composite
	namespace import global::intf_used_by_composite
	if { [intf_used_by_composite $name] eq 1 } {
		cli_set_errmsg "invalid heartbeat interface (must not used by composite)"
		return 0
	}
	if { [cli_obj_support "system virtual-switch"] } {
		set vsnodelist [cli_get_tbl_list $CLI_GLOBAL_NODE "system virtual-switch"]
		foreach vsnode $vsnodelist {
			set vsportlist [cli_get_tbl_list $vsnode "port"]
			foreach vsport $vsportlist {
				set vsportname [cli_get_value $vsport "" "" "name"]
				if { $vsportname eq $name } {
					cli_set_errmsg "invalid heartbeat interface (must not used by virtual-switch)"
					return 0
				}
			}
		}
	}

	# IS_MODEM -> cannot be modem
	# no need to check feature because user cannot rename physical interface
	if { $name eq "modem" } {
		cli_set_errmsg "invalid heartbeat interface (must not be modem interface)"
		return 0
	}

	# IS_USB_LTE, IS_USB_WWAN -> cannot be wwan
	# note: these two are both aliased to "wwan"
	if { $name eq "wwan" } {
		cli_set_errmsg "invalid heartbeat interface (must not be wwan interface)"
		return 0
	}

	# HAVE_DEDICATED_MGMT -> cannot be dedicated mgmt
	if { [cli_obj_support "system dedicated-mgmt"] } {
		set dmgmt [cli_get_node $CLI_GLOBAL_NODE "system dedicated-mgmt" "" ""]
		set dmgmt_status [cli_get_value $dmgmt "" "" "status"]
		if { $dmgmt_status eq "enable" } {
			set dmgmt_intf [cli_get_value $dmgmt "" "" "interface"]
			if { $dmgmt_intf eq $name } {
				cli_set_errmsg "invalid heartbeat interface (must not be dedicated management interface)"
				return 0
			}
		}
	}

	# cannot be used by switchctl
	set fortilink [cli_get_node $CLI_GLOBAL_NODE "system interface" "fortilink" ""]
	if { [cli_get_match_nr $fortilink 1 "" "member" 0 $name] > 1 } {
		cli_set_errmsg "invalid heartbeat interface (must not be used by fortilink)"
		return 0
	}


	# HAVE_NET_NPU -> cannot be NPU vlink
	if { [cli_obj_support "f_npu_net"] } {
		if {[regexp {npu\d(-|_)vlink\d} $char]} {
			cli_set_errmsg "invalid heartbeat interface (must not be NPU vlink interface)"
			return 0
		}
	}

	# cannot be port pair member (INTF_USED_VWP)
	set pplist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "system port-pair"]
	foreach pp $pplist {
		set ppintf [cli_get_value $node "" "" "member"]
		if { $ppintf eq $name } {
			cli_set_errmsg "invalid heartbeat interface (must not used by port pair)"
			return 0
		}
	}

	return 1
}

set mode [cli_get_value $CLI_CUR_NODE "" "" "mode"]
if {$mode eq "a-a" || $mode eq "a-p"} {
	set hbdev [cli_get_value $CLI_CUR_NODE "" "" "hbdev"]
	set i 0
	foreach e $hbdev {
		if {($i % 2) == 0} {
			set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $e ""]
			if {$intfnode != 0} {
				# check if the interface can be used as heartbeat device
				if { [check_interface_heartbeatable $intfnode] eq 0 } {
					# errmsg handled inside proc
					return 0
				}
			}
		} else {
			if {$e < 0 || $e > 512} {
				cli_set_errmsg "invalid value"
				return 0
			}
		}
		incr i
	}
	if { $i > 16 } {
		cli_set_errmsg "Maximum 8 heartbeat interfaces are allowed"
		return 0
	}
}
return 1
	%}
	"system ha ha-mgmt-interface" = %{
set ifname [cli_get_value $CLI_CUR_NODE "" "" ""]
set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $ifname ""]
if {$intfnode == 0} {
	cli_set_errmsg "entry not exist"
	return 0
}
set type [cli_get_value $intfnode "" "" "type"]
if {$type eq "loopback"} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}

	"system modem interface" = %{
set modem_node [cli_get_parent $CLI_CUR_PARENT_NODE]
set mode [cli_get_value $modem_node "" "" "mode"]

set interface [cli_get_value $CLI_CUR_NODE "" "" ""]
set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $interface ""]
if {$intf_node == 0} {
	cli_set_errmsg "invalid value"
	return 0
}
set vdom [cli_get_value $intf_node "" "" "vdom"]
set vdom_node [cli_get_vdom_node $vdom]
set opmode [cli_get_value $vdom_node "system settings" "" "opmode"]
if {$opmode eq "transparent"} {
	cli_set_errmsg "invalid interface"
	return 0
}
return 1
	%}

	"system session-ttl default" = %{
set val [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$val ne "never"} {
	if {[string last \n $val] != -1 || [catch {expr {abs($val)}}] || $val < 300 || $val > 604800} {
		cli_set_errmsg "out of range"
		return 0
	}
}
return 1
	%}
	"system session-ttl port timeout" = %{
set val [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$val ne "never"} {
	if {[string last \n $val] != -1 || [catch {expr {abs($val)}}] || $val < 1 || $val > 604800} {
		cli_set_errmsg "out of range"
		return 0
	}
}
return 1
	%}

	"system session-helper" = %{
set proto [cli_get_value $CLI_CUR_NODE "" "" "protocol"]
set port [cli_get_value $CLI_CUR_NODE "" "" "port"]
set match_nr [cli_get_match_nr $CLI_GLOBAL_NODE 1 "system session-helper" "protocol" 0 $proto "port" 0 $port]
if {$match_nr > 1} {
	cli_set_errmsg "duplicate"
	return 0
}
return 1
	%}

	"system snmp community name" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set match_nr [cli_get_match_nr $CLI_GLOBAL_NODE 1 "system snmp community" "name" 0 $name]
if {$match_nr > 1} {
	cli_set_errmsg "entry exists"
	return 0
}
return 1
	%}

	"system snmp community hosts" = %{
set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
if {$ip ne ""} {
	set iplist [split $ip .]
	set ipbyte1 [lindex $iplist 0]
	if {$ipbyte1 != 0 && $ipbyte1 & 0x0ff != 127 && ($ipbyte1 & 0xf0 == 0xe0 || $ip eq "255.255.255.255")} {
		cli_set_errmsg "invalid ip"
		return 0
	}
	set has_cmd 0
	set iplist2 [split [join $ip " "] " "]
	set ip1 [lindex $iplist2 0]
	set ipmask [lindex $iplist2 1]
	if {$ipmask eq ""} {
		set ipmask [lindex [split $ip /] 1]
		if {$ipmask ne ""} {
			set ip1 [lindex [split $ip /] 0]
			set newip [cli_format_ipmask $ip 0]
			set ipmask [lindex [split $newip /] 1]
		} else {
			set ipmask "255.255.255.255"
		}
		set has_cmd 1
	}
	if { $has_cmd == 1 } {
		set formatted_ip "$ip1 $ipmask"
	} else {
		set formatted_ip $ip
	}
	if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "ip" 0 $formatted_ip] > 1} {
		cli_set_errmsg "Duplicate: This ip/mask already exists in the community."
			return 0
	}
##
## FortiOS 6.4.x: cmf/plugin/base/snmp.c --> snmp_host_ip_check()
##
	set iptype [cli_get_iptype $ip1 $ipmask]
	if { $iptype eq "IP_SUBNET" } {
		if { $ipmask eq "255.255.255.255" } {
			cli_set_errmsg "IP is a subnet address with no netmask"
			return 0
		}
	} elseif { $iptype eq "IP_BROADCAST" } {
		cli_set_errmsg "This ip/mask is a broadcast address"
		return 0
	} elseif { $iptype eq "IP_MULTICAST" } {
		cli_set_errmsg "This ip/mask is a multicast address"
		return 0
	} elseif { $iptype ne "IP_UNICAST" && $iptype ne "IP_LOOPBACK" && $iptype ne "IP_NONE"} {
		cli_set_errmsg "Bad ip type $iptype"
		return 0
	}
	if { $has_cmd == 1 } {
                set ipnode [cli_get_parent $CLI_CUR_PARENT_NODE]
                set cmd "config hosts\nedit $id\nset ip $ip1 $ipmask\nnext\nend\n"
                cli_exec_cmd $ipnode $cmd
	}
}
return 1
	%}

	"system arp-table" = %{
set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
set interface [cli_get_value $CLI_CUR_NODE "" "" "interface"]
if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "ip" 0 $ip "interface" 0 $interface] > 1} {
	cli_set_errmsg "duplicate"
	return 0
}
return 1
	%}

	"system fortimanager" = %{
set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
if { $ip ne "0.0.0.0" } {
	if {[cli_is_match $CLI_GLOBAL_NODE 0 "system fortiguard" "central-mgmt-status" 0 "enable"]} {
		cli_set_errmsg "internal error"
		return 0
	}
}
return 1
	%}

	"system fortianalyzer" = %{
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
if {$status eq "enable"} {
	set log_ftgd [cli_get_value $CLI_GLOBAL_NODE "log fortiguard setting" "" "status"]
	if {$log_ftgd eq "enable"} {
		cli_set_errmsg "FortiGuard service is already enabled"
		return 0
	}
}

set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
if {$status eq ""} {
	return 1
}
if { [cli_ver_start 500 0] } {
	if {$status eq "enable" } {
		cli_set_errmsg "fortilog ip"
		return 0
	}
} else {
	set admode [cli_get_value $CLI_CUR_NODE "" "" "address-mode"]
	if {$status eq "enable" && $admode eq "" && $server eq ""} {
		cli_set_errmsg "fortilog ip"
		return 0
	}
}
if {$server eq ""} {set server "0.0.0.0"}
set iplist [split $server .]

set ip1 [lindex $iplist 0]
set ip2 [lindex $iplist 1]
set ip3 [lindex $iplist 2]
set ip4 [lindex $iplist 3]

if { $ip1==0 && $ip2==0 && $ip3==0 && $ip4==0 } {
	if {$admode eq ""} {
		cli_set_errmsg "invalid ip"
		return 0
	}
} else {
	if { $ip1==0 || ( $ip1>126 && $ip1<128) } {
		cli_set_errmsg "invalid ip"
		return 0
	}
	if { $admode eq "" && $ip1 > 223 } {
		cli_set_errmsg "invalid ip"
		return 0
	} elseif {$admode eq "auto-discovery" &&
		  ( ($ip1 > 223 && $ip1 < 240) || $ip1 > 240 ||
		    ($ip1==240 && $ip2==0 && $ip3==0 && $ip4==0) ) } {
		cli_set_errmsg "invalid ip"
		return 0
	}
}
if {[cli_is_match $CLI_GLOBAL_NODE 0 "system fortianalyzer2" "status" 0 "enable" "server" 0 $server]} {
	cli_set_errmsg "fortilog ip"
	return 0
}
if {[cli_is_match $CLI_GLOBAL_NODE 0 "system fortianalyzer3" "status" 0 "enable" "server" 0 $server]} {
	cli_set_errmsg "fortilog ip"
	return 0
}
if {$status eq ""} {
	if {[cli_is_match $CLI_GLOBAL_NODE 0 "antivirus quarantine" "quar-to-fortianalyzer" 0 "enable"] || [cli_is_match $CLI_GLOBAL_NODE 0 "log fortianalyzer setting" "status" 0 "enable"]} {
		cli_set_errmsg "fortilog in use"
		return 0
	}
}
return 1
	%}
	"system fortianalyzer2" = %{
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
if {$status eq "enable"} {
	set log_ftgd [cli_get_value $CLI_GLOBAL_NODE "log fortiguard setting" "" "status"]
	if {$log_ftgd eq "enable"} {
		cli_set_errmsg "FortiGuard service is already enabled"
		return 0
	}
}

set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
if { [cli_ver_start 500 0] } {
	if {$status eq "enable" } {
		cli_set_errmsg "fortilog ip"
		return 0
	}
} else {
	set admode [cli_get_value $CLI_CUR_NODE "" "" "address-mode"]
	if {$status eq "enable" && $admode eq "" && $server eq ""} {
		cli_set_errmsg "fortilog ip"
		return 0
	}
}
if {$server eq ""} {set server "0.0.0.0"}
set iplist [split $server .]
set ipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
if {$ipint == 0} {
	if {$admode ne ""} {
		cli_set_errmsg "invalid ip"
		return 0
	}
} else {
	if {$ipint < 0x01000000 || ($ipint > 0x7effffff && $ipint < 0x80000000) || ($ipint > 0xbfffffff && $ipint < 0xc0000000)} {
		cli_set_errmsg "invalid ip"
		return 0
	}
	if {$admode eq "" && $ipint > 0xdfffffff} {
		cli_set_errmsg "invalid ip"
		return 0
	} elseif {$admode eq "auto-discovery" && (($ipint > 0xdfffffff && $ipint < 0xf0000001) || $ipint > 0xf0ffffff)} {
		cli_set_errmsg "invalid ip"
		return 0
	}
}
if {[cli_is_match $CLI_GLOBAL_NODE 0 "system fortianalyzer" "status" 0 "enable" "server" 0 $server]} {
	cli_set_errmsg "fortilog ip"
	return 0
}
if {[cli_is_match $CLI_GLOBAL_NODE 0 "system fortianalyzer3" "status" 0 "enable" "server" 0 $server]} {
	cli_set_errmsg "fortilog ip"
	return 0
}
if {$status eq ""} {
	if {[cli_is_match $CLI_GLOBAL_NODE 0 "log fortianalyzer2 setting" "status" 0 "enable"]} {
		cli_set_errmsg "fortilog in use"
		return 0
	}
}
return 1
	%}
	"system fortianalyzer3" = %{
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
if {$status eq "enable"} {
	set log_ftgd [cli_get_value $CLI_GLOBAL_NODE "log fortiguard setting" "" "status"]
	if {$log_ftgd eq "enable"} {
		cli_set_errmsg "FortiGuard service is already enabled"
		return 0
	}
}

set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
if { [cli_ver_start 500 0] } {
	if {$status eq "enable" } {
		cli_set_errmsg "fortilog ip"
		return 0
	}
} else {
	set admode [cli_get_value $CLI_CUR_NODE "" "" "address-mode"]
	if {$status eq "enable" && $admode eq "" && $server eq ""} {
		cli_set_errmsg "fortilog ip"
		return 0
	}
}
if {$server eq ""} {set server "0.0.0.0"}
set iplist [split $server .]
set ipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
if {$ipint == 0} {
	if {$admode ne ""} {
		cli_set_errmsg "invalid ip"
		return 0
	}
} else {
	if {$ipint < 0x01000000 || ($ipint > 0x7effffff && $ipint < 0x80000000) || ($ipint > 0xbfffffff && $ipint < 0xc0000000)} {
		cli_set_errmsg "invalid ip"
		return 0
	}
	if {$admode eq "" && $ipint > 0xdfffffff} {
		cli_set_errmsg "invalid ip"
		return 0
	} elseif {$admode eq "auto-discovery" && (($ipint > 0xdfffffff && $ipint < 0xf0000001) || $ipint > 0xf0ffffff)} {
		cli_set_errmsg "invalid ip"
		return 0
	}
}
if {[cli_is_match $CLI_GLOBAL_NODE 0 "system fortianalyzer" "status" 0 "enable" "server" 0 $server]} {
	cli_set_errmsg "fortilog ip"
	return 0
}
if {[cli_is_match $CLI_GLOBAL_NODE 0 "system fortianalyzer2" "status" 0 "enable" "server" 0 $server]} {
	cli_set_errmsg "fortilog ip"
	return 0
}
if {$status eq ""} {
	if {[cli_is_match $CLI_GLOBAL_NODE 0 "log fortianalyzer3 setting" "status" 0 "enable"]} {
		cli_set_errmsg "fortilog in use"
		return 0
	}
}
return 1
	%}

	"system global {vdom-admin vdom-mode}" = %{
if { [cli_branchpt_start 600 787] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "vdom-mode" 0 "no-vdom"] } {
	set oldval [cli_get_org_value $CLI_CUR_NODE "" "" ""]
	set status [cli_get_value $CLI_CUR_NODE "" "" ""]
	set vdom_num [cli_get_tbl_cnt $CLI_GLOBAL_NODE "system vdom-property"]
	if {$vdom_num > 2} {
		cli_set_errmsg "Change vdom-mode from $oldval to $status can only be done when there are no non-root virtual domains"
		return 0
	}
	if {$vdom_num == 2} {
		if {$oldval eq "split-vdom"} {
			return 1
		}
		namespace import global::dmgmt_vdom_support
		set dmgmt [dmgmt_vdom_support]
		if { $dmgmt } {
			set vdomlist [cli_get_tbl_list $CLI_GLOBAL_NODE "system vdom-property"]
			foreach vdom $vdomlist {
				set name [cli_get_value $vdom "" "" "name"]
				if {$name eq "dmgmt-vdom"} {
					return 1
				}
			}
		}
		cli_set_errmsg "Change vdom-mode from $oldval to $status can only be done when there are no non-root virtual domains"
		return 0
	}
} elseif { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "vdom-admin" 0 "disable"] } {
	set vdom_num [cli_get_tbl_cnt $CLI_GLOBAL_NODE "system vdom-property"]
	if {$vdom_num > 2} {
		cli_set_errmsg "Disabling virtual domain configuration can only be done when there are no non-root virtual domains"
		return 0
	}
	if {$vdom_num == 2} {
		namespace import global::dmgmt_vdom_support
		set dmgmt [dmgmt_vdom_support]
		if { $dmgmt } {
			set vdomlist [cli_get_tbl_list $CLI_GLOBAL_NODE "system vdom-property"]
			foreach vdom $vdomlist {
				set name [cli_get_value $vdom "" "" "name"]
				if {$name eq "dmgmt-vdom"} {
					return 1
				}
			}
		}
		cli_set_errmsg "Disabling virtual domain configuration can only be done when there are no non-root virtual domains"
		return 0
	}
} elseif { ![cli_branchpt_start 600 2274] } {
	if { [cli_obj_support "system csf"] && [cli_is_match $CLI_GLOBAL_NODE 0 "system csf" "status" 0 "enable"] } {
		cli_set_errmsg "vdom_admin(vdom-mode) cannot be enabled when csf is enabled"
		return 0
	}
}
return 1
	%}

	"system global gui-device-latitude" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value eq "" } { set value 0 }
set value [string map {, .} $value]
if { $value > 90 || $value < -90} {
	cli_set_errmsg "Please enter a coordinate value in the range of (-90 to 90)"
	return 0
}
return 1
	%}

	"system global gui-device-longitude" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value eq "" } { set value 0 }
set value [string map {, .} $value]
if { $value > 180 || $value < -180} {
	cli_set_errmsg "Please enter a coordinate value in the range of (-180 to 180)"
	return 0
}
return 1
	%}

	"system global" = %{
set hostname [cli_get_value $CLI_CUR_NODE "" "" "hostname"]
set hostname [string trim $hostname \"]
if {[regexp {[^0-9a-zA-Z\-_]} $hostname]} {
	cli_set_errmsg "invalid value"
	return 0
}
if {[cli_get_value $CLI_CUR_NODE "" "" "admin-port"] == 541 ||
	[cli_get_value $CLI_CUR_NODE "" "" "admin-sport"] == 541 ||
	[cli_get_value $CLI_CUR_NODE "" "" "admin-ssh-port"] == 541 ||
	[cli_get_value $CLI_CUR_NODE "" "" "admin-telnet-port"] == 541 ||
	[cli_get_value $CLI_CUR_NODE "" "" "sslvpn-sport"] == 541 ||
	[cli_get_value $CLI_CUR_NODE "" "" "auth-http-port"] == 541 ||
	[cli_get_value $CLI_CUR_NODE "" "" "auth-https-port"] == 541 } {
	cli_set_errmsg "invalid port number"
	return 0
}
array unset port_array
set aport [cli_get_value $CLI_CUR_NODE "" "" "admin-port"]
if {$aport eq ""} {set aport 80}
set port_array($aport) 1
set asport [cli_get_value $CLI_CUR_NODE "" "" "admin-sport"]
if {$asport eq ""} {set asport 443}
set port_array($asport) 1
set sshport [cli_get_value $CLI_CUR_NODE "" "" "admin-ssh-port"]
if {$sshport eq ""} {set sshport 22}
set port_array($sshport) 1
set telnetport [cli_get_value $CLI_CUR_NODE "" "" "admin-telnet-port"]
if {$telnetport eq ""} {set telnetport 23}
set port_array($telnetport) 1
set sslvpnport [cli_get_value $CLI_CUR_NODE "" "" "sslvpn-sport"]
if {$sslvpnport eq ""} {set sslvpnport 10443}
set port_array($sslvpnport) 1
set authport [cli_get_value $CLI_CUR_NODE "" "" "auth-http-port"]
if {$authport eq ""} {set authport 1000}
set port_array($authport) 1
set authsport [cli_get_value $CLI_CUR_NODE "" "" "auth-https-port"]
if {$authsport eq ""} {set authsport 1003}
set port_array($authsport) 1
if {$sslvpnport == $asport} {
	set expect_len 6
} else {
	set expect_len 7
}
if {[array size port_array] != $expect_len} {
	cli_set_errmsg "one or more ports configured are already used by others"
	return 0
}
if {$sslvpnport == $asport} {
	set vdom_list [cli_get_tbl_list $CLI_VDOM_NODE ""]
	foreach e $vdom_list {
		set pol_list [cli_get_match_list $e 1 "firewall policy" "action" 0 "ssl-vpn"]
		foreach e2 $pol_list {
			set sintf [cli_get_value $e2 "" "" "srcintf"]
			set zone [cli_get_value $e "system zone" $sintf "interface"]
			if {$zone ne ""} {
				set intf_list $zone
			} else {
				set intf_list $sintf
			}
			set ret 0
			foreach intf $intf_list {
				set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $intf ""]
				if {[cli_is_match $intf_node 0 "" "allowaccess" 0 "https"]} {
					set ret 1
				} else {
					set secip_list [cli_get_tbl_list $intf_node "secondaryip"]
					foreach item $secip_list {
						if {[cli_is_match $item 0 "" "allowaccess" 0 "https"]} {
							set ret 1
							break
						}
					}
				}
				if {$ret == 1} {
					break
				}
			}
			if {$ret == 1} {
				cli_set_errmsg "sslvpn policy srcintf https"
				return 0
			}
		}
	}
}
return 1
	%}

	"system gre-tunnel" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if {$CLI_IS_RESYNC != 1 && $CLI_ACT eq "add"} {
	if {[cli_get_node $CLI_CUR_VDOM_NODE "system zone" $name ""]} {
		cli_set_errmsg "entry exists"
		return 0
	}
	if {[cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $name ""]} {
		cli_set_errmsg "entry exists"
		return 0
	}
	if {[cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec manualkey-interface" $name ""]} {
		cli_set_errmsg "entry exists"
		return 0
	}

	set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
	if {$intf_node} {
		set intf_type [cli_get_value $intf_node "" "" "type"]
		if { $intf_type ne "tunnel" } {
			cli_set_errmsg "entry exists"
			return 0
		}

		set intf_vdom [cli_get_value $intf_node "" "" "vdom"]
		if {$intf_vdom ne ""} {
			set intf_vdom [string trim $intf_vdom \"]
			if {$intf_vdom ne $CLI_CUR_VDOM_NAME} {
				cli_set_errmsg "entry exists"
				return 0
			}
		}
	}
}

set remote_gw [cli_get_value $CLI_CUR_NODE "" "" "remote-gw"]
set local_gw [cli_get_value $CLI_CUR_NODE "" "" "local-gw"]
namespace import global::check_gw
if {[check_gw $remote_gw] == -1 || [check_gw $local_gw] == -1} {
	cli_set_errmsg "invalid gateway"
	return 0
}
if { [cli_get_value $CLI_CUR_NODE "" "" "interface"] eq "" } {
	cli_set_errmsg "Interface must be set"
	return 0
}
return 1
	%}
	"system gre-tunnel remote-gw" = %{
if {$CLI_ACT ne "add" && ![cli_ver_start 600 0] } {
	cli_set_errmsg "cannot modify"
	return 0
}
return 1
	%}
	"system gre-tunnel local-gw" = %{
if {$CLI_ACT ne "add" && ![cli_ver_start 600 0]} {
	cli_set_errmsg "cannot modify"
	return 0
}
return 1
	%}
	"system gre-tunnel interface" = %{
if {$CLI_ACT ne "add" && ![cli_ver_start 600 0]} {
	cli_set_errmsg "cannot modify"
	return 0
}
return 1
	%}

	"system vdom-link vcluster" = %{
if {$CLI_ACT ne "add"} {
	set vc [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { [cli_ver_start 700 2] } {
		set ha_node [cli_get_node $CLI_GLOBAL_NODE "system ha" "" ""]
		if { [cli_get_value $ha_node "" "" "vcluster-status"] ne "enable" } {
			if { !($vcluster eq "" || $vcluster eq 0) } {
				cli_set_errmsg "cannot set vcluster when system ha vcluster-status is disabled"
				return 0
			}
		}
		set vcluster_id [string range $vc 8 end]
		set vdoms [cli_get_value $ha_node "vcluster" $vcluster_id "vdom"]
	} else {
		if {$vc eq "vcluster1"} {
			set vdoms [cli_get_value $CLI_GLOBAL_NODE "system ha" "" "vdom"]
		} else {
			set vdoms [cli_get_node $CLI_GLOBAL_NODE "system ha" "secondary-vcluster" "vdom"]
		}
	}

	set found 0
	foreach e $vdoms {
		set vnode [cli_get_vdom_node $e]
		set node [cli_get_node $vnode "system settings" "" ""]
		if { !$node || [cli_is_match $node 0 "" "opmode" 0 "nat"] } {
			set found 1
			break
		}
	}
	if {$found == 0} {
		cli_set_errmsg "invalid value"
		return 0
	}
}
return 1
	%}

	"system vdom-link" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [string length $name] > 12 } {
	cli_set_errmsg "invalid value"
	return 0
}

if {$CLI_IS_RESYNC != 1 && $CLI_ACT eq "add"} {
	if {[cli_get_node $CLI_GLOBAL_NODE "system interface" "${name}0" ""] ||
	    [cli_get_node $CLI_GLOBAL_NODE "system interface" "${name}1" ""]} {
		    cli_set_errmsg "entry exists"
		    return 0
	}
}

return 1
	%}

	"spamfilter iptrust" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "" ||
     [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1 } {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}

	"spamfilter iptrust entries" = %{
# duplicate check for type IP4ADDRMASK not support yet!
return 1
	%}

	"spamfilter mheader" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "" ||
     [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1 } {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}

	"spamfilter mheader entries" = %{
set ptype [cli_get_value $CLI_CUR_NODE "" "" "pattern-type"]
set fieldname [cli_get_value $CLI_CUR_NODE "" "" "fieldname"]
set fieldbody [cli_get_value $CLI_CUR_NODE "" "" "fieldbody"]
if { $fieldname eq "" || $fieldbody eq "" ||
     [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "pattern-type" 0 $ptype "fieldname" 0 $fieldname "fieldbody" 0 $fieldbody] > 1 } {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}

	"spamfilter dnsbl" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "" ||
     [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1 } {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}

	"spamfilter dnsbl entries" = %{
set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
if { $server eq "" } {
	cli_set_errmsg "invalid value"
	return 0
}

set entry_list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach l $entry_list {
	if { [cli_if_same_node $l $CLI_CUR_NODE] } {
		continue
	}

	set l_server [cli_get_value $l "" "" "server"]
	if { [string equal -nocase $server $l_server] } {
		cli_set_errmsg "entry exists"
		return 0
	}
}
return 1
	%}

	"log trafficfilter rule" = %{
set service [cli_get_value $CLI_CUR_NODE "" "" "service"]
if {$service eq ""} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}

	"log report period" = %{
proc check_time_format { time } {
	set para_num [scan $time "%d:%d %d/%d/%d" a b c d e]
	if { $para_num != 5 } {
		return 0
	}
	if { $a < 0 || $a > 23 || $b < 0 || $b > 59 ||
	     $c < 1970 || $c > 9999 || $d < 1 || $d > 12 ||
	     $e < 1 || $e > 31 } {
		return 0
	}
	return 1
}

set last_n [cli_get_value $CLI_CUR_NODE "" "" "last-n"]
if { $last_n <= 0 } {
	if { [cli_get_node $CLI_CUR_NODE "" "" "last-n"] } {
		cli_set_errmsg "invalid value"
		return 0
	}
}

set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $type eq "other" } {
	set start [cli_get_value $CLI_CUR_NODE "" "" "start"]
	set s_num [llength $start]

	set end [cli_get_value $CLI_CUR_NODE "" "" "end"]
	set e_num [llength $end]

	if { $s_num != 2 || $e_num != 2 } {
		cli_set_errmsg "invalid value"
		return 0
	}

	if { [check_time_format $start] == 0 ||
	     [check_time_format $end] == 0 } {
		cli_set_errmsg "invalid value"
		return 0
	}

	set start_m [lindex $start 0]
	set start_y [lindex $start 1]
	append start_y $start_m

	set end_m [lindex $end 0]
	set end_y [lindex $end 1]
	append end_y $end_m

	if { [string compare $end_y $start_y] < 0 } {
		cli_set_errmsg "invalid value"
		return 0
	}
}
return 1
	%}

	"log report scope" = %{
proc check_value_int { curnode field min_v max_v } {
	set v [cli_get_value $curnode "" "" $field]
	if { $v == "" } {
		if { [cli_get_node $curnode "" "" $field] } {
			return 0
		}
		return 1
	}

	if { $v < $min_v || $v > $max_v } {
		return 0
	}
	return 1
}

if { [check_value_int $CLI_CUR_NODE "top1" 1 30] == 0 } {
	cli_set_errmsg "invalid value"
	return 0
}

if { [check_value_int $CLI_CUR_NODE "top2" 1 30] == 0 } {
	cli_set_errmsg "invalid value"
	return 0
}

if { [check_value_int $CLI_CUR_NODE "audit" 1 10000] == 0 } {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}

	"system ipv6-tunnel" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$name eq ""} {
	cli_set_errmsg "empty value"
	return 0
}
if {$CLI_IS_RESYNC != 1 && $CLI_ACT eq "add"} {

#	 In FOS plugin code, it checks all the vdoms for the new added tunnel name.
#	 If it exists in any vdom, the add operation will fail. Since each time
#	 when add a tunnel, there will be a entry in "system interface" with the
#	 same name. Therefore, checking the name in "system interface" will be OK.

	if {[cli_get_node $CLI_CUR_VDOM_NODE "system zone" $name ""] ||
	    [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $name ""] ||
	    [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec manualkey-interface" $name ""] ||
	    [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]} {
		    cli_set_errmsg "entry exists"
		    return 0
	}
}

set source [cli_get_value $CLI_CUR_NODE "" "" "source"]
set dest [cli_get_value $CLI_CUR_NODE "" "" "destination"]
if {[cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "system ipv6-tunnel" "source" 0 $source "destination" 0 $dest] > 1} {
	cli_set_errmsg "entry exists"
	return 0
}
return 1
	%}

	"system ipv6-tunnel source" = %{
if {$CLI_ACT ne "add"} {
	cli_set_errmsg "cannot modify"
	return 0
}
return 1
	%}
	"system ipv6-tunnel destination" = %{
if {$CLI_ACT ne "add"} {
	cli_set_errmsg "cannot modify"
	return 0
}
return 1
	%}

	"system wireless settings" = %{
set mode [cli_get_value $CLI_CUR_NODE "" "" "mode"]
if {$mode eq "CLIENT" || $mode eq "SCAN"} {
	if {[cli_get_match_nr $CLI_GLOBAL_NODE 1 "system interface" "type" 0 "wireless"] > 1} {
		cli_set_errmsg "Please remove virtual AP interfaces before switching out of AP mode."
		return 0
	}
}
set band [cli_get_value $CLI_CUR_NODE "" "" "band"]
set geo [cli_get_value $CLI_CUR_NODE "" "" "geography"]
if {$geo eq ""} {set geo "World"}
set channel [cli_get_value $CLI_CUR_NODE "" "" "channel"]
if {$channel eq ""} {set channel 5}
if {$channel != 0 && $band ne "802.11a"} {
	switch $geo {
		"World" -
		"Israel" {
			if {$channel < 5 || $channel > 8} {
				cli_set_errmsg "invalid value"
				return 0
			}
		}
		"Americas" {
			if {$channel < 1 || $channel > 11} {
				cli_set_errmsg "invalid value"
				return 0
			}
		}
		"EMEA" {
			if {$channel < 1 || $channel > 13} {
				cli_set_errmsg "invalid value"
				return 0
			}
		}
		"Japan" {
			if {$channel < 1 || $channel > 14} {
				cli_set_errmsg "invalid value"
				return 0
			}
		}
	}
}
set rad [cli_get_value $CLI_CUR_NODE "" "" "radius-server"]
if {$rad ne ""} {
	set mgmt_vd [cli_get_value $CLI_GLOBAL_NODE "system global" "" "management-vdom"]
	if {$mgmt_vd eq ""} {set mgmt_vd "root"}
	set mgmt_vdnode [cli_get_vdom_node $mgmt_vd]
	if {$mgmt_vdnode != 0} {
		if {[cli_get_node $mgmt_vdnode "user radius" $rad ""] == 0} {
			cli_set_errmsg "invalid value"
			return 0
		}
	}
}
set ssid [cli_get_value $CLI_CUR_NODE "" "" "ssid"]
if {$ssid ne ""} {
	if { [string compare -length 1 $ssid " "] == 0 } {
		cli_set_errmsg "invalid value"
		return 0
	}
}
set security [cli_get_value $CLI_CUR_NODE "" "" "security"]
if {$security ne ""} {
	set key [cli_get_value $CLI_CUR_NODE "" "" "key"]
	if {$security eq "WEP64"} {
		if {[string length $security] != 10} {
			cli_set_errmsg "invalid enc key"
			return 0
		}
		if {[regexp {[^0-9a-zA-Z]} $security]} {
			cli_set_errmsg "invalid enc key"
			return 0
		}
	} elseif {$security eq "WEP128"} {
		if {[string length $security] != 26} {
			cli_set_errmsg "invalid enc key"
			return 0
		}
		if {[regexp {[^0-9a-zA-Z]} $security]} {
			cli_set_errmsg "invalid enc key"
			return 0
		}
	}

	if {$security eq "WPA_RADIUS"} {
		if {$rad eq ""} {
			cli_set_errmsg "invalid value"
			return 0
		}
	}
}
return 1
	%}

	"system tos-based-priority" = %{
set tos [cli_get_value $CLI_CUR_NODE "" "" "tos"]
if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "tos" 0 $tos] > 1 } {
	cli_set_errmsg "duplicate"
	return 0
}
return 1
	%}

	"system zone" = %{
namespace import global::invalid_zone_member
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $name eq "" } {
     cli_set_errmsg "invalid value"
     return 0
}
if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1 ||
     [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""] != 0 } {
	cli_set_errmsg "entry exists"
	return 0
}

set opmode [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"]
set intfs [cli_get_value $CLI_CUR_NODE "" "" "interface" 1]
if {$opmode eq "transparent"} {
	set init 0
	set fdid 0
	foreach e $intfs {
		set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $e ""]
		if {$intfnode} {
			set intf_fdid [cli_get_value $intfnode "" "" "forward-domain"]
			if {$init} {
				if {$intf_fdid != $fdid} {
					cli_set_errmsg "Interfaces must have the same forward domain ID in TP mode"
					return 0
				}
			} else {
				set fdid $intf_fdid
				set init 1
			}
		}
	}
}
if { $intfs eq "" } {
	return 1
}
foreach intf $intfs {
	if { [invalid_zone_member $intf $CLI_CUR_NODE] } {
		return 0
	}
	set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $intf ""]
	if { [cli_get_value $intfnode "" "" "type"] eq "loopback" } {
		cli_set_errmsg "Cannot use loopback interface \"$intf\" in system zone"
		return 0
	}
	set name [cli_get_value $intfnode "" "" "name"]
	if { [regexp {^ssl\.} $name] } {
		cli_set_errmsg "$name interface cannot be a zone member"
		return 0
	}

	set is_src_intf [cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall policy" "srcintf" 0 "\"$intf\""]
	set is_dst_intf [cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall policy" "dstintf" 0 "\"$intf\""]
	if { $is_src_intf || $is_dst_intf } {
		cli_set_errmsg "$name interface is used in a policy as a srcintf or dstintf and cannot be a zone member"
		return 0
	}
}
return 1
	%}

	"firewall addrgrp6" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {[cli_get_node $CLI_CUR_VDOM_NODE "firewall address6" $name ""] != 0} {
	cli_set_errmsg "addr/addrgrp conflict"
	return 0
}
set grpmember [cli_get_value $CLI_CUR_NODE "" "" "member"]
if { ![cli_ver_start 700 2] } {
if { $grpmember eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
}
namespace import global::addr6_all_exist
set addr_all [addr6_all_exist $grpmember]
return 1
	%}

	"system vdom" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$name eq ""} {
	cli_set_errmsg "illegal name"
	return 0
}
set long_vdom_name_enable 0
if { [string match "*dvm_import*" [cli_get_clisrc]] } {
	## allow long vdom name for import, as actual config will be retrieved later
	set long_vdom_name_enable 1
}
if { [cli_ver_start 500 6] } {
	set long_vdom_name [cli_get_value $CLI_GLOBAL_NODE "system global" "" "long-vdom-name"]
	if { $long_vdom_name eq "enable" } {
		set long_vdom_name_enable 1
	}
}
if { $long_vdom_name_enable == 1 } {
	if {[string length $name]>(31+11+1)} {
		cli_set_errmsg "name is too long"
		return 0
	}
	set pat {[^0-9a-zA-Z\-_/]}
} else {
	if {[string length $name]>11} {
		cli_set_errmsg "name is too long"
		return 0
	}
	set pat {[^0-9a-zA-Z\-_]}
}

if {[regexp $pat $name]} {
	cli_set_errmsg "illegal name"
	return 0
}

if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1} {
	cli_set_errmsg "duplicate"
	return 0
}
if {$name eq "dmgmt-vdom"} {
	if { [cli_ver_start 500 0] } {
		set platform [cli_get_devinfo "platform"]
		if { [string first "7000E" $platform] == -1 && [string first "7030E" $platform] == -1 && [string first "7040E" $platform] == -1 && [string first "7060E" $platform] == -1 } {
		cli_set_errmsg "'dmgmt-vdom' is reserved and cannot be created/edited"
		return 0
		}
	} else {
		namespace import global::dmgmt_vdom_support
		set dmgmt [dmgmt_vdom_support]
		if { $dmgmt } {
			if {$CLI_ACT eq "add"} {
				cli_set_errmsg "'dmgmt-vdom' is reserved and cannot be created"
			} else {
				cli_set_errmsg "'dmgmt-vdom' is reserved and cannot be edited"
			}
			return 0
		}
	}
}
return 1
	%}

	"firewall address6" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {[cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp6" $name ""] != 0} {
	cli_set_errmsg "addr/addrgrp conflict"
	return 0
}
if { ![cli_ver_start 600 2] } {
	return 1
}
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $type eq "dynamic" } {
	set sdn_name [cli_get_value $CLI_CUR_NODE "" "" "sdn"]
	set sdn_node [cli_get_node $CLI_GLOBAL_NODE "system sdn-connector" $sdn_name ""]
	set sdn_type [cli_get_value $sdn_node "" "" "type"]
	if { ($sdn_type ne "nsx") && ($sdn_type ne "aci") } {
		cli_set_errmsg "firewall address6 can only use nsx or aci type sdn-connector."
		return 0
	}
	return 1
}
return 1
	%}
    "firewall address6-template subnet-segment values" = %{
set segment [cli_get_parent $CLI_CUR_PARENT_NODE]
set bits [cli_get_value $segment "" "" "bits"]
set seg_name [cli_get_value $segment "" "" "name"]
set val [cli_get_value $CLI_CUR_NODE "" "" "value"]
set length [string length $val]
set type [string tolower [string range $val 0 1]]
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $type eq "0b" } {
    if {[regexp {^0[bB][01]+$} $val] eq 0} {
        cli_set_errmsg "Value ($val) for $seg_name:$name must be a binary number"
        return 0
    }
    if { $length ne ($bits + 2) } {
        cli_set_errmsg "Value ($val) for $seg_name:$name must be a $bits-bit number"
        return 0
    }
} elseif { $type eq "0x" } {
    if { ($bits % 4) ne 0   } {
        cli_set_errmsg "Value ($val) for $seg_name:$name cannot be in hexadecimal format"
        return 0
    }
    if { $length ne ($bits/4 + 2) } {
        cli_set_errmsg "Value ($val) for $seg_name:$name must be a $bits-bit number"
        return 0
    }
    if { [regexp {^0[xX][0-9a-fA-F]+$} $val] eq 0 } {
        cli_set_errmsg "Invalid hexadecimal value ($val) for $seg_name:$name"
        return 0
    }
} else {
    cli_set_errmsg "Invalid format for $seg_name:$name value, must be 0b# or 0x#"
    return 0
}
return 1
%}
	"firewall ipmacbinding table" = %{
set mac [cli_get_value $CLI_CUR_NODE "" "" "mac"]
set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
if {$mac ne ""} {
	set l [split $mac ":"]
	if {[llength $l] != 6} {
		cli_set_errmsg "invalid mac"
		return 0
	}
	foreach e $l {
		if {[regexp {([[:xdigit:]]){2}} $e] == 0} {
			cli_set_errmsg "invalid mac"
			return 0
		}
	}
}
if { ($mac == 0 || $mac eq "" || ([scan $mac "%d:%d:%d:%d:%d:%d" m0 m1 m2 m3 m4 m5] == 6 && $m0 == 0 && $m1 == 0 && $m2 == 0 && $m3 == 0 && $m4 == 0 && $m5 == 0))
	&& ($ip == 0 || $ip eq "" || ([scan $ip "%d.%d.%d.%d" n0 n1 n2 n3] == 4 && $n0 == 0 && $n1 == 0 && $n2 == 0 && $n3 == 0)) } {
	cli_set_errmsg "Invalid mac address. If mac address is 0, ip address can not be 0."
	return 0
}
set nr_match [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall ipmacbinding table" "mac" 0 $mac "ip" 0 $ip]
if {$nr_match > 1} {
	cli_set_errmsg "entry exists"
	return 0
}
return 1
	%}

	"firewall ippool" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set sip [cli_get_value $CLI_CUR_NODE "" "" "startip"]
set eip [cli_get_value $CLI_CUR_NODE "" "" "endip"]
if {$sip eq "" || $sip eq "0.0.0.0"} {
	cli_set_errmsg "ippool \"$name\": start ip should be set"
	return 0
}
if {$eip eq ""} {set eip "0.0.0.0"}
set iplist [split $sip .]
set sipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
set iplist [split $eip .]
set eipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
if {$sipint > $eipint} {
	cli_set_errmsg "ippool \"$name\": end ip should be larger than start ip"
	return 0
}
if {$eipint >= 0xe0000000} {
	cli_set_errmsg "ippool \"$name\": invalid end ip"
	return 0
}

set ptype [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $ptype == "one-to-one" || $ptype == "port-block-allocation" } {
	set plist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall ippool"]
	foreach node $plist {
		set nname [cli_get_value $node "" "" "name"]
		if { $name == $nname } {
			continue
		}
		set nptype [cli_get_value $node "" "" "type"]
		if { $nptype != "one-to-one" && $ptype != "port-block-allocation" } {
			continue
		}
		set nsip [cli_get_value $node "" "" "startip"]
		set neip [cli_get_value $node "" "" "endip"]
		if {$nsip eq ""} {set nsip "0.0.0.0"}
		if {$neip eq ""} {set neip "0.0.0.0"}
		set iplist [split $nsip .]
		set nsipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
		set iplist [split $neip .]
		set neipint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
		if { $sipint<$neipint && $nsipint<$eipint } {
			cli_set_errmsg "ippool \"$name\": overlap ip-range with ippool \"$nname\""
			return 0
		}
	}
} else {
	set nr_match [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall ippool" "startip" 0 $sip "endip" 0 $eip]
	if {$nr_match > 1} {
		cli_set_errmsg "ippool \"$name\": duplicated startip/endip"
		return 0
	}
}

if { [cli_ver_start 500 0] && $ptype == "fixed-port-range" } {
	set ssip [cli_get_value $CLI_CUR_NODE "" "" "source-startip"]
	set seip [cli_get_value $CLI_CUR_NODE "" "" "source-endip"]
	if {$ssip eq "" || $ssip eq "0.0.0.0"} {
		cli_set_errmsg "ippool \"$name\": source-startip should be set"
		return 0
	}
	if {$seip eq ""} {set seip "0.0.0.0"}
	set siplist [split $ssip .]
	set ssipint [expr ([lindex $siplist 0]<<24)+([lindex $siplist 1]<<16)+([lindex $siplist 2]<<8)+[lindex $siplist 3]]
	set siplist [split $seip .]
	set seipint [expr ([lindex $siplist 0]<<24)+([lindex $siplist 1]<<16)+([lindex $siplist 2]<<8)+[lindex $siplist 3]]
	if {$ssipint > $seipint} {
		cli_set_errmsg "ippool \"$name\": source-startip is larger than source-endip"
		return 0;
	}

	set nnum [expr $eipint-$sipint+1]
	set snum [expr $seipint-$ssipint+1]
	set portrange [expr 65533-5117]
	set nport [expr $portrange/(($snum+$nnum-1)/$nnum)]
	if { $nport < 32 } {
		cli_set_errmsg "ippool \"$name\": not enough available ports (less that 32) for each IP"
		return 0;
	}
}

return 1
	%}
	"firewall multicast-policy" = %{
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
if {$dstaddr eq ""} {
	cli_set_errmsg "dstaddr cannot be empty"
	return 0
}
set dnat [cli_get_value $CLI_CUR_NODE "" "" "dnat"]
if {$dnat ne "" && $dnat ne "0.0.0.0"} {
	set iplist [split $dnat .]
	set dnatint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
	if {($dnatint & 0xff000000) == 0x7f000000 && ($dnatint & 0xf0000000) != 0xe0000000} {
		cli_set_errmsg "dnat is not a multicast addr"
		return 0
	}
	namespace import global::is_multicast_address
	set is_multicast [is_multicast_address $dnat]
	if { $is_multicast == 0 } {
		cli_set_errmsg "dnat is not a multicast addr"
		return 0
	}
}
set protocol [cli_get_value $CLI_CUR_NODE "" "" "protocol"]
if {$protocol == 6 || $protocol == 17} {
        set start_port [cli_get_value $CLI_CUR_NODE "" "" "start-port"]
        set end_port [cli_get_value $CLI_CUR_NODE "" "" "end-port"]
        if {$start_port ne "" && $end_port ne "" && $start_port > $end_port} {
                cli_set_errmsg "invalid start-port/end-port number"
                return 0
        }
}
if { [cli_ver_start 500 0] } {
	set addrs [cli_get_value $CLI_CUR_NODE "" "" "srcaddr"]
	foreach addr $addrs {
		set addr [string trim $addr \"]
		set anode [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $addr ""]
		if { 0 == $anode } {
#fw_addr might be copied from adom level later.
#			cli_set_errmsg "srcaddr \"$addr\" not exist"
#			return 0
			continue
		}
		set asintf [cli_get_value $anode "" "" "associated-interface"]
		set srcintf [cli_get_value $CLI_CUR_NODE "" "" "srcintf"]
		if { $asintf ne "" && $asintf ne "any" && $asintf ne $srcintf } {
			cli_set_errmsg "srcaddr's associate-interface not match with srcintf"
			return 0
		}
	}
}
set srcintf [cli_get_value $CLI_CUR_NODE "" "" "srcintf"]
set srcintf [string trim $srcintf \"]
set dstintf [cli_get_value $CLI_CUR_NODE "" "" "dstintf"]
set dstintf [string trim $dstintf \"]
if { $srcintf eq $dstintf && $srcintf ne "any" } {
	cli_set_errmsg "srcintf and dstintf must be different"
	return 0
}
if { [cli_ver_start 500 0] } {
} else {
	if { $srcintf eq "any" || $dstintf eq "any" } {
		cli_set_errmsg "srcintf/dstintf cannot be \"any\""
		return 0
	}
}
set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
set srcaddr [cli_get_value $CLI_CUR_NODE "" "" "srcaddr" 1]
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr" 1]
namespace import global::intf_binding_contradiction
set msg [intf_binding_contradiction $srcaddr $dstaddr $srcintf $dstintf $id 0 1]
if { $msg ne 0 } {
	cli_set_errmsg $msg
	return 0
}
namespace import global::wildcard_fqdn_check
if { [wildcard_fqdn_check $srcaddr "src" 0] } {
        return 0
}
return 1
	%}

	"firewall policy6" = %{
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
set srcintf [cli_get_value $CLI_CUR_NODE "" "" "srcintf"]
set dstintf [cli_get_value $CLI_CUR_NODE "" "" "dstintf"]
if {$srcintf eq "" || $dstintf eq ""} {
	cli_set_errmsg "entry not exist"
	return 0
}
proc fw_pol_get_fdid {name} {
	global CLI_CUR_VDOM_NODE CLI_GLOBAL_NODE
	set zone [cli_get_value $CLI_CUR_VDOM_NODE "system zone" $name "interface"]
	if {$zone ne ""} {
		set intf_list $zone
	} else {
		set intf_list $name
	}
	set intf [lindex $intf_list 0]
	return [cli_get_value $CLI_GLOBAL_NODE "system interface" $intf "forward-domain"]
}
if {$srcintf != "\"any\"" && $dstintf != "\"any\""} {
set src_fdid [fw_pol_get_fdid $srcintf]
set dst_fdid [fw_pol_get_fdid $dstintf]
if {$src_fdid != 0 && $dst_fdid != 0 && $src_fdid != $dst_fdid} {
	cli_set_errmsg "Interfaces must have the same forward domain ID in TP mode"
	return 0
}
}
if {[cli_get_value $CLI_CUR_NODE "" "" "srcaddr"] eq "" ||
    [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"] eq ""} {
	cli_set_errmsg "addr name"
	return 0
}
if {[cli_get_value $CLI_CUR_NODE "" "" "trafficshaping"] eq "enable"} {
	set maxband [cli_get_value $CLI_CUR_NODE "" "" "maxbandwidth"]
	set gband [cli_get_value $CLI_CUR_NODE "" "" "gbandwidth"]
	if {$maxband < $gband} {
		cli_set_errmsg "policy bandwidth"
		return 0
	}
}
if {$action eq "ipsec"} {
	set vpntunnel [cli_get_value $CLI_CUR_NODE "" "" "vpntunnel"]
	if {$vpntunnel eq ""} {
		cli_set_errmsg "tunnel name"
		return 0
	}
	if {[cli_get_value $CLI_CUR_NODE "" "" "inbound"] ne "enable" && [cli_get_value $CLI_CUR_NODE "" "" "outbound"] ne "enable"} {
		cli_set_errmsg "Please set inbound or/and outbound setting."
		return 0
	}
	set sif_type [cli_get_value $CLI_GLOBAL_NODE "system interface" $srcintf "type"]
	set dif_type [cli_get_value $CLI_GLOBAL_NODE "system interface" $dstintf "type"]
	if {$sif_type eq "tunnel" || $dif_type eq "tunnel"} {
		cli_set_errmsg "invalid value"
		return 0
	}
	set p1_node [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1" $vpntunnel ""]
	set mk_node 0
	if {$p1_node == 0} {
		set mk_node [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec manualkey" $vpntunnel ""]
		if {$mk_node == 0} {
			cli_set_errmsg "invalid value"
			return 0
		}
	}
	if {[cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq ""} {
		if {$p1_node} {
			set p1_intf [cli_get_value $p1_node "" "" "interface"]
			if {$p1_intf ne $dstintf} {
				cli_set_errmsg "invalid value"
				return 0
			}
		}
		if {$mk_node} {
			set mk_intf [cli_get_value $mk_node "" "" "interface"]
			if {$mk_intf ne $dstintf} {
				cli_set_errmsg "invalid value"
				return 0
			}
		}
	}
}

if { [cli_ver_start 500 0] } {
set idb [cli_get_value $CLI_CUR_NODE "" "" "identity-based"]
if { $idb ne "enable" } {
	set logtraffic [cli_get_value $CLI_CUR_NODE "" "" "logtraffic"]
	if {$logtraffic ne "all"} {
		set reputation [cli_get_value $CLI_CUR_VDOM_NODE "client-reputation profile" "" "status"]
		if { $reputation eq "enable" } {
			cli_set_errmsg "logtraffic MUST be set to \"all\" when client reputation is enabled"
			return 0
		}
	}
	if { $action eq "deny" || $action == 0 || $action eq "" } {
		if { ($logtraffic == 0) || ($logtraffic eq "") || ($logtraffic eq "utm") } {
			cli_set_errmsg "logtraffic cannot be set to utm when policy action is deny"
			return 0
		}
	}
}
}

## Mantis 271372
if { [cli_ver_start 500 2] } {
	set schedule [cli_get_value $CLI_CUR_NODE "" "" "schedule"]
	if { $schedule == 0 || $schedule eq "" } {
		cli_set_errmsg "Must set schedule."
		return 0
	}
} elseif { [cli_ver_start 500 0] } {
	if {[cli_is_match $CLI_CUR_NODE 0 "" "action" 1 "ssl-vpn"] && [cli_is_match $CLI_CUR_NODE 0 "" "identity-based" 1 "enable"]} {
		set schedule [cli_get_value $CLI_CUR_NODE "" "" "schedule"]
		if { $schedule == 0 || $schedule eq "" } {
			cli_set_errmsg "Must set schedule."
			return 0
		}
	}
} elseif { [cli_ver_start 400 3] } {
	if {[cli_is_match $CLI_CUR_NODE 0 "" "action" 1 "ssl-vpn"] && [cli_is_match $CLI_CUR_NODE 0 "" "identity-based" 1 "enable"]} {
		set schedule [cli_get_value $CLI_CUR_NODE "" "" "schedule"]
		if { $schedule == 0 || $schedule eq "" } {
			cli_set_errmsg "Must set schedule."
			return 0
		}
	}
}
if { [cli_ver_start 500 4] } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	if { $name ne "" } {
		if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1 } {
			cli_set_errmsg "Duplicate policy name: $name."
			return 0
		} else {
			set n [string trim $name \"]
			if { $n ne $name } {
				if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $n] } {
					cli_set_errmsg "Duplicate policy name: $name."
					return 0
				}
			}
		}
		set name [string trim $name \"]
		if { [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall policy" "name" 0 $name] ||
		     [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall policy" "name" 0 "\"$name\""] } {
			cli_set_errmsg "$name is already used by firewall.policy"
			return 0
		}
	}
	if { [cli_get_value $CLI_CUR_NODE "" "" "utm-status"] eq "enable" } {
	    if { [cli_get_value $CLI_CUR_NODE "" "" "profile-type"] eq "single" } {
		if { [cli_get_value $CLI_CUR_NODE "" "" "av-profile"] ne "" ||
		     [cli_get_value $CLI_CUR_NODE "" "" "webfilter-profile"] ne "" ||
		     [cli_get_value $CLI_CUR_NODE "" "" "spamfilter-profile"] ne "" ||
		     [cli_get_value $CLI_CUR_NODE "" "" "dlp-sensor"] ne "" ||
		     [cli_get_value $CLI_CUR_NODE "" "" "icap-profile"] ne "" } {
		    if { [cli_get_value $CLI_CUR_NODE "" "" "profile-protocol-options"] eq "" } {
			cli_set_errmsg "Attribute 'profile-protocol-options' MUST be set."
			return 0
		    }
		}
	    }
	}
}
return 1
	%}
	"webfilter bword" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1} {
	cli_set_errmsg "duplicate"
	return 0
}
return 1
	%}
	"webfilter bword entries" = %{
set score [cli_get_value $CLI_CUR_NODE "" "" "score"]
if {$score <= 0 || $score > 99999} {
	cli_set_errmsg "Score out of range [0,999999]"
	return 0
}
set ptype [cli_get_value $CLI_CUR_NODE "" "" "pattern-type"]
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set lang [cli_get_value $CLI_CUR_NODE "" "" "lang"]
if {[cli_check_regex 1 $name $ptype $lang]} {
	cli_set_errmsg "unexpected input"
	return 0
}
return 1
	%}
	"webfilter exmword" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1} {
	cli_set_errmsg "duplicate"
	return 0
}
return 1
	%}
        "webfilter exmword entries" = %{
set ptype [cli_get_value $CLI_CUR_NODE "" "" "pattern-type"]
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set lang [cli_get_value $CLI_CUR_NODE "" "" "lang"]
if {[cli_check_regex 1 $name $ptype $lang]} {
	cli_set_errmsg "unexpected input"
	return 0
}
return 1
        %}
        "webfilter content entries" = %{
set ptype [cli_get_value $CLI_CUR_NODE "" "" "pattern-type"]
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set lang [cli_get_value $CLI_CUR_NODE "" "" "lang"]
if {[cli_check_regex 1 $name $ptype $lang]} {
	cli_set_errmsg "unexpected input"
	return 0
}
return 1
        %}

	"webfilter fortiguard" = %{
set ovrd_auth_http_port [cli_get_value $CLI_CUR_NODE "" "" "ovrd-auth-port-http"]
if {$ovrd_auth_http_port eq ""} {set ovrd_auth_http_port 8008}
set ovrd_auth_https_port [cli_get_value $CLI_CUR_NODE "" "" "ovrd-auth-port-https"]
if {$ovrd_auth_https_port eq ""} {set ovrd_auth_https_port 8010}
proc check_port {p op} {
	if {$p < 1 || $p == 80 || $p == 443 || $p > 65535 || $p == $op} {
		return -1
	}
	return 0
}
if {[check_port $ovrd_auth_http_port $ovrd_auth_https_port] == -1} {
	cli_set_errmsg "invalid ftgd auth port"
	return 0
}
if {[check_port $ovrd_auth_https_port $ovrd_auth_http_port] == -1} {
	cli_set_errmsg "invalid ftgd auth port"
	return 0
}
return 1
	%}

	"webfilter ftgd-local-rating" = %{
if { [cli_ver_start 600 0] } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "url"]
	for {set i 0} {$i < [string length $name]} {incr i} {
		set char [string index $name $i]
		if {[regexp {[<>\"*#{}|\\^`[:space:]]} $char]} {
			cli_set_errmsg "invalid ftgd-local-rating.url: $name"
			return 0
		}
	}
}
if { [cli_ver_start 500 4] } {
	set c [cli_get_value $CLI_CUR_NODE "" "" "rating"]
	if { $c eq "" || $c eq 0 } { return 1 }
	namespace import global::is_multiple
	if { [is_multiple $c] } {
		cli_set_errmsg "Only one single category is allowed"
		return 0
	}
	set c [string trim $c \"]
	if { [string is integer $c] == 0 } {
		cli_set_errmsg "No category group is allowed"
		return 0
	}
}
return 1
	%}

	"webfilter ftgd-local-cat" = %{
set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
if {$id ne "" && $id ne "0" && [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "id" 0 $id] > 1} {
	cli_set_errmsg "duplicate"
	return 0
}
return 1
	%}

	"webfilter ftgd-ovrd" = %{
proc check_dt {dt} {
	set dt [string trim $dt \"]
	if {[scan $dt "%d/%d/%d %d:%d:%d" yr mon day hr min sec] != 6} {
		return -1
	}
	if {$yr < 2001 || $yr > 2037} {
		return -1
	}
	switch $mon {
		1 - 3 - 5 - 7 - 8 - 10 - 12 {
			if {$day < 0 || $day > 31} {
				return -1
			}
		}
		4 - 6 - 9 - 11 {
			if {$day < 0 || $day > 30} {
				return -1
			}
		}
		2 {
			if {($yr % 4 == 0) && (($yr % 100 != 0) || ($yr % 400 == 0))} {
				if {$day < 0 || $day > 29} {
					return -1
				}
			} else {
				if {$day < 0 || $day > 28} {
					return -1
				}
			}
		}
		default {
			return -1
		}
	}
	if {$hr < 0 || $hr > 23 || $min < 0 || $min > 59 || $sec < 0 || $sec > 59} {
		return -1
	}
	return 0
}
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set url [cli_get_value $CLI_CUR_NODE "" "" "url"]
if {$url eq ""} {
	if {$type eq "dir" || $type eq "domain"} {
		cli_set_errmsg "empty value"
		return 0
	}
}
if {$type eq "domain"} {
	set url [string trim $url \"]
	if {[string first "\/" $url] != -1} {
		cli_set_errmsg "invalid ftgd ovrd domain"
		return 0
	}
}
set scope [cli_get_value $CLI_CUR_NODE "" "" "scope"]
set scope_test "user"
set scope_tgt "user"
switch $scope {
	"user" {
		set user [cli_get_value $CLI_CUR_NODE "" "" "user"]
		if {$user eq ""} {
			cli_set_errmsg "empty value"
			return 0
		}
		set scope_test "user"
		set scope_tgt $user
	}
	"user-group" {
		set user_group [cli_get_value $CLI_CUR_NODE "" "" "user-group"]
		if {$user_group eq ""} {
			cli_set_errmsg "empty value"
			return 0
		}
		set scope_test "user-group"
		set scope_tgt $user_group
	}
	"ip" {
		set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
		if {$ip eq ""} {
			cli_set_errmsg "empty value"
			return 0
		}
		set scope_test "ip"
		set scope_tgt $ip
	}
	"profile" {
		set profile [cli_get_value $CLI_CUR_NODE "" "" "profile"]
		if {$profile eq ""} {
			cli_set_errmsg "empty value"
			return 0
		}
		set scope_test "profile"
		set scope_tgt $profile
	}
}
set expiry [cli_get_value $CLI_CUR_NODE "" "" "expires"]
if {$expiry ne ""} {
	if {[check_dt $expiry] == -1} {
		cli_set_errmsg "invalid date/time"
		return 0
	}
}
set rating [cli_get_value $CLI_CUR_NODE "" "" "rating"]
if {$rating eq ""} {
	if {$type eq "rating"} {
		cli_set_errmsg "empty value"
		return 0
	}
}
set ovrd_nodes [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
set type_test "rating"
set type_tgt $rating
if {$type eq "dir" || $type eq "domain"} {
	set type_test "url"
	set type_tgt $url
} elseif {$type eq "rating"} {
	set type_test "rating"
	set type_tgt $rating
}
foreach e $ovrd_nodes {
	if { [cli_if_same_node $e $CLI_CUR_NODE] } {
		continue
	}
	set etype [cli_get_value $e "" "" "type"]
	if {$etype ne $type} {
		continue
	}
	set etype_tgt [cli_get_value $e "" "" $type_test]
	if {$etype_tgt ne $type_tgt} {
		continue
	}
	set escope [cli_get_value $e "" "" "scope"]
	if {$escope ne $scope} {
		continue
	}
	set escope_tgt [cli_get_value $e "" "" $scope_test]
	if {$escope_tgt eq $scope_tgt} {
		cli_set_errmsg "duplicate"
		return 0
	}
}
set profile [cli_get_value $CLI_CUR_NODE "" "" "profile"]
if {$profile ne ""} {
	if {![cli_get_node $CLI_CUR_VDOM_NODE "firewall profile" $profile ""]} {
		cli_set_errmsg "entry not exist"
		return 0
	}
}
return 1
	%}

	"webfilter urlfilter entries" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set url [cli_get_value $CLI_CUR_NODE "" "" "url"]
if { $type eq "regex" } {
        if {[string index $url 0] eq "*" || [string index $url 0] eq "?"} {
                cli_set_errmsg "url cannot start with * or ?"
                return 0
        }
} elseif { $type eq "simple" } {
        set url [string trim $url \"]
        set url [string trim $url]
        if { ($url ne "") && [cli_check_url 0 $url] } {
                cli_set_errmsg "URL \"$url\" is invalid"
                return 0
        }
}
return 1
	%}
	"webfilter urlfilter" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1} {
	cli_set_errmsg "duplicate"
	return 0
}
return 1
	%}

	"log disk setting" = %{
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
set ip [cli_get_value $CLI_CUR_NODE "" "" "uploadip"]
if {$ip ne ""} {
	set byte1 [lindex [split $ip .] 0]
	if {$byte1 & 0x0ff == 127 && $byte1 & 0xf0 == 0xe0} {
		cli_set_errmsg "invalid ip"
		return 0
	}
}
if {$status eq "enable"} {
	set rolltime [cli_get_value $CLI_CUR_NODE "" "" "roll-time"]
	set rolltime [string trim $rolltime \"]
	if {[scan $rolltime "%d:%d" hr min] != 2 ||
    	    $hr < 0 || $hr > 23 || $min < 0 || $min > 59} {
	    	cli_set_errmsg "invalid date/time"
	    	return 0
	}
} else {
	set fazlog_status [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "status"]
	set fazlog_uplopt [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "upload-option"]
	set faz2log_status [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer2 setting" "" "status"]
	set faz2log_uplopt [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer2 setting" "" "upload-option"]
	set faz3log_status [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer3 setting" "" "status"]
	set faz3log_uplopt [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer3 setting" "" "upload-option"]

	if { [cli_obj_support "log remote setting"] } {
		set remote_status [cli_get_value $CLI_CUR_VDOM_NODE "log remote setting" "" "status"]
		set remote_dst [cli_get_value $CLI_CUR_VDOM_NODE "log remote setting" "" "destination"]
		if {($remote_status eq "enable" && $remote_dst eq "FAZ" &&
			($fazlog_status eq "enable" || $faz2log_status eq "enable" || $faz3log_status eq "enable"))} {
			if {(![cli_branchpt_start 400 522] ||
				($fazlog_status eq "enable" && $fazlog_uplopt eq "store-and-upload") ||
				($faz2log_status eq "enable" && $faz2log_uplopt eq "store-and-upload") ||
				($faz3log_status eq "enable" && $faz3log_uplopt eq "store-and-upload"))} {
				cli_set_errmsg "conflict value"
				return 0
			}
		}
	}
	if { [cli_ver_start 400 3] } {
		namespace import global::cli_sys_global_vdom_enable
		if { [cli_sys_global_vdom_enable] == 0 } {
			set fazlog_status [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "status"]
			if { $fazlog_status eq "enable" } {
				if { ![cli_branchpt_start 400 522] } {
					cli_set_errmsg "Can't be disabled because remote(fortianalyzer) log has been enabled."
					return 0
				}
				set fazlog_uplopt [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "upload-option"]
				if { $fazlog_uplopt eq "store-and-upload" } {
					cli_set_errmsg "FortiAnalyzer is enabled in Store-and-Upload mode.\nCan't be disabled because remote log upload has been enabled."
					return 0
				}
			}
			set fdslog_status [cli_get_value $CLI_GLOBAL_NODE "log fortiguard setting" "" "status"]
			if { $fdslog_status eq "enable" } {
				if { ![cli_branchpt_start 400 522] } {
					cli_set_errmsg "Can't be disabled because remote(fortiguard) log has been enabled."
					return 0
				}
				set fdslog_uplopt [cli_get_value $CLI_GLOBAL_NODE "log fortiguard setting" "" "upload-option"]
				if { $fdslog_uplopt eq "store-and-upload" } {
					cli_set_errmsg "FortiCloud is enabled in Store-and-Upload mode.\nCan't be disabled because remote log upload has been enabled."
					return 0
				}
			}
		}
	}
}
return 1
	%}

	"log report schedule" = %{
set time [cli_get_value $CLI_CUR_NODE "" "" "time"]
if { $time != 0 } {
	if {[scan $time "%d:%d" hr min] != 2 || $hr < 0 || $hr > 23 || $min < 0 || $min > 59} {
		cli_set_errmsg "invalid value"
		return 0
	}
}
return 1
	%}

	"log report output addresses" = %{
set address [cli_get_value $CLI_CUR_NODE "" "" ""]
set address [string trim $address \"]
set pattern {^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})$}
if {[regexp $pattern $address] == 0} {
	cli_set_errmsg "addresses $address is invalid"
	return 0
}
return 1
	%}
	"log report output" = %{
set uploadip [cli_get_value $CLI_CUR_NODE "" "" "upload-ip"]
if {$uploadip eq ""} {
	cli_set_errmsg "invalid ip"
	return 0
} else {
	set byte1 [lindex [split $uploadip .] 0]
	if {$byte1 & 0x0ff == 127 && $byte1 & 0xf0 == 0xe0} {
		cli_set_errmsg "invalid ip"
		return 0
	}
}
return 1
	%}

	"log report summary-layout summary-reports" = %{
set sumrpt_list {sum-proto sum-band sum-bond-source sum-bond-dest sum-tv sum-tv-name sum-tv-src sum-tv-dst sum-attacks sum-attacks-id sum-attacks-src sum-attacks-dst sum-mf sum-mf-band sum-mf-dst sum-mf-src sum-wf sum-wf-cat sum-wf-src sum-wf-dst sum-ct sum-ct-type sum-ct-src sum-ev sum-ev-cat sum-ev-type}
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {[lsearch $sumrpt_list $name] == -1} {
	cli_set_errmsg "invalid value"
	return 0
}
set style [cli_get_value $CLI_CUR_NODE "" "" "style"]
if {$style ne "bar"} {
	set topn [cli_get_value $CLI_CUR_NODE "" "" "topN"]
	if {$topn < 1 || $topn > 10} {
		cli_set_errmsg "invalid value"
		return 0
	}
}
return 1
	%}

	"alertemail setting" = %{
foreach m {1 2 3} {
	set rcv [cli_get_value $CLI_CUR_NODE "" "" "mailto${m}"]
	if {$rcv ne ""} {
		set offset [string first "@" $rcv]
		if {$offset == -1 || [string first "@" $rcv [expr $offset+1]] != -1} {
			cli_set_errmsg "invalid value"
			return 0
		}
	}
}
return 1
	%}

	"router aspath-list rule" = %{
set regexp [cli_get_value $CLI_CUR_NODE "" "" "regexp"]
if {$regexp eq ""} {
	cli_set_errmsg "empty value"
	return 0
}
return 1
	%}
	"router aspath-list" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {[regexp {[^[[:alnum:]]]|\s} $name] != 0} {
	cli_set_errmsg "invalid value"
	return 0
}
if { ![cli_ver_start 600 0] && ![string match "*gui*" [cli_get_clisrc]] } {
	if {[cli_get_tbl_cnt $CLI_CUR_NODE "rule"] < 1} {
		cli_set_errmsg "AS path list must have at least 1 rule"
		return 0
	}
}
return 1
	%}

	"router bgp" = %{
set dist_ext [cli_get_value $CLI_CUR_NODE "" "" "distance-external"]
set dist_int [cli_get_value $CLI_CUR_NODE "" "" "distance-internal"]
set dist_local [cli_get_value $CLI_CUR_NODE "" "" "distance-local"]
if {$dist_ext && !($dist_int && $dist_local)} {
	cli_set_errmsg "entry not exist"
	return 0
}
set keepalive [cli_get_value $CLI_CUR_NODE "" "" "keepalive-timer"]
set holdtime [cli_get_value $CLI_CUR_NODE "" "" "holdtime-timer"]
if {$keepalive eq ""} {set keepalive 60}
if {$holdtime eq ""} {set holdtime 180}
if {$holdtime != 0 && ($holdtime < 3 || $holdtime >= 65535)} {
	cli_set_errmsg "invalid value"
	return 0
}
if {($keepalive >= 0 && $holdtime < 0) || ($keepalive < 0 && $holdtime >= 0)} {
	cli_set_errmsg "entry not exist"
	return 0
}
set damp_max [cli_get_value $CLI_CUR_NODE "" "" "dampening-max-suppress-time"]
if {$damp_max eq ""} {set damp_max 60}
set damp_half [cli_get_value $CLI_CUR_NODE "" "" "dampening-reachability-half-life"]
if {$damp_half eq ""} {set damp_half 15}
set unreach_half [cli_get_value $CLI_CUR_NODE "" "" "dampening-unreachability-half-life"]
if {$unreach_half eq ""} {set unreach_half 15}
if {$damp_max < $damp_half || $damp_max < $unreach_half} {
	cli_set_errmsg "entry not exist"
	return 0
}
set conf_id [cli_get_value $CLI_CUR_NODE "" "" "confederation-identifier"]
set conf_oldid [cli_get_org_value $CLI_CUR_NODE "" "" "confederation-identifier"]
if {$conf_id ne $conf_oldid} {
	if {$conf_id < 1 || $conf_id > 65535} {
		cli_set_errmsg "invalid value"
		return 0
	}
	if {[cli_get_node $CLI_CUR_NODE "peer" $conf_id ""]} {
		cli_set_errmsg "invalid value"
		return 0
	}
}
return 1
	%}
	"router bgp aggregate-address" = %{
set prefix [cli_get_value $CLI_CUR_NODE "" "" "prefix"]

set tok [string first "/" $prefix]
if {$tok > 0} {
	set ipaddr [string range $prefix 0 $tok-1]
	set mask [string range $prefix $tok+1 end]
        if {[string compare $ipaddr "0.0.0.0"] || $mask <= 0 || $mask > 32} {
                cli_set_errmsg "invalid ip"
                return 0
        }
} else {
        if {[string compare $prefix "0.0.0.0 0.0.0.0"] == 0} {
                cli_set_errmsg "invalid ip"
                return 0
        }
}
if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "prefix" 0 $prefix] > 1} {
	cli_set_errmsg "entry exists"
	return 0
}
return 1
	%}
	"router bgp neighbor" = %{

proc validateIPv6 {IPv6} {
	if {[regexp {(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*)$}  $IPv6]} {
		return 1
	} else {
		return 0
	}
}

set distlistin [cli_get_value $CLI_CUR_NODE "" "" "distribute-list-in"]
set prelistin [cli_get_value $CLI_CUR_NODE "" "" "prefix-list-in"]
if { $distlistin ne "" && $prelistin ne "" } {
	cli_set_errmsg "\"distribute-list-in\" and \"prefix-list-in\" cannot be set at the same time"
	return 0
}
set distlistout [cli_get_value $CLI_CUR_NODE "" "" "distribute-list-out"]
set prelistout [cli_get_value $CLI_CUR_NODE "" "" "prefix-list-out"]
if { $distlistout ne "" && $prelistout ne "" } {
	cli_set_errmsg "\"distribute-list-out\" and \"prefix-list-out\" cannot be set at the same time"
	return 0
}

set keepalive [cli_get_value $CLI_CUR_NODE "" "" "keep-alive-timer"]
set holdtime [cli_get_value $CLI_CUR_NODE "" "" "holdtime-timer"]
if {$holdtime != 4294967295 || $keepalive != 4294967295} {
	if {$holdtime != 4294967295 && ($holdtime < 3 || $holdtime >= 65535)} {
		cli_set_errmsg "invalid value"
		return 0
	}
	if { $keepalive == 4294967295 } {
		cli_set_errmsg "keep-alive-timer must be set when holdtime-timer is set"
		return 0
	}
	if { $holdtime == 4294967295 } {
		cli_set_errmsg "holdtime-timer must be set when keep-alive-timer is set"
		return 0
	}
}
set ip [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$ip eq "" || ([scan $ip "%d.%d.%d.%d" a a a a] != 4 && [validateIPv6 $ip] == 0)} {
	cli_set_errmsg "invalid ip"
	return 0
}
if {[string compare $ip "0.0.0.0"] == 0} {
	cli_set_errmsg "invalid ip"
	return 0
}
set allnodelist [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
foreach intf_node $allnodelist {
	if { [cli_if_same_node $intf_node $CLI_CUR_PARENT_NODE] } {
		continue
	}
	set vdom [cli_get_value $intf_node "" "" "vdom"]
		set vdom [string trim $vdom \"]
		set cur_dom $CLI_CUR_VDOM_NAME
		if {[string compare $vdom $cur_dom] != 0} {
			continue
		}

	set mip [cli_get_value $intf_node "" "" "ip"]
		set iplist [split $mip " "]

		set mip [lindex $iplist 0]
		if {[string compare $ip $mip] == 0} {
			cli_set_errmsg "invalid ip"
			return 0
		}

	set secip_list [cli_get_tbl_list $intf_node "secondaryip"]
		foreach item $secip_list {
			set sip [cli_get_value $item "" "" "ip"]
			set iplist [split $sip " "]
			set sip [lindex $iplist 0]
			if {[string compare $ip $sip] == 0} {
				cli_set_errmsg "invalid ip"
				return 0
			}
		}
}

set node_list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach e $node_list {
	if { [cli_if_same_node $e $CLI_CUR_NODE] } {
		continue
	}
	set eip [cli_get_value $e "" "" "ip"]
	if { [string equal -nocase $eip $ip] } {
		cli_set_errmsg "duplicate IP neighbor $ip"
		return 0
	}
}

set max_prefix [cli_get_value $CLI_CUR_NODE "" "" "maximum-prefix"]
if {$max_prefix ne "" && $max_prefix < 0} {
	cli_set_errmsg "invalid maximum-prefix"
	return 0
}
return 1
	%}
	"router bgp network" = %{
set prefix [cli_get_value $CLI_CUR_NODE "" "" "prefix"]
if {$prefix eq ""} {
	cli_set_errmsg "invalid ip"
	return 0
}
if {[string compare $prefix "0.0.0.0 0.0.0.0"] == 0} {
	cli_set_errmsg "invalid ip"
	return 0
}
if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "prefix" 0 $prefix] > 1} {
	cli_set_errmsg "entry exists"
	return 0
}
return 1
	%}
	"router bgp admin-distance" = %{
set prefix [cli_get_value $CLI_CUR_NODE "" "" "neighbour-prefix"]
if {$prefix eq ""} {
	cli_set_errmsg "invalid ip"
	return 0
}

set tok [string first "/" $prefix]
if {$tok > 0} {
	set ipaddr [string range $prefix 0 $tok-1]
	set mask [string range $prefix $tok+1 end]
	if {[string compare $ipaddr "0.0.0.0"] || $mask <= 0 || $mask > 32} {
		cli_set_errmsg "invalid ip"
		return 0
	}
} else {
	if {[string compare $prefix "0.0.0.0 0.0.0.0"] == 0} {
		cli_set_errmsg "invalid ip"
		return 0
	}
}
if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "neighbour-prefix" 0 $prefix] > 1} {
	cli_set_errmsg "entry exists"
	return 0
}
return 1
	%}
	"router bgp scan-time" = %{
set val [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $val > 0 && $val < 5 } {
	cli_set_errmsg "scan-time must be 0 or 5-60"
	return 0
}
return 1
	%}

	"router community-list" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$name eq "" || [regexp {[^[[:alnum:]]]|\s} $name] != 0} {
	cli_set_errmsg "invalid value"
	return 0
}
if { ![cli_ver_start 600 0] && ![string match "*gui*" [cli_get_clisrc]] } {
	if {[cli_get_tbl_cnt $CLI_CUR_NODE "rule"] < 1} {
		cli_set_errmsg "Community list must have at least 1 rule"
		return 0
	}
}
return 1
	%}
	"router community-list rule" = %{
set match [cli_get_value $CLI_CUR_NODE "" "" "match"]
set regexp [cli_get_value $CLI_CUR_NODE "" "" "regexp"]
set type [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "type"]
if { $type eq "standard" } {
	if { $match eq "" } {
		cli_set_errmsg "attribute 'match' MUST be set"
		return 0
	}
	namespace import global::valid_router_community_name
	set subs [regexp -all -inline {\S+} $match]
	foreach sub $subs {
		if { ![valid_router_community_name $sub] } {
			cli_set_errmsg "community string '$sub' is invalid"
			return 0
		}
	}
}
if { $type eq "expanded" } {
	if { $regexp eq "" } {
		cli_set_errmsg "attribute 'regexp' MUST be set"
		return 0
	}
	if { ([string first "\n" $regexp] != -1) || ([string first "\r" $regexp] != -1) } {
		cli_set_errmsg "attribute 'regexp' can not has '\n' or '\r'"
		return 0
	}
}
return 1
	%}
	"router key-chain" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {[regexp {[^[[:alnum:]]]|\s} $name] != 0} {
        cli_set_errmsg "invalid value"
        return 0
}
return 1
	%}
	"router key-chain key" = %{
proc check_date {day mon yr} {
	switch $mon {
		1 - 3 - 5 - 7 - 8 - 10 - 12 {
			if {$day < 0 || $day > 31} {
				return -1
			}
		}
		4 - 6 - 9 - 11 {
			if {$day < 0 || $day > 30} {
				return -1
			}
		}
		2 {
			if {($yr % 4 == 0) && (($yr % 100 != 0) || ($yr % 400 == 0))} {
				if {$day < 0 || $day > 29} {
					return -1
				}
			} else {
				if {$day < 0 || $day > 28} {
					return -1
				}
			}
		}
		default {
			return -1
		}
	}
	return 0
}
proc check_dt {t} {
	set t [string trim $t \"]
	set tlen [llength $t]
	if {$tlen != 5 && $tlen != 8} {
		return -1
	}
	set check_end 1
	if {$tlen == 5} {
		if {[scan $t "%d:%d:%d %d %d %d %s" start_hr start_min start_sec start_day start_mon start_yr end] != 7} {
			return -1
		}
		if {$end ne "infinite" && [string is digit $end] == 0} {
			return -1
		}
		set check_end 0
	} else {
		if {[scan $t "%d:%d:%d %d %d %d %d:%d:%d %d %d %d" start_hr start_min start_sec start_day start_mon start_yr end_hr end_min end_sec end_day end_mon end_yr] != 12} {
			return -1
		}
	}

	if {$start_hr < 0 || $start_hr > 23 || $start_min < 0 || $start_min > 59 || $start_sec < 0 || $start_sec > 59} {
		return -1
	}
	if {[check_date $start_day $start_mon $start_yr] == -1} {
		return -1
	}
	if {$check_end} {
		if {$end_hr < 0 || $end_hr > 23 || $end_min < 0 || $end_min > 59 || $end_sec < 0 || $end_sec > 59} {
			return -1
		}
		if {[check_date $end_day $end_mon $end_yr] == -1} {
			return -1
		}
		if {!($end_yr > $start_yr || $end_mon > $start_mon || $end_day > $start_day || $end_hr > $start_hr || $end_min > $start_min || $end_sec > $start_sec)} {
			return -1
		}
	}
	return 0
}
set accept_life [cli_get_value $CLI_CUR_NODE "" "" "accept-lifetime"]
set key [cli_get_value $CLI_CUR_NODE "" "" "key-string"]
set send_life [cli_get_value $CLI_CUR_NODE "" "" "send-lifetime"]
if {$accept_life eq "" || $key eq "" || $send_life eq ""} {
	cli_set_errmsg "empty value"
	return 0
}
if {[check_dt $accept_life] == -1 || [check_dt $send_life] == -1} {
	cli_set_errmsg "time/date"
	return 0
}
return 1
	%}
	"router multicast" = %{
set threshold [cli_get_value $CLI_CUR_NODE "" "" "route-threshold"]
set limit [cli_get_value $CLI_CUR_NODE "" "" "route-limit"]
if {$threshold ne "" && $limit ne "" && $threshold > $limit} {
	cli_set_errmsg "threshold greater than limit"
	return 0
}
return 1
	%}
	"router multicast pim-sm-global" = %{
set bsr_candidate [cli_get_value $CLI_CUR_NODE "" "" "bsr-candidate"]
if {$bsr_candidate eq "enable"} {
	if {[cli_get_value $CLI_CUR_NODE "" "" "bsr-interface"] eq ""} {
		cli_set_errmsg "no BSR interface"
		return 0
	}
}
set reg_src [cli_get_value $CLI_CUR_NODE "" "" "register-source"]
if {$reg_src eq "interface"} {
	if {[cli_get_value $CLI_CUR_NODE "" "" "register-source-interface"] eq ""} {
		cli_set_errmsg "no source override interface"
		return 0
	}
}
return 1
	%}
	"router multicast pim-sm-global rp-address" = %{
set ip [cli_get_value $CLI_CUR_NODE "" "" "ip-address"]
if {$ip eq ""} {
	cli_set_errmsg "invalid ip"
	return 0
}
if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "ip-address" 0 $ip] > 1} {
	cli_set_errmsg "conflict value"
	return 0
}
return 1
	%}
	"router multicast interface" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if {$name eq "modem"} {
	cli_set_errmsg "router multicast interface can not be modem"
	return 0
}
set holdtime [cli_get_value $CLI_CUR_NODE "" "" "hello-holdtime"]
set interval [cli_get_value $CLI_CUR_NODE "" "" "hello-interval"]
if {$holdtime ne "" && $interval ne "" && $interval > $holdtime} {
	cli_set_errmsg "hello hold too low"
	return 0
}
return 1
	%}
	"router multicast interface join-group" = %{
set addr [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$addr eq ""} {
	cli_set_errmsg "not multicast addr"
	return 0
}
set iplist [split $addr .]
set ip [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
if {($ip & 0xff000000) == 0x7f000000 && ($ip & 0xf0000000) != 0xe0000000} {
	cli_set_errmsg "not multicast addr"
	return 0
}
return 1
	%}
	"router multicast interface igmp" = %{
set interval [cli_get_value $CLI_CUR_NODE "" "" "query-interval"]
set max_resp [cli_get_value $CLI_CUR_NODE "" "" "query-max-response-time"]
if {$max_resp eq ""} {set max_resp 10}
if {$interval && $interval <= $max_resp} {
	cli_set_errmsg "interval less than response"
	return 0
}
return 1
	%}

	"router ospf" = %{
set router_id [cli_get_value $CLI_CUR_NODE "" "" "router-id"]
if {$router_id eq "" || [scan $router_id "%d.%d.%d.%d" a b c d] != 4 || $a > 255 || $b > 255 || $c > 255 || $d > 255} {
	cli_set_errmsg "invalid ip"
	return 0
}
set dfl_info_rtmap [cli_get_value $CLI_CUR_NODE "" "" "default-information-route-map"]
if {$dfl_info_rtmap ne "" && [regexp {[^[[:alnum:]]]|\s} $dfl_info_rtmap] != 0} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"router ospf area range" = %{
if {[cli_get_value $CLI_CUR_NODE "" "" "substitute-status"] eq "enable"} {
	set sub [cli_get_value $CLI_CUR_NODE "" "" "substitute"]
	if {$sub eq ""} {
		cli_set_errmsg "invalid ip"
		return 0
	}
	if {[cli_get_value $CLI_CUR_NODE "" "" "prefix"] eq ""} {
		cli_set_errmsg "invalid ip"
		return 0
	}
}
return 1
	%}
	"router ospf area filter-list" = %{
set flist [cli_get_value $CLI_CUR_NODE "" "" "list"]
if {$flist eq "" || [regexp {[^[[:alnum:]]]|\s} $flist] != 0} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"router ospf area virtual-link" = %{
set peer [cli_get_value $CLI_CUR_NODE "" "" "peer"]
if {$peer eq "" || [scan $peer "%d.%d.%d.%d" a b c d] != 4 || $a > 255 || $b > 255 || $c > 255 || $d > 255} {
	cli_set_errmsg "invalid ip"
	return 0
}
set auth [cli_get_value $CLI_CUR_NODE "" "" "authentication"]
if {$auth eq "md5"} {
	namespace import global::ospf_md5key_valid
	set md5key [cli_get_value $CLI_CUR_NODE "" "" "md5-key"]
	if {$md5key eq ""} {
		cli_set_errmsg "Please input the md5-key"
		return 0
	}
	foreach {id md5} $md5key {
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
	}
}
if {$auth eq "text"} {
	set authkey [cli_get_value $CLI_CUR_NODE "" "" "authentication-key"]
	if {$authkey eq ""} {
		cli_set_errmsg "empty value"
		return 0
	}
}
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$name eq "" || [regexp {[^[[:alnum:]]]|\s} $name] != 0} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}
	"router ospf area" = %{
set id [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$id eq "" || [scan $id "%d.%d.%d.%d" a b c d] != 4 || $a > 255 || $b > 255 || $c > 255 || $d > 255} {
	cli_set_errmsg "invalid ip"
	return 0
}
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if {$type eq "nssa" || $type eq "stub"} {
	if {[cli_get_tbl_cnt $CLI_CUR_NODE "virtual-link"] > 0} {
		cli_set_errmsg "conflict value"
		return 0
	}
}
return 1
	%}
	"router ospf distribute-list" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "access-list"]
if {[regexp {[^[[:alnum:]]]|\s} $name] != 0} {
        cli_set_errmsg "invalid value"
        return 0
}
return 1
	%}
	"router ospf ospf-interface" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$name eq "" || [regexp {[^[[:alnum:]]]|\s} $name] != 0} {
	cli_set_errmsg "invalid value"
	return 0
}
set auth [cli_get_value $CLI_CUR_NODE "" "" "authentication"]
if {$auth eq "md5"} {
	namespace import global::ospf_md5key_check
	if { ![cli_ver_start 600 2] } {
		set md5key [cli_get_value $CLI_CUR_NODE "" "" "md5-key"]
		if {$md5key eq ""} {
			cli_set_errmsg "Please input the md5-key"
			return 0
		}
		foreach {id md5} $md5key {
			if { ![ospf_md5key_check $id $md5] } {
				return 0
			}
		}
	}
}
set interface [cli_get_value $CLI_CUR_NODE "" "" "interface"]
set interface [string trim $interface \"]
set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $interface ""]
if {$intf_node == 0} {
	cli_set_errmsg "invalid interface"
	return 0
} else {
    set intftype [cli_get_value $intf_node "" "" "type"]
	set network_type [cli_get_value $CLI_CUR_NODE "" "" "network-type"]
	if { [cli_ver_start 500 6] && $intftype eq "tunnel" } {
		if { $network_type eq "broadcast" || $network_type eq "non-broadcast" } {
			cli_set_errmsg "Network type must be point-to-* when selected interface ($interface) type is tunnel"
			return 0
		}
	}
}
set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
if {($ip ne "") && ($ip ne "0.0.0.0")} {
	if {![cli_is_match $intf_node 0 "" "ip" 0 "'*$ip*'"]} {
		if {![cli_is_match $intf_node 1 "secondaryip" "ip" 0 "'*$ip*'"]} {
			cli_set_errmsg "invalid ip"
			return 0
		}
	}
}
set node_list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach e $node_list {
	if { [cli_if_same_node $e $CLI_CUR_NODE] } {
		continue
	}
	set pip [cli_get_value $e "" "" "ip"]
	set pintf [cli_get_value $e "" "" "interface"]
	set pintf [string trim $pintf \"]
	if {($pip eq $ip) && ($pintf eq $interface)} {
		cli_set_errmsg "duplicate"
		return 0
	}
}
return 1
	%}
	"router ospf ospf-interface md5-keys" = %{
set id [cli_get_value $CLI_CUR_NODE "" "" ""]
set md5 [cli_get_value $CLI_CUR_NODE "" "" "key-string"]
namespace import global::ospf_md5key_check
if { ![ospf_md5key_check $id $md5] } {
	return 0
}
return 1
	%}
	"router ospf network" = %{
set area [cli_get_value $CLI_CUR_NODE "" "" "area"]
set prefix [cli_get_value $CLI_CUR_NODE "" "" "prefix"]
if {$area eq "" || [scan $area "%d.%d.%d.%d" a b c d] != 4 || $a > 255 || $b > 255 || $c > 255 || $d > 255} {
	cli_set_errmsg "entry not exist"
	return 0
}
set ospf_node [cli_get_parent $CLI_CUR_PARENT_NODE]
if {[cli_get_node $ospf_node "area" $area ""] == 0} {
	cli_set_errmsg "entry not exist"
	return 0
}
set network_list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach e $network_list {
	if { [cli_if_same_node $e $CLI_CUR_NODE] } {
		continue
	}
	set eprefix [cli_get_value $e "" "" "prefix"]
	if {$eprefix eq $prefix} {
		cli_set_errmsg "duplicate"
		return 0
	}
}
return 1
	%}
	"router ospf neighbor" = %{
set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
set neigh_list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach e $neigh_list {
	if { [cli_if_same_node $e $CLI_CUR_NODE] } {
		continue
	}
	set eip [cli_get_value $e "" "" "ip"]
	if {$eip eq $ip} {
		cli_set_errmsg "duplicate"
		return 0
	}
}
return 1
	%}
	"router ospf summary-address" = %{
set prefix [cli_get_value $CLI_CUR_NODE "" "" "prefix"]
if {$prefix eq ""} {
	cli_set_errmsg "invalid ip"
	return 0
}

set tok [string first "/" $prefix]
if {$tok > 0} {
	set ipaddr [string range $prefix 0 $tok-1]
	set mask [string range $prefix $tok+1 end]
        if {[string compare $ipaddr "0.0.0.0"] || $mask <= 0 || $mask > 32} {
                cli_set_errmsg "invalid ip"
                return 0
        }
} else {
        if {[string compare $prefix "0.0.0.0 0.0.0.0"] == 0} {
                cli_set_errmsg "invalid ip"
                return 0
        }
}
set addr_list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach e $addr_list {
	if { [cli_if_same_node $e $CLI_CUR_NODE] } {
		continue
	}
	set eprefix [cli_get_value $e "" "" "prefix"]
	if {$eprefix eq $prefix} {
		cli_set_errmsg "duplicate"
		return 0
	}
}
return 1
	%}
	"router ospf redistribute" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$name eq "" || [regexp {[^[[:alnum:]]]|\s} $name] != 0} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}

	"router policy" = %{
set protocol [cli_get_value $CLI_CUR_NODE "" "" "protocol"]
if {$protocol == 6 || $protocol == 17 || $protocol == 132} {
	set start_port [cli_get_value $CLI_CUR_NODE "" "" "start-port"]
	set end_port [cli_get_value $CLI_CUR_NODE "" "" "end-port"]
	if {$start_port ne "" && $end_port ne "" && $start_port > $end_port} {
		cli_set_errmsg "invalid port number"
		return 0
	}
}
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
set ofname [cli_get_value $CLI_CUR_NODE "" "" "output-device"]
set gw [cli_get_value $CLI_CUR_NODE "" "" "gateway"]
if { $action ne "deny" && ($gw eq "" || $gw eq "0.0.0.0") && $ofname eq "" } {
	cli_set_errmsg "Both gateway and output-device are null when action is not deny. Please assign at least one of them."
	return 0
}
return 1
	%}

	"router prefix-list" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$name eq "" || [regexp {[^[[:alnum:]]]|\s} $name] != 0} {
	cli_set_errmsg "invalid value"
	return 0
}
if {[cli_get_node $CLI_CUR_VDOM_NODE "router access-list" $name ""] != 0} {
	cli_set_errmsg "duplicate"
	return 0
}
return 1
	%}
	"router prefix-list rule" = %{
set prefix [cli_get_value $CLI_CUR_NODE "" "" "prefix"]
set ge [cli_get_value $CLI_CUR_NODE "" "" "ge"]
set le [cli_get_value $CLI_CUR_NODE "" "" "le"]
if {$prefix eq ""} {
	cli_set_errmsg "invalid ip"
	return 0
} elseif {$prefix ne "any"} {
	if {[scan $prefix "%d.%d.%d.%d %d.%d.%d.%d" a a a a m1 m2 m3 m4] != 8} {
		cli_set_errmsg "invalid ip"
		return 0
	}
	foreach e "$m1 $m2 $m3 $m4" {
		if {$e == 0} {continue}
		if {[expr ((~$e+1)&0xff) & (~$e&0xff)] != 0} {
			cli_set_errmsg "invalid mask"
			return 0
		}
	}
	if {$ge eq ""} {
		if {$le eq "0"} {
			cli_set_errmsg "beyond the boundary"
			return 0
		}
	} else {
		if {$le eq ""} {set le 0}
		set m [format "0x%x" [expr ~(($m1<<24)+($m2<<16)+($m3<<8)+$m4)]]
		set m [format "0x%x" [expr (0x00000000ffffffff & $m)]]
		for {set n 0} {$m > 0} {incr n} {
                     set m [expr int($m) >> 1]
		}
		set n [expr 32 - $n]
		if {$ge < 0 || $ge > 32 || $le < 0 || $le > 32 || ($ge > 0 && $ge <= $n) ||
			($ge > 0 && $le > 0 && $le < $ge)} {
			cli_set_errmsg "beyond the boundary"
			return 0
		}
	}
}
return 1
	%}

	"router route-map rule" = %{
set aspath [cli_get_value $CLI_CUR_NODE "" "" "as"]
foreach e $aspath {
	if {$e < 0 || $e > 65535} {
		cli_set_errmsg "invalid number"
		return 0
	}
}
set community [cli_get_value $CLI_CUR_NODE "" "" "set-community"]
set pref_comms {internet local-AS no-advertise no-export none}
set found 0
foreach e $community {
	if {[lsearch -exact $pref_comms $e] != -1} {
		continue
	}
	if {[string is digit $e]} {
		if {$e < 0 || $e > 65535} {
			set found 1
			break
		}
	} else {
		if {[scan $e "%d:%d" a b] != 2} {
			set found 1
			break
		}
		if {$a < 0 || $a > 65535 || $b < 0 || $b > 65535} {
			set found 1
			break
		}
	}
}
if {$found} {
	cli_set_errmsg "invalid value"
	return 0
}
set dr_hlife [cli_get_value $CLI_CUR_NODE "" "" "set-dampening-reachability-half-life"]
set dreuse [cli_get_value $CLI_CUR_NODE "" "" "set-dampening-reuse"]
if {$dreuse eq ""} {set dreuse 0}
set dsuppress [cli_get_value $CLI_CUR_NODE "" "" "set-dampening-suppress"]
if {$dsuppress eq ""} {set dsuppress 0}
set dmax_suppress [cli_get_value $CLI_CUR_NODE "" "" "set-dampening-max-suppress"]
if {$dmax_suppress eq ""} {set dmax_suppress 0}
set dunreach_hlife [cli_get_value $CLI_CUR_NODE "" "" "set-dampening-unreachability-half-life"]
if {$dunreach_hlife eq ""} {set dunreach_hlife 0}
if {$dr_hlife ne ""} {
	if {$dreuse} {
		if {!$dsuppress || !$dmax_suppress} {
			cli_set_errmsg "entry not exist"
			return 0
		}
	} elseif {$dsuppress || $dmax_suppress || $dunreach_hlife} {
			cli_set_errmsg "entry not exist"
			return 0
	}
} elseif {$dreuse || $dsuppress || $dmax_suppress || $dunreach_hlife} {
	cli_set_errmsg "entry not exist"
	return 0
}
set aggr_as [cli_get_value $CLI_CUR_NODE "" "" "set-aggregator-as"]
set aggr_ip [cli_get_value $CLI_CUR_NODE "" "" "set-aggregator-ip"]
if {$aggr_as ne "" && $aggr_as > 0 && $aggr_ip eq ""} {
	cli_set_errmsg "entry not exist"
	return 0
}
if {[scan $aggr_ip "%d.%d.%d.%d" a b c d] != 4 || $a > 255 || $b > 255 || $c > 255 || $d > 255} {
        cli_set_errmsg "invalid ip"
        return 0
}
return 1
	%}
	"router route-map" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$name eq "" || [regexp {[^[[:alnum:]]]|\s} $name] != 0} {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}

	"router static" = %{
proc address_allow_routing { node } {
	set allow_routing [cli_get_value $node "" "" "allow-routing"]
	if { $allow_routing eq "enable" } {
		set type [cli_get_value $node "" "" "type"]
		if { $type eq "ipmask" || $type eq "fqdn" || $type eq "interface-subnet" } {
			return 1
		}
	}
	return 0
}
proc addrgrp_allow_routing { vdom node } {
	set allow_routing [cli_get_value $node "" "" "allow-routing"]
	if { $allow_routing eq "enable" } {
		set member [cli_get_value $node "" "" "member"]
		foreach m $member {
			set address_node [cli_get_node $vdom "firewall address" $m ""]
			if { 0 != $address_node } {
				set allow [address_allow_routing $address_node]
				if { 0 == $allow } {
					return 0
				}
			} else {
				set addrgrp_node [cli_get_node $vdom "firewall addrgrp" $m ""]
				if { 0 != $addrgrp_node } {
					set allow [addrgrp_allow_routing $vdom $addrgrp_node]
					if { 0 == $allow } {
						return 0
					}
				}
			}
		}
		return 1
	}
	return 0
}
proc intf_route_vrf_get { route } {
	global CLI_CUR_VDOM_NODE
	global CLI_GLOBAL_NODE
	if { [cli_is_match $route 0 "" "blackhole" 0 "enable"] } {
		return [cli_get_value $route "" "" "vrf"]
	}
	set route_zones [cli_get_value $route "" "" "sdwan-zone"]
	if { [cli_branchpt_start 600 1614] } {
		set sdwan "sdwan"
	} else {
		set sdwan "virtual-wan-link"
	}
	set vwl_node [cli_get_node $CLI_CUR_VDOM_NODE "system $sdwan" "" ""]
	if { $vwl_node && $route_zones ne "" } {
		foreach route_zone $route_zones {
			set vwl_mbrs [cli_get_tbl_list $vwl_node "members"]
			if { $vwl_mbrs == 0 || ![llength $vwl_mbrs] } {
				return 0
			}
			foreach mbr $vwl_mbrs {
				set mbr_zone [cli_get_value $mbr "" "" "zone"]
				if { [cli_is_match $mbr 0 "" "zone" 0 $route_zone] } {
					set ifname [cli_get_value $mbr "" "" "interface"]
					set ifname [string trim $ifname \"]
					set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $ifname ""]
					if { $intfnode } {
						return [cli_get_value $intfnode "" "" "vrf"]
					}
				}
			}
		}
	}
	return 0
}
proc route4_zone_do_duplicated_check { route1 route2 } {
	set vrf1 [intf_route_vrf_get $route1]
	set vrf2 [intf_route_vrf_get $route2]
	if { $vrf1 eq $vrf2 } {
		return 0
	}
	return 1
}
proc route_zone_duplicated_check { route1 route2 } {
	set zone1 [cli_get_value $route1 "" "" "sdwan-zone"]
	set zone2 [cli_get_value $route2 "" "" "sdwan-zone"]
	if { $zone1 eq "" || $zone2 eq "" } {
		return [route4_zone_do_duplicated_check $route1 $route2]
	}
	set zone1 [split $zone1]
	set zone2 [split $zone2]
	foreach z1 $zone1 {
		foreach z2 $zone2 {
			if { $z1 eq $z2} {
				return 0
			}
		}
	}
	return 1
}
proc intf_not_match_vdom { device intflist cur_vdom_name } {
	foreach intf $intflist {
		set name [cli_get_value $intf "" "" "name"]
		set vdom [string map {\" ""} [cli_get_value $intf "" "" "vdom"]]
		if { $name eq $device } {
			if { $vdom ne $cur_vdom_name } {
				return 1
			} else {
				return 0
			}
		}
	}
	return 0
}

proc get_route_flag { route } {
	global CLI_GLOBAL_NODE
	set flag 0
	if { [cli_get_value $route "" "" "blackhole"] eq "enable" } {
		set flag [expr $flag | 1 << 0]
	}
	if { [cli_get_value $route "" "" "dynamic-gateway"] eq "enable" } {
		set flag [expr $flag | 1 << 1]
	}
	if { [cli_get_value $route "" "" "status"] eq "enable" } {
		set flag [expr $flag | 1 << 2]
	}
	if { [cli_get_value $route "" "" "link-monitor-exempt"] eq "enable" } {
		set flag [expr $flag | 1 << 3]
	}
	if { [cli_get_value $route "" "" "bfd"] eq "enable" } {
		set flag [expr $flag | 1 << 4]
	}
	set dev1 [cli_get_value $route "" "" "device"]
	if { $dev1 ne "" } {
		set intf [cli_get_node $CLI_GLOBAL_NODE "system interface" $dev1 ""]
		if { $intf != 0 && [cli_get_value $intf "" "" "type"] eq "tunnel" } {
			set flag [expr $flag | 1 << 5]
		}
	}
	return $flag
}

proc is_route_dst_same { r1 r2 } {
	set v1 [cli_get_value $r1 "" "" "dst"]
	set v2 [cli_get_value $r2 "" "" "dst"]
	if { $v1 ne $v2 } {
		return 0
	}
	set v1 [cli_get_value $r1 "" "" "src"]
	set v2 [cli_get_value $r2 "" "" "src"]
	if { $v1 ne $v2 } {
		return 0
	}
	set v1 [cli_get_value $r1 "" "" "dstaddr"]
	set v2 [cli_get_value $r2 "" "" "dstaddr"]
	if { $v1 ne $v2 } {
		return 0
	}
	set v1 [cli_get_value $r1 "" "" "internet-service"]
	set v2 [cli_get_value $r2 "" "" "internet-service"]
	if { $v1 ne $v2 } {
		return 0
	}
	set v1 [cli_get_value $r1 "" "" "internet-service-name"]
	set v2 [cli_get_value $r2 "" "" "internet-service-name"]
	if { $v1 ne $v2 } {
		return 0
	}

	return 1
}

set dst [cli_get_value $CLI_CUR_NODE "" "" "dst"]
set gw [cli_get_value $CLI_CUR_NODE "" "" "gateway"]
set blackhole [cli_get_value $CLI_CUR_NODE "" "" "blackhole"]
if { [cli_branchpt_start 600 1614] } {
	set sdwan "sdwan"
} else {
	set sdwan "virtual-wan-link"
}
set dyn_gw [cli_get_value $CLI_CUR_NODE "" "" "dynamic-gateway"]
set device [cli_get_value $CLI_CUR_NODE "" "" "device"]
set intserv [cli_get_value $CLI_CUR_NODE "" "" "internet-service"]
set intserv_cust [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom"]
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
set vrf [cli_get_value $CLI_CUR_NODE "" "" "vrf"]
if { [cli_branchpt_start 700 133] } {
	set vwan_zone [cli_get_value $CLI_CUR_NODE "" "" $sdwan-zone]
	if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "nat" && $blackhole eq "disable" && $vwan_zone eq "" } {
		if {$device eq ""} {
			cli_set_errmsg "device can not be empty."
			return 0
		}
	}
} else {
	set vwan [cli_get_value $CLI_CUR_NODE "" "" $sdwan]
	if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "nat" && $device eq "" && $blackhole eq "disable" && $vwan eq "disable" } {
		cli_set_errmsg "device can not be empty."
		return 0
	}
}
if { [intf_not_match_vdom [string map {\" ""} $device] [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"] $CLI_CUR_VDOM_NAME] } {
	cli_set_errmsg "interface $device does not belong to current vdom $CLI_CUR_VDOM_NAME."
	return 0
}
if {$dst ne ""} {
	set iplist [split $dst]
	set iplist [split [lindex $iplist 0] .]
	set ip [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
	if {($ip & 0xff000000) == 0x7f000000 && ($ip & 0xf0000000) != 0xe0000000} {
		cli_set_errmsg "invalid ip"
		return 0
	}
}

if { $CLI_IS_RESYNC != 1 } {
	set rt_nodes [cli_get_tbl_list $CLI_CUR_VDOM_NODE "router static"]
	foreach e $rt_nodes {
		if { [cli_if_same_node $e $CLI_CUR_NODE] } {
			continue
		}


		if { [cli_ver_start 700 0] } {
			set sdwan_zone [cli_get_value $CLI_CUR_NODE "" "" "sdwan-zone"]
			set esdwan_zone [cli_get_value $e "" "" "sdwan-zone"]
			if { $sdwan_zone ne "" || $esdwan_zone ne "" } {
				if { ![is_route_dst_same $CLI_CUR_NODE $e] } {
					continue
				}
				set flag1 [get_route_flag $CLI_CUR_NODE]
				set flag2 [get_route_flag $e]
				if { $flag1 ne $flag2 } {
					continue
				}
				if { [route_zone_duplicated_check $CLI_CUR_NODE $e ] } {
					continue
				}
				set n1 [cli_get_value $CLI_CUR_NODE "" "" "seq-num"]
				set n2 [cli_get_value $e "" "" "seq-num"]
				cli_set_errmsg "You cannot have duplicated routes ($n1 and $n2) on SD-WAN and non-SD-WAN interfaces"
				return 0
			}
		}

		set edst [cli_get_value $e "" "" "dst"]
		set edstaddr [cli_get_value $e "" "" "dstaddr"]
		set eblackhole [cli_get_value $e "" "" "blackhole"]
		set edyn_gw [cli_get_value $e "" "" "dynamic-gateway"]
		if {$edst ne $dst || $eblackhole ne $blackhole || $edyn_gw ne $dyn_gw || $edstaddr ne $dstaddr } {
			continue
		}
		if {$eblackhole ne "enable"} {
			set eintserv_cust [cli_get_value $e "" "" "internet-service-custom"]
			set edstaddr [cli_get_value $e "" "" "dstaddr"]
			set eintserv [cli_get_value $e "" "" "internet-service"]
			set egw [cli_get_value $e "" "" "gateway"]
			set edevice [cli_get_value $e "" "" "device"]
			if {$eintserv_cust ne $intserv_cust || $edstaddr ne $dstaddr || $eintserv ne $intserv || $egw ne $gw || $edevice ne $device} {
				continue
			}
		} else {
			set evrf [cli_get_value $e "" "" "vrf"]
			if { $evrf ne $vrf } {
				continue
			}
		}
		set seq_num [cli_get_value $e "" "" "seq-num"]
		cli_set_errmsg "entry cannot be created, duplicate of static route $seq_num"
		return 0
	}
}
if { [cli_ver_start 500 4] } {
	set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
	if { $dstaddr ne "" } {
		set r [cli_sync_reference $CLI_CUR_NODE "" "" "dstaddr"]
		if { $r != 0 } {
			cli_set_errmsg "dstaddr \"$dstaddr\" can not be copied from adom."
			return 0
		}
		set address_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $dstaddr ""]
		set addrgrp_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp" $dstaddr ""]
		if { 0 != $address_node } {
			set allow [address_allow_routing $address_node]
			if { 0 == $allow } {
				cli_set_errmsg "dstaddr \"$dstaddr\" does not allow routing."
				return 0
			}
		} elseif { 0 != $addrgrp_node } {
			set allow [addrgrp_allow_routing $CLI_CUR_VDOM_NODE $addrgrp_node]
			if { 0 == $allow } {
				cli_set_errmsg "dstaddr \"$dstaddr\" does not allow routing."
				return 0
			}
		} else {
			cli_set_errmsg "dstaddr \"$dstaddr\" is invalid."
			return 0
		}
	}
}
if {[cli_obj_support "router static" $sdwan] &&
		[cli_is_match $CLI_CUR_NODE 0 "" $sdwan 0 "enable"]} {
	if { ![cli_branchpt_start 600 1614] } {
		set vwl_node [cli_get_node $CLI_CUR_VDOM_NODE "system $sdwan" "" ""]
		if { $vwl_node } {
			set vwl_mbrs [cli_get_tbl_list $vwl_node "members"]
			if { $vwl_mbrs == 0 || ![llength $vwl_mbrs] } {
				cli_set_errmsg "Please enable $sdwan and add at least one member."
				return 0
			}
		}
	}
	if {[cli_is_match $CLI_CUR_VDOM_NODE 1 "system $sdwan" "status" 0 "disable"]} {
		cli_set_errmsg "Please enable $sdwan."
		return 0
	}
	if { $dyn_gw eq "enable" } {
		cli_set_errmsg "Can not enable dynamic_gateway if device is $sdwan."
		return 0
	}
}
set ifname [cli_get_value $CLI_CUR_NODE "" "" "device"]
set ifname [string trim $ifname \"]
set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $ifname ""]
if { $intfnode != 0 && [cli_get_value $intfnode "" "" "mode"] eq "static" } {
	set ip [cli_get_value $intfnode "" "" "ip"]
	if { [string first " " $ip] != -1 } {
		set ip [lindex [split $ip " "] 0]
	}
	if { $ip eq $gw && $ip ne "0.0.0.0" } {
		cli_set_errmsg "Device \"$ifname\" ip is the same as gateway address"
		return 0
	}
}
return 1
	%}

	"router static6" = %{
proc intf_not_match_vdom { device intflist cur_vdom_name } {
	foreach intf $intflist {
		set name [cli_get_value $intf "" "" "name"]
		set vdom [string map {\" ""} [cli_get_value $intf "" "" "vdom"]]
		if { $name eq $device } {
			if { $vdom ne $cur_vdom_name } {
				return 1
			} else {
				return 0
			}
		}
	}
	return 0
}
set dst [cli_get_value $CLI_CUR_NODE "" "" "dst"]
set gw [cli_get_value $CLI_CUR_NODE "" "" "gateway"]
set blackhole [cli_get_value $CLI_CUR_NODE "" "" "blackhole"]
if { [cli_branchpt_start 600 1614] } {
	set sdwan "sdwan"
} else {
	set sdwan "virtual-wan-link"
}
set device [cli_get_value $CLI_CUR_NODE "" "" "device"]
if { [cli_branchpt_start 700 133] } {
	set vwan_zone [cli_get_value $CLI_CUR_NODE "" "" $sdwan-zone]
	if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "nat" && $blackhole eq "disable" && $vwan_zone eq "" } {
		if {$device eq ""} {
			cli_set_errmsg "device can not be empty."
			return 0
		}
	}
} else {
	set vwan [cli_get_value $CLI_CUR_NODE "" "" $sdwan]
	if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "nat" && $device eq "" && $blackhole eq "disable" && $vwan eq "disable" } {
		cli_set_errmsg "device can not be empty."
		return 0
	}
}
if { [intf_not_match_vdom [string map {\" ""} $device] [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"] $CLI_CUR_VDOM_NAME] } {
	cli_set_errmsg "interface $device does not belong to current vdom $CLI_CUR_VDOM_NAME."
	return 0
}
return 1
	%}

        "dlp rule" = %{
set field [cli_get_value $CLI_CUR_NODE "" "" "field"]
switch $field {
        "subject" - "sender" - "receiver" - "url" -
        "cookie-content" - "cgi-parameters" - "hostname" -
        "file-text" - "attachment-text" {
                set regexp [cli_get_value $CLI_CUR_NODE "" "" "regexp"]
                if {$regexp eq ""} {
                        cli_set_errmsg "empty value"
                        return 0
                }
        }
        "header" {
                set hpattern [cli_get_value $CLI_CUR_NODE "" "" "http-header-pattern"]
                set hfield [cli_get_value $CLI_CUR_NODE "" "" "http-header-field"]
                if {$hpattern eq "" || $hfield eq ""} {
                        cli_set_errmsg "empty value"
                        return 0
                }
        }
        "file-pattern" {
                set fpattern [cli_get_value $CLI_CUR_NODE "" "" "file-pattern"]
                set fpattern [string trim $fpattern \"]
                if {$fpattern eq ""} {
                        cli_set_errmsg "'file-pattern' value is empty"
                        return 0
                }
                set fpl [string length $fpattern]
                if {$fpl % 4} {
                        cli_set_errmsg "'file-pattern' value is an invalid base64 string"
                        return 0
                }
                set base64set "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                for {set i 0} {$i < $fpl} {incr i} {
                        set r [string first [string index $fpattern $i] $base64set]
                        if { $r == -1 } {
                                cli_set_errmsg "'file-pattern' has invalid base64 character(s)"
                                return 0
                        }
                }
        }
        "user" {
                set string [cli_get_value $CLI_CUR_NODE "" "" "string"]
                if {$string eq ""} {
                        cli_set_errmsg "empty value"
                        return 0;
                }
        }
}
return 1;
        %}

	"dlp sensor filter" = %{
if { [cli_ver_start 500 0] } {
	set ftype [cli_get_value $CLI_CUR_NODE "" "" "type"]
	if { $ftype eq "message" } {
		set f_by [cli_get_value $CLI_CUR_NODE "" "" "filter-by"]
		if { ($f_by ne "ssn") && ($f_by ne "credit-card") && ($f_by ne "regexp")} {
			cli_set_errmsg "invalid value"
			return 0
		}
	}
        set p [cli_get_value $CLI_CUR_NODE "" "" "proto"]
        if { $p eq "" } {
                cli_set_errmsg "Error: protocol not set"
                return 0
        }
}
set filter_type [cli_get_value $CLI_CUR_NODE "" "" "filter-type"]
if {$filter_type ne "advanced-rule"} {
	return 1
}
set archive [cli_get_value $CLI_CUR_NODE "" "" "archive"]
set rule_name [cli_get_value $CLI_CUR_NODE "" "" "rule-name"]
set dlprule [cli_get_node $CLI_CUR_VDOM_NODE "dlp rule" $rule_name ""]
if { $dlprule == 0 } {
	cli_set_errmsg "invalid value"
	return 0
}
return 1
	%}

	"dlp sensor rule" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
if { ($action eq "ban") || ($action eq "ban-sender") ||
     ($action eq "quarantine-ip") || ($action eq "quarantine-port") } {
	set expiry [cli_get_value $CLI_CUR_NODE "" "" "expiry"]
	if {"$expiry" == "indefinite" || "$expiry" == ""} {
		return 1
	}
	set ed [string first "d" $expiry]
	set eh [string first "h" $expiry]
	set em [string first "m" $expiry]
	if { ($ed == -1 && $eh == -1 && $em == -1) ||
	     ($ed != -1 && ([scan $expiry {"%dd"} day] != 1 || $day < 0)) ||
	     ($eh != -1 && ([scan $expiry {"%dh"} hour] != 1 || $hour > 23 || $hour < 0)) ||
	     ($em != -1 && ([scan $expiry {"%dm"} min] != 1 || $min > 59 || $min < 0)) } {
		cli_set_errmsg "invalid date/time"
		return 0
	}
}
return 1;
	%}

	"system resource-limits" = %{
set list {
	{"ipsec-phase1" "vpn ipsec phase1"}
	{"ipsec-phase2" "vpn ipsec phase2"}
	{"firewall-policy" "firewall policy"}
	{"firewall-profile" "firewall profile"}
	{"firewall-address" "firewall address"}
	{"firewall-addrgrp" "firewall addrgrp"}
	{"custom-service" "firewall service custom"}
	{"service-group" "firewall service group"}
	{"onetime-schedule" "firewall schedule onetime"}
	{"recurring-schedule" "firewall schedule recurring"}
	{"user" "user local"}
	{"user-group" "user group"}
}

set prop_list [cli_get_tbl_list $CLI_GLOBAL_NODE "system vdom-property"]
foreach e $list {
	set limit [cli_get_value $CLI_CUR_NODE "" "" [lindex $e 0]]
	if {$limit > 0} {
		set cnt [cli_get_tbl_size [lindex $e 1]]
		if {$limit < $cnt} {
			cli_set_errmsg "max entry"
			return 0;
		}
		set total 0
		foreach p $prop_list {
			set cnt [cli_get_value $p "" "" [lindex $e 0]]
			set cnt [string trim $cnt \"]
			set cnt [split $cnt]
			set maxu [lindex $cnt 0]
			set gu [lindex $cnt 1]
			if {$maxu > $limit} {
				cli_set_errmsg "max entry"
				return 0;
			}
			incr total $gu
			if {$total > $limit} {
				cli_set_errmsg "max entry"
				return 0;
			}
		}
	}
}
cli_on_rlimit_change
return 1;
	%}

	"system vdom-property" = %{
set list {
	{"ipsec-phase1" "vpn ipsec phase1"}
	{"ipsec-phase2" "vpn ipsec phase2"}
	{"firewall-policy" "firewall policy"}
	{"firewall-profile" "firewall profile"}
	{"firewall-address" "firewall address"}
	{"firewall-addrgrp" "firewall addrgrp"}
	{"custom-service" "firewall service custom"}
	{"service-group" "firewall service group"}
	{"onetime-schedule" "firewall schedule onetime"}
	{"recurring-schedule" "firewall schedule recurring"}
	{"user" "user local"}
	{"user-group" "user group"}
}

set vdom_name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set vdom_node [cli_get_vdom_node $vdom_name]
set prop_list [cli_get_tbl_list $CLI_GLOBAL_NODE "system vdom-property"]
foreach e $list {
	set upperb [cli_get_value $CLI_GLOBAL_NODE "system resource-limits" "" [lindex $e 0]]
	set cnt [cli_get_value $CLI_CUR_NODE "" "" [lindex $e 0]]
	set cnt [string trim $cnt \"]
	set cnt [split $cnt]
	set limit [lindex $cnt 0]
	set gu [lindex $cnt 1]
	set mysize [cli_get_tbl_size $vdom_node 0 [lindex $e 1]]
	if {$limit > 0 && $limit < $mysize} {
		cli_set_errmsg "max entry"
		return 0;
	}
	if {$upperb != 0 && $limit > $upperb} {
		cli_set_errmsg "max entry"
		return 0;
	}
	if {$gu > 0 && $upperb > 0} {
		set real [cli_get_tbl_size [lindex $e 1]]
		if {$real + $gu - $mysize > $upperb} {
			cli_set_errmsg "max entry"
			return 0;
		}
		set total 0
		foreach p $prop_list {
			set cnt [cli_get_value $p "" "" [lindex $e 0]]
			set cnt [string trim $cnt \"]
			set cnt [lindex [split $cnt] 1]
			incr total $cnt
			if {$total > $upperb} {
				cli_set_errmsg "max entry"
				return 0;
			}
		}
	}
}
cli_on_rlimit_change
return 1;
	%}

        "log syslogd setting" = %{
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
if { $status eq "enable" } {
        namespace import global::check_hostname
        set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
        set port [cli_get_value $CLI_CUR_NODE "" "" "port"]
        if {$server eq "" || $server eq "\"0.0.0.0\"" || $port eq "" || $port eq "0"} {
                cli_set_errmsg "Syslog server/port can't be empty"
                return 0
        }
        if { [check_hostname [string trim $server \"]] } {
                cli_set_errmsg "Invalid syslog server"
                return 0
        }
}
return 1
        %}

        "log syslogd2 setting" = %{
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
if { $status eq "enable" } {
        namespace import global::check_hostname
        set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
        set port [cli_get_value $CLI_CUR_NODE "" "" "port"]
        if {$server eq "" || $server eq "\"0.0.0.0\"" || $port eq "" || $port eq "0"} {
                cli_set_errmsg "Syslog server/port can't be empty"
                return 0
        }
        if { [check_hostname [string trim $server \"]] } {
                cli_set_errmsg "Invalid syslog server"
                return 0
        }
}
return 1
        %}

        "log syslogd3 setting" = %{
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
if { $status eq "enable" } {
        namespace import global::check_hostname
        set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
        set port [cli_get_value $CLI_CUR_NODE "" "" "port"]
        if {$server eq "" || $server eq "\"0.0.0.0\"" || $port eq "" || $port eq "0"} {
                cli_set_errmsg "Syslog server/port can't be empty"
                return 0
        }
        if { [check_hostname [string trim $server \"]] } {
                cli_set_errmsg "Invalid syslog server"
                return 0
        }
}
return 1
        %}
	"wanopt webcache cache-exemption-list" = %{
set id [cli_get_value $CLI_CUR_NODE "" "" ""]
set url [cli_get_value $CLI_CUR_NODE "" "" "url-pattern"]
if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "url-pattern" 0 $url] > 1} {
	cli_set_errmsg "duplicate"
	return 0
}
return 1
	%}

	"system sdn-connector" = %{
set ctype [cli_get_value $CLI_CUR_NODE "" "" "type"]
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { [cli_ver_start 600 0] } {
	set server_attrname "server"
	if { $ctype eq "aci" || $ctype eq "nuage" } {
		if { [cli_branchpt_start 700 259] } {
			set server_attrname "server-list"
		} elseif { ![cli_ver_start 700 0] && [cli_branchpt_start 600 1945] } {
			set server_attrname "server-list"
		}
	}
} else {
	set server_attrname "server-ip"
}
if { $ctype eq "" } {
	cli_set_errmsg "sdn connector type must be set"
	return 0
} else {
	if { $ctype ne "aws" && $ctype ne "azure" && $ctype ne "oci" && $ctype ne "gcp" && $ctype ne "kubernetes" && $ctype ne "acs" && $ctype ne "alicloud" && $ctype ne "ibm"} {
		set username [cli_get_value $CLI_CUR_NODE "" "" "username"]
		if { $username eq "" } {
			cli_set_errmsg "Attribute username must be set"
			return 0
		}
		set ip [cli_get_value $CLI_CUR_NODE "" "" $server_attrname]
		if { $ip eq "" } {
			if { [cli_ver_start 600 0] } {
				cli_set_errmsg "Attribute $server_attrname must be set"
				return 0
			}
		} elseif { $server_attrname eq "server" || $server_attrname eq "server-ip" } {
			if { $ctype ne "openstack" && $ctype ne "vmware" && $ctype ne "aci-direct" && $ctype ne "nsx" } {
				#(![string match {http://*} $ip] && ![string match {https://*} $ip])
				if { [scan $ip "%d.%d.%d.%d" a1 a2 a3 a4] != 4 || ($a1 == 127 || ($a1 > 223 && $a1 < 240)) } {
						cli_set_errmsg "Invalid server ip"
						return 0
				}
			}
		}
		set pwd [cli_get_value $CLI_CUR_NODE "" "" "password"]
		if { $pwd eq "" } {
			cli_set_errmsg "Attribute password must be set"
			return 0
		}
	}

	if { $ctype eq "acs" || $ctype eq "alicloud" } {
		set ak [cli_get_value $CLI_CUR_NODE "" "" "access-key"]
		set sk [cli_get_value $CLI_CUR_NODE "" "" "secret-key"]
		set region [cli_get_value $CLI_CUR_NODE "" "" "region"]
		if { $ak eq "" } {
			cli_set_errmsg "Access key must be set"
			return 0
		}
		if { $sk eq "" } {
			cli_set_errmsg "Secret key must be set"
			return 0
		}
		if { $region eq "" } {
			cli_set_errmsg "Region must be set"
			return 0
		}
	}
	set use_iam [cli_get_value $CLI_CUR_NODE "" "" "use-metadata-iam"]
	if { $ctype eq "aws" && $use_iam ne "enable" } {
		set ak [cli_get_value $CLI_CUR_NODE "" "" "access-key"]
		set sk [cli_get_value $CLI_CUR_NODE "" "" "secret-key"]
		set region [cli_get_value $CLI_CUR_NODE "" "" "region"]
		if { $ak eq "" } {
			cli_set_errmsg "Access key must be set"
			return 0
		}
		if { $sk eq "" } {
			cli_set_errmsg "Secret key must be set"
			return 0
		}
		if { $region eq "" } {
			cli_set_errmsg "Region must be set"
			return 0
		}
	}
	if { $ctype eq "gcp" && $use_iam ne "enable" } {
		if { ![cli_branchpt_start 600 1898] } {
			set project [cli_get_value $CLI_CUR_NODE "" "" "gcp-project"]
			if { $project eq "" } {
				cli_set_errmsg "GCP project name must be set"
				return 0
			}
		}
		set account [cli_get_value $CLI_CUR_NODE "" "" "service-account"]
		set pk [cli_get_value $CLI_CUR_NODE "" "" "private-key"]
		if { $account eq "" } {
			cli_set_errmsg "GCP service account email must be set"
			return 0
		}
		if { $pk eq "" } {
			cli_set_errmsg "Private key must be set"
			return 0
		}
	}
	if { $ctype eq "azure" && $use_iam ne "enable" } {
		set tenant_id [cli_get_value $CLI_CUR_NODE "" "" "tenant-id"]
		set client_id [cli_get_value $CLI_CUR_NODE "" "" "client-id"]
		set client_secret [cli_get_value $CLI_CUR_NODE "" "" "client-secret"]
		if { $tenant_id eq "" } {
			cli_set_errmsg "Azure tenant-id must be set"
			return 0
		}
		if { $client_id eq "" } {
			cli_set_errmsg "Azure client-id must be set"
			return 0
		}
		if { $client_secret eq "" } {
			cli_set_errmsg "Azure client-secret must be set"
			return 0
		}
	}
	if { $ctype eq "oci" && $use_iam ne "enable" } {
		set oci_region [cli_get_value $CLI_CUR_NODE "" "" "oci-region"]
		if { $oci_region eq "" } {
			cli_set_errmsg "OCI oci-region must be set"
			return 0
		}
	}
	set nodelist [cli_get_tbl_list $CLI_CUR_PARENT_NODE "system sdn-connector"]
	foreach n $nodelist {
		set n1 [cli_get_value $n "" "" "name"]
		set t1 [cli_get_value $n "" "" "type"]
		if { $ctype eq "kubernetes" } {
			set ip [cli_get_value $CLI_CUR_NODE "" "" "server"]
			if { $ip eq "" } {
				cli_set_errmsg "Attribute server must be set for Kubernetes Service"
				return 0
			}
			set token [cli_get_value $CLI_CUR_NODE "" "" "secret-token"]
			if { $token eq "" } {
				cli_set_errmsg "Attribute secret-token must be set for Kubernetes Service"
				return 0
			}
		}
		if { $ctype eq $t1 } {
			if { $ctype eq "aci" || $ctype eq "nuage" } {
				if { $name ne $n1 } {
					set ip [cli_get_value $CLI_CUR_NODE "" "" $server_attrname]
					set ip1 [cli_get_value $n "" "" $server_attrname]
					if { $ip eq $ip1 } {
						set svrport [cli_get_value $CLI_CUR_NODE "" "" "server-port"]
						set svrport1 [cli_get_value $n "" "" "server-port"]
						if { $svrport eq $svrport1 || $svrport1 == 0 || $svrport1 eq "" } {
							cli_set_errmsg "Duplicated entry disallowed: server-list duplicated."
							return 0
						}
					}
				} elseif { ![cli_ver_start 600 2] } {
					cli_set_errmsg "more than one $ctype sdn connectors"
					return 0
				}
			}
		}
  	}
}

if { $ctype eq "nsx" && [cli_has_feature "f_netx_svm"] } {
	set pwd [cli_get_value $CLI_CUR_NODE "" "" "rest-password"]
	if { [string compare $pwd [cli_get_defvalue $CLI_CUR_NODE_NAME "rest-password"] ] == 0 } {
		cli_set_errmsg "REST API password must be set"
		return 0
	}
}
if { $ctype eq "openstack" || $ctype eq "kubernetes" || $ctype eq "vmware" || $ctype eq "nsx" || $ctype eq "nutanix" } {
	set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
	if { $server eq "" } {
		cli_set_errmsg "server must be set for $ctype connector"
		return 0
	}
}
if { $ctype eq "aci" || $ctype eq "nuage" } {
	set server_list [cli_get_value $CLI_CUR_NODE "" "" "server-list"]
	set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
	if { $server eq "" && $server_list eq "" } {
		cli_set_errmsg "server/server-list must be set for $ctype connector"
		return 0
	}
}
return 1
%}
	"system sdn-connector update-interval" = %{
set val [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $val == 0 || ($val >= 30 && $val <= 3600) } {
	return 1
}
cli_set_errmsg "update-interval must be an integer value <0> or from <30> to <3600> (0 means disabled, default = <60>)"
return 0
	%}
	"wireless-controller vap" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ![cli_ver_start 600 0] } {
	for {set i 0} {$i < [string length $name]} {incr i} {
		set char [string index $name $i]
		if {![regexp {[a-zA-Z0-9[:space:]._-]} $char]} {
				cli_set_errmsg "illegal name: $name"
				return 0
		}
	}
}
if { ![cli_ver_start 600 2] } {
	set vdom [cli_get_value $CLI_CUR_NODE "" "" "vdom"]
	set vdom [string trim $vdom \"]
	if { $vdom eq "" } {
		cli_set_errmsg "Error: vdom value not exist"
		return 0
	}
}

if { [cli_ver_start 600 2] } {
	set ssid [cli_get_value $CLI_CUR_NODE "" "" "ssid"]
	set ov_ssid $ssid
	if { $CLI_ACT eq "edit" } {
		set ov_ssid [cli_get_org_value $CLI_CUR_NODE "" "" "ssid"]
	}
	if { $CLI_ACT eq "add" || $ssid ne $ov_ssid } {
		set nodelist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "wireless-controller vap"]
		foreach e $nodelist {
			if { !$e } { continue }
			if { [cli_if_same_node $e $CLI_CUR_NODE] } {
				continue
			}
			set id [cli_get_value $e "" "" "ssid"]
			if { $ssid eq $id } {
				set vap_name [cli_get_value $e "" "" "name"]
				cli_set_errmsg "ssid $ssid is used by vap, $vap_name, in same vdom"
				return 0
			}
		}
	}
}

if { ![cli_ver_start 600 2] && $CLI_ACT ne "add"} {
	set ovdom [cli_get_org_value $CLI_CUR_NODE "" "" "vdom"]
	set ovdom [string trim $ovdom \"]
	if {$ovdom ne "" && $vdom ne "" && $ovdom ne $vdom} {
		set intf [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
		if { $intf } {
			if { [cli_ver_start 500 0] } {
				cli_set_errmsg "VDOM cannot be changed after interface is created."
				return 0
			} else {
				if { [cli_is_referenced $intf $ovdom] } {
					cli_set_errmsg "system interface $name is in use"
					return 0
				}
			}
		}
	}
}

# TOMMY: global object using vdom object, the datasrc will not exist during commit check
# set pmog [cli_get_value $CLI_CUR_NODE "" "" "portal-message-override-group"]
# if { $pmog ne "" } {
# 	set vnode [cli_get_vdom_node $vdom]
# 	if { $vnode eq 0 } {
# 		cli_set_errmsg "Error: vdom $vdom not exist."
# 		return 0
# 	}
# 	set rmsg [cli_get_node $vnode "system replacemsg-group" $pmog ""]
# 	if { $rmsg eq 0 } {
# 		cli_set_errmsg "Error: replacemsg-group $pmog not exist."
# 		return 0
# 	}
# 	set rmgt [cli_get_value $rmsg "" "" "group-type"]
# 	if { $rmgt ne "captive-portal"} {
# 		cli_set_errmsg "Error: replacemsg-group $pmog not for captive-portal authentication."
# 		return 0
# 	}
# }
# set sec [cli_get_value $CLI_CUR_NODE "" "" "security"]
# if { $sec eq "wpa-enterprise" || $sec eq "wpa-only-enterprise" || $sec eq "wpa2-only-enterprise" } {
# 	set auth [cli_get_value $CLI_CUR_NODE "" "" "auth"]
#	if { $auth eq "usergroup" } {
#		set ug [cli_get_value $CLI_CUR_NODE "" "" "usergroup"]
#		if { $ug eq "" } {
#			cli_set_errmsg "Usergroup is empty. Must be configured for auth type usergroup."
#			return 0
#		}
#	}
# }
return 1
	%}
        "firewall shaper traffic-shaper diffservcode" = %{
set code [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
if {[regexp {^[01]{1,6}$} $code] == 0} {
	cli_set_errmsg "Traffic shaper: DSCP value must be 6 bits binary, range 000000-111111"
	return 0
}
return 1
    %}
        "firewall shaper traffic-shaper bandwidth-unit" = %{
if { [string match "*override*" [cli_get_clisrc]] } { return 1 }
set unit [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
if { ![cli_has_feature "f_x86_64"] && $unit ne "kbps" } {
	cli_set_errmsg "Traffic shaper: bandwidth-unit (default-kbps) cannot be set when device is non-64 bit"
	return 0
}
return 1
    %}
        "firewall shaper per-ip-shaper bandwidth-unit" = %{
if { [string match "*override*" [cli_get_clisrc]] } { return 1 }
set unit [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
if { ![cli_has_feature "f_x86_64"] && $unit ne "kbps" } {
	cli_set_errmsg "Per-ip shaper: bandwidth-unit (default-kbps) cannot be set when device is non-64 bit"
	return 0
}
return 1
     %}

        "firewall shaper per-ip-shaper diffservcode-forward" = %{
set code [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
if {[regexp {^[01]{1,6}$} $code] == 0} {
	cli_set_errmsg "Per-ip shaper: DSCP value must be 6 bits binary, range 000000-111111"
	return 0
}
return 1
	%}
        "firewall shaper per-ip-shaper diffservcode-rev" = %{
set code [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
if {[regexp {^[01]{1,6}$} $code] == 0} {
	cli_set_errmsg "Per-ip shaper: DSCP value must be 6 bits binary, range 000000-111111"
	return 0
}
return 1
	%}
        "vpn ssl web virtual-desktop-app-list apps md5s" = %{
set md5s [cli_get_value $CLI_CUR_NODE "" "" ""]
set md5s [string trim $md5s \"]
if { $md5s eq "" } {
	return 1
}
if { [string length $md5s] != 32 } {
	cli_set_errmsg "Invalid length, md5s size mustbe 32 bytes"
	return 0
}
if {[regexp {^[0123456789abcdefABCDEF]{1,32}$} $md5s] == 0} {
	cli_set_errmsg "md5s mustbe Hex string of MD5 checksum"
	return 0
}
return 1
        %}
        "vpn ssl web host-check-software check-item-list md5s" = %{
set md5s [cli_get_value $CLI_CUR_NODE "" "" ""]
set md5s [string trim $md5s \"]
if { $md5s eq "" } {
	return 1
}
if { [string length $md5s] != 32 } {
	cli_set_errmsg "Invalid length, md5s size mustbe 32 bytes"
	return 0
}
if {[regexp {^[0123456789abcdefABCDEF]{1,32}$} $md5s] == 0} {
	cli_set_errmsg "md5s mustbe Hex string of MD5 checksum"
	return 0
}
return 1
        %}
        "system replacemsg-image" = %{
set base64 [cli_get_value $CLI_CUR_NODE "" "" "image-base64"]
set base64 [string trim $base64 \"]
if { $base64 eq "" || $base64 eq "''" } {
        return 1
}
set type [cli_get_value $CLI_CUR_NODE "" "" "image-type"]
set list {
        {"gif" "R0lGO"}
        {"tiff" "TU0AK"}
        {"tiff" "SUkqA"}
        {"jpg" "/9j/4"}
        {"png" "iVBORw0K"}
}
set ctype "n/a"
foreach e $list {
        set t [lindex $e 0]
        set c [lindex $e 1]
        if { [string compare -length [string length $c] $base64 $c] == 0 } {
                set ctype $t
                break;
        }
}
if { $ctype ne $type } {
        cli_set_errmsg "Error: Selected image type ($type) does not match the image data format ($ctype)."
        return 0
}
return 1
        %}
        "wireless-controller setting country" = %{
set new [cli_get_value $CLI_CUR_NODE "" "" ""]
set region [cli_get_devinfo "region"]
if { $region ne "" } {
        set opts [cli_get_wl_country "options" $region]
        set found 0
        foreach opt $opts {
                if { $opt eq $new } {
                        set found 1
                        break
                }
        }
        if { $found ne 1 } {
                cli_set_errmsg "option \"$new\" unsupported under current license"
                return 0
        }
}
if { [cli_ver_start 500 2] } {
	# start from FOSv52, it will auto update wtp-profile contents instead blocked.
} else {
	set old [cli_get_org_value $CLI_CUR_NODE "" "" ""]
	if { $old ne $new } {
		if {[cli_get_tbl_cnt $CLI_CUR_VDOM_NODE "wireless-controller wtp-profile"] > 0} {
			cli_set_errmsg "Remove WTP profile before changing country code"
			return 0
		}
	}
}
if { [cli_branchpt_start 500 1105] } {
	namespace import global::ncfg_is_fapc_support_ctry
	set new_value [cli_get_value $CLI_CUR_NODE "" "" ""]
	set old_value [cli_get_org_value $CLI_CUR_NODE "" "" ""]
	if { ![ncfg_is_fapc_support_ctry $new_value] && [ncfg_is_fapc_support_ctry $old_value] } {
		if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fapc-compatibility" 0 "enable"] } {
			cli_set_errmsg "Error: need to disable fapc-compatibility before changing to FAPC unsupported country"
			return 0
		}
	}
}
return 1
        %}

        "wireless-controller wtp-profile ap-country" = %{
if {$CLI_ACT ne "add"} {
        set new [cli_get_value $CLI_CUR_NODE "" "" ""]
        set old [cli_get_org_value $CLI_CUR_NODE "" "" ""]
        if { $new ne $old && $old ne "NA" && $old ne "--" && $old ne "" } {
		namespace import global::ncfg_is_cw_wtpprof_used
		set  prfname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
		if { [ncfg_is_cw_wtpprof_used $prfname] } {
			cli_set_errmsg "The ap-country can not be changed, for WTP Profile $prfname has been used!"
			return 0
		}
        }
}
if { [cli_branchpt_start 500 1105] } {
	set fapc_compatibility [cli_get_value $CLI_CUR_VDOM_NODE "wireless-controller setting" "" "fapc-compatibility"]
	if { $fapc_compatibility eq "enable" } {
		namespace import global::ncfg_is_fapc_platform
		namespace import global::ncfg_is_fapc_support_ctry
		set platform [cli_get_node $CLI_CUR_PARENT_NODE "platform" "" ""]
		if { $platform ne 0 } {
			set type [cli_get_value $platform "" "" "type"]
			if { [ncfg_is_fapc_platform $type] } {
				set value [cli_get_value $CLI_CUR_NODE "" "" ""]
				if { ![ncfg_is_fapc_support_ctry $value] } {
					cli_set_errmsg "Error: cannot change ap-country to other unsupported country"
					return 0
				}
			}
		}
	}
}
set region [cli_get_devinfo "region"]
if { $region ne "" } {
        if { [cli_has_feature "a_fwf"] } {
		namespace import global::wtp_profile_platform
		set plat [wtp_profile_platform $CLI_CUR_PARENT_NODE]
                if { [cli_get_devinfo "wifilocal" $plat] eq "yes" } {
                        set cn [cli_get_value $CLI_CUR_NODE "" "" ""]
                        set opts [cli_get_wl_country "options" $region]
                        set found 0
                        foreach opt $opts {
                                if { $opt eq $cn } {
                                        set found 1
                                        break
                                }
                        }
                        if { $found != 1 } {
                                cli_set_errmsg "ap-country \"$cn\" unsupported under current license"
                                return 0
                        }
                }
        }
}
return 1
        %}

	"wireless-controller wtp-profile handoff-sta-thresh" = %{
if { [string match "*gui*" [cli_get_clisrc]] && [cli_branchpt_start 600 200] } {
	set ho_sta [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $ho_sta < 5 } {
		set plat [cli_get_value $CLI_CUR_PARENT_NODE "platform" "" "type"]
		set ho_sta_max [cli_get_devinfo "pm2_wl_handoff_sta_max" $plat]
		if { $ho_sta_max } {
			set ho_sta [expr $ho_sta_max - 5]
			set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
			cli_set_errmsg "Handoff threshold value at wtp-profile, $name, should be between 5 and $ho_sta inclusively"
			return 0
		}
	}
}
return 1
	%}

        "wireless-controller wtp-profile login-passwd" = %{
if { !([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "login-passwd-change" 0 "yes"]) } {
        return 1
}
set pass [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [string compare -length 4 $pass "ENC "] != 0 } {
        regsub -all {(\\)+([\'\"\\])} $pass { } pass
        set len [string length $pass]
        if { ($len > 0 && $len < 5) || $len > 8 } {
                cli_set_errmsg "The login-passwd must be empty or 5 to 8 characters long"
                return 0
        }
}
return 1
        %}

	"wireless-controller wtp-profile {radio-1 radio-2 radio-3} channel" = %{
set cnty [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "ap-country"]
if { $cnty eq "" || $cnty eq "NA" || $cnty eq "--" } {
	return 1
}
set cs [cli_get_value $CLI_CUR_NODE "" "" ""]
set ocs [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { [string compare $cs $ocs] == 0 } {
       return 1
}
set rd_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if { $rd_mode ne "ap" } {
       return 1
}
namespace import global::channel_is_invalid
namespace import global::wtp_profile_platform
set band [cli_get_value $CLI_CUR_PARENT_NODE "" "" "band"]
set bond [cli_get_value $CLI_CUR_PARENT_NODE "" "" "channel-bonding"]
set plat [wtp_profile_platform [cli_get_parent $CLI_CUR_PARENT_NODE]]
set outdoor ""
if {[cli_obj_support "wireless-controller wtp-profile" "indoor-outdoor-deployment"]} {
	set outdoor [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "indoor-outdoor-deployment"]
}
set clist [cli_get_devinfo "wlchanlist" $cnty $band $bond $plat $outdoor]
set region [cli_get_devinfo "region"]
set isdfs [cli_get_devinfo "is_dfs" $region $cnty $plat]
foreach c $cs {
	if { [channel_is_invalid $c $clist $isdfs] } {
		cli_set_errmsg "channel $c is not supported. dfs=$isdfs,region=$region,plat=$plat,cnty=$cnty,band=$band,bond=$bond"
		return 0
	}
}
return 1
	%}

	"wireless-controller wtp-profile {radio-1 radio-2 radio-3} vap-all" = %{
set vap_all [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $vap_all eq "bridge" } {
	namespace import global::wtp_profile_platform
	set plat [wtp_profile_platform [cli_get_parent $CLI_CUR_PARENT_NODE]]
	if { $plat eq "FWF" } {
		set name [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "name"]
		cli_set_errmsg "Bridge SSIDs are not allowed in FWF profile, $name"
		return 0
	}
}
return 1
	%}

	"wireless-controller wtp-profile {radio-1 radio-2 radio-3} vaps" = %{
set vap_all [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vap-all"]
if { $vap_all eq "disable" || $vap_all eq "manual" } {
	set plat [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "platform" "" "type"]
	if { $plat eq "FWF" } {
		set vaps [cli_get_value $CLI_CUR_NODE "" "" ""]
		foreach vap $vaps {
			if { [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "wireless-controller vap" "name" 0 $vap "local-bridging" 0 "enable"] > 0 } {
				set name [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "name"]
				cli_set_errmsg "local bridging enabled vap, $vap, is not allowed in FWF profile $name"
				return 0
			}
		}
	}
}
return 1
	%}

	"extender-controller extender {profile extension-type}" = %{
if { !$CLI_GLOBAL_DEV } {
	set authorized [cli_get_value $CLI_CUR_PARENT_NODE "" "" "authorized"]
	set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	set old [cli_get_org_value $CLI_CUR_NODE "" "" ""]
	set new [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $authorized eq "enable" && $old ne "" } {
		cli_set_errmsg "can not change from \"$old\" to \"$new\" when extender is authorized, please deauthorize extender $name"
		return 0
	}
}
return 1
	%}

	"extension-controller extender {profile extension-type}" = %{
if { !$CLI_GLOBAL_DEV } {
	set authorized [cli_get_value $CLI_CUR_PARENT_NODE "" "" "authorized"]
	set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	set old [cli_get_org_value $CLI_CUR_NODE "" "" ""]
	set new [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $authorized eq "enable" && $old ne "" } {
		cli_set_errmsg "can not change from \"$old\" to \"$new\" when extender is authorized, please deauthorize extender $name"
		return 0
	}
}
return 1
	%}


	"extender-controller extender wan-extension {modem1-extension modem2-extension}" = %{
if { !$CLI_GLOBAL_DEV } {
	set authorized [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "authorized"]
	set name [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "name"]
	set value [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $value eq "" } {
		if { $authorized eq "enable" } {
			cli_set_errmsg "can not unset \"$CLI_CUR_NODE_NAME\" when extender is authorized, please deauthorize extender $name"
			return 0
		}
	} else {
		set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $value ""]
		if { !$intf_node } {
			cli_set_errmsg "invalid interface name: $value"
			return 0
		}
		set intf_type [cli_get_value $intf_node "" "" "type"]
		if { $intf_type ne "fext-wan" } {
			cli_set_errmsg "\"mismatch interface type of \"$value\": \"$intf_type\" vs \"fext-wan\""
			return 0
		}
	}
}
return 1
	%}

	"extension-controller extender wan-extension {modem1-extension modem2-extension}" = %{
if { !$CLI_GLOBAL_DEV } {
	set authorized [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "authorized"]
	set name [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "name"]
	set value [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $value eq "" } {
		if { $authorized eq "enable" } {
			cli_set_errmsg "can not unset \"$CLI_CUR_NODE_NAME\" when extender is authorized, please deauthorize extender $name"
			return 0
		}
	} else {
		set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $value ""]
		if { !$intf_node } {
			cli_set_errmsg "invalid interface name: $value"
			return 0
		}
		set intf_type [cli_get_value $intf_node "" "" "type"]
		if { $intf_type ne "fext-wan" } {
			cli_set_errmsg "\"mismatch interface type of \"$value\": \"$intf_type\" vs \"fext-wan\""
			return 0
		}
	}
}
return 1
	%}

	"firewall mms-profile" = %{
if { [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
	namespace import global::inspection_mode_vdom_flow
	if { [inspection_mode_vdom_flow] } {
		cli_set_errmsg "firewall mms-profile is not supported for flow inspection-mode"
		return 0
	}
}
return 1
	%}
        "firewall mms-profile notification" = %{
if { [string match "*override*" [cli_get_clisrc]] } { return 1 }
namespace import global::mms_profile_notification_mmsc_port_valid
if { [mms_profile_notification_mmsc_port_valid $CLI_CUR_NODE] } {
        if { [cli_get_value $CLI_CUR_NODE "" "" "mmsc-port"] eq 0 } {
                cli_set_errmsg "The \"mmsc-port\" value should be in the range of 1-65535."
                return 0
        }
}
return 1
        %}
	"system replacemsg {mail http webproxy ftp nntp fortiguard-wf spam im alertmail admin sslvpn ec nac-quar traffic-quota mms device-detection-portal utm}" = %{
if { [string match "*override*" [cli_get_clisrc]] } {
	return 1
}
set buffer [cli_get_value $CLI_CUR_NODE "" "" "buffer"]
if { $buffer == 0 || $buffer eq "" || $buffer eq "''" } {
	set msg [cli_get_value $CLI_CUR_NODE "" "" "msg-type"]
	cli_set_errmsg "The value of the \"$msg\" buffer can not be empty"
	return 0
}
return 1
	%}
        "system replacemsg-group {mail http webproxy ftp nntp fortiguard-wf spam im alertmail admin sslvpn ec nac-quar traffic-quota mms device-detection-portal utm}" = %{
if { [string match "*override*" [cli_get_clisrc]] } {
	return 1
}
set buffer [cli_get_value $CLI_CUR_NODE "" "" "buffer"]
if { $buffer == 0 || $buffer eq "" || $buffer eq "''" } {
        set msg [cli_get_value $CLI_CUR_NODE "" "" "msg-type"]
        cli_set_errmsg "The value of the \"$msg\" buffer can not be empty"
        return 0
}
return 1
        %}
        "system replacemsg {auth captive-portal-dflt}" = %{
if { [string match "*override*" [cli_get_clisrc]] } {
	return 1
}
set checking 1
set msg [cli_get_value $CLI_CUR_NODE "" "" "msg-type"]
if { [string index $msg end-1] eq "-" } {
	set n [string index $msg end]
	if { $n eq "1" || $n eq "2" || $n eq "3" } {
		set checking 0
	}
}
if { $checking == 1 } {
	set buffer [cli_get_value $CLI_CUR_NODE "" "" "buffer"]
	if { $buffer == 0 || $buffer eq "" || $buffer eq "''" } {
		cli_set_errmsg "The value of the \"$msg\" buffer can not be empty"
		return 0
	}
}
return 1
        %}
        "system replacemsg-group {auth captive-portal-dflt}" = %{
if { [string match "*override*" [cli_get_clisrc]] } {
	return 1
}
set checking 1
set msg [cli_get_value $CLI_CUR_NODE "" "" "msg-type"]
if { [string index $msg end-1] eq "-" } {
	set n [string index $msg end]
	if { $n eq "1" || $n eq "2" || $n eq "3" } {
		set checking 0
	}
}
if { $checking == 1 } {
	set buffer [cli_get_value $CLI_CUR_NODE "" "" "buffer"]
	if { $buffer == 0 || $buffer eq "" || $buffer eq "''" } {
		cli_set_errmsg "The value of the \"$msg\" buffer can not be empty"
		return 0
	}
}
return 1
        %}
        "system replacemsg {mm1 mm3 mm4 mm7}" = %{
if { [string match "*override*" [cli_get_clisrc]] } {
	return 1
}
set msg [cli_get_value $CLI_CUR_NODE "" "" "msg-type"]
if { $msg eq "mm1-send-conf-block" ||
     $msg eq "mm1-send-conf-virus" ||
     $msg eq "mm1-send-conf-bwl" ||
     $msg eq "mm1-send-conf-checksum" ||
     $msg eq "mm1-send-conf-bword" ||
     $msg eq "mm1-send-conf-flood" ||
     $msg eq "mm1-send-conf-dupe" } {
	set dst "rsp-text"
} else {
	set dst "message"
}
set buffer [cli_get_value $CLI_CUR_NODE "" "" $dst]
if { $buffer == 0 || $buffer eq "" || $buffer eq "''" } {
	cli_set_errmsg "The value of the \"$msg\" buffer can not be empty"
	return 0
}
return 1
        %}
        "system replacemsg-group {mm1 mm3 mm4 mm7}" = %{
if { [string match "*override*" [cli_get_clisrc]] } {
	return 1
}
set msg [cli_get_value $CLI_CUR_NODE "" "" "msg-type"]
if { $msg eq "mm1-send-conf-block" ||
     $msg eq "mm1-send-conf-virus" ||
     $msg eq "mm1-send-conf-bwl" ||
     $msg eq "mm1-send-conf-checksum" ||
     $msg eq "mm1-send-conf-bword" ||
     $msg eq "mm1-send-conf-flood" ||
     $msg eq "mm1-send-conf-dupe" } {
	set dst "rsp-text"
} else {
	set dst "message"
}
set buffer [cli_get_value $CLI_CUR_NODE "" "" $dst]
if { $buffer == 0 || $buffer eq "" || $buffer eq "''" } {
	cli_set_errmsg "The value of the \"$msg\" buffer can not be empty"
	return 0
}
return 1
        %}

	"user fsso" = %{
## Mantis 0399280
set svr [cli_get_value $CLI_CUR_NODE "" "" "server"]
if { $svr eq "" } {
	set if_no_default [cli_get_value $CLI_CUR_NODE "" "" "_if_no_default"]
	if { $if_no_default != 1} {
		cli_set_errmsg "Server cannot be empty."
		return 0
	}
}
if {$CLI_ACT ne "add"} {
        set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
        if { [cli_ver_start 500 2] } {
                if {$name eq "Local FSSO Agent"} {
                        if { $svr ne "127.0.0.1" } {
                                cli_set_errmsg "invalid value"
                                return 0
                        }
                }
        } else {
                set oldname [cli_get_org_value $CLI_CUR_NODE "" "" ""]
                if {($oldname eq "Local FSSO Agent") || ($name eq "Local FSSO Agent")} {
                        cli_set_errmsg "cannot modify"
                        return 0
                }
        }
}
return 1
	%}
	"user fsso-polling" = %{
set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
if { $server == 0 || $server eq "" } {
        cli_set_errmsg "invalid server"
        return 0
}
if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "server" 0 $server] > 1 } {
        cli_set_errmsg "duplicate server name"
        return 0
}

set ldsvr [string trim [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"] \"]
set oldsvr [string trim [cli_get_org_value $CLI_CUR_NODE "" "" "ldap-server"] \"]
if { $oldsvr ne "" && $ldsvr ne $oldsvr } {
	cli_set_errmsg "Modifying ldap-server is not allowed."
	return 0
}
return 1
	%}

	"system ntp" = %{
if { [cli_ver_start 500 0] } {
	set mode [cli_get_value $CLI_CUR_NODE "" "" "server-mode"]
	if { $mode eq "enable" } {
		set intf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
		if { $intf eq 0 || $intf eq "" } {
			cli_set_error "There aren't any interfaces with NTP server enabled."
			return 0
		}
	}
}
return 1
	%}
	"firewall policy6 {srcintf dstintf ssl-mirror-intf}" =%{
namespace import global::intf_dedicated_to_mgmt
if { [intf_dedicated_to_mgmt] } {
	return 0
}
return 1
	%}
	"firewall multicast-policy {srcintf dstintf}" = %{
namespace import global::intf_dedicated_to_mgmt
if { [intf_dedicated_to_mgmt] } {
    return 0
}
namespace import global::is_zone_member
set intf_name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [is_zone_member $intf_name] } {
	cli_set_errmsg "Firewall multicast-policy $CLI_CUR_NODE_NAME ($intf_name) cannot be a zone member."
	return 0
}
return 1
	%}
	"firewall interface-policy interface" = %{
namespace import global::is_zone_member
set intf_name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [is_zone_member $intf_name] } {
	cli_set_errmsg "Firewall interface-policy $CLI_CUR_NODE_NAME ($intf_name) cannot be a zone member."
	return 0
}
return 1
	%}
	"firewall policy64 {srcintf dstintf}" = %{
namespace import global::intf_dedicated_to_mgmt
if { [intf_dedicated_to_mgmt] } {
    return 0
}
return 1
	%}
	"firewall DoS-policy {interface}" = %{
namespace import global::is_zone_member
set intf_name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [is_zone_member $intf_name] } {
	cli_set_errmsg "Firewall DoS-policy $CLI_CUR_NODE_NAME ($intf_name) cannot be a zone member."
	return 0
}
return 1
	%}
	"firewall policy46 {srcintf dstintf}" = %{
namespace import global::intf_dedicated_to_mgmt
if { [intf_dedicated_to_mgmt] } {
    return 0
}
return 1
	%}
	"firewall multicast-policy6 {srcintf dstintf}" = %{
namespace import global::intf_dedicated_to_mgmt
if { [intf_dedicated_to_mgmt] } {
    return 0
}
return 1
	%}
	"firewall proxy-policy {srcintf dstintf}" = %{
namespace import global::intf_dedicated_to_mgmt
if { [intf_dedicated_to_mgmt] } {
    return 0
}
namespace import global::is_zone_member
set intf_name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [is_zone_member $intf_name] } {
	cli_set_errmsg "Firewall proxy-policy $CLI_CUR_NODE_NAME ($intf_name) cannot be a zone member."
	return 0
}
return 1
	%}
	"firewall security-policy {srcintf dstintf}" = %{
namespace import global::intf_dedicated_to_mgmt
if { [intf_dedicated_to_mgmt] } {
    return 0
}
namespace import global::is_zone_member
set intf_name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [is_zone_member $intf_name] } {
	cli_set_errmsg "Firewall security-policy $CLI_CUR_NODE_NAME ($intf_name) cannot be a zone member."
	return 0
}
return 1
	%}
	"firewall central-snat-map {srcintf dstintf}" = %{
namespace import global::intf_dedicated_to_mgmt
if { [intf_dedicated_to_mgmt] } {
    return 0
}
namespace import global::is_zone_member
set intf_name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [is_zone_member $intf_name] } {
	cli_set_errmsg "Firewall central-snat-map $CLI_CUR_NODE_NAME ($intf_name) cannot be a zone member."
	return 0
}
return 1
	%}
	"vpn ssl settings source-interface" = %{
namespace import global::is_zone_member
set intf_name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [is_zone_member $intf_name] } {
	cli_set_errmsg "vpn ssl settings source-interface $CLI_CUR_NODE_NAME ($intf_name) cannot be a zone member."
	return 0
}
return 1
	%}
	"firewall central-snat-map {orig-addr dst-addr}" = %{
namespace import global::wildcard_fqdn_check
set addr [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [wildcard_fqdn_check $addr "src" 0] } {
        return 0
}
return 1
	%}
	"firewall local-in-policy {srcaddr dstaddr}" = %{
namespace import global::wildcard_fqdn_check
set addr [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [wildcard_fqdn_check $addr "src" 0] } {
        return 0
}
return 1
	%}
	"firewall shaping-policy {srcaddr dstaddr}" = %{
namespace import global::wildcard_fqdn_check
set addr [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [wildcard_fqdn_check $addr "src" 0] } {
        return 0
}
return 1
	%}
	"firewall policy46 srcaddr" = %{
namespace import global::wildcard_fqdn_check
set srcaddr [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [wildcard_fqdn_check $srcaddr "src" 0] } {
	    return 0
}
return 1
	%}
	"firewall policy46 dstaddr" = %{
namespace import global::addr_iprange_or_ipmask
set addrs [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ![addr_iprange_or_ipmask $addrs ""] } {
	return 0
}
return 1
	%}
	"firewall policy64 dstaddr" = %{
namespace import global::addr_iprange_or_ipmask
namespace import global::wildcard_fqdn_check
set addrs [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [string length $addrs] == 0 } {
	cli_set_errmsg "dstaddr for policy46 or policy 64 cannot be empty"
	return 0
}
foreach addr $addrs {
        if { [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip64" $addr ""] ||
             [cli_get_node $CLI_CUR_VDOM_NODE "firewall vipgrp64" $addr ""] } {
                continue
        }
        if { ![addr_iprange_or_ipmask $addr ""] } {
                return 0
        }
}
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [wildcard_fqdn_check $dstaddr "dst" 0] } {
	    return 0
}
return 1
        %}
	"user device-group" = %{
set member [cli_get_value $CLI_CUR_NODE "" "" "member"]
if { $member == 0 || $member eq "" } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	cli_set_errmsg "Device group \"$name\" cannot be empty."
	return 0
}
return 1
	%}
	"user device" = %{
set mac [cli_get_value $CLI_CUR_NODE "" "" "mac"]
if { $mac == 0 || $mac eq "" || $mac eq "00:00:00:00:00:00" } {
	set alias [cli_get_value $CLI_CUR_NODE "" "" "alias"]
	cli_set_errmsg "user device \"$alias\" mac attribute cannot be empty."
	return 0
}
if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "mac" 0 $mac] > 1} {
	cli_set_errmsg "user device mac attribute is duplicated."
	return 0
}
if { [cli_is_match $CLI_CUR_NODE 0 "" "master-device" 0 ""] } {
	set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
	if { $type eq "unknown" || $type eq "" } {
    		cli_set_errmsg "Device type must be set"
    		return 0
	}
}
return 1
	%}
	"system virtual-switch" = %{
if { ![cli_ver_start 600 0] } {
if { [string match "*script*" [cli_get_clisrc]] } {
	if { [cli_get_tbl_cnt $CLI_CUR_NODE "port"] < 2 } {
		cli_set_errmsg "Virtual switch must have 2 or more ports"
		return 0
	}
}
}
if { [cli_get_value $CLI_CUR_NODE "" "" "physical-switch"] eq "" } {
	cli_set_errmsg "Attribute 'physical-switch' MUST be set."
	return 0
}
return 1
	%}
	"system virtual-switch port" = %{
if {$CLI_ACT eq "add"} {
	set intf [cli_get_value $CLI_CUR_NODE "" "" ""]
	set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $intf ""]
	if { [cli_get_value $intf_node "" "" "type"] ne "physical" } {
		cli_set_errmsg "Only physical ports can be added to virtual switch."
		return 0
	}
}
return 1
	%}
        "system admin accprofile" = %{
return 1
        %}
	"firewall ssl-ssh-profile server-cert" = %{
set cert [cli_get_value $CLI_CUR_NODE "" "" ""]
set cert [string trim $cert \"]
if { $cert eq "self-sign" } {
	cli_set_errmsg "self-sign can not be used by ssl-ssh-profile.server-cert"
	return 0
}
return 1
	%}
        "endpoint-control profile" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "profile-name"]
set dg [cli_get_value $CLI_CUR_NODE "" "" "device-groups"]
if { $name eq "default" } {
	set u [cli_get_value $CLI_CUR_NODE "" "" "users"]
	set ug [cli_get_value $CLI_CUR_NODE "" "" "user-groups"]
	if { $dg ne "" || $u ne "" || $ug ne "" } {
		cli_set_errmsg "device-groups/users/user-groups unavailable for default profile"
		return 0
	}
}
if { [cli_ver_start 500 4] } {
	if { ($dg eq "") && ($name ne "default") } {
		cli_set_errmsg "Device groups can not be empty!"
		return 0
	}
}
return 1
        %}
	"vpn ssl web portal widget type" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $type eq "tool" ||
     $type eq "tunnel" ||
     $type eq "info" ||
     $type eq "history" ||
     $type eq "forticlient-download" } {
	if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "type" 0 $type] > 1 } {
		cli_set_errmsg "Only one $type widget is allow."
		return 0
	}
}
return 1
	%}
	"vpn ssl web portal" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "tunnel-mode"]
if { $type eq "enable" } {
	set pool [cli_get_value $CLI_CUR_NODE "" "" "ip-pools"]
	if { $pool eq "" } {
		set sslset [cli_get_node $CLI_CUR_VDOM_NODE "vpn ssl settings" "" ""]
		set pool [cli_get_value $sslset "" "" "tunnel-ip-pools"]
		if { $pool eq "" } {
			cli_set_errmsg "ip-pools cannot be empty if tunnel-mode is enabled"
			return 0
		}
	}
}
set type [cli_get_value $CLI_CUR_NODE "" "" "ipv6-tunnel-mode"]
if { $type eq "enable" } {
	set pool [cli_get_value $CLI_CUR_NODE "" "" "ipv6-pools"]
	if { $pool eq "" } {
		set sslset [cli_get_node $CLI_CUR_VDOM_NODE "vpn ssl settings" "" ""]
		set pool [cli_get_value $sslset "" "" "tunnel-ipv6-pools"]
		if { $pool eq "" } {
			cli_set_errmsg "ipv6-pools cannot be empty if ipv6-tunnel-mode is enabled"
			return 0
		}
	}
}
return 1
	%}
	"system interface interface" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "vlan" || [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "emac-vlan" } {
	set ha [cli_get_node $CLI_GLOBAL_NODE "system ha" "" ""]
	set mode [cli_get_value $ha "" "" "mode"]
	if { $mode eq "a-a" || $mode eq "a-p" } {
		if { [cli_get_value $ha "" "" "ha-mgmt-status"] eq "enable" } {
			set intf [cli_get_value $CLI_CUR_NODE "" "" ""]
			set port [cli_get_value $ha "" "" "ha-mgmt-interface"]
			if { $port eq $intf } {
				cli_set_errmsg "can not use ha-mgmt-interface."
				return 0
			}
		}
	}
}
return 1
	%}
	"vpn ipsec {phase1 phase1-interface} certificate" = %{
set cert [cli_get_value $CLI_CUR_NODE "" "" ""]
namespace import global::auth_cert_not_exist
if { [auth_cert_not_exist $cert] } {
        cli_set_errmsg "Certificate $cert does not exist"
        return 0
}
	%}
	"webfilter override initiator" = %{
if {$CLI_ACT ne "add"} {
	set o_initiator [cli_get_org_value $CLI_CUR_NODE "" "" ""]
	set initiator [cli_get_value $CLI_CUR_NODE "" "" ""]
		if { $o_initiator != $initiator } {
			cli_set_errmsg "initiator is not allowed to change."
			return 0
		}
	return 0
}
return 1
	%}
	"firewall gtp imsi mcc-mnc" = %{
set m [cli_get_value $CLI_CUR_NODE "" "" ""]
set m [string trim $m \"]
if { $m eq "" } {
	return 1
}
if { [cli_ver_start 500 0] } {
	if { [string is digit $m] } {
		return 1
	}
} else {
	if { [string is alnum $m] } {
		return 1
	}
}
cli_set_errmsg "invalid format"
return 0
	%}
	"wanopt profile {http cifs mapi ftp tcp} secure-tunnel" = %{
set s [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $s eq "enable" } {
	set c [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "auth-group"]
	if { $c eq "" } {
		cli_set_errmsg "enable Must have authgrp when secure-tunnel is enabled in a protocol"
		return 0
	}
}
return 1
	%}
	"firewall gtp noip-policy" = %{
set start_protocol [cli_get_value $CLI_CUR_NODE "" "" "start"]
set end_protocol [cli_get_value $CLI_CUR_NODE "" "" "end"]
if { $start_protocol > $end_protocol } {
	cli_set_errmsg "start must not be greater than end"
	return 0
}
return 1
	%}
	"wanopt profile auth-group" = %{
set a [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $a eq "" } {
	set h [cli_get_value $CLI_CUR_PARENT_NODE "http" "" "secure-tunnel"]
	set c [cli_get_value $CLI_CUR_PARENT_NODE "cifs" "" "secure-tunnel"]
	set m [cli_get_value $CLI_CUR_PARENT_NODE "mapi" "" "secure-tunnel"]
	set f [cli_get_value $CLI_CUR_PARENT_NODE "ftp" "" "secure-tunnel"]
	set t [cli_get_value $CLI_CUR_PARENT_NODE "tcp" "" "secure-tunnel"]
	if { $h eq "enable" || $c eq "enable" || $m eq "enable" || $f eq "enable" || $t eq "enable" } {
		cli_set_errmsg "Must set authgrp when secure-tunnel is enabled in a protocol"
		return 0
	}
}
return 1
	%}
        "vpn ipsec manualkey authkey" = %{
set alg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "authentication"]
set key [cli_get_value $CLI_CUR_NODE "" "" ""]
set key [string trim $key \"]
if { [cli_get_devinfo "ipsec_manualkey_chk_authkey" "0" $alg $key] ne "yes" } {
	cli_set_errmsg "authkey format is invalid"
	return 0
}
return 1
	%}
        "vpn ipsec manualkey enckey" = %{
set alg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "encryption"]
set key [cli_get_value $CLI_CUR_NODE "" "" ""]
set key [string trim $key \"]
if { [cli_get_devinfo "ipsec_manualkey_chk_enckey" "0" $alg $key] ne "yes" } {
	cli_set_errmsg "enckey format is invalid"
	return 0
}
return 1
	%}
        "vpn ipsec manualkey-interface auth-key" = %{
set alg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "auth-alg"]
set key [cli_get_value $CLI_CUR_NODE "" "" ""]
set key [string trim $key \"]
if { [cli_get_devinfo "ipsec_manualkey_chk_authkey" "1" $alg $key] ne "yes" } {
	cli_set_errmsg "auth-key format is invalid"
	return 0
}
return 1
	%}
        "vpn ipsec manualkey-interface enc-key" = %{
set alg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "enc-alg"]
set key [cli_get_value $CLI_CUR_NODE "" "" ""]
set key [string trim $key \"]
if { [cli_get_devinfo "ipsec_manualkey_chk_enckey" "1" $alg $key] ne "yes" } {
	cli_set_errmsg "enc-key format is invalid"
	return 0
}
return 1
	%}
        "wireless-controller wtp" = %{
set cmode [cli_get_value $CLI_CUR_NODE "" "" "wtp-mode"]
if { $cmode eq "remote" } {
	if { [cli_get_value $CLI_CUR_NODE "" "" "wtp-profile"] eq "" } {
	    cli_set_errmsg "Attribute 'wtp-profile' MUST be set."
	    return 0
	}
}
if {$CLI_ACT eq "add"} {
	if { [cli_ver_start 500 0] } {
		namespace import global::ncfg_get_local_wtp_id
		set localid [ncfg_get_local_wtp_id]
		set cid [cli_get_value $CLI_CUR_NODE "" "" "wtp-id"]
		set wtp_num [cli_get_devinfo "cli_get_tablesize" "wireless-controller wtp" "vdom"]
## FOS logic: first check total wtp table size, fail if exceed; then will check wtp-normal table size if wtp-mode is normal,
## BUT current fmg syntax do not has wtp-normal and wtp-remote table while fgt has. So here we only check the total wtp table
## size, will add wtp-normal size check after fmg add relate syntax.
##		set wtp_num [expr ($wtp_num / 2)]
		if { $cid eq $localid } {
			# reserved one no need checking tablesz
		} elseif { $wtp_num eq 0 } {
			# no limit, no need checking tablesz
		} else {
			set local 0
			set remote 0
			set node_list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
			foreach e $node_list {
				if { [cli_if_same_node $e $CLI_CUR_NODE] } {
					continue
				}
				set id [cli_get_value $e "" "" "wtp-id"]
				if { $id eq $localid } {
					continue
				}
				set mode [cli_get_value $e "" "" "wtp-mode"]
				if { $mode eq "normal" } {
					incr local
				} elseif { $mode eq "remote" } {
					incr remote
				}
			}
			if { ($local >= $wtp_num) && ($cmode eq "normal") } {
				cli_set_errmsg "Too many normal wtp entries ($local/$wtp_num)"
				return 0
			}
			if { ($remote >= $wtp_num) && ($cmode eq "remote") } {
				cli_set_errmsg "Too many remote wtp entries ($remote/$wtp_num)"
				return 0
			}
		}
	}
}
if { [cli_ver_start 500 4] } {
} else {
	namespace import global::capwap_mesh_enabled_vap_exist
	namespace import global::capwap_mesh_intf_auto_add_check_pass
	namespace import global::capwap_mesh_intf_auto_del_check_pass
	namespace import global::ncfg_get_local_wtp_id
	set wtp [cli_get_value $CLI_CUR_NODE "" "" "wtp-id"]
	if { $wtp eq [ncfg_get_local_wtp_id] } {
		set ovaps [cli_get_org_value $CLI_CUR_NODE "" "" "vaps"]
		set nvaps [cli_get_value $CLI_CUR_NODE "" "" "vaps"]
		if { $ovaps ne $nvaps } {
			set oe [capwap_mesh_enabled_vap_exist $ovaps]
			set ne [capwap_mesh_enabled_vap_exist $nvaps]
			if { $oe && !$ne } {
				if { ![capwap_mesh_intf_auto_del_check_pass] } {
					return 0
				}
			} elseif { !$oe && $ne } {
				if { ![capwap_mesh_intf_auto_add_check_pass] } {
					return 0
				}
			}
		}
	}
}
return 1
	%}
	"wireless-controller wtp login-passwd" = %{
if { !([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-login-passwd-change" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "login-passwd-change" 0 "yes"]) } {
	return 1
}
set pass [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [string compare -length 4 $pass "ENC "] != 0 } {
	regsub -all {(\\)+([\'\"\\])} $pass { } pass
	set len [string length $pass]
	if { ($len > 0 && $len < 5) || $len > 8 } {
		cli_set_errmsg "The login-passwd must be empty or 5 to 8 characters long"
		return 0
	}
}
return 1
	%}
        "wireless-controller wtp {radio-1 radio-2}" = %{
namespace import global::capwap_mesh_enabled_vap_exist
namespace import global::capwap_mesh_intf_auto_add_check_pass
namespace import global::capwap_mesh_intf_auto_del_check_pass
namespace import global::ncfg_get_local_wtp_id
set wtp [cli_get_value [cli_get_parent $CLI_CUR_NODE] "" "" "wtp-id"]
if { $wtp eq [ncfg_get_local_wtp_id] } {
        set ovaps [cli_get_org_value $CLI_CUR_NODE "" "" "vaps"]
        set nvaps [cli_get_value $CLI_CUR_NODE "" "" "vaps"]
        if { $ovaps ne $nvaps } {
                set oe [capwap_mesh_enabled_vap_exist $ovaps]
                set ne [capwap_mesh_enabled_vap_exist $nvaps]
                if { $oe && !$ne } {
                        if { ![capwap_mesh_intf_auto_del_check_pass] } {
                                return 0
                        }
                } elseif { !$oe && $ne } {
                        if { ![capwap_mesh_intf_auto_add_check_pass] } {
                                return 0
                        }
                }
        }
}
return 1
	%}
	"wireless-controller wtp {wtp-profile wtp-mode}" = %{
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wtp-mode"]
if { $mode eq "remote" &&  ![cli_ver_start 600 4] } {
	set prof_name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wtp-profile"]
	namespace import global::wireless_controller_wtp_mode_valid
	return [wireless_controller_wtp_mode_valid $mode $prof_name]
}
return 1
	%}

	"router bgp neighbor-range neighbor-group" = %{
set g [cli_get_value $CLI_CUR_NODE "" "" ""]
set g [string trim $g \"]
set pns [cli_get_tbl_list [cli_get_parent $CLI_CUR_PARENT_NODE] "neighbor-group"]
foreach n $pns {
	set gg [cli_get_value $n "" "" "name"]
	if { $gg eq $g } {
		return 1
	}
}
cli_set_errmsg "\"$g\" is an invalid datasource"
return 0
	%}
	"firewall ssl-ssh-profile ssl-exempt" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $type eq "fortiguard-category" } {
	set c [cli_get_value $CLI_CUR_NODE "" "" "fortiguard-category"]
	if { $c ne "" && $c ne 0 } {
		set c [string trim $c \"]
        	if { [string is integer $c] == 0 || $c eq "0" } {
                	cli_set_errmsg "unsupport fortiguard-category value \"$c\""
                	return 0
		}
	}
} elseif { $type eq "address" } {
	set addr [cli_get_value $CLI_CUR_NODE "" "" "address"]
	if { $addr eq "" } {
		cli_set_errmsg "unsupport address value \"$addr\""
                return 0
	}
} elseif { $type eq "address6" } {
	set addr6 [cli_get_value $CLI_CUR_NODE "" "" "address6"]
	if { $addr6 eq "" } {
		cli_set_errmsg "unsupport address6 value \"$addr6\""
                return 0
	}
} elseif { $type eq "wildcard-fqdn" } {
	set fqdn [cli_get_value $CLI_CUR_NODE "" "" "wildcard-fqdn"]
	if { $fqdn eq "" } {
		cli_set_errmsg "unsupport wildcard-fqdn value \"$fqdn\""
                return 0
	}
} elseif { $type eq "regex" } {
	set regex [cli_get_value $CLI_CUR_NODE "" "" "regex"]
	if { $regex eq "" } {
		cli_set_errmsg "unsupport regex value \"$regex\""
                return 0
	}
}
return 1
        %}
	"vpn certificate ca" = %{
if { $CLI_IS_RESYNC || $CLI_ACT ne "add" } {
	return 1
}
if { [cli_ver_start 500 4] && [cli_get_devinfo "vdom-admin"] eq "yes" } {
	set range [cli_get_value $CLI_CUR_NODE "" "" "range"]
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set gnode [cli_get_node $CLI_GLOBAL_NODE "certificate ca" $name ""]
	if { $range eq "vdom" && $gnode != 0 } {
		cli_set_errmsg "certificate ca with same name $name already exist in global."
		return 0;
	} elseif { $range eq "global" && $gnode == 0 } {
		cli_set_errmsg "certificate ca with same name $name dose not exist in global."
		return 0;
	}
}
set ca1 [cli_get_value $CLI_CUR_NODE "" "" "ca"]
set calist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "vpn certificate ca"]
foreach canode $calist {
	if { [cli_if_same_node $canode $CLI_CUR_NODE] } {
		continue
	}
	set ca2 [cli_get_value $canode "" "" "ca"]
	set ca1 [string trim $ca1 \"]
	set ca2 [string trim $ca2 \"]
	set res [cli_certificate_cmp $ca1 $ca2]
	if { $res == 0 } {
		cli_set_errmsg "This CA certificate is duplicated."
		return 0;
	}
}
return 1
	%}
	"certificate {ca local crl remote} range" = %{
set range [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $range ne "global" } {
	cli_set_errmsg "Range must be global"
	return 0;
}
return 1
	%}
	"vpn certificate {ca local crl remote} range" = %{
if { [string match "*override*" [cli_get_clisrc]] || [string match "*preload*" [cli_get_clisrc]] } {
	## let override and preload pass as this is handled by handler or ZTP
	return 1
}
set range [cli_get_value $CLI_CUR_NODE "" "" ""]
set orange [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { $CLI_ACT ne "add" && $range ne $orange } {
	cli_set_errmsg "Range cannot be changed"
	return 0;
}
return 1
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3} band" = %{
if { ![cli_ver_start 500 0] } { return 1 }
if { [cli_is_unset $CLI_CUR_NODE "" "" ""] } { return 1 }
set radio $CLI_CUR_PARENT_NAME
set band [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $band eq "" } {
	return 1
}
namespace import global::wtp_profile_platform
set plat [wtp_profile_platform [cli_get_parent $CLI_CUR_PARENT_NODE]]
set r "1"
set mode ""
set CW_WTP_CAP_VWTP [expr 1 << 20]
if { $radio eq "radio-1" } {
	set val [cli_get_devinfo "pm2_wl_wtpcap_attr" $plat "cap"]
	if {[cli_obj_support "wireless-controller wtp-profile platform" "mode"] && [expr ($val & $CW_WTP_CAP_VWTP)] } {
		set mode [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "platform" "" "mode"]
	}
} else {
	if { $radio eq "radio-2" } {
		set r "2"
		if { [cli_get_devinfo "pm2_wl_radio_enabled" $r $plat] eq "no" } {
			return 1
		}
		set val [cli_get_devinfo "pm2_wl_wtpcap_attr" $plat "cap"]
		if {[cli_obj_support "wireless-controller wtp-profile platform" "mode"] && [expr ($val & $CW_WTP_CAP_VWTP)] } {
			set mode [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "platform" "" "mode"]
		}
	} elseif { $radio eq "radio-3" } {
		set r "3"
		if { [cli_get_devinfo "pm2_wl_radio_enabled" $r $plat] eq "no" } {
			return 1
		}
		set val [cli_get_devinfo "pm2_wl_wtpcap_attr" $plat "cap"]
		if {[cli_obj_support "wireless-controller wtp-profile platform" "mode"] && [expr ($val & $CW_WTP_CAP_VWTP)] } {
			set mode [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "platform" "" "mode"]
		}
	}
}
if { [cli_get_devinfo "wlbandvalid" $r $plat $band $mode] ne "yes" } {
	cli_set_errmsg "unsupported $radio band $band under platform $mode $plat"
	return 0
}
if { $CLI_ACT eq "edit" } {
	set oldband [cli_get_org_value $CLI_CUR_NODE "" "" ""]
	if { $band ne $oldband && $oldband ne "" } {
		set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
		set cnty [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "ap-country"]
		if { $mode eq "ap" && $cnty ne "NA" && $cnty ne "--" } {
			namespace import global::channel_is_invalid
			namespace import global::wtp_profile_platform
			set bond [cli_get_value $CLI_CUR_PARENT_NODE "" "" "channel-bonding"]
			set cs   [cli_get_value $CLI_CUR_PARENT_NODE "" "" "channel"]
			set outdoor ""
			if {[cli_obj_support "wireless-controller wtp-profile" "indoor-outdoor-deployment"]} {
				set outdoor [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "indoor-outdoor-deployment"]
			}
			set clist [cli_get_devinfo "wlchanlist" $cnty $band $bond $plat $outdoor]
			set region [cli_get_devinfo "region"]
			set isdfs [cli_get_devinfo "is_dfs" $region $cnty $plat]
			foreach c $cs {
				if { [channel_is_invalid $c $clist $isdfs] } {
					cli_set_errmsg "channel $c is not supported. dfs=$isdfs,region=$region,plat=$plat,cnty=$cnty,band=$band,bond=$bond"
					return 0
				}
			}
		}
	}
}
return 1
	%}
	"application custom id" = %{
set nid [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ($nid != 0) && ($nid < 1000 || $nid > 9999) } {
	cli_set_errmsg "custom signature id must be between 1000 and 9999"
	return 0
}
return 1
	%}
	"system {virtual-wan-link sdwan} health-check name" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set dash [string first "-" $name 0]
if { $dash >= 0 } {
	cli_set_errmsg "Invalid health-check name $name."
	return 0;
}
return 1
	%}
	"system {virtual-wan-link sdwan} members interface" = %{
## manually perform reference check due to weakdatasrc
set intf [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $intf ne "" && $intf ne "''" } {
	set node [cli_get_node $CLI_GLOBAL_NODE "system interface" $intf ""]
	if { $node eq 0 } {
		cli_set_errmsg "Invalid interface $intf."
		return 0
	}
}

if { ![cli_branchpt_start 600 1614] } {
	if {[cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall policy" "learning-mode" 0 "enable" "srcintf" 0 "virtual-wan-link"] > 0} {
		set intfname [cli_get_value $CLI_CUR_NODE "" "" ""]
		if {[cli_get_match_nr $CLI_GLOBAL_NODE 1 "system interface" "device-identification" 0 "disable" "name" 0 $intfname] > 0} {
			cli_set_errmsg "Device-identification disabled interface $intfname can not used as a member of virtual-wan-link which is used as source interface in one or more policies with learning mode enabled."
			return 0
		}
	}
}
return 1
	%}
	"system {virtual-wan-link sdwan} neighbor ip" = %{
## manually perform reference check due to weakdatasrc
set neighbor [cli_get_value $CLI_CUR_NODE "" "" ""]
set bgp [cli_get_node $CLI_CUR_VDOM_NODE "router bgp" "" ""]
set node 0
if { $bgp ne 0 } {
	set node [cli_get_node $bgp "neighbor" $neighbor ""]
}
if { $node eq 0 } {
	cli_set_errmsg "Invalid BGP neighbor $neighbor."
	return 0
}
return 1
	%}
	"system interface name" = %{
set n [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [string equal -length 3 $n "ppp"] } {
	cli_set_errmsg "interface name cannot start with 'ppp'"
	return 0
}
return 1
	%}
	"system interface allowaccess" = %{
if { [cli_ver_start 500 6] && ![string match "*tcl*" [cli_get_clisrc]] } {
	set flink [cli_get_value $CLI_CUR_PARENT_NODE "" "" "fortilink"]
	if { $flink eq "enable" } {
		cli_set_errmsg "cannot change allowaccess if when fortilink is enabled"
		return 0
	}
}
return 1
	%}
	"system interface fortilink" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "enable" } {
	set multi "enable"
	if { ![cli_branchpt_start 600 1695] } {
		set multi [cli_get_value $CLI_CUR_VDOM_NODE "switch-controller global" "" "allow-multiple-interfaces"]
	}
	if { $multi eq "enable" } {
		return 1
	}
	set vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vdom"]
	set num [cli_get_match_nr $CLI_GLOBAL_NODE 1 "system interface" "vdom" 0 $vdom "fortilink" 0 "enable"]
	if { $num > 1 } {
		cli_set_errmsg "can only have 1 fortilink interface per vdom"
		return 0
	}
}
return 1
	%}
	"system csf status" = %{
set status [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $status eq "enable" } {
	namespace import global::cli_sys_global_vdom_enable
	if { [cli_sys_global_vdom_enable] } {
		if { ![cli_branchpt_start 600 2274] } {
			cli_set_errmsg "Can not set csf when vdom mode is enabled"
			return 0
		}
	}
}
return 1
	%}
	"system settings" = %{
set mn [cli_get_value $CLI_CUR_NODE "" "" "opmode"]
set mo [cli_get_org_value $CLI_CUR_NODE "" "" "opmode"]
if { $mo eq "transparent" && $mn eq "nat" } {
	set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
	namespace import global::ip_class
	set class [ip_class [lindex $ip 0]]
	if { !($class eq "A" || $class eq "B" || $class eq "C") } {
		cli_set_errmsg "IP address must be a class A, B, or C IP"
		return 0
	}
}
if { $mn eq "transparent" } {
	set csf_en [cli_get_value $CLI_GLOBAL_NODE "system csf" "" "status"]
	if { $csf_en eq "enable" } {
		cli_set_errmsg "Cannot set opmode to transparent while Cooperative Security Fabric is enabled."
		return 0
	}
}
namespace import global::is_platform_support_hyperscale
if { [is_platform_support_hyperscale] } {
	set oldval [cli_get_org_value $CLI_CUR_NODE "" "" "policy-offload-level"]
	if { $oldval eq "default" } {
		set oldval [cli_get_value $CLI_GLOBAL_NODE "system npu" "" "policy-offload-level"]
	}
	set newval [cli_get_value $CLI_CUR_NODE "" "" "policy-offload-level"]
	if { $newval eq "default" } {
		set newval [cli_get_value $CLI_GLOBAL_NODE "system npu" "" "policy-offload-level"]
	}

	if { $oldval ne $newval } {
		if { $oldval eq "full-offload" } {
			set policy_cnt [cli_get_tbl_cnt $CLI_CUR_VDOM_NODE "firewall hyperscale-policy"]
			if { $policy_cnt > 0 } {
				cli_set_errmsg "There are $policy_cnt hyperscale-policy exists in this vdom, please delete them first!"
				return 0
			}
			set policy_cnt [cli_get_tbl_cnt $CLI_CUR_VDOM_NODE "firewall hyperscale-policy6"]
			if { $policy_cnt > 0 } {
				cli_set_errmsg "There are $policy_cnt hyperscale-policy6 exists in this vdom, please delete them first!"
				return 0
			}
			set policy_cnt [cli_get_tbl_cnt $CLI_CUR_VDOM_NODE "firewall hyperscale-policy64"]
			if { $policy_cnt > 0 } {
				cli_set_errmsg "There are $policy_cnt hyperscale-policy64 exists in this vdom, please delete them first!"
				return 0
			}
			set policy_cnt [cli_get_tbl_cnt $CLI_CUR_VDOM_NODE "firewall hyperscale-policy46"]
			if { $policy_cnt > 0 } {
				cli_set_errmsg "There are $policy_cnt hyperscale-policy46 exists in this vdom, please delete them first!"
				return 0
			}

			set ippool_list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall ippool"]
			foreach ippool $ippool_list {
				set pooltype [cli_get_value $ippool "" "" "type"]
				if { $pooltype eq "cgn-resource-allocation" } {
					set poolname [cli_get_value $ippool "" "" "name"]
					cli_set_errmsg "IP pool name = $poolname still use type only supported in full offload mode, please disable it first!"
					return 0
				}
			}

		}
		if { $newval eq "full-offload" } {
			set policy_cnt [cli_get_tbl_cnt $CLI_CUR_VDOM_NODE "firewall policy"]
			if { $policy_cnt > 0 } {
				cli_set_errmsg "There are $policy_cnt policy exists in this vdom, please delete them first!"
				return 0
			}
			set policy_cnt [cli_get_tbl_cnt $CLI_CUR_VDOM_NODE "firewall policy6"]
			if { $policy_cnt > 0 } {
				cli_set_errmsg "There are $policy_cnt policy6 exists in this vdom, please delete them first!"
				return 0
			}
			set policy_cnt [cli_get_tbl_cnt $CLI_CUR_VDOM_NODE "firewall policy64"]
			if { $policy_cnt > 0 } {
				cli_set_errmsg "There are $policy_cnt policy64 exists in this vdom, please delete them first!"
				return 0
			}
			set policy_cnt [cli_get_tbl_cnt $CLI_CUR_VDOM_NODE "firewall policy46"]
			if { $policy_cnt > 0 } {
				cli_set_errmsg "There are $policy_cnt policy46 exists in this vdom, please delete them first!"
				return 0
			}
		}
	}
}
return 1
	%}
        "wireless-controller vap mesh-backhaul" = %{
proc vaps_used_error_report { vaps name wname } {
        foreach v $vaps {
                set v [string trim $v "\""]
                if { $v eq $name } {
                        cli_set_errmsg "mesh-backhaul setting can't be changed since this vap is in use in wtp-profile \"$wname\""
                        return 1
                }
        }
        return 0
}
set valmesh [cli_get_value $CLI_CUR_NODE "" "" ""]
set old [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { $old eq $valmesh } {
	return 1
}
if { $valmesh == "enable" } {
        set valse [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"]
        if { ($valse ne "open") && ($valse ne "wpa-personal") &&
             ($valse ne "wpa-only-personal") && ($valse ne "wpa2-only-personal") } {
                cli_set_errmsg "mesh-backhaul can only be enabled when security is open or WPA personal"
                return 0
        }
}
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
if { [cli_ver_start 600 2] } {
	set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
	set vdom [cli_get_value $intf_node "" "" "vdom"]
} else {
	set vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vdom"]
}
if { $vdom eq "" } {
	set vdom $CLI_CUR_VDOM_NAME
}
set vnode [cli_get_vdom_node $vdom]
set wtps [cli_get_tbl_list $vnode "wireless-controller wtp"]
foreach w $wtps {
        set wname [cli_get_value $w "" "" "wtp-id"]
        if { [cli_ver_start 500 4] } {
                set vaps [cli_get_value $w "radio-1" "" "vaps"]
                if { [vaps_used_error_report $vaps $name $wname] } {
                        return 0
                }
                set vaps [cli_get_value $w "radio-2" "" "vaps"]
                if { [vaps_used_error_report $vaps $name $wname] } {
                        return 0
                }
        } else {
                set vaps [cli_get_value $w "" "" "vaps"]
                if { [vaps_used_error_report $vaps $name $wname] } {
                        return 0
                }
        }
}
return 1
        %}
	"wireless-controller vap auth" = %{
if { [cli_ver_start 500 2] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa-only-enterprise"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa2-only-enterprise"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa-enterprise"] } {
		set vapname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
		set auth [cli_get_value $CLI_CUR_NODE "" "" ""]
		if { $auth eq "radius" } {
			set radiusserver [cli_get_value $CLI_CUR_PARENT_NODE "" "" "radius-server"]
			if { $radiusserver eq ""} {
				cli_set_errmsg "$vapname : RADIUS server is empty. Must be configured for auth type radius."
				return 0
			}
		} elseif { $auth eq "usergroup" } {
			set usergroup [cli_get_value $CLI_CUR_PARENT_NODE "" "" "usergroup"]
			if { $usergroup eq ""} {
				cli_set_errmsg "$vapname : Usergroup is empty. Must be configured for auth type usergroup."
				return 0
			}
		}
	}
}
return 1
	%}
	"wireless-controller vap security" = %{
if { [cli_ver_start 500 2] } {
	set vapname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	set sec [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $sec eq "wpa-enterprise" || $sec eq "wpa-only-enterprise" || $sec eq "wpa2-only-enterprise" } {
		set auth [cli_get_value $CLI_CUR_PARENT_NODE "" "" "auth"]
		if { $auth eq "" } {
			cli_set_errmsg "$vapname : auth mode can not be empty for $sec security "
			return 0
		}
	}
}
set sec [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $sec eq "wep64" || $sec eq "wep128" || $sec eq "wpa-only-enterprise" || $sec eq "wpa-only-personal" || $sec eq "wpa-only-personal+captive-portal"} {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-obsolete-option" 1 "enable"] } {
		cli_set_errmsg "security option $sec is not avaliable when security-obsolete-option is disable"
		return 0
	}
}
return 1
	%}
	"wireless-controller vap security-obsolete-option" = %{
set sec [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"]
if { $sec eq "wep64" || $sec eq "wep128" || $sec eq "wpa-only-enterprise" || $sec eq "wpa-only-personal" || $sec eq "wpa-only-personal+captive-portal"} {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-obsolete-option" 1 "enable"] } {
                cli_set_errmsg "security option $sec is not avaliable when security-obsolete-option is disable"
                return 0
        }
}
return 1
	%}
	"wireless-controller vap portal-type" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" ""]
set bridging [cli_get_value $CLI_CUR_PARENT_NODE "" "" "local-bridging"]
if { $bridging eq "enable" && $type ne "auth" && $type ne "cmcc" && $type ne "cmcc-macauth" && $type ne "external-auth" } {
	set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	cli_set_errmsg "\"wireless-controller vap\", $name, portal-type can not be \"$type\" when local-bridging is enabled"
	return 0
}
return 1
	%}
	"icap profile request" = %{
set val [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$val eq "enable"} {
	set server [cli_get_value $CLI_CUR_PARENT_NODE "" "" "request-server"]
	if {$server eq ""} {
		cli_set_errmsg "request server cannot be empty when request is enable"
		return 0
	}
}
return 1
        %}
	"icap profile response" = %{
set val [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$val eq "enable"} {
	set server [cli_get_value $CLI_CUR_PARENT_NODE "" "" "response-server"]
	if {$server eq ""} {
		cli_set_errmsg "response server cannot be empty when response is enable"
		return 0
	}
}
return 1
	%}
	"spamfilter bwl entries" = %{
set node [cli_get_parent $CLI_CUR_PARENT_NODE]
set name [cli_get_value $node "" "" "name"]
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set enid [cli_get_value $CLI_CUR_NODE "" "" "id"]
if {$type eq "email"} {
	set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
	if {$action eq "reject"} {
		cli_set_errmsg "spamfilter.bwl:$name entries($enid) action can not be \"$action\" when type is \"$type\""
		return 0
	}
}
return 1
	%}
	"switch-controller qos ip-dscp-map map" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" "value"]
set diffserv [cli_get_value $CLI_CUR_NODE "" "" "diffserv"]
set precedence [cli_get_value $CLI_CUR_NODE "" "" "ip-precedence"]
set type 0
if { $value ne "" && $value ne "''" } { incr type }
if { $diffserv ne "" && $diffserv ne 0 } { incr type }
if { $precedence ne "" && $precedence ne 0 } { incr type }
if { $type ne 1 } {
	cli_set_errmsg "ip-dscp-map can only have one of \"value\", \"diffserv\", or \"ip-precedence\""
	return 0
}
return 1
	%}
	"switch-controller security-policy 802-1X user-group" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value eq 0 || $value eq "" } {
	cli_set_errmsg "security-policy 802-1X user-group MUST be set."
	return 0
}
return 1
	%}
	"switch-controller managed-switch name" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set name [string trim $name \"]
if {[regexp {[^0-9a-zA-Z\-_]} $name]} {
	cli_set_errmsg "Invalid switch name - the legal characters are numbers (0-9), letters(a-z,A-z) and special characters - and _"
	return 0
}
	%}
	"switch-controller managed-switch dynamic-capability" = %{
set old [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set new [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $old ne "" && $old ne 0 && $old ne "0x00000000000000000000000000000000" && $old ne $new } {
	cli_set_errmsg "dynamic-capability is read only"
	return 0
}
return 1
	%}
	"switch-controller managed-switch poe-detection-type" = %{
set old [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set new [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $old ne "" && $old ne 0 && $old ne $new } {
	cli_set_errmsg "poe-detection-type is read only"
	return 0
}
return 1
	%}
	"switch-controller nac-device" = %{
if { $CLI_ACT eq"add" } {
	cli_set_errmsg "User not allowed to set this command. It should be learned through NAC policy from managed FortiSwitch"
	return 0
}
return 1
	%}
	"switch-controller dynamic-port-policy policy mac" = %{
set mac [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $mac ne "" } {
	set ret [cli_check_wildcard_mac $mac]
	if { $ret ne "" } {
		cli_set_errmsg $ret
		return 0
	}
}
return 1
	%}
	"application group category" = %{
set catid [cli_get_value $CLI_CUR_PARENT_NODE "" "" "category"]
foreach cat $catid {
	if { ![cli_valid_ips_catid $cat 0] } {
		cli_set_errmsg "invalid category $cat"
		return 0
	}
}
return 1
 	%}
	"system virtual-wire-pair" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { [string length $name] > 11 } {
	cli_set_errmsg "Virtual Wire Pair name length must less than 12"
	return 0
}
set mem_list [cli_get_value $CLI_CUR_NODE "" "" "member"]
if { [llength $mem_list] != 2 } {
	cli_set_errmsg "Virtual Wire Pair member must contain 2 elements."
	return 0
}
return 1
	%}
        "ips sensor entries" = %{
if {[cli_get_tbl_cnt $CLI_CUR_PARENT_NODE "entries"] > 256} {
	cli_set_errmsg "Exceed the maximum number of entries in ips sensor(max : 256)"
	return 0
}
return 1
        %}
	"switch-controller qos ip-dscp-map map diffserv" = %{
set maps [cli_get_tbl_list [cli_get_parent $CLI_CUR_PARENT_NODE] ""]
set val1 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "diffserv"]
set n1 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
foreach map $maps {
	set n2 [cli_get_value $map "" "" "name"]
	if { $n1 ne $n2 } {
		set val2 [cli_get_value $map "" "" "diffserv"]
		foreach v1 $val1 {
			foreach v2 $val2 {
				if { $v1 eq $v2 } {
					cli_set_errmsg "Duplicate priority setting, exist in $n2"
					return 0
				}
			}
		}
	}
}
return 1
	%}
	"switch-controller qos ip-dscp-map map ip-precedence" = %{
set maps [cli_get_tbl_list [cli_get_parent $CLI_CUR_PARENT_NODE] ""]
set val1 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ip-precedence"]
set n1 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
foreach map $maps {
	set n2 [cli_get_value $map "" "" "name"]
	if { $n1 ne $n2 } {
		set val2 [cli_get_value $map "" "" "ip-precedence"]
		foreach v1 $val1 {
			foreach v2 $val2 {
				if { $v1 eq $v2 } {
					cli_set_errmsg "Duplicate priority setting, exist in $n2"
					return 0
				}
			}
		}
	}
}
return 1
	%}
	"switch-controller qos queue-policy cos-queue" = %{
set queue [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $queue ne "queue-0" && $queue ne "queue-1" && $queue ne "queue-2" && $queue ne "queue-3" && $queue ne "queue-4" && $queue ne "queue-5" && $queue ne "queue-6" && $queue ne "queue-7" } {
	set polname [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "name"]
	cli_set_errmsg "Cannot create additional queue number ($queue) for policy $polname"
	return 0
}
return 1
	%}
	"switch-controller lldp-profile med-network-policy" = %{
set pol [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $pol ne "voice" && $pol ne "voice-signaling" && $pol ne "guest-voice" && $pol ne "guest-voice-signaling" && $pol ne "softphone-voice" && $pol ne "video-conferencing" && $pol ne "streaming-video" && $pol ne "video-signaling"} {
	set prof [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "name"]
	cli_set_errmsg "Additional network policy TLV types ($pol) cannot be created for profile $prof"
	return 0
}
return 1
	%}
	"switch-controller lldp-profile med-location-service" = %{
set pol [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $pol ne "coordinates" && $pol ne "address-civic" && $pol ne "elin-number"} {
	set prof [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "name"]
	cli_set_errmsg "Additional network policy TLV types ($pol) cannot be created for profile $prof"
	return 0
}
return 1
	%}
	"switch-controller initial-config template" = %{
# mantis#0790453
namespace import global::ip_invalid

if { [cli_is_match $CLI_CUR_NODE 0 "" "dhcp-server" 0 "enable"] && [cli_is_match $CLI_CUR_NODE 0 "" "auto-ip" 0 "disable"] } {
	set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
	if { [ip_invalid $ip 1] eq 1 } {
		cli_set_errmsg "invalid ip: $ip"
		return 0
	}
}
return 1
	%}
	"router route-map rule {match-metric match-tag set-local-preference set-metric set-tag set-weight set-route-tag}" = %{
set val [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $val ne "" && (![string is integer $val] || $val < 0) } {
	cli_set_errmsg "Value must be integer from 0 to 4294967295."
	return 0
}
return 1
	%}
	"firewall addrgrp member" = %{
namespace import global::addr_all_exist
namespace import global::check_recur_group_members
proc intf_binding_contradiction_check { pol_list members vdom addr} {
	foreach member $members {
		set assc_intf [cli_get_value $vdom "firewall address" $member "associated-interface"]
		set assc_intf [string trim $assc_intf \"]
		if { $assc_intf eq "any" || $assc_intf eq "" } {
			continue
		}
		foreach pol $pol_list {
			if { $addr eq "srcaddr" } {
				set srcintf [cli_get_value $pol "" "" "srcintf"]
				foreach intf $srcintf {
					set intf [string trim $intf \"]
					if { $intf ne $assc_intf } {
						set polid [cli_get_value $pol "" "" "policyid"]
						cli_set_errmsg "Interface binding contradiction for member \"$member\" on policy $polid"
						return 1
					}
				}
			}
			if { $addr eq "dstaddr" } {
				set dstintf [cli_get_value $pol "" "" "dstintf"]
				foreach intf $dstintf {
					set intf [string trim $intf \"]
					if { $intf ne $assc_intf } {
						set polid [cli_get_value $pol "" "" "policyid"]
						cli_set_errmsg "Interface binding contradiction for member \"$member\" on policy $polid"
						return 1
					}
				}
			}
		}
	}
	return 0
}

set members [cli_get_value $CLI_CUR_NODE "" "" "" 1]
set grpname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set grplist [list "$grpname"]
if { [check_recur_group_members $grplist "firewall addrgrp" $members $CLI_CUR_VDOM_NODE] eq 0 } {
	return 0
}

set pol_list [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "firewall policy" "srcaddr" 0 $grpname]
if { [intf_binding_contradiction_check $pol_list $members $CLI_CUR_VDOM_NODE "srcaddr"] } {
	return 0
}
set pol_list [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "firewall policy" "dstaddr" 0 $grpname]
if { [intf_binding_contradiction_check $pol_list $members $CLI_CUR_VDOM_NODE "dstaddr"] } {
	return 0
}

set addr_all [addr_all_exist $members]
if { $addr_all } {
	set grp_list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall addrgrp"]
	set destgrp {}
	lappend destgrp $grpname
	foreach grp $grp_list {
		set mlist [cli_get_value $grp "" "" "member"]
		if { [cli_if_same_node $grp $CLI_CUR_PARENT_NODE] } {
			continue
		}
		set match 0
		foreach m $mlist {
			if { $m eq $grpname } {
				set match 1
				break
			}
		}
		if { $match == 1 } {
			lappend destgrp $grp
		}
	}
	if { ![cli_ver_start 500 2] } {
		set pol_list [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "firewall policy" "action" 0 "ssl-vpn"]
		foreach policy $pol_list {
			set dstaddr [cli_get_value $policy "" "" "dstaddr"]
			set match 0
			foreach dst $dstaddr {
				foreach g $destgrp {
					if { $dst eq $g } {
						set match 1
						break
					}
				}
				if { $match == 1 } {
					break
				}
			}
			if { $match == 0 } {
				continue
			}
			set ibp_list [cli_get_tbl_list $policy "identity-based-policy"]
			foreach ibp $ibp_list {
				set groups [cli_get_value $ibp "" "" "groups"]
				foreach grp $groups {
					set gnode [cli_get_node $CLI_CUR_VDOM_NODE "user group" $grp ""]
					set portalname [cli_get_value $gnode "" "" "sslvpn-portal"]
					if { $portalname eq "" } {
						continue
					}
					set portal [cli_get_node $CLI_CUR_VDOM_NODE "vpn ssl web portal" $portalname ""]
					if { [cli_get_match_nr $portal 1 "widget" "type" 0 "tunnel" "tunnel-status" 0 "enable" "split-tunneling" 0 "enable"] } {
						cli_set_errmsg "\"$grp\" with split tunnel does not allow policy destination address \"$dst\" to be 0.0.0.0/0"
						return 0
					}
				}
			}
		}
	}
}
if { [cli_ver_start 600 4] } {
	if { ![cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall addrgrp" "type" 0 "folder"] } {
		return 1
	}
	set grptype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
	set is_exclusive 0
	set member ""
	foreach m $members {
		set m [string trim $m \"]
		set node [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $m ""]
		if { 0 != $node } {
			set glist [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "firewall addrgrp" "member" 0 $m]
			foreach grp $glist {
				set gname [cli_get_value $grp "" "" "name"]
				set gname [string trim $gname \"]
				if { $grpname eq $gname } {
					continue
				}
				set gtype [cli_get_value $grp "" "" "type"]
				if { $grptype ne "folder" && $gtype eq "folder" } {
					set is_exclusive 1
				}
				if { $grptype eq "folder" && $gtype ne "folder" } {
					set is_exclusive 2
				}
				if { $is_exclusive } {
					set member $m
					break;
				}
			}
		}
		if { $is_exclusive } {
			break;
		}
	}
	if { $is_exclusive == 1 } {
		cli_set_errmsg "$member within $grpname is used by another folder type address group"
		return 0
	}
	if { $is_exclusive == 2 } {
		cli_set_errmsg "$member within a folder type address group $grpname is used by another address group"
		return 0
	}
}
return 1
	%}

	"firewall addrgrp6 member" = %{
namespace import global::check_recur_group_members
set members [cli_get_value $CLI_CUR_NODE "" "" ""]
set grpname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set grplist [list "$grpname"]
if { [check_recur_group_members $grplist "firewall addrgrp6" $members $CLI_CUR_VDOM_NODE] eq 0 } {
	return 0
}
return 1
	%}
	"system {interface zone} tagging" = %{
namespace import global::check_obj_tagging
if { [check_obj_tagging $CLI_CUR_NODE] eq 0 } {
	return 0
}
return 1
	%}
	"firewall {address address6 addrgrp addrgrp6 multicast-address multicast-address6 proxy-address proxy-addrgrp} tagging" = %{
namespace import global::check_obj_tagging
if { [check_obj_tagging $CLI_CUR_NODE] eq 0 } {
	return 0
}
return 1
	%}
	"user {device device-group} tagging" = %{
namespace import global::check_obj_tagging
if { [check_obj_tagging $CLI_CUR_NODE] eq 0 } {
	return 0
}
return 1
	%}
	"system object-tagging" = %{
if { [cli_is_referenced $CLI_CUR_NODE] } {
	set tags [cli_get_value $CLI_CUR_NODE "" "" "tags" 1]
	set otags [cli_get_org_value $CLI_CUR_NODE "" "" "tags" 1]
	set dlist {}
	set newtags [lsort -unique $tags]
	if { [llength $newtags] ne [llength $tags] } {
		cli_set_errmsg "duplicated tags"
		return 0
	}
	foreach ot $otags {
		if { [lsearch -exact $tags $ot] == -1 } {
			lappend dlist $ot
		}
	}
	if { [llength $dlist] > 0 } {
		set rlist [cli_get_ref_list $CLI_CUR_NODE]
		foreach ref $rlist {
			set rtags [cli_get_value $ref "" "" "tags" 1]
			foreach dtag $dlist {
				if { [lsearch -exact $rtags $dtag] != -1 } {
					cli_set_errmsg "tag $dtag is used, cannot be deleted"
					return 0
				}
			}
		}
	}
}
return 1
	%}
	"webfilter profile ftgd-wf" = %{
set prof [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set filters [cli_get_tbl_list $CLI_CUR_NODE "filters"]
set catelist {}
foreach f1 $filters {
	set cate_1 [cli_get_value $f1 "" "" "category"]
	foreach f2 $filters {
		if { [cli_if_same_node $f1 $f2] } {
			continue
		}
		set cate_2 [cli_get_value $f2 "" "" "category"]
		if { $cate_1 eq $cate_2 } {
			set f1_id [cli_get_value $f1 "" "" "id"]
			set f2_id [cli_get_value $f2 "" "" "id"]
			cli_set_errmsg "The category $cate_1 of filter \"$f2_id\" is already set in another filter \"$f1_id\" for webfiler profile \"$prof\"."
			return 0
		}
	}
	set cate_1 [string trim $cate_1 \"]
	set act [cli_get_value $f1 "" "" "action"]
	if { $act ne "block" } {
		lappend catelist $cate_1
	}
}
set quota [cli_get_tbl_list $CLI_CUR_NODE "quota"]
foreach qt $quota {
	set qid [cli_get_value $qt "" "" "id"]
	set qcat [cli_get_value $qt "" "" "category"]
	if { $qcat eq "" || $qcat eq 0 } {
		cli_set_errmsg "Invalid category for quota $qid."
		return 0
	}
	set qcat [cli_expand_ftgd_categories $qcat]
	foreach cate $qcat {
		set cate [string trim $cate \"]
		set pos [lsearch -exact $catelist $cate]
		if {$pos < 0} {
			cli_set_errmsg "Invalid category $cate for quota $qid."
			return 0
		}
		set catelist [lreplace $catelist $pos $pos]
	}
}
return 1
	%}
	"webfilter profile ftgd-wf filters" = %{
set cat [cli_get_value $CLI_CUR_NODE "" "" "category"]
set cat [string trim $cat \"]
if { ![regexp {^[0-9]} $cat] } {
	cli_set_errmsg "Invalid category ID: $cat"
	return 0
}
cli_schedule_post_check $CLI_CUR_PARENT_NODE "edit"
return 1
	%}
	"webfilter profile ftgd-wf quota" = %{
cli_schedule_post_check $CLI_CUR_PARENT_NODE "edit"
return 1
	%}
	"firewall proxy-address type" = %{
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set new_value [cli_get_value $CLI_CUR_NODE "" "" ""]
set old_value [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { $new_value ne $old_value } {
	if { $old_value ne "" } {
		if { [cli_is_used $CLI_CUR_PARENT_NODE "web-proxy explicit pac-policy" "srcaddr"] } {
			cli_set_errmsg "Can not change type: $name is used in web-proxy explicit pac-policy srcaddr"
			return 0
		}
		if { [cli_is_used $CLI_CUR_PARENT_NODE "firewall proxy-addrgrp" "member"] } {
			cli_set_errmsg "Can not change type: $name is used in firewall proxy-addrgrp member"
			return 0
		}
		if { [cli_is_used $CLI_CUR_PARENT_NODE "firewall proxy-policy" "srcaddr"] } {
			cli_set_errmsg "Can not change type: $name is used in firewall proxy-policy srcaddr"
			return 0
		}
		if { [cli_is_used $CLI_CUR_PARENT_NODE "firewall proxy-policy" "dstaddr"] } {
			cli_set_errmsg "Can not change type: $name is used in firewall proxy-policy dstaddr"
			return 0
		}
		if { [cli_is_used $CLI_CUR_PARENT_NODE "authentication rule" "srcaddr"] } {
			cli_set_errmsg "Can not change type: $name is used in authentication rule srcaddr"
			return 0
		}
	}
}
return 1
	%}
	"firewall proxy-addrgrp" =%{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set members [cli_get_value $CLI_CUR_NODE "" "" "member"]
set dtypes { "host-regex" "url" "category" "dst-advanced" }
foreach member $members {
	set node [cli_get_node $CLI_CUR_VDOM_NODE "firewall proxy-address" $member ""]
	if { $node } {
		set mtype [cli_get_value $node "" "" "type"]
		if { $type eq "src" } {
			if { [lsearch -exact $dtypes $mtype] != -1} {
				cli_set_errmsg "Member \"$member\" has type \"$mtype\" which cannot be used in this proxy address group with type \"$type\""
				return 0
			}
		} else {
			if { [lsearch -exact $dtypes $mtype] == -1} {
				cli_set_errmsg "Member \"$member\" has type \"$mtype\" which cannot be used in proxy address group with type \"$type\""
				return 0
			}
		}
	} else {
		set node [cli_get_node $CLI_CUR_VDOM_NODE "firewall proxy-addrgrp" $member ""]
		if { $node } {
			set gtype [cli_get_value $node "" "" "type"]
			if { $gtype ne $type } {
				cli_set_errmsg "Member proxy address group \"$member\" has conflicting type"
				return 0
			}
		}
	}
}
return 1
	%}
	"system external-resource" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $type eq "category" || $type eq "domain" } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set val [cli_get_value $CLI_CUR_NODE "" "" "category"]
	if { $val eq 0 || $val eq "" } {
		cli_set_errmsg "Category must be set!"
		return 0
	}
	set extlist [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
	foreach ext $extlist {
		set etype [cli_get_value $ext "" "" "type"]
		set ecate [cli_get_value $ext "" "" "category"]
		set ename [cli_get_value $ext "" "" "name"]
		if { $name != $ename && ($etype eq "category" || $etype eq "domain") } {
			if { $ecate == $val } {
				cli_set_errmsg "Category $val is already used in $ename"
				return 0
			}
		}
	}
}
return 1
	%}

	"authentication scheme" = %{
set method [cli_get_value $CLI_CUR_NODE "" "" "method"]
if { [llength $method] eq 0 } {
	cli_set_errmsg "invalid method"
	return 0
}
if { [llength $method] > 1 } {
	set type 0
	foreach m $method {
		switch $m {
			"ntlm" -
			"negotiate" {
				if { $type eq 0 } {
					set type 1
				} elseif { $type ne 1 } {
					cli_set_errmsg "invalid multi-method combination: $method"
					return 0
				}
			}
			"ssh-publickey" {
				if { $type eq 0 } {
					set type 2
				} elseif { $type ne 2 } {
					cli_set_errmsg "invalid multi-method combination: $method"
					return 0
				}
			}
			"basic" {}
			default {
				cli_set_errmsg "invalid multi-method combination: $method"
				return 0
			}
		}
	}
}

if { [lsearch $method "form"] != -1 || [lsearch $method "basic"] != -1 ||
	[lsearch $method "digest"] != -1 ||
	[lsearch $method "ssh-publickey"] != -1 } {
	set userdb [cli_get_value $CLI_CUR_NODE "" "" "user-database"]
	if { $userdb eq "" } {
		cli_set_errmsg "Must configure 'user-database'"
		return 0
	}
}

if { $method eq "digest" } {
set userdb [cli_get_value $CLI_CUR_NODE "" "" "user-database"]
	foreach db $userdb {
		if { [cli_ver_start 600 2] && $db eq "local-user-db" } {
			continue
		} elseif { $db eq "local" } {
			continue
		}
		set usrgrp [cli_get_node $CLI_CUR_VDOM_NODE "user group" $db ""]
		if { $usrgrp ne 0 } {
			if { [cli_get_value $usrgrp "" "" "group-type"] eq "guest" } {
				continue
			}
		}
		cli_set_errmsg "invalid user-database member for digest scheme: $db"
		return 0
	}
}

## only check fsso and rsso service in device-level
if { ([lsearch $method "fsso"] != -1)} {
	set fsso [cli_get_tbl_list $CLI_CUR_VDOM_NODE "user fsso"]
	if { $fsso eq 0 || [llength $fsso] eq 0 } {
		set fssop [cli_get_tbl_list $CLI_CUR_VDOM_NODE "user fsso-polling"]
		if { $fssop eq 0 || [llength $fssop] eq 0 } {
			cli_set_errmsg "cannot choose fsso since no fsso/fsso-polling is configured"
			return 0
		}
	}
}
if { ([lsearch $method "rsso"] != -1)} {
	set rsso [cli_get_tbl_list $CLI_CUR_VDOM_NODE "user radius"]
	set found 0
	if { $rsso eq 0 || [llength $rsso] eq 0 } {
		cli_set_errmsg "cannot choose rsso since no rsso server is configured"
		return 0
	}
	foreach r $rsso {
		if { [cli_get_value $r "" "" "rsso"] eq "enable" } {
			set found 1
			break
		}
	}
	if { $found eq 0 } {
		cli_set_errmsg "cannot choose rsso since no rsso server is enabled"
		return 0
	}
}

## make sure the scheme is still valid for the rules that uses it
set rlist [cli_get_ref_list $CLI_CUR_NODE]
foreach ref $rlist {
	cli_schedule_post_check $ref "edit"
}
return 1
	%}
	"system central-management {fmg type serial-number}" =%{
if { [string match "*json*" [cli_get_clisrc]] || [string match "*script*" [cli_get_clisrc]] } {
	cli_set_errmsg "Attribute '$CLI_CUR_NODE_NAME' cannot be modified"
	return 0
}
return 1
	%}
	"authentication rule srcaddr" = %{
namespace import global::wildcard_fqdn_check
set addr [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [wildcard_fqdn_check $addr "src" 0] } {
        return 0
}
return 1
	%}
	"system interface forward-error-correction" = %{
namespace import global::sys_intf_is_media_iface
namespace import global::platform_digit_suffix
namespace import global::is_platform_support_hyperscale
set platform [cli_get_devinfo "platform"]
set suffix [platform_digit_suffix $platform]
set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set ifname [string trim $ifname \"]
if { [sys_intf_is_media_iface $ifname] } {
	if { [regexp -nocase {6000F|7000E|7000F} $suffix] } {
		## TODO: unknown behaviour
	} elseif { [is_platform_support_hyperscale] } {
		set fec [cli_get_value $CLI_CUR_NODE "" "" ""]
		if { $fec eq "" } {
			cli_set_errmsg "The FEC setting is invalid (do not use unset)."
			return 0
		}
		set speed [cli_get_value $CLI_CUR_PARENT_NODE "" "" "speed"]
		set nofec_speeds {10full 10half 100full 100half 1000full 1000half 1000auto 10000full 10000auto 40000full 40000auto}
		if { [lsearch $nofec_speeds $speed] != -1 && $fec ne "disable" } {
			cli_set_errmsg "The FEC setting should be keep disable on 1/10/40G speed."
			return 0
		}
	} else {
		if { [cli_branchpt_start 700 276] } {
			set fec [cli_get_value $CLI_CUR_NODE "" "" ""]
			if { $fec eq "" } {
				cli_set_errmsg "The FEC setting is invalid (do not use unset)."
				return 0
			}
			set speed [cli_get_value $CLI_CUR_PARENT_NODE "" "" "speed"]
			set nofec_speeds {10full 10half 100full 100half 1000full 1000half 1000auto 10000full 10000auto 40000full 40000auto}
			if { [lsearch $nofec_speeds $speed] != -1 && $fec ne "disable" } {
				cli_set_errmsg "The FEC setting should be keep disable on 1/10/40G speed."
				return 0
			}
		} else {
			return 1
		}
	}
}
return 1
	%}
	"file-filter profile rules" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "file-type"]
if { $type == 0 || $type == "" } {
	cli_set_errmsg "file-type must not be empty."
	return 0
}
return 1
	%}
	"emailfilter block-allow-list entries" = %{
# check if there are 2 entries with same type and pattern
set ents [cli_get_tbl_list [cli_get_parent $CLI_CUR_PARENT_NODE] "entries"]
set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
foreach ent $ents {
	set ent_id [cli_get_value $ent "" "" "id"]
	if { $id != $ent_id } {
		if { $type == [cli_get_value $ent "" "" "type"] } {
			if { $type == "ip" } {
				set ip_type [cli_get_value $CLI_CUR_NODE "" "" "addr-type"]
				if { $ip_type == [cli_get_value $ent "" "" "addr-type"] } {
					if { $ip_type == "ipv4" } {
						set ipv4_subnet [cli_get_value $CLI_CUR_NODE "" "" "ip4-subnet"]
						if { $ipv4_subnet == [cli_get_value $ent "" "" "ip4-subnet"] } {
							set ipv4s [cli_get_value $ent "" "" "ip4-subnet"]
							cli_set_errmsg "Duplicate entries (id $id, $ent_id) with the same type and pattern found (ipv4_subnet): $id: $ipv4_subnet, $ent_id: $ipv4s"
							return 0
						}
					} elseif { $ip_type == "ipv6" } {
						set ipv6_subnet [cli_get_value $CLI_CUR_NODE "" "" "ip6-subnet"]
						if { $ipv6_subnet == [cli_get_value $ent "" "" "ip6-subnet"] } {
							set ipv6s [cli_get_value $ent "" "" "ip6-subnet"]
							cli_set_errmsg "Duplicate entries (id $id, $ent_id) with the same type and pattern found  (ipv6_subnet): $id: $ipv6_subnet, $ent_id: $ipv6s"
							return 0
						}
					}
				}
			} elseif { $type == "email" || $type == "email-to" || $type == "email-from" || $type == "subject" } {
				set pattern_type [cli_get_value $CLI_CUR_NODE "" "" "pattern-type"]
				if { $pattern_type == [cli_get_value $ent "" "" "pattern-type"] } {
					set pattern [cli_get_value $CLI_CUR_NODE "" "" "pattern"]
					set pat [cli_get_value $ent "" "" "pattern"]
					if { $pattern ne "" && $pat ne "" && $pattern eq [cli_get_value $ent "" "" "pattern"] } {
						cli_set_errmsg "Duplicate entries (id $id, $ent_id) with the same type ($type) and pattern found (pattern): $id: $pattern, $ent_id: $pat"
						return 0
					}
				}
			}
		}
	}
}
return 1
	%}
	"dlp profile" = %{
namespace import global::ngfw_mode_policy
set prof_feat_set [cli_get_value $CLI_CUR_NODE "" "" "feature-set"]
set rule_nodes [cli_get_tbl_list $CLI_CUR_NODE "rule"]
foreach rule_node $rule_nodes {
	set rule_id [cli_get_value $rule_node "" "" "id"]
	set rule_type [cli_get_value $rule_node "" "" "type"]
	set rule_filter_by [cli_get_value $rule_node "" "" "filter-by"]
	set rule_proto [cli_get_value $rule_node "" "" "proto"]
	if { $rule_proto eq "" } {
		cli_set_errmsg "rule/$rule_id proto can not be empty."
		return 0
	}
	foreach proto [split $rule_proto " "] {
		if { $proto eq "ssh" } {
			if { $rule_type ne "file" || $prof_feat_set ne "proxy" } {
				cli_set_errmsg "rule/$rule_id proto \"$proto\" only available when dlp profile feature-set is proxy and rule type is file."
				return 0
			}
		}
		if { $proto eq "ftp" || $proto eq "cifs" || $proto eq "http-get" } {
			if { $rule_type ne "file" } {
				cli_set_errmsg "rule/$rule_id proto \"$proto\" only available when rule type is file."
				return 0
			}
		}
		if { $proto eq "mapi" } {
			if { $prof_feat_set eq "flow" } {
				cli_set_errmsg "rule/$rule_id proto \"$proto\" only available when dlp profile feature-set is not flow."
				return 0
			}
			if { [ngfw_mode_policy] } {
				cli_set_errmsg "rule/$rule_id proto \"$proto\" only available when ngfw-mode is not policy."
				return 0
			}
		}
	}
	if { $rule_filter_by eq "fingerprint" || $rule_filter_by eq "mip" } {
		if { $prof_feat_set ne "proxy" } {
			cli_set_errmsg "rule/$rule_id filter-by \"$rule_filter_by\" only available when dlp profile feature-set is proxy."
			return 0
		}
	}
	if { $rule_filter_by eq "fingerprint" || $rule_filter_by eq "mip" || $rule_filter_by eq "encrypted" } {
		if { $rule_type ne "file" } {
			cli_set_errmsg "rule/$rule_id filter-by \"$rule_filter_by\" only available when rule type is file."
			return 0
		}
	}
}
return 1
	%}
	"firewall internet-service-custom reputation" = %{
set rep [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $rep < 1 || $rep > 5 } {
	cli_set_errmsg "Attribute '$CLI_CUR_NODE_NAME' must be between 1 and 5."
	return 0
}
return 1
	%}
	"gtp apn" = %{
set apn [cli_get_value $CLI_CUR_NODE "" "" "apn"]
if { $apn == 0 || $apn eq "" } {
	cli_set_errmsg "Attribute apn must be set."
	return 0
}
return 1
	%}
	"system link-monitor {http-get}" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if { [lsearch $protocol "http"] >= 0 } {
	set http_get [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $http_get eq "" } {
		cli_set_errmsg "http-get cannnot be empty"
		return 0
	}
}
return 1
	%}
	"firewall sniffer" = %{
set intfname [cli_get_value $CLI_CUR_NODE "" "" "interface"]
set inttfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $intfname ""]
if { $inttfnode } {
	set intfvdom [cli_get_value $inttfnode "" "" "vdom"]
	if { $intfvdom ne $CLI_CUR_VDOM_NAME } {
		if { [string trim $intfvdom \"] ne $CLI_CUR_VDOM_NAME } {
			cli_set_errmsg "interface vdom ($intfvdom) does not belong to current vdom ($CLI_CUR_VDOM_NAME)"
			return 0
		}
	}
}
return 1
	%}
	"system settings policy-offload-level" = %{
set nv [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $nv eq "full-offload" } {
	if { $CLI_CUR_VDOM_NAME ne "root" && ![regexp {^.*-hw\d+$} $CLI_CUR_VDOM_NAME] } {
		cli_set_errmsg "Full-offload cannot be enabled on this VDOM as its VDOM name does not meet the rules \"<prefix>-hw<number>\"."
		return 0
	}
}
return 1
	%}
	"icap profile icap-headers content" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
set items [regexp -all -inline {\$\w+} $value]
foreach item $items {
	set valid 0
	foreach pattern {"\$client-ip" "\$user" "\$upn" "\$domain" "\$local_grp" "\$remote_grp" "\$proxy_name"} {
		if { [string first $pattern $item] == 0 } {
			set valid 1
			break
		}
	}
	if { [cli_branchpt_start 700 1366] } {
		foreach pattern {"\$auth_user_uri" "\$auth_group_uri"} {
			if { [string first $pattern $item] == 0 } {
				set valid 1
				break
			}
		}
	}
	if { !$valid } {
		cli_set_errmsg "the icap-headers content includes un-supported pattern \"$item\""
		return 0
	}
}
return 1
	%}
%};
