nodecheck %{
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
if { [cli_is_used $CLI_CUR_PARENT_NODE "system ha ha-mgmt-interfaces" "interface"] } {
        cli_set_errmsg "system interface \"$ifname\" set ip $ip \[HA configuration is not allowed to be changed in HA mode\]"
        return 0
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
		} else {
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
	set status "status"
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
if {$type eq "vlan"} {
    if { [string compare $ifname "wlan"] != 0 && [string compare $ifname "modem"] != 0 } {
	set vlanid [cli_get_value $CLI_CUR_NODE "" "" "vlanid"]
        if {$vlanid < 1 || $vlanid > 4094} {
                cli_set_errmsg "VLAN id must between 1 to 4094"
		return 0
        }
	set phyname [cli_get_value $CLI_CUR_NODE "" "" "interface"]
	if {$phyname eq ""} {
		cli_set_errmsg "invalid interface"
		return 0
	}
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
	set vsmax [cli_feature_value "max_vlan_num"]
	if { $vsmax > 0 } {
		set pintf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
		set nr [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "interface" 0 $pintf "type" 0 "vlan"]
		if { $nr > $vsmax } {
			cli_set_errmsg "$pintf already got maximum vlan entries (max is $vsmax)"
			return 0
		}
	}
	set phyname [cli_get_value $CLI_CUR_NODE "" "" "interface"]
	set pnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $phyname ""]
	namespace import global::nCfg_is_port_pair_member
	if {[nCfg_is_port_pair_member $pnode]} {
		cli_set_errmsg "Can not create vlan interface on Virtual Wire Pair members."
		return 0
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

		"pppoe" { if { [report_mtu_range_notpass $mtu 576 [expr ($max-8)] "PPPoE"] } { return 0 } }
		"static" { if { [report_mtu_range_notpass $mtu $min $max "static"] } { return 0 } }
		"ipoa" { if { [report_mtu_range_notpass $mtu 68 65527 "IPoA"] } { return 0 } }
		"pppoa" { if { [report_mtu_range_notpass $mtu 576 1500 "PPPoA"] } { return 0 } }
		}
}
return 1
	%}

	"system interface vlanid" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if {$type ne "vlan"} {
	return 1
}

if {$CLI_ACT eq "add"} {
        set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]       
	if {$type eq "vlan"} {
		set vlanid [cli_get_value $CLI_CUR_NODE "" "" ""]
		set phyintf [cli_get_value $CLI_CUR_PARENT_NODE "" "" "interface"]
		set nr [cli_get_match_nr $CLI_GLOBAL_NODE 1 "system interface" "vlanid" 0 $vlanid "interface" 0 $phyintf "type" 0 "vlan"]
		if {$nr > 1} {
			cli_set_errmsg "The VLAN id $vlanid already been used"
			return 0
		}
	}
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
		} else {
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
if { $profilename eq "" || \
     $profilename eq "FGT_ha_acc_profile" || \
     $profilename eq "prof_fmgr_access" || \
     $profilename eq "super_admin" || \
     $profilename eq "super_admin_readonly" } {
     cli_set_errmsg "invalid profile name"
     return 0
}
return 1
	%}
	"firewall policy service" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] } {
	return 1
}
set potype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $potype eq "explicit-ftp" || $potype eq "ssh" || $potype eq "access-proxy" } {
	return 1
}
set service [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $service eq "" } {
	set id [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
	cli_set_errmsg "service in Policy \"$id\" cannot be empty."
	return 0
}
return 1
	%}

	"firewall policy schedule" = %{
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
	if { $type ne "ipmask" && ([cli_get_value $CLI_CUR_NODE "" "" "allow-routing"] eq "enable") } {
			cli_set_errmsg "cannot change the type if it is enabled for routing"
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

if { $intf_new == $intf_old || ($intf_old eq "" && $intf_new eq "any") } {
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
if { $grpmember eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
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
if { $grpmember eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
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

	if {($vipname eq "FGh_FtMngr") || ($vipname eq "FGh_FtiLog1") || ($vipname eq
	"FGh_FtiLog2") || ($vipname eq "FGh_FtiLog3")} {
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
if {$intf != "any"} {
	if {[cli_get_node $CLI_GLOBAL_NODE "system interface" $intf ""] == 0} {
		cli_set_errmsg "system interface \"$intf\" not exist"
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
set proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if { $proto eq "icmp" } {
	return 1
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
                if {$intf != "any" && $port != "any"} {
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

      "ips custom" = %{
set tag [cli_get_value $CLI_CUR_NODE "" "" ""]
set signature [cli_get_value $CLI_CUR_NODE "" "" "signature"]
set signature [string trim $signature '"']
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
	"log {fortianalyzer fortianalyzer2 fortianalyzer3} {setting}" = %{
set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
set ipv6addr 0
if {$status eq "enable"} {
	set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
	set server [string trim $server \"]
	if { $server eq "" || $server eq "0.0.0.0" } {
		cli_set_errmsg "Please set server ip address"
		return 0
	}
	if { $server eq "::" } {
		cli_set_errmsg "Please set server ip address"
		return 0
	}
	if { [string first ":" $server] > -1 } {
		set ipv6addr 1
	}
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
				if { $uploadopt eq "store-and-upload" } {
					cli_set_errmsg "conflict value with log.disk.setting"
					return 0
				}
			}
		}
	}
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
	if {[cli_get_value $CLI_CUR_NODE "" "" "sms-phone"] eq ""} {
		cli_set_errmsg "You must specify an SMS phone number."
		return 0
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
set dn [cli_get_value $CLI_CUR_NODE "" "" "dn"]
if { $dn eq "" } {
	cli_set_errmsg "Distinguished name cannot be empty."
	return 0
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
set scrt [cli_get_value $CLI_CUR_NODE "" "" "secret"]
if { $scrt eq "" } {
	cli_set_errmsg "secret cannot be empty."
	return 0
}
set rsso [cli_get_value $CLI_CUR_NODE "" "" "rsso"]
if { $rsso eq "enable" } {
	if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "rsso" 0 "enable"] > 1} {
		cli_set_errmsg "only one RSSO agent is allowed"
		return 0
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
set uname [cli_get_value $CLI_CUR_NODE "" "" "user-name"]
if { $uname == 0 || $uname eq "" } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	cli_set_errmsg "user saml \"$name\" cannot have empty user-name."
	return 0
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

	"user group group-type" = %{
namespace import global::user_group_check_type
set gname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set gname [string trim $gname \"]
if { $gname eq "SSO_Guest_Users" } {
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
	if { $grpname eq "SSO_Guest_Users" } {
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
if {$CLI_ACT ne "add"} {
	set ntype [cli_get_value $CLI_CUR_NODE "" "" "explicit-proxy"]
	set otype [cli_get_org_value $CLI_CUR_NODE "" "" "explicit-proxy"]
	if {[string compare $ntype $otype]} {
		cli_set_errmsg "Cannot change whether this service group is used for explicit proxy, once the group is created"
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

if { $type eq "static" } {
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
		set ipver [cli_get_value $CLI_CUR_NODE "" "" "mode-cfg-ip-version"]
		if {$ipver eq "6"} {
			set startip [cli_get_value $CLI_CUR_NODE "" "" "ipv6-start-ip"]
			set endip [cli_get_value $CLI_CUR_NODE "" "" "ipv6-end-ip"]
			if {$startip eq "" || $startip eq "::" || $endip eq "" || $endip eq "::" } {
				cli_set_errmsg "ipv4-start-ip/ipv4-end-ip cannot be ::"
				return 0
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
		set netdev [cli_get_value $CLI_CUR_NODE "" "" "net-device"]
		set extra_errmsg 1
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
}
set usrgrp [cli_get_value $CLI_CUR_NODE "" "" "usrgrp"]
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
	"vpn ipsec phase1-interface local-gw6" = %{
set local_gw6 [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$local_gw6 ne "" && $local_gw6 ne "::"} {
	set gw6_list [split $local_gw6 :]
	set gw6_byte [expr 0x[lindex $gw6_list 0]]
	set gw6_byte [expr $gw6_byte >> 8]
	if {$gw6_byte == 0xff} {
		cli_set_errmsg "invalid value 004"
		return 0
	}
	set gw6_byte [expr 0x[lindex $gw6_list end]]
	if {$gw6_byte == 1} {
		cli_set_errmsg "invalid value 005"
		return 0
	}
	foreach e $gw6_list {
		if {[string length $e] != 0} {
		if {[expr 0x$e] != 0} {
			break
		}
		}
		cli_set_errmsg "invalid value 006"
		return 0
	}
}
return 1
	%}
	"vpn ipsec phase1-interface remote-gw6" = %{
set remote_gw6 [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$remote_gw6 ne "" && $remote_gw6 ne "::"} {
	set gw6_list [split $remote_gw6 :]
	set gw6_byte [expr 0x[lindex $gw6_list 0]]
	set gw6_byte [expr $gw6_byte >> 8]
	if {$gw6_byte == 0xff} {
		cli_set_errmsg "invalid value 003"
		return 0
	}
	set gw6_byte [expr 0x[lindex $gw6_list end]]
	if {$gw6_byte == 1} {
		cli_set_errmsg "invalid value 002"
		return 0
	}
	foreach {e} $gw6_list {
		if {[string length $e] != 0} {
		if {[expr 0x$e] != 0} {
			break
		}
		}
		cli_set_errmsg "invalid value 001"
		return 0
	}
}
return 1
	%}
        "vpn ipsec phase1-interface peer" = %{
if { ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peertype" 0 "peer"] } {
	return 1
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
set monitor [string trim $monitor '"']
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
	"vpn ipsec phase1-interface usrgrp" = %{
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
	"vpn ipsec phase1-interface {xauthtype authusrgrp ike-version eap}" = %{
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
	"vpn ipsec phase1-interface psksecret" = %{
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
namespace import global::cli_sys_global_split_vdom
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
if { 1 } {
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

	"system admin" = %{
set admin_vdom [cli_get_value $CLI_CUR_NODE "" "" "vdom"]
set vnode [cli_get_vdom_node $admin_vdom]
set a 1
set gauth [cli_get_value $CLI_CUR_NODE "" "" "guest-auth"]
if { $gauth eq "enable" } {
	set a 0
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
	if {[cli_get_value $CLI_CUR_NODE "" "" "sms-phone"] eq ""} {
		cli_set_errmsg "You must specify an SMS phone number."
		return 0
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

if {[regexp {^\s*"?(ssh-rsa|ssh-dss)\s*AAAAB3NzaC1} $pkey] == 0} {
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

if {[regexp {^\s*"?(ssh-rsa|ssh-dss)\s*AAAAB3NzaC1} $pkey] == 0} {
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

if {[regexp {^\s*"?(ssh-rsa|ssh-dss)\s*AAAAB3NzaC1} $pkey] == 0} {
	cli_set_errmsg "invalid value"
	return 0
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
set status "status"
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
if { [cli_get_value $CLI_CUR_NODE "" "" "action"] ne "reserved" } {
	return 1
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
	if { [cli_get_value $e "" "" "action"] ne "reserved" } {
		continue
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
	if {$sub != "" && $sub != "\"\""
		&& ! [regexp {^[-a-zA-Z0-9]+(\.[-a-zA-Z0-9]+)*$} $sub]} {
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
if {! [regexp {^\"[-a-zA-Z0-9]+(\.[-a-zA-Z0-9]+)*\"$} $domain] && ! [regexp {^[-a-zA-Z0-9]+(\.[-a-zA-Z0-9]+)*$} $domain]} {
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
set mode [cli_get_value $CLI_CUR_NODE "" "" "mode"]
if {$mode eq "a-a" || $mode eq "a-p"} {
	set hbdev [cli_get_value $CLI_CUR_NODE "" "" "hbdev"]
	set i 0
	foreach e $hbdev {
		if {($i % 2) == 0} {
			set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $e ""]
			if {$intfnode != 0} {
				set type [cli_get_value $intfnode "" "" "type"]
				set aggr [cli_get_value $intfnode "" "" "aggregate"]
				if {$type ne "physical" || $aggr ne ""} {
					cli_set_errmsg "invalid value"
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
set id [cli_get_value $CLI_CUR_NODE "" "" ""]
set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "ip" 0 $ip] > 1} {
	cli_set_errmsg "duplicate"
	return 0
}
if {$ip ne ""} {
	set iplist [split $ip .]
	set ipbyte1 [lindex $iplist 0]
	if {$ipbyte1 != 0 && $ipbyte1 & 0x0ff != 127 && ($ipbyte1 & 0xf0 == 0xe0 || $ip eq "255.255.255.255")} {
		cli_set_errmsg "invalid ip"
		return 0
	}

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

	"system global gui-device-latitude" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$value eq ""} { set value 0 }
if { $value > 90 || $value < -90} {
	cli_set_errmsg "Please enter a coordinate value in the range of (-90 to 90)"
	return 0
}
return 1
	%}

	"system global gui-device-longitude" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$value eq ""} { set value 0 }
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
if {$CLI_ACT ne "add"} {
	cli_set_errmsg "cannot modify"
	return 0
}
return 1
	%}
	"system gre-tunnel local-gw" = %{
if {$CLI_ACT ne "add"} {
	cli_set_errmsg "cannot modify"
	return 0
}
return 1
	%}
	"system gre-tunnel interface" = %{
if {$CLI_ACT ne "add"} {
	cli_set_errmsg "cannot modify"
	return 0
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
if { $grpmember eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
namespace import global::addr6_all_exist
set addr_all [addr6_all_exist $grpmember]
return 1
	%}

	"firewall address6" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {[cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp6" $name ""] != 0} {
	cli_set_errmsg "addr/addrgrp conflict"
	return 0
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

if { $ptype == "fixed-port-range" } {
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
if { 1 } {
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
			if {(($fazlog_status eq "enable" && $fazlog_uplopt eq "store-and-upload") ||
				($faz2log_status eq "enable" && $faz2log_uplopt eq "store-and-upload") || 
				($faz3log_status eq "enable" && $faz3log_uplopt eq "store-and-upload"))} {
				cli_set_errmsg "conflict value"
				return 0
			}
		}
	}
	if { 1 } {
		namespace import global::cli_sys_global_vdom_enable
		if { [cli_sys_global_vdom_enable] == 0 } {
			set fazlog_status [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "status"]
			if { $fazlog_status eq "enable" } {
				set fazlog_uplopt [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "upload-option"]
				if { $fazlog_uplopt eq "store-and-upload" } {
					cli_set_errmsg "FortiAnalyzer is enabled in Store-and-Upload mode.\nCan't be disabled because remote log upload has been enabled."
					return 0
				}
			}
			set fdslog_status [cli_get_value $CLI_GLOBAL_NODE "log fortiguard setting" "" "status"]
			if { $fdslog_status eq "enable" } {
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

	"router static" = %{
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
set dst [cli_get_value $CLI_CUR_NODE "" "" "dst"]
set gw [cli_get_value $CLI_CUR_NODE "" "" "gateway"]
set blackhole [cli_get_value $CLI_CUR_NODE "" "" "blackhole"]
set sdwan "virtual-wan-link"
set vwan [cli_get_value $CLI_CUR_NODE "" "" $sdwan]
set dyn_gw [cli_get_value $CLI_CUR_NODE "" "" "dynamic-gateway"]
set device [cli_get_value $CLI_CUR_NODE "" "" "device"]
set intserv [cli_get_value $CLI_CUR_NODE "" "" "internet-service"]
set intserv_cust [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom"]
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "nat" && $device eq "" && $blackhole eq "disable" && $vwan eq "disable" } {
	cli_set_errmsg "device can not be empty."
	return 0
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
		}
		set seq_num [cli_get_value $e "" "" "seq-num"]
		cli_set_errmsg "entry cannot be created, duplicate of static route $seq_num"
		return 0
	}
}
if { 1 } {
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
	if { 1 } {
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
set sdwan "virtual-wan-link"
set device [cli_get_value $CLI_CUR_NODE "" "" "device"]
set vwan [cli_get_value $CLI_CUR_NODE "" "" $sdwan]
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "nat" && $device eq "" && $blackhole eq "disable" && $vwan eq "disable" } {
	cli_set_errmsg "device can not be empty."
	return 0
}
if { [intf_not_match_vdom [string map {\" ""} $device] [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"] $CLI_CUR_VDOM_NAME] } {
	cli_set_errmsg "interface $device does not belong to current vdom $CLI_CUR_VDOM_NAME."
	return 0
}
return 1
	%}

	"dlp sensor filter" = %{
if { 1 } {
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
set ip [cli_get_value $CLI_CUR_NODE "" "" "server-ip"]
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
		if { $ip eq "" } {
			if { [cli_ver_start 600 0] } {
				cli_set_errmsg "Attribute server must be set"
				return 0
			}
		} else {
			if { $ctype ne "openstack" && $ctype ne "vmware" && $ctype ne "aci-direct" && $ctype ne "nsx" } {
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
        if {$name eq "Local FSSO Agent"} {
                if { $svr ne "127.0.0.1" } {
                        cli_set_errmsg "invalid value"
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
if { 1 } {
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
	"firewall central-snat-map {srcintf dstintf}" = %{
namespace import global::intf_dedicated_to_mgmt
if { [intf_dedicated_to_mgmt] } {
    return 0
}
return 1
	%}
	"firewall central-snat-map dst-addr" = %{
namespace import global::wildcard_fqdn_check
set addr [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [wildcard_fqdn_check $addr "src" 0] } {
        return 0
}
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
	"vpn ipsec phase1-interface certificate" = %{
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
        "firewall ssl-ssh-profile ssl-exempt fortiguard-category" = %{
set c [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $c ne "" && $c ne 0 } {
	set c [string trim $c \"]	
        if { [string is integer $c] == 0 || $c eq "0" } {
                cli_set_errmsg "unsupport fortiguard-category value \"$c\""
                return 0
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
	"application custom id" = %{
set nid [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ($nid != 0) && ($nid < 1000 || $nid > 9999) } {
	cli_set_errmsg "custom signature id must be between 1000 and 9999"
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
        "ips sensor entries" = %{
if {[cli_get_tbl_cnt $CLI_CUR_PARENT_NODE "entries"] > 256} {
	cli_set_errmsg "Exceed the maximum number of entries in ips sensor(max : 256)"
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
}
if { [cli_ver_start 600 4] } {
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
	"firewall {address address6 addrgrp addrgrp6 proxy-address proxy-addrgrp} tagging" = %{
namespace import global::check_obj_tagging
if { [check_obj_tagging $CLI_CUR_NODE] eq 0 } {
	return 0
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
		if { [cli_is_used $CLI_CUR_PARENT_NODE "web-proxy pac-policy" "srcaddr"] } {
			cli_set_errmsg "Can not change type: $name is used in web-proxy explicit pac-policy srcaddr"
			return 0
		}
		if { [cli_is_used $CLI_CUR_PARENT_NODE "firewall proxy-addrgrp" "member"] } {
			cli_set_errmsg "Can not change type: $name is used in firewall proxy-addrgrp member"
			return 0
		}
		if { [cli_is_used $CLI_CUR_PARENT_NODE "firewall policy" "srcaddr"] } {
			cli_set_errmsg "Can not change type: $name is used in firewall proxy-policy srcaddr"
			return 0
		}
		if { [cli_is_used $CLI_CUR_PARENT_NODE "firewall policy" "dstaddr"] } {
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
			if { [cli_get_value $usrgrp "" "" "group-type"] eq "guest" }
			continue
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
	"web-proxy pac-policy" = %{
set policyid [cli_get_value $CLI_CUR_NODE "" "" "policyid"]
if { $policyid < 1 || $policyid > 100 } {
	cli_set_errmsg "Attribute policyid must be between 1 and 100."
	return 0
}
set pac_file_data [cli_get_value $CLI_CUR_NODE "" "" "pac-file-data"]
if { $pac_file_data == 0 || $pac_file_data eq "" } {
	cli_set_errmsg "Attribute pac-file-data can not be empty!"
	return 0
}
set srcaddr [cli_get_value $CLI_CUR_NODE "" "" "srcaddr"]
set srcaddr6 [cli_get_value $CLI_CUR_NODE "" "" "srcaddr6"]
if { ($srcaddr == 0 || $srcaddr eq "") && ($srcaddr6 == 0 || $srcaddr6 eq "") } {
	cli_set_errmsg "Attribute srcaddr or srcaddr6 can not be empty!"
	return 0
}
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
if { $dstaddr == 0 || $dstaddr eq "" } {
	cli_set_errmsg "Attribute dstaddr can not be empty!"
	return 0
}
return 1
	%}
%};
