nodeact %{
	"firewall policy capture-packet" = %{
if { [string match "*override*" [cli_get_clisrc]] } { return 1 }
if { [cli_obj_support "firewall policy" "auto-asic-offload"] } {
	set cappkt [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $cappkt eq "enable" } {
		set cmd "set auto-asic-offload disable\n"
	} else {
		set cmd "set auto-asic-offload enable\n"
	}
	cli_exec_cmd $CLI_CUR_PARENT_NODE $cmd
}
return 1
	%}

        "system vdom" = %{
namespace import global::cli_sys_global_split_vdom
if {$CLI_ACT eq "add"} {
	set plat [cli_get_devinfo "platform"]
	set fullname [cli_get_value $CLI_CUR_NODE "" "" ""]
	set findex [string first "/" $fullname]
	if { $findex > 0 } {
		set vdname [string range $fullname 0 $findex-1 ]
	} else {
		set vdname $fullname
	}
	if { [cli_sys_global_split_vdom] && ($vdname ne "FG-traffic") } {
		cli_set_errmsg "Can not add vdom $vdname in split-vdom mode."
		return 0
	}
	set opmode [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"]
	namespace import global::dmgmt_vdom_support
	set dmgmt [dmgmt_vdom_support]
	if {$dmgmt && ($vdname eq "dmgmt-vdom")} {
		# do nothing when vdom is "dmgmt-vdom"
	} else {
		if { [cli_ver_start 500 4] } {
			if { [cli_branchpt_start 500 1099] } {
				if { [cli_has_feature "f_caputp_ac"] } {
					cli_exec_cmd $CLI_CUR_VDOM_NODE "config switch-controller switch-profile\nedit \"default\"\nnext\nend\n"
				}
			}
		} else {
			set hanode [cli_get_node $CLI_GLOBAL_NODE "system ha" "" ""]
			if {$hanode != 0} {
				set ha_vdoms [cli_get_value $hanode "" "" "vdom"]
				append ha_vdoms " $vdname"
				cli_exec_cmd $CLI_GLOBAL_NODE "config system ha\nset vdom $ha_vdoms\nend\n"
			}
		}

		set description "\"property limits for vdom "
		append description $vdname
		append description "\""
		set r [cli_exec_cmd $CLI_GLOBAL_NODE "config system vdom-property\nedit $vdname\nset description $description\nnext\nend\n"]
		if { $r ne 0 } {
			return 0
		}
		if {[cli_obj_support "system vdom-property" "snmp-index"]} {
			namespace import global::set_vdom_snmp_index
			set_vdom_snmp_index $vdname
		}
	}
	if { $opmode eq "nat" } {
		if { [cli_has_feature "f_sslvpn"] } {
			namespace import global::get_mux_tunnel_dev_name
			set intfname [get_mux_tunnel_dev_name $fullname]
			cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $intfname\nset vdom $vdname\nset type tunnel\nset alias \"SSL VPN interface\"\nnext\nend\n"
			if {[cli_obj_support "system interface" "snmp-index"]} {
				namespace import global::auto_set_snmp_index
				auto_set_snmp_index $intfname
			}
			cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall address\nedit \"SSLVPN_TUNNEL_ADDR1\"\nset associated-interface \"$intfname\"\nnext\nend\n"
		}	
	} elseif { $opmode eq "transparent" } {
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config router static\nedit 1\nnext\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config router static6\nedit 1\nnext\nend\n"
	}

	namespace import global::sync_certs_between_global_vdom
	set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate local"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate local\n$cmd\nend\n"
	set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate crl"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate crl\n$cmd\nend\n"
	set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate ca"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate ca\n$cmd\nend\n"
	set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate remote"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate remote\n$cmd\nend\n"

	if { [cli_has_feature "f_netx"] } {
		namespace import global::get_shadow_intf_name
		namespace import global::auto_set_snmp_index
		set nint [get_shadow_intf_name "" $vdname "-int"]
		set mac [cli_gen_macaddr]
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $nint\nset vdom $vdname\nset type physical\nset macaddr $mac\nset mtu-override enable\nset mtu 65521\nnext\nend\n"
		auto_set_snmp_index $nint
		set next [get_shadow_intf_name "" $vdname "-ext"]
		set mac [cli_gen_macaddr]
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $next\nset vdom $vdname\nset type physical\nset macaddr $mac\nset mtu-override enable\nset mtu 65521\nnext\nend\n"
		auto_set_snmp_index $next
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config system virtual-wire-pair\nedit $vdname\nset member \"$nint\" \"$next\"\nnext\nend\n"
	}
	set cmd  "config wireless-controller wtp-profile\nedit \"FAP220B-default\"\nconfig platform\nset type 220B\nend\nnext\nend\n"
	cli_exec_cmd  $CLI_CUR_VDOM_NODE $cmd
	set cmd  "config wireless-controller wtp-profile\nedit \"FAP221E-default\"\nconfig platform\nset type 221E\nend\nnext\nend\n"
	cli_exec_cmd  $CLI_CUR_VDOM_NODE $cmd
	if { [cli_obj_support "switch-controller auto-config default" "fgt-policy"] } {
		if { [cli_branchpt_start 600 1008] } {
			set icl_defval "default-icl"
		} else {
			set icl_defval "default"
		}
		set cmd  "config switch-controller auto-config default\nset fgt-policy default\nset isl-policy default\nset icl-policy $icl_defval\nend\n"
		cli_exec_cmd  $CLI_CUR_VDOM_NODE $cmd
	}
	if { ![cli_branchpt_start 600 1068] && ![string match -nocase $plat "FortiGateRugged-60F-3G4G"] } {
		set prof_node [cli_get_node $CLI_CUR_VDOM_NODE "wireless-controller wtp-profile" "FAPU431F-default" ""] 
		if { $prof_node } { 
			set cmd  "config wireless-controller wtp-profile\nedit \"FAPU431F-default\"\n"
			append cmd "config radio-1\nset band 802.11ax-5G\nend\n"
			append cmd "config radio-2\nset band 802.11ax-5G\nend\n"
			append cmd "config radio-3\nset mode ap\nset band 802.11n,g-only\nend\nnext\nend\n"
			cli_exec_cmd  $CLI_CUR_VDOM_NODE $cmd
                }
		set prof_node [cli_get_node $CLI_CUR_VDOM_NODE "wireless-controller wtp-profile" "FAPU433F-default" ""] 
		if { $prof_node } { 
			set cmd  "config wireless-controller wtp-profile\nedit \"FAPU433F-default\"\n"
			append cmd "config radio-1\nset band 802.11ax-5G\nend\n"
			append cmd "config radio-2\nset band 802.11ax-5G\nend\n"
			append cmd "config radio-3\nset mode ap\nset band 802.11n,g-only\nend\nnext\nend\n"
			cli_exec_cmd  $CLI_CUR_VDOM_NODE $cmd
                }
	}
}
if { ![cli_branchpt_start 600 933] } {
	# 6.2.1 vdom sysdefconf
	set fwlist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall address"]
	foreach fwnode $fwlist {
		set atype [cli_get_value $fwnode "" "" "type"]
		if { $atype eq "fqdn" } {
			set aname [cli_get_value $fwnode "" "" "name"]
			set afqdn [cli_get_value $fwnode "" "" "fqdn"]
			if { [regexp {[\*?]} $afqdn] } {
				cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall address\nedit $aname\nset type wildcard-fqdn\nset wildcard-fqdn $afqdn\nnext\nend\n"
			}
		}
	}
}
cli_on_rlimit_change
return 1
        %}
	"user fsso-polling" = %{
set fsso [cli_get_node $CLI_CUR_VDOM_NODE "user fsso" "Local FSSO Agent" ""]
if { $fsso == 0 } {
	set server [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config user fsso\nedit \"Local FSSO Agent\"\nset ldap-server $server\nset server \"127.0.0.1\"\nnext\nend\n"
}
return 1

set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
if { $status eq "enable" } {
	if { $fsso == 0 } {
		set server [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config user fsso\nedit	\"Local FSSO Agent\"\nset ldap-server $server\nset server \"127.0.0.1\"\nnext\nend\n"
	}
} else {
	if { $fsso != 0 } {
		set fssoldap [cli_get_value $fsso "" "" "ldap-server"]
		set curldap [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]

		if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "status" 0 "enable"] == 0 } {
			cli_delete_node $fsso
		} elseif { $curldap eq $fssoldap }  {
			# select another node for the new new local fsso agent
			set list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
			foreach node $list {
				set status [cli_get_value $node "" "" "status"]
				set server [cli_get_value $node "" "" "ldap-server"]
				if { $server == 0 || $status ne "enable" } {
					continue
				}

				cli_exec_cmd $CLI_CUR_VDOM_NODE "config user fsso\nedit \"Local FSSO Agent\"\nset ldap-server $server\nset server \"127.0.0.1\"\nnext\nend\n"
				break
			}
		}
	}
}
return 1
	%}
	"wireless-controller vap security" = %{
set sec [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $sec eq "captive-portal" } {
	set vapname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	set intravap [cli_get_value $CLI_CUR_PARENT_NODE "" "" "intra-vap-privacy"]
	set localswitch [cli_get_value $CLI_CUR_PARENT_NODE "" "" "local-switching"] 
	set localbridge [cli_get_value $CLI_CUR_PARENT_NODE "" "" "local-bridging"] 
	if { $intravap ne "enable" || $localswitch ne "disable" || $localbridge ne "disable" } {
		set cmd  "config wireless-controller vap\nedit $vapname\nset intra-vap-privacy enable\nset local-switching disable\nset local-bridging  disable\nend\n"
		cli_exec_cmd  $CLI_CUR_VDOM_NODE  $cmd
	}
}
return 1
	%}

	"wireless-controller wtp-profile split-tunneling-acl" = %{
		set name [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "name" ]
		set idx [cli_get_value $CLI_CUR_NODE "" "" "id" ]
		set dstip [cli_get_value $CLI_CUR_NODE "" "" "dest-ip" ]
		if { $dstip ne "" } {
			set newip [cli_format_ipmask $dstip 0]
			set cmd "config wireless-controller wtp-profile\nedit $name\nconfig split-tunneling-acl\nedit $idx\nset dest-ip $newip\nnext\nend\nnext\nend\n"
			cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		}

return 1
	%}
	"wireless-controller wtp-profile {radio-1 radio-2}" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" "vap-all"] eq "enable" } {
	cli_clear_value $CLI_CUR_NODE "" "" "vaps"
}
return 1
 	%}
	"extender-controller extender" = %{
set admin [cli_get_value $CLI_CUR_NODE "" "" "admin"]
if { $admin eq "enable" } {
			set intf_name [cli_get_value $CLI_CUR_NODE "" "" "ifname"]
			if { $intf_name eq "" } {
				set intf_name "fext-wan1"
				set id [cli_get_value $CLI_CUR_NODE "" "" "" ]
				set cmd "config extender-controller extender\nedit $id\nset ifname  $intf_name\nend\n"
				cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
			}
			set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $intf_name ""]
			if { $intfnode == 0 } {
				set cmd "config system interface\nedit \"$intf_name\"\nset vdom $CLI_CUR_VDOM_NAME\nset mode dhcp\nset type fext-wan\nend\n"
				cli_exec_cmd $CLI_GLOBAL_NODE $cmd
			}
}
if { $CLI_ACT eq "add" } {
	if { [cli_is_match $CLI_GLOBAL_NODE 0 "system global" "fortiextender" 0 "enable"] } {
		set auth [cli_get_value $CLI_CUR_NODE "" "" "authorized"]
		if { $auth eq "enable" && [cli_obj_support "extender-controller extender modem1"] } {
			set ifname [cli_get_value $CLI_CUR_NODE "modem1" "" "ifname"]
			if { $ifname eq "" } {
				set intfs [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
				foreach intf $intfs {
					set type [cli_get_value $intf "" "" "type"]
					if { $type eq "fext-wan" } {
						set ifname [cli_get_value $intf "" "" "name"]
						break
					}
				}
				if { $ifname eq "" } {
					set ifname "FEXT"
					set cmd "config system interface\nedit \"$ifname\"\nset vdom $CLI_CUR_VDOM_NAME\nset mode dhcp\nset type fext-wan\nset role wan\nend\n"
					cli_exec_cmd $CLI_GLOBAL_NODE $cmd
					set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $ifname ""]
					if { $intfnode } {
						set id [cli_get_value $CLI_CUR_NODE "" "" "" ]
						set cmd "config extender-controller extender\nedit $id\nconfig modem1\nset ifname $ifname\nend\nend\n"
						cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
						namespace import global::auto_set_snmp_index
						auto_set_snmp_index $ifname
					}
				} else {
					set id [cli_get_value $CLI_CUR_NODE "" "" "" ]
					set cmd "config extender-controller extender\nedit $id\nconfig modem1\nset ifname $ifname\nend\nend\n"
					cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
				}
			}
		}
	} else {
		set auth [cli_get_value $CLI_CUR_NODE "" "" "authorized"]
		if { $auth ne "disable" } {
			set id [cli_get_value $CLI_CUR_NODE "" "" "" ]
			set cmd "config extender-controller extender\nedit $id\nset authorized disable\nend\n"
			cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		}
	}
}
return 1
	%}
	"system interface" = %{
namespace import global::global_admin_https_redirected_valid
if { [global_admin_https_redirected_valid] } {
	if { [cli_is_match $CLI_GLOBAL_NODE 0 "system global" "admin-https-redirect" 0 "enable"] } {
		set allows [cli_get_value $CLI_CUR_NODE "" "" "allowaccess"]
		set http_exist 0
		set https_exist 0
		foreach a $allows {
			if { $a eq "http" } {
				set http_exist 1
			} elseif { $a eq "https" } {
				set https_exist 1
			}
		}
		if { $http_exist == 1 && $https_exist == 0 } {
			append allows " https"
			set name [cli_get_value $CLI_CUR_NODE "" "" ""]
			cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit \"$name\"\nset allowaccess $allows\nend\n"
		}
	}
}
if {[cli_obj_support "system interface" "snmp-index"]} {
        namespace import global::auto_set_snmp_index
        set intfname [cli_get_value $CLI_CUR_NODE "" "" "name"]
        auto_set_snmp_index $intfname
}
set old_speed [cli_get_org_value $CLI_CUR_NODE "" "" "speed"]
set speed [cli_get_value $CLI_CUR_NODE "" "" "speed"]
if { $old_speed ne $speed && ( $old_speed eq "25000full" || $speed eq "25000full" ) } {
	namespace import global::get_intf_speed_group
	set plat [cli_get_devinfo "platform"]
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set group [get_intf_speed_group $plat $name]
	if { $group ne "" } {
		set fec "disable"
		if { $speed eq "25000full" || $speed eq "100Gfull" } {
			set fec "fec-cl91"
		}
		set intfs [split $group " "]
		foreach intf $intfs {
			if { $intf ne $name } {
				cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit \"$intf\"\nset speed $speed\nset forward-error-correction $fec\nend\n"
			} else {
				cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit \"$intf\"\nset forward-error-correction $fec\nend\n"
			}
		}
	}
}
return 1
	%}
	"system interface role" = %{
set role [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set old_role [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { $role eq $old_role } {
	return 1
}
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set cmd "config system interface\nedit $name\n"
if { $role eq "lan" } {
	if { [cli_branchpt_start 600 930] } {
		append cmd "set lldp-transmission enable\n"
	}
	append cmd "set device-identification enable\nend\n"
	if {  $type ne "loopback" } {
		cli_exec_cmd $CLI_GLOBAL_NODE $cmd
	}
} elseif { $role eq "wan" } {
	append cmd "set lldp-reception enable\nend\n"
	cli_exec_cmd $CLI_GLOBAL_NODE $cmd
}
return 1
	%}
        "firewall policy" = %{
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
set ippool [cli_get_value $CLI_CUR_NODE "" "" "ippool"]
set nat [cli_get_value $CLI_CUR_NODE "" "" "nat"]
set hascmd 0
set cmd ""
if { $action eq "deny" } {
    set hascmd 1
    append cmd "unset traffic-shaper\nunset traffic-shaper-reverse\n"
    if { [cli_get_value $CLI_CUR_NODE "" "" "utm-status"] eq "enable" } {
        append cmd "unset utm-status\n"
    }
    if {$ippool ne "disable"} {
        append cmd "unset poolname\nunset ippool\n"
    } else {
        if {[cli_get_value $CLI_CUR_NODE "" "" "poolname"] ne ""} {
            append cmd "unset poolname\n"
        }
    }
} else {
    set ibp [cli_get_value $CLI_CUR_NODE "" "" "identity-based"]
    set ident_from [cli_get_value $CLI_CUR_NODE "" "" "identity-from"]
    if { $ibp ne "enable" || $ident_from ne "device" } {
        if { [cli_get_value $CLI_CUR_NODE "" "" "device-detection-portal"] eq "enable" } {
            set hascmd 1
            append cmd "unset device-detection-portal\n"
        }
    }
    if { $nat eq "disable" || $ippool eq "disable" } {
        if {$ippool ne "disable"} {
            set hascmd 1
            append cmd "unset poolname\nunset ippool\n"
        } else {
            if {[cli_get_value $CLI_CUR_NODE "" "" "poolname"] ne ""} {
                set hascmd 1
                append cmd "unset poolname\n"
            }
        }
    }
}
if {$action ne "ipsec" && [cli_get_value $CLI_CUR_NODE "" "" "vpntunnel"] ne ""} {
    set hascmd 1
    append cmd "unset vpntunnel\n"
}
if { $hascmd } {
    cli_exec_cmd $CLI_CUR_NODE $cmd
}
return 1
        %}
        "system vdom-property {session ipsec-phase1 ipsec-phase2 ipsec-phase1-interface ipsec-phase2-interface dialup-tunnel firewall-policy firewall-address firewall-addrgrp custom-service service-group onetime-schedule recurring-schedule user user-group sslvpn proxy log-disk-quota}" = %{
set v [cli_get_value $CLI_CUR_NODE "" "" ""]
set len [llength [split $v " "]]
if { $len eq 1 } {
        set vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
        cli_exec_cmd $CLI_GLOBAL_NODE "config system vdom-property\nedit $vdom\nset $CLI_CUR_NODE_NAME $v 0\nnext\nend\n"
}
return 1
        %}
	"log disk setting" = %{
set status [cli_get_value $CLI_CUR_PARENT_NODE "" "" "status"]
if { $status eq "disable" } {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config report setting\nset status disable\nend\n"
}
return 1
	%}
	"system settings inspection-mode" = %{
proc load_default_waf_profile { } {
	return "config signature\nconfig main-class 100000000\nset action block\nset severity high\nend\nconfig main-class 20000000\nend\nconfig main-class 30000000\nset status enable\nset action block\nset severity high\nend\nconfig main-class 40000000\nend\nconfig main-class 50000000\nset status enable\nset action block\nset severity high\nend\nconfig main-class 60000000\nend\nconfig main-class 70000000\nset status enable\nset action block\nset severity high\nend\nconfig main-class 80000000\nset status enable\nset severity low\nend\nconfig main-class 110000000\nset status enable\nset severity high\nend\nconfig main-class 90000000\nset status enable\nset action block\nset severity high\nend\nset disabled-signature 80080005 80200001 60030001 60120001 80080003 90410001 90410002\nend\nconfig constraint\nconfig header-length\nset status enable\nset log enable\nset severity low\nend\nconfig content-length\nset status enable\nset log enable\nset severity low\nend\nconfig param-length\nset status enable\nset log enable\nset severity low\nend\nconfig line-length\nset status enable\nset log enable\nset severity low\nend\nconfig url-param-length\nset status enable\nset log enable\nset severity low\nend\nconfig version\nset log enable\nend\nconfig method\nset action block\nset log enable\nend\nconfig hostname\nset action block\nset log enable\nend\nconfig malformed\nset log enable\nend\nconfig max-cookie\nset status enable\nset log enable\nset severity low\nend\nconfig max-header-line\nset status enable\nset log enable\nset severity low\nend\nconfig max-url-param\nset status enable\nset log enable\nset severity low\nend\nconfig max-range-segment\nset status enable\nset log enable\nset severity high\nend\nend\n"
}
proc update_inspection_mode { obj ov nv } {
	global CLI_CUR_VDOM_NODE
	set DEFAULT_SNIFFER_PROFILE "sniffer-profile"
	set nodes [cli_get_match_list $CLI_CUR_VDOM_NODE 1 $obj "inspection-mode" 0 $ov]
	foreach node $nodes {
		set name [cli_get_value $node "" "" "name"]
		if { $ov eq "proxy" || $name ne $DEFAULT_SNIFFER_PROFILE } {
		set cmd "config $obj\nedit \"$name\"\nset inspection-mode $nv\nnext\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		}
	}
}
proc check_profile_setting { node explicit_policy } {
	set cmd ""
	set sensor [cli_get_value $node "" "" "dlp-sensor"]
	if { $sensor ne 0 && $sensor ne "" } {
		append cmd "unset dlp-sensor\n"
	}
	set profile [cli_get_value $node "" "" "spamfilter-profile"]
	if { $profile ne 0 && $profile ne "" } {
		append cmd "unset spamfilter-profile\n"
	}
	if { $explicit_policy eq "1" } {
		set profile [cli_get_value $node "" "" "av-profile"]
		if { $profile ne 0 && $profile ne "" } {
			append cmd "unset av-profile\n"
		}
		set profile [cli_get_value $node "" "" "webfilter-profile"]
		if { $profile ne 0 && $profile ne "" } {
			append cmd "unset webfilter-profile\n"
		}
	} else {
		set profile [cli_get_value $node "" "" "icap-profile"]
		if { $profile ne 0 && $profile ne "" } {
			append cmd "unset icap-profile\n"
		}
	}
	return $cmd
}
proc check_fw_policy_profile_setting { node_path } {
	global CLI_CUR_VDOM_NODE
	set fw_policies [cli_get_tbl_list $CLI_CUR_VDOM_NODE $node_path]
	set cmd "config $node_path\n"
	foreach policy $fw_policies {
		set polscan [cli_get_value $policy "" "" "utm-status"]
		set profile_type [cli_get_value $policy "" "" "profile-type"]
		if { $polscan eq "enable" && $profile_type ne "group" } {
			set pid [cli_get_value $policy "" "" "policyid"]
			append cmd "edit \"$pid\"\n"
			append cmd [check_profile_setting $policy "0"]
			append cmd "next\n"
		}
	}
	append cmd "end\n"
	cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
}

set mode [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $mode eq "proxy" } {
	set ov "flow-based"
	set nv "proxy"
} elseif { $mode eq "flow" } {
	set ov "proxy"
	set nv "flow-based"
}
update_inspection_mode "antivirus profile" $ov $nv
update_inspection_mode "webfilter profile" $ov $nv

if { $mode eq "flow" } {
	set profile_groups [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall profile-group"]
	set cmd "config firewall profile-group\n"
	foreach pg $profile_groups {
		set name [cli_get_value $pg "" "" "name"]
		append cmd "edit \"$name\"\n"
		append cmd [check_profile_setting $pg "0"]
		append cmd "next\n"
	}
	append cmd "end\n"
	cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd

	check_fw_policy_profile_setting "firewall policy"
	check_fw_policy_profile_setting "firewall policy6"

	set explicit_policies [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall explicit-proxy-policy"]
	set cmd "config firewall explicit-proxy-policy\n"
	foreach policy $explicit_policies {
		set pid [cli_get_value $policy "" "" "policyid"]
		set exppolsplit [cli_get_value $policy "" "" "identity-based"]
		if { $exppolsplit && $sxppolsplit eq "enable" } {
			append cmd "edit \"$pid\"\n"
			append cmd "config identity-based-policy\n"
			set identity_policies [cli_get_tbl_list $policy "identity-based-policy"]
			foreach idpol $identity_policies {
				set polscan [cli_get_value $idpol "" "" "utm-status"]
				set profile_type [cli_get_value $idpol "" "" "profile-type"]
				if { $polscan eq "enable" && $profile_type ne "group" } {
					set idpol_id [cli_get_value $idpol "" "" "id"]
					append cmd "edit \"$idpol_id\"\n"
					append cmd [check_profile_setting $idpol  "1"]
					append cmd "next\n"
				}
			}
			append cmd "end\n"
			append cmd "next\n"
		}
		else {
			set polscan [cli_get_value $policy "" "" "utm-status"]
			set profile_type [cli_get_value $policy "" "" "profile-type"]
			if { $polscan eq "enable" && $profile_type ne "group" } {
				append cmd "edit \"$pid\"\n"
				append cmd [check_profile_setting $policy "1"]
				append cmd "next\n"
			}
		}
	}
	append cmd "end\n"
	cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
} elseif { $mode eq "proxy" } {
	if { ![cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "waf profile" "name" 0 "default"] } {
		set cmd "config waf profile\nedit default\n"
		append cmd [load_default_waf_profile]
		append cmd "next\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
	}
}
return 1
	%}
        "system geoip-override" = %{
if { ![cli_branchpt_start 500 926] } { return 1 }
if { [cli_get_value $CLI_CUR_NODE "" "" "country-id"] eq "" } {
        set id [cli_gen_geoip_country_id]
        if { $id ne 0 } {
                set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
                cli_exec_cmd $CLI_GLOBAL_NODE "config system geoip-override\nedit $name\nset country-id $id\nnext\nend\n"
        }
}
return 1
        %}
        "system virtual-wan-link service" = %{
set proto [cli_get_value $CLI_CUR_NODE "" "" "protocol"]
set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
if { !($proto eq 6 || $proto eq 17 || $proto eq 132) } {
	cli_exec_cmd $CLI_CUR_NODE "set start-port 1\nset end-port 65535\n"
}
return 1
	%}
        "endpoint-control profile forticlient-winmac-settings" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" "forticlient-application-firewall"] eq "disable" } {
	cli_clear_value $CLI_CUR_NODE "" "" "forticlient-application-firewall-list"
}
return 1
        %}
        "firewall policy learning-mode" = %{
namespace import global::cmf_firewall_policy_learn_enabled
namespace import global::cmf_firewall_set_learning_policy
namespace import global::cmf_firewall_unset_learning_policy
set o [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set n [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $o eq "enable" && $n eq "disable" } {
        cmf_firewall_unset_learning_policy $CLI_CUR_PARENT_NODE
} elseif { $o eq "disable" && $n eq "enable" } {
        cmf_firewall_set_learning_policy $CLI_CUR_PARENT_NODE
}
return 1
        %}
    "certificate {local crl ca remote}" = %{
if { [string match "*override*" [cli_get_clisrc]] } {
	## let override pass as this is handled by handler
	return 1
}
if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set cname "vpn $CLI_CUR_NODE_NAME"
	set cmd [cli_export_node_attrs $CLI_CUR_NODE]
	set vdoms [cli_get_tbl_list $CLI_GLOBAL_NODE "system vdom-property"]
	foreach vd $vdoms {
		set vdname [cli_get_value $vd "" "" "name"]
		set vnode [cli_get_vdom_node $vdname]		
		cli_exec_cmd $vnode "config $cname\nedit \"$name\"\n$cmd\nend\n"
	}
}
return 1
	%}
	"system vxlan" = %{
if {$CLI_ACT eq "add"} {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set phy_devname [cli_get_value $CLI_CUR_NODE "" "" "interface"]
	if { $name ne "" && $phy_devname ne "" } {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $name\nset vdom $CLI_CUR_VDOM_NAME\nset type vxlan\nset interface $phy_devname\nnext\nend\n"
		if {[cli_obj_support "system interface" "snmp-index"]} {
			namespace import global::auto_set_snmp_index
			auto_set_snmp_index $name
		}
	}
}
return 1
	%}
	"system settings ngfw-mode" = %{
namespace import global::ngfw_mode_set_policy_mode
namespace import global::ngfw_mode_set_profile_mode

set new_mode [cli_get_value $CLI_CUR_NODE "" "" ""]
set old_mode [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if {$new_mode eq $old_mode} {
	return 1
}
set insp_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"]
set cnfw_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "consolidated-firewall-mode"]
if {$insp_mode eq "flow" && $new_mode eq "policy-based"} {
	ngfw_mode_set_policy_mode $cnfw_mode $CLI_CUR_VDOM_NODE
} else {
	ngfw_mode_set_profile_mode $cnfw_mode $CLI_CUR_VDOM_NODE
}
return 1
	%}
	"system interface ipv6 ip6-extra-addr" = %{
set old_prefix [cli_get_value $CLI_CUR_NODE "" "" "prefix"]
if { [cli_branchpt_start 600 920] && [regexp {^::\d+\.\d+\.\d+\.\d+} $old_prefix] } {
	## since v6.2.1, FOS force convert "::192.168.141.165/120" to "::c0a8:8da5/120"
	set subs [regexp -inline -all {\d+} $old_prefix]
	set mask 128
	if { [llength $subs] == 5 } {
		set mask [lindex $subs 4]
	}
	set hex0 [format %x [lindex $subs 0]]
	set hex1 [format %02x [lindex $subs 1]]
	set hex2 [format %x [lindex $subs 2]]
	set hex3 [format %02x [lindex $subs 3]]
	set new_prefix "::$hex0$hex1:$hex2$hex3/$mask"
	cli_set_value $CLI_CUR_NODE "" "" "prefix" $new_prefix
}
if { ![cli_branchpt_start 600 920] && [regexp {::[0-9a-fA-F]+:[0-9a-fA-F]+} $old_prefix] } {
	## before v6.2.0, FOS force convert "::c0a8:8da5/120" to "::192.168.141.165/120"
	set subs [regexp -inline -all {[0-9a-fA-F]+} $old_prefix]
	set mask 128
	set hexstr ""
	if { [llength $subs] == 3 } {
		set mask [lindex $subs 2]
	}
	set tmp [lindex $subs 0]
	if { [string length $tmp] == 3 } {
		append hexstr [string range $tmp 0 0] , [string range $tmp 1 2]
	} else {
		append hexstr [string range $tmp 0 1] , [string range $tmp 2 3]
	}
	set tmp [lindex $subs 1]
	if { [string length $tmp] == 3 } {
		append hexstr , [string range $tmp 0 0] , [string range $tmp 1 2]
	} else {
		append hexstr , [string range $tmp 0 1] , [string range $tmp 2 3]
	}
	if { [scan $hexstr "%x,%x,%x,%x" ip0 ip1 ip2 ip3] == 4 } {
		set new_prefix "::$ip0.$ip1.$ip2.$ip3/$mask"
		cli_set_value $CLI_CUR_NODE "" "" "prefix" $new_prefix
	}
}
return 1
	%}
	"system npu" = %{
set new_accounting [cli_get_value $CLI_CUR_NODE "" "" "mcast-session-accounting"]
set old_accounting [cli_get_org_value $CLI_CUR_NODE "" "" "mcast-session-accounting"]
set new_counting [cli_get_value $CLI_CUR_NODE "" "" "mcast-session-counting"]
if { $new_counting ne $new_accounting } {
	if { $new_accounting ne $old_accounting } {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system npu\nset mcast-session-counting $new_accounting\nend\n"
	} else {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system npu\nset mcast-session-accounting $new_counting\nend\n"
	}
}
return 1
	%}
	"system virtual-switch port" = %{
if {$CLI_ACT eq "add"} {
	set name [cli_get_value $CLI_CUR_NODE "" "" ""]
	set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
	if { $intfnode } {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $name\nunset ip\nnext\ndelete $name\nend\n"
	}
}
return 1
	%}
%};
