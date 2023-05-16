nodeact %{
	"wireless-controller wtp-profile platform type" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" ""]
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if { [cli_get_devinfo "pm2_wl_radio_enabled" "2" $type] eq "no" } {
	set profilenode [cli_get_parent $CLI_CUR_PARENT_NODE]
	cli_exec_cmd $profilenode "config radio-2\nset mode disabled\nend\n"
}
if { [cli_get_devinfo "pm2_wl_radio_enabled" "3" $type] eq "no" } {
	set profilenode [cli_get_parent $CLI_CUR_PARENT_NODE]
	cli_exec_cmd $profilenode "config radio-3\nset mode disabled\nend\n"
}
if { [cli_get_devinfo "pm2_wl_radio_enabled" "4" $type $mode] eq "no" } {
	set profilenode [cli_get_parent $CLI_CUR_PARENT_NODE]
	cli_exec_cmd $profilenode "config radio-4\nset mode disabled\nend\n"
}
if { [cli_ver_start 700 2] && $mode eq "single-5G" } {
	set cap [cli_get_devinfo "pm2_wl_wtpcap_attr" $type "cap"]
	set CW_WTP_CAP_DDSCAN [expr 1<<19]
	if { [expr {$cap & $CW_WTP_CAP_DDSCAN}] } {
		set CW_RADIO_CAP_NO_AP [expr 1<<5]
		for { set radio 1 } {$radio <4} {incr radio} {
			set radio_flag [cli_get_devinfo "pm2_wl_handoff_radio_flags" $type $radio]
			if { [expr {$radio_flag & $CW_RADIO_CAP_NO_AP}] } {
				cli_exec_cmd [cli_get_parent $CLI_CUR_PARENT_NODE] "config platform\nset ddscan enable\nend\n"	
				break
			}
		}
	}			
}
return 1
	%}
	"wireless-controller vap intra-vap-privacy" = %{
if { [cli_ver_start 500 0] } {
	set intravap [cli_get_value $CLI_CUR_NODE "" "" ""]
	set localswitch [cli_get_value $CLI_CUR_PARENT_NODE "" "" "local-switching"]
	if { $intravap eq "enable" && $localswitch ne "disable" } {
		set vapname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
		set cmd  "config wireless-controller vap\nedit $vapname\nset local-switching disable\nend\n"
		cli_exec_cmd  $CLI_CUR_VDOM_NODE  $cmd
	}
}
return 1
	%}

	"wireless-controller vap mpsk-profile" = %{
if { [cli_ver_start 600 4] && [cli_obj_support "wireless-controller vap" "mpsk-profile"] } {
	set old [cli_get_org_value $CLI_CUR_NODE "" "" ""]
	set new [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $old ne $new } {
		if { $new eq "" } {
			cli_unset_value $CLI_CUR_PARENT_NODE "" "" "dynamic-vlan"
		} else {
			cli_set_value $CLI_CUR_PARENT_NODE "" "" "dynamic-vlan" "enable"
		}
	}
}
return 1
	%}

	"wireless-controller vap" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set name [string trim $name \"]
if { [cli_ver_start 600 2] } {
	if { $CLI_ACT eq "add" && $name eq "wifi" && [string match "*gui*" [cli_get_clisrc]] } {
		cli_set_errmsg "$name is a reserved name."
		return 0
	}
	set vapvdom $CLI_CUR_VDOM_NAME
} else {
	set vapvdom [cli_get_value $CLI_CUR_NODE "" "" "vdom"]
}
set cmd "config system interface\nedit \"$name\"\nset vdom $vapvdom\nset type vap-switch\n"
if { [cli_ver_start 500 4] && $CLI_ACT eq "add" } {
	append cmd "set role lan\n"
	append cmd "set device-identification enable\n"
}
append cmd "next\nend\n"
cli_exec_cmd $CLI_GLOBAL_NODE $cmd

set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
if { $CLI_ACT eq "add" && [cli_obj_support "system interface" "snmp-index"] } {
	if { $intf_node && [cli_get_value $intf_node "" "" "snmp-index"] == 0 } {
		namespace import global::auto_set_snmp_index
		auto_set_snmp_index $name
	}
	namespace import global::cli_is_quarantine_vap
	if { $intf_node && [cli_is_quarantine_vap $CLI_CUR_NODE $vapvdom] && [cli_get_value $CLI_CUR_NODE "" "" "quarantine"] eq "enable"} {
		namespace import global::cli_add_quarantine_intf
		cli_add_quarantine_intf $name $vapvdom
	}
}

if {[cli_obj_support "wireless-controller vap" "alias"]} {
	if { [cli_branchpt_start 500 257] } {
		set m [cli_get_value $CLI_CUR_NODE "" "" "mesh-backhaul"]
		set b [cli_get_value $CLI_CUR_NODE "" "" "local-bridging"]
		if {$m eq "enable"} {
			set a "set alias \"m\""
		} elseif {$b eq "enable"} {
			set a "set alias \"b\""
		} else {
			set a "set alias \"\""
		}
		if { [cli_ver_start 600 2] } {
			cli_exec_cmd $CLI_CUR_VDOM_NODE "config wireless-controller vap\nedit \"$name\"\n$a\nend\n"
		} else {
			cli_exec_cmd $CLI_GLOBAL_NODE "config wireless-controller vap\nedit \"$name\"\n$a\nend\n"
		}
		if { $a ne "" && ($m eq "enable" || $b eq "enable") } {
			if { $intf_node && [cli_get_value $intf_node "" "" "alias"] eq "" } {
				cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit \"$name\"\n$a\nend\n"
			}
		}
	}
}

set security [cli_get_value $CLI_CUR_NODE "" "" "security"]
set portaltype [cli_get_value $CLI_CUR_NODE "" "" "portal-type"]
if {$name ne "" && !([string match "*captive-portal" $security] && ([string match "auth*" $portaltype] || [string match "cmcc*" $portaltype]))} {
	if { [cli_ver_start 600 2] } {
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config wireless-controller vap\nedit \"$name\"\nunset selected-usergroups\nend\n"
	} else {
		cli_exec_cmd $CLI_GLOBAL_NODE "config wireless-controller vap\nedit \"$name\"\nunset selected-usergroups\nend\n"
	}
}

return 1
	%}
	"wireless-controller vap security-redirect-url" = %{
set url [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ($url ne "") && ([string compare -nocase -length 7 $url "http://"] != 0) && ([string compare -nocase -length 8 $url "https://"] != 0) } {
        set new_url "http://${url}"
        set cli "set security-redirect-url ${new_url}"
	set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
        if { [cli_ver_start 600 2] } {
                cli_exec_cmd $CLI_CUR_VDOM_NODE "config wireless-controller vap\nedit \"$name\"\n$cli\nend\n"
        } else {
                cli_exec_cmd $CLI_GLOBAL_NODE "config wireless-controller vap\nedit \"$name\"\n$cli\nend\n"
        }
}
return 1
	%}
	"wireless-controller vap vlan-pool" = %{
set vapnode [cli_get_parent $CLI_CUR_PARENT_NODE]
if {[cli_get_value $vapnode "" "" "local-bridging"] ne "enable" && [cli_get_value $vapnode "" "" "mesh-backhaul"] ne "enable"} {
	set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
	set name [cli_get_value $vapnode "" "" "name"]
	set name [string trim $name \"]
	if { [cli_ver_start 600 2] } {
		set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
		set vapvdom [cli_get_value $intf_node "" "" "vdom"]
	} else {
		set vapvdom [cli_get_value $vapnode "" "" "vdom"]
	}
	set vlan_name "$name.$id"
	set cmd "config system interface\n"
	append cmd "edit \"$vlan_name\"\n"
	append cmd "set vdom $vapvdom\n"
	append cmd "set interface \"$name\"\n"
	append cmd "set vlanid $id\n"
	if { [cli_ver_start 500 4] } {
		append cmd "set role lan\n"
	}
	append cmd "set type vlan\nnext\nend\n"
	cli_exec_cmd $CLI_GLOBAL_NODE $cmd
	if {[cli_obj_support "system interface" "snmp-index"]} {
		namespace import global::auto_set_snmp_index
		auto_set_snmp_index $vlan_name
	}
}
return 1
	%}

	"wireless-controller vap quarantine" = %{
if { ![cli_ver_start 600 0] } {
	return 1
}
set val [cli_get_value $CLI_CUR_NODE "" "" ""]
set vapname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $vapname ""]
if { $intf_node == 0 } {
	return 1
}
set vapvdom [cli_get_value $intf_node "" "" "vdom"]
namespace import global::cli_is_quarantine_vap
if { [cli_is_quarantine_vap $CLI_CUR_PARENT_NODE $vapvdom] && $val eq "enable" } {
       namespace import global::cli_add_quarantine_intf
       cli_add_quarantine_intf $vapname $vapvdom
} elseif { $val ne "enable" } {
       namespace import global::cli_del_quarantine_intf
       cli_del_quarantine_intf $vapname $vapvdom
}
return 1
	%}

	"wireless-controller vap {local-bridging mesh-backhaul}" = %{
if { ![cli_ver_start 600 0] } {
	return 1
}
if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "enable" } {
       set vapname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
       set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $vapname ""]
       if { $intf_node } {
               set vapvdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vdom"]
               namespace import global::cli_del_quarantine_intf
               cli_del_quarantine_intf $vapname $vapvdom
       }
}
return 1
	%}

        "firewall profile" = %{
proc check_all_match {slist tlist} {
        foreach e $tlist {
                if {[lsearch $slist $e] == -1} {
                        return -1
                }
        }
        return 0
}
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set hascmd 0
set cmd "config firewall profile\nedit \"$name\"\n"
set ftgd_wf_allow [cli_get_value $CLI_CUR_NODE "" "" "ftgd-wf-allow"]
set all_allow {g01 g02 g03 g04 g05 g06 g07 g08 g21 c01 c02 c03 c04 c05 c06}
if {[check_all_match $ftgd_wf_allow $all_allow] == 0} {
	set catnodes [cli_get_tbl_list $CLI_CUR_VDOM_NODE "webfilter ftgd-local-cat"]
	set catlist {}
	foreach e $catnodes {
		set cat [cli_get_value $e "" "" "id"]
		lappend catlist $cat
	}
	if {[check_all_match $ftgd_wf_allow $catlist] == 0} {
        	append cmd "set ftgd-wf-allow all\n"
        	set hascmd 1
	} else {
		set g22 {g22}
		if {[check_all_match $ftgd_wf_allow $g22] == 0} {
	        	append cmd "set ftgd-wf-allow all\n"
	        	set hascmd 1
		}
	}
}
set ips [cli_get_value $CLI_CUR_NODE "" "" "ips-sensor-status"]
if { $ips eq "disable" && [cli_get_value $CLI_CUR_NODE "" "" "ips-sensor"] ne "" } {
        append cmd "unset ips-sensor\n"
        set hascmd 1
}
set als [cli_get_value $CLI_CUR_NODE "" "" "application-list-status"]
if { $als eq "disable" && [cli_get_value $CLI_CUR_NODE "" "" "application-list"] ne "" } {
        append cmd "unset application-list\n"
        set hascmd 1
}
if {$hascmd} {
        append cmd "end\n"
        cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
}
return 1
        %}

	"system admin" = %{
set hascmd 0
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set vdom [cli_get_value $CLI_CUR_NODE "" "" "vdom"]
#set rem_auth [cli_get_value $CLI_CUR_NODE "" "" "remote-auth"]
set cmd "config system admin\nedit $name\n"
## if {$rem_auth eq "enable"} {
# 	set hascmd 1
#	append cmd "set peer-auth disable\n"
# }
#set peer_auth [cli_get_value $CLI_CUR_NODE "" "" "peer-auth"]
## if {$peer_auth eq "enable"} {
#	set hascmd 1
#	append cmd "set remote-auth disable\n"
# }
set is_admin [cli_get_value $CLI_CUR_NODE "" "" "is-admin"]
if {$is_admin ne "" && $is_admin != 0} {
	set hascmd 1
	append cmd "set accprofile super_admin\n"
}
if {$vdom eq ""} {
	set hascmd 1
	append cmd "set vdom \"root\"\n"
}
set tf [cli_get_value $CLI_CUR_NODE "" "" "two-factor"]
if { $tf ne "fortitoken" } {
	set hascmd 1
	append cmd "unset fortitoken\n"
}
if {$hascmd} {
	append cmd "end\n"
	cli_exec_cmd $CLI_GLOBAL_NODE $cmd
}
# check trusthost1~10 ip
set list {
        {"trusthost1"}
        {"trusthost2"}
        {"trusthost3"}
        {"trusthost4"}
        {"trusthost5"}
        {"trusthost6"}
        {"trusthost7"}
        {"trusthost8"}
        {"trusthost9"}
        {"trusthost10"}
}
set cmd ""
foreach e $list {
        set host [lindex $e 0]
        set ip [cli_get_value $CLI_CUR_NODE "" "" $host]
        if { $ip ne "" } {
		set newip [cli_format_ipmask $ip 0]
		append cmd "set $host $newip\n"
        }
}
if { $cmd ne "" } {
        cli_exec_cmd $CLI_GLOBAL_NODE "config system admin\nedit $name\n$cmd\nnext\nend\n"
}

set is_peer_auth [cli_is_match $CLI_CUR_NODE 0 "" "peer-auth" 0 "enable"]
set is_remote_auth [cli_is_match $CLI_CUR_NODE 0 "" "remote-auth" 0 "enable"]
set any_user [cli_is_match $CLI_CUR_NODE 0 "" "wildcard" 0 "enable"]

set clisrc [cli_get_clisrc]
if { [string match "*json*" $clisrc] || [string match "*script*" $clisrc] || [string match "*gui*" $clisrc] } {
if { $is_peer_auth == 0 && ($is_remote_auth == 0 || $any_user == 0) } {
set passwd_new [cli_get_value $CLI_CUR_NODE "" "" "password"]
set passwd_org [cli_get_org_value $CLI_CUR_NODE "" "" "password"]

if { $CLI_ACT eq "add" || ($passwd_new != $passwd_org) } {
	set guest_auth [cli_get_value $CLI_CUR_NODE "" "" "guest-auth"]
	if { [cli_ver_start 500 4] && $guest_auth eq "enable" } {
		set guest_status [cli_get_value $CLI_GLOBAL_NODE "system password-policy-guest-admin" "" "status"]
		if { $guest_status eq "enable" } {
			set expire_day [cli_get_value $CLI_GLOBAL_NODE "system password-policy-guest-admin" "" "expire-day"]
			set dst [cli_get_value $CLI_GLOBAL_NODE "system global" "" "dst"]
			set timezone [cli_get_value $CLI_GLOBAL_NODE "system global" "" "timezone"]
			set passwd_exp [cli_adjust_admin_passwd_expire $expire_day $timezone $dst ]
			cli_set_value $CLI_CUR_NODE "" "" "password-expire" $passwd_exp
			return 1
		}
	}
	set pp_status [cli_get_value $CLI_GLOBAL_NODE "system password-policy" "" "status"]
	set pp_apply2 [cli_get_value $CLI_GLOBAL_NODE "system password-policy" "" "apply-to"]
	if { $pp_status eq "enable" && $pp_apply2 eq "admin-password" } {
		set expire_day [cli_get_value $CLI_GLOBAL_NODE "system password-policy" "" "expire-day"]
		if { $expire_day eq "" } {
			set expire_day [cli_get_defvalue "system password-policy" "expire-day"]
		}
		set dst [cli_get_value $CLI_GLOBAL_NODE "system global" "" "dst"]
		set timezone [cli_get_value $CLI_GLOBAL_NODE "system global" "" "timezone"]
		set passwd_exp [cli_adjust_admin_passwd_expire $expire_day $timezone $dst ]
		cli_set_value $CLI_CUR_NODE "" "" "password-expire" $passwd_exp
		return 1
	}
}
}
}
return 1
        %}

	"system admin password" =%{
set password [cli_get_value $CLI_CUR_NODE "" "" ""]
set len [string length $password]
if { $len != 180 || [string compare -length 4 $password "ENC "] != 0 } {
	return 1
}
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set clear [string map {"\"" ""} [cli_decode_passwd $password]]
set clear [string trim $clear]
if { $clear ne ""} {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config system admin\nedit $name\nset password $clear\nnext\nend\n"
}
return 1
	%}

	"system password-policy" = %{
set clisrc [cli_get_clisrc]
if { [string match "*json*" $clisrc] || [string match "*script*" $clisrc] || [string match "*gui*" $clisrc] } {
	set pp_expire_status [cli_get_value $CLI_CUR_NODE "" "" "expire-status"]
	set pp_orig_expire_status [cli_get_org_value $CLI_CUR_NODE "" "" "expire-status"]
	set pp_status [cli_get_value $CLI_CUR_NODE "" "" "status"]
	set applyto [cli_get_value $CLI_CUR_NODE "" "" "apply-to"]
	if { $pp_status eq "enable" && $pp_expire_status eq "enable" && $applyto eq "admin-password" } {
		set admins [cli_get_tbl_list $CLI_GLOBAL_NODE "system admin"]
		set expire_day [cli_get_value $CLI_CUR_NODE "" "" "expire-day"]
		set orig_expire_day [cli_get_org_value $CLI_CUR_NODE "" "" "expire-day"]
		if { $expire_day ne $orig_expire_day || $pp_expire_status ne $pp_orig_expire_status } {
			set dst [cli_get_value $CLI_GLOBAL_NODE "system global" "" "dst"]
			set timezone [cli_get_value $CLI_GLOBAL_NODE "system global" "" "timezone"]
			set day [cli_adjust_admin_passwd_expire $expire_day $timezone $dst]
			foreach admin $admins {
				cli_set_value $admin "" "" "password-expire" $day
			}
		}
	}
}
return 1
%}

	"ips custom" = %{
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
set tag [cli_get_value $CLI_CUR_NODE "" "" "tag"]
set signature [cli_get_value $CLI_CUR_NODE "" "" "signature"]
set attack_key "--attack_id "
set attack_id [ips_cus_get_attr_value $attack_key $signature]
if { $attack_id eq "" } {
        for {set x 1000} {$x <= 9999} {incr x} {
		set attack_list($x) 0
        }
        set nodelist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "ips custom"]
        foreach node $nodelist {
		set this_sig [cli_get_value $node "" "" "signature"]
		set this_id [ips_cus_get_attr_value $attack_key $this_sig]
		if { $this_id ne "" } {
			set attack_list($this_id) 1
		}
        }
        for {set x 1000} {$x <= 9999} {incr x} {
                if { $attack_list($x) != 1 } {
                        set attack_id $x
                        break
                }
        }
        if {$attack_id != 0} {
                if { $attack_id < 1000 || $attack_id > 9999 } {
                        cli_set_errmsg "Invalid attack id."
                        return 0
                }
                set signature [regsub {[\(]} $signature "(${attack_key}${attack_id}; "]
                set cmd "config ips custom\nedit \"$tag\"\nset signature $signature\nnext\nend\n"
                cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
        }
}
set name_key "--name "
set name [ips_cus_get_attr_value $name_key $signature]
if { $name eq "" } {
        set signature [regsub {[\(]} $signature "(${name_key}\\\"${tag}\\\"; "]
        set cmd "config ips custom\nedit \"$tag\"\nset signature $signature\nnext\nend\n"
        cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
}
return 1
	%}

	"vpn ipsec phase1-interface" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $CLI_ACT eq "edit" && [cli_branchpt_start 600 910] } {
	set old_type [cli_get_org_value $CLI_CUR_NODE "" "" "type"]
	if { $old_type ne $type } {
		set dpd [cli_get_value $CLI_CUR_NODE "" "" "dpd"]
		set dpd_retryinterval [cli_get_value $CLI_CUR_NODE "" "" "dpd-retryinterval"]
		set dpd_retrycount [cli_get_value $CLI_CUR_NODE "" "" "dpd-retrycount"]
		set old_dpd [cli_get_org_value $CLI_CUR_NODE "" "" "dpd"]
		set old_dpd_retryinterval [cli_get_org_value $CLI_CUR_NODE "" "" "dpd-retryinterval"]
		set old_dpd_retrycount [cli_get_org_value $CLI_CUR_NODE "" "" "dpd-retrycount"]
		if { $type eq "dynamic" } {
			if { $dpd eq $old_dpd } {
				cli_set_value $CLI_CUR_NODE "" "" "dpd" "on-idle"
			}
			if { $dpd_retryinterval eq $old_dpd_retryinterval } {
				cli_set_value $CLI_CUR_NODE "" "" "dpd-retryinterval" 60
			}
			if { $dpd_retrycount eq $old_dpd_retrycount } {
				cli_unset_value $CLI_CUR_NODE "" "" "dpd-retrycount"
			}
		} elseif { $old_type eq "dynamic" } {
			if { $dpd eq $old_dpd } {
				cli_unset_value $CLI_CUR_NODE "" "" "dpd"
			}
			if { $dpd_retryinterval eq $old_dpd_retryinterval } {
				cli_unset_value $CLI_CUR_NODE "" "" "dpd-retryinterval"
			}
			if { $dpd_retrycount eq $old_dpd_retrycount } {
				cli_unset_value $CLI_CUR_NODE "" "" "dpd-retrycount"
			}
		}
	}
}
set tunname [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $type eq "ddns" } {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface\nedit \"$tunname\"\nunset remote-gw\nend\n"
}
set phyintf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
cli_set_modify_flag 0
if { [cli_branchpt_start 600 884] && [cli_is_match $CLI_CUR_NODE 0 "" "aggregate-member" 0 "enable"] } {
	namespace import global::find_zone_by_phase1intf
	set zone [find_zone_by_phase1intf $CLI_CUR_VDOM_NODE $tunname]
	if { $zone } {
		set zone_name [cli_get_value $zone "" "" "name"]
		set zone_intfs [cli_get_value $zone "" "" "interface"]
		regsub -all \"$tunname\" $zone_intfs {} zone_intfs
		if { $zone_intfs == ""  } {
			cli_exec_cmd $CLI_GLOBAL_NODE "config system zone\nedit $zone_name\nunset interface\nnext\nend\n"
		} else {
			cli_exec_cmd $CLI_GLOBAL_NODE "config system zone\nedit $zone_name\nset interface $zone_intfs\nnext\nend\n"
		}
	}
	cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\ndelete \"$tunname\"\nend\n"
} else {
	cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit \"$tunname\"\nset vdom $CLI_CUR_VDOM_NAME\nset type tunnel\nset interface $phyintf\nend\n"
	if {[cli_obj_support "system interface" "snmp-index"]} {
		namespace import global::auto_set_snmp_index
		auto_set_snmp_index $tunname
	}
}
if { [cli_branchpt_start 700 415] && [cli_is_match $CLI_CUR_NODE 0 "" "mode-cfg" 0 "enable"] } {
	cli_set_value $CLI_CUR_NODE "" "" "auto-discovery-shortcuts" "dependent"
}
namespace import global::ipsec_peertype_state_apply
ipsec_peertype_state_apply
cli_set_modify_flag 1
return 1
	%}
	"system ipsec-aggregate" = %{
set tunname [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $CLI_ACT eq "add" } {
	cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit \"$tunname\"\nset vdom $CLI_CUR_VDOM_NAME\nset type tunnel\nend\n"
	if {[cli_obj_support "system interface" "snmp-index"]} {
		namespace import global::auto_set_snmp_index
		auto_set_snmp_index $tunname
	}
	cli_set_modify_flag 1
}
return 1
	%}
	"vpn ipsec phase1" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $CLI_ACT eq "edit" && [cli_branchpt_start 600 910] } {
	set old_type [cli_get_org_value $CLI_CUR_NODE "" "" "type"]
	if { $old_type ne $type } {
		set dpd [cli_get_value $CLI_CUR_NODE "" "" "dpd"]
		set dpd_retryinterval [cli_get_value $CLI_CUR_NODE "" "" "dpd-retryinterval"]
		set dpd_retrycount [cli_get_value $CLI_CUR_NODE "" "" "dpd-retrycount"]
		set old_dpd [cli_get_org_value $CLI_CUR_NODE "" "" "dpd"]
		set old_dpd_retryinterval [cli_get_org_value $CLI_CUR_NODE "" "" "dpd-retryinterval"]
		set old_dpd_retrycount [cli_get_org_value $CLI_CUR_NODE "" "" "dpd-retrycount"]
		if { $type eq "dynamic" } {
			if { $dpd eq $old_dpd } {
				cli_set_value $CLI_CUR_NODE "" "" "dpd" "on-idle"
			}
			if { $dpd_retryinterval eq $old_dpd_retryinterval } {
				cli_set_value $CLI_CUR_NODE "" "" "dpd-retryinterval" 60
			}
			if { $dpd_retrycount eq $old_dpd_retrycount } {
				cli_unset_value $CLI_CUR_NODE "" "" "dpd-retrycount"
			}
		} elseif { $old_type eq "dynamic" } {
			if { $dpd eq $old_dpd } {
				cli_unset_value $CLI_CUR_NODE "" "" "dpd"
			}
			if { $dpd_retryinterval eq $old_dpd_retryinterval } {
				cli_unset_value $CLI_CUR_NODE "" "" "dpd-retryinterval"
			}
			if { $dpd_retrycount eq $old_dpd_retrycount } {
				cli_unset_value $CLI_CUR_NODE "" "" "dpd-retrycount"
			}
		}
	}
}
namespace import global::ipsec_peertype_state_apply
ipsec_peertype_state_apply
return 1
%}
	"system mobile-tunnel" = %{
set tunname [cli_get_value $CLI_CUR_NODE "" "" "name"]
set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $tunname ""]
if { $CLI_ACT eq "add" && $intf_node eq "0" } {
	set phyintf [cli_get_value $CLI_CUR_NODE "" "" "roaming-interface"]
	cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit \"$tunname\"\nset vdom $CLI_CUR_VDOM_NAME\nset type tunnel\nset interface $phyintf\nend\n"
	if {[cli_obj_support "system interface" "snmp-index"]} {
		namespace import global::auto_set_snmp_index
		auto_set_snmp_index $tunname
	}
	cli_set_modify_flag 1
}
return 1
	%}

         "ips global" = %{
set hascmd 0
set cmd "config ips global\n"
set size [cli_get_value $CLI_CUR_NODE "" "" "socket-size"]
if {$size < 1} {
	set hascmd 1
	append cmd "unset socket-size\n"
}
if {$hascmd} {
	append cmd "end\n"
	cli_exec_cmd $CLI_GLOBAL_NODE $cmd
}
set old_db_type [cli_get_org_value $CLI_CUR_NODE "" "" "database"]
set new_db_type [cli_get_value $CLI_CUR_NODE "" "" "database"]
if { $old_db_type ne $new_db_type } {
	cli_ips_db_changed
}

return 1
         %}

	"vpn certificate ca" = %{
if { [cli_ver_start 500 4] } {
	if {$CLI_ACT eq "add"} {
		if { [cli_get_devinfo "vdom-admin"] ne "yes" } {
			cli_set_value $CLI_CUR_NODE "" "" "range" "global"
		}
	}
}
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set ca [cli_get_value $CLI_CUR_NODE "" "" "ca"]
set ca [string trimright $ca "\n"]
cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate ca\nedit $name\nset ca \"$ca\"\nend\n"
return 1
	%}
        "vpn certificate local" = %{
if { [cli_ver_start 500 4] } {
	if {$CLI_ACT eq "add"} {
		if { [cli_get_devinfo "vdom-admin"] ne "yes" } {
			cli_set_value $CLI_CUR_NODE "" "" "range" "global"
		}
	}
}
return 1
        %}

	"vpn ipsec manualkey-interface" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set phyintf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $name\nset vdom $CLI_CUR_VDOM_NAME\nset type tunnel\nset interface $phyintf\nend\n"
if {[cli_obj_support "system interface" "snmp-index"]} {
	namespace import global::auto_set_snmp_index
	auto_set_snmp_index $name
}
return 1
	%}

	"vpn ssl web bookmarks" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set fav [cli_get_value $CLI_CUR_NODE "" "" "url"]
set fav [string range $fav 1 [expr [string length $fav] - 2]]
if {[string index $fav 0] eq "/"} {
	set fav [string trimleft $fav '/']
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config ssl web bookmark\nedit $name\nset url \"$fav\"\nend\n"
}
return 1
	%}

	"firewall policy redirect-url" = %{
set policyid [cli_get_value $CLI_CUR_PARENT_NODE "" "" "policyid"]
set url [cli_get_value $CLI_CUR_NODE "" "" ""]
set url [string trimleft $url "\""]
set url [string trimright $url "\""]
if {$url ne "" && [string match -nocase {http://*} $url]==0 && [string match -nocase {https://*} $url]==0} {
	set newurl "http://"
	append newurl $url
	cli_exec_cmd $CLI_CUR_PARENT_NODE "set redirect-url \"$newurl\"\n"
}
return 1
	%}
	"firewall {DoS-policy DoS-policy6} anomaly" = %{
if { [cli_ver_start 500 4] } {
    set expiry [cli_get_value $CLI_CUR_NODE "" "" "quarantine-expiry"]
    if { $expiry ne "" } {
        namespace import global::fix_datetime_format
        set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
        set cmd "config anomaly\nedit $name\n"
        set newdt [fix_datetime_format $expiry]
        if { [string compare $expiry $newdt] != 0 } {
            append cmd "set quarantine-expiry $newdt\nend\n"
            set node [cli_get_parent $CLI_CUR_PARENT_NODE]
            cli_exec_cmd $node $cmd
        }
    }
}
if { [cli_ver_start 500 2] } {
	set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
	set cp_status [cli_get_value $CLI_CUR_VDOM_NODE "client-reputation profile" "" "status"]
	if { $status eq "enable" && $cp_status eq "enable" } {
		if { [cli_get_value $CLI_CUR_NODE "" "" "log"] ne "enable" } {
					set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
					set policyid [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "policyid"]
					set pname $CLI_CUR_PARENT_NAME
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config $pname\nedit $policyid\nconfig anomaly\nedit $name\nset log enable\nnext\nend\nnext\nend\n"
		}
	}
}
return 1
%}
	"application list entries" = %{
if { [cli_ver_start 500 4] } {
    set expiry [cli_get_value $CLI_CUR_NODE "" "" "quarantine-expiry"]
    if { $expiry ne "" } {
        namespace import global::fix_datetime_format
        set ename [cli_get_value $CLI_CUR_NODE "" "" ""]
        set appname [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" ""]
        set newdt [fix_datetime_format $expiry]
        if { [string compare $expiry $newdt] != 0 } {
            append cmd "set quarantine-expiry $newdt\nend\nend\n"
            cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
        }
    }
}
return 1
	%}
        "firewall interface-policy" = %{
set policyid [cli_get_value $CLI_CUR_NODE "" "" "policyid"]
set hascmd 0
set cmd "config firewall interface-policy\nedit $policyid\n"
set als [cli_get_value $CLI_CUR_NODE "" "" "application-list-status"]
if {$als eq "disable" && [cli_get_value $CLI_CUR_NODE "" "" "application-list"] ne ""} {
    set hascmd 1
    append cmd "unset application-list\n"
}
set iss [cli_get_value $CLI_CUR_NODE "" "" "ips-sensor-status"]
if {$iss eq "disable" && [cli_get_value $CLI_CUR_NODE "" "" "ips-sensor"] ne ""} {
    set hascmd 1
    append cmd "unset ips-sensor\n"
}
set ids [cli_get_value $CLI_CUR_NODE "" "" "ips-DoS-status"]
if {$ids eq "disable" && [cli_get_value $CLI_CUR_NODE "" "" "ips-DoS"] ne ""} {
    set hascmd 1
    append cmd "unset ips-DoS\n"
}
if {$hascmd} {
    append cmd "end\n"
    cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
}
return 1
        %}

	"firewall address" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set attr_name ""
set cmd ""

if { $type eq "ipmask" } {
	set attr_name "subnet"
} elseif { $type eq "wildcard" } {
	set attr_name "wildcard"
}
if { $attr_name ne "" } {
	set ipmask [cli_get_value $CLI_CUR_NODE "" "" $attr_name]
	set ip [regsub -all {\.} [lindex $ipmask 0] { }]
	set mask [regsub -all {\.} [lindex $ipmask 1] { }]
	if { [llength $ip] ne 4 || [llength $mask] ne 4 } {
		cli_set_errmsg "invalid ip"
		return 0
	}
	set nip list
	lset nip [list [expr [lindex $ip 0] & [lindex $mask 0]] [expr [lindex $ip 1] & [lindex $mask 1]] \
		[expr [lindex $ip 2] & [lindex $mask 2]] [expr [lindex $ip 3] & [lindex $mask 3]]]
	if { [lindex $nip 0] == [lindex $ip 0] && [lindex $nip 1] == [lindex $ip 1] &&
		[lindex $nip 2] == [lindex $ip 2] && [lindex $nip 3] == [lindex $ip 3] } {
		## do nothing
	} else {
		set nip [regsub -all { } $nip {.}]
		set mask [regsub -all { } $mask {.}]
		set ip [regsub -all { } $ip {.}]
		append cmd "set $attr_name $nip $mask\n"
		set logmsg "Automatically convert address from $ip/$mask to $nip/$mask\n"
		cli_set_log $logmsg 0
	}
}
set assoc [cli_get_value $CLI_CUR_NODE "" "" "associated-interface"]
if {$assoc ne 0 && ($assoc eq "" || $assoc eq "''")} {
	append cmd "unset associated-interface\n"
}
if {$cmd ne "" && $name ne ""} {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall address\nedit $name\n$cmd\nend\n"
}
return 1
	%}

	"firewall address6" = %{
set orgip6 [cli_get_value $CLI_CUR_NODE "" "" "ip6"]
set ip6tmp [string tolower $orgip6]
regsub -all {^0+([0-9a-f])}   $ip6tmp  {\1}   ip6tmp2
regsub -all {(:)0+([0-9a-f])} $ip6tmp2 {\1\2} newip6
set ipv6mask  [lindex [split $orgip6 /] 1]
if { $ipv6mask eq "" } {
	append  newip6  "/128"
}
if { $orgip6 ne $newip6 } {
	set name   [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set ip6node [cli_get_parent $CLI_CUR_PARENT_NODE]
	cli_exec_cmd $ip6node  "config firewall address6\nedit $name\nset  ip6  $newip6\nend\n"
}
return 1
	%}
    "firewall multicast-address" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set cmd ""

set assoc [cli_get_value $CLI_CUR_NODE "" "" "associated-interface"]
if {$assoc ne 0 && ($assoc eq "" || $assoc eq "''")} {
	append cmd "unset associated-interface\n"
}

if {$cmd ne "" && $name ne ""} {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall multicast-address\nedit $name\n$cmd\nend\n"
}
return 1
	%}
    "firewall ippool" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set cmd ""

set assoc [cli_get_value $CLI_CUR_NODE "" "" "associated-interface"]
if {$assoc ne 0 && ($assoc eq "" || $assoc eq "''")} {
	append cmd "unset associated-interface\n"
}

if {$cmd ne "" && $name ne ""} {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall ippool\nedit $name\n$cmd\nend\n"
}
return 1
	%}
         "user ldap" = %{
if { [string match "*script*" [cli_get_clisrc]] } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set secure [cli_get_value $CLI_CUR_NODE "" "" "secure"]
	set port [cli_get_value $CLI_CUR_NODE "" "" "port"]
	set org_port [cli_get_org_value $CLI_CUR_NODE "" "" "port"]
	if { $org_port eq $port } {
		if { ($secure eq "ldaps") && ($port != 636) } {
			   set cmd "config user ldap\nedit $name\nset port 636\nend\n"
			   cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		}
		if { ($secure eq "starttls") && ($port != 389) } {
			   set cmd "config user ldap\nedit $name\nset port 389\nend\n"
			   cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		}
	}
}
if { [cli_branchpt_start 600 910] } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	set ca [cli_get_value $CLI_CUR_NODE "" "" "ca-cert"]
	if { $ca eq "" } {
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config user ldap\nedit $name\nset server-identity-check disable\nend\n"
	}
}
return 1
   %}

	"system gre-tunnel" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set interface [cli_get_value $CLI_CUR_NODE "" "" "interface"]
if {$CLI_ACT eq "add"} {
	if {$interface ne ""} {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $name\nset type tunnel\nset vdom $CLI_CUR_VDOM_NAME\nset interface $interface\nend\n"
	} else {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $name\nset type tunnel\nset vdom $CLI_CUR_VDOM_NAME\nend\n"
	}
	if {[cli_obj_support "system interface" "snmp-index"]} {
		namespace import global::auto_set_snmp_index
		auto_set_snmp_index $name
	}
} elseif { $CLI_ACT eq "edit" } {
	if {$interface ne ""} {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $name\nset interface $interface\nend\n"
	}
}
return 1
	%}

	"system switch-interface" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
if {$CLI_ACT eq "add" && $intfnode eq "0"} {
	set cmd "config system interface\nedit $name\nset type switch\n"
	set vdom [cli_get_value $CLI_CUR_NODE "" "" "vdom"]
	if {$vdom ne ""} {
		append cmd "set vdom $vdom\n"
	} elseif {$CLI_CUR_VDOM_NAME ne ""} {
		append cmd "set vdom $CLI_CUR_VDOM_NAME\n"
	} else {
		append cmd "set vdom root\n"
	}
	append cmd "end\n"
	cli_exec_cmd $CLI_GLOBAL_NODE $cmd
	if {[cli_obj_support "system interface" "snmp-index"]} {
		namespace import global::auto_set_snmp_index
		auto_set_snmp_index $name
	}
}
return 1
	%}
	"system vdom-link" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set vcluster [cli_get_value $CLI_CUR_NODE "" "" "vcluster"]
set ha_node [cli_get_node $CLI_GLOBAL_NODE "system ha" "" ""]
if {$vcluster eq ""} {set vcluster 0}

	if {$vcluster eq "vcluster1"} {
		set vdom_list [cli_get_value $ha_node "" "" "vdom"]
	} elseif {$vcluster eq "vcluster2"} {
		if {![cli_is_match $CLI_GLOBAL_NODE 0 "system ha" "vcluster2" 0 "enable"]} {
			cli_set_errmsg "system error"
			return 0
		}
		set vdom_list [cli_get_value $ha_node "secondary-vcluster" "" "vdom"]
	} else {
		cli_set_errmsg "system error"
		return 0
	}

if {[llength $vdom_list] <= 0} {
	set vdom_list "root"
}

if { [cli_ver_start 500 0] } {
	# FOSv5 support TP mode vdom.
} else {
	set found 0
	foreach vv $vdom_list {
		set vnode [cli_get_vdom_node $vv]
		set node [cli_get_node $vnode "system settings" "" ""]
		if { !$node || [cli_is_match $node 0 "" "opmode" 0 "nat"] } {
			set found 1
			break
		}
	}
	if { $found == 0 } {
		cli_set_errmsg "TP vdom found when creating system.vdom-link \"$name\""
		return 0
	}
}

namespace import global::auto_update_vdom_link_macddr
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if {[auto_update_vdom_link_macddr $name $type] != 0} {
	cli_set_errmsg "run auto_update_vdom_link_macddr failed."
	return 0
}

# update link interface's vdom to a valid one (first one in the vdom list)
foreach i {0 1} {
	set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $name$i ""]
	if { ($intf_node ne 0 || $intf_node ne "") && [cli_get_value $intf_node "" "" "type"] eq "vdom-link" } {
		cli_set_value $intf_node "" "" "vdom" [lindex $vdom_list 0]
	}
}
return 1
	%}

	"system ipv6-tunnel" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $name\nset vdom $CLI_CUR_VDOM_NAME\nset type tunnel\nend\n"
return 1
	%}

	"firewall policy6" = %{
set hascmd 0
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
set identity_based [cli_get_value $CLI_CUR_NODE "" "" "identity-based"]
set identity_from [cli_get_value $CLI_CUR_NODE "" "" "identity-from"]
set cmd ""
if {$action ne "ipsec"} {
	set hascmd 1
	append cmd "unset vpntunnel\n"
}
if {$identity_based eq "disable" || $identity_from ne "device"} {
	if {[cli_get_value $CLI_CUR_NODE "" "" "device-detection-portal"] eq "enable"} {
		set hascmd 1
		append cmd "unset device-detection-portal\n"
	}
}
if {$hascmd} {
	cli_exec_cmd $CLI_CUR_NODE $cmd
}
return 1
	%}

	"webfilter ftgd-local-cat" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "desc"]
set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
if {$id eq ""} {
	set cat_nodes [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
	set catlist {}
	foreach e $cat_nodes {
		if { [cli_if_same_node $e $CLI_CUR_NODE] } {
			continue;
		}
		set cat [cli_get_value $e "" "" "id"]
		lappend catlist $cat
	}
	if {[llength $catlist]} {
		set catlist [lsort -integer $catlist]
		if {[lindex $catlist 0] > 140} {
			set id 140
		} else {
			set id 140
			foreach e $catlist {
				if {$id < $e} {
					break
				} else {
					set id [expr $e + 1]
				}
			}
		}
	}
	if {$id > 191} {
		cli_set_errmsg "max entry"
		return 0
	}
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config webfilter ftgd-local-cat\nedit $name\nset id $id\nend\n"
}

return 1
	%}

	"webfilter ftgd-ovrd url" = %{
set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
set url [cli_get_value $CLI_CUR_NODE "" "" ""]
set index [string first {https://} $url]
if {$index == 0} {
	set url [string replace $url 0 8]
} else {
	set index [string first {http://} $url]
	if {$index == 0} {
		set url [string replace $url 0 7]
	}
}
if {[string range $url end-1 end] eq {\/}} {
	set url [string replace $url end-1 end {/}]
} elseif {[string range $url end end] eq {/}} {
	set url [string replace $url end end]
}
cli_exec_cmd $CLI_CUR_VDOM_NODE "config webfilter ftgd-ovrd url\nedit $id\nset url $url\nend\n"
return 1
	%}

        "webfilter urlfilter entries" = %{
namespace import global::options_exact_match
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
if { $action eq "exempt" } {
        set ifall 0
        set ifpass 0
	set exempt [cli_get_value $CLI_CUR_NODE "" "" "exempt"]
	foreach e $exempt {
		if { $e eq "all" } {
			set ifall 1
		}
		if { $e eq "pass" } {
			set ifpass 1
		}
	}
	set c ""
        if { $ifall == 1 } {
                if { $ifpass == 1 } {
                        set e [cli_get_defvalue "webfilter urlfilter entries" "exempt"]
			set e [cli_update_opts 1 $e "pass"]
                        append c "set exempt $e\n"
                } else {
                        append c "unset exempt\n"
                }
        } elseif { $ifpass == 0 } {
		set e [cli_get_defvalue "webfilter urlfilter entries" "exempt"]
		set e [cli_update_opts 0 $e "all"]
		if { [options_exact_match $exempt $e] } {
                        append c "unset exempt\n"
		}
	}
	if { $c ne "" } {
                set urlfilter [cli_get_parent $CLI_CUR_PARENT_NODE]
                set urlfilter_id [cli_get_value $urlfilter "" "" "id"]
                set cmd "config webfilter urlfilter\nedit $urlfilter_id\nconfig entries\n"
                if { [cli_ver_start 500 2] } {
                        set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
                        append cmd "edit $id\n"
                } else {
                        set url [cli_get_value $CLI_CUR_NODE "" "" "url"]
                        append cmd "edit \"$url\"\n"
                }
		append cmd $c
                append cmd "end\nend\n"
                cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
	}
}
if { [cli_ver_start 500 2] } {
	if { [cli_get_value $CLI_CUR_NODE "" "" "type"] eq "simple" } {
		set url [cli_get_value $CLI_CUR_NODE "" "" "url"]
		set new_url [cli_check_url 1 $url]
		set new_url [string trim $new_url]
		if {[string compare $url $new_url] != 0} {
			set pid [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "id"]
			set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
			set cmd "config webfilter urlfilter\nedit $pid\nconfig entries\nedit $id\nset url \"$new_url\"\n"
			append cmd "next\nend\nnext\nend\n"
			cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
		}
	}
} else {
	set url [cli_get_value $CLI_CUR_NODE "" "" "url"]
	set tmp_url [string trimright $url "/"]
	set new_url $tmp_url
	if {[string first {https://} $tmp_url] == 0} {
		set new_url [string replace $tmp_url 0 7]
	} else {
		if {[string first {http://} $tmp_url] == 0} {
			set new_url [string replace $tmp_url 0 6]
		}
	}
	if {[string compare $url $new_url] != 0} {
		# remove the trailing slash
		set urlfilter [cli_get_parent $CLI_CUR_PARENT_NODE]
		set urlfilter_id [cli_get_value $urlfilter "" "" "id"]
		set cmd "config webfilter urlfilter\nedit $urlfilter_id\nconfig entries\n"
		# TODO: imply cli_cone_obj API to avoid attributes changing.
		set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
		set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
		set status [cli_get_value $CLI_CUR_NODE "" "" "status"]
		if { [cli_obj_support "webfilter urlfilter entries" "exempt"] } {
			set exempt [cli_get_value $CLI_CUR_NODE "" "" "exempt"]
		}
		append cmd "delete \"$url\"\n"
		append cmd "edit \"$new_url\"\n"
		append cmd "set type $type\n"
		append cmd "set action $action\n"
		append cmd "set status $status\n"
		if { [cli_obj_support "webfilter urlfilter entries" "exempt"] } {
			append cmd "set exempt $exempt\n"
		}
		append cmd "next\nend\nnext\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
	}
}
return 1
	%}

	"router multicast route-limit" = %{
set threshold [cli_get_value $CLI_CUR_PARENT_NODE "" "" "route-threshold"]
if {$threshold eq ""} {
	set limit [cli_get_value $CLI_CUR_NODE "" "" ""]
	if {$limit ne ""} {
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config router multicast route-limit\nset route-threshold $limit\nend\n"
	}
}
return 1
	%}
	"router multicast interface hello-interval" = %{
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set holdtime [cli_get_value $CLI_CUR_PARENT_NODE "" "" "hello-holdtime"]
set interval [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$holdtime eq "" && $interval ne ""} {
	set hold [expr int($interval * 3.5)]
	if {$hold > 65535} {set hold 65535}
	set node [cli_get_parent $CLI_CUR_PARENT_NODE]
	set node [cli_get_parent $node]
	cli_exec_cmd $node "config interface\nedit $name\nset hello-holdtime $hold\nend\n"
}
return 1
	%}

	"system wireless settings mode" = %{
if {$CLI_ACT ne "add"} {
	cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit wlan\nset wifi-security None\nset mode static\nend\n"
}
return 1
	%}

	"system interface vdom" = %{
set settings {geography channel broadcast-ssid ssid power-level beacon-interval rts-threshold fragment-threshold security mode key passphrase radius-server}
set platform [cli_get_devinfo "platform"]
if {$CLI_ACT ne "add" && $platform eq "FortiWiFi-60"} {
	set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
	set newvd [cli_get_value $CLI_CUR_NODE "" "" ""]
	if {$name eq "wlan"} {
		set oldvd_node [cli_get_vdom_node $CLI_ORG_ATTR]
		set wlnode [cli_get_node $oldvd_node "system wireless settings" "" ""]
		if {$wlnode} {
			set vnode [cli_get_vdom_node $newvd]
			if {$vnode} {
				set cmd "config system wireless settings\n"
				foreach e $settings {
					set val [cli_get_value $wlnode "" "" $e]
					if {$val ne ""} {
						append cmd "set $e $val\n"
					}
				}
				append cmd "end\n"
				cli_delete_node $wlnode
				cli_exec_cmd $vnode $cmd
			}
		}
	}
}
set vdom [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $vdom ne $CLI_ORG_ATTR } {
        if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "vdom-link" } {
                if { [cli_get_value [cli_get_vdom_node $vdom] "system settings" "" "opmode"] eq "transparent" } {
			if { [cli_ver_start 500 0] } {
				set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
				set name [string range $name 0 [expr [string length $name] - 2]]
				set cmd "config system vdom-link\nedit $name\nset type ethernet\nnext\nend\n";
				cli_exec_cmd $CLI_GLOBAL_NODE $cmd
				namespace import global::auto_update_vdom_link_macddr
				if { [auto_update_vdom_link_macddr $name "ethernet"] != 0 } {
					cli_set_errmsg "run auto_update_vdom_link_macddr failed"
					return 0
				}
			}
                }
        }
}
return 1
	%}

	"system global {vdom-admin vdom-mode}" = %{
set oldval [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set status [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ([cli_branchpt_start 600 787] && ($status eq "multi-vdom" || $status eq "split-vdom")) || $status eq "enable" } {
	if {($oldval ne "disable") && ($oldval ne "no-vdom")} {
		cli_set_errmsg "vdom status: Can not transfer from $oldval to $status."
		return 0
	}
	set prop_node [cli_get_node $CLI_GLOBAL_NODE "system vdom-property" "root" ""]
	if {$prop_node == 0} {
		set description "\"property limits for vdom root\""
		cli_exec_cmd $CLI_GLOBAL_NODE "config system vdom-property\nedit \"root\"\nset description $description\nend\n"
	}
	if {[cli_obj_support "system vdom-property" "snmp-index"]} {
		namespace import global::set_vdom_snmp_index
		set_vdom_snmp_index "root"
	}
	set hanode [cli_get_node $CLI_GLOBAL_NODE "system ha" "" ""]
	if {$hanode != 0} {
		set primary [cli_get_value $hanode "" "" "vdom"]
		set secondary [cli_get_value $hanode "secondary-vcluster" "" "vdom"]
		if {[string first "\"root\"" $primary] == -1 && [string first "\"root\"" $secondary] == -1} {
			cli_exec_cmd $CLI_GLOBAL_NODE "config system ha\nset vdom root\nend\n"
		}
	}
	set quota [cli_get_devinfo "logdisk_size"]
	if { $quota > 0 } {
		set wanopt_nodes [cli_get_tbl_list $CLI_GLOBAL_NODE "wanopt storage"]
		if {$wanopt_nodes != 0 && [llength $wanopt_nodes]} {
			set wanopt [cli_get_value [lindex $wanopt_nodes 0] "" "" "size"]
			set quota [expr {$quota - $wanopt}]
			if { $quota < 0 } {
				set quota 0
			}
		}
		cli_exec_cmd $CLI_GLOBAL_NODE "config system resource-limits\nset log-disk-quota $quota\nend\n"
	}
	if { [cli_ver_start 500 0] } {
		if { [cli_branchpt_start 500 643] } {
			set comment "Default"
		} else {
			set comment "default"
		}
		cli_exec_cmd [cli_get_vdom_node "root"] "config system replacemsg-group\nedit \"default\"\nset comment \"$comment\"\nnext\nend\n"
	}
	if { [cli_ver_start 500 4] } {
		namespace import global::sync_certs_between_global_vdom
		set cmd [sync_certs_between_global_vdom $CLI_CUR_VDOM_NODE "vpn certificate local"]
		cli_exec_cmd $CLI_GLOBAL_NODE "config certificate local\n$cmd\nend\n"
		set cmd [sync_certs_between_global_vdom $CLI_CUR_VDOM_NODE "vpn certificate crl"]
		cli_exec_cmd $CLI_GLOBAL_NODE "config certificate crl\n$cmd\nend\n"
		set cmd [sync_certs_between_global_vdom $CLI_CUR_VDOM_NODE "vpn certificate ca"]
		cli_exec_cmd $CLI_GLOBAL_NODE "config certificate ca\n$cmd\nend\n"
	}
	if { [cli_ver_start 600 2] } {
		namespace import global::sync_certs_between_global_vdom
		set cmd [sync_certs_between_global_vdom $CLI_CUR_VDOM_NODE "vpn certificate remote"]
		cli_exec_cmd $CLI_GLOBAL_NODE "config certificate remote\n$cmd\nend\n"
	}

	if { [cli_ver_start 500 6] && [cli_has_npuvlink] && $status ne "split-vdom" } {
		set vlinks [cli_npuvlink_list]
		foreach vlink $vlinks {
			set name [string trim $vlink \"]
			cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $name\nset vdom root\nset type physical\nnext\nend\n"
			if {[cli_obj_support "system interface" "snmp-index"]} {
				namespace import global::auto_set_snmp_index
				auto_set_snmp_index $name
			}
		}
	}
	if { [cli_ver_start 600 0] } {
		##
		## FortiOS 6.2.1 code: 
		## cmf/cmdb/cmdb_default_profiles.c: check_utm_profile_wifi_dflt(int is_global)
		##
		set vaplist [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "wireless-controller vap" "utm-profile" 0 "\"wifi-default\""]
		foreach vap $vaplist {
			set vapname [cli_get_value $vap "" "" "name"]
			cli_exec_cmd $CLI_CUR_VDOM_NODE "config wireless-controller vap\nedit $vapname\nset utm-profile \"g-wifi-default\"\nnext\nend\n"
		}
	}

	set root_vdnode $CLI_CUR_VDOM_NODE

	if { [cli_branchpt_start 600 787] && $status eq "split-vdom" } {
		set vdname "FG-traffic"
		set description "\"property limits for vdom "
		append description $vdname
		append description "\""
		if { [cli_exec_cmd $CLI_GLOBAL_NODE "config system vdom-property\nedit \"$vdname\"\nset description $description\nend\n"] ne 0 } {
			return 0
		}
		if { [cli_add_vdom $vdname] != 0 } {
			cli_set_errmsg "Create vdom $vdname failed."
			return 0
		}
		if {[cli_obj_support "system vdom-property" "snmp-index"]} {
			namespace import global::set_vdom_snmp_index
			set_vdom_snmp_index $vdname
		}
		set vdnode [cli_get_vdom_node $vdname]
		set opmode [cli_get_value $vdnode "system settings" "" "opmode"]
		if { $opmode eq "nat" } {
			if { [cli_has_feature "f_sslvpn"] } {
				namespace import global::get_mux_tunnel_dev_name
				set intfname [get_mux_tunnel_dev_name $vdname]
				cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $intfname\nset vdom $vdname\nset type tunnel\nset alias \"SSL VPN interface\"\nnext\nend\n"
				if {[cli_obj_support "system interface" "snmp-index"]} {
					namespace import global::auto_set_snmp_index
					auto_set_snmp_index $intfname
				}

				if { [cli_branchpt_start 700 133] } {
					cli_exec_cmd $vdnode "config firewall address\nedit \"SSLVPN_TUNNEL_ADDR1\"\nnext\nend\n"

					set nafname [string map {ssl. naf.} $intfname]
					cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $nafname\nset vdom $vdname\nset type tunnel\nnext\nend\n"
					if { [cli_obj_support "system interface" "snmp-index"] } {
						namespace import global::auto_set_snmp_index
						auto_set_snmp_index $nafname
					}
					set l2tname [string map {ssl. l2t.} $intfname]
					cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $l2tname\nset vdom $vdname\nset type tunnel\nnext\nend\n"
					if { [cli_obj_support "system interface" "snmp-index"] } {
						namespace import global::auto_set_snmp_index
						auto_set_snmp_index $l2tname
					}
				} else {
					cli_exec_cmd $vdnode "config firewall address\nedit \"SSLVPN_TUNNEL_ADDR1\"\nset associated-interface \"$intfname\"\nnext\nend\n"
				}
			}
		} elseif { $opmode eq "transparent" } {
			cli_exec_cmd $vdnode "config router static\nedit 1\nnext\nend\n"
			cli_exec_cmd $vdnode "config router static6\nedit 1\nnext\nend\n"
		}

		namespace import global::sync_certs_between_global_vdom
		set cmd [sync_certs_between_global_vdom $root_vdnode "vpn certificate local"]
		cli_exec_cmd $vdnode "config vpn certificate local\n$cmd\nend\n"
		set cmd [sync_certs_between_global_vdom $root_vdnode "vpn certificate crl"]
		cli_exec_cmd $vdnode "config vpn certificate crl\n$cmd\nend\n"
		set cmd [sync_certs_between_global_vdom $root_vdnode "vpn certificate ca"]
		cli_exec_cmd $vdnode "config vpn certificate ca\n$cmd\nend\n"
		if { [cli_ver_start 600 2] } {
			set cmd [sync_certs_between_global_vdom $root_vdnode "vpn certificate remote"]
			cli_exec_cmd $vdnode "config vpn certificate remote\n$cmd\nend\n"
		}

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
			cli_exec_cmd $vdnode "config system virtual-wire-pair\nedit $vdname\nset member \"$nint\" \"$next\"\nnext\nend\n"
		}
	}
} else {
	if { [cli_branchpt_start 600 787] && ($oldval eq "split-vdom") } {
		if { [cli_del_vdom "FG-traffic"] != 0 } {
			cli_set_errmsg "Remove FG-traffic vdom failed."
			return 0
		}
		set vdname "FG-traffic"
		set found 0
		set vnew ""

		set hanode [cli_get_node $CLI_GLOBAL_NODE "system ha" "" ""]
		set vdoms [cli_get_value $hanode "" "" "vdom"]
		foreach v $vdoms {
			if {$v != $vdname} {
				append vnew " "
				append vnew $v
			} else {
				set found 1
			}
		}
		if {$found == 0} {
			set vnew ""
			set vdoms [cli_get_value $hanode "secondary-vcluster" "" "vdom"]
			foreach v $vdoms {
				if {$v != $vdname} {
					append vnew " "
					append vnew $v
				} else {
					set found 2
				}
			}
		}
		if {$found} {
			set cmd "config system ha\n"
			if {$found == 1} {
				if {$vnew == ""} {
					append cmd "unset vdom\n"
				} else {
					append cmd "set vdom $vnew\n"
				}
			} else {
				if {$vnew == ""} {
					append cmd "config secondary-vcluster\nunset vdom\nend\n"
				} else {
					append cmd "config secondary-vcluster\nset vdom $vnew\nend\n"
				}
			}
			append cmd "end\n"
			cli_exec_cmd $CLI_GLOBAL_NODE $cmd
		}

		proc remove_intf_node { intfname } {
			global CLI_GLOBAL_NODE
			set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $intfname ""]
			if {[cli_is_referenced $intfnode]} {
				cli_delete_node $intfnode 1
				if {[cli_is_referenced $intfnode]} {
					cli_set_errmsg "interface $intfname is used"
					return 0
				}
			}
			cli_delete_node $intfnode
		}

		namespace import global::get_mux_tunnel_dev_name
		set intfname [get_mux_tunnel_dev_name $vdname]
		remove_intf_node $intfname
		remove_intf_node [string map {ssl. naf.} $intfname]
		remove_intf_node [string map {ssl. l2t.} $intfname]

		if { [cli_has_feature "f_netx"] } {
			namespace import global::get_shadow_intf_name
			remove_intf_node [get_shadow_intf_name "" $vdname "-int"]
			remove_intf_node [get_shadow_intf_name "" $vdname "-ext"]
		}

		set vdomproperty [cli_get_node $CLI_GLOBAL_NODE "system vdom-property" $vdname ""]
		cli_delete_node $vdomproperty
	}
	if { [cli_ver_start 500 0] } {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system replacemsg-group\ndelete \"default\"\nend\n"
	}
	if { [cli_ver_start 500 4] } {
		namespace import global::sync_certs_between_global_vdom
		set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate local"]
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate local\n$cmd\nend\n"
		set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate crl"]
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate crl\n$cmd\nend\n"
		set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate ca"]
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate ca\n$cmd\nend\n"
	}
	if { [cli_ver_start 600 2] } {
		namespace import global::sync_certs_between_global_vdom
		set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate remote"]
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate remote\n$cmd\nend\n"
	}
	if { [cli_ver_start 500 6] && [cli_has_npuvlink] } {
		set vlinks [cli_npuvlink_list]
		foreach vlink $vlinks {
			set name [string trim $vlink \"]
			cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\ndelete $name\nend\n"
		}
	}
	if { [cli_branchpt_start 500 1449] } {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system global\nset long-vdom-name disable\nend\n"
	}

	set vdnode $CLI_CUR_VDOM_NODE
	if { [cli_ver_start 600 0] } {
		set attrval [cli_get_value $vdnode "firewall ssh setting" "" "caname"]
		set attrval [string trim $attrval \"]
		if { ($attrval ne "") && ([string first "g-" $attrval] == 0) } {
			set attrval [string range $attrval 2 [string length $attrval]]
			cli_exec_cmd $vdnode "config firewall ssh setting\nset caname \"$attrval\"\nend\n"
		}
		set attrval [cli_get_value $vdnode "firewall ssh setting" "" "untrusted-caname"]
		set attrval [string trim $attrval \"]
		if { ($attrval ne "") && ([string first "g-" $attrval] == 0) } {
			set attrval [string range $attrval 2 [string length $attrval]]
			cli_exec_cmd $vdnode "config firewall ssh setting\nset untrusted-caname \"$attrval\"\nend\n"
		}
		set attrval [cli_get_value $vdnode "firewall ssh setting" "" "hostkey-rsa2048"]
		set attrval [string trim $attrval \"]
		if { ($attrval ne "") && ([string first "g-" $attrval] == 0) } {
			set attrval [string range $attrval 2 [string length $attrval]]
			cli_exec_cmd $vdnode "config firewall ssh setting\nset hostkey-rsa2048 \"$attrval\"\nend\n"
		}
		set attrval [cli_get_value $vdnode "firewall ssh setting" "" "hostkey-dsa1024"]
		set attrval [string trim $attrval \"]
		if { ($attrval ne "") && ([string first "g-" $attrval] == 0) } {
			set attrval [string range $attrval 2 [string length $attrval]]
			cli_exec_cmd $vdnode "config firewall ssh setting\nset hostkey-dsa1024 \"$attrval\"\nend\n"
		}
		set attrval [cli_get_value $vdnode "firewall ssh setting" "" "hostkey-ecdsa256"]
		set attrval [string trim $attrval \"]
		if { ($attrval ne "") && ([string first "g-" $attrval] == 0) } {
			set attrval [string range $attrval 2 [string length $attrval]]
			cli_exec_cmd $vdnode "config firewall ssh setting\nset hostkey-ecdsa256 \"$attrval\"\nend\n"
		}
		set attrval [cli_get_value $vdnode "firewall ssh setting" "" "hostkey-ecdsa384"]
		set attrval [string trim $attrval \"]
		if { ($attrval ne "") && ([string first "g-" $attrval] == 0) } {
			set attrval [string range $attrval 2 [string length $attrval]]
			cli_exec_cmd $vdnode "config firewall ssh setting\nset hostkey-ecdsa384 \"$attrval\"\nend\n"
		}
		set attrval [cli_get_value $vdnode "firewall ssh setting" "" "hostkey-ecdsa521"]
		set attrval [string trim $attrval \"]
		if { ($attrval ne "") && ([string first "g-" $attrval] == 0) } {
			set attrval [string range $attrval 2 [string length $attrval]]
			cli_exec_cmd $vdnode "config firewall ssh setting\nset hostkey-ecdsa521 \"$attrval\"\nend\n"
		}
		set attrval [cli_get_value $vdnode "firewall ssh setting" "" "hostkey-ed25519"]
		set attrval [string trim $attrval \"]
		if { ($attrval ne "") && ([string first "g-" $attrval] == 0) } {
			set attrval [string range $attrval 2 [string length $attrval]]
			cli_exec_cmd $vdnode "config firewall ssh setting\nset hostkey-ed25519 \"$attrval\"\nend\n"
		}
	}
	if { [cli_ver_start 600 0] } {
		##
		## FortiOS 6.2.1 code: 
		## cmf/cmdb/cmdb_default_profiles.c: check_utm_profile_wifi_dflt(int is_global)
		##
		set vaplist [cli_get_match_list $vdnode 1 "wireless-controller vap" "utm-profile" 0 "\"g-wifi-default\""]
		foreach vap $vaplist {
			set vapname [cli_get_value $vap "" "" "name"]
			cli_exec_cmd $vdnode "config wireless-controller vap\nedit $vapname\nset utm-profile \"wifi-default\"\nnext\nend\n"
		}
	}
}
cli_on_rlimit_change
return 1
	%}

	"system global switch-controller" = %{
namespace import global::lldp_profile_add_act
set status [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $status eq "enable" } {
	set vdom_list [cli_get_tbl_list $CLI_VDOM_NODE ""]
	foreach e $vdom_list {
		set lldp [cli_get_node $e "switch-controller lldp-profile" "default" ""]
		lldp_profile_add_act $lldp
	}
}
return 1
	%}

	"router ospf ospf-interface" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set interface [cli_get_value $CLI_CUR_NODE "" "" "interface"]
set interface [string trim $interface \"]
set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $interface ""]
if { ![cli_ver_start 500 6] && $intf_node} {
	set intftype [cli_get_value $intf_node "" "" "type"]
	if { $intftype eq "tunnel" } {
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config router ospf\nconfig ospf-interface\nedit $name\nset network-type point-to-point\nend\nend\n"
	}
}
set auth [cli_get_value $CLI_CUR_NODE "" "" "authentication"]
if {$auth eq "md5"} {
	set md5key [cli_get_value $CLI_CUR_NODE "" "" "md5-key"]
	if {$md5key ne ""} {
		regsub -all {(ENC )} $md5key "ENC." md5key
		regsub -all {(,\")|(\",)|\"} $md5key " " md5key
		foreach {id md5} $md5key {
			regsub -all {(ENC.)} $md5 "ENC " md5
			if { [llength [split $md5 " "]] eq 1 } {
				set encryp [cli_get_devinfo "ospf_md5_key" "encode" "$md5"]
				cli_exec_cmd $CLI_CUR_VDOM_NODE "config router ospf\nconfig ospf-interface\nedit \"$name\"\nset md5-key $id \"ENC $encryp\"\nnext\nend\nend\n"
			}
		}
        }
}
return 1
	%}

        "spamfilter ipbwl entries" = %{
return 1
        %}

        "spamfilter iptrust entries" = %{
return 1
        %}

	"spamfilter profile imap" = %{
namespace import global::mime_field_format_check
set prof [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set tagtype [cli_get_value $CLI_CUR_NODE "" "" "tag-type"]
if {[string first "header" $tagtype] != -1} {
	set tagmsg [cli_get_value $CLI_CUR_NODE "" "" "tag-msg"]
	return [mime_field_format_check "imap" $prof $tagmsg]
}
return 1
	%}

	"spamfilter profile pop3" = %{
namespace import global::mime_field_format_check
set prof [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set tagtype [cli_get_value $CLI_CUR_NODE "" "" "tag-type"]
if {[string first "header" $tagtype] != -1} {
	set tagmsg [cli_get_value $CLI_CUR_NODE "" "" "tag-msg"]
	return [mime_field_format_check "pop3" $prof $tagmsg]
}
return 1
	%}

	"spamfilter profile smtp" = %{
namespace import global::mime_field_format_check
set prof [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set tagtype [cli_get_value $CLI_CUR_NODE "" "" "tag-type"]
if {[string first "header" $tagtype] != -1} {
	set tagmsg [cli_get_value $CLI_CUR_NODE "" "" "tag-msg"]
	return [mime_field_format_check "smtp" $prof $tagmsg]
}
return 1
	%}

	"spamfilter profile imaps" = %{
namespace import global::mime_field_format_check
set prof [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set tagtype [cli_get_value $CLI_CUR_NODE "" "" "tag-type"]
if {[string first "header" $tagtype] != -1} {
	set tagmsg [cli_get_value $CLI_CUR_NODE "" "" "tag-msg"]
	return [mime_field_format_check "imaps" $prof $tagmsg]
}
return 1
	%}

	"spamfilter profile pop3s" = %{
namespace import global::mime_field_format_check
set prof [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set tagtype [cli_get_value $CLI_CUR_NODE "" "" "tag-type"]
if {[string first "header" $tagtype] != -1} {
	set tagmsg [cli_get_value $CLI_CUR_NODE "" "" "tag-msg"]
	return [mime_field_format_check "pop3s" $prof $tagmsg]
}
return 1
	%}

	"spamfilter profile smtps" = %{
namespace import global::mime_field_format_check
set prof [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set tagtype [cli_get_value $CLI_CUR_NODE "" "" "tag-type"]
if {[string first "header" $tagtype] != -1} {
	set tagmsg [cli_get_value $CLI_CUR_NODE "" "" "tag-msg"]
	return [mime_field_format_check "smtps" $prof $tagmsg]
}
return 1
	%}

	"firewall mms-profile" = %{
if { [cli_ver_start 500 0] } {
	return 1
}
if {$CLI_ACT ne "add"} { return 1 }
if { [string match "*override*" [cli_get_clisrc]] } { return 1 }
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set cmd "config firewall mms-profile\nedit $name\n"
append cmd "config notification mm7\nset msg-type deliver-req\nset from-in-header disable\nend\n"
append cmd "config notification alert-flood-1\nset mmsc-port 80\nset from-in-header disable\nset days-allowed sunday monday tuesday wednesday thursday friday saturday\nset alert-int 1\nset alert-status enable\nend\n"
append cmd "config notification alert-flood-2\nset mmsc-port 80\nset from-in-header disable\nset days-allowed sunday monday tuesday wednesday thursday friday saturday\nset alert-int 1\nset alert-status enable\nend\n"
append cmd "config notification alert-flood-3\nset mmsc-port 80\nset from-in-header disable\nset days-allowed sunday monday tuesday wednesday thursday friday saturday\nset alert-int 1\nset alert-status enable\nend\n"
append cmd "config notification alert-dupe-1\nset mmsc-port 80\nset from-in-header disable\nset days-allowed sunday monday tuesday wednesday thursday friday saturday\nset alert-int 1\nset alert-status enable\nend\n"
append cmd "config notification alert-dupe-2\nset mmsc-port 80\nset from-in-header disable\nset days-allowed sunday monday tuesday wednesday thursday friday saturday\nset alert-int 1\nset alert-status enable\nend\n"
append cmd "config notification alert-dupe-3\nset mmsc-port 80\nset from-in-header disable\nset days-allowed sunday monday tuesday wednesday thursday friday saturday\nset alert-int 1\nset alert-status enable\nend\n"
append cmd "end\n"
cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
proc gen_mms_default { cat name } {
        return "config $cat $name\nset status1 disable\nset window1 60\nset limit1 100\nset block-time1 100\nset action1 block log\nset status2 disable\nset window2 70\nset limit2 110\nset block-time2 100\nset action2 block log\nset status3 disable\nset window3 80\nset limit3 120\nset block-time3 100\nset action3 block log\nend\n"
}
set cmd ""
append cmd [gen_mms_default "flood" "mm1"]
append cmd [gen_mms_default "flood" "mm4"]
append cmd [gen_mms_default "dupe" "mm1"]
append cmd [gen_mms_default "dupe" "mm4"]
cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall mms-profile\nedit \"$name\"\n$cmd\nnext\nend\n"
return 1
	%}

	"endpoint-control profile" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "profile-name"]
set ad [cli_get_value $CLI_CUR_NODE "" "" "application-detection"]
set adlist [cli_get_value $CLI_CUR_NODE "" "" "application-detection-rule-list"]
if {$ad eq "disable" && $adlist ne ""} {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config endpoint-control profile\nedit $name\nunset application-detection-rule-list\nend\n"
}
if { $CLI_ACT eq "add" } {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config endpoint-control profile\nmove \"$name\" before \"default\"\nend\n"
}
return 1
	%}

        "ips DoS" = %{
if {$CLI_ACT ne "add"} { return 1}
set list {
        {"tcp_syn_flood" "2000" "400" "2"}
        {"tcp_port_scan" "1000" "400" "2"}
        {"tcp_src_session" "5000" "400" "2"}
        {"tcp_dst_session" "5000" "400" "2"}
        {"udp_flood" "2000" "400" "2"}
        {"udp_scan" "2000" "400" "2"}
        {"udp_src_session" "5000" "400" "2"}
        {"udp_dst_session" "5000" "400" "2"}
        {"icmp_flood" "250" "400" "2"}
        {"icmp_sweep" "100" "400" "2"}
        {"icmp_src_session" "300" "400" "2"}
        {"icmp_dst_session" "1000" "400" "2"}
        {"ip_src_session" "5000" "400" "3"}
        {"ip_dst_session" "5000" "400" "3"}
}
set cmd ""
foreach e $list {
	set a [lindex $e 0]
	set v [lindex $e 1]
	set n [lindex $e 2]
	set m [lindex $e 3]
	if {![cli_get_node $CLI_CUR_NODE "anomaly" $a "threshold"]} {
		if { [cli_ver_start $n $m] } {
			append cmd "edit $a\nset threshold $v\nnext\n"
		}
	}
}
if { $cmd ne "" } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config ips DoS\nedit \"$name\"\nconfig anomaly\n$cmd\nend\nend\n"
}
return 1
        %}

        "system ha ha-mgmt-interface" = %{
set oldname [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { $oldname ne "" } {
       cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $oldname\nset vdom root\nunset ip\nnext\nend\n"
}
return 1
        %}
	"system ha ha-mgmt-status" = %{
set stat [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $stat eq "disable" } {
	set intf [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ha-mgmt-interface"]
	if { $intf ne "" } {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $intf\nset vdom root\nunset ip\nnext\nend\n"
	}
	cli_exec_cmd $CLI_GLOBAL_NODE "config system ha\nunset ha-mgmt-interface\nend\n"
}
return 1
%}
	"system ha mode" = %{
set mode [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $mode eq "standalone" } {
	set stat [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ha-mgmt-status"]
	set intf [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ha-mgmt-interface"]
	if { $stat eq "enable" && $intf ne "" } {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $intf\nset vdom root\nunset ip\nnext\nend\n"
	}
	cli_exec_cmd $CLI_GLOBAL_NODE "config system ha\nunset ha-mgmt-interface\nend\n"
	cli_exec_cmd $CLI_GLOBAL_NODE "config system ha\nunset ha-mgmt-status\nend\n"
}
return 1
%}
	"system ha" = %{
set mode [cli_get_value $CLI_CUR_NODE "" "" "mode"]
if { $mode eq "a-a" || $mode eq "a-p" } {
	set hamgmt [cli_get_value $CLI_CUR_NODE "" "" "ha-mgmt-status"]
	if { $hamgmt eq "enable" } {
		set intf [cli_get_value $CLI_CUR_NODE "" "" "ha-mgmt-interface"]
		if { $intf ne "" } {
			cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $intf\nunset vdom\nnext\nend\n"
		}
	}
}
return 1
	%}

        "router prefix-list rule" = %{
set parent [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "name"]
set id [cli_get_value $CLI_CUR_NODE "" "" ""]
set prefix [cli_get_value $CLI_CUR_NODE "" "" "prefix"]
set ge [cli_get_value $CLI_CUR_NODE "" "" "ge"]
set le [cli_get_value $CLI_CUR_NODE "" "" "le"]
set has_cmd 0
set cmd "config router prefix-list\nedit $parent\nconfig rule\nedit $id\n"
if {$prefix ne "any"} {
        if {$ge eq "0" || $ge eq ""} {
                set has_cmd 1
                append cmd "unset ge\n";
        }
        if {$le eq "0" || $le eq ""} {
                set has_cmd 1
                append cmd "unset le\n";
        }
}
if {$has_cmd} {
        append cmd "next\nend\nnext\nend\n"
        cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
}
return 1
        %}

        "firewall shaper traffic-shaper diffservcode" = %{
set shaper [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set code [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
set codelen [string length $code]
if {$codelen < 6} {
    set newcode [string repeat "0" [expr 6 - $codelen]]$code
    set cmd "config firewall shaper traffic-shaper\nedit \"$shaper\"\nset diffservcode $newcode\nend\n"
    cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
}
return 1
        %}
        "firewall shaper per-ip-shaper diffservcode-forward" = %{
set shaper [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set code [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
set codelen [string length $code]
if {$codelen < 6} {
    set newcode [string repeat "0" [expr 6 - $codelen]]$code
    set cmd "config firewall shaper per-ip-shaper\nedit \"$shaper\"\nset diffservcode-forward $newcode\nend\n"
    cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
}
return 1
    %}
        "firewall shaper per-ip-shaper diffservcode-rev" = %{
set shaper [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set code [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
set codelen [string length $code]
if {$codelen < 6} {
    set newcode [string repeat "0" [expr 6 - $codelen]]$code
    set cmd "config firewall shaper per-ip-shaper\nedit \"$shaper\"\nset diffservcode-rev $newcode\nend\n"
    cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
}
return 1
    %}

	"log fortianalyzer setting status" = %{
if { [cli_obj_support "log remote setting"] } {
	set faz_status [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "status"]
	if {$faz_status eq "disable"} {
		set vdom_list [cli_get_tbl_list $CLI_VDOM_NODE ""]
		foreach e $vdom_list {
			cli_exec_cmd $e "config log remote setting\nunset status\nunset destination\nend\n"
		}
	}
}
return 1
	%}

	"log remote setting status" = %{
set faz_status [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "status"]
if {$faz_status eq "disable"} {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config log remote setting\nunset status\nunset destination\nend\n"
}
return 1
	%}

        "wireless-controller wtp-profile ap-country" = %{
if {$CLI_ACT eq "add" || [string match "*script*" [cli_get_clisrc]]} {
	return 1
}
set ov [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set nv [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $ov eq $nv } {
	return 1
}
namespace import global::wtp_profile_platform
set type [wtp_profile_platform $CLI_CUR_PARENT_NODE]
set deftype [cli_get_defvalue "wireless-controller wtp-profile platform" "type"]
set  cmd  "config radio-1\nunset mode\nunset channel\nunset vaps\n"
if {[cli_obj_support "wireless-controller wtp-profile radio-1" "wids-profile"]} {
       	append cmd  "unset wids-profile\n"
}
set band [cli_get_devinfo "pm2_wl_band_dflt" "1" $type]
append cmd "set band $band\nend\n"
cli_exec_cmd $CLI_CUR_NODE  $cmd
set radio [cli_get_devinfo "pm2_wl_radio_enabled" "2" $type]
if { $radio eq "yes" } {
	set  cmd  "config radio-2\nunset mode\nunset channel\nunset vaps\n"
	if {[cli_obj_support "wireless-controller wtp-profile radio-2" "wids-profile"]} {
       		append cmd  "unset wids-profile\n"
	}
	set band [cli_get_devinfo "pm2_wl_band_dflt" "2" $type]
       	append cmd "set band $band\nend\n"
	cli_exec_cmd $CLI_CUR_NODE  $cmd
}
return 1
	%}

        "wireless-controller wtp-profile" = %{
set prof [cli_get_value $CLI_CUR_NODE "" "" ""]
set country [cli_get_value $CLI_CUR_NODE "" "" "ap-country"]
if { $country eq "" } {
	set country [cli_get_value $CLI_CUR_VDOM_NODE "wireless-controller setting" "" "country"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config wireless-controller wtp-profile\nedit $prof\nset ap-country $country\nend\n"
}
if { $CLI_ACT eq "add" } {
	if { [cli_branchpt_start 600 200] } {
		set ho_sta [cli_get_value $CLI_CUR_NODE "" "" "handoff-sta-thresh"]
		namespace import global::wtp_profile_platform
		set plat [wtp_profile_platform $CLI_CUR_NODE]
		set ho_sta_max [cli_get_devinfo "pm2_wl_handoff_sta_max" $plat]
		set ho_sta_max [expr {$ho_sta_max - 5}]
		if { ($ho_sta_max > 0) && ($ho_sta == 0 || ($ho_sta > 0 && $ho_sta > $ho_sta_max)) } {
			set ho_sta $ho_sta_max
			cli_exec_cmd $CLI_CUR_VDOM_NODE "config wireless-controller wtp-profile\nedit $prof\nset handoff-sta-thresh $ho_sta\nend\n"
		}
		if { [cli_obj_support "wireless-controller wtp-profile platform" "mode"] && [cli_get_devinfo "pm2_wl_radio_enabled" "3" $plat] eq "yes" } {
			set mode [cli_get_value $CLI_CUR_NODE "platform" "" "mode"]
			if { $mode ne "dual-5G" && [cli_get_value $CLI_CUR_NODE "radio-3" "" "mode"] eq "ap" } {
				cli_exec_cmd $CLI_CUR_NODE "config radio-3\nset mode monitor\nend\n"
			}
		}
	}
}
return 1
        %}

	"wireless-controller wtp-profile {radio-1 radio-2 radio-3} band" = %{
if {$CLI_ACT eq "add" || $CLI_ACT eq "edit" || [string match "*script*" [cli_get_clisrc]] || [string match "*gui*" [cli_get_clisrc]] } {
	return 1
}
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if { $mode eq "ap" } {
	set band [cli_get_value $CLI_CUR_NODE "" "" ""]
	set oldband [cli_get_org_value $CLI_CUR_NODE "" "" ""]
	if { $band ne $oldband && $oldband ne "" } {
		set  cmd  "config $CLI_CUR_PARENT_NAME\nunset channel\nend\n"
		cli_exec_cmd [cli_get_parent $CLI_CUR_PARENT_NODE] $cmd
	}
}
return 1
	%}
        "dlp fp-doc-source" = %{
set path [string trim [cli_get_value $CLI_CUR_NODE "" "" "file-path"] \"]
if {$path ne "" && [string index $path end] != "/"} {
	set n_path "\"$path/\""
	set name [cli_get_value $CLI_CUR_NODE "" "" ""]
        cli_exec_cmd $CLI_CUR_VDOM_NODE "config dlp fp-doc-source\nedit $name\nset file-path $n_path\nnext\nend\n"
}
return 1
        %}
        "log {fortiguard fortianalyzer} {setting override-setting} upload-option" = %{
set opt [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $opt eq "store-and-upload" } {
	set g [cli_get_devinfo "get_log_disk_info"]
	if { $g eq "NA" } {
		set g [cli_get_devinfo "hdd"]
	}
	if { $g ne "NA" } {
		if { $g eq "no" } {
			set cmd "config $CLI_CUR_PARENT_NAME\nset upload-option realtime\nend\n"
			cli_exec_cmd $CLI_GLOBAL_NODE $cmd
		}
	}
}
return 1
        %}
	"log {fortianalyzer2 fortianalyzer3} setting upload-option" = %{
set opt [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $opt eq "store-and-upload" } {
        set g [cli_get_devinfo "get_log_disk_info"]
        if { $g eq "NA" } {
                set g [cli_get_devinfo "hdd"]
        }
        if { $g ne "NA" } {
                if { $g eq "no" } {
                        set cmd "config $CLI_CUR_PARENT_NAME\nset upload-option realtime\nend\n"
                        cli_exec_cmd $CLI_GLOBAL_NODE $cmd
                }
        }
}
return 1
	%}
	"system virtual-switch" = %{
set intfname [cli_get_value $CLI_CUR_NODE "" "" "name"]
set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $intfname ""]
if {$CLI_ACT eq "add" && $intfnode eq 0} {
	set vdom $CLI_CUR_VDOM_NAME
	if {$vdom eq ""} {
		set vdom "root"
	}
	cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $intfname\nset vdom $vdom\nset type hard-switch\nnext\nend\n"
	if {[cli_obj_support "system interface" "snmp-index"]} {
		namespace import global::auto_set_snmp_index
		auto_set_snmp_index $intfname
	}
}
return 1
	%}
	"router ospf area virtual-link" = %{
set auth [cli_get_value $CLI_CUR_NODE "" "" "authentication"]
if {$auth eq "md5"} {
	set md5key [cli_get_value $CLI_CUR_NODE "" "" "md5-key"]
	if {$md5key ne ""} {
		regsub -all {(ENC )} $md5key "ENC." md5key
		regsub -all {(,\")|(\",)|\"} $md5key " " md5key
		foreach {id md5} $md5key {
			regsub -all {(ENC.)} $md5 "ENC " md5
			if { [llength [split $md5 " "]] eq 1 } {
				set encryp [cli_get_devinfo "ospf_md5_key" "encode" "$md5"]
				set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
				cli_exec_cmd [cli_get_parent $CLI_CUR_PARENT_NODE] "config virtual-link\nedit \"$name\"\nset md5-key $id \"ENC $encryp\"\nnext\nend\n"
			}
		}
	}
}
return 1
	%}
        "vpn ipsec {manualkey manualkey-interface} {authkey enckey auth-key enc-key}" = %{
set key [cli_get_value $CLI_CUR_NODE "" "" ""]
set key [string trim $key \"]
if { [string compare -length 5 $key "\'ENC "] } {
	set enc [cli_get_devinfo "ipsec_manualkey" "encode" $key]
	set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config $CLI_CUR_PARENT_NAME\n\nedit $name\nset $CLI_CUR_NODE_NAME $enc\nnext\nend\n"
}
return 1
        %}
        "router policy {src dst}" = %{
set seq [cli_get_value $CLI_CUR_PARENT_NODE "" "" "seq-num"]
set key [cli_get_value $CLI_CUR_NODE "" "" ""]
set iplist [split $key " "]
set nocmd 1
set ipmask ""
foreach key $iplist {
	set key [string trim $key \"]
	set ip [string range $key 0 [expr {[string first "/" $key] - 1}]]
	set ip [regsub -all {\.} $ip { }]
	set mask [string range $key [expr {[string first "/" $key] + 1}] end]
	set t [string first "." $mask]
	if { $t == -1 } {
		if {[scan $mask "%d" mask_v] != 1} {
			cli_set_errmsg "invalid value for router policy src/dst"
			return 0
		}
		set mask [expr {(0xFFFFFFFF << (32 - $mask_v)) & 0xFFFFFFFF}]
		set mask [format "%d.%d.%d.%d" [expr ($mask>>24)%256] [expr ($mask>>16)%256] [expr ($mask>>8)%256] [expr $mask%256]]
		set nocmd 0
	}
	set mask [regsub -all {\.} $mask { }]
	if { [llength $ip] ne 4 || [llength $mask] ne 4 } {
		cli_set_errmsg "invalid ip"
		return 0
	}
	set nip list
	lset nip [list [expr [lindex $ip 0] & [lindex $mask 0]] [expr [lindex $ip 1] & [lindex $mask 1]] \
	    [expr [lindex $ip 2] & [lindex $mask 2]] [expr [lindex $ip 3] & [lindex $mask 3]]]
	set dnip [regsub -all { } $nip {.}]
	set dmask [regsub -all { } $mask {.}]
	append ipmask " $dnip/$dmask"
	if { $nocmd == 1 && [lindex $nip 0] == [lindex $ip 0] && [lindex $nip 1] == [lindex $ip 1] &&
	    [lindex $nip 2] == [lindex $ip 2] && [lindex $nip 3] == [lindex $ip 3] } {
		continue;
	} else {
		set nocmd 0
	}
}
if { $nocmd == 0 } {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config router policy\n\nedit $seq\nset $CLI_CUR_NODE_NAME $ipmask\nnext\nend\n"
}
return 1
        %}
	"system replacemsg ftp" = %{
if { [cli_ver_start 500 0] } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "msg-type"]
	if { $name eq "ftp-explicit-banner" } {
		set omsg [cli_get_value $CLI_CUR_NODE "" "" "buffer"]
		set msg [split $omsg "\n"]
		set sz 0
		foreach m $msg {
			incr sz
		}
		set n ""
		if { $sz == 1 } {
			if { [string range $omsg 0 3] ne "220 " } {
				append n "220 "
				append n $omsg
			}
		} else {
			set i 0
			foreach m $msg {
				incr i
				if { $i == 1 } {
					if { [string range $m 0 3] ne "220-" } {
						append n "220-"
					}
				} elseif { $i == $sz } {
					if { [string range $m 0 3] ne "220 " } {
						append n "220 "
					}
				}
				append n $m
				append n "\n"
			}
		}
		cli_exec_cmd $CLI_GLOBAL_NODE "config system replacemsg ftp ftp-explicit-banner\nset buffer \"$n\"\nend\n"
	}
}
return 1
	%}
        "system settings manageip" = %{
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "opmode"]
if { $mode ne "transparent" } {
	return 1
}
set ip [cli_get_value $CLI_CUR_NODE "" "" ""]
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
	if { $number == 0 } {
		set ip1 [lindex $ipmask 0]
		set mask1 [lindex $ipmask 1]
	} else {
		set ip2 [lindex $ipmask 0]
		set mask2 [lindex $ipmask 1]
	}
	incr number
}
set has_cmd 0
if { $number >= 1 } {
	set tmp [string first "." $mask1]
	if { $tmp == -1 } {
		if {[scan $mask1 "%d" mask_v] != 1} {
			cli_set_errmsg "invalid value"
			return 0
		}
		set mask1 [expr {(0xFFFFFFFF << (32 - $mask_v)) & 0xFFFFFFFF}]
		set mask1 [format "%d.%d.%d.%d" [expr ($mask1>>24)%256] [expr ($mask1>>16)%256] [expr ($mask1>>8)%256] [expr $mask1%256]]
		set has_cmd 1
	}
}
if { $number > 1 } {
	set tmp [string first "." $mask2]
	if { $tmp == -1 } {
		if {[scan $mask2 "%d" mask_v] != 1} {
			cli_set_errmsg "invalid value"
			return 0
		}
		set mask2 [expr {(0xFFFFFFFF << (32 - $mask_v)) & 0xFFFFFFFF}]
		set mask2 [format "%d.%d.%d.%d" [expr ($mask2>>24)%256] [expr ($mask2>>16)%256] [expr ($mask2>>8)%256] [expr $mask2%256]]
		set has_cmd 1
	}
}
if { $has_cmd == 1 } {
	if { $number == 1 } {
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config system settings\n\nset $CLI_CUR_NODE_NAME $ip1/$mask1\nend\n"
	} else {
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config system settings\n\nset $CLI_CUR_NODE_NAME $ip1/$mask1 $ip2/$mask2\nend\n"
	}
}
return 1
        %}
	"system settings wccp-cache-engine" = %{
set intf_name "w.$CLI_CUR_VDOM_NAME"
set wccp [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $wccp eq "enable" } {
	set cmd "config system interface\n"
	append cmd "edit \"$intf_name\"\n"
	append cmd "set vdom $CLI_CUR_VDOM_NAME\n"
	append cmd "set type tunnel\nnext\nend\n"
	cli_exec_cmd $CLI_GLOBAL_NODE $cmd
	if {[cli_obj_support "system interface" "snmp-index"]} {
		namespace import global::auto_set_snmp_index
		auto_set_snmp_index $intf_name
	}
} elseif { $wccp eq "disable" } {
	set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $intf_name ""]
	if { $intfnode && [cli_is_referenced $intfnode] } {
		cli_set_errmsg "system interface $intf_name is being used"
		return 0
	}
	if { $intfnode } {
		set intftype [cli_get_value $intfnode "" "" "type"]
		if { $intftype eq "tunnel" } {
			cli_delete_node $intfnode
		}
	}
}
return 1
	%}
	"firewall mms-profile {flood dupe} {status1 status2 status3}" = %{
set proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if { $proto eq "mm1" || $proto eq "mm4" } {
	set cname $CLI_CUR_NODE_NAME
	set en [cli_get_value $CLI_CUR_PARENT_NODE "" "" $cname]
	if { $en eq "enable" } {
		if { $cname eq "status1" } {
			set cmd "set window1 60\nset limit1 100\nset block-time1 100\nset action1 block log\n"
		} elseif { $cname eq "status2" } {
			set cmd "set window2 70\nset limit2 110\nset block-time2 100\nset action2 block log\n"
		} elseif { $cname eq "status3" } {
			set cmd "set window3 80\nset limit3 120\nset block-time3 100\nset action3 block log\n"
		}
		cli_exec_cmd $CLI_CUR_PARENT_NODE $cmd
	}
}
return 1
	%}
	"firewall mms-profile notification" = %{
if { [cli_ver_start 500 4] } {
	if { [string match "*preload*" [cli_get_clisrc]] } {
		return 1
	}
}
if { ![cli_is_unset $CLI_CUR_NODE "" "" "alert-int"] } {
	set proto [cli_get_value $CLI_CUR_NODE "" "" "protocol"]
	if { [string compare -length 6 $proto "alert-"] == 0 } {
		cli_exec_cmd $CLI_CUR_NODE "set alert-status enable\n"
	}
}
return 1
	%}
	"certificate template" = %{
if { $CLI_ACT eq "add" } {
	set name [cli_get_value $CLI_CUR_NODE "" "" ""]
	set dyn_cert [cli_get_node $CLI_GLOBAL_NODE "dynamic certificate local" $name ""]
	if { !$dyn_cert } {
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config dynamic certificate local\nedit $name \nset description \"Automatically generated by certificate template\"\nend\nend\n"
	}
}
return 1
	%}
        "system interface mode" = %{
if {$CLI_ACT eq "unset"} {
        set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
        if { $name eq "adsl" } {
                if { [cli_has_feature "f_adsl"] || [cli_has_feature "f_adsl_amazon"] } {
                        cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit \"$name\"\nset mode eoa\nnext\nend\n"
                }
        } elseif { $name eq "modem" } {
                if { [cli_has_feature "f_modem"] } {
                        cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit \"$name\"\nset mode pppoe\nnext\nend\n"
                }
        }
}
set mode [cli_get_value $CLI_CUR_NODE "" "" ""]
set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
if { $mode ne "static" } {
	set vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vdom"]
	set vnode [cli_get_vdom_node $vdom]
	set svrs [cli_get_match_list $vnode 1 "system dhcp server" "server-type" 0 "regular" "interface" 0 "\"$ifname\"" "status" 0 "enable"]
	foreach e $svrs {
		set svrid [cli_get_value $e "" "" "id"]
		cli_exec_cmd $vnode "config system dhcp server\ndelete $svrid\nend\n"
	}
}
return 1
        %}
        "wireless-controller setting" = %{
namespace import global::ncfg_is_fapc_platform
namespace import global::ncfg_is_fapc_support_ctry
namespace import global::ncfg_add_default_fapc_wtpprof
namespace import global::cwAc_fapc_cleanup
if { ![cli_ver_start 500 2] } { return 1 }
set nv [cli_get_value $CLI_CUR_NODE "" "" "country"]
set ov [cli_get_org_value $CLI_CUR_NODE "" "" "country"]
if { $nv ne $ov } {
	namespace import global::ncfg_is_cw_wtpprof_used
        set list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "wireless-controller wtp-profile"]
        foreach n $list {
                cli_clear_value $n "radio-1" "" "channel"
                cli_clear_value $n "radio-2" "" "channel"
                cli_set_value $n "radio-1" "" "channel-bonding" "20MHz"
                cli_set_value $n "radio-2" "" "channel-bonding" "20MHz"
		set  profname [cli_get_value $n "" "" "name"]
		if { ![ncfg_is_cw_wtpprof_used $profname] } {
			cli_set_value $n "" "" "ap-country" $nv
		}
        }
}
if { [cli_branchpt_start 500 1105] && [ncfg_is_fapc_support_ctry $nv] } {
	set n_fapc [cli_get_value $CLI_CUR_NODE "" "" "fapc-compatibility"]
	set o_fapc [cli_get_org_value $CLI_CUR_NODE "" "" "fapc-compatibility"]
	if { $n_fapc ne $o_fapc } {
		if { $n_fapc eq "enable" } {
			if { ![ncfg_add_default_fapc_wtpprof $nv] } {
				return 0
			}
		} else {
			if { ![cwAc_fapc_cleanup] } {
				return 0
			}
		}
	}
}
return 1
        %}
        "application custom" = %{
namespace import global::app_cus_get_attr_value
set signature [cli_get_value $CLI_CUR_NODE "" "" "signature"]
set category [cli_get_value $CLI_CUR_NODE "" "" "category"]
set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
set appcat [app_cus_get_attr_value "--app_cat " $signature]
set vuln_id [app_cus_get_attr_value "--vuln_id " $signature]
set attack_id [app_cus_get_attr_value "--attack_id " $signature]

if {$appcat ne ""} {
	set category $appcat
} elseif {$category eq "" || $category eq "0"} {
	cli_set_errmsg "Missing application category"
	return 0
}
cli_set_value $CLI_CUR_NODE "" "" "category" $category

if {$vuln_id ne ""} {
        set id $vuln_id
} elseif {$attack_id ne ""} {
        set id $attack_id
}
if { $id ne "" } {
	if { $id < 1000 || $id > 9999 } {
		cli_set_errmsg "custom signature id must be between 1000 and 9999"
		return 0
	}
        cli_set_value $CLI_CUR_NODE "" "" "id" $id
}

if {$attack_id eq ""} {
        set tag [cli_get_value $CLI_CUR_NODE "" "" "tag"]
        set cmd "config application custom\nedit \"$tag\"\n"
        if {$vuln_id ne ""} {
                append cmd "set signature \"F-SBID( --attack_id $vuln_id;"
        } else {
                append cmd "set signature \"F-SBID( --attack_id 9820;"
        }
        set start [string first "(" $signature 0]
        incr start
        append cmd [string range $signature $start [string length $signature]]
        set cmd [string trimright $cmd "\""]
        append cmd "\"\nnext\nend\n"
        cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
}
return 1
        %}
	"system wccp server-list" = %{
set svrs [cli_get_value $CLI_CUR_NODE "" "" ""]
set cmd ""
set slash_style -1
foreach e $svrs {
	set e [string trim $e \"]
	set ipmask [split $e "/"]
	set len [llength $ipmask]
	if { $len == 2 } {
		if { $slash_style eq 0 } {
			cli_set_errmsg "must use \[ip mask\] pairs"
			return 0
		}
		set slash_style 1
		set ipmask [cli_format_ipmask $ipmask 2]
		foreach ip $ipmask {
			set cmd [cli_update_opts 1 $cmd $ip]
		}
	} elseif { $slash_style eq 1 } {
		cli_set_errmsg "no /, must use same style"
		return 0
	} else {
		set slash_style 0
		set cmd [cli_update_opts 1 $cmd $ipmask]
	}
}
set ipmask [split $cmd " "]
set len [llength $ipmask]
if { [expr ($len % 2)] != 0 } {
	cli_set_errmsg "must use \[ip mask\] pairs"
	return 0
}
namespace import global::cli_invalid_maskv4
namespace import global::cli_invalid_ipv4
foreach {ip mask} $cmd {
	if { [cli_invalid_ipv4 $ip] } {
		cli_set_errmsg "Invalid ip address: $ip"
		return 0
	}
	if { [cli_invalid_maskv4 $mask] } {
		cli_set_errmsg "Invalid netmask: $mask"
		return 0
	}
}
cli_set_value $CLI_CUR_PARENT_NODE "" "" "server-list" $cmd
return 1
	%}
	"system settings" = %{
set mn [cli_get_value $CLI_CUR_NODE "" "" "opmode"]
set mo [cli_get_org_value $CLI_CUR_NODE "" "" "opmode"]
if { $mn eq "transparent" && $mo eq "nat" } {
	namespace import global::get_mux_tunnel_dev_name
	set intfname [get_mux_tunnel_dev_name $CLI_CUR_VDOM_NAME]
	set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $intfname ""]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall address\nedit \"SSLVPN_TUNNEL_ADDR1\"\nunset associated-interface\nnext\nend\n"
	cli_delete_node $intfnode 1

	set nafname [string map {ssl. naf.} $intfname]
	set nafnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $nafname ""]
	if { $nafnode != 0 } {
		cli_delete_node $nafnode 1
	}
	set l2tname [string map {ssl. l2t.} $intfname]
	set l2tnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $l2tname ""]
	if { $l2tnode != 0 } {
		cli_delete_node $l2tnode 1
	}

} elseif { $mn eq "nat" && $mo eq "transparent" } {
	namespace import global::get_mux_tunnel_dev_name
	namespace import global::auto_set_snmp_index
	set intfname [get_mux_tunnel_dev_name $CLI_CUR_VDOM_NAME]
	cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $intfname\nset vdom $CLI_CUR_VDOM_NAME\nset type tunnel\nset alias \"SSL VPN interface\"\nnext\nend\n"
	auto_set_snmp_index $intfname

	if { [cli_branchpt_start 700 133] } {
		set nafname [string map {ssl. naf.} $intfname]
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $nafname\nset vdom $CLI_CUR_VDOM_NAME\nset type tunnel\nnext\nend\n"
		auto_set_snmp_index $nafname
		set l2tname [string map {ssl. l2t.} $intfname]
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $l2tname\nset vdom $CLI_CUR_VDOM_NAME\nset type tunnel\nnext\nend\n"
		auto_set_snmp_index $l2tname
	}

	cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall address\nedit \"SSLVPN_TUNNEL_ADDR1\"\nset type iprange\nset start-ip 10.212.134.200\nset end-ip 10.212.134.210\nnext\nend\n"
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall address6\nedit \"SSLVPN_TUNNEL_IPv6_ADDR1\"\nset ip6 fdff:ffff::/120\nnext\nend\n"
	set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
	set device [cli_get_value $CLI_CUR_NODE "" "" "device"]
	set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $device ""]
	cli_set_value $intfnode "" "" "ip" $ip
	cli_unset_value $CLI_CUR_NODE "" "" "ip"
	cli_unset_value $CLI_CUR_NODE "" "" "device"
}
return 1
	%}
	"system global admin-https-redirect" = %{
if { $CLI_GLOBAL_DEV } {
	return 1
}
namespace import global::global_admin_https_redirected_valid
set val [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [global_admin_https_redirected_valid] && $val eq "enable" } {
	set intflist [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
	foreach intf $intflist {
		set name [cli_get_value $intf "" "" "name"]
		set access [cli_get_value $intf "" "" "allowaccess"]
		if {[lsearch $access "http"] != -1 && [lsearch $access "https"] == -1} {
			cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit \"$name\"\nset allowaccess $access https\nend\n"
		}
	}
}
return 1
	%}
	"router static" = %{
set seq [cli_get_value $CLI_CUR_NODE "" "" "seq-num"]
set ip [cli_get_value $CLI_CUR_NODE "" "" "dst"]
if {$ip ne 0 && $ip ne ""} {
	set ip [cli_format_ipmask $ip 0]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config router static\nedit $seq\nset dst $ip\nnext\nend\n"
}
set distance [cli_get_value $CLI_CUR_NODE "" "" "distance"]
if { [cli_branchpt_start 600 1614] } {
	set sdwan "sdwan"
} else {
	set sdwan "virtual-wan-link"
}
set vwanlink [cli_get_value $CLI_CUR_NODE "" "" $sdwan]
set sdwan_zone [cli_get_value $CLI_CUR_NODE "" "" $sdwan-zone]
if { $vwanlink eq "enable" && $distance == 10 } {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config router static\nedit $seq\nset distance 1\nnext\nend\n"
}
if { $sdwan_zone ne "" && $distance == 10 } {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config router static\nedit $seq\nset distance 1\nnext\nend\n"
}
return 1
	%}
	"router static dstaddr" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] ne "" } {
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "dst"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "internet-service"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "internet-service-custom"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "virtual-wan-link"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "sdwan"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "sdwan-zone"
}
return 1
	%}
	"router static internet-service" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] ne "" } {
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "dst"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "dstaddr"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "internet-service-custom"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "virtual-wan-link"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "sdwan"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "sdwan-zone"
}
return 1
	%}
	"router static internet-service-custom" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] ne "" } {
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "dst"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "dstaddr"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "internet-service"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "virtual-wan-link"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "sdwan"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "sdwan-zone"
}
return 1
	%}
	"router static {virtual-wan-link sdwan}" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "enable" } {
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "dstaddr"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "internet-service"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "internet-service-custom"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "blackhole"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "dynamic-gateway"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "link-monitor-exempt"
}
return 1
	%}
	"router static sdwan-zone" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] ne "" } {
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "dstaddr"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "internet-service"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "internet-service-custom"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "blackhole"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "dynamic-gateway"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "link-monitor-exempt"
}
return 1
	%}
	"router static {blackhole dynamic-gateway link-monitor-exempt}" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "enable" } {
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "virtual-wan-link"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "sdwan"
	cli_unset_value $CLI_CUR_PARENT_NODE "" "" "sdwan-zone"
}
return 1
	%}
        "wireless-controller wtp {radio-1 radio-2}" = %{
namespace import global::capwap_mesh_enabled_vap_exist
namespace import global::capwap_mesh_intf_auto_add
namespace import global::capwap_mesh_intf_auto_del
namespace import global::ncfg_get_local_wtp_id
set wtp [cli_get_value [cli_get_parent $CLI_CUR_NODE] "" "" "wtp-id"]
if { $wtp eq [ncfg_get_local_wtp_id] } {
        set ovaps [cli_get_org_value $CLI_CUR_NODE "" "" "vaps"]
        set nvaps [cli_get_value $CLI_CUR_NODE "" "" "vaps"]
        if { $ovaps ne $nvaps } {
                set oe [capwap_mesh_enabled_vap_exist $ovaps]
                set ne [capwap_mesh_enabled_vap_exist $nvaps]
                if { $oe && !$ne } {
                        capwap_mesh_intf_auto_del
                } elseif { !$oe && $ne } {
                        capwap_mesh_intf_auto_add
                }
        }
}
return 1
        %}
	"switch-controller managed-switch ports members" = %{
set oldlist [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set newlist [cli_get_value $CLI_CUR_NODE "" "" ""]
set tname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-name"]
set pnode [cli_get_parent $CLI_CUR_PARENT_NODE]
set swnode [cli_get_parent $pnode]
set cmd ""
set defport ""

set fortilink [cli_get_value $swnode "" "" "fsw-wan1-peer"]
if { $fortilink eq 0 || $fortilink eq "" } {
	set fortilink [cli_get_value $swnode "" "" "fsw-wan2-peer"]
}
set fortilink [string trim $fortilink \"]

if {[cli_ver_start 600 4]} {
	set intflist [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
	foreach intf $intflist {
		set parent [string trim [cli_get_value $intf "" "" "interface"] \"]
		set feature [cli_get_value $intf "" "" "switch-controller-feature"]
		if { $parent eq $fortilink && $feature eq "default-vlan" } {
			set defport [cli_get_value $intf "" "" "name"]
			break
		}
	}
	if { $defport eq "" } {
		set defport "default"
	}
} else {
	set defport "vsw.$fortilink"
}

foreach m $oldlist {
	if {[lsearch $newlist $m] == -1} {
		set mnode [cli_get_node $pnode "" $m ""]
		set owner [cli_get_value $mnode "" "" "port-owner" 1]
		if { $owner eq $tname } {
			append cmd "edit $m\nunset port-owner\nset vlan \"$defport\"\nnext\n"
		}
	}
}
foreach m $newlist {
	if {[lsearch $oldlist $m] == -1} {
		append cmd "edit $m\nset port-owner \"$tname\"\nset trunk-member 1\nnext\n"
	}
}
if { $cmd ne "" } {
	set swname [cli_get_value $swnode "" "" ""]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config switch-controller managed-switch\nedit $swname\nconfig ports\n$cmd\nend\nend\n"
}
return 1
	%}
	"switch-controller switch-group" = %{
if { [cli_branchpt_start 600 1682] } {
	set flink [string trim [cli_get_value $CLI_CUR_NODE "" "" "fortilink"] \"]
	set members [cli_get_value $CLI_CUR_NODE "" "" "members"]
	set update 0

	foreach m $members {
		set mflink [cli_get_value $CLI_CUR_VDOM_NODE "switch-controller managed-switch" $m "fsw-wan1-peer"]
		if { $mflink eq 0 || $mflink eq "" } {
			set mflink [cli_get_value $CLI_CUR_VDOM_NODE "switch-controller managed-switch" $m "fsw-wan2-peer"]
		}
		if { $mflink eq 0 || $mflink eq "" } {
			cli_set_errmsg "Invalid fortilink interface for switch $m."
			return 0
		}

		set mflink [string trim $mflink \"]

		if { $flink eq 0 || $flink eq "" } {
			## workaround GUI-support issue, assume the fortilink of first switch to be fortilink of the group
			set flink $mflink
			set update 1
		} elseif { $flink ne $mflink } {
			cli_set_errmsg "All switch in switch-group must be under same fortilink $flink."
			return 0
		}
	}

	if { $flink eq 0 || $flink eq "" } {
		cli_set_errmsg "Fortilink interface should not be empty."
		return 0
	} else {
		set stat [cli_get_value $CLI_GLOBAL_NODE "system interface" $flink "fortilink"]
		if { $stat ne "enable" } {
			cli_set_errmsg "Invalid fortilink port $flink."
			return 0
		}
	}

	if { $update ne 0 } {
		cli_set_value $CLI_CUR_NODE "" "" "fortilink" $flink
	}
}
return 1
	%}
	"application internet-service-custom entry" = %{
## this logic is added so user can create entry through GUI CLI-only objects and should be taken out when GUI add a page for it ##
if { [string match "*gui*" [cli_get_clisrc]] } {
	set ns [cli_get_tbl_list $CLI_CUR_NODE "port-range"]
	if { $ns eq "" } {
		cli_exec_cmd $CLI_CUR_NODE "config port-range\nedit 1\nset start-port 1\nset end-port 65535\nend\n"
	}
}
return 1
	%}
	"webfilter profile ftgd-wf filters auth-usr-grp" = %{
set grpname [cli_get_value $CLI_CUR_NODE "" "" ""]
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
set grptype [cli_get_value $CLI_CUR_VDOM_NODE "user group" $grpname "group-type"]
if { ($action eq "authenticate" || $action eq "\"authenticate\"") &&
	($grptype eq "" || $grptype eq "guest" || $grptype eq "\"guest\"") } {
	cli_set_errmsg "Invalid auth-usr-grp. It cannot be empty or set to a guest group."
	return 0
}
return 1
	%}
	"webfilter profile ftgd-wf filters warn-duration" = %{
set duration [cli_get_value $CLI_CUR_NODE "" "" ""]
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "warning" || $action eq "\"warning\"" || $action eq "authenticate" || $action eq "\"authenticate\"" } {
	if { ([regexp {^((\d+)h)?((\d+)m)?((\d+)s)?$} $duration dm1 dm2 h dm3 m dm4 s] == 0) ||
		($h ne "" && $h > 23) || ($m ne "" && $m > 59) || ($s ne "" && $s > 59) } {
		cli_set_errmsg "Invalid $action warn-duration $duration. It should follow the following format: 23h59m59s"
		return 0;
	}
	set new_duration ""
	scan $h "%d" h
	scan $m "%d" m
	scan $s "%d" s
	if {$h ne "" && $h ne 0} {
		append new_duration "${h}h"
	}
	if {$m ne "" && $m ne 0} {
		append new_duration "${m}m"
	}
	if {$s ne "" && $s ne 0} {
		append new_duration "${s}s"
	}
	if {$new_duration != $duration} {
		cli_exec_cmd $CLI_CUR_PARENT_NODE "set warn-duration $new_duration\n"
	}
}
return 1
	%}
	"webfilter profile ftgd-wf quota duration" = %{
set duration [cli_get_value $CLI_CUR_NODE "" "" ""]
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "time" || $type eq "\"type\"" } {
	if { ([regexp {^((\d+)h)?((\d+)m)?((\d+)s)?$} $duration dm1 dm2 h dm3 m dm4 s] == 0) ||
		($h ne "" && $h > 23) || ($m ne "" && $m > 59) || ($s ne "" && $s > 59) } {
		cli_set_errmsg "Invalid quota duration $duration. It should follow the following format: 23h59m59s"
		return 0;
	}
	set new_duration ""
	scan $h "%d" h
	scan $m "%d" m
	scan $s "%d" s
	if {$h ne "" && $h ne 0} {
		append new_duration "${h}h"
	}
	if {$m ne "" && $m ne 0} {
		append new_duration "${m}m"
	}
	if {$s ne "" && $s ne 0} {
		append new_duration "${s}s"
	}
	if {$new_duration != $duration} {
		cli_exec_cmd $CLI_CUR_PARENT_NODE "set duration $new_duration\n"
	}
}
return 1
	%}
	"webfilter profile override ovrd-dur" = %{
set duration [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ([regexp {^((\d+)d)?((\d+)h)?((\d+)m)?$} $duration dm1 dm2 d dm3 h dm4 m] == 0) ||
	($d ne "" && $d > 364) || ($h ne "" && $h > 23) || ($m ne "" && $m > 59) ||
	($d eq "" && $h eq "" && $m < 5) } {
	cli_set_errmsg "Invalid override duration $duration. It should follow the following format: 364d23h59m"
	return 0
}
set new_duration ""
scan $d "%d" d
scan $h "%d" h
scan $m "%d" m
if {$d ne "" && $d ne 0} {
	append new_duration "${d}d"
}
if {$h ne "" && $h ne 0} {
	append new_duration "${h}h"
}
if {$m ne "" && $m ne 0} {
	append new_duration "${m}m"
}
if {$new_duration != $duration} {
	cli_exec_cmd $CLI_CUR_PARENT_NODE "set ovrd-dur $new_duration\n"
}
return 1
	%}
	"webfilter ftgd-local-rating" = %{
if { $CLI_ACT eq "add" } {
	set url1 [cli_get_value $CLI_CUR_NODE "" "" "url"]
	set url2 [cli_check_url 1 $url1]
	if {[string compare $url1 $url2] != 0} {
		set node [cli_get_node $CLI_CUR_VDOM_NODE "webfilter ftgd-local-rating" $url2 ""]
		if { $node != 0 } {
			cli_set_errmsg "Object already exists"
			return 0
		}
		cli_set_value $CLI_CUR_NODE "" "" "url" $url2
	}
}
return 1
	%}
	"system virtual-wire-pair" = %{
set members [cli_get_value $CLI_CUR_NODE "" "" "member"]
set status [cli_get_value $CLI_CUR_NODE "" "" "wildcard-vlan"]
foreach m $members {
	set intf [cli_get_node $CLI_GLOBAL_NODE "system interface" $m ""]
	if { $intf != 0 } {
		cli_set_value $intf "" "" "vlanforward" $status
	}
}
return 1
	%}

	"ips sensor entries" = %{
if { ![cli_ver_start 500 4] } { return 1 }
set expiry [cli_get_value $CLI_CUR_NODE "" "" "quarantine-expiry"]
set entryid [cli_get_value $CLI_CUR_NODE "" "" "id"]
set cmd "config entries\nedit $entryid\n"
if { $expiry ne "" } {
	namespace import global::fix_datetime_format
	set newv [fix_datetime_format $expiry]
	if { [string compare $expiry $newv] != 0 } {
		append cmd "set quarantine-expiry $newv\nend\n"
		set node [cli_get_parent $CLI_CUR_PARENT_NODE]
		cli_exec_cmd $node $cmd
	}
}
return 1
	%}
	"system interface fortilink" = %{
namespace import global::cli_ip2val
namespace import global::cli_val2ip

set status [cli_get_value $CLI_CUR_NODE "" "" ""]
set intf [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
set cmd ""

set defval [cli_get_defvalue "system interface" "fortilink"]
set org_status [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { $org_status eq "" && $status eq "disable" && $defval eq "disable" } {
    return 1
}

## system interface
if {$status eq "enable"} {
	if { [cli_branchpt_start 600 1054] } {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $intf\nset allowaccess ping fabric\nend\n"
	} else {
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $intf\nset allowaccess ping capwap\nend\n"
	}
}

## system ntp
set ntp [cli_get_node $CLI_GLOBAL_NODE "system ntp" "" ""]
set ntpintf 0
if { $ntp ne 0 } {
	set ntpintf [string trim [cli_get_value $ntp "" "" "interface"] \"]
}
if { $status eq "enable" || $ntpintf eq $intf } {
	append cmd "config system ntp\nset server-mode $status\n"
	if {$status eq "enable"} {
		append cmd "append interface $intf\n"
	}
	append cmd "end\n"
}

## system dhcp
if { [string match "*gui*" [cli_get_clisrc]] } {
	if {$status eq "enable"} {
		set ipmask [split [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ip"] " "]
		set ip [lindex $ipmask 0]
		set mask [lindex $ipmask 1]

		if { $ip ne "0.0.0.0" } {
			## skip if ip is 0.0.0.0, as it cannot generate a valid dhcp server config

			append cmd "config system dhcp server\n"
			append cmd "edit 0\nset ntp-service local\nset default-gateway $ip\nset netmask $mask\nset interface $intf\n"
			append cmd "config ip-range\n"

			set ipval [cli_ip2val $ip]
			set maskval [cli_ip2val $mask]
			set ipsval [expr ($ipval & $maskval) + 1]
			set ipeval [cli_ip2val [cli_val2ip [expr (($ipval & $maskval) | ~$maskval) - 1]]]

			if {$ipsval == $ipval} {
				set start [cli_val2ip [expr $ipsval + 1]]
				set end [cli_val2ip $ipeval]
				append cmd "edit 1\nset start-ip $start\nset end-ip $end\nnext\n"
			} elseif {$ipeval == $ipval} {
				set start [cli_val2ip $ipsval]
				set end [cli_val2ip [expr $ipeval - 1]]
				append cmd "edit 1\nset start-ip $start\nset end-ip $end\nnext\n"
			} elseif {$ipval < $ipsval || $ipval > $ipeval} {
				set start [cli_val2ip $ipsval]
				set end [cli_val2ip $ipeval]
				append cmd "edit 1\nset start-ip $start\nset end-ip $end\nnext\n"
			} else {
				set start1 [cli_val2ip $ipsval]
				set end1 [cli_val2ip [expr $ipval - 1]]
				set start2 [cli_val2ip [expr $ipval + 1]]
				set end2 [cli_val2ip $ipeval]
				append cmd "edit 1\nset start-ip $start1\nset end-ip $end1\nnext\n"
				append cmd "edit 2\nset start-ip $start2\nset end-ip $end2\nnext\n"
			}
			append cmd "end\n"
			append cmd "set vci-match enable\nset vci-string \"FortiSwitch\"\nend\n"
		}
	} else {
		set dhcp [cli_get_tbl_list $CLI_CUR_VDOM_NODE "system dhcp server"]
		foreach e $dhcp {
			set eid [cli_get_value $e "" "" "id"]
			set eintf [string trim [cli_get_value $e "" "" "interface"] "\""]
			set evci [cli_get_value $e "" "" "vci-string"]
			if {$eintf eq $intf && [string first "FortiSwitch" $evci] != -1} {
				cli_delete_node $e
			}
		}
	}
}
if {$cmd ne ""} {
	set vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vdom"]
	set vnode [cli_get_vdom_node $vdom]
	cli_exec_cmd $vnode $cmd
}
if { $status eq "enable" } {
	set ret [cli_check_fsp_config $CLI_CUR_NODE 1]
	if { $ret != 0 } {
		return 0
	}
}
return 1
	%}
	"switch-controller qos queue-policy" = %{
namespace import global::queue_policy_add_act
queue_policy_add_act $CLI_CUR_NODE
return 1
	%}
	"switch-controller lldp-profile" = %{
namespace import global::lldp_profile_add_act
lldp_profile_add_act $CLI_CUR_NODE
return 1
	%}
	"system sdn-connector" = %{
set port [cli_get_value $CLI_CUR_NODE "" "" "server-port"]
if { $CLI_ACT eq "add" } {
	set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
	if { $type eq "oci" } {
		return 1
	}
	if { $port eq 0 || $port == "" } {
		set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
		set cmd "config system sdn-connector\nedit $name\nset server-port 5671\nnext\nend\n"
		cli_exec_cmd $CLI_GLOBAL_NODE $cmd
	}
}
return 1
	%}
	"user local" = %{
set tf [cli_get_value $CLI_CUR_NODE "" "" "two-factor"]
if { $tf ne "fortitoken" } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config $CLI_CUR_NODE_NAME\nedit $name\nunset fortitoken\nend\n"
}
return 1
	%}
	"firewall vip" = %{
## repair invalid db entries and wrap each ip with quote during copy so config check can perform properly
if { ![string match "*override*" [cli_get_clisrc]] } { return 1 }
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set ipranges [cli_get_value $CLI_CUR_NODE "" "" "mappedip"]
set cmd "set mappedip "
set has_cmd 0
if { [cli_ver_start 600 4] } {
	foreach iprange $ipranges {
		set iprange [string trim $iprange \"]
		set iprange [split $iprange "-"]
		if { 2 == [llength $iprange] } {
			set startip [lindex $iprange 0]
			set endip [lindex $iprange 1]
			if { $startip eq $endip } {
				append cmd "\"$startip\" "
			} else {
				append cmd "\"$startip-$endip\" "
			}
		} else {
			append cmd "\"$iprange\" "
		}
		set has_cmd 1
	}
} else {
	foreach iprange $ipranges {
		set iprange [string trim $iprange \"]
		append cmd "\"$iprange\" "
		set has_cmd 1
	}
}
append cmd "\n"
if { $has_cmd } {
	cli_exec_cmd $CLI_CUR_NODE $cmd
}
return 1
	%}
	"switch-controller managed-switch" = %{
if { $CLI_ACT eq "add" } {
	set ret [cli_check_fsp_config $CLI_CUR_NODE 1]
	if { $ret != 0 } {
		return 0
	}

	## cannot trigger tcl node act from inside c callback function, so manually trigger it here
	namespace import global::lldp_profile_add_act

	set intflist [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
	set linkintf ""
	foreach intf $intflist {
		set flink [cli_get_value $intf "" "" "fortilink"]
		set vdom [string trim [cli_get_value $intf "" "" "vdom"] \"]
		if { $flink eq "enable" && $vdom eq $CLI_CUR_VDOM_NAME } {
			set linkintf [cli_get_value $intf "" "" "name"]
			break
		}
	}
	if { $linkintf ne "" } {
		set lldp [cli_get_node $CLI_CUR_VDOM_NODE "switch-controller lldp-profile" "fortivoice.$linkintf" ""]
		if { $lldp ne 0 } {
			lldp_profile_add_act $lldp
		}
	}
}
return 1
	%}
	"user quarantine" = %{
if { [cli_ver_start 600 4] } {
	set fw_grps [cli_get_value $CLI_CUR_NODE "" "" "firewall-groups"]
	set status [cli_get_value $CLI_CUR_NODE "" "" "quarantine"]
	if { $status eq "disable" } {
		return 1
	}

	#if no firewall-groups specified, default to QuarantinedDevices
	if { $fw_grps eq "" } {
		set fw_grps "QuarantinedDevices"
	}
	set fw_grps [string map {\" ""} $fw_grps]
	#if firewall group does not exist, create it and add a dummy mac as member
	if {![cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall addrgrp" "name" 0 $fw_grps]} {
		set dummy "qtn.mac_00:00:00:00:00:00"
		if {![cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall address" "name" 0 $dummy]} {
			cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall address\nedit $dummy\nset type mac\nset comment \"Quarantine dummy MAC to keep the addrgrp\"\nend\n"
		}
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall addrgrp\nedit $fw_grps\nset member $dummy\nend\n"
	}

	set orig_members [cli_get_value $CLI_CUR_VDOM_NODE "firewall addrgrp" $fw_grps "member"]
	set orig_members [join $orig_members " "]
	set targets [cli_get_tbl_list $CLI_CUR_NODE "targets"]
	set members "qtn.mac_00:00:00:00:00:00"
	foreach t $targets {
		set macs [cli_get_tbl_list $t "macs"]
		foreach mac $macs {
			set mac [cli_get_value $mac "" "" "mac"]
			set mac_name "qtn.mac_$mac"
			if {![cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall address" "name" 0 $mac_name]} {
				cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall address\nedit $mac_name\nset type mac\nset comment \"Quarantine MAC\"\nset start-mac $mac\nset end-mac $mac\nend\n"
			}
			set members "$members $mac_name"
		}
	}
	foreach mem $members {
		dict set d_members $mem 1
	}
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall addrgrp\nedit $fw_grps\nset member $members\nend\n"
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config user quarantine\nset firewall-groups $fw_grps\nend\n"

	foreach mem $orig_members {
		if { ![dict exists $d_members $mem] } {
			set fw_addr [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $mem ""]
			if {![cli_is_referenced $fw_addr]} {
				cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall address\n delete $mem\nend\n"
			}
		}
	}
}
return 1
	%}
	"user quarantine targets macs" = %{
set targets [cli_get_parent $CLI_CUR_PARENT_NODE]
set quar [cli_get_parent [cli_get_parent $targets]]
cli_schedule_post_check $quar "edit"
return 1
%}
    "user quarantine quarantine" = %{
set old [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set new [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $old eq "disable" && $new eq "enable" } {
    set fswnodes [cli_get_tbl_list $CLI_CUR_VDOM_NODE "switch-controller managed-switch"]
    foreach node $fswnodes {
		set ret [cli_check_fsp_config $node 1 1]
        if { $ret != 0 } {
            return 0
        }
    }
}
return 1
    %}
    "switch-controller quarantine quarantine" = %{
set old [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set new [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $old eq "disable" && $new eq "enable" } {
    set fswnodes [cli_get_tbl_list $CLI_CUR_VDOM_NODE "switch-controller managed-switch"]
    foreach node $fswnodes {
		set ret [cli_check_fsp_config $node 1 1]
        if { $ret != 0 } {
            return 0
        }
    }
}
return 1
    %}
	"switch-controller {port-policy dynamic-port-policy}" = %{
if { $CLI_ACT eq "add" } {
	set fortilink [cli_get_value $CLI_CUR_NODE "" "" "fortilink"]
	if { $fortilink eq "" || $fortilink eq 0 } {
		set intflist [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
		set fortilink ""
		foreach intf $intflist {
			set flink [cli_get_value $intf "" "" "fortilink"]
			set vdom [string trim [cli_get_value $intf "" "" "vdom"] \"]
			if { $flink eq "enable" && $vdom eq $CLI_CUR_VDOM_NAME } {
				set fortilink [cli_get_value $intf "" "" "name"]
				break
			}
		}
		if { $fortilink ne "" } {
			cli_set_value $CLI_CUR_NODE "" "" "fortilink" $fortilink
		}
	}
}
return 1
	%}
	"webfilter profile ftgd-wf {category-override exempt-quota ovrd}" = %{
set list [cli_get_value $CLI_CUR_NODE "" "" ""]
set newlist [cli_collapse_ftgd_categories $list]
if {$list ne $newlist} {
	set prof [cli_get_parent $CLI_CUR_PARENT_NODE]
	set profname [cli_get_value $prof "" "" "name"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config webfilter profile\nedit $profname\nconfig ftgd-wf\nset $CLI_CUR_NODE_NAME $newlist\nend\nend\n"
}
return 1
	%}
	"webfilter profile ftgd-wf quota category" = %{
set list [cli_get_value $CLI_CUR_NODE "" "" ""]
set newlist [cli_collapse_ftgd_categories $list]
if {$list ne $newlist} {
	set quotaid [cli_get_value $CLI_CUR_PARENT_NODE "" "" "id"]
	set prof [cli_get_parent [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]]]
	set profname [cli_get_value $prof "" "" "name"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config webfilter profile\nedit $profname\nconfig ftgd-wf\n config quota\nedit $quotaid\nset $CLI_CUR_NODE_NAME $newlist\nend\nend\nend\n"
}
return 1
	%}
	"emailfilter profile {imap pop3 smtp}" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "tag-type"]
set msg [cli_get_value $CLI_CUR_NODE "" "" "tag-msg"]
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set cmd ""
if {[lsearch $type "header"] != -1} {
	if {$msg eq ""} {
		set cmd "set tag-msg \"X-Spam:\"\n"
	} elseif {[string first ":" $msg] eq -1 && [string index $msg end] ne ":"} {
		set cmd "set tag-msg ${msg}:\n"
	}
	if {$cmd ne ""} {
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config emailfilter profile\nedit $name\nconfig $CLI_CUR_NODE_NAME\n$cmd\nend\nend\n"
	}
}
return 1
	%}
	"user device" = %{
set type_name [cli_get_value $CLI_CUR_NODE "" "" "type"]
set type_cate "none"
if { [string match -nocase $type_name "ipad"] ||
     [string match -nocase $type_name "iphone"] } {
	set type_cate "ios-device"
} elseif { [string match -nocase $type_name "gaming-console"] ||
           [string match -nocase $type_name "linux-pc"] ||
	   [string match -nocase $type_name "mac"] ||
	   [string match -nocase $type_name "media-streaming"] ||
	   [string match -nocase $type_name "ip-phone"] ||
	   [string match -nocase $type_name "router-nat-device"] ||
	   [string match -nocase $type_name "printer"] } {
	set type_cate "none"
} elseif { [string match -nocase $type_name "blackberry-phone"] ||
           [string match -nocase $type_name "blackberry-playbook"] } {
	set type_cate "blackberry-device"
} elseif { [string match -nocase $type_name "windows-pc"] ||
           [string match -nocase $type_name "windows-phone"] ||
	   [string match -nocase $type_name "windows-tablet"] } {
	set type_cate "windows-device"
} elseif { [string match -nocase $type_name "android-phone"] ||
           [string match -nocase $type_name "android-tablet"] } {
	set type_cate "android-device"
} elseif { [string match -nocase $type_name "fortinet-device"] ||
           [string match -nocase $type_name "fortifone"] ||
	   [string match -nocase $type_name "forticam"] } {
	set type_cate "fortinet-device"
} else {
	set type_cate "none"
}

set category [cli_get_value $CLI_CUR_NODE "" "" "category"]
if { $category ne $type_cate } {
	cli_set_value $CLI_CUR_NODE "" "" "category" $type_cate
}
return 1
	%}

        "firewall ssl-ssh-profile" = %{
if { $CLI_ACT ne "add" } {
	return 1
}
if { [string match "*override*" [cli_get_clisrc]] } {
	return 1
}
set inspect_all [cli_get_value $CLI_CUR_NODE "ssl" "" "inspect-all"]
set list {
	{"https" "443"}
	{"ftps" "990"}
	{"imaps" "993"}
	{"pop3s" "995"}
	{"smtps" "465"}
	{"ssh" "22"}
}
set cmd ""
foreach e $list {
        set n [lindex $e 0]
        set p [lindex $e 1]
	set prot_node [cli_get_node $CLI_CUR_NODE $n "" ""]
	if { $prot_node == 0 } {
                append cmd "config $n\nset ports $p\nend\n"
	} else {
		if { $n eq "ssh" } {
			set inspect_all [cli_get_value $prot_node "" "" "inspect-all"]
		}
		if { $inspect_all eq "disable" } {
			set ports [cli_get_value $prot_node "" "" "ports"]
			if { $ports eq "" || $ports == 0 || [llength $ports] == 0 } {
				append cmd "config $n\nset ports $p\nend\n"
			}
		}
	}
}
if { $CLI_CUR_NODE_NAME eq "firewall ssl-ssh-profile" } {
	set ssl {
		{"1" "31"}
		{"2" "33"}
		{"3" "87"}
	}
	foreach e $ssl {
		set i [lindex $e 0]
		set v [lindex $e 1]
		if {![cli_get_node $CLI_CUR_NODE "ssl-exempt" $i ""]} {
			append cmd "config ssl-exempt\nedit $i\nset fortiguard-category $v\nnext\nend\n"
		}
	}
}
if { $cmd ne "" } {
        # Fixing #821778, the original command: cli_exec_cmd $CLI_CUR_VDOM_NODE "config $CLI_CUR_NODE_NAME\nedit \"$name\"\n$cmd\nnext\nend\n" was changed to "cli_exec_cmd $CLI_CUR_NODE cmd" which execute the command under current node to keep same behaviour and prevent the "preload.c" from overriding the script.
        cli_exec_cmd $CLI_CUR_NODE $cmd
}
return 1
        %}
        "system pppoe-interface" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set intf [string trim [cli_get_value $CLI_CUR_NODE "" "" "device"] \"]
if { $intf eq "" || $intf eq 0 } {
	cli_set_errmsg "Attribute 'device' must be set."
	return 0
}
set cmd "config system interface\nedit \"$name\"\nset vdom $CLI_CUR_VDOM_NAME\nset type tunnel\nset mode pppoe\nset interface $intf\nnext\nend\n"
cli_exec_cmd $CLI_GLOBAL_NODE $cmd

if { $CLI_ACT eq "add" && [cli_obj_support "system interface" "snmp-index"] } {
	set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
	if { $intf_node && [cli_get_value $intf_node "" "" "snmp-index"] == 0 } {
		namespace import global::auto_set_snmp_index
		auto_set_snmp_index $name
	}
}
return 1
        %}
		"system geneve" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set intf [string trim [cli_get_value $CLI_CUR_NODE "" "" "interface"] \"]
if { $CLI_ACT eq "add" && [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""] } {
	cli_set_errmsg "Name $name conflicts with system interface name"
	return 0
}
set cmd "config system interface\nedit \"$name\"\nset vdom $CLI_CUR_VDOM_NAME\nset type geneve\nset interface $intf\nnext\nend\n"
cli_exec_cmd $CLI_GLOBAL_NODE $cmd
if { $CLI_ACT eq "add" && [cli_obj_support "system interface" "snmp-index"] } {
	set intf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
	if { $intf_node && [cli_get_value $intf_node "" "" "snmp-index"] == 0 } {
		namespace import global::auto_set_snmp_index
		auto_set_snmp_index $name
	}
}
return 1
		%}
	"firewall internet-service-custom entry" = %{
set proto [cli_get_value $CLI_CUR_NODE "" "" "protocol"]
set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
set svcname [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "name"]
if { $proto == 6 || $proto == 17 || $proto == 132 } {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall internet-service-custom\nedit $svcname\nconfig entry\nedit $id\nconfig port-range\nedit 1\n\nnext\nend\nnext\nend\nnext\nend\n"
}
return 1
	%}
	"firewall shaper traffic-shaper" = %{
set unit [string trim [cli_get_value $CLI_CUR_NODE "" "" "bandwidth-unit"] \"]
if { ![cli_has_feature "f_x86_64"] && $unit ne "kbps" } {
	## auto convert to kbps
	set gbw [cli_get_value $CLI_CUR_NODE "" "" "guaranteed-bandwidth"]
	set mbw [cli_get_value $CLI_CUR_NODE "" "" "maximum-bandwidth"]
	set ebw [cli_get_value $CLI_CUR_NODE "" "" "exceed-bandwidth"]
	if { $unit eq "mbps" } {
		set ngbw [expr $gbw * 1024]
		set nmbw [expr $mbw * 1024]
		set nebw [expr $ebw * 1024]
	} elseif { $unit eq "gbps" } {
		set ngbw [expr $gbw * 1024 * 1024]
		set nmbw [expr $mbw * 1024 * 1024]
		set nebw [expr $ebw * 1024 * 1024]
	}
	if { $ngbw > 16776000 } {
		cli_set_errmsg "guaranteed-bandwidth over 16776000 limit after conversion"
		return 0
	}
	if { $nmbw > 16776000 } {
		cli_set_errmsg "maximum-bandwidth over 16776000 limit after conversion"
		return 0
	}
	if { $nebw > 16776000 } {
		cli_set_errmsg "exceed-bandwidth over 16776000 limit after conversion"
		return 0
	}
	cli_set_value $CLI_CUR_NODE "" "" "guaranteed-bandwidth" $ngbw
	cli_set_value $CLI_CUR_NODE "" "" "maximum-bandwidth" $nmbw
	cli_set_value $CLI_CUR_NODE "" "" "exceed-bandwidth" $nebw
	cli_set_value $CLI_CUR_NODE "" "" "bandwidth-unit" "kbps"
}
return 1
	%}
	"firewall shaper per-ip-shaper" = %{
set unit [string trim [cli_get_value $CLI_CUR_NODE "" "" "bandwidth-unit"] \"]
if { ![cli_has_feature "f_x86_64"] && $unit ne "kbps" } {
	## auto convert to kbps
	set bw [cli_get_value $CLI_CUR_NODE "" "" "max-bandwidth"]
	if { $unit eq "mbps" } {
		set nbw [expr $bw * 1024]
	} elseif { $unit eq "gbps" } {
		set nbw [expr $bw * 1024 * 1024]
	}
	if { $nbw > 16776000 } {
		cli_set_errmsg "max-bandwidth over 16776000 limit after conversion"
		return 0
	}
	cli_set_value $CLI_CUR_NODE "" "" "max-bandwidth" $nbw
	cli_set_value $CLI_CUR_NODE "" "" "bandwidth-unit" "kbps"
}
return 1
	%}
	"firewall consolidated policy" = %{
set srcaddr6 [cli_get_value $CLI_CUR_NODE "" "" "srcaddr6"]
set dstaddr6 [cli_get_value $CLI_CUR_NODE "" "" "dstaddr6"]
if { ($srcaddr6 ne "" && $dstaddr6 eq "") || ($srcaddr6 eq "" && $dstaddr6 ne "") } {
	set none_addr6 [cli_get_node $CLI_CUR_VDOM_NODE "firewall address6" "none" ""]
	if { $none_addr6 == 0 } {
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall address6\nedit \"none\"\nset ip6 ::/128\nnext\nend\n"
	}
	if { $srcaddr6 eq "" } {
		cli_set_value $CLI_CUR_NODE "" "" "srcaddr6" "none"
	}
	if { $dstaddr6 eq "" } {
		cli_set_value $CLI_CUR_NODE "" "" "dstaddr6" "none"
	}
}
return 1
	%}
	"firewall profile-protocol-options http" = %{
if { [cli_ver_start 600 0] } {
	set options [cli_get_value $CLI_CUR_NODE "" "" "options"]
	set postlang [cli_get_value $CLI_CUR_NODE "" "" "post-lang"]
	set cmd ""
	set has_cmd 0
	if { $options eq "" } {
		append cmd "unset options\n"
		set has_cmd 1
	}
	if { $postlang eq "" } {
		append cmd "unset post-lang\n"
		set has_cmd 1
	}
	if { $has_cmd } {
		cli_exec_cmd $CLI_CUR_NODE $cmd
	}
}
return 1
	%}
	"system interface ip" = %{
# Sync device interface-subnet address with new interface IP
set intf [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set ip [cli_get_value $CLI_CUR_NODE "" "" ""]
set addrlist [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "firewall address" "interface" 0 $intf]
foreach addr $addrlist {
	if { [cli_get_value $addr "" "" "type"] eq "interface-subnet" } {
		cli_set_value $addr "" "" "subnet" $ip
	}
}
return 1
	%}
	"file-filter profile rules" = %{
set opts [cli_get_value $CLI_CUR_NODE "" "" "file-type"]
if { [cli_branchpt_start 600 148] } {
	set opts [cli_update_opts 0 $opts "hibun" "ignored" "prc"]
} else {
	set opts [cli_update_opts 0 $opts "chm" "crx" "dmg" ".net" "iso" "mach-o" "xar"]
}
if { ![cli_branchpt_start 600 909] } {
	set opts [cli_update_opts 0 $opts "flac"]
}
if { [cli_branchpt_start 600 1677] } {
	set opts [cli_update_opts 0 $opts "bin" "unknown"]
}
if { [cli_branchpt_start 600 1748] } {
	set opts [cli_update_opts 0 $opts "msc"]
}
cli_exec_cmd $CLI_CUR_NODE "set file-type $opts\n"
return 1
	%}
    "system sdwan health-check" = %{
set old [cli_get_org_value $CLI_CUR_NODE "" "" "system-dns"]
set new [cli_get_value $CLI_CUR_NODE "" "" "system-dns"]
if { $old ne $new && $new eq "enable" } {
    cli_set_value $CLI_CUR_NODE "" "" "protocol" "dns"
}
return 1
    %}
    "system sdwan members" = %{
set intf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
if {$intf ne 0 && ($intf eq "" || $intf eq "''")} {
	cli_unset_value $CLI_CUR_NODE "" "" "interface"
}
return 1
	%}
%};
