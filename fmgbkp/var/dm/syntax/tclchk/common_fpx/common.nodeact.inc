nodeact %{
	"system admin" = %{
set hascmd 0
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set vdom [cli_get_value $CLI_CUR_NODE "" "" "vdom"]
set cmd "config system admin\nedit $name\n"
set is_admin [cli_get_value $CLI_CUR_NODE "" "" "is-admin"]
if {$is_admin ne "" && $is_admin != 0} {
	set hascmd 1
	append cmd "set accprofile super_admin\n"
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

if { $is_peer_auth == 0 && ($is_remote_auth == 0 || $any_user == 0) } {
set passwd_new [cli_get_value $CLI_CUR_NODE "" "" "password"]
set passwd_org [cli_get_org_value $CLI_CUR_NODE "" "" "password"]

if { $CLI_ACT eq "add" || ($passwd_new != $passwd_org) } {
	set guest_auth [cli_get_value $CLI_CUR_NODE "" "" "guest-auth"]
	if { $guest_auth eq "enable" } {
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
set tunname [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $type eq "ddns" } {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface\nedit \"$tunname\"\nunset remote-gw\nend\n"
}
set phyintf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
cli_set_modify_flag 0
cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit \"$tunname\"\nset vdom $CLI_CUR_VDOM_NAME\nset type tunnel\nset interface $phyintf\nend\n"
if {[cli_obj_support "system interface" "snmp-index"]} {
	namespace import global::auto_set_snmp_index
	auto_set_snmp_index $tunname
}
cli_set_modify_flag 1
return 1
	%}

         "ips global" = %{
set hascmd 0
set cmd "config ips global\n"
set count [cli_get_value $CLI_CUR_NODE "" "" "engine-count"]
if {$count > 8} {
	set hascmd 1
	append cmd "set engine-count 8\n"
}
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
if { [cli_ver_start 700 2] } {
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
if { [cli_ver_start 700 2] } {
	if {$CLI_ACT eq "add"} {
		if { [cli_get_devinfo "vdom-admin"] ne "yes" } {
			cli_set_value $CLI_CUR_NODE "" "" "range" "global"
		}
	}
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
	"application list entries" = %{
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
	if { [lindex $nip 0] == [lindex $ip 0] && [lindex $nip 1] == [lindex $ip 1] && \
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
                if { 1 } {
                        set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
                        append cmd "edit $id\n"
                }
		append cmd $c
                append cmd "end\nend\n"
                cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
	}
}
if { [cli_get_value $CLI_CUR_NODE "" "" "type"] eq "simple" } {
	set url [cli_get_value $CLI_CUR_NODE "" "" "url"]
	set new_url [cli_check_url 1 $url]
	if {[string compare $url $new_url] != 0} {
		set pid [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "id"]
		set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
		set cmd "config webfilter urlfilter\nedit $pid\nconfig entries\nedit $id\nset url \"$new_url\"\n"
		append cmd "next\nend\nnext\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
	}
}
return 1
	%}

	"system global vdom-mode" = %{
set oldval [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set status [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $oldval eq $status } {
	return 1
}
if { $status eq "multi-vdom" } {
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
		cli_exec_cmd $CLI_GLOBAL_NODE "config system resource-limits\nset log-disk-quota $quota\nend\n"
	}
	set comment "Default"
	cli_exec_cmd [cli_get_vdom_node "root"] "config system replacemsg-group\nedit \"default\"\nset comment \"$comment\"\nnext\nend\n"

	namespace import global::sync_certs_between_global_vdom
	set cmd [sync_certs_between_global_vdom $CLI_CUR_VDOM_NODE "vpn certificate local"]
	cli_exec_cmd $CLI_GLOBAL_NODE "config certificate local\n$cmd\nend\n"
	set cmd [sync_certs_between_global_vdom $CLI_CUR_VDOM_NODE "vpn certificate crl"]
	cli_exec_cmd $CLI_GLOBAL_NODE "config certificate crl\n$cmd\nend\n"
	set cmd [sync_certs_between_global_vdom $CLI_CUR_VDOM_NODE "vpn certificate ca"]
	cli_exec_cmd $CLI_GLOBAL_NODE "config certificate ca\n$cmd\nend\n"
	set cmd [sync_certs_between_global_vdom $CLI_CUR_VDOM_NODE "vpn certificate remote"]
	cli_exec_cmd $CLI_GLOBAL_NODE "config certificate remote\n$cmd\nend\n"

	if { [cli_has_npuvlink] } {
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
	set root_vdnode $CLI_CUR_VDOM_NODE

} else {
	set hanode [cli_get_node $CLI_GLOBAL_NODE "system ha" "" ""]
	if {$hanode != 0} {
		set primary [cli_get_value $hanode "" "" "vdom"]
		if { ($primary != 0) && ($primary ne "") } {
			cli_exec_cmd $CLI_GLOBAL_NODE "config system ha\nunset vdom\nend\n"
		}
	}
	cli_exec_cmd $CLI_GLOBAL_NODE "config system replacemsg-group\ndelete \"default\"\nend\n"

	namespace import global::sync_certs_between_global_vdom
	set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate local"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate local\n$cmd\nend\n"
	set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate crl"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate crl\n$cmd\nend\n"
	set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate ca"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate ca\n$cmd\nend\n"
	set cmd [sync_certs_between_global_vdom $CLI_GLOBAL_NODE "certificate remote"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate remote\n$cmd\nend\n"

	if { [cli_has_npuvlink] } {
		set vlinks [cli_npuvlink_list]
		foreach vlink $vlinks {
			set name [string trim $vlink \"]
			cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\ndelete $name\nend\n"
		}
	}
	cli_exec_cmd $CLI_GLOBAL_NODE "config system global\nset long-vdom-name disable\nend\n"

	set vdnode $CLI_CUR_VDOM_NODE
	if { 1 } {
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
}
cli_on_rlimit_change
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
        "router policy {src dst}" = %{
set seq [cli_get_value $CLI_CUR_PARENT_NODE "" "" "seq-num"]
set key [cli_get_value $CLI_CUR_NODE "" "" ""]
set iplist [split $key " "]
set nocmd 1
set ipmask ""
foreach key $iplist {
	set key [string trim $key \"]
	set fmtkey [cli_format_ipmask $key 0]
	if { $fmtkey eq "" } {
		cli_set_errmsg "invalid value for router policy src/dst"
		return 0
	} elseif { $fmtkey ne $key } {
		set nocmd 0
	}
	append ipmask " $fmtkey"
}
if { $nocmd == 0 } {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config router policy\n\nedit $seq\nset $CLI_CUR_NODE_NAME $ipmask\nnext\nend\n"
}
return 1
        %}
	"system replacemsg ftp" = %{
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
} elseif { $mn eq "nat" && $mo eq "transparent" } {
	namespace import global::get_mux_tunnel_dev_name
	namespace import global::auto_set_snmp_index
	set intfname [get_mux_tunnel_dev_name $CLI_CUR_VDOM_NAME]
	cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $intfname\nset vdom $CLI_CUR_VDOM_NAME\nset type tunnel\nset alias \"SSL VPN interface\"\nnext\nend\n"
	auto_set_snmp_index $intfname

	if { [cli_ver_start 700 0] } {
		set nafname [string map {ssl. naf.} $intfname]
		cli_exec_cmd $CLI_GLOBAL_NODE "config system interface\nedit $nafname\nset vdom $vdname\nset type tunnel\nnext\nend\n"
		auto_set_snmp_index $nafname
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
	"ips sensor entries" = %{
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
		if { $inspect_all ne "enable" } {
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
        set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
        cli_exec_cmd $CLI_CUR_VDOM_NODE "config $CLI_CUR_NODE_NAME\nedit \"$name\"\n$cmd\nnext\nend\n"
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
set addr [cli_get_match_nr $CLI_CUR_VDOM_NODE 1 "firewall address" "interface" 0 $intf]
if { $addr ne 0 && [cli_get_value $addr "" "" "type"] eq "interface-subnet" } {
	cli_set_value $addr "" "" "subnet" [cli_get_value $CLI_CUR_NODE "" "" ""]
}
return 1
	%}
%};
