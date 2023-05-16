nodeact %{
        "wireless-controller wtp-profile platform type" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [cli_get_devinfo "pm2_wl_radio_enabled" "2" $type] eq "no" } {
        set profilenode [cli_get_parent $CLI_CUR_PARENT_NODE]
        cli_exec_cmd $profilenode "config radio-2\nset mode disabled\nend\n"
}
return 1
        %}
	"user fsso-polling" = %{
set fsso [cli_get_node $CLI_CUR_VDOM_NODE "user fsso" "Local FSSO Agent" ""]
if { $fsso == 0 } {
	set server [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config user fsso\nedit \"Local FSSO Agent\"\nset ldap-server $server\nset server \"127.0.0.1\"\nnext\nend\n"
}
return 1
	%}
	"{application ips} custom" = %{
namespace import global::app_cus_get_attr_value
set node_name [cli_get_node_name $CLI_CUR_NODE]
set tag [cli_get_value $CLI_CUR_NODE "" "" "tag"]
set signature [cli_get_value $CLI_CUR_NODE "" "" "signature"]
set category [cli_get_value $CLI_CUR_NODE "" "" "category"]
set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
set attack_key "--attack_id "
set vuln_key "--vuln_id "
set appcat [app_cus_get_attr_value "--app_cat " $signature]
set vuln_id [app_cus_get_attr_value $vuln_key $signature]
set attack_id [app_cus_get_attr_value $attack_key $signature]
set do_cmd 0
set sig_changed 0
set cmd ""
set id ""

set sigchk [cli_get_value $CLI_CUR_NODE "" "" "signature" 1]
if { [llength $sigchk] > 1 } {
	## attempt to fix this by stripping all the quote
	set signature [regsub -all " \"" $signature ""]
	set sig_changed 1
}

if { $CLI_CUR_NODE_NAME eq "ips custom" } {
	set signature [string map {\\\\\\ \\} $signature]
	if { ![regexp { \\\\\\\"} $signature] } {
		set signature [string map {\\\\ \\} $signature]
	}
	set sig_changed 1
}

if {$node_name eq "application custom"} {
	if {$appcat ne ""} {
		cli_set_value $CLI_CUR_NODE "" "" "category" $appcat
	} elseif {$category eq "" || $category eq "0"} {
		cli_set_errmsg "missing application category"
		return 0
	}
}

if { [llength [regexp -all -inline (?=$attack_key) $signature]] > 1 } {
	cli_set_errmsg "$node_name cannot have multiple attack_id"
	return 0
}

if {$vuln_id ne ""} {
	set id $vuln_id
} elseif {$attack_id ne ""} {
	set id $attack_id
}

if { $id ne "" } {
	if { ![string is integer $id] || $id < 1000 || $id > 9999 } {
		cli_set_errmsg "custom signature id must be between 1000 and 9999"
		return 0
	}
	cli_set_value $CLI_CUR_NODE "" "" "id" $id
}

for {set x 1000} {$x <= 9999} {incr x} {
	set attack_list($x) 0
}

set nodelist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "ips custom"]
foreach node $nodelist {
	set this_sig [cli_get_value $node "" "" "signature"]
	set this_tag [cli_get_value $node "" "" "tag"]
	if { $node_name eq "ips custom" && $tag eq $this_tag } {
		continue
	}
	set this_id [app_cus_get_attr_value $attack_key $this_sig]
	if { $this_id ne "" } {
		set attack_list($this_id) 1
	}
}
set nodelist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "application custom"]
foreach node $nodelist {
	set this_sig [cli_get_value $node "" "" "signature"]
	set this_tag [cli_get_value $node "" "" "tag"]
	if { $node_name eq "application custom" && $tag eq $this_tag } {
		continue
	}
	set this_id [app_cus_get_attr_value $vuln_key $this_sig]
	if { $this_id ne "" } {
		set attack_list($this_id) 1
	} else {
		set this_id [app_cus_get_attr_value $attack_key $this_sig]
		if { $this_id ne "" } {
			set attack_list($this_id) 1
		}
	}
}
if { $id ne "" && $attack_list($id) == 1 } {
	cli_set_errmsg "attack or vuln id duplicate"
	return 0
}

set cmd "config $node_name\nedit \"$tag\"\n"
if { $attack_id eq "" } {
	if {$node_name eq "application custom" && $vuln_id ne ""} {
		set signature [regsub {[\(]} $signature "(${attack_key}${vuln_id}; "]
		set sig_changed 1
	} else {
        for {set x 1000} {$x <= 9999} {incr x} {
			if { $attack_list($x) != 1 } {
				set attack_id $x
				break
			}
        }
		set signature [regsub {[\(]} $signature "(${attack_key}${attack_id}; "]
		set sig_changed 1
	}
}

set name_key "--name "
set name [app_cus_get_attr_value $name_key $signature]
if { $name eq "" } {
	set signature [regsub {[\(]} $signature "(${name_key}\\\"${tag}\\\"; "]
	set sig_changed 1
}
if { $sig_changed == 1 } {
	set signature [string trim $signature \"]
	append cmd "set signature \"$signature\"\n"
	set do_cmd 1
}
if { $node_name eq "ips custom" && $attack_id ne "" } {
	append cmd "set rule-id $attack_id\n"
	set do_cmd 1
}
if { $node_name eq "application custom" && $attack_id ne "" } {
	append cmd "set id $attack_id\n"
	set do_cmd 1
}
if { $do_cmd == 1 } {
	append cmd "next\nend\n"
	cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
}
return 1
	%}

	"dynamic interface" = %{
#  if {$CLI_ACT eq "add"} { return 1 }
#  set name [cli_get_value $CLI_CUR_NODE "" "" ""]
#  set single_intf [cli_get_value $CLI_CUR_NODE "" "" "single-intf"]
#  set old_single_intf [cli_get_org_value $CLI_CUR_NODE "" "" "single-intf"]
#  if {$single_intf ne $old_single_intf && [cli_check_zonemap_changable $name $single_intf]} {
#  	cli_set_errmsg "mapped to multiple interfaces or has been set on vip"
#  	return 0
#  }
return 1
	%}

	"system vdom" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$name eq ""} {
	cli_set_errmsg "illegal name"
	return 0
}
if {[string length $name]>11} {
	cli_set_errmsg "name is too long"
	return 0
}
return 1
	%}

        "firewall policy redirect-url" = %{
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

        "firewall policy" = %{
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
set prof_status [cli_get_value $CLI_CUR_NODE "" "" "profile-status"]
set ippool [cli_get_value $CLI_CUR_NODE "" "" "ippool"]
set nat [cli_get_value $CLI_CUR_NODE "" "" "nat"]
set hascmd 0
set unset_utm_status 0
set dstaddr_visib 1 
set dstaddr6_visib 1 

namespace import global::set_rep_dst
namespace import global::fw_dstaddr_visible
namespace import global::fw_dstaddr6_visible
if { [set_rep_dst $CLI_CUR_NODE] } {
	set dstaddr_visib 0 
	set dstaddr6_visib 0 
} else {
	set dstaddr_visib [fw_dstaddr_visible $CLI_CUR_NODE]
	set dstaddr6_visib [fw_dstaddr6_visible $CLI_CUR_NODE]
}

if { $dstaddr_visib && $dstaddr6_visib } {
	set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
	set dstaddr6 [cli_get_value $CLI_CUR_NODE "" "" "dstaddr6"]
	if { $CLI_IS_AUTOUPDATE == 0 && $dstaddr eq "" && $dstaddr6 eq ""} {
        	cli_set_errmsg "dstaddr address not exist."
        	return 0
	}
}
if { $dstaddr_visib } {
###firewall policy address check ###
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
set hasvip 0
set hasaddr 0
set vipslb 0
foreach m $dstaddr {
    set vip [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $m ""]
    set vipgrp [cli_get_node $CLI_CUR_VDOM_NODE "firewall vipgrp" $m ""]
    set dynvip [cli_get_node $CLI_CUR_VDOM_NODE "dynamic vip" $m ""]
    if { ($vip != 0) || ($vipgrp != 0) || ($dynvip != 0) } {
    		if { ($vip != 0) && [cli_is_match $vip 0 "" "type" 0 "server-load-balance"] } {
			set vipslb 1
		}
		set hasvip 1
    }
    set addr [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $m ""]
    set addrgrp [cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp" $m ""]
    set dynaddr [cli_get_node $CLI_CUR_VDOM_NODE "dynamic address" $m ""]
    if { ($addr != 0) || ($addrgrp != 0) || ($dynaddr != 0) } {
		set hasaddr 1
	}
}
### dst-addr can not mix addr/addrgrp and vip/vipgrp
if { $hasaddr == 1 && $hasvip == 1 } {
    cli_set_errmsg "interface binding contradiction"
    return 0
}
### 157898 check srcintf web-proxy ftp-proxy
if { [cli_is_match $CLI_CUR_NODE 0 "" "srcintf" 0 "\"ftp-proxy\""] && ($hasvip == 1) } {
	cli_set_errmsg "source interface cannot be ftp-proxy with virtual dstaddr"
        return 0
}
if { [cli_is_match $CLI_CUR_NODE 0 "" "srcintf" 0 "\"web-proxy\""] && ($vipslb == 1) } {
        cli_set_errmsg "source interface cannot be web-proxy with virtual dstaddr of type server-load-balance"
        return 0
}
}

if { $dstaddr_visib == 0 && [set_rep_dst $CLI_CUR_NODE] == 0 } {
	set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
	if { $dstaddr ne "" } {
        	cli_clear_value $CLI_CUR_NODE "" "" "dstaddr"
	}
}
if { $dstaddr6_visib == 0 && [set_rep_dst $CLI_CUR_NODE] == 0 } {
	set dstaddr6 [cli_get_value $CLI_CUR_NODE "" "" "dstaddr6"]
	if { $dstaddr6 ne "" } {
        	cli_clear_value $CLI_CUR_NODE "" "" "dstaddr6"
	}
}
if { $action eq "deny" } {
    set hascmd 1
    cli_clear_value $CLI_CUR_NODE "" "" "profile"
    cli_clear_value $CLI_CUR_NODE "" "" "profile-status"
    cli_clear_value $CLI_CUR_NODE "" "" "traffic-shaper"
    cli_clear_value $CLI_CUR_NODE "" "" "traffic-shaper-reverse"
} else {
	if { [cli_ver_start 500 2] } {
	} else {
	    set ibp [cli_get_value $CLI_CUR_NODE "" "" "identity-based"]
	    if { $ibp eq "enable" } {
		if {$prof_status eq "enable"} {
            cli_clear_value $CLI_CUR_NODE "" "" "profile"
            cli_clear_value $CLI_CUR_NODE "" "" "profile-status"
		}
		if {[cli_get_value $CLI_CUR_NODE "" "" "traffic-shaper"] ne ""} {
            cli_clear_value $CLI_CUR_NODE "" "" "traffic-shaper"
		}
		if {[cli_get_value $CLI_CUR_NODE "" "" "traffic-shaper-reverse"] ne ""} {
            cli_clear_value $CLI_CUR_NODE "" "" "traffic-shaper-reverse"
		}
		if {[cli_get_value $CLI_CUR_NODE "" "" "utm-status"] eq "enable"} {
		    set unset_utm_status 1
		}
	    } else {
		if {$prof_status eq "disable" && [cli_get_value $CLI_CUR_NODE "" "" "profile"] ne ""} {
            cli_clear_value $CLI_CUR_NODE "" "" "profile"
		}
	    }
	}
	set clean_ippool 0
	if { [cli_ver_start 700 0] } {
		set nat46 [cli_get_value $CLI_CUR_NODE "" "" "nat46"]
		set nat64 [cli_get_value $CLI_CUR_NODE "" "" "nat64"]
		if { ($nat eq "disable" && $nat46 eq "disable" && $nat64 eq "disable") || $ippool eq "disable" } {
			set clean_ippool 1
		}
	} else {
		if { $nat eq "disable" || $ippool eq "disable" } {
			set clean_ippool 1
		}
	}
	if { $clean_ippool } {
		cli_clear_value $CLI_CUR_NODE "" "" "ippool"
		cli_clear_value $CLI_CUR_NODE "" "" "poolname"
		if { [cli_ver_start 600 4] } {
			cli_clear_value $CLI_CUR_NODE "" "" "poolname6"
		}
	}
}
if { $unset_utm_status } {
    if {[cli_get_value $CLI_CUR_NODE "" "" "application-list"] ne ""} {
        cli_clear_value $CLI_CUR_NODE "" "" "application-list"
    }
    if {[cli_get_value $CLI_CUR_NODE "" "" "av-profile"] ne ""} {
        cli_clear_value $CLI_CUR_NODE "" "" "av-profile"
    }
    if {[cli_get_value $CLI_CUR_NODE "" "" "ips-sensor"] ne ""} {
        cli_clear_value $CLI_CUR_NODE "" "" "ips-sensor"
    }
    if {[cli_get_value $CLI_CUR_NODE "" "" "mms-profile"] ne ""} {
        cli_clear_value $CLI_CUR_NODE "" "" "mms-profile"
    }
    if {[cli_get_value $CLI_CUR_NODE "" "" "spamfilter-profile"] ne ""} {
        cli_clear_value $CLI_CUR_NODE "" "" "spamfilter-profile"
    }
    if {[cli_get_value $CLI_CUR_NODE "" "" "dlp-sensor"] ne ""} {
        cli_clear_value $CLI_CUR_NODE "" "" "dlp-sensor"
    }
    if {[cli_get_value $CLI_CUR_NODE "" "" "webfilter-profile"] ne ""} {
        cli_clear_value $CLI_CUR_NODE "" "" "webfilter-profile"
    }
    if {[cli_get_value $CLI_CUR_NODE "" "" "voip-profile"] ne ""} {
        cli_clear_value $CLI_CUR_NODE "" "" "voip-profile"
    }
    if {[cli_get_value $CLI_CUR_NODE "" "" "icap-profile"] ne ""} {
        cli_clear_value $CLI_CUR_NODE "" "" "icap-profile"
    }
    if {[cli_get_value $CLI_CUR_NODE "" "" "profile-protocol-options"] ne ""} {
        cli_clear_value $CLI_CUR_NODE "" "" "profile-protocol-options"
    }
    cli_clear_value $CLI_CUR_NODE "" "" "utm-status"
}
if {$action ne "ipsec" && [cli_get_value $CLI_CUR_NODE "" "" "vpntunnel"] ne ""} {
    cli_clear_value $CLI_CUR_NODE "" "" "vpntunnel"
}
if { [cli_get_value $CLI_CUR_NODE "" "" "utm-status"] eq "disable" } {
	if { [cli_get_value $CLI_CUR_NODE "" "" "profile-type"] eq "group" } {
		cli_set_value $CLI_CUR_NODE "" "" "profile-type" "single"
		cli_set_value $CLI_CUR_NODE "" "" "ssl-ssh-profile" "\"no-inspection\""
	}
}
if { ![string match "*override*" [cli_get_clisrc]] } {
	if { [cli_obj_support "firewall policy" "auto-asic-offload"] } {
		set cappkt [cli_get_value $CLI_CUR_NODE "" "" "capture-packet"]
		set aao [cli_get_value $CLI_CUR_NODE "" "" "auto-asic-offload"]
		if {!($cappkt eq "disable" && $aao eq "disable" && $CLI_ACT eq "add")} {
			set ocappkt [cli_get_org_value $CLI_CUR_NODE "" "" "capture-packet"]
			if { $cappkt ne $ocappkt } {
				if { $cappkt eq "enable" } {
					cli_set_value $CLI_CUR_NODE "" "" "auto-asic-offload" "disable"
				} else {
					cli_clear_value $CLI_CUR_NODE "" "" "auto-asic-offload"
				}
			} else {
				set oaao [cli_get_org_value $CLI_CUR_NODE "" "" "auto-asic-offload"]
				if { ($aao ne $oaao) && ($aao eq "enable" && $cappkt eq "enable") } {
					cli_clear_value $CLI_CUR_NODE "" "" "capture-packet"
				}
			}
		}
	}
}
return 1
	%}

	"firewall policy6" = %{
### please refer to FortiOS cmf/plugin/firewall/policy6.c ###
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
set ippool [cli_get_value $CLI_CUR_NODE "" "" "ippool"]
set nat [cli_get_value $CLI_CUR_NODE "" "" "nat"]
set hascmd 0
set cmd ""

### policy6_poolname_skip ###
if { $nat eq "disable" || $ippool eq "disable" || $action eq "ipsec" } {
	if {[cli_get_value $CLI_CUR_NODE "" "" "poolname"] ne ""} {
		set hascmd 1
		append cmd "unset poolname\n"
	}
	if { $ippool eq "enable" } {
		set hascmd 1
		append cmd "unset ippool\n"
	}
}
if { $hascmd } {
    cli_exec_cmd $CLI_CUR_NODE $cmd
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
    cli_exec_cmd $CLI_CUR_PKG_NODE $cmd
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
if {$dnat ne ""} {
        set iplist [split $dnat .]
        set dnatint [expr ([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]]
        if {($dnatint & 0xff000000) == 0x7f000000 && ($dnatint & 0xf0000000) != 0xe0000000} {
                cli_set_errmsg "not multicast addr"
                return 0
        }
}
set nat [cli_get_value $CLI_CUR_NODE "" "" "nat"]
if {$nat ne ""} {
    if {4 != [scan $nat "%u.%u.%u.%u" q1 q2 q3 q4]
    || 255 < $q1 || 255 < $q2 || 255 < $q3 || 255 < $q4} {
        cli_set_errmsg "invalid ip"
        return 0
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
return 1
        %}

	"firewall policy identity-based-policy" = %{
if { [cli_ver_start 500 2] } {
} elseif { [cli_ver_start 500 0] } {
	set parent [cli_get_parent $CLI_CUR_PARENT_NODE]
	set policyid [cli_get_value $parent "" "" "policyid"]
	set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
	set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
	set hascmd 0
	set unset_utm_status 0

	set cmd "config identity-based-policy\nedit $id\n"

	if { $action eq "deny" } {
		set hascmd 1
		append cmd "unset traffic-shaper\nunset traffic-shaper-reverse\n"
		if { [cli_get_value $CLI_CUR_NODE "" "" "utm-status"] eq "enable" } {
			set unset_utm_status 1
		}
	}

	if { $unset_utm_status } {
		if {[cli_get_value $CLI_CUR_NODE "" "" "application-list"] ne ""} {
			append cmd "unset application-list\n"
		}
		if {[cli_get_value $CLI_CUR_NODE "" "" "av-profile"] ne ""} {
			append cmd "unset av-profile\n"
		}
		if {[cli_get_value $CLI_CUR_NODE "" "" "ips-sensor"] ne ""} {
			append cmd "unset ips-sensor\n"
		}
		if {[cli_get_value $CLI_CUR_NODE "" "" "spamfilter-profile"] ne ""} {
			append cmd "unset spamfilter-profile\n"
		}
		if {[cli_get_value $CLI_CUR_NODE "" "" "dlp-sensor"] ne ""} {
			append cmd "unset dlp-sensor\n"
		}
		if {[cli_get_value $CLI_CUR_NODE "" "" "webfilter-profile"] ne ""} {
			append cmd "unset webfilter-profile\n"
		}
		if {[cli_get_value $CLI_CUR_NODE "" "" "voip-profile"] ne ""} {
			append cmd "unset voip-profile\n"
		}
		if {[cli_get_value $CLI_CUR_NODE "" "" "icap-profile"] ne ""} {
			append cmd "unset icap-profile\n"
		}
		if {[cli_get_value $CLI_CUR_NODE "" "" "profile-protocol-options"] ne ""} {
			append cmd "unset profile-protocol-options\n"
		}
		if {[cli_get_value $CLI_CUR_NODE "" "" "deep-inspection-options"] ne ""} {
			append cmd "unset deep-inspection-options\n"
		}
		append cmd "unset utm-status\n"
	}

	if { $hascmd } {
		append cmd "end\nend\n"
		cli_exec_cmd $CLI_CUR_PKG_NODE $cmd
	}
}
return 1
	%}

        "ips DoS" = %{
if {$CLI_ACT ne "add"} { return 1}
if { [string match "*override*" [cli_get_clisrc]] } { return 1 }
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

	"firewall multicast-address" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set cmd ""

if { $type eq "broadcastmask" } {
	set subnet [cli_get_value $CLI_CUR_NODE "" "" "subnet"]
	set ip [regsub -all {\.} [lindex $subnet 0] { }]
	set mask [regsub -all {\.} [lindex $subnet 1] { }]
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

	"vpnmgr vpntable" = %{
if {$CLI_ACT ne "add"} {
	if {$CLI_ACT ne "edit" } {
		return 1
	}
	set old_option [cli_get_org_value $CLI_CUR_NODE "" "" "auto-zone-policy"]
	set old_zone1 [cli_get_org_value $CLI_CUR_NODE "" "" "vpn-zone"]
	set old_zone2 [cli_get_org_value $CLI_CUR_NODE "" "" "spoke2hub-zone"]
	set old_zone3 [cli_get_org_value $CLI_CUR_NODE "" "" "hub2spoke-zone"]
	if { $old_option eq "enable" && $old_zone1 eq "" && $old_zone2 eq "" && $old_zone3 eq "" } {
		set option [cli_get_value $CLI_CUR_NODE "" "" "auto-zone-policy"]
		set zone1 [cli_get_value $CLI_CUR_NODE "" "" "vpn-zone"]
		set zone2 [cli_get_value $CLI_CUR_NODE "" "" "spoke2hub-zone"]
		set zone3 [cli_get_value $CLI_CUR_NODE "" "" "hub2spoke-zone"]
		if { $option ne "enable" || $zone1 ne "" || $zone2 ne "" || $zone3 ne "" } {
			set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
			set intfname "vpnmgr_"
			set cmd ""
			append intfname $name
			foreach e {"_mesh" "_hub2spoke" "_spoke2hub"} {
				set intfnode [cli_get_node $CLI_CUR_VDOM_NODE "dynamic interface" ${intfname}${e} ""]
				if { $intfnode && [cli_is_referenced $intfnode] } {
					cli_set_errmsg "VPN zone ${intfname}${e} is being used"
					return 0
				} elseif { $intfnode } {
					append cmd "config dynamic interface\ndelete \"${intfname}${e}\"\nend\n"
				}
			}
			if { $cmd ne "" } {
				set ret [cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd]
			}
			if { $ret ne 0 } {
			        cli_set_errmsg "Failed to delete auto-generated vpnmgr zones"
				return 0
			}
		}
		return 1
	}
} else {
	set retrycount [cli_get_value $CLI_CUR_NODE "" "" "dpd-retrycount"]
	set retryinterval [cli_get_value $CLI_CUR_NODE "" "" "dpd-retryinterval"]
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	if { $retrycount eq "" && $retryinterval eq "" } {
		set cmd "config vpnmgr vpntable\nedit $name\nset dpd-retrycount 3\nset dpd-retryinterval 20\nnext\nend\n"
		cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
	}
}
set topology [cli_get_value $CLI_CUR_NODE "" "" "topology"]
set option [cli_get_value $CLI_CUR_NODE "" "" "auto-zone-policy"]
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set zone1 [cli_get_value $CLI_CUR_NODE "" "" "vpn-zone"]
set zone2 [cli_get_value $CLI_CUR_NODE "" "" "spoke2hub-zone"]
set zone3 [cli_get_value $CLI_CUR_NODE "" "" "hub2spoke-zone"]
if { $option eq "enable" && $zone1 eq "" && $zone2 eq "" && $zone3 eq "" } {
	set cmd "config dynamic interface\nedit \"vpnmgr_${name}_mesh\"\nset single-intf disable\nset description \"VPN manager auto-generated\"\nnext\nedit \"vpnmgr_${name}_hub2spoke\"\nset single-intf disable\nset description \"VPN manager auto-generated\"\nnext\nedit \"vpnmgr_${name}_spoke2hub\"\nset single-intf disable\nset description \"VPN manager auto-generated\"\nend\n"
	cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
}
return 1
%}

	"vpnmgr vpntable ike-version" = %{
if {$CLI_ACT ne "edit" } {
	return 1
}
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set old_ike [cli_get_org_value $CLI_CUR_PARENT_NODE "" "" "ike-version"]
set ike [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ike-version"]
if { $old_ike == 2 && $ike == 1 } {
	set cmd "config vpnmgr vpntable\nedit $name\nunset network-id\nunset network-overlay\nnext\nend\n"
	cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
}

return 1
	%}

	"vpnmgr vpntable network-overlay" = %{
if {$CLI_ACT ne "edit" } {
	return 1
}
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set old [cli_get_org_value $CLI_CUR_PARENT_NODE "" "" "network-overlay"]
set new [cli_get_value $CLI_CUR_PARENT_NODE "" "" "network-overlay"]
if { $old eq "enable" && $new eq "disable" } {
	set cmd "config vpnmgr vpntable\nedit $name\nunset network-id\nnext\nend\n"
	cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
}

return 1
	%}
	"vpnmgr node peertype" = %{
if {$CLI_ACT ne "edit" } {
	return 1
}
set type [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $type ne "peer" } {
	set peer [cli_get_value $CLI_CUR_PARENT_NODE "" "" "peer"]
	if { $peer ne "" } {
		cli_unset_value $CLI_CUR_PARENT_NODE "" "" "peer"
	}
}
if { $type ne "peertype" } {
	set peergrp [cli_get_value $CLI_CUR_PARENT_NODE "" "" "peergrp"]
	if { $peergrp ne "" } {
		cli_unset_value $CLI_CUR_PARENT_NODE "" "" "peergrp"
	}
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

        "firewall profile-protocol-options http" = %{
namespace import global::prof_protocol_options_act
set tagtype [cli_get_value $CLI_CUR_NODE "" "" "options"]
return [prof_protocol_options_act "http"]
	%}
        "firewall profile-protocol-options ftp" = %{
namespace import global::prof_protocol_options_act
return [prof_protocol_options_act "ftp"]
	%}
        "firewall profile-protocol-options imap" = %{
namespace import global::prof_protocol_options_act
return [prof_protocol_options_act "imap"]
	%}
        "firewall profile-protocol-options mapi" = %{
namespace import global::prof_protocol_options_act
return [prof_protocol_options_act "mapi"]
	%}
        "firewall profile-protocol-options pop3" = %{
namespace import global::prof_protocol_options_act
return [prof_protocol_options_act "pop3"]
	%}
        "firewall profile-protocol-options smtp" = %{
namespace import global::prof_protocol_options_act
return [prof_protocol_options_act "smtp"]
	%}
        "firewall profile-protocol-options nntp" = %{
namespace import global::prof_protocol_options_act
return [prof_protocol_options_act "nntp"]
	%}
        "firewall profile-protocol-options" = %{
if { [cli_ver_start 500 0] } {
	return 1
}
if {$CLI_ACT ne "add"} { return 1}
if { [string match "*override*" [cli_get_clisrc]] } { return 1 }
set list {
	{"http" "80" "set options no-content-summary" "unset post-lang"}
	{"https" "443" "set options no-content-summary" "unset post-lang"}
	{"ftp" "21" "set options no-content-summary splice" ""}
	{"ftps" "990" "set options no-content-summary splice" "unset post-lang"}
	{"imap" "143" "set options fragmail no-content-summary" ""}
	{"imaps" "993" "set options fragmail no-content-summary" ""}
	{"pop3" "110" "set options fragmail no-content-summary" ""}
	{"pop3s" "995" "set options fragmail no-content-summary" ""}
	{"smtp" "25" "set options fragmail no-content-summary splice" ""}
	{"smtps" "465" "set options fragmail no-content-summary splice" ""}
	{"nntp" "119" "set options no-content-summary splice" ""}
}
set cmd ""
foreach e $list {
        set n [lindex $e 0]
        set p [lindex $e 1]
        set o [lindex $e 2]
        set l [lindex $e 3]
	set node [cli_get_node $CLI_CUR_NODE $n "" ""]
        if {!$node} {
		append cmd "config $n\n"
		if { $p ne "" } {
			if {[cli_ver_start 500 0]} {
				append cmd "set ports $p\n"
			} else {
				append cmd "set port $p\n"
			}
		}
		if { $o ne "" } {
			append cmd "$o\n"
		}
		if { $l ne "" } {
			append cmd "$l\n"
		}
		append cmd "end\n"
	} else {
		if { $p ne "" } {
			if { [cli_get_value $node "" "" "inspect-all"] ne "enable" } {
				if {[cli_ver_start 500 0]} {
					set ports [cli_get_value $node "" "" "ports"]
					if {$ports eq ""} {
						append cmd "config $n\nset ports $p\nend\n"
					}
				} else {
					set port [cli_get_value $node "" "" "port"]
					if {$port eq ""} {
						append cmd "config $n\nset port $p\nend\n"
					}
				}
			}
		}
		if { $o ne "" } {                                                          
			set options [cli_get_value $node "" "" "options"]                                   
			if { $options eq "" } {                                            
				append cmd "config $n\n$o\nend\n"                              
			}                                                                  
		}                                                                               
		if { $l ne "" } {                                                          
			set postlang [cli_get_value $node "" "" "post-lang"]              
			if { $postlang eq "" } {                                                               
				append cmd "config $n\n$l\nend\n"                         
			}                                                                 
		}    
	}
}
if { $cmd ne "" } {
        set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
        cli_exec_cmd $CLI_CUR_VDOM_NODE "config firewall profile-protocol-options\nedit \"$name\"\n$cmd\nnext\nend\n"
}
return 1
        %}
        "firewall ssl-ssh-profile" = %{
if { $CLI_ACT ne "add" } {
	return 1
}
if { [string match "*override*" [cli_get_clisrc]] || [string match "*clone*" [cli_get_clisrc]]} {
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
        "firewall ssl-ssh-profile ssl-exempt" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set address [cli_get_value $CLI_CUR_NODE "" "" "address"]
set wildcard [cli_get_value $CLI_CUR_NODE "" "" "wildcard-fqdn"]
if { $type eq "wildcard-fqdn" && $address ne "" && $wildcard ne "" } {
	cli_exec_cmd $CLI_CUR_NODE "unset address"
}
return 1
	%}
        "certificate template" = %{
if {$CLI_ACT eq "add"} {
	set name [cli_get_value $CLI_CUR_NODE "" "" ""]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config dynamic certificate local\nedit \"$name\"\nset description \"Created from certificate template $name\"\nend\n"
}
return 1
        %}
	"wireless-controller vap mpsk-profile" = %{
set mpsk [cli_get_value $CLI_CUR_NODE "" "" ""]
set ompsk [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { $mpsk ne $ompsk } {
	if { $mpsk ne "" && $ompsk eq "" } {
		cli_set_value $CLI_CUR_PARENT_NODE "" "" "dynamic-vlan" "enable"
	} elseif { $mpsk eq "" && $ompsk ne "" } {
		cli_clear_value $CLI_CUR_PARENT_NODE "" "" "dynamic-vlan"
	}
}
return 1
        %}
	"wireless-controller vap" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set name [string trim $name \"]
if { $name eq "" } {
	return 1
}
if { [cli_ver_start 600 2] } {
	if { $CLI_ACT eq "add" && $name eq "wifi" && [string match "*gui*" [cli_get_clisrc]] } {
		cli_set_errmsg "$name is a reserved name."
		return 0
	}
}
if { ![cli_ver_start 500 6] } {
	set sec  [cli_get_value $CLI_CUR_NODE "" "" "security"]
	set intravap    [cli_get_value $CLI_CUR_NODE "" "" "intra-vap-privacy"] 
	set localswitch [cli_get_value $CLI_CUR_NODE "" "" "local-switching"] 
	set localbridge [cli_get_value $CLI_CUR_NODE "" "" "local-bridging"]
	if { $sec eq "captive-portal" && ($intravap ne "enable" || $localswitch ne "disable" || $localbridge ne "disable") } {
	set cmd  "config wireless-controller vap\nedit $name\nset intra-vap-privacy enable\nset local-switching disable\nset local-bridging         disable\nend\n" 
	cli_exec_cmd  $CLI_CUR_VDOM_NODE  $cmd 
	}
}
set security [cli_get_value $CLI_CUR_NODE "" "" "security"]
set portaltype [cli_get_value $CLI_CUR_NODE "" "" "portal-type"]
if {$name ne 0 && !([string match "*captive-portal" $security] && ([string match "auth*" $portaltype] || [string match "cmcc*" $portaltype]))} {
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config wireless-controller vap\nedit \"$name\"\nunset selected-usergroups\nend\n"
}
if { $CLI_GLOBAL_DEV == 0 } {                                                                                                                   
        return 1                                                                                                                                
}
set dyn_node 0                                                                                                                                  
if { $CLI_ACT ne "add" } {
        set dyn_node [cli_get_node $CLI_CUR_VDOM_NODE "dynamic interface" $name ""]
} 
if { $dyn_node } {                                            
        return 1                                                                   
}
set cmd "config dynamic interface\nedit \"$name\"\nset description \"VAP interface\"\nset single-intf enable\n"
append cmd "set default-mapping enable\nset defmap-intf \"$name\"\n"
append cmd "next\nend\n"
cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
return 1
	%}
	"wireless-controller vap _dhcp_svr_id" = %{
set newval [cli_get_value $CLI_CUR_NODE "" "" ""]
set oldval [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set newval [string trim $newval "\""]
set oldval [string trim $oldval "\""]
if { $oldval ne "" && $newval ne $oldval } {
	set node    [cli_get_node $CLI_CUR_VDOM_NODE "system dhcp server" $oldval ""] 
	if { $node && ![cli_is_referenced $node] } { cli_delete_node $node }
}
return 1
	%}
        "wireless-controller wtp-profile {radio-1 radio-2}" = %{
if { [cli_ver_start 500 4] } {
	if { [cli_get_value $CLI_CUR_NODE "" "" "vap-all"] eq "enable" } {
		cli_clear_value $CLI_CUR_NODE "" "" "vaps"
	}
}
return 1
        %}
        "wireless-controller wtp {radio-1 radio-2}" = %{
if { [cli_is_match $CLI_CUR_NODE 0 "" "override-vaps" 0 "disable"] || [cli_is_match $CLI_CUR_NODE 0 "" "vap-all" 1 "manual"] } {
	cli_unset_value $CLI_CUR_NODE "" "" "vaps"
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
        "webfilter profile ftgd-wf enable" = %{
namespace import global::ftgd_wf_cat_exact_match
set ss "\"g01\" \"g02\" \"g04\" \"g05\" \"g06\" \"g07\" \"g21\" \"g22\""
set es [cli_get_value $CLI_CUR_PARENT_NODE "" "" "enable"]
if { [ftgd_wf_cat_exact_match $ss $es] } {
        set name [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_NODE]] "" "" "name"]
        cli_exec_cmd $CLI_CUR_VDOM_NODE "config webfilter profile\nedit $name\nconfig ftgd-wf\nset enable all\nunset disable\nend\nnext\nend\n"
}
return 1
        %}
        "system geoip-override" = %{
if { ![cli_branchpt_start 500 674] } { return 1 }
if { [cli_get_value $CLI_CUR_NODE "" "" "country-id"] eq "" } {
        set id [cli_gen_geoip_country_id]
        if { $id ne 0 } {
                set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
                cli_exec_cmd $CLI_GLOBAL_NODE "config system geoip-override\nedit $name\nset country-id $id\nnext\nend\n"
        }
}
return 1
        %}
	"vpn certificate ca" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set ca [cli_get_value $CLI_CUR_NODE "" "" "ca"]
set ca [string trimleft $ca "\""]
set ca [string trimright $ca "\""]
set ca [string trimright $ca "\n"]
set ca [cli_ca_import $ca]
if { $ca eq "" } {
	cli_set_errmsg "invalid ca"
	return 0
}
cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn certificate ca\nedit \"$name\"\nset ca \"$ca\"\nend\n"
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
	"firewall policy passive-wan-health-measurement" = %{
if { [cli_ver_start 700 0] } {
	set measurement [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $measurement eq "enable" } {
		if { [cli_obj_support "firewall policy" "auto-asic-offload"] } {
			cli_set_value $CLI_CUR_PARENT_NODE "" "" "auto-asic-offload" "disable"
		}
	}
}
return 1
        %}
	"ips global" = %{
if { $CLI_ACT eq "add" } {
	set db [cli_get_value $CLI_CUR_NODE "" "" "database"]
	if { $db eq "" } {
		cli_exec_cmd $CLI_CUR_PARENT_NODE "config ips global\nset database regular\nend\n"
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
	"switch-controller managed-switch ports members" = %{
set oldlist [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set newlist [cli_get_value $CLI_CUR_NODE "" "" ""]
set tname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-name"]
set pnode [cli_get_parent $CLI_CUR_PARENT_NODE]
set swnode [cli_get_parent $pnode]
set cmd ""

if {[cli_ver_start 600 4]} {
	set defport "default"
} else {
	set defport "default.vswport"
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
	cli_exec_cmd $swnode "config ports\n$cmd\nend\n"
}
return 1
	%}
	"switch-controller switch-group" = %{
if { [cli_branchpt_start 600 1682] } {
	set flink [string trim [cli_get_value $CLI_CUR_NODE "" "" "fortilink"] \"]
	set members [cli_get_value $CLI_CUR_NODE "" "" "members"]
	set update 0

	foreach m $members {
		set mflink [cli_get_value $CLI_CUR_PKG_NODE "fsp managed-switch" $m "vlan-interface"]
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
	}

	if { $update ne 0 } {
		cli_set_value $CLI_CUR_NODE "" "" "fortilink" $flink
	}
}
return 1
	%}
	"switch-controller managed-switch ports access-mode" = %{
if { [string match "*gui*" [cli_get_clisrc]] } {
	## GUI should handle the logic of setting up correct parameter for nac mode
	return 1
}

set mode [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $mode eq "nac" } {
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "loop-guard" "disable"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "lldp-status" "tx-rx"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "sample-direction" "both"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "sflow-counter-interval" "0"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "packet-sampler" "disable"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "edge-port" "enable"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "stp-bpdu-guard" "disable"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "stp-root-guard" "disable"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "stp-state" "enable"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "speed" "auto"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "port-security-policy" ""
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "ptp-policy" "default"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "qos-policy" "default"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "lldp-profile" "default-auto-isl"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "discard-mode" "none"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "allowed-vlans-all" "disable"
	cli_set_value $CLI_CUR_PARENT_NODE "" "" "storm-control-policy" ""
}
return 1
	%}
	"waf profile method method-policy" = %{
set addr [cli_get_value $CLI_CUR_NODE "" "" "address"]
if { $addr eq "" } {
	cli_exec_cmd $CLI_CUR_NODE "set address all\n"
}
return 1
	%}
	"webfilter ftgd-local-rating" = %{
if { $CLI_ACT eq "add" || $CLI_ACT eq "edit"} {
	set url1 [cli_get_value $CLI_CUR_NODE "" "" "url"]
	set url2 [cli_check_url 1 $url1]
	if {[string compare $url1 $url2] != 0} {
		set node [cli_get_node $CLI_CUR_VDOM_NODE "webfilter ftgd-local-rating" $url2 ""]
		cli_set_value $CLI_CUR_NODE "" "" "url" $url2
		if { $node != 0 && $node != $CLI_CUR_NODE } {
			cli_set_errmsg "Object already exists"
			return 0
		}
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
	"policy package settings ngfw-mode" = %{
if {![cli_ver_start 600 2]} {
	return 1
}
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
	ngfw_mode_set_policy_mode $cnfw_mode [cli_get_parent $CLI_CUR_PARENT_NODE]
} else {
	ngfw_mode_set_profile_mode $cnfw_mode [cli_get_parent $CLI_CUR_PARENT_NODE]
}

if { $old_mode eq "profile-based" && $new_mode eq "policy-based" } {
	cli_exec_cmd $CLI_CUR_PKG_NODE "config firewall policy\npurge\nend\nconfig firewall policy6\npurge\nend\n"
	if { ![string match "*import*" [cli_get_clisrc]] && ([string match "*gui*" [cli_get_clisrc]] || [string match "*script*" [cli_get_clisrc]]) } {
		set count [cli_get_tbl_cnt $CLI_CUR_PKG_NODE "firewall consolidated policy"]
		if { $count == 0 } {
			set cmd "config firewall consolidated policy\n"
			append cmd "edit 1\n"
			append cmd "set name \"Default\"\n"
			append cmd "set srcintf \"any\"\n"
			append cmd "set dstintf \"any\"\n"
			append cmd "set srcaddr4 \"all\"\n"
			append cmd "set dstaddr4 \"all\"\n"
			append cmd "set srcaddr6 \"all\"\n"
			append cmd "set dstaddr6 \"all\"\n"
			append cmd "set service \"ALL\"\n"
			append cmd "set ssl-ssh-profile \"certificate-inspection\"\n"
			append cmd "next\n"
			append cmd "end\n"
			cli_exec_cmd $CLI_CUR_PKG_NODE $cmd
		}
	}
} elseif { $old_mode eq "" && $new_mode eq "policy-based" } {
	if { ![string match "*import*" [cli_get_clisrc]] && ([string match "*gui*" [cli_get_clisrc]] || [string match "*script*" [cli_get_clisrc]]) } {
		set count [cli_get_tbl_cnt $CLI_CUR_PKG_NODE "firewall consolidated policy"]
		if { $count == 0 } {
			set cmd "config firewall consolidated policy\n"
			append cmd "edit 1\n"
			append cmd "set name \"Default\"\n"
			append cmd "set srcintf \"any\"\n"
			append cmd "set dstintf \"any\"\n"
			append cmd "set srcaddr4 \"all\"\n"
			append cmd "set dstaddr4 \"all\"\n"
			append cmd "set srcaddr6 \"all\"\n"
			append cmd "set dstaddr6 \"all\"\n"
			append cmd "set service \"ALL\"\n"
			append cmd "set ssl-ssh-profile \"certificate-inspection\"\n"
			append cmd "next\n"
			append cmd "end\n"
			cli_exec_cmd $CLI_CUR_PKG_NODE $cmd
		}
	}
} else {
	cli_exec_cmd $CLI_CUR_PKG_NODE "config firewall consolidated policy\npurge\nend\nconfig firewall security-policy\npurge\nend\n"
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
	"wireless-controller wtp-profile" = %{
set prof [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $CLI_ACT eq "add" || $CLI_ACT eq "edit"} {
	if { [cli_branchpt_start 600 200] } {
		set ho_sta [cli_get_value $CLI_CUR_NODE "" "" "handoff-sta-thresh"]
		namespace import global::wtp_profile_platform
		set plat [wtp_profile_platform $CLI_CUR_NODE]
		if { [cli_get_devinfo "wifilocal" $plat] eq "yes" } {
			set platform_str [cli_get_value $CLI_CUR_NODE "platform" "" "_local_platform_str"]
			set ho_sta_max [cli_get_devinfo "pm2_wl_handoff_sta_max" $plat $platform_str]
		} else {
			set ho_sta_max [cli_get_devinfo "pm2_wl_handoff_sta_max" $plat]
		}
		set ho_sta_max [expr {$ho_sta_max - 5}]
		if { ($ho_sta_max > 0) && ($ho_sta < 5 || ($ho_sta > 0 && $ho_sta > $ho_sta_max)) } {
			set ho_sta $ho_sta_max
			cli_exec_cmd $CLI_CUR_VDOM_NODE "config wireless-controller wtp-profile\nedit $prof\nset handoff-sta-thresh $ho_sta\nend\n"
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
	"fsp vlan" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $CLI_ACT ne "add" || $CLI_GLOBAL_DEV == 0 } {
	return 1
}

set cmd "config dynamic interface\nedit \"$name\"\nset description \"FortiSwitch VLAN interface\"\nset single-intf enable\nset default-mapping enable\nset defmap-intf \"$name\"\nnext\nend\n"
cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
return 1
	%}
	"system sdwan zone" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $CLI_ACT ne "add" || $CLI_GLOBAL_DEV == 0 } {
	return 1
}

if { $name eq "virtual-wan-link" } {
	set cmd "config dynamic interface\nedit \"$name\"\nnext\nend\n"
} else {
	set cmd "config dynamic interface\nedit \"$name\"\nset description \"SDWAN Zone\"\nset single-intf enable\nset default-mapping enable\nset defmap-intf \"$name\"\nnext\nend\n"
}
cli_exec_cmd $CLI_CUR_VDOM_NODE $cmd
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
    "firewall {policy policy6} action" = %{
set action [cli_get_value $CLI_CUR_NODE "" "" ""]
set group [cli_get_value $CLI_CUR_PARENT_NODE "" "" "profile-group"]
if { $group ne "" && $action eq "deny" } {
    cli_unset_value $CLI_CUR_PARENT_NODE "" "" "profile-group"
    cli_unset_value $CLI_CUR_PARENT_NODE "" "" "profile-type"
}
return 1
    %}
	"vpn ssl web portal" = %{
if { $CLI_ACT eq "add" } {
	if { [cli_ver_start 600 4] } {
		set objs [list "windows-2000" "windows-7" "windows-8" "windows-8.1" "windows-10" "os-x-mavericks-10.9" "os-x-yosemite-10.10" "os-x-el-capitan-10.11" "macos-sierra-10.12" "macos-high-sierra-10.13" "macos-mojave-10.14" "macos-catalina-10.15"]
		set cmd ""
		foreach name $objs {
			append cmd "config os-check-list \"$name\"\nend\n"
		}
		cli_exec_cmd $CLI_CUR_NODE $cmd
	}
}
return 1
	%}
	"device template widget action-list" = %{
if { $CLI_ACT ne "add" && $CLI_ACT ne "edit" } {
	return 1
}
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
if { $action eq "conf-vap-ssid" } {
	set value [cli_get_value $CLI_CUR_NODE "" "" "value"]
	set new_value [cli_password_encode $value "passphrase"]
	if {[string compare $value $new_value] != 0} {
		cli_set_value $CLI_CUR_NODE "" "" "value" $new_value
	}
}
return 1
	%}
	"device template widget action-list dynamic_mapping" = %{
if { $CLI_ACT ne "add" && $CLI_ACT ne "edit" } {
	return 1
}
set action [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "action"]
if { $action eq "conf-vap-ssid" } {
	set value [cli_get_value $CLI_CUR_NODE "" "" "local-value"]
	set new_value [cli_password_encode $value "passphrase"]
	if {[string compare $value $new_value] != 0} {
		cli_set_value $CLI_CUR_NODE "" "" "local-value" $new_value
	}
}
return 1
	%}
	"system sdn-connector" = %{
set ctype [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $ctype eq "aci-direct" } {
	set ip [cli_get_value $CLI_CUR_NODE "" "" "server"]
	set ip2 [cli_get_value $CLI_CUR_NODE "" "" "server-list"]
	if { $ip ne "" && $ip2 eq "" } {
		cli_set_value $CLI_CUR_NODE "" "" "server-list" $ip
	} elseif { $ip eq "" && $ip2 ne "" } {
		set iplist [split $ip2]
		cli_set_value $CLI_CUR_NODE "" "" "server" [lindex $iplist 0]
	}
}
return 1
	%}
%};
