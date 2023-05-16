nodecheck %{
	"log npu-server server-group" = %{
set server_number [cli_get_value $CLI_CUR_NODE "" "" "server-number"]
set server_start_id [cli_get_value $CLI_CUR_NODE "" "" "server-start-id"]
if { $server_number eq 0 || $server_start_id eq 0 } {
	cli_set_errmsg "The server_number and server_start_id should not be 0."
	return 0
}
return 1
	%}
	"firewall {hyperscale-policy hyperscale-policy64}" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set cgn_eif [cli_get_value $CLI_CUR_NODE "" "" "cgn-eif"]
set cgn_eim [cli_get_value $CLI_CUR_NODE "" "" "cgn-eim"]
if { $cgn_eif eq "enable" || $cgn_eim eq "enable" } {
	set ippool_list [cli_get_value $CLI_CUR_NODE "" "" "poolname"]
	foreach ippool $ippool_list {
	        set ippool_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall ippool" $ippool ""]
		if { $ippool_node ne 0 && $ippool_node ne "" } {
			if { [cli_get_value $ippool_node "" "" "cgn-overload"] eq "enable" } {
				cli_set_errmsg "'cgn-eif' or 'cgn-eim' in hyperscale policy $name conflicts with 'cgn-overload' in ippool $ippool."
				return 0
			}
		} else {
			set pool_grp [cli_get_node $CLI_CUR_VDOM_NODE "firewall ippool_grp" $ippool ""]
			if { $pool_grp ne 0 && $pool_grp ne "" } {
				set pool_memb [cli_get_value $pool_grp "" "" "member"]
				foreach ippool $pool_memb {
					set ippool_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall ippool" $ippool ""]
					if { $ippool_node ne 0 && $ippool_node ne "" } {
						if { [cli_get_value $ippool_node "" "" "cgn-overload"] eq "enable" } {
							cli_set_errmsg "'cgn-eif' in hyperscale policy $name conflicts with 'cgn-overload' in ippool $ippool."
							return 0
						}
					}
				}
			}
		}
	}
}
if { [cli_ver_start 600 4] && ($CLI_CUR_NODE_NAME eq "hyperscale-policy") } {
	set policyid [cli_get_value $CLI_CUR_NODE "" "" "policyid"]
	set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
	set srcaddr [cli_get_value $CLI_CUR_NODE "" "" "srcaddr"]
	set dstaddr6 [cli_get_value $CLI_CUR_NODE "" "" "dstaddr6"]
	set srcaddr6 [cli_get_value $CLI_CUR_NODE "" "" "srcaddr6"]

	if { ($srcaddr == 0 || $srcaddr eq "") && ($srcaddr6 == 0 || $srcaddr6 eq "") } {
		cli_set_errmsg "Policy \"$policyid\": either srcaddr/dstaddr or srcaddr6/dstaddr6 must be set."
		return 0
	}
	if { ($srcaddr != 0 && $srcaddr ne "") && ($dstaddr == 0 || $dstaddr eq "") } {
		cli_set_errmsg "Policy \"$policyid\": dstaddr must be set."
		return 0
	}
	if { ($srcaddr == 0 || $srcaddr eq "") && ($dstaddr != 0 && $dstaddr ne "") } {
		cli_set_errmsg "Policy \"$policyid\": srcaddr must be set."
		return 0
	}
	if { ($srcaddr6 != 0 && $srcaddr6 ne "") && ($dstaddr6 == 0 || $dstaddr6 eq "") } {
		cli_set_errmsg "Policy \"$policyid\": dstaddr6 must be set."
		return 0
	}
	if { ($srcaddr6 == 0 || $srcaddr6 eq "") && ($dstaddr6 != 0 && $dstaddr6 ne "") } {
		cli_set_errmsg "Policy \"$policyid\": srcaddr6 must be set."
		return 0
	}
}

set offload [cli_get_value $CLI_CUR_NODE "" "" "policy-offload"]; # enable
set nat [cli_get_value $CLI_CUR_NODE "" "" "nat"]; # enable
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]; # accept
set ippool [cli_get_value $CLI_CUR_NODE "" "" "ippool"]; # enable
set poolname [cli_get_value $CLI_CUR_NODE "" "" "poolname"]; # poolname

if { $offload eq "enable" } {
	if { $nat eq "enable" } {
		if { !($ippool eq "enable" && $action eq "accept") } {
			cli_set_errmsg "SNAT must use IP pool for policy offload!"
			return 0;
		}
		if { $poolname eq "" } {
			cli_set_errmsg "SNAT must set pool-name for policy offload!"
			return 0;
		}
	}
}

return 1
	%}
	"webfilter profile ftgd-wf" = %{
if {[cli_ver_start 500 0]} {
	set opt [cli_get_value $CLI_CUR_NODE "" "" "options"]
	foreach o $opt {
		if { $o eq "log-all-url" } {
			cli_set_errmsg "log-all-url is not supported in options"
			return 0
		}
	}
}

set local_cats [cli_get_tbl_list $CLI_CUR_VDOM_NODE "webfilter ftgd-local-cat"]
foreach cat $local_cats {
	set name [cli_get_value $cat "" "" "desc"]
	set id [cli_get_value $cat "" "" "id"]
	set status [cli_get_value $cat "" "" "status"]
	set catmap($id) "$status $name"
}

set filters [cli_get_tbl_list $CLI_CUR_NODE "filters"]
set catelist {}
foreach f1 $filters {
	set cate [string trim [cli_get_value $f1 "" "" "category"] \"]
	if { [info exists catmap($cate)] } {
		if { [lindex [split $catmap($cate) " "] 0] eq "disable" } {
			cli_set_errmsg "Cannot use local category \"[lindex [split $catmap($cate) " "] 1]\" in filter because its status is disabled"
			return 0
		}
	}
	set act [cli_get_value $f1 "" "" "action"]
	if { $act ne "block" } {
		lappend catelist $cate
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
}
return 1
	%}
	"webfilter profile override ovrd-dur" = %{
set duration [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ([regexp {^((\d+)d)?((\d+)h)?((\d+)m)?$} $duration dm1 dm2 d dm3 h dm4 m] == 0) ||
	($d ne "" && $d > 364) || ($h ne "" && $h > 23) || ($m ne "" && $m > 59) || 
	($d eq "" && $h eq "" && $m < 5) } {
	cli_set_errmsg "Invalid override duration $duration. It should follow the following format: 364d23h59m"
	return 0;
}
return 1
	%}
	"webfilter profile web" = %{
set profname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
if { [string match "g-*" $profname] } {
	set btable [cli_get_value $CLI_CUR_NODE "" "" "bword-table"]
	set utable [cli_get_value $CLI_CUR_NODE "" "" "urlfilter-table"]
	if { $btable ne 0 && $btable ne "" } {
		cli_set_errmsg "Do not support bword-table for global scope webfilter profile"
		return 0
	}
	if { $utable ne 0 && $utable ne "" } {
		cli_set_errmsg "Do not support urlfilter-table for global scope webfilter profile"
		return 0
	}
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
			cli_set_errmsg "Local FSSO Agent server IP must be 127.0.0.1"
			return 0
		}
	}
}
return 1
	%}

	"webfilter ftgd-local-cat" = %{
set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
if {$id ne "" && $id ne "0"} {
	if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "id" 0 $id] > 1} {
		cli_set_errmsg "Duplicate ID"
		return 0
	}
}
return 1
	%}
	"webfilter ftgd-local-cat status" = %{
set status [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $status eq "disable" && [cli_is_referenced $CLI_CUR_PARENT_NODE] } {
	cli_set_errmsg "Cannot disable category that is in use"
	return 0
}
return 1
%}
	"extender-controller extender" = %{
set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
if {$id ne "" && $id ne "0"} {
	if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "id" 0 $id] > 1} {
		cli_set_errmsg "Duplicate extender id: $id."
		return 0
	}
}
return 1
	%}
	"extension-controller extender" = %{
set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
if {$id ne "" && $id ne "0"} {
	if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "id" 0 $id] > 1} {
		cli_set_errmsg "Duplicate extender id: $id."
		return 0
	}
}
return 1
	%}

	"firewall ippool" = %{
set if_no_default [cli_get_value $CLI_CUR_NODE "" "" "_if_no_default"]
if { $if_no_default == 1} {
	return 1
}
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

    "firewall address6" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"] 
if { $type eq "dynamic" } {
	set sdn_name [cli_get_value $CLI_CUR_NODE "" "" "sdn"]
	set sdn_node [cli_get_node $CLI_CUR_VDOM_NODE "system sdn-connector" $sdn_name ""]
	set sdn_type [cli_get_value $sdn_node "" "" "type"]
	if { ($sdn_type ne "nsx") && ($sdn_type ne "aci") } {
		cli_set_errmsg "firewall address6 can only use nsx or aci type sdn-connector."
		return 0
	}
	return 1
}
if { $type ne "iprange" } {
    return 1
}
set sip6 [cli_get_value $CLI_CUR_NODE "" "" "start-ip"]
set eip6 [cli_get_value $CLI_CUR_NODE "" "" "end-ip"]
if {$sip6 eq "" || $sip6 eq "::" } { set sip6 ":" }
if { $eip6 eq "" || $eip6 eq "::" } { set eip6 ":" }
set sip6list [split $sip6 :]
set eip6list [split $eip6 :]

if { [regexp {\d{1,3}\.} $sip6 ] || [regexp {\d{1,3}\.} $eip6 ]}  {
    set siplist [split [lindex $sip6list [llength $sip6list]-1] .]
    set eiplist [split [lindex $eip6list [llength $eip6list]-1] .]
    if { $siplist eq "" || $eiplist eq "" } {
        cli_set_errmsg "Invalid address range"
        return 0
    }
    set ipint1 [expr { (([lindex $siplist 0]<<24)+([lindex $siplist 1]<<16)+([lindex $siplist 2]<<8)+[lindex $siplist 3]) & 0xffffffff }]
    set ipint2 [expr { (([lindex $eiplist 0]<<24)+([lindex $eiplist 1]<<16)+([lindex $eiplist 2]<<8)+[lindex $eiplist 3]) & 0xffffffff }]
    if {$ipint1 > $ipint2} {
       cli_set_errmsg "Start IP greater than end IP"
       return 0
    }
    return 1
}

set full_sip6 ""
set full_eip6 ""

if {([lindex $sip6list 0] eq "") || ([lindex $sip6list [llength $sip6list]-1] eq "")} {
    set idx [lsearch $sip6list ""]
    set sip6list [lreplace $sip6list $idx $idx]
}

if {([lindex $eip6list 0] eq "") || ([lindex $eip6list [llength $eip6list]-1] eq "")} {
    set idx [lsearch $eip6list ""]
    set eip6list [lreplace $eip6list $idx $idx]
}

for { set i 0 } {$i < [llength $sip6list]} {incr i} {
    set v [lindex $sip6list $i]
    if { $v eq "" } {
        for {set j 0} {$j < [expr 9 - [llength $sip6list]]} {incr j} {
            append full_sip6 "0000"
        }
    } else {
        append full_sip6 [format %04s $v]
    }
}

for { set i 0 } {$i < [llength $eip6list]} {incr i} {
    set v [lindex $eip6list $i]
    if { $v eq "" } {
        for {set j 0} {$j < [expr 9 - [llength $eip6list]]} {incr j} {
            append full_eip6 "0000"
        }
    } else {
        append full_eip6 [format %04s $v]
    }
}

if { [string length $full_sip6] ne 32 || [string length $full_eip6] ne 32 } {
	cli_set_errmsg "Invalid IP address"
	return 0
}

if { $full_sip6 > $full_eip6 } {
    cli_set_errmsg "Start IP greater than end IP"
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
	if { ($bits % 4) ne 0	} {
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
	"firewall vip" = %{
if { [string match "*upgrade*" [cli_get_clisrc]] } {
	return 1
}
set if_no_default [cli_get_value $CLI_CUR_NODE "" "" "_if_no_default"]
if { $if_no_default == 1} {
	return 1
}

if {$CLI_ACT ne "add"} {
	set ntype [cli_get_value $CLI_CUR_NODE "" "" "type"]
	set otype [cli_get_org_value $CLI_CUR_NODE "" "" "type"]
	if {[string compare $ntype $otype]} {
		cli_set_errmsg "Virtual IP type cannot be changed"
		return 0
	}
}

set viptype [cli_get_value $CLI_CUR_NODE "" "" "type"]
set intf [cli_get_value $CLI_CUR_NODE "" "" "extintf"]
set extip [cli_get_value $CLI_CUR_NODE "" "" "extip"]
if {($intf == "\"any\"") || ($intf == "any")} {
	if { $viptype eq "fqdn" } {
		set extaddr [cli_get_value $CLI_CUR_NODE "" "" "extaddr"]
		if {$extip == "0.0.0.0" && ($extaddr == 0 || $extaddr eq "")} {
			cli_set_errmsg "when extintf is $intf and extaddr is null, extip $extip is invalid"
			return 0
		}
	} else {
		if {$extip == "0.0.0.0"} {
			cli_set_errmsg "when extintf is $intf, extip $extip is invalid"
			return 0
		}
	}
}

namespace import global::iprange_invalid
namespace import global::ip_invalid
if { [iprange_invalid $extip 0] } {
	cli_set_errmsg "External ip range \"$extip\" is invalid"
	return 0
}

# mappedip can be in the following forms:
# x.x.x.x , x.x.x.x - y.y.y.y, x.x.x.x/y, x.x.x.x/y.y.y.y 
if { $viptype eq "dns-translation" || $viptype eq "static-nat" } {
	set mappedips [cli_get_value $CLI_CUR_NODE "" "" "mappedip"]
	foreach mappedip $mappedips {
		set mappedip [string trim $mappedip \"]
		set mappedip [string map {" " ""} $mappedip]
		if { [string first "/" $mappedip] != -1 } {
			set ip [string range $mappedip 0 [expr {[string first "/" $mappedip] - 1}]]
			set mask [string range $mappedip [expr {[string first "/" $mappedip] + 1}] end]
			set t [string first "." $mask]
			if { $t == -1 } {
				if { [scan $mask "%d" mask_v] != 1 || $mask_v > 32 || $mask_v < 0 } {
					cli_set_errmsg "Invalid netmask"
					return 0
				}
				set mask [expr {(0xFFFFFFFF << (32 - $mask_v)) & 0xFFFFFFFF}]
				set mask [format "%d.%d.%d.%d" [expr ($mask>>24)%256] [expr ($mask>>16)%256] [expr ($mask>>8)%256] [expr $mask%256]]
			}
			if { [ip_invalid $ip 1] || [ip_invalid $mask 0] || $mask eq "0.0.0.0" } {
				cli_set_errmsg "Invalid mapped IP/netmask mask($mask)"
				return 0
			}
		} elseif { [llength [split $mappedip -]] <= 2} {
			if { [iprange_invalid $mappedip 0] eq 1} {
				cli_set_errmsg "Invalid mapped IP range"
				return 0
			} else {
				if { [llength [split $mappedip -]] eq 1 && [ip_invalid $mappedip 1] eq 1} {
					cli_set_errmsg "Invalid mapped IP"
					return 0
				}
			}
		} else {
			cli_set_errmsg "Invalid mapped IP range"
			return 0
		}
	}
} 
if { $viptype eq "access-proxy" } {
	set scert [cli_get_value $CLI_CUR_NODE "" "" "ssl-certificate"]
	if { $scert eq "" } {
		cli_set_errmsg "Attribute 'ssl-certificate' MUST be set."
		return 0
	}
}

set nat46 [cli_get_value $CLI_CUR_NODE "" "" "nat46"]
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

namespace import global::cli_invalid_ipv4
namespace import global::cli_invalid_ipv6
if {$CLI_ACT ne "add"} {
	set orig_nat46 [cli_get_org_value $CLI_CUR_NODE "" "" "nat46"]
	set realsrv_list [cli_get_tbl_list $CLI_CUR_NODE "realservers"]
	if { $nat46 ne $orig_nat46} {
		foreach e $realsrv_list {
			set realsrv_ip [cli_get_value $e "" "" "ip"]
			if { $nat46 eq "enable" && [cli_invalid_ipv6 $realsrv_ip] || $nat46 eq "disable" && [cli_invalid_ipv4 $realsrv_ip] } {
				cli_set_errmsg "Please purge realservers first."
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
set no_default [cli_get_value $CLI_CUR_PARENT_NODE "" "" "_if_no_default"]
if { $no_default eq 0 } {
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
}
return 1
	%}

	"firewall address" = %{
namespace import global::check_fw_address
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
# these chars are FGT cmf/cli/commands.c XSS_CHARS
if {[regexp {[<>()#\"']} $name]} {
    cli_set_errmsg "illegal name"
    return 0
}

# fix bug #573140: for fw_addr_dynamic_mapping, skip this name conflict check
if { $CLI_CUR_NODE_NAME ne "dynamic_mapping" && 
	[cli_get_node $CLI_CUR_VDOM_NODE "system external-resource" $name ""] != 0 } {
	cli_set_errmsg "Name \"$name\" conflicts with a system external-resource entry"
	return 0
}

if { $CLI_CUR_NODE_NAME ne "dynamic_mapping" && ![string match "*upgrade*" [cli_get_clisrc]] &&
	[cli_get_node $CLI_CUR_VDOM_NODE "firewall wildcard-fqdn custom" $name ""] != 0 } {
	cli_set_errmsg "Name \"$name\" conflicts with an entry in wildcard FQDN address"
	return 0
}

set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if {$type == "fqdn"} {
	set fqdn [cli_get_value $CLI_CUR_NODE "" "" "fqdn"]
	set fqdn [string trim $fqdn \"]
	# XSS_CHARS check
	if {[regexp {[<>()#\"']} $fqdn]} {
		cli_set_errmsg "Invalid FQDN"
		return 0
	}
	if {[cli_ver_start 500 4] && [regexp {[?]} $fqdn]} {
		cli_set_errmsg "Invalid FQDN"
		return 0
	}
	if {[cli_ver_start 500 4] && ![cli_ver_start 600 2] && [regexp {[\*]} $fqdn]} {
		cli_set_errmsg "Invalid FQDN"
		return 0
	}
	# FGT checks the XSS_CHARS and only allow letters/numbers and .- for "fqdn"
	# The . cannot be consecutive or in the beginning or end
	# Last section after last period cannot begin or end with numbers and must be atleast two characters long
	if { [cli_ver_start 500 6] && ![cli_ver_start 600 2] && ![regexp {^((([a-zA-Z0-9\_\-]{1,61})\.{0,1}){1,})$} $fqdn]} {
		cli_set_errmsg "Invalid FQDN"
		return 0
	}
	if { [cli_ver_start 600 2] && ![regexp {^((([a-zA-Z0-9\_\-\*]{1,61})\.{0,1}){1,})$} $fqdn]} {
		cli_set_errmsg "Invalid FQDN"
		return 0
	}
} elseif { $type eq "dynamic" } {
	set tenant [cli_get_value $CLI_CUR_NODE "" "" "tenant"]
	if { $tenant eq "" } {
		set sdn_name [cli_get_value $CLI_CUR_NODE "" "" "sdn"]
		set sdn_node [cli_get_node $CLI_CUR_VDOM_NODE "system sdn-connector" $sdn_name ""]
		set sdn_type [cli_get_value $sdn_node "" "" "type"]
		if { $sdn_type eq "aci" } {
			cli_set_errmsg "Tenant must be set"
			return 0
		}
	}
} elseif { $type eq "interface-subnet" } {
	set intf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
	if { $intf eq "" } {
		cli_set_errmsg "Attribute 'interface' MUST be set."
		return 0
	}
}
if { [cli_ver_start 500 2] } {
} else {
	set type_org [cli_get_org_value $CLI_CUR_NODE "" "" "type"]
	if {$CLI_ACT ne "add" && $type ne $type_org} {
	    cli_set_errmsg "cannot change address type"
	    return 0
	}
}

# cannot edit the subnet of an existing interface-subnet
# for device level address they are sync with device port
# for adom level address their subnet are not used for PP install and meaningless to edit
set addr_subnet [cli_get_value $CLI_CUR_NODE "" "" "subnet"]
set addr_subnet_org [cli_get_org_value $CLI_CUR_NODE "" "" "subnet"]
if {![string match "*override*" [cli_get_clisrc]] && $CLI_ACT eq "edit" && $type eq "interface-subnet" && $addr_subnet ne $addr_subnet_org} {
	cli_set_errmsg "cannot edit the subnet if the type is 'interface-subnet'. this subnet will not be used for policy package installing."
	return 0
}

return [check_fw_address $CLI_CUR_NODE $type]
	%}

	"firewall multicast-policy" = %{
if { [cli_ver_start 600 0] } {
	set dnat [cli_get_value $CLI_CUR_NODE "" "" "dnat"]
	if { $dnat != 0 && $dnat ne "" && $dnat ne "0.0.0.0" } {
		namespace import global::is_multicast_address
		set is_multicast [is_multicast_address $dnat]
		if { $is_multicast == 0 } {
			cli_set_errmsg "dnat is not a multicast addr"
			return 0
		}
	}
	return 1
}
namespace import global::check_fw_multicast_policy
return [check_fw_multicast_policy $CLI_CUR_NODE]
	%}

	"firewall multicast-policy6" = %{
if { [cli_ver_start 600 0] } {
	return 1
}
namespace import global::check_fw_multicast_policy
return [check_fw_multicast_policy $CLI_CUR_NODE]
	%}


	"firewall multicast-address" = %{
namespace import global::check_fw_multicast_address
return [check_fw_multicast_address $CLI_CUR_NODE]
      %}

	"firewall {addrgrp addrgrp6} member" = %{
if { ![cli_ver_start 700 2] } {
set grpmember [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $grpmember eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
}
return 1
	%}

	"firewall {internet-service-group internet-service-custom-group proxy-addrgrp} member" = %{
set grpmember [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $grpmember eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
return 1
	%}

	"firewall {service schedule wildcard-fqdn} group member" = %{
set grpmember [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $grpmember eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
return 1
	%}
	
	"firewall {internet-service-group internet-service-custom-group proxy-addrgrp}" = %{
set members [cli_get_value $CLI_CUR_NODE "" "" "member"]
if { $members eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
if { [cli_ver_start 600 2] && $CLI_CUR_NODE_NAME eq "firewall internet-service-group" } {
	set gdir [cli_get_value $CLI_CUR_NODE "" "" "direction"]
	foreach m $members {
		set dir [cli_internet_srv_direction $m]
		if { $dir ne "" && $dir ne "both" && $gdir ne $dir } {
			cli_set_errmsg "Direction of member(s) must either be both or the same direction as the group"
			return 0
		}
	}
}
return 1
	%}

	"firewall wildcard-fqdn group" = %{
set members [cli_get_value $CLI_CUR_NODE "" "" "member"]
if { $members eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
return 1
	%}
	"firewall wildcard-fqdn custom" = %{
set wc [cli_get_value $CLI_CUR_NODE "" "" "wildcard-fqdn"]
if {[regexp {\*} $wc] == 0} {
	cli_set_errmsg "invalid wildcard-fqdn \"$wc\""
	return 0
}
return 1
	%}
	"firewall addrgrp" = %{
proc check_assc_intf { grplist grploop members gassc_intf vdom } {
	upvar $grploop looping
	upvar $gassc_intf assc_intf
	foreach m $members {
		if { [cli_get_node $vdom "firewall address" $m ""] != 0 } {
			set assc_intf2 [cli_get_value $vdom "firewall address" $m "associated-interface"]
			set assc_intf2 [string trim $assc_intf2 \"]
			if { $assc_intf2 eq "any" || $assc_intf2 eq $assc_intf } {
				continue
			} elseif { $assc_intf eq "any" } {
				set $assc_intf $assc_intf2
			} else {
				return 0
			}
		} else {
			if { [lsearch $grplist $m] >= 0 } {
				cli_set_errmsg "recursively nested addrgrp $m in member list is detected."
				set looping 1
				return 0
			}
			lappend grplist $m
			set memlist [cli_get_value $vdom "firewall addrgrp" $m "member" 1]
			if { [check_assc_intf $grplist looping $memlist assc_intf $vdom] == 0 } {
				return 0
			}
			if { $looping } {
				return 0
			}
			set grplist [lreplace $grplist end end]
		}
	}
	return 1
}
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set members [cli_get_value $CLI_CUR_NODE "" "" "member" 1]
if { ![cli_ver_start 700 2] } {
if { $members eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
}
set allow_routing [cli_get_value $CLI_CUR_NODE "" "" "allow-routing"]
if { $allow_routing eq "enable" } {
	foreach member $members {
		set fwaddr [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $member ""]
		set static [cli_get_value $fwaddr "" "" "allow-routing"]
		if { $static eq "disable" } {
			cli_set_errmsg "Member $member does not have static route configuration enabled"
			return 0
		}
	}
}
set grplist [list $name]
set grploop 0
set assc_intf "any"
if { [check_assc_intf $grplist grploop $members assc_intf $CLI_CUR_VDOM_NODE] == 0 } {
	cli_set_errmsg "Members cannot have address binding to different interface in one group"
	return 0
}
if { $grploop } {
	return 0
}
return 1
	%}

	"firewall addrgrp6" = %{
set grpmember [cli_get_value $CLI_CUR_NODE "" "" "member" 1]
if { ![cli_ver_start 700 2] } {
if { $grpmember eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
}
namespace import global::addr6_all_exist
namespace import global::check_recur_group_members
set addr_all [addr6_all_exist $grpmember]
set name [cli_get_value $CLI_CUR_NODE "" "" "name" 1]
set grplist [list $name]
return [check_recur_group_members $grplist "firewall addrgrp6" $grpmember $CLI_CUR_VDOM_NODE]
	%}

	"firewall addrgrp dynamic_mapping member" = %{
set grpmember [cli_get_value $CLI_CUR_NODE "" "" "" 1]
if { ![cli_ver_start 700 2] } {
if { $grpmember eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
}
namespace import global::check_recur_group_members
set name [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "name" 1]
set grplist [list $name]
return [check_recur_group_members $grplist "firewall addrgrp" $grpmember $CLI_CUR_VDOM_NODE]
	%}

	"firewall addrgrp6 dynamic_mapping member" = %{
set grpmember [cli_get_value $CLI_CUR_NODE "" "" "" 1]
if { ![cli_ver_start 700 2] } {
if { $grpmember eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
}
namespace import global::check_recur_group_members
set name [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "name" 1]
set grplist [list $name]
return [check_recur_group_members $grplist "firewall addrgrp" $grpmember $CLI_CUR_VDOM_NODE]
	%}

       "firewall schedule group" = %{
if {[cli_get_value $CLI_CUR_NODE "" "" "member"] eq ""} {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
return 1
	%}

	"firewall vip6" = %{
set if_no_default [cli_get_value $CLI_CUR_NODE "" "" "_if_no_default"]
if { $if_no_default == 1} {
	return 1
}

namespace import global::check_ip_any_or_all
set eip [lindex [split [cli_get_value $CLI_CUR_NODE "" "" "extip"] "-"] 0]
if { [check_ip_any_or_all $eip "External" 6] } {
	return 0
}
set vtype [cli_get_value $CLI_CUR_NODE "" "" "type"]
set nat66 [cli_get_value $CLI_CUR_NODE "" "" "nat66"]
set nat64 [cli_get_value $CLI_CUR_NODE "" "" "nat64"]
if { $nat66 == 0 || $nat66 eq "" || $nat66 eq "enable" } {
	set mip [lindex [split [cli_get_value $CLI_CUR_NODE "" "" "mappedip"] "-"] 0]
	if { $vtype ne "server-load-balance" && $vtype ne "access-proxy" && [check_ip_any_or_all $mip "Mapped" 6] } {
		return 0
	}
}
if { $nat64 eq "enable" } {
	set emb_ipv4 [cli_get_value $CLI_CUR_NODE "" "" "embedded-ipv4-address"]
	set mip [lindex [split [cli_get_value $CLI_CUR_NODE "" "" "ipv4-mappedip"] "-"] 0]
	if { $emb_ipv4 ne "enable" && $vtype ne "server-load-balance" && $vtype ne "access-proxy" && [check_ip_any_or_all $mip "Mapped" 4] } {
		return 0
	}
}
return 1
	%}

	"firewall vip46" = %{
namespace import global::check_ip_any_or_all
set eip [lindex [split [cli_get_value $CLI_CUR_NODE "" "" "extip"] "-"] 0]
if { [check_ip_any_or_all $eip "External" 4] } {
	return 0
}
set vtype [cli_get_value $CLI_CUR_NODE "" "" "type"]
set mip [lindex [split [cli_get_value $CLI_CUR_NODE "" "" "mappedip"] "-"] 0]
if { $vtype ne "server-load-balance" && [check_ip_any_or_all $mip "Mapped" 6] } {
	return 0
}
return 1
	%}

	"firewall vip64" = %{
namespace import global::check_ip_any_or_all
set eip [lindex [split [cli_get_value $CLI_CUR_NODE "" "" "extip"] "-"] 0]
if { [check_ip_any_or_all $eip "External" 6] } {
	return 0
}
set vtype [cli_get_value $CLI_CUR_NODE "" "" "type"]
set mip [lindex [split [cli_get_value $CLI_CUR_NODE "" "" "mappedip"] "-"] 0]
if { $vtype ne "server-load-balance" && [check_ip_any_or_all $mip "Mapped" 4] } {
	return 0
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
set if_no_default [cli_get_value $CLI_CUR_NODE "" "" "_if_no_default"]
if { $if_no_default == 1} {
	return 1
}

if {[cli_get_value $CLI_CUR_NODE "" "" "member"] eq ""} {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
if {[cli_get_value $CLI_CUR_NODE "" "" "interface"] eq ""} {
        set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
        cli_set_errmsg "empty interface is not allowed at firewall vipgrp $name"
        return 0
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
			cli_set_errmsg "vipgrp interface \"$intf\" not match with vip extintf \"$port\""
			return 0
		}
		if { $port != "any" && [cli_ver_start 600 0] } {
			cli_set_errmsg "vipgrp interface \"$intf\" not match with vip extintf \"$port\""
			return 0
		}
	}
}
return 1
      %}

	"firewall schedule onetime" = %{
proc check_dt {dt} {
	set dt [string trim $dt \"]
	if {[scan $dt "%d:%d %d/%d/%d" hr min yr mon day] != 5} {
		return -1
	}
	if {$hr < 0 || $hr > 23 || $min < 0 || $min > 59} {
		return -1
	}
	if {$yr < 2001 || $yr > 2050} {
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
	return 0
}
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {[cli_get_node $CLI_CUR_VDOM_NODE "firewall schedule recurring" $name ""] != 0} {
	cli_set_errmsg "entry $name already exists in recurring schedule"
	return 0
}
set start [cli_get_value $CLI_CUR_NODE "" "" "start"]
if {$start eq ""} {set start "00:00 2001/01/01"}
set end [cli_get_value $CLI_CUR_NODE "" "" "end"]
if {$end eq ""} {set end "00:00 2001/01/01"}
if {[check_dt $start] == -1} {
	cli_set_errmsg "start date/time is invalid"
	return 0
}
if {[check_dt $end] == -1} {
	cli_set_errmsg "end date/time is invalid"
	return 0
}
set start_date [lindex $start 1]
set start_time [lindex $start 0]
set end_date [lindex $end 1]
set end_time [lindex $end 0]
set start_date [string trim $start_date \"]
set end_date [string trim $end_date \"]
scan $start_date "%d/%d/%d" start_yr start_mon start_day
scan $end_date "%d/%d/%d" end_yr end_mon end_day

if {$start_yr == $end_yr && $start_mon == $end_mon && $start_day == $end_day} {
	set start_time [string trim $start_time \"]
	set end_time [string trim $end_time \"]
	scan $start_time "%d:%d" start_hr start_min 
	scan $end_time "%d:%d" end_hr end_min
	if {($start_hr > $end_hr) || ($start_hr == $end_hr && $start_min >= $end_min)} {
		cli_set_errmsg "start time cannot be after end time"
		return 0
	}
} elseif {$start_yr > $end_yr || ($start_yr == $end_yr && $start_mon > $end_mon) || ($start_yr == $end_yr && $start_mon == $end_mon && $start_day > $end_day)} {
	cli_set_errmsg "start date cannot be after end date"
	return 0
}
return 1
	%}

	"firewall schedule recurring" = %{
proc check_time {t} {
	set t [string trim $t \"]
	if {[scan $t "%d:%d" hr min] != 2} {
		return -1
	}
	if {$hr < 0 || $hr > 23 || $min < 0 || $min > 59} {
		return -1
	}
	return 0
}
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {[cli_get_node $CLI_CUR_VDOM_NODE "firewall schedule onetime" $name ""] != 0} {
	cli_set_errmsg "entry $name already exists in onetime schedule"
	return 0
}
set start [cli_get_value $CLI_CUR_NODE "" "" "start"]
set end [cli_get_value $CLI_CUR_NODE "" "" "end"]
if {$start ne "" && [check_time $start] == -1} {
	cli_set_errmsg "invalid start time"
	return 0
}
if {$end ne "" && [check_time $end] == -1} {
	cli_set_errmsg "invalid end time"
	return 0
}
return 1
	%}

 	"firewall vip mappedport" = %{
set if_no_default [cli_get_value $CLI_CUR_PARENT_NODE "" "" "_if_no_default"]
if { $if_no_default == 1 } {
	return 1
}

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
	    cli_set_errmsg "invalid port range"
	    return 0
	}
}
if { ($start_port > $end_port) || ($end_port > 65535) || ($start_port < 0) } {
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
set if_no_default [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "_if_no_default"]
if { $if_no_default == 1 } {
	return 1
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
		!($client_ip eq "" || $client_ip == 0) && (($is_range == -1 && [cli_invalid_ipv4 $client_ip]) || ($is_range != -1 && ([cli_invalid_ipv4 [lindex $client_ip_range 0]] || [cli_invalid_ipv4 [lindex $client_ip_range 1]])))
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
	!($client_ip eq "" || $client_ip == 0) && (($is_range == -1 && [cli_invalid_ipv6 $client_ip]) || ($is_range != -1 && ([cli_invalid_ipv6 [lindex $client_ip_range 0]] || [cli_invalid_ipv6 [lindex $client_ip_range 1]])))
} {
	cli_set_errmsg "Invalid client-ip range $client_ip"
	return 0
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
set tag [cli_get_value $CLI_CUR_NODE "" "" ""]
set signature [cli_get_value $CLI_CUR_NODE "" "" "signature"]
set signature [string trim $signature \"]
if {[cli_check_ips_custom_rule $signature $tag]} {
	cli_set_errmsg "invalid ips data"
	return 0
}
set name_key "--name "
set name [ips_cus_get_attr_value $name_key $signature]
if {($name ne "") || ($tag ne "")} {
        set nodelist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "ips custom"]
        foreach node $nodelist {
                if { [cli_if_same_node $node $CLI_CUR_NODE] } {
                        continue;
                }
                set this_tag [cli_get_value $node "" "" "tag"]
                if {($this_tag ne "") && (($this_tag == $name) || ($this_tag == $tag))} {
                        cli_set_errmsg "duplicate ips custom tag name"
                        return 0
                }
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
	set pkg_name [cli_get_value $CLI_CUR_PKG_NODE "" "" ""]
	cli_set_errmsg "service in Policy \"$id\" Package \"$pkg_name\" cannot be empty"
	return 0
}
return 1
	%}

	"firewall policy _policy_block" = %{
set id [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
set blk [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $blk ne "" } {
	set list [cli_get_match_list [cli_get_parent $CLI_CUR_PARENT_NODE] 1 "firewall policy" "_policy_block" 0 $blk]
	foreach e $list {
		set aid [cli_get_value $e "" "" "policyid"]
		if { $id eq $aid } {
			continue
		}
		cli_set_errmsg "a policy block cannot be used more than once in one package"
		return 0
	}
}
return 1
	%}
	"firewall policy profile-group" = %{
namespace import global::fw_policy_inspection_flow
set group [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $group ne "" } {
	if { [fw_policy_inspection_flow $CLI_CUR_PARENT_NODE] } {
		set pgrp [cli_get_node $CLI_CUR_VDOM_NODE "firewall profile-group" $group ""]
		set waf [cli_get_value $pgrp "" "" "waf-profile"]
		if { $waf ne "" } {
			cli_set_errmsg "Profile group \"$group\" with waf-profile set cannot be used when firewall policy inspection mode is flow-based."
			return 0
		}
		set icap [cli_get_value $pgrp "" "" "icap-profile"]
		if { $icap ne "" } {
			cli_set_errmsg "Profile group \"$group\" with icap-profile set cannot be used when firewall policy inspection mode is flow-based."
			return 0
		}
		set mms [cli_get_value $pgrp "" "" "mms-profile"]
		if { $mms ne "" } {
			cli_set_errmsg "Profile group \"$group\" with mms-profile set cannot be used when firewall policy inspection mode is flow-based."
			return 0
		}
		set ssh_filter [cli_get_value $pgrp "" "" "ssh-filter-profile"]
		if { $ssh_filter ne "" } {
			cli_set_errmsg "Profile group \"$group\" with ssh-filter-profile set cannot be used when firewall policy inspection mode is flow-based."
			return 0
		}
		set cifs [cli_get_value $pgrp "" "" "cifs-profile"]
		if { $cifs ne "" } {
			cli_set_errmsg "Profile group \"$group\" with cifs-profile set cannot be used when firewall policy inspection mode is flow-based."
			return 0
		}
	}
}
return 1
	%}
	"firewall policy nat64" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]

if { $value eq "disable" } {
	set policy $CLI_CUR_PARENT_NODE
	set dstaddr6list [cli_get_value $policy "" "" "dstaddr6"]
	set dstaddr6nlist {}
	foreach addr6 $dstaddr6list {
		set addr6 [string trim $addr6 \"]
		lappend dstaddr6nlist $addr6
	}

	set fwvip6list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall vip6"]
	foreach fwvip6 $fwvip6list {
		set fwvip6name [cli_get_value $fwvip6 "" "" "name"]
		set fwvip6name [string trim $fwvip6name \"]
		if { [lsearch -exact $dstaddr6nlist $fwvip6name] >= 0 } {
			set fwvip6nat64 [cli_get_value $fwvip6 "" "" "nat64"]
			if { $fwvip6nat64 eq "enable" } {
				cli_set_errmsg "Firewall policy dstaddr6 ($fwvip6name) cannot be a vip6 or vipgrp6 with nat64 enabled when policy nat64 is disabled."
				return 0
			}
		}
	}

	set fwvipgrp6list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall vipgrp6"]
	foreach fwvipgrp6 $fwvipgrp6list {
		set fwvipgrp6name [cli_get_value $fwvipgrp6 "" "" "name"]
		set fwvipgrp6name [string trim $fwvipgrp6name \"]
		if { [lsearch -exact $dstaddr6nlist $fwvipgrp6name] >= 0 } {
			set fwvipgrp6nat64 [cli_get_value $fwvipgrp6 "" "" "nat64"]
			if { $fwvipgrp6nat64 eq "enable" } {
				cli_set_errmsg "Firewall policy dstaddr6 ($fwvip6name) cannot be a vip6 or vipgrp6 with nat64 enabled when policy nat64 is disabled."
				return 0
			}
		}
	}
}

 return 1
 	%}
	"firewall {policy policy6 shaping-policy} {diffservcode-forward diffservcode-rev}" = %{
set servcode [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
if { $servcode ne "" } {
	if {[regexp {^[01]{6}$} $servcode] == 0} {
        	cli_set_errmsg "must be 6 bits binary, range 000000-111111"
		return 0
	}
}
return 1
	%}
	"firewall policy6 _policy_block" = %{
set id [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
set blk [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $blk ne "" } {
	set list [cli_get_match_list [cli_get_parent $CLI_CUR_PARENT_NODE] 1 "firewall policy6" "_policy_block" 0 $blk]
	foreach e $list {
		set aid [cli_get_value $e "" "" "policyid"]
		if { $id eq $aid } {
			continue
		}
		cli_set_errmsg "a policy block cannot be used more than once in one package"
		return 0
	}
}
return 1
	%}

	"firewall consolidated policy _policy_block" = %{
set id [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
set blk [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $blk ne "" } {
	set list [cli_get_match_list [cli_get_parent $CLI_CUR_PARENT_NODE] 1 "firewall consolidated policy" "_policy_block" 0 $blk]
	foreach e $list {
		set aid [cli_get_value $e "" "" "policyid"]
		if { $id eq $aid } {
			continue
		}
		cli_set_errmsg "a policy block cannot be used more than once in one package"
		return 0
	}
}
return 1
	%}

	"firewall policy schedule" = %{
set schedule [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $schedule eq "" } {
	set id [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
	set pkg_name [cli_get_value $CLI_CUR_PKG_NODE "" "" ""]
	cli_set_errmsg "schedule in Policy \"$id\" Package \"$pkg_name\" cannot be empty"
	return 0
}
return 1
	%}
        "firewall policy session-ttl" = %{
set ttl [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [cli_branchpt_start 600 1051] } {
	if { $ttl eq "never" } {
		return 1
	}
}
if {! (($ttl == 0) || ((300 <= $ttl) && ($ttl <= 2764800)))} {
	cli_set_errmsg "out of range"
	return 0
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

	"firewall policy replacemsg-override-group" = %{
set g [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$g ne ""} {
	set msgnode [cli_get_node $CLI_CUR_VDOM_NODE "system replacemsg-group" $g ""]
	if {$msgnode eq 0} {
		cli_set_errmsg "replacemsg-group $g does not exist"
		return 0
	}
	set auth_type [cli_get_value $msgnode "" "" "group-type"]
	if {$auth_type ne "auth"} {
		cli_set_errmsg "replacemsg-group $g is not for firewall policies."
		return 0
	}
}
return 1
	%}
"firewall policy nat46" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]

if { $value eq "disable" } {
	set policy $CLI_CUR_PARENT_NODE
	set dstaddrlist [cli_get_value $policy "" "" "dstaddr"]
	set dstaddrnlist {}
	foreach addr $dstaddrlist {
		set addr [string trim $addr \"]
		lappend dstaddrnlist $addr
	}

	set fwviplist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall vip"]
	foreach fwvip $fwviplist {
		set fwvipname [cli_get_value $fwvip "" "" "name"]
		set fwvipname [string trim $fwvipname \"]
		if { [lsearch -exact $dstaddrnlist $fwvipname] >= 0 } {
			set fwvipnat46 [cli_get_value $fwvip "" "" "nat46"]
			if { $fwvipnat46 eq "enable" } {
				cli_set_errmsg "Firewall policy dstaddr ($fwvipname) cannot be a vip or vipgrp with nat46 enabled when policy nat46 is disabled."
				return 0
			}
		}
	}

	set fwvipgrplist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall vipgrp"]
	foreach fwvipgrp $fwvipgrplist {
		set fwvipgrpname [cli_get_value $fwvipgrp "" "" "name"]
		set fwvipgrpname [string trim $fwvipgrpname \"]
		if { [lsearch -exact $dstaddrnlist $fwvipgrpname] >= 0 } {
			set fwvipgrpnat46 [cli_get_value $fwvipgrp "" "" "nat46"]
			if { $fwvipgrpnat46 eq "enable" } {
				cli_set_errmsg "Firewall policy dstaddr ($fwvipname) cannot be a vip or vipgrp with nat46 enabled when policy nat46 is disabled."
				return 0
			}
		}
	}
}

return 1
	%}
        "webfilter urlfilter entries" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set url [cli_get_value $CLI_CUR_NODE "" "" "url"]
if {$url eq ""} {
	cli_set_errmsg "url cannot be empty"
	return 0;
}
if { $type eq "regex" } {
        if {[string index $url 0] eq "*" || [string index $url 0] eq "?"} {
                cli_set_errmsg "URL \"$url\" cannot begin with * or ?"
                return 0
        }
} elseif { $type eq "simple" } {
	set url [string trim $url \"]
	set url [string trim $url]
	if { ($url ne "") && [cli_check_url 0 $url] } {
		cli_set_errmsg "URL \"$url\" is invalid"
		return 0
	}
	if { [cli_ver_start 500 4] && ![cli_ver_start 500 6] } {
		if { [string first "*" $url] != -1 } {
			cli_set_errmsg "URL \"$url\" cannot contain \"*\" when type is simple"
			return 0
		}
	}
}
return 1
        %}

        "vpnmgr vpntable psksecret" = %{
if { ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "psk-auto-generate" 0 "disable"] } {
	return 1
}
set cert [cli_get_value $CLI_CUR_PARENT_NODE "" "" "certificate"]
if { $cert ne "" } {
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
		"vpnmgr vpntable network-overlay" = %{
set ike [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ike-version"]
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value eq "enable" && $ike ne "2" } {
	cli_set_errmsg "Network-overlay is only available when IKE version is 2"
	return 0
}
return 1
	%}
        "vpnmgr vpntable" = %{
set ike1prop [cli_get_value $CLI_CUR_NODE "" "" "ike1proposal"]
if { $ike1prop eq "" || $ike1prop eq 0 } {
	cli_set_errmsg "Must set at least 1 phase 1 encryption."
	return 0
}
set ike2prop [cli_get_value $CLI_CUR_NODE "" "" "ike2proposal"]
if { $ike2prop eq "" || $ike2prop eq 0 } {
	cli_set_errmsg "Must set at least 1 phase 2 encryption."
	return 0
}
set type [cli_get_value $CLI_CUR_NODE "" "" "topology"]
set mode [cli_get_value $CLI_CUR_NODE "" "" "ike1mode"]
if {$CLI_ACT ne "add"} {
        set org_type [cli_get_org_value $CLI_CUR_NODE "" "" "topology"]
        if { $type ne $org_type } {
                cli_set_errmsg "cannot be edited"
                return 0
        }
}

set zonelist {vpn-zone spoke2hub-zone hub2spoke-zone}
foreach zone_name $zonelist {
	set zone [cli_get_value $CLI_CUR_NODE "" "" $zone_name]
	if {[llength $zone] > 1} {
		cli_set_errmsg "Cannot set more than one $zone_name"
		return 0
	}
}
return 1
        %}

        "vpnmgr node extgwip" = %{
set extgw [cli_get_value $CLI_CUR_PARENT_NODE "" "" "extgw"]
set extgwip [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ($extgw ne "") && ($extgwip eq "") } {
	cli_set_errmsg "external gateway ip cannot be empty"
	return 0
}
return 1
        %}

        "vpnmgr node protected_subnet" = %{
if { [cli_ver_start 500 0] } {
set vpnnode [cli_get_parent $CLI_CUR_PARENT_NODE]
set num [cli_get_tbl_cnt $vpnnode "protected_subnet"]
if {$num == 0} {
	cli_set_errmsg "protected subnet cannot be empty"
	return 0
}
set vpnrole [cli_get_value $vpnnode "" "" "role"]
set modecfg [cli_get_value $vpnnode "" "" "mode-cfg"]
if {$vpnrole eq "spoke" && $modecfg eq "enable"} {
	if {$num > 1} {
		cli_set_errmsg "cannot have multiple protected subnets when mode-cfg is enabled"
		return 0
	}
}
}
return 1
        %}
	"vpnmgr node" = %{
set tablename [cli_get_value $CLI_CUR_NODE "" "" "vpntable"]
set vpntable [cli_get_node $CLI_CUR_VDOM_NODE "vpnmgr vpntable" $tablename ""]
set topology [cli_get_value $vpntable "" "" "topology"]
set role [cli_get_value $CLI_CUR_NODE "" "" "role"]
if { $topology eq "dialup" && $role eq "hub" } {
	set status [cli_get_value $CLI_CUR_NODE "" "" "dhcp-server"]
	set iprange [cli_get_tbl_cnt $CLI_CUR_NODE "ip-range"]
	set modecfg [cli_get_value $CLI_CUR_NODE "" "" "mode-cfg"]
	if { $modecfg ne "enable" && $status eq "enable" && $iprange == 0 } {
		cli_set_errmsg "The DHCP server should at least have one IP range."
		return 0
	}
}
set tunnel_search [cli_get_value $CLI_CUR_NODE "" "" "tunnel-search"]
set net_device [cli_get_value $CLI_CUR_NODE "" "" "net-device"]
if { $topology eq "dialup" && $net_device eq "enable" && $tunnel_search eq "nexthop" } {
    cli_set_errmsg "Tunnel-search cannot be nexthop if net-device is enabled"
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
			cli_set_errmsg "regexp must be set"
			return 0
		}
	}
	"header" {
		set hpattern [cli_get_value $CLI_CUR_NODE "" "" "http-header-pattern"]
		set hfield [cli_get_value $CLI_CUR_NODE "" "" "http-header-field"]
		if {$hpattern eq "" || $hfield eq ""} {
			cli_set_errmsg "http-header-pattern and http-header-field must be set"
			return 0
		}
	}
	"file-pattern" {
		set fpattern [cli_get_value $CLI_CUR_NODE "" "" "file-pattern"]
		set fpattern [string trim $fpattern \"]
		if {$fpattern eq ""} {
			cli_set_errmsg "file-pattern must be set"
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
			cli_set_errmsg "string must be set"
			return 0
		}
	}
	"attachment-size" -
	"transfer-size" {
		set fldval [cli_get_value $CLI_CUR_NODE "" "" "value"] 
		if  { $fldval > 1073741824 } {
			cli_set_errmsg "out of file size range \[0, 1073741824\] "
			return 0
		}
	}
	"server" {
                set addr_start_ip [cli_get_value $CLI_CUR_NODE "" "" "ip-range-start"]
                set addr_end_ip [cli_get_value $CLI_CUR_NODE "" "" "ip-range-end"]
                if {$addr_end_ip eq ""} {
			cli_set_errmsg "invalid server end IP address"
			return 0                                                      
                }
                set iplist [split $addr_start_ip .]
                set ipint1 [expr { (([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]) & 0xffffffff }]
                set iplist [split $addr_end_ip .]
                set ipint2 [expr { (([lindex $iplist 0]<<24)+([lindex $iplist 1]<<16)+([lindex $iplist 2]<<8)+[lindex $iplist 3]) & 0xffffffff }]
                if {$ipint1 > $ipint2} {
			cli_set_errmsg "invalid server IP address range"
			return 0 
                }
	}
}
return 1
        %}

	"dlp sensor filter" = %{
if { [cli_ver_start 500 0] } {
        set ftype [cli_get_value $CLI_CUR_NODE "" "" "type"]
        if { $ftype eq "message" } {
                set f_by [cli_get_value $CLI_CUR_NODE "" "" "filter-by"]
                if { ($f_by ne "ssn") && ($f_by ne "credit-card") && ($f_by ne "regexp")} {
                        cli_set_errmsg "invalid value for filter-by"
                        return 0
                }
        }
        set p [cli_get_value $CLI_CUR_NODE "" "" "proto"]
        if { $p eq "" } {
        	set f_name [cli_get_value $CLI_CUR_NODE "" "" ""]
	        set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
		cli_set_errmsg "protocol in Filter \"$f_name\" of Dlp Sensor \"$name\" is not set"
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
	cli_set_errmsg "$rule_name does not exist"
	return 0
}
return 1
	%}

	   "user local" = %{
set local_name [cli_get_value $CLI_CUR_NODE "" "" ""]
set ldap_node [cli_get_node $CLI_CUR_VDOM_NODE "user ldap" $local_name ""]
set radius_node [cli_get_node $CLI_CUR_VDOM_NODE "user radius" $local_name ""]
set tacplus_node [cli_get_node $CLI_CUR_VDOM_NODE "user tacacs+" $local_name ""]
set peer_node [cli_get_node $CLI_CUR_VDOM_NODE "user peer" $local_name ""]
if { (0 != $ldap_node) || ( 0 != $radius_node) || (0 != $tacplus_node) || (0 != $peer_node)} {
    cli_set_errmsg "Name conflicts with another entry in user LDAP/RADIUS/TACACS+/peer"
    return 0
}

set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $type eq "ldap" } {
   set svr [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]
   set svr [string trim $svr \"]
   if { $svr eq "" } {
      cli_set_errmsg "LDAP server must be configured"
      return 0
   } 
}
if { $type eq "radius" } {
   set svr [cli_get_value $CLI_CUR_NODE "" "" "radius-server"]
   set svr [string trim $svr \"]
   if { $svr eq "" } {
      cli_set_errmsg "RADIUS server must be configured"
      return 0
   } 
}
if { $type eq "tacacs+" } {
   set svr [cli_get_value $CLI_CUR_NODE "" "" "tacacs+-server"]
   set svr [string trim $svr \"]
   if { $svr eq "" } {
      cli_set_errmsg "TACACS+ server must be configured"
      return 0
   }
}
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
	"user pxgrid" = %{
if { $CLI_ACT eq "add" } {
	set mysize [cli_get_tbl_size "user pxgrid"]
	if { $mysize > 1 } {
		#cli_set_errmsg "Only one pxgrid server is allowed in each adom."
		#return 0
	}
}
set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
if { $server eq "" } {
	cli_set_errmsg "Must set server for user pxgrid."
	return 0
}
if { [scan $server "%d.%d.%d.%d" a a a a] != 4 } {
	cli_set_errmsg "Invalid server ip"
	return 0
}
set node_list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach e $node_list {
	if { [cli_if_same_node $e $CLI_CUR_NODE] } {
		continue
	}
	set svr [cli_get_value $e "" "" "server"]
	if { $svr eq $server } {
		cli_set_errmsg "duplicate server"
		return 0
	}
}
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "" } {
	cli_set_errmsg "Must set name for user pxgrid."
	return 0
}
if { [string compare -length 3 $name "px_"] == 0 } {
	cli_set_errmsg "The pxgrid server name cannot have prefix \'px_\'."
	return 0
}
set namelen [string length $name]
if { $namelen > 16 } {
	cli_set_errmsg "The pxgrid server name cannot be longer than 16 characters."
	return 0
}
return 1
	%}
	"user clearpass" = %{
if { $CLI_ACT eq "add" } {
	set mysize [cli_get_tbl_size "user clearpass"]
	if { $mysize > 1 } {
		#cli_set_errmsg "Only one clearpass server is allowed in each adom."
		#return 0
	}
}
set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
if { $server eq "" } {
	cli_set_errmsg "Must set server for user clearpass."
	return 0
}
if { [scan $server "%d.%d.%d.%d" a a a a] != 4 } {
	cli_set_errmsg "Invalid server ip"
	return 0
}
set node_list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach e $node_list {
	if { [cli_if_same_node $e $CLI_CUR_NODE] } {
		continue
	}
	set svr [cli_get_value $e "" "" "server"]
	if { $svr eq $server } {
		cli_set_errmsg "duplicate server"
		return 0
	}
}
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "" } {
	cli_set_errmsg "Must set name for user clearpass."
	return 0
}
if { [string compare -length 3 $name "cp_"] == 0 } {
	cli_set_errmsg "The clearpass server name cannot have prefix \'cp_\'."
	return 0
}
set namelen [string length $name]
if { $namelen > 16 } {
	cli_set_errmsg "The clearpass server name cannot be longer than 16 characters."
	return 0
}
set user [cli_get_value $CLI_CUR_NODE "" "" "user"]
set client [cli_get_value $CLI_CUR_NODE "" "" "client"]
if { $user eq "" || $client eq "" } {
	cli_set_errmsg "Must set user and client for user clearpass."
	return 0
}
return 1
	%}
	"user nsx" = %{
if { $CLI_ACT eq "add" } {
	set mysize [cli_get_tbl_size "user nsx"]
	if { $mysize > 1 } {
		#cli_set_errmsg "Only one nsx server is allowed in each adom."
		#return 0
	}
}
set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
if { $server eq "" } {
	cli_set_errmsg "Must set server for user nsx."
	return 0
}
if { [scan $server "%d.%d.%d.%d" a a a a] != 4 } {
	cli_set_errmsg "Invalid server ip"
	return 0
}
set node_list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach e $node_list {
	if { [cli_if_same_node $e $CLI_CUR_NODE] } {
		continue
	}
	set svr [cli_get_value $e "" "" "server"]
	if { $svr eq $server } {
		cli_set_errmsg "duplicate server"
		return 0
	}
}
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "" } {
	cli_set_errmsg "Must set name for user nsx."
	return 0
}
if { [string compare -length 4 $name "nsx_"] == 0 } {
	cli_set_errmsg "The nsx server name cannot have prefix \'nsx_\'."
	return 0
}
set namelen [string length $name]
if { $namelen > 16 } {
	cli_set_errmsg "The nsx server name cannot be longer than 16 characters."
	return 0
}
set user [cli_get_value $CLI_CUR_NODE "" "" "user"]
if { $user eq "" } {
	cli_set_errmsg "Must set user for user nsx."
	return 0
}
set fmgip [cli_get_value $CLI_CUR_NODE "" "" "fmgip"]
set fmguser [cli_get_value $CLI_CUR_NODE "" "" "fmguser"]
set fmgpwd [cli_get_value $CLI_CUR_NODE "" "" "fmgpasswd"]
if { $fmgip eq "" || $fmguser eq "" || $fmgpwd eq "" } {
	cli_set_errmsg "Must set fmgip, fmguser and fmgpasswd for user nsx."
	return 0
}
if { [scan $fmgip "%d.%d.%d.%d" a a a a] != 4 } {
	cli_set_errmsg "Invalid fmgip"
	return 0
}
return 1
	%}
	"user vcenter" = %{
if { $CLI_ACT eq "add" } {
	set mysize [cli_get_tbl_size "user vcenter"]
	if { $mysize > 1 } {
		#cli_set_errmsg "Only one vcenter server is allowed in each adom."
		#return 0
	}
}
set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
if { $server eq "" } {
	cli_set_errmsg "Must set server for user vcenter."
	return 0
}
if { [scan $server "%d.%d.%d.%d" a a a a] != 4 } {
	cli_set_errmsg "Invalid server ip"
	return 0
}
set node_list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach e $node_list {
	if { [cli_if_same_node $e $CLI_CUR_NODE] } {
		continue
	}
	set svr [cli_get_value $e "" "" "server"]
	if { $svr eq $server } {
		cli_set_errmsg "duplicate server"
		return 0
	}
}
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "" } {
	cli_set_errmsg "Must set name for user vcenter."
	return 0
}
if { [string compare -length 3 $name "vc_"] == 0 } {
	cli_set_errmsg "The vcenter server name cannot have prefix \'vc_\'."
	return 0
}
set namelen [string length $name]
if { $namelen > 16 } {
	cli_set_errmsg "The vcenter server name cannot be longer than 16 characters."
	return 0
}
set user [cli_get_value $CLI_CUR_NODE "" "" "user"]
if { $user eq "" } {
	cli_set_errmsg "Must set user for user vcenter."
	return 0
}
return 1
	%}
	"user vcenter rule" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "" } {
	cli_set_errmsg "Must set name for user vcenter."
	return 0
}
set namelen [string length $name]
if { $namelen > 16 } {
	cli_set_errmsg "The vcenter server name cannot be longer than 16 characters."
	return 0
}
if { $name eq "default_group" } {
	cli_set_errmsg "user vcenter rule name cannot be \'default_group\' (reserved)."
	return 0
}
return 1
	%}
	"user group" = %{
set id [cli_get_value $CLI_CUR_NODE "" "" "user-id"]
set email [cli_get_value $CLI_CUR_NODE "" "" "email"]
set group_type [cli_get_value $CLI_CUR_NODE "" "" "group-type"]
set attr_val [cli_get_value $CLI_CUR_NODE "" "" "sso-attribute-value"]
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "SSO_Guest_Users" } {
	set org_type [cli_get_org_value $CLI_CUR_NODE "" "" "group-type"]
	if { $group_type ne "fsso-service" } {
		cli_set_errmsg "SSO_Guest_Users must be FSSO/SSO type"
		return 0
	}
}

if { $group_type eq "rsso" } {
    if { $attr_val eq "" } {
        cli_set_errmsg "RADIUS attribute value cannot be empty"
        return 0
    }
}

if { $id eq "email" } {
	if { $email ne "enable" } {
		cli_set_errmsg "Email must be enabled when User ID is set as Email."
		return 0
	}
}
return 1
	%}
	"user ldap" = %{
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
return 1
	%}
	"user radius" = %{
set svr [cli_get_value $CLI_CUR_NODE "" "" "server"]
set rsso [cli_get_value $CLI_CUR_NODE "" "" "rsso"]
if { $svr eq "" &&  $rsso ne "enable" } {                                                           
   cli_set_errmsg "server cannot be empty." 
   return 0                                                                   
}
if { [cli_ver_start 500 4] } {
	set scrt [cli_get_value $CLI_CUR_NODE "" "" "secret"]
	if { $scrt eq "" } {
		cli_set_errmsg "Secret cannot be empty."
		return 0
	}
}
set dynp [cli_get_value $CLI_CUR_NODE "" "" "dynamic-profile"]
if { $dynp eq "enable" } {
        if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "dynamic-profile" 0 "enable"] > 1} {
                cli_set_errmsg "Can not duplicate enable Dynamic profile"
                return 0
        }
}
return 1
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
	cli_set_errmsg "Invalid server. (Mask is not allowed.)"
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
	"user tacacs+" = %{
set server [cli_get_value $CLI_CUR_NODE "" "" "server"]
if { $server eq "" } {
	cli_set_errmsg "Server cannot be empty."
	return 0
}
return 1
	%}
	"user radius accounting-server {server secret}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"spamfilter bword" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "" || 
     [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1 } {
	cli_set_errmsg "invalid name"
	return 0
}
return 1
	%}

	"spamfilter bword entries" = %{
set ptype [cli_get_value $CLI_CUR_NODE "" "" "pattern-type"]
set plang [cli_get_value $CLI_CUR_NODE "" "" "language"]
set pattern [cli_get_value $CLI_CUR_NODE "" "" "pattern"]
if { $pattern eq "" ||
     [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "pattern-type" 0 $ptype "language" 0 $plang "pattern" 0 $pattern] > 1 } {
	cli_set_errmsg "invalid value"
	return 0
}
set pattern [string trim $pattern \"]
if {[cli_check_regex 1 $pattern $ptype $plang]} {
        cli_set_errmsg "Unexpected pattern for $ptype:$plang (pattern-type:language)"
        return 0
}
return 1
	%}
	
	"spamfilter ipbwl" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "" || 
     [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1 } {
	cli_set_errmsg "invalid name"
	return 0
}
return 1
	%}
	
	"spamfilter ipbwl entries" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "addr-type"]
if {$type eq "ipv6"} {
	return 1
}
set ip [cli_get_value $CLI_CUR_NODE "" "" "ip4-subnet"]
set attr "ip4-subnet"
if { $ip eq "" } {
	cli_set_errmsg "IP must be set"
	return 0
}
set node_list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach e $node_list {
	if { [cli_if_same_node $e $CLI_CUR_NODE] } {
		continue
	}
	set pip [cli_get_value $e "" "" $attr]
	if { $pip eq $ip } {
		cli_set_errmsg "duplicate IP"
		return 0
	}
}
return 1
	%}
	
	"spamfilter emailbwl" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name eq "" || 
     [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1 } {
	cli_set_errmsg "invalid name"
	return 0
}
return 1
	%}
	
	"spamfilter emailbwl entries" = %{
set email_pattern [cli_get_value $CLI_CUR_NODE "" "" "email-pattern"]
if {$email_pattern eq ""} {
	cli_set_errmsg "email-pattern must be set"
	return 0
}

set etype [cli_get_value $CLI_CUR_NODE "" "" "pattern-type"]

set entry_list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach l $entry_list {
	if { [cli_if_same_node $l $CLI_CUR_NODE] } {
		continue
	}

	set l_email [cli_get_value $l "" "" "email-pattern"]
	set l_etype [cli_get_value $l "" "" "pattern-type"]

	if { $etype eq $l_etype } {
		if { [string equal -nocase $email_pattern $l_email] } {
			cli_set_errmsg "entry already exists"
			return 0
		}
	}
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

		"user group group-type" = %{
namespace import global::user_group_check_type
set grpname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set grpname [string trim $grpname \"]
if {($grpname eq "SSO_Guest_Users") && [cli_ver_start 500 2]} {
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

		"user group name" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set org_name [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { $org_name eq "SSO_Guest_Users" } {
	cli_set_errmsg "Cannot change SSO_Guest_Users name"
	return 0
}
return 1
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
	set check_if_used_ipsec [user_group_ipsec_used $grpname]
	foreach m $members {
		if { [cli_get_node $CLI_CUR_VDOM_NODE "user adgrp" $m ""] != 0 } {
			cli_set_errmsg "fsso group $m can only be assigned to a group of type fsso-server"
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

        "firewall shaper traffic-shaper diffservcode" = %{
set code [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
if {[regexp {^[01]{1,6}$} $code] == 0} {
        cli_set_errmsg "Per-ip shaper: DSCP value must be 6 bits binary, range 000000-111111"
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
	"firewall policy identity-based-policy" = %{
set policy [cli_get_parent $CLI_CUR_PARENT_NODE]
set groups [cli_get_value $CLI_CUR_NODE "" "" "groups"]
if { [cli_ver_start 500 0] } {
	namespace import global::fw_check_usrgrp
	foreach grp $groups {
		set usrgrp [cli_get_node $CLI_CUR_VDOM_NODE "user group" $grp ""]
		if { [fw_check_usrgrp $usrgrp $policy $CLI_CUR_VDOM_NODE] == 0 } {
			return 0
		}
	}

	namespace import global::fw_ident_check_usrs_grps
	if { [fw_ident_check_usrs_grps $CLI_CUR_NODE $groups $policy] == 0 } {
		return 0
	}
}
if { [cli_get_value $policy "" "" "action"] eq "ssl-vpn" } {
	set dstaddr [cli_get_value $policy "" "" "dstaddr"]
	namespace import global::addr_all_exist
	set addr_all [addr_all_exist $dstaddr]
	foreach grp $groups {
		set usrgrp [cli_get_node $CLI_CUR_VDOM_NODE "user group" $grp ""]
		if { $usrgrp == 0 } {
			cli_set_errmsg "user group $grp does not exist"
			return 0
		}
		if { [cli_get_value $usrgrp "" "" "group-type"] ne "firewall" } {
			cli_set_errmsg "user group $grp 's group-type must be firewall"
			return 0
		}
		if { [cli_ver_start 500 0] } {
			# user group sslvpn-portal moved in FOSv5
			continue
		}
		set pname [cli_get_value $usrgrp "" "" "sslvpn-portal"]
		if { $pname eq "" } {
			cli_set_errmsg "user group $grp 's sslvpn-portal must be set"
			return 0
		}
		set portal [cli_get_node $CLI_CUR_VDOM_NODE "vpn ssl web portal" $pname ""]
		if { $portal == 0 } {
			cli_set_errmsg "user group $grp 's sslvpn-portal $pname not exist"
			return 0
		}
		if { !$addr_all } {
			continue
		}
		if { [cli_ver_start 500 0] } {
			if { [cli_get_match_nr $portal 1 "widget" "type" 0 "tunnel" "split-tunneling" 0 "enable"] } {
				cli_set_errmsg "$grp with split tunnel does not allow policy destination address to be 0.0.0.0/0"
				return 0
			}
		} else {
			if { [cli_get_match_nr $portal 1 "widget" "type" 0 "tunnel" "tunnel-status" 0 "enable" "split-tunneling" 0 "enable"] } {
				cli_set_errmsg "$grp with split tunnel does not allow policy destination address to be 0.0.0.0/0"
				return 0
			}
		}
	}
	if { [cli_ver_start 500 0] } {
                set pname [cli_get_value $CLI_CUR_NODE "" "" "sslvpn-portal"]
                if { $pname eq "" } {
                        cli_set_errmsg "Must set SSLVPN portal."
                        return 0
                }
                set portal [cli_get_node $CLI_CUR_VDOM_NODE "vpn ssl web portal" $pname ""]
                if { $portal == 0 } {
                        cli_set_errmsg "sslvpn-portal $pname does not exist"
                        return 0
                }
                if { $addr_all } {
                if { [cli_get_match_nr $portal 1 "widget" "type" 0 "tunnel" "split-tunneling" 0 "enable"] } {
                        cli_set_errmsg "$pname with split tunnel does not allow policy destination address to be 0.0.0.0/0"
                        return 0
                }
		}
	}
}
if { [cli_ver_start 500 0] } {
	set intf [cli_get_value $policy "" "" "srcintf"]
	set intf [string trim $intf \"]
	if { ($intf eq "web-proxy" || $intf eq "ftp-proxy") && ([cli_get_value $policy "" "" "active-auth-method"] eq "" && [cli_get_value $policy "" "" "sso-auth-method"] eq "") } {
		cli_set_errmsg "active-auth-method or sso-auth-method must be set when srcintf is web_proxy or ftp_proxy"
		return 0
	}
}

## Mantis 271372
	set schedule [cli_get_value $CLI_CUR_NODE "" "" "schedule"]
	if { $schedule == 0 || $schedule eq "" } {
		cli_set_errmsg "Must set schedule."
		return 0
	}

return 1
	%}

	"firewall policy6" = %{
if { [cli_ver_start 500 0] } {
        set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
	set logtraffic [cli_get_value $CLI_CUR_NODE "" "" "logtraffic"]
	if { $action eq "deny" || $action == 0 || $action eq "" } {
		if { ($logtraffic == 0) || ($logtraffic eq "") || ($logtraffic eq "utm") } {
			namespace import global::ngfw_mode_policy
			if { [cli_ver_start 600 4] } {
				if { ![ngfw_mode_policy] } {
					cli_set_errmsg "logtraffic cannot be set to utm when policy action is deny"
					return 0
				}
			} else {
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
                set list {
                        {"firewall policy" "pkg"}
                        {"firewall policy6" "pkg"}
                        {"global header policy" "adom"}
                        {"global header policy6" "adom"}
                        {"global footer policy" "adom"}
                        {"global footer policy6" "adom"}
                }
                set s $CLI_CUR_NODE_NAME
		set name [string trim $name \"]
                foreach e $list {
                        set o [lindex $e 0]
                        set p [lindex $e 1]
                        set o [string trim $o \"]
                        if { $o eq $s } {
                                continue
                        }
                        set root $CLI_CUR_PKG_NODE
			if { ($p eq "adom") && $CLI_ADOM_DEV } {
				set root $CLI_CUR_VDOM_NODE
			}
                        if { [cli_get_match_nr $root 1 $o "name" 0 $name] ||
			     [cli_get_match_nr $root 1 $o "name" 0 "\"$name\""] } {
                                cli_set_errmsg "$name is already used by $o"
                                return 0
                        }
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

namespace import global::policy_ippool_visible
if { [policy_ippool_visible $CLI_CUR_NODE] } {
	set ippool [cli_get_value $CLI_CUR_NODE "" "" "ippool"]
    set poolname [cli_get_value $CLI_CUR_NODE "" "" "poolname"]
    if { $ippool eq "enable" && $poolname eq "" } {
        cli_set_errmsg "IP pool name cannot be empty"
        return 0
    }
}

return 1
%}
 
	"firewall policy6 identity-based-policy" = %{
## Mantis 271372
	set schedule [cli_get_value $CLI_CUR_NODE "" "" "schedule"]
	if { $schedule == 0 || $schedule eq "" } {
		cli_set_errmsg "Must set schedule."
		return 0
	}

return 1
        %}

	"firewall policy" = %{
namespace import global::fw_check_service
namespace import global::policy_action_sslvpn_visible
namespace import global::policy_ippool_visible
namespace import global::policy_addr_intf_check

## Mantis bug 435675
namespace import global::nCfg_policy_check_intf

if { [policy_addr_intf_check $CLI_CUR_NODE] eq 0 } {
	return 0
}

# Mantis 622129
set skip_dst 0
set skip_src 0
namespace import global::set_rep_dst
namespace import global::set_rep_src
if { [cli_ver_start 600 2] } {
	if { [set_rep_dst $CLI_CUR_NODE] } {
		set skip_dst 1
	} elseif { [set_rep_src $CLI_CUR_NODE] } {
		set skip_src 1
	}
}
set rp_min [cli_get_value $CLI_CUR_NODE "" "" "reputation-minimum"]
set int_srv [cli_get_value $CLI_CUR_NODE "" "" "internet-service"]
set int_srv6 [cli_get_value $CLI_CUR_NODE "" "" "internet-service6"]
set int_srv_s [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src"]
set int_srv6_s [cli_get_value $CLI_CUR_NODE "" "" "internet-service6-src"]
set policyid [cli_get_value $CLI_CUR_NODE "" "" "policyid"]
set pkg_name [cli_get_value $CLI_CUR_PKG_NODE "" "" ""]
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
set srcaddr [cli_get_value $CLI_CUR_NODE "" "" "srcaddr"]
set dstaddr6 [cli_get_value $CLI_CUR_NODE "" "" "dstaddr6"]
set srcaddr6 [cli_get_value $CLI_CUR_NODE "" "" "srcaddr6"]
# check reputation minimum
set rp_min [string trim $rp_min \"]
if { [cli_ver_start 600 2] && $rp_min != 0} {
	if { $rp_min ne "" } {
		if {$rp_min < 0 || $rp_min > 5} {
			cli_set_errmsg "'reputation-minimum' in Policy \"$policyid\" Package \"$pkg_name\" should be '1-5'"
			return 0
		}
	}
} 
# check dstaddr6 and srcaddr6
if { (([cli_ver_start 600 4] && $int_srv ne "enable" 
	&& $int_srv_s ne "enable") && ([cli_ver_start 700 2] && $int_srv6 ne "enable" && $int_srv6_s ne "enable")) 
	&& ($rp_min == 0 || $rp_min eq "") } {
	if { $srcaddr6 == 0 || $srcaddr6 eq "" } {
		if { ($dstaddr == 0 || $dstaddr eq "") && ($srcaddr == 0 || $srcaddr eq "") } {
			cli_set_errmsg "srcadrr6 in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if dstaddr and srcaddr are not set"
			return 0
		}
		if { $dstaddr6 != 0 && $dstaddr6 ne "" } {
			cli_set_errmsg "srcaddr6 in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if dstaddr6 is set"
			return 0
		}
	}
	if { $dstaddr6 == 0 || $dstaddr6 eq "" } {
		if { ($dstaddr == 0 || $dstaddr eq "") && ($srcaddr == 0 || $srcaddr eq "") } {
			cli_set_errmsg "dstadrr6 in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if dstaddr and srcaddr are not set"
			return 0
		}
		if { $srcaddr6 != 0 && $srcaddr6 ne "" } {
			cli_set_errmsg "dstaddr6 in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if srcaddr6 is set"
			return 0
		}
	}
}
# check dstaddr and srcaddr
if { [cli_ver_start 500 6] && !$skip_src && $int_srv_s ne "enable"
		&& ($srcaddr == 0 || $srcaddr eq "") } {
	if { $int_srv ne "enable" && !$skip_dst} {
		if {[cli_ver_start 600 4]} {
			if { ($dstaddr6 == 0 || $dstaddr6 eq "") && ($srcaddr6 == 0 && $srcaddr6 eq "") } {
				cli_set_errmsg "srcaddr in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if dstaddr6 and srcaddr6 are not set"
				return 0
			}
		}
		if { $dstaddr != 0 && $dstaddr ne "" } {
			cli_set_errmsg "srcaddr in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if dstaddr is set"
			return 0
		}
	} else {
		cli_set_errmsg "srcaddr in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty"
		return 0
	}
}
if { [cli_ver_start 500 6] && !$skip_dst && $int_srv ne "enable" 
		&& ($dstaddr == 0 || $dstaddr eq "") } {
	if { $int_srv_s ne "enable" && !$skip_src} {
		if {[cli_ver_start 600 4]} {
			if { ($dstaddr6 == 0 || $dstaddr6 eq "") && ($srcaddr6 == 0 && $srcaddr6 eq "") } {
				cli_set_errmsg "dstaddr in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if dstaddr6 and srcaddr6 are not set"
				return 0
			}
		}
		if { $srcaddr != 0 && $srcaddr ne "" } {
			cli_set_errmsg "dstaddr in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if srcaddr is set"
			return 0
		}
	} else {
		cli_set_errmsg "dstaddr in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty"
		return 0
	}
}

set srcintf [cli_get_value $CLI_CUR_NODE "" "" "srcintf" 1]
if { $srcintf eq "" } {
	set pkg_name [cli_get_value $CLI_CUR_PKG_NODE "" "" ""]
	cli_set_errmsg "srcintf in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty"
	return 0
}
set dstintf [cli_get_value $CLI_CUR_NODE "" "" "dstintf" 1]
if { $dstintf eq "" } {
	set pkg_name [cli_get_value $CLI_CUR_PKG_NODE "" "" ""]
	cli_set_errmsg "dstintf in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty"
	return 0
}
set nat [cli_get_value $CLI_CUR_NODE "" "" "nat"]
set port_list [cli_get_tbl_list $CLI_CUR_VDOM_NODE "system virtual-wire-pair"]
foreach port_node $port_list {
	set mem_list [cli_get_value $port_node "" "" "member"]
	if { [llength $mem_list] == 2 } {
		set m1 [lindex $mem_list 0]
		set m2 [lindex $mem_list 1]

		set m1_src [nCfg_policy_check_intf $CLI_CUR_NODE $m1 1]
		set m1_dst [nCfg_policy_check_intf $CLI_CUR_NODE $m1 0]
		set m2_src [nCfg_policy_check_intf $CLI_CUR_NODE $m2 1]
		set m2_dst [nCfg_policy_check_intf $CLI_CUR_NODE $m2 0]

		if { [cli_branchpt_start 500 1138] } {
			if { ($m1_src && !$m2_dst) || (!$m1_src && $m2_dst) || ($m1_dst && !$m2_src) || (!$m1_dst && $m2_src) } {
				cli_set_errmsg "srcintf and dstintf are not in the same port pair."
				return 0
			}
			if { ($m1_src && $m2_dst) || ($m1_dst && $m2_src) } {
				if { ![cli_ver_start 700 0] } {
					if { [llength $srcintf] > 2 || [llength $dstintf] > 2 } {
						cli_set_errmsg "Maximum interface number of port pair policy is two."
						return 0
					}
					if { [llength $srcintf]== 2 || [llength $dstintf]== 2 } {
						if { (!$m1_src && !$m2_dst) || (!$m1_dst && !$m2_src) } {
							cli_set_errmsg "Invalid srcintf or dstintf for port pair policy."
							return 0
						}
					}
				}
				if { ![cli_ver_start 600 4] && $nat eq "enable" } {
					cli_set_errmsg "The nat option of policy between port pair must be disable."
					return 0
				}
			}
		} else {
			if { $m1_src || $m1_dst || $m2_src || $m2_dst } {
				if { [llength $srcintf] != 1 || [llength $dstintf] != 1 } {
					cli_set_errmsg "Only one srcintf and one dstintf can be included in policy between port pair."
					return 0
				}
				if { (!$m1_src && !$m1_dst) || (!$m2_src && !$m2_dst) } {
					cli_set_errmsg "srcintf and dstintf are not in the same port pair."
					return 0
				}
				if { $nat eq "enable" } {
					cli_set_errmsg "The nat option of policy between port pair must be disable."
					return 0
				}
			}
		}
	}
}

if {[cli_get_value $CLI_CUR_NODE "" "" "endpoint-check"] eq "enable"} {
    if {[cli_get_value $CLI_CUR_NODE "" "" "endpoint-profile"] eq ""} {
	cli_set_errmsg "endpoint profile missing"
	return 0
    }
}
if {[cli_get_value $CLI_CUR_NODE "" "" "dynamic-profile"] eq "enable"} {
	if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "dynamic-profile" 0 "enable"] > 1} {
		cli_set_errmsg "Can not duplicate enable Dynamic profile in different policies"
		return 0
	}
}

if { [cli_get_value $CLI_CUR_NODE "" "" "utm-status"] eq "enable" } {
        if { [cli_get_value $CLI_CUR_NODE "" "" "profile-type"] eq "single" } {
		set ppo [cli_get_value $CLI_CUR_NODE "" "" "profile-protocol-options"]
		if { $ppo eq "" } {
			set avp [cli_get_value $CLI_CUR_NODE "" "" "av-profile"]
			set wfp [cli_get_value $CLI_CUR_NODE "" "" "webfilter-profile"]
			set sfp [cli_get_value $CLI_CUR_NODE "" "" "spamfilter-profile"]
			set dlp [cli_get_value $CLI_CUR_NODE "" "" "dlp-sensor"]
			if { [cli_ver_start 500 2] } {
				set icp [cli_get_value $CLI_CUR_NODE "" "" "icap-profile"]
				if { ($avp ne "") || ($wfp ne "") || ($sfp ne "") || ($dlp ne "") || ($icp ne "") } {
				        cli_set_errmsg "Attribute 'profile-protocol-options' MUST be set."
				        return 0
				}
			} else {
				if { ($avp ne "") || ($wfp ne "") || ($sfp ne "") || ($dlp ne "") } {
				        cli_set_errmsg "Attribute 'profile-protocol-options' MUST be set."
				        return 0
				}
			}
		}
        }
}

if {[expr {[cli_get_value $CLI_CUR_NODE "" "" "webcache"] eq "enable"}]} {
	set profileopt [cli_get_value $CLI_CUR_NODE "" "" "profile-protocol-options"] 
	if { $profileopt ne "" } { 
		set node [cli_get_node $CLI_CUR_VDOM_NODE "firewall profile-protocol-options" $profileopt ""] 
		if { 0 != $node && [expr {[cli_get_value $node "http" "" "inspect-all"] eq "enable"}]} { 
			cli_set_errmsg "Web cache cannot be enabled when inspect-all is enabled in http option of firewall profile-protocol-options" 
			return 0 
		} 
	} 
}

if { [cli_is_match $CLI_CUR_NODE 0 "" "action" 0 "accept"] } {
	if { [cli_is_match $CLI_CUR_NODE 0 "" "inspection-mode" 0 "proxy"] } {
		if { [cli_is_match $CLI_CUR_NODE 0 "" "videofilter-profile" 1 ""] } {
			# Mantis 0743649
			# FGT only checks if the status of the https profile is deep-inspection
			set ssl_ssh_profile_name [cli_get_value $CLI_CUR_NODE "" "" "ssl-ssh-profile"]
			set ssl_ssh_profile [cli_get_node $CLI_CUR_VDOM_NODE "firewall ssl-ssh-profile" $ssl_ssh_profile_name ""]
			set ssl_ssh_profile_https [cli_get_node $ssl_ssh_profile "https" "" ""]
			set status [cli_get_value $ssl_ssh_profile_https "" "" "status"]
			if { $status ne "deep-inspection" } {  
				# msg copied from FortiOS/fortinet/cmf/plugin/firewall/policy.c:firewall_policy_check (search 'video_filter_profile')
				cli_set_errmsg "\"deep-inspection\" must be enabled in https when there is a firewall policy with \"videofilter-profile\" enabled uses this profile. name:$ssl_ssh_profile_name node:$ssl_ssh_profile nodes:$ssl_ssh_profile_https status:$status "
				return 0
			}
		}
	}
}
namespace import global::nCfg_is_address_vip46
namespace import global::nCfg_is_address6_vip64
## Mantis 307632
if { [cli_ver_start 500 2] && [policy_ippool_visible $CLI_CUR_NODE] } {
	set ippool [cli_get_value $CLI_CUR_NODE "" "" "ippool"]
	set central_nat ""
	if { [cli_ver_start 500 4] } {
		set sys_settings [cli_get_node $CLI_CUR_VDOM_NODE "system settings" "" ""]
		if { $sys_settings != 0 } {
			set central_nat [cli_get_value $sys_settings "" "" "central-nat"]
		}
	}

	if { $ippool eq "enable" && $central_nat ne "enable" } {
		set nat46 [cli_get_value $CLI_CUR_NODE "" "" "nat46"]
		set nat64 [cli_get_value $CLI_CUR_NODE "" "" "nat64"]
		if { $nat46 eq "enable" || $nat64 eq "enable" } {
			if { ($srcaddr == 0 || $srcaddr eq "") || ($dstaddr == 0 || $dstaddr eq "") || ($srcaddr6 == 0 || $srcaddr6 eq "") || ($dstaddr6 == 0 || $dstaddr6 eq "") } {
				cli_set_errmsg "Policy IPv4 and IPv6 addresses must be specified when NAT46/NAT64 is enable."
				return 0
			}
			if { $nat64 eq "enable" } {
				foreach addr6 $dstaddr6 {
					if { ![nCfg_is_address6_vip64 $addr6] } {
						cli_set_errmsg "Policy dstaddr6 must be vip6 when NAT64 is enabled."
						return 0
					}
				}
				foreach addr $dstaddr {
					if { [nCfg_is_address_vip46 $addr] } {
						cli_set_errmsg "Policy dstaddr must not be vip when NAT64 is enabled."
						return 0
					}
				}
			}
		}

		set poolname [cli_get_value $CLI_CUR_NODE "" "" "poolname"]
		set poolname6 [cli_get_value $CLI_CUR_NODE "" "" "poolname6"]
		if { ($poolname == 0 || $poolname eq "") && ($poolname6 == 0 || $poolname6 eq "") } {
			cli_set_errmsg "Policy ippool (ippool6) name cannot be empty."
			return 0
		}
		if { $poolname != 0 && $poolname != "" && $int_srv ne "enable" && ($dstaddr == 0 || $dstaddr eq "") } {
			cli_set_errmsg "poolname in Policy \"$policyid\" cannot be set if dstaddr is empty"
			return 0
		}
		if { $poolname6 != 0 && $poolname6 != "" && $int_srv ne "enable" && ($dstaddr6 == 0 || $dstaddr6 eq "") } {
			cli_set_errmsg "poolname6 in Policy \"$policyid\" cannot be set if dstaddr6 is empty"
			return 0
		}
		if { $nat eq "enable" && $nat46 eq "disable" && $nat64 eq "disable" } {
			set ippool_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall ippool" $poolname ""]
			if { $ippool_node ne 0 && $ippool_node ne "" } {
				set ippool_nat64 [cli_get_value $ippool_node "" "" "nat64"]
				if { $ippool_nat64 eq "enable" } {
					cli_set_errmsg "nat64 cannot be enable for poolname when nat is enable (policy \"$policyid\")"
					return 0
				}
			}
		}
	}
} elseif { [cli_ver_start 500 0] } {
	set nat [cli_get_value $CLI_CUR_NODE "" "" "nat"]
	set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
	set ippool [cli_get_value $CLI_CUR_NODE "" "" "ippool"]
	if { $nat eq "enable" && $ippool eq "enable" && $action ne "ipsec" && $action ne "deny" } {
		set poolname [cli_get_value $CLI_CUR_NODE "" "" "poolname"]
		if { $poolname == 0 || $poolname eq "" } {
			cli_set_errmsg "Policy ip pool name cannot be empty."
			return 0
		}
	}
}

## Mantis 232854
if { $srcintf eq "" } {
	cli_set_errmsg "srcintf does not exist. "
	return 0
}

if { $dstintf eq "" } {
	cli_set_errmsg "dstintf does not exist. "
	return 0
}

if { [cli_get_value $CLI_CUR_NODE "" "" "action"] eq "ssl-vpn" } {
	if { [cli_ver_start 500 2] } {
	} elseif { [cli_ver_start 500 0] } {
		set e [policy_action_sslvpn_visible $CLI_CUR_NODE]
		if { $e ne 0 } {
			cli_set_errmsg "can not set action to ssl-vpn. reason: $e"
			return 0
		}
	}

	namespace import global::addr_all_exist
	set addr_all [addr_all_exist $dstaddr]
	set ibp_list [cli_get_tbl_list $CLI_CUR_NODE "identity-based-policy"]
	foreach ibp $ibp_list {
		set groups [cli_get_value $ibp "" "" "groups"]
		foreach grp $groups {
			set usrgrp [cli_get_node $CLI_CUR_VDOM_NODE "user group" $grp ""]
			if { $usrgrp == 0 } {
				cli_set_errmsg "user group $grp does not exist"
				return 0
			}
			if { [cli_get_value $usrgrp "" "" "group-type"] ne "firewall" } {
				cli_set_errmsg "user group $grp 's group-type must be firewall"
				return 0
			}
			if { [cli_ver_start 500 0] } {
				# user group sslvpn-portal moved in FOSv5
				continue
			}
			set pname [cli_get_value $usrgrp "" "" "sslvpn-portal"]
			if { $pname eq "" } {
				cli_set_errmsg "user group $grp 's sslvpn-portal must be set"
				return 0
			}
			set portal [cli_get_node $CLI_CUR_VDOM_NODE "vpn ssl web portal" $pname ""]
			if { $portal == 0 } {
				cli_set_errmsg "user group $grp 's sslvpn-portal $pname does not exist"
				return 0
			}
			if { !$addr_all } {
				continue
			}
			if { [cli_ver_start 500 0] } {
				if { [cli_get_match_nr $portal 1 "widget" "type" 0 "tunnel" "split-tunneling" 0 "enable"] } {
					cli_set_errmsg "\"$grp\" with split tunnel does not allow policy destination address to be 0.0.0.0/0"
					return 0
				}
			} else {
				if { [cli_get_match_nr $portal 1 "widget" "type" 0 "tunnel" "tunnel-status" 0 "enable" "split-tunneling" 0 "enable"] } {
					cli_set_errmsg "\"$grp\" with split tunnel does not allow policy destination address to be 0.0.0.0/0"
					return 0
				}
			}
		}
		if { [cli_ver_start 500 0] } {
			set pname [cli_get_value $ibp "" "" "sslvpn-portal"]
			if { $pname eq "" } {
				cli_set_errmsg "Must set SSLVPN portal."
				return 0
			}
			set portal [cli_get_node $CLI_CUR_VDOM_NODE "vpn ssl web portal" $pname ""]
			if { $portal == 0 } {
				cli_set_errmsg "sslvpn-portal \"$pname\" does not exist"
				return 0
			}
			if { $addr_all } {
				if { [cli_get_match_nr $portal 1 "widget" "type" 0 "tunnel" "split-tunneling" 0 "enable"] } {
					cli_set_errmsg "\"$pname\" with split tunnel does not allow policy destination address to be 0.0.0.0/0"
					return 0
				}
			}
		}
	}
}

set srcintf_sslvpn_policy 0
set sslvpn_web 0
if { [cli_ver_start 500 2] } {
	set srcintfs_count 0
	foreach intf $srcintf {
		incr srcintfs_count
		namespace import global::is_sslvpn_intf
		if { [is_sslvpn_intf $intf] } {
			set srcintf_sslvpn_policy 1
			break
		}
	}
	if { $srcintf_sslvpn_policy } {
		if { $srcintfs_count > 1 } {
			cli_set_errmsg "Cannot use tunnel interface in multiple interfaces."
			return 0
		}
		if { [cli_has_feature "f_sslvpn"] } {
			set us [cli_get_value $CLI_CUR_NODE "" "" "users"]
			set gs [cli_get_value $CLI_CUR_NODE "" "" "groups"]
			namespace import global::is_sslvpn_policy_has_tunnel
			if { [is_sslvpn_policy_has_tunnel $us $gs 0] } {
				set sslvpn_web 1
			}
		}
	} 
}

if { $CLI_IS_AUTOUPDATE == 0 } {
	if { !$skip_src && ($srcaddr eq "" && $srcaddr6 eq "") } {
		if { !([cli_ver_start 600 0] && ([cli_get_value $CLI_CUR_NODE "" "" "internet-service-src"] eq "enable"
				|| ([cli_branchpt_start 700 1228] && [cli_get_value $CLI_CUR_NODE "" "" "internet-service6-src"] eq "enable"))) } {
			if { ($srcaddr eq "") && ($srcaddr6 eq "") } {
				if { [cli_ver_start 500 2] } {
					if { !$sslvpn_web } {
						cli_set_errmsg "Must set source address name."
						return 0
					}
				} else {
					cli_set_errmsg "srcaddr address does not exist. "
					return 0
				}
			} else {
				cli_set_errmsg "srcaddr6 address does not exist. "
				return 0
			}
		}
	}
	namespace import global::fw_dstaddr_visible
	if { !$skip_dst && [fw_dstaddr_visible $CLI_CUR_NODE] } {
		if { ($dstaddr eq "" && $dstaddr6 eq "") } {
			cli_set_errmsg "dstaddr address does not exist. "
			return 0
		}
	}
}

namespace import global::cmf_firewall_policy_learn_enabled
if { [cli_ver_start 500 0] && ![cmf_firewall_policy_learn_enabled $CLI_CUR_NODE] } {
	set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
	set logtraffic [cli_get_value $CLI_CUR_NODE "" "" "logtraffic"]
	if { $action eq "deny" || $action == 0 || $action eq "" } {
		if { ($logtraffic == 0) || ($logtraffic eq "") || ($logtraffic eq "utm") } {
			namespace import global::is_hyperscale_activated
			namespace import global::ngfw_mode_policy
			if { [cli_ver_start 600 4] } {
				if { ![ngfw_mode_policy] && ![is_hyperscale_activated] } {
					cli_set_errmsg "logtraffic cannot be set to utm when policy action is deny"
					return 0
				}
			} else {
				cli_set_errmsg "logtraffic cannot be set to utm when policy action is deny"
				return 0
			}
		}
	}
}

set cap [cli_get_value $CLI_CUR_NODE "" "" "capture-packet"]
if {$cap eq "enable" && ($srcintf eq "web-proxy" || $srcintf eq "\"web-proxy\"" || $dstintf eq "web-proxy" || $dstintf eq "\"web-proxy\"")} {
	cli_set_errmsg "capture-packat is not supported for web-proxy policies"
	return 0
}

if { !$skip_dst && [fw_check_service $CLI_CUR_NODE $CLI_CUR_VDOM_NODE] == 0 } {
	return 0
}

## Mantis 433799 
if { !$skip_dst && [cli_ver_start 500 6] } {
	if { [cli_is_match $CLI_CUR_NODE 0 "" "internet-service" 0 "enable"] } {
		if { [cli_ver_start 600 4] } {
			set intsvc_id [cli_get_value $CLI_CUR_NODE "" "" "internet-service-name"]
		} else {
			set intsvc_id [cli_get_value $CLI_CUR_NODE "" "" "internet-service-id"]
		}
		set intsvc_cus [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom"]
		if { ($intsvc_id eq "") && ($intsvc_cus eq "") } {
			if { [cli_ver_start 600 2] } {
				set intsvc_id_grp [cli_get_value $CLI_CUR_NODE "" "" "internet-service-group"]
				set intsvc_cus_grp [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom-group"]
				if { ($intsvc_id_grp eq "") && ($intsvc_cus_grp eq "") } {
					cli_set_errmsg "Must set internet service (group) or custom internet service (group) when internet-service is enabled."
					return 0;
				}
			} else {
				cli_set_errmsg "Must set internet service or custom internet service when internet-service is enabled."
				return 0
			}
		}
	}
}

## Mantis 271372
if { [cli_ver_start 500 2] } {
	set schedule [cli_get_value $CLI_CUR_NODE "" "" "schedule"]
	if { $schedule == 0 || $schedule eq "" } {
		namespace import global::ngfw_mode_policy
		namespace import global::is_hyperscale_activated
		if { [cli_ver_start 600 4] } {
			if { ![ngfw_mode_policy] && ![is_hyperscale_activated] } {
				cli_set_errmsg "Must set schedule."
				return 0
			}
		} else {
			cli_set_errmsg "Must set schedule."
			return 0
		}
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
                set list {
                        {"firewall policy" "pkg"}
                        {"firewall policy6" "pkg"}
                        {"global header policy" "adom"}
                        {"global header policy6" "adom"}
                        {"global footer policy" "adom"}
                        {"global footer policy6" "adom"}
                }
                set s $CLI_CUR_NODE_NAME
		set name [string trim $name \"]
                foreach e $list {
                        set o [lindex $e 0]
                        set p [lindex $e 1]
                        set o [string trim $o \"]
                        if { $o eq $s } {
                                continue
                        }
                        set root $CLI_CUR_PKG_NODE
                        if { ($p eq "adom") && $CLI_ADOM_DEV } {
				set root $CLI_CUR_VDOM_NODE
                        }
                        if { [cli_get_match_nr $root 1 $o "name" 0 $name] ||
                             [cli_get_match_nr $root 1 $o "name" 0 "\"$name\""] } {
                                cli_set_errmsg "$name is already used by $o"
                                return 0
                        }
                }
	}
}

if { [cli_ver_start 500 4] } {
	namespace import global::cmf_firewall_policy_learn_enabled
	namespace import global::cmf_firewall_validate_learning_src_dst
	if { [cmf_firewall_policy_learn_enabled $CLI_CUR_NODE] && 
	    ![cmf_firewall_validate_learning_src_dst $CLI_CUR_NODE] } {
		return 0
	}
}

if { [cli_is_match $CLI_CUR_NODE 0 "" "action" 0 "accept"] } {
	if { [cli_is_match $CLI_CUR_NODE 0 "" "inspection-mode" 0 "flow"] } {
		foreach addr $dstaddr {
			set addr_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $addr ""]
			set vip_type [cli_get_value $addr_node "" "" "type"]
			if { $addr_node && $vip_type eq "server-load-balance" } {
				set s_type [cli_get_value $addr_node "" "" "server-type"]
				if { $s_type ne "ip" && $s_type ne "tcp" && $s_type ne "ssh" && $s_type ne "udp" } {
					cli_set_errmsg "Virtual Server address is not allowed when inspection-mode is flow."
					return 0
				}
			}
		}
	}
}

if { ![cli_branchpt_start 700 234] } {
if { [cli_is_match $CLI_CUR_NODE 0 "" "action" 0 "deny"] } {
	foreach addr $dstaddr {
		set addr_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $addr ""]
		if { $addr_node } {
			set vip_type [cli_get_value $addr_node "" "" "type"]
			if { $vip_type eq "server-load-balance" } {
				cli_set_errmsg "Virtual Server address is not allowed when action is deny."
				return 0
			}
		}
	}
}
}

return 1
	%}

	"firewall central-snat-map" = %{
if { ![cli_ver_start 600 4] } {
	return 1
}
set ctype [cli_get_value $CLI_CUR_NODE "" "" "type"]
if { $ctype eq "ipv4" } {
	set orig_addr [cli_get_value $CLI_CUR_NODE "" "" "orig-addr"]
	set dst_addr [cli_get_value $CLI_CUR_NODE "" "" "dst-addr"]
	if { $orig_addr eq "" || $dst_addr eq ""} {
		cli_set_errmsg "MUst set orig-addr and dst-addr if type is ipv4"
		return 0
	}
}
if { $ctype eq "ipv6" } {
	set orig_addr6 [cli_get_value $CLI_CUR_NODE "" "" "orig-addr6"]
	set dst_addr6 [cli_get_value $CLI_CUR_NODE "" "" "dst-addr6"]
	if { $orig_addr6 eq "" || $dst_addr6 eq ""} {
		cli_set_errmsg "MUst set orig-addr6 and dst-addr6 if type is ipv6"
		return 0
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
	
	"firewall proxy-policy internet-service-custom" = %{
set ov [cli_get_org_value $CLI_CUR_NODE "" "" ""]
set nv [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $ov ne $nv && $nv ne "" && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] && ![string match "*upgrade*" [cli_get_clisrc]] } {
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
if { [cli_get_value $CLI_CUR_NODE "" "" "utm-status"] eq "enable" } {
    if { [cli_get_value $CLI_CUR_NODE "" "" "profile-type"] eq "single" } {
        if { [cli_get_value $CLI_CUR_NODE "" "" "profile-protocol-options"] eq "" } {
            cli_set_errmsg "Attribute 'profile-protocol-options' MUST be set."
            return 0
        }
	}
}
if { [cli_get_value $CLI_CUR_NODE "" "" "profile-type"] eq "group" && [cli_get_value $CLI_CUR_NODE "" "" "profile-group"] eq "" } {
    cli_set_errmsg "Profile group must be selected when profile type is group"
    return 0
}

set srcaddr [cli_get_value $CLI_CUR_NODE "" "" "srcaddr"]
set srcaddr6 [cli_get_value $CLI_CUR_NODE "" "" "srcaddr6"]
if { $srcaddr eq "" && $srcaddr6 eq "" } {
	set id [cli_get_value $CLI_CUR_NODE "" "" ""]
	set pkg_name [cli_get_value $CLI_CUR_PKG_NODE "" "" ""]
	cli_set_errmsg "srcaddr/srcaddr6 in proxy policy \"$id\" Package \"$pkg_name\" cannot be empty"
	return 0
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
		if { $access_proxy eq "" &&  $access_proxy6 eq "" } {
			cli_set_errmsg "Must set access-proxy or access-proxy6 address."
			return 0
		}
	}
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
    
	"firewall proxy-policy service" = %{
if { [cli_ver_start 500 6] } {
	set srvlist [cli_get_value $CLI_CUR_NODE "" "" ""]
	set proxy [cli_get_value $CLI_CUR_PARENT_NODE "" "" "proxy"]
	foreach srv $srvlist {
		set node [cli_get_node $CLI_CUR_VDOM_NODE "firewall service custom" $srv ""]
		if {$node != 0} {
			set pkg_name [cli_get_value $CLI_CUR_PKG_NODE "" "" ""]
			if { [cli_branchpt_start 500 1450] } {
				set webproxy [cli_get_value $node "" "" "proxy"]
			} else {
				set webproxy [cli_get_value $node "" "" "explicit-proxy"]
			}
			if { ($proxy eq "transparent-web" || $proxy eq "explicit-web") && $webproxy ne "enable"} {
				cli_set_errmsg "$CLI_CUR_NODE_NAME \"$srv\" cannot be used in \"$proxy\" proxy policy in package \"$pkg_name\" because $srv's type is not for explicit proxy"
				return 0
			} elseif { ($proxy eq "ftp" || $proxy eq "wanopt") && $webproxy eq "enable" } {
				cli_set_errmsg "$CLI_CUR_NODE_NAME \"$srv\" cannot be used in \"$proxy\" proxy policy in package \"$pkg_name\" because $srv's type is for explicit proxy"
				return 0
			}
		}
	} 
}
return 1
	%}

	"global {header footer} policy {srcaddr dstaddr srcaddr6 dstaddr6 service schedule}" = %{
if { [cli_ver_start 600 4] && $CLI_CUR_NODE_NAME ne "service" && $CLI_CUR_NODE_NAME ne "schedule"} {
	set policy $CLI_CUR_PARENT_NODE
	set skip_dst 0
	set skip_src 0
	namespace import global::set_rep_dst
	namespace import global::set_rep_src
	if { [set_rep_dst $policy] } {
		set skip_dst 1
	} elseif { [set_rep_src $policy] } {
		set skip_src 1
	}
	set rp_min [cli_get_value $policy "" "" "reputation-minimum"]
	set int_srv [cli_get_value $policy "" "" "internet-service"]
	set int_srv_s [cli_get_value $policy "" "" "internet-service-src"]
	set policyid [cli_get_value $policy "" "" "policyid"]
	set pkg_name [cli_get_value $CLI_CUR_PKG_NODE "" "" ""]
	set dstaddr [cli_get_value $policy "" "" "dstaddr"]
	set srcaddr [cli_get_value $policy "" "" "srcaddr"]
	set dstaddr6 [cli_get_value $policy "" "" "dstaddr6"]
	set srcaddr6 [cli_get_value $policy "" "" "srcaddr6"]
	# check dstaddr6 and srcaddr6
	if { $int_srv ne "enable" && $int_srv_s ne "enable" && ($rp_min == 0 || $rp_min eq "") } {
		if { $srcaddr6 == 0 || $srcaddr6 eq "" } {
			if { ($dstaddr == 0 || $dstaddr eq "") && ($srcaddr == 0 || $srcaddr eq "") } {
				cli_set_errmsg "srcadrr6 in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if dstaddr and srcaddr are not set"
				return 0
			}
			if { $dstaddr6 != 0 && $dstaddr6 ne "" } {
				cli_set_errmsg "srcaddr6 in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if dstaddr6 is set"
				return 0
			}
		}
		if { $dstaddr6 == 0 || $dstaddr6 eq "" } {
			if { ($dstaddr == 0 || $dstaddr eq "") && ($srcaddr == 0 || $srcaddr eq "") } {
				cli_set_errmsg "dstadrr6 in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if dstaddr and srcaddr are not set"
				return 0
			}
			if { $srcaddr6 != 0 && $srcaddr6 ne "" } {
				cli_set_errmsg "dstaddr6 in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if srcaddr6 is set"
				return 0
			}
		}
	}
	# check dstaddr and srcaddr
	if { !$skip_src && $int_srv_s ne "enable" && ($srcaddr == 0 || $srcaddr eq "") } {
		if { $int_srv ne "enable" && !$skip_dst} {
			if { ($dstaddr6 == 0 || $dstaddr6 eq "") && ($srcaddr6 == 0 && $srcaddr6 eq "") } {
				cli_set_errmsg "srcaddr in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if dstaddr6 and srcaddr6 are not set"
				return 0
			}
			if { $dstaddr != 0 && $dstaddr ne "" } {
				cli_set_errmsg "srcaddr in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if dstaddr is set"
				return 0
			}
		} else {
			cli_set_errmsg "srcaddr in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty"
			return 0
		}
	}
	if {!$skip_dst && $int_srv ne "enable" && ($dstaddr == 0 || $dstaddr eq "") } {
		if { $int_srv_s ne "enable" && !$skip_src} {
			if { ($dstaddr6 == 0 || $dstaddr6 eq "") && ($srcaddr6 == 0 && $srcaddr6 eq "") } {
				cli_set_errmsg "dstaddr in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if dstaddr6 and srcaddr6 are not set"
				return 0
			}
			if { $srcaddr != 0 && $srcaddr ne "" } {
				cli_set_errmsg "dstaddr in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty if srcaddr is set"
				return 0
			}
		} else {
			cli_set_errmsg "dstaddr in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty"
			return 0
		}
	}
} else {
	set value [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $value eq "" } {
		set is [cli_get_value $CLI_CUR_PARENT_NODE "" "" "internet-service"]
		if { ($CLI_CUR_NODE_NAME eq "service" && $is ne "enable") || $CLI_CUR_NODE_NAME eq "schedule" } { 
			set id [cli_get_value $CLI_CUR_PARENT_NODE "" "" ""]
			set pkg_name [cli_get_value $CLI_CUR_PKG_NODE "" "" ""]
			cli_set_errmsg "$CLI_CUR_NODE_NAME in Policy \"$id\" Package \"$pkg_name\" cannot be empty"
			return 0
		}
	}
}
return 1
	%}

	"firewall policy {srcaddr dstaddr}" = %{
set policy $CLI_CUR_PARENT_NODE
set node $CLI_CUR_NODE_NAME
namespace import global::set_rep_dst
namespace import global::set_rep_src
set int_srv [cli_get_value $policy "" "" "internet-service"]
set int_srv_s [cli_get_value $policy "" "" "internet-service-src"]
if { $node eq "dstaddr" } {
	if { [cli_ver_start 600 2] } {
		if { [set_rep_dst $policy] } {
			return 1
		}
	}
	if { [cli_ver_start 500 6] } {
		if { $int_srv eq "enable" } {
			return 1
		}
	}
}
if { $node eq "srcaddr" } {
	if { [cli_ver_start 600 2] } {
		if { [set_rep_src $policy] } {
			return 1
		}
	}
	if { [cli_ver_start 500 6] } {
		if { $int_srv_s eq "enable" } {
			return 1
		}
	}
}
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { ![cli_ver_start 500 6] && $value eq "" } {
	set policyid [cli_get_value $policy "" "" "policyid"]
	set pkg_name [cli_get_value $CLI_CUR_PKG_NODE "" "" ""]
	cli_set_errmsg "$CLI_CUR_NODE_NAME in Policy \"$policyid\" Package \"$pkg_name\" cannot be empty"
	return 0
}
if { [cli_ver_start 500 4] } {
	if { $node eq "dstaddr" } {
		set pkg [cli_get_node [cli_get_parent $CLI_CUR_PARENT_NODE] "policy package settings" "" ""]
		if { [cli_get_value $pkg "" "" "central-nat"] eq "enable" } {
			set fwviplist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall vip"]
			set fwvipnlist {}
			foreach fwvip $fwviplist {
				set fwvipname [cli_get_value $fwvip "" "" "name"]
				set fwvipname [string trim $fwvipname \"]
				lappend fwvipnlist $fwvipname
			}
			set fwvipgrplist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall vipgrp"]
			foreach fwvipgrp $fwvipgrplist {
				set fwvipgrpname [cli_get_value $fwvipgrp "" "" "name"]
				set fwvipgrpname [string trim $fwvipgrpname \"]	
				lappend fwvipnlist $fwvipgrpname
			}
			set addrs [cli_get_value $CLI_CUR_NODE "" "" ""]
			foreach addr $addrs {
				set addr [string trim $addr \"]
				if { [lsearch -exact $fwvipnlist $addr] >= 0 } {
					cli_set_errmsg "Firewall policy dstaddr ($addr) cannot be a vip or vipgrp when central-nat is enabled."
					return 0
				}
			}
		}
	}
}
set addrs [cli_get_value $policy "" "" $node]
foreach addr $addrs {
	set addr [string trim $addr \"]
	if { [cli_is_match $CLI_CUR_VDOM_NODE 1 "firewall address" "name" 0 $addr "type" 0 "url"] } {
		cli_set_errmsg "Url type of firewall address ($addr) should only be used in webproxy policy"
		return 0
	}
}
return 1
	%}
	"policy package settings central-nat" = %{
if { [cli_ver_start 500 4] } {
	set pkg_cen_nat [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $pkg_cen_nat eq "enable" } {
		set policylist [cli_get_tbl_list [cli_get_parent $CLI_CUR_PARENT_NODE] "firewall policy"]
		set fwviplist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall vip"]
		set fwvipnlist {}
		foreach fwvip $fwviplist {
			set fwvipname [cli_get_value $fwvip "" "" "name"]
			set fwvipname [string trim $fwvipname \"]
			lappend fwvipnlist $fwvipname
		}
		set fwvipgrplist [cli_get_tbl_list $CLI_CUR_VDOM_NODE "firewall vipgrp"]
		foreach fwvipgrp $fwvipgrplist {
			set fwvipgrpname [cli_get_value $fwvipgrp "" "" "name"]
			set fwvipgrpname [string trim $fwvipgrpname \"]	
			lappend fwvipnlist $fwvipgrpname
		}		
		foreach policy $policylist {
			set addrs [cli_get_value $policy "" "" "dstaddr"]
			foreach addr $addrs {
				set addr [string trim $addr \"]
				if { [lsearch -exact $fwvipnlist $addr] >= 0 } {
					cli_set_errmsg "Package central-nat cannot be enable when VIP ($addr) policy exsits."
					return 0
				}	
			}
		}	
	}	
}       
return 1
	%}
	"policy package settings ngfw-mode" = %{
if { [cli_ver_start 600 2] || $CLI_POLICY_BLOCK } {
	return 1
}
if { [cli_ver_start 500 6] } {
	set mode [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $mode eq "policy-based" } {
		set prof [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ssl-ssh-profile"]
		if { $prof eq 0 || $prof eq "" } {
			cli_set_errmsg "ssl-ssh-profile required for policy-based ngfw-mode"
			return 0
		}
	}
	return 1
}
return 1
	%}
	"firewall policy identity-based-policy dstaddr" = %{
set policy [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]]
set action [cli_get_value $policy "" "" "action"]
set idp [cli_get_value $policy "" "" "identity-based"]
if { [cli_ver_start 500 0] && $action eq "accept" && $idp eq "enable"} {
	namespace import global::intf_binding_contradiction
	set policyid [cli_get_value $policy "" "" "policyid"]
	set srcaddr [cli_get_value $policy "" "" "srcaddr" 1]
	set srcintf [cli_get_value $policy "" "" "srcintf" 1]
	set dstintf [cli_get_value $policy "" "" "dstintf" 1]
	set dstaddr [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dstaddr" 1]
	set id [cli_get_value $CLI_CUR_PARENT_NODE "" "" "id"]
	set msg [intf_binding_contradiction $srcaddr $dstaddr $srcintf $dstintf $policyid $id 0]
	if { $msg ne 0 } {
		cli_set_errmsg $msg
		return 0
        }
}
return 1
        %}

        "system ntp ntpserver" = %{
if { [cli_ver_start 500 0] } {
	set ntp [cli_get_parent $CLI_CUR_PARENT_NODE]
	if { ![string match "*override*" [cli_get_clisrc]] && [cli_is_match $ntp 0 "" "type" 1 "custom"] } {
		cli_set_errmsg "ntpserver only available when type is custom"
		return 0
	}
}
return 1
        %}

        "firewall profile-protocol-options {http https ftp ftps imap imaps pop3 pop3s smtp smtps nntp}" = %{
namespace import global::profile_protocol_options_ports_valid
return [profile_protocol_options_ports_valid 0]
        %}
        "firewall profile-protocol-options {mapi dns}" = %{
namespace import global::profile_protocol_options_ports_valid
return [profile_protocol_options_ports_valid 1]
        %}
        "firewall {deep-inspection-options ssl-ssh-profile} {ssh https ftps imaps pop3s smtps}" = %{
if { [cli_ver_start 600 2] } {
	if { [string match "*preload*" [cli_get_clisrc]] } {
		return 1
	}
}
namespace import global::deep_inspection_ports_valid
return [deep_inspection_ports_valid]
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
	"wireless-controller wtp {wtp-profile vaps}" = %{
### need check wtp-profile used ssid vdom conflict
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wtp-profile"]
set ret [cli_check_wtp_profile $CLI_CUR_PARENT_NODE $name]
if {$ret != 0} {
	set wtp_id [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wtp-id"]
	cli_set_errmsg "The wtp-profile, $name, used ssid's vdom in conflict with wtp $wtp_id's vdom"
	return 0
}
if { $CLI_CUR_NODE_NAME eq "wtp-profile" && ![cli_ver_start 600 4] } {
	set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wtp-mode"]
	namespace import global::wireless_controller_wtp_mode_valid
	return [wireless_controller_wtp_mode_valid $mode $name]
}
return 1
	%}
	"wireless-controller wtp wtp-mode" = %{
set mode [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $mode eq "remote" && ![cli_ver_start 600 4] } {
	set prof_name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wtp-profile"]
	namespace import global::wireless_controller_wtp_mode_valid
	return [wireless_controller_wtp_mode_valid $mode $prof_name]
}
return 1
	%}
	"wireless-controller wtp-profile {radio-1 radio-2}" = %{
set prof [cli_get_parent $CLI_CUR_NODE]
set name [cli_get_value $prof "" "" "name"]
set ret [cli_check_wtp_profile $prof $name]
if {$ret != 0} {
	cli_set_errmsg "The wtp-profile, $name, $CLI_CUR_NODE_NAME used ssid's vdom in conflict with wtp's vdom"
	return 0
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
	"wireless-controller vap passphrase" = %{
set pass [cli_get_value $CLI_CUR_NODE "" "" ""]
if { [string compare -length 4 $pass "ENC "] != 0 } {
        regsub -all {(\\)+([\'\"\\])} $pass { } pass
        set len [string length $pass]
	if { $len == 64 } {
		set res [string is xdigit $pass]
		if { $res != 1 } {
			cli_set_errmsg "The passphrase must be 8 to 63 characters long or 64 hexadecimal digits"
			return 0
		}
	} elseif { $len < 8 || $len > 63 } {
                cli_set_errmsg "The passphrase must be 8 to 63 characters long or 64 hexadecimal digits"
                return 0
        }    
}
return 1
        %}
	"wireless-controller vap split-tunneling" = %{
if { [cli_ver_start 500 2] } {
	if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "enable" } {
		if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "local-bridging"] eq "enable" } {
			set vapname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
			cli_set_errmsg "SSID $vapname : split-tunneling can not be enabled due to local-bridging enabled "
			return 0
		} elseif { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mesh-backhaul"] eq "enable" } {
			set vapname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
			cli_set_errmsg "SSID $vapname : split-tunneling can not be enabled due to mesh-backhaul enabled "
			return 0
		}
	}
}
return 1
        %}

        "firewall policy46" = %{
if { [cli_is_match $CLI_CUR_NODE 0 "" "ippool" 0 "enable"] } {
    set poolname [cli_get_value $CLI_CUR_NODE "" "" "poolname"]
    if { $poolname eq "" } {
        cli_set_errmsg "IP pool name cannot be empty"
        return 0
    }
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

		"firewall policy64" = %{
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
set ippool [cli_get_value $CLI_CUR_NODE "" "" "ippool"]
if { $action eq "accept" && $ippool eq "enable" } {
	set poolname [cli_get_value $CLI_CUR_NODE "" "" "poolname"]
	if { $poolname eq "" } {
		cli_set_errmsg "IP pool name cannot be empty"
		return 0
	}
}
return 1
%}

        "firewall policy64 dstaddr" = %{
namespace import global::addr_iprange_or_ipmask			
set addrs [cli_get_value $CLI_CUR_NODE "" "" ""]
set hasvip 0
set hasaddr 0
if { [string length $addrs] == 0 } {
	cli_set_errmsg "dstaddr for policy46 or policy 64 cannot be empty"
	return 0
}
foreach addr $addrs {
	set vip [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip64" $addr ""]
	set vipgrp [cli_get_node $CLI_CUR_VDOM_NODE "firewall vipgrp64" $addr ""]
	set dynvip [cli_get_node $CLI_CUR_VDOM_NODE "dynamic vip" $addr ""]
	if { ($vip != 0) || ($vipgrp != 0) || ($dynvip != 0) } {
		set hasvip 1
	}
	set fwaddr [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $addr ""]
	set addrgrp [cli_get_node $CLI_CUR_VDOM_NODE "firewall addrgrp" $addr ""]
	set dynaddr [cli_get_node $CLI_CUR_VDOM_NODE "dynamic address" $addr ""]
	if { ($fwaddr != 0) || ($addrgrp != 0) || ($dynaddr != 0) } {
		set hasaddr 1
	}

        if { [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip64" $addr ""] ||
             [cli_get_node $CLI_CUR_VDOM_NODE "firewall vipgrp64" $addr ""] } {
                continue
        }
        if { ![addr_iprange_or_ipmask $addr ""] } {
                return 0
        }
}
### dst-addr can not mix addr/addrgrp and vip/vipgrp
if { $hasaddr == 1 && $hasvip == 1 } {
    cli_set_errmsg "interface binding contradiction"
    return 0
}

return 1
        %}
	"firewall policy auto-asic-offload" = %{
set offload [cli_get_value $CLI_CUR_NODE "" "" ""]
set measurement [cli_get_value $CLI_CUR_PARENT_NODE "" "" "passive-wan-health-measurement"]
if { $measurement eq "enable" && $offload eq "enable" } {
	cli_set_errmsg "Firewall policy auto-asic-offload cannot be enabled when passive-wan-health-measurement is enabled"
	return 0
}

return 1
	%}
        "firewall {interface-policy DoS-policy DoS-policy6}" = %{
set policyid [cli_get_value $CLI_CUR_NODE "" "" "policyid"]
set pkg_name [cli_get_value $CLI_CUR_PKG_NODE "" "" ""]
set intf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
if { $intf eq "" } {
        cli_set_errmsg "Attribute 'interface' of $CLI_CUR_NODE_NAME '$policyid' in Package '$pkg_name' MUST be set."
        return 0
}
if { $intf eq "any" || $intf eq "\"any\"" } {
        cli_set_errmsg "Attribute 'interface' of $CLI_CUR_NODE_NAME '$policyid' in Package '$pkg_name' cannot be set to 'any'."
        return 0
}

if { [cli_ver_start 600 2] } {
	set srcaddr [cli_get_value $CLI_CUR_NODE "" "" "srcaddr"]
	set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
	set service [cli_get_value $CLI_CUR_NODE "" "" "service"]
	if { $srcaddr eq "" || $dstaddr eq "" } {
		cli_set_errmsg "Attribute 'srcaddr' or 'dstaddr' of $CLI_CUR_NODE_NAME '$policyid' in Package '$pkg_name' MUST be set."
		return 0
	}
	if { $service eq "" } {
		cli_set_errmsg "Attribute 'service' of $CLI_CUR_NODE_NAME '$policyid' in Package '$pkg_name' MUST be set."
		return 0
	}
}

return 1
        %}
		"firewall {interface-policy6}" = %{
set policyid [cli_get_value $CLI_CUR_NODE "" "" "policyid"]
set pkg_name [cli_get_value $CLI_CUR_PKG_NODE "" "" ""]
set intf [cli_get_value $CLI_CUR_NODE "" "" "interface"]
if { $intf eq "" } {
        cli_set_errmsg "Attribute 'interface' of interface-policy6 '$policyid' in Package '$pkg_name' MUST be set."
        return 0
}
if { $intf eq "any" || $intf eq "\"any\"" } {
        cli_set_errmsg "Attribute 'interface' of interface-policy6 '$policyid' in Package '$pkg_name' cannot be set to 'any'."
        return 0
}
if { [cli_ver_start 600 2] } {
	set srcaddr6 [cli_get_value $CLI_CUR_NODE "" "" "srcaddr6"]
	set dstaddr6 [cli_get_value $CLI_CUR_NODE "" "" "dstaddr6"]
	set service6 [cli_get_value $CLI_CUR_NODE "" "" "service6"]
	if { $srcaddr6 eq "" || $dstaddr6 eq "" } {
		cli_set_errmsg "Attribute 'srcaddr6' or 'dstaddr6' of interface-policy6 '$policyid' in Package '$pkg_name' MUST be set."
		return 0
	}
	if { $service6 eq "" } {
		cli_set_errmsg "Attribute 'service6' of interface-policy6 '$policyid' in Package '$pkg_name' MUST be set."
		return 0
	}
}
return 1
        %}
        "firewall profile-group" = %{
set ppo [cli_get_value $CLI_CUR_NODE "" "" "profile-protocol-options"]
if { $ppo eq "" } {
	set avp [cli_get_value $CLI_CUR_NODE "" "" "av-profile"]
	set wfp [cli_get_value $CLI_CUR_NODE "" "" "webfilter-profile"]
	set sfp [cli_get_value $CLI_CUR_NODE "" "" "spamfilter-profile"]
	set dlp [cli_get_value $CLI_CUR_NODE "" "" "dlp-sensor"]
	if { [cli_ver_start 500 2] } {
		set icp [cli_get_value $CLI_CUR_NODE "" "" "icap-profile"]
		if { ($avp ne "") || ($wfp ne "") || ($sfp ne "") || ($dlp ne "") || ($icp ne "") } {
		        cli_set_errmsg "Attribute 'profile-protocol-options' MUST be set."
		        return 0
		}
	} else {
		if { ($avp ne "") || ($wfp ne "") || ($sfp ne "") || ($dlp ne "") } {
			cli_set_errmsg "Attribute 'profile-protocol-options' MUST be set."
			return 0
		}
	}
}
return 1
        %}
        "firewall {DoS-policy DoS-policy6} anomaly log" = %{
if { [cli_ver_start 500 2] } {
        if { [cli_get_value $CLI_CUR_NODE "" "" ""] ne "enable" } {
                set status [cli_get_value $CLI_CUR_PARENT_NODE "" "" "status"]
                set cp_status [cli_get_value $CLI_CUR_VDOM_NODE "client-reputation profile" "" "status"]
                if { $status eq "enable" && $cp_status eq "enable" } {
                        cli_set_errmsg "The value of log must be \"enable\" when client-reputation enabled."
                        return 0
                }
        }
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
	"vpn ssl web portal host-check-interval" = %{
set hci [cli_get_value $CLI_CUR_NODE "" "" ""]
set hci [string trim $hci \"]
if { $hci == 0 || (120 <= $hci && $hci <= 259200) } {
        return 1
}
cli_set_errmsg "The interval range is 0,120~259200 seconds(max 72 hours), 0 for disabled"
return 0
        %}
	"dynamic interface" = %{
set intf_name [cli_get_value $CLI_CUR_NODE "" "" ""]
set prefix "vpnmgr_"
if { [string first $prefix $intf_name] == 0 && ![string match "*upgrade*" [cli_get_clisrc]] } {
	cli_set_errmsg "\"vpnmgr_\" prefix is reserved and cannot be used"
	return 0
}
return 1
	%}
	"cloud service template cst-vdom cst-vdom-gintf" = %{
set intf_name [cli_get_value $CLI_CUR_NODE "" "" ""]
set dintf_name [cli_get_value $CLI_CUR_NODE "" "" "dyn_name"]
set node [cli_get_node $CLI_CUR_VDOM_NODE "dynamic interface" $dintf_name ""]
if {$node != 0} {
	set defmap [cli_get_value $node "" "" "default-mapping"]
	set defmap [string trim $defmap \"]
	if { $defmap eq "disable" } {
		cli_set_errmsg "dynamic intf defmap must be enable for cst usage."
		return 0
	} else {
		set defintf [cli_get_value $node "" "" "defmap-intf"]
		set defintf [string trim $defintf \"]
		set intf_name [string trim $intf_name \"]
		if { $defintf ne $intf_name } {
			cli_set_errmsg "dynamic intf defintf must be the same as cst-vdom-gintf."
			return 0
		}
	}
} else {
	cli_set_errmsg "dynamic intf has not been found."
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
	"firewall gtp noip-policy" = %{
set start_protocol [cli_get_value $CLI_CUR_NODE "" "" "start"]
set end_protocol [cli_get_value $CLI_CUR_NODE "" "" "end"]
if { $start_protocol > $end_protocol } {
	cli_set_errmsg "start must not be greater than end"
	return 0
}
return 1
	%}
        "firewall gtp interface-notify" = %{
# set name [cli_get_value $CLI_CUR_NODE "" "" ""]
# set node [cli_get_node $CLI_CUR_VDOM_NODE "dynamic interface" $name ""]
# if {$node != 0} {
#         set single_intf [cli_get_value $node "" "" "single-intf"]
#         if { $single_intf eq "disable" } {
#                 cli_set_errmsg "zone is not allowed for GTP interface-notify"
#                 return 0
#         }
# }
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
	"firewall service custom" = %{
set ntcp [llength [cli_get_value $CLI_CUR_NODE "" "" "tcp-portrange"]]
set nudp [llength [cli_get_value $CLI_CUR_NODE "" "" "udp-portrange"]]
set nsctp [llength [cli_get_value $CLI_CUR_NODE "" "" "sctp-portrange"]]
if { $ntcp + $nudp + $nsctp > 16 } {
	cli_set_errmsg "TCP/UDP/SCTP port ranges over 16 limit, current numbers are: $ntcp/$nudp/$nsctp"
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
if {[cli_ver_start 500 0] && $CLI_ACT ne "add"} {
	set ntype [cli_get_value $CLI_CUR_NODE "" "" "explicit-proxy"]
	set otype [cli_get_org_value $CLI_CUR_NODE "" "" "explicit-proxy"]
	if {[string compare $ntype $otype]} {
		cli_set_errmsg "Cannot change whether this service group is used for explicit proxy, once the group is created"
		return 0
	}
}
set members [cli_get_value $CLI_CUR_NODE "" "" "member"] 
if { $members eq "" } {
        cli_set_errmsg "empty member is not allowed"
        return 0
}
return 1
	%}

	"system zone" = %{
		cli_set_errmsg "System zone is not supported in adom DB. Please look at dynamic interface syntax"
		return 0
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
        "firewall address type" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $type eq "url" } {
        namespace import global::nCfg_is_addr_used_except_explicit_policy
        if { [nCfg_is_addr_used_except_explicit_policy $CLI_CUR_PARENT_NODE] } {
                cli_set_errmsg "Can not be url address when it were used"
                return 0
        }
}
if { $CLI_ACT ne "add" && $type ne "ipmask" } {
	set org_type [cli_get_org_value $CLI_CUR_NODE "" "" ""]
	if { $org_type ne $type } {
		if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "allow-routing"] eq "enable" } {
			cli_set_errmsg "cannot change the type if it is enabled for routing"
			return 0
		}
	}
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
        "system geoip-override country-id" = %{
if { ![cli_branchpt_start 500 674] } { return 1 }
if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "" } { return 1 }
if { ![string match "*override*" [cli_get_clisrc]] } {
        cli_set_errmsg "Geoip override country-id is generated automatically and can not be set or unset manually."
        return 0
}
return 1
        %}
        "wireless-controller wtp-profile {radio-1 radio-2 radio-3} {auto-power-low auto-power-high}" = %{
if { ![cli_ver_start 500 4] } { return 1 }
if { $CLI_CUR_PARENT_NAME eq "radio-1" } {
        set radio "1"
} elseif { $CLI_CUR_PARENT_NAME eq "radio-2" } {
        set radio "2"
} elseif { $CLI_CUR_PARENT_NAME eq "radio-3" } {
        set radio "3"
} else {
        return 0
}
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
set band [cli_get_value $CLI_CUR_PARENT_NODE "" "" "band"]
set platform [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "platform" "" "type"]
if { $band ne "" && $platform ne "" } {
        set max [cli_get_devinfo "wl_radio_maxpower" $radio $platform $band]
        if { $max > 0 && ($value < 1 || $value > $max) } {
                cli_set_errmsg "value range from 1 to $max"
                return 0
        }
}
return 1
        %}
        "wireless-controller wtp-profile {radio-1 radio-2 radio-3} channel" = %{
namespace import global::channel_is_invalid
set cs [cli_get_value $CLI_CUR_NODE "" "" ""]
set band [cli_get_value $CLI_CUR_PARENT_NODE "" "" "band"]
set bond [cli_get_value $CLI_CUR_PARENT_NODE "" "" "channel-bonding"]
set cnty [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "ap-country"]
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if { $mode ne "ap" } {
	return 1
}
set plat [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "platform" "" "type"]
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
	if { $plat eq "FWF" && ![string match "*upgrade*" [cli_get_clisrc]] } {
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

        "antivirus profile" = %{
if { [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
	namespace import global::DEFAULT_SNIFFER_PROFILE
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	if { $name eq [DEFAULT_SNIFFER_PROFILE]} {
		set mode [cli_get_value $CLI_CUR_NODE "" "" "inspection-mode"]
		if { $mode ne "flow-based" } {
			cli_set_errmsg "Inspection mode should be flow-based for default sniffer profile."
			return 0
		}
	}
} elseif { [cli_ver_start 600 2] } {
	set scan_mode [cli_get_value $CLI_CUR_NODE "" "" "scan-mode"]
	if { $scan_mode eq "quick" } {
		set httpopt [cli_get_value $CLI_CUR_NODE "http" "" "options"]
		set ftpopt [cli_get_value $CLI_CUR_NODE "ftp" "" "options"]
		set pop3opt [cli_get_value $CLI_CUR_NODE "pop3" "" "options"]
		set smtpopt [cli_get_value $CLI_CUR_NODE "smtp" "" "options"]
		set cifsopt [cli_get_value $CLI_CUR_NODE "cifs" "" "options"]
		if { $httpopt eq "quarantine" || $httpopt eq "avquery" ||
			$ftpopt eq "quarantine" || $ftpopt eq "avquery" ||
			$pop3opt eq "quarantine" || $pop3opt eq "avquery" ||
			$smtpopt eq "quarantine" || $smtpopt eq "avquery" ||
			$cifsopt eq "quarantine" || $cifsopt eq "avquery" } {
			cli_set_errmsg "WARNING: Quarantine option is not supported in quick mode!"
			return 0
		}
	}
	return 1
}
return 1
        %}
        "webfilter profile" = %{
if { [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
	namespace import global::DEFAULT_SNIFFER_PROFILE
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	if { $name eq [DEFAULT_SNIFFER_PROFILE]} {
		set mode [cli_get_value $CLI_CUR_NODE "" "" "inspection-mode"]
		if { $mode ne "flow-based" } {
			cli_set_errmsg "Inspection mode should be flow-based for default sniffer profile."
			return 0
		}
	}
}
return 1
        %}
        "dlp sensor" = %{
if { [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
	namespace import global::DEFAULT_SNIFFER_PROFILE
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	if { $name eq [DEFAULT_SNIFFER_PROFILE] } {
		set flow [cli_get_value $CLI_CUR_NODE "" "" "flow-based"]
		if { $flow ne "enable" } {
			cli_set_errmsg "Flow-based should be enabled for default sniffer profile."
			return 0
		}
	}
}
return 1
        %}
        "spamfilter profile" = %{
if { [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
	namespace import global::DEFAULT_SNIFFER_PROFILE
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	if { $name eq [DEFAULT_SNIFFER_PROFILE] } {
		set flow [cli_get_value $CLI_CUR_NODE "" "" "flow-based"]
		if { $flow ne "enable" } {
			cli_set_errmsg "Flow-based should be enabled for default sniffer profile."
			return 0
		}
	}
}
return 1
        %}
	"firewall local-in-policy" = %{
namespace import global::ln_policy_intf_binding_contradiction
set srcaddr [cli_get_value $CLI_CUR_NODE "" "" "srcaddr" 1]
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr" 1]
set schedule [cli_get_value $CLI_CUR_NODE "" "" "schedule"]
set intf [cli_get_value $CLI_CUR_NODE "" "" "intf" 1]
set service [cli_get_value $CLI_CUR_NODE "" "" "service"]
set policyid [cli_get_value $CLI_CUR_NODE "" "" "policyid"]
set hamgmt [cli_get_value $CLI_CUR_NODE "" "" "ha-mgmt-intf-only"]

if { $CLI_IS_AUTOUPDATE == 0 } {
	if { $schedule == 0 || $schedule eq "" } {
		cli_set_errmsg "Must set schedule."
		return 0
	}

	if { $srcaddr == 0 || $srcaddr eq "" } {
		cli_set_errmsg "Must set srcaddr."
		return 0
	}

	if { $dstaddr == 0 || $dstaddr eq "" } {
		cli_set_errmsg "Must set dstaddr"
		return 0
	}

	if { $intf == 0 || $intf eq "" } {
		cli_set_errmsg "Must set intf"
		return 0
	}

	if { $service == 0 || $service eq "" } {
		cli_set_errmsg "Must set service"
		return 0
	}
}

set msg [ln_policy_intf_binding_contradiction $srcaddr $intf $policyid 0]
if { $msg ne 0 } {
	cli_set_errmsg $msg
	return 0
}
set msg [ln_policy_intf_binding_contradiction $dstaddr $intf $policyid 1]
if { $msg ne 0 } {
	cli_set_errmsg $msg
	return 0
}
return 1
	%}
	"firewall local-in-policy6" = %{
set srcaddr [cli_get_value $CLI_CUR_NODE "" "" "srcaddr"]
set dstaddr [cli_get_value $CLI_CUR_NODE "" "" "dstaddr"]
set schedule [cli_get_value $CLI_CUR_NODE "" "" "schedule"]
set intf [cli_get_value $CLI_CUR_NODE "" "" "intf"]
set service [cli_get_value $CLI_CUR_NODE "" "" "service"]

if { $CLI_IS_AUTOUPDATE == 0 } {
	if { $schedule == 0 || $schedule eq "" } {
		cli_set_errmsg "Must set schedule."
		return 0
	}

	if { $srcaddr == 0 || $srcaddr eq "" } {
		cli_set_errmsg "Must set srcaddr."
		return 0
	}

	if { $dstaddr == 0 || $dstaddr eq "" } {
		cli_set_errmsg "Must set dstaddr"
		return 0
	}

	if { $intf == 0 || $intf eq "" } {
		cli_set_errmsg "Must set intf"
		return 0
	}

	if { $service == 0 || $service eq "" } {
		cli_set_errmsg "Must set service"
		return 0
	}
}
return 1
	%}
	"firewall consolidated policy {diffservcode-forward diffservcode-rev}" = %{
set servcode [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
if { $servcode ne "" } {
	if {[regexp {^[01]{6}$} $servcode] == 0} {
        	cli_set_errmsg "must be 6 bits binary, range 000000-111111"
		return 0
	}
}
return 1
	%}
	"firewall consolidated policy" = %{
set srcaddr4 [cli_get_value $CLI_CUR_NODE "" "" "srcaddr4"]
set srcaddr6 [cli_get_value $CLI_CUR_NODE "" "" "srcaddr6"]
set dstaddr4 [cli_get_value $CLI_CUR_NODE "" "" "dstaddr4"]
set dstaddr6 [cli_get_value $CLI_CUR_NODE "" "" "dstaddr6"]
set schedule [cli_get_value $CLI_CUR_NODE "" "" "schedule"]
set srcintf [cli_get_value $CLI_CUR_NODE "" "" "srcintf" 1]
set dstintf [cli_get_value $CLI_CUR_NODE "" "" "dstintf" 1]
set service [cli_get_value $CLI_CUR_NODE "" "" "service"]
set policyid [cli_get_value $CLI_CUR_NODE "" "" "policyid"]
set internetservice [cli_get_value $CLI_CUR_NODE "" "" "internet-service"]
set internetservicesrc [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src"]

if { $CLI_IS_AUTOUPDATE == 0 } {
	if { ($internetservicesrc eq "disable") && ($srcaddr4 == 0 || $srcaddr4 eq "") && ($srcaddr6 == 0 || $srcaddr6 eq "") } {
		cli_set_errmsg "Must set srcaddr4 or srcaddr6."
		return 0
	}

	if { ($internetservice eq "disable") && ($dstaddr4 == 0 || $dstaddr4 eq "") && ($dstaddr6 == 0 || $dstaddr6 eq "") } {
		cli_set_errmsg "Must set dstaddr4 or dstaddr6"
		return 0
	}

	if { $srcintf == 0 || $srcintf eq "" } {
		cli_set_errmsg "Must set srcintf"
		return 0
	}

	if { $dstintf == 0 || $dstintf eq "" } {
		cli_set_errmsg "Must set dstintf"
		return 0
	}

	if { ($internetservice eq "disable") && ($service == 0 || $service eq "") } {
		cli_set_errmsg "Must set service"
		return 0
	}
}
return 1
	%}
        "wireless-controller wtp-profile ap-country" = %{
if {$CLI_ACT ne "add"} {
        set new [cli_get_value $CLI_CUR_NODE "" "" ""]
        set old [cli_get_org_value $CLI_CUR_NODE "" "" ""]
        if { $new ne $old } {
                namespace import global::ncfg_is_cw_wtpprof_used
                set  prfname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
                if { [ncfg_is_cw_wtpprof_used $prfname] } {
                        cli_set_errmsg "The ap-country can not be changed, for WTP Profile $prfname has been used!"
                        return 0
                }
        }
}
return 1
	%}
        "endpoint-control profile forticlient-winmac-settings" = %{
if { [cli_ver_start 500 4] } {
	if { [cli_get_value $CLI_CUR_NODE "" "" "forticlient-system-compliance"] eq "enable" &&
	     [cli_get_value $CLI_CUR_NODE "" "" "os-av-software-installed"] eq "enable" &&
	     [cli_get_value $CLI_CUR_NODE "" "" "av-realtime-protection"] eq "enable" } {
		cli_set_errmsg "Please disable 'os-av-software-installed' first"
		return 0
	}
	if { [cli_get_value $CLI_CUR_NODE "" "" "forticlient-application-firewall"] eq "enable" &&
	     [cli_get_value $CLI_CUR_NODE "" "" "forticlient-application-firewall-list"] eq "" } {
		cli_set_errmsg "Please set the FortiClient application firewall rule list"
		return 0
	}
}
return 1
        %}
        "endpoint-control profile" = %{
if { [cli_ver_start 500 4] } {
	if { [cli_get_value $CLI_CUR_NODE "" "" "device-groups"] eq "" &&
	     [cli_get_value $CLI_CUR_NODE "" "" "profile-name"] ne "default" } {
		cli_set_errmsg "Device groups can not be empty!"
		return 0
	}
}
return 1
        %}
	"fsp managed-switch name" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set name [string trim $name \"]
if {[regexp {[^0-9a-zA-Z\-_]} $name]} {
	cli_set_errmsg "Invalid switch name - the legal characters are numbers (0-9), letters(a-z,A-z) and special characters - and _"
	return 0
}
	%}
	"switch-controller fortilink-settings" = %{
set vlan [cli_get_value $CLI_CUR_NODE "nac-ports" "" "onboarding-vlan"]
if { $vlan eq "" } {
	cli_set_errmsg "onboarding-vlan must be set"
	return 0
}
return 1
	%}
	"switch-controller managed-switch ports" = %{
if { [string match "*upgrade*" [cli_get_clisrc]] } {
	## skip during migration, as we cannot predict the order of the data
	return 1
}
set name [cli_get_value $CLI_CUR_NODE "" "" "port-name"]
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set owner ""
if { $type ne "trunk" } {
	set owner [cli_get_value $CLI_CUR_NODE "" "" "port-owner" 1]
}
if { $owner eq 0 || $owner eq "" } {
	set vlan_all [cli_get_value $CLI_CUR_NODE "" "" "allowed-vlans-all"]
	set native [cli_get_value $CLI_CUR_NODE "" "" "vlan"]
	set native [string trim $native \"]
	if { [cli_ver_start 600 4] } {
		set mode [cli_get_value $CLI_CUR_NODE "" "" "access-mode"]
	} else {
		set mode "normal"
	}
	if { $mode eq "normal" && ($native eq 0 || $native eq "") } {
		cli_set_errmsg "native vlan must be set"
		return 0
	}
	if { $native eq "default.qtnport" } {
		cli_set_errmsg "default quarantine VLAN not supported for native vlan"
		return 0
	}
	if { $vlan_all eq "disable" && ![cli_ver_start 600 2] } {
		set vlan [cli_get_value $CLI_CUR_NODE "" "" "allowed-vlans"]
		foreach v $vlan {
			if { $v eq $native } {
				cli_set_errmsg "cannot use $v as both native and allowed vlans"
				return 0
			}
			if {![cli_ver_start 500 6] && $v eq "default.qtnport"} {
				cli_set_errmsg "default quarantine VLAN not supported for this version"
				return 0
			}
		}
	}
}
cli_schedule_post_check $CLI_CUR_PARENT_NODE "edit"
return 1
	%}
	"switch-controller managed-switch ports untagged-vlans" = %{
set untags [cli_get_value $CLI_CUR_NODE "" "" ""]
set vlan [string trim [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vlan"] \"]
set port [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-name"]
foreach untag $untags {
	set untag [string trim $untag \"]
	if { $untag eq $vlan } {
		cli_set_errmsg "vlan $untag can not be both untagged-vlans and native vlan for $port"
		return 0
	}
}
return 1
	%}
	"switch-controller managed-switch ports {allowed-vlans-all}" = %{
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "access-mode"]
set omode [cli_get_org_value $CLI_CUR_PARENT_NODE "" "" "access-mode"]
if { $mode eq "nac" && $omode eq "nac" } {
	set val [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
	set oval [string trim [cli_get_org_value $CLI_CUR_NODE "" "" ""] \"]
	if { $val ne $oval} {
		cli_set_errmsg "cannot be changed when port is in nac-mode"
		return 0
	}
}
return 1
	%}
	"switch-controller managed-switch ports {lldp-profile qos-policy port-security-policy}" = %{
if { [cli_ver_start 700 0] } {
	return 1
}
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "access-mode"]
set omode [cli_get_org_value $CLI_CUR_PARENT_NODE "" "" "access-mode"]
if { $mode eq "nac" && $omode eq "nac" } {
	set val [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
	set oval [string trim [cli_get_org_value $CLI_CUR_NODE "" "" ""] \"]
	if { $val ne $oval} {
		cli_set_errmsg "cannot be changed when port is in nac-mode"
		return 0
	}
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
	"fsp vlan" = %{
set vlanid [cli_get_value $CLI_CUR_NODE "" "" "vlanid"]
if { ($vlanid < 1 || $vlanid > 4094) } {
	cli_set_errmsg "vlanid must be between 1 and 4094"
	return 0
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

		"log threat-weight application" = %{
	set cur_cat [cli_get_value $CLI_CUR_NODE "" "" "category"]
	set cur_id [cli_get_value $CLI_CUR_NODE "" "" "id"]
	set apps [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
	foreach app $apps {
		set cat [cli_get_value $app "" "" "category"]
		set id [cli_get_value $app "" "" "id"]
		if { $cur_id != $id && $cur_cat == $cat } {
			if { [string match "*postcheck*" [cli_get_clisrc]] } { 
				cli_set_errmsg "Duplicated category $cur_cat in threat-weight application"
				return 0
			} else {
				cli_schedule_post_check $CLI_CUR_NODE "edit"
			}
		}
	}
	return 1
%}
        "wireless-controller vap security" = %{
set sec [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $sec eq "wep64" || $sec eq "wep128" || $sec eq "wpa-only-enterprise" || $sec eq "wpa-only-personal" || $sec eq "wpa-only-personal+captive-portal"} {
	if { !([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-obsolete-option" 0 "enable"]) } {
		cli_set_errmsg "security option $sec is not avaliable when security-obsolete-option is disable"
		return 0
	}
}
return 1
        %}
        "wireless-controller vap security-obsolete-option" = %{
set sec [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"]
if { $sec eq "wep64" || $sec eq "wep128" || $sec eq "wpa-only-enterprise" || $sec eq "wpa-only-personal" || $sec eq "wpa-only-personal+captive-portal"} {
        if { !([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-obsolete-option" 0 "enable"]) } {
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
	"firewall profile-group ssl-ssh-profile" = %{
set sslprof [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $sslprof eq "" } {
	cli_set_errmsg "ssl-ssh-profile cannot be empty"
	return 0
}
return 1
	%}
	"user fsso-polling" = %{
if { $CLI_ACT eq "edit" } {
	set ldsvr [string trim [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"] \"]
	set oldsvr [string trim [cli_get_org_value $CLI_CUR_NODE "" "" "ldap-server"] \"]
	if { $oldsvr ne "" && $ldsvr ne $oldsvr } {
		cli_set_errmsg "Modifying ldap-server is not allowed."
		return 0
	}
}
return 1
	%}
	"firewall mms-profile {carrier-endpoint-prefix carrier-endpoint-prefix-string carrier-endpoint-prefix-range-min carrier-endpoint-prefix-range-max}" = %{
set pfxen [cli_get_value $CLI_CUR_PARENT_NODE "" "" "carrier-endpoint-prefix"]
set pfxstr [cli_get_value $CLI_CUR_PARENT_NODE "" "" "carrier-endpoint-prefix-string"]
set pfxmax [cli_get_value $CLI_CUR_PARENT_NODE "" "" "carrier-endpoint-prefix-range-max"]
set pfxmin [cli_get_value $CLI_CUR_PARENT_NODE "" "" "carrier-endpoint-prefix-range-min"]
if { $pfxen eq "enable" } {
	if { $pfxstr eq "" } {
		cli_set_errmsg "carrier-endpoint-prefix-string cannot be empty"
		return 0
	}
	if { $pfxmax < 1 || $pfxmax > 48 } {
		cli_set_errmsg "carrier-endpoint-prefix-range-max out of range"
		return 0
	}
	if { $pfxmin < 1 || $pfxmin > 48 } {
		cli_set_errmsg "carrier-endpoint-prefix-range-min out of range"
		return 0
	}
	if { $pfxmin >= $pfxmax } {
		cli_set_errmsg "carrier-endpoint-prefix-range-min should be less than carrier-endpoint-prefix-range-max"
		return 0
	}
}
return 1
	%}
	"firewall mms-profile {flood dupe} {status2 window2 limit2 status3 window3 limit3}" = %{
set window1 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "window1"]
set limit1 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "limit1"]
set status2 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "status2"]
set window2 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "window2"]
set limit2 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "limit2"]
set status3 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "status3"]
set window3 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "window3"]
set limit3 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "limit3"]
if { $status2 eq "enable" } {
	if { $window1 > $window2 || $limit1 >= $limit2 } {
		cli_set_errmsg "Duplicate threshold 1's message window/limit should less than duplicate threshold 2's"
		return 0
	}
}
if { $status3 eq "enable" } {
	if { $window2 > $window3 || $limit2 >= $limit3 } {
		cli_set_errmsg "Duplicate threshold 2's message window/limit should less than duplicate threshold 3's"
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
	"system {virtual-wan-link swdan} health-check name" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set dash [string first "-" $name 0]
if { $dash >= 0 } {
	cli_set_errmsg "Invalid health-check name $name."
	return 0;
}
return 1
	%}
	"system virtual-wan-link service" = %{
## for adom version <= 6.2
set nm [cli_get_value $CLI_CUR_NODE "" "" "name"]
for {set i 0} {$i < [string length $nm]} {incr i} {
	set char [string index $nm $i]
	if {![regexp {[ -~]} $char] || [regexp {[<>\"\'\(\)#\\\s]} $char]} {
		cli_set_errmsg "invalid character in name : $nm"
		return 0
	}
}

set proto [cli_get_value $CLI_CUR_NODE "" "" "protocol"]
if { $proto eq 6 || $proto eq 17 || $proto eq 132 } {
	set spt [cli_get_value $CLI_CUR_NODE "" "" "start-port"]
	set ept [cli_get_value $CLI_CUR_NODE "" "" "end-port"]
	if { $spt > $ept } {
		cli_set_errmsg "Start port should not be larger than end port"
		return 0
	}
}
set mode [cli_get_value $CLI_CUR_NODE "" "" "mode"]
if { ![cli_ver_start 600 2] && $mode eq "manual" } {
	set m [cli_get_value $CLI_CUR_NODE "" "" "member"]
	set m [string trim $m \"]
	if { $m eq 0 || $m eq "" } {
		cli_set_errmsg "Please assign a member"
		return 0
	}
}
if { $mode eq "auto" } {
	set q [cli_get_value $CLI_CUR_NODE "" "" "quality-link"]
	if { $q eq 0 || $q eq "" } {
		cli_set_errmsg "Please assign a quality-link"
		return 0
	}
}
if { $mode eq "auto" || $mode eq "priority" } {
	set h [cli_get_value $CLI_CUR_NODE "" "" "health-check"]
	set h [string trim $h \"]
	if { $h eq "" } {
		cli_set_errmsg "Please select a health-check"
		return 0
	}
}
if { ([cli_ver_start 600 2] && $mode eq "manual") || $mode eq "priority" || $mode eq "sla" || $mode eq "load-balance" } {
	set pm [cli_get_value $CLI_CUR_NODE "" "" "priority-members"]
	if { $pm eq "" } {
		cli_set_errmsg "Please assign priority-member(s)"
		return 0
	}
}
if { $mode eq "sla" && ![cli_ver_start 600 2] } {
	if { ![string match "*import*" [cli_get_clisrc]] } {
		## do not check this for import because the child table haven't created yet
		set sla [cli_get_tbl_cnt $CLI_CUR_NODE "sla"]
		if { $sla eq 0 } {
			cli_set_errmsg "Please add SLA"
			return 0
		}
	}
}
if { [cli_ver_start 600 0] } {
	set is [cli_get_value $CLI_CUR_NODE "" "" "internet-service"]
	if { [cli_ver_start 600 4] } {
		set isi [cli_get_value $CLI_CUR_NODE "" "" "internet-service-name"]
	} else {
		set isi [cli_get_value $CLI_CUR_NODE "" "" "internet-service-id"]
	}
	set isg [cli_get_value $CLI_CUR_NODE "" "" "internet-service-group"]
	set isc [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom"]
	set iscg [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom-group"]
	if { [cli_ver_start 600 2] } {
		set isct [cli_get_value $CLI_CUR_NODE "" "" "internet-service-app-ctrl"]
		set isctg [cli_get_value $CLI_CUR_NODE "" "" "internet-service-app-ctrl-group"]
	} else {
		set isct [cli_get_value $CLI_CUR_NODE "" "" "internet-service-ctrl"]
		set isctg [cli_get_value $CLI_CUR_NODE "" "" "internet-service-ctrl-group"]
	}
	set am [cli_get_value $CLI_CUR_NODE "" "" "addr-mode"]
	set dst [cli_get_value $CLI_CUR_NODE "" "" "dst"]
	set dst6 [cli_get_value $CLI_CUR_NODE "" "" "dst6"]
	set rtag [cli_get_value $CLI_CUR_NODE "" "" "route-tag"]
	if { ($is eq "enable") && ($isi eq "") && ($isg eq "") && ($isc eq "") && ($iscg eq "") && ($isct eq "") && ($isctg eq "") } {
		cli_set_errmsg "Please assign internet service or custom internet service since internet-service is enabled"
		return 0
	}
	if { $is ne "enable" && $rtag eq "0" } {
		if { ($am eq "ipv4" && $dst eq "") || ($am eq "ipv6" && $dst6 eq "") } {
			cli_set_errmsg "Please assign a dst or internet-service"
			return 0
		}
	}
} elseif { [cli_ver_start 500 4] } {
	set is [cli_get_value $CLI_CUR_NODE "" "" "internet-service"]
	set isi [cli_get_value $CLI_CUR_NODE "" "" "internet-service-id"]
	set isc [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom"]
	set dst [cli_get_value $CLI_CUR_NODE "" "" "dst"]
	if { ($is eq "enable") && ($isi eq "") && ($isc eq "") } {
		cli_set_errmsg "Please assign internet service or custom internet service since internet-service is enabled"
		return 0
	}
	if { ($is ne "enable") && ($dst eq "") } {
		cli_set_errmsg "Please assign a dst or internet-service"
		return 0
	}
}

cli_schedule_post_check $CLI_CUR_PARENT_NODE $CLI_ACT

return 1
	%}
	"system sdwan service" = %{
## for adom version >= 6.4
set nm [cli_get_value $CLI_CUR_NODE "" "" "name"]
for {set i 0} {$i < [string length $nm]} {incr i} {
	set char [string index $nm $i]
	if {![regexp {[ -~]} $char] || [regexp {[<>\"\'\(\)#\\\s]} $char]} {
		cli_set_errmsg "invalid character in name : $nm"
		return 0
	}
}

set proto [cli_get_value $CLI_CUR_NODE "" "" "protocol"]
if { $proto eq 6 || $proto eq 17 || $proto eq 132 } {
	set spt [cli_get_value $CLI_CUR_NODE "" "" "start-port"]
	set ept [cli_get_value $CLI_CUR_NODE "" "" "end-port"]
	if { $spt > $ept } {
		cli_set_errmsg "Start port should not be larger than end port"
		return 0
	}
}
set mode [cli_get_value $CLI_CUR_NODE "" "" "mode"]
if { $mode eq "auto" } {
	set q [cli_get_value $CLI_CUR_NODE "" "" "quality-link"]
	if { $q eq 0 || $q eq "" } {
		cli_set_errmsg "Please assign a quality-link"
		return 0
	}
}
if { $mode eq "auto" || $mode eq "priority" } {
	set h [cli_get_value $CLI_CUR_NODE "" "" "health-check"]
	set h [string trim $h \"]
	if { $h eq "" } {
		cli_set_errmsg "Please select a health-check"
		return 0
	}
}
if { $mode eq "manual" || $mode eq "priority" || $mode eq "sla" || $mode eq "load-balance" } {
	set pm [cli_get_value $CLI_CUR_NODE "" "" "priority-members"]
	if { [cli_ver_start 700 0] } {
		set pz [cli_get_value $CLI_CUR_NODE "" "" "priority-zone"]
		if { $pm eq "" && $pz eq "" } {
			cli_set_errmsg "Please assign priority-member(s) or priority-zone(s)"
			return 0
		}
	} elseif { $pm eq "" } {
		cli_set_errmsg "Please assign priority-member(s)"
		return 0
	}
}

set is [cli_get_value $CLI_CUR_NODE "" "" "internet-service"]
set isi [cli_get_value $CLI_CUR_NODE "" "" "internet-service-name"]
set isg [cli_get_value $CLI_CUR_NODE "" "" "internet-service-group"]
set isc [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom"]
set iscg [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom-group"]
set isct [cli_get_value $CLI_CUR_NODE "" "" "internet-service-app-ctrl"]
set isctg [cli_get_value $CLI_CUR_NODE "" "" "internet-service-app-ctrl-group"]
set am [cli_get_value $CLI_CUR_NODE "" "" "addr-mode"]
set dst [cli_get_value $CLI_CUR_NODE "" "" "dst"]
set dst6 [cli_get_value $CLI_CUR_NODE "" "" "dst6"]
set rtag [cli_get_value $CLI_CUR_NODE "" "" "route-tag"]
if { ($is eq "enable") && ($isi eq "") && ($isg eq "") && ($isc eq "") && ($iscg eq "") && ($isct eq "") && ($isctg eq "") } {
	if { [cli_ver_start 700 2] } {
		set isctc [cli_get_value $CLI_CUR_NODE "" "" "internet-service-app-ctrl-category"]
		if { $isctc eq "" } {
			cli_set_errmsg "Please assign internet service or custom internet service since internet-service is enabled"
			return 0
		}
	} else {
		cli_set_errmsg "Please assign internet service or custom internet service since internet-service is enabled"
		return 0
	}
}
if { $is ne "enable" && $rtag eq "0" } {
	if { ($am eq "ipv4" && $dst eq "") || ($am eq "ipv6" && $dst6 eq "") } {
		cli_set_errmsg "Please assign a dst or internet-service"
		return 0
	}
}

cli_schedule_post_check $CLI_CUR_PARENT_NODE $CLI_ACT

return 1
	%}
	"system virtual-wan-link health-check" = %{
## for adom version <= 6.2
if { [cli_ver_start 600 2] } {
	set proto [cli_get_value $CLI_CUR_NODE "" "" "protocol"]
	set mode [cli_get_value $CLI_CUR_NODE "" "" "addr-mode"]
	if { $mode eq "ipv4" && $proto eq "ping6" } {
		cli_set_errmsg "ping6 protocol not available in ipv4"
		return 0
	} elseif { $mode eq "ipv6" && $proto eq "ping" } {
		cli_set_errmsg "ping protocol not available in ipv6"
		return 0
	} elseif { $mode eq "ipv6" && $proto eq "tcp-echo" } {
		cli_set_errmsg "tcp-echo protocol not available in ipv6"
		return 0
	} elseif { $mode eq "ipv6" && $proto eq "udp-echo" } {
		cli_set_errmsg "udp-echo protocol not available in ipv6"
		return 0
	} elseif { $mode eq "ipv6" && $proto eq "http" } {
		cli_set_errmsg "http protocol not available in ipv6"
		return 0
	} elseif { $mode eq "ipv6" && $proto eq "twamp" } {
		cli_set_errmsg "twamp protocol not available in ipv6"
		return 0
	}
}
return 1
	%}
	"system sdwan health-check" = %{
## for adom version >= 6.4
set proto [cli_get_value $CLI_CUR_NODE "" "" "protocol"]
set mode [cli_get_value $CLI_CUR_NODE "" "" "addr-mode"]
if { [cli_branchpt_start 600 1684] } {
	if { $mode eq "ipv6" && $proto eq "tcp-echo" } {
		cli_set_errmsg "tcp-echo protocol not available in ipv6"
		return 0
	} elseif { $mode eq "ipv6" && $proto eq "http" } {
		cli_set_errmsg "http protocol not available in ipv6"
		return 0
	} elseif { $mode eq "ipv6" && $proto eq "twamp" } {
		cli_set_errmsg "twamp protocol not available in ipv6"
		return 0
	}
} else {
	if { $mode eq "ipv4" && $proto eq "ping6" } {
		cli_set_errmsg "ping6 protocol not available in ipv4"
		return 0
	} elseif { $mode eq "ipv6" && $proto eq "ping" } {
		cli_set_errmsg "ping protocol not available in ipv6"
		return 0
	} elseif { $mode eq "ipv6" && $proto eq "tcp-echo" } {
		cli_set_errmsg "tcp-echo protocol not available in ipv6"
		return 0
	} elseif { $mode eq "ipv6" && $proto eq "udp-echo" } {
		cli_set_errmsg "udp-echo protocol not available in ipv6"
		return 0
	} elseif { $mode eq "ipv6" && $proto eq "http" } {
		cli_set_errmsg "http protocol not available in ipv6"
		return 0
	} elseif { $mode eq "ipv6" && $proto eq "twamp" } {
		cli_set_errmsg "twamp protocol not available in ipv6"
		return 0
	}
}
return 1
	%}
	"system sdwan neighbor" = %{
cli_schedule_post_check $CLI_CUR_PARENT_NODE $CLI_ACT
return 1
	%}
	"system virtual-wan-link" = %{
## for adom version <= 6.2
if { ![cli_ver_start 500 4] } {
	## currently check not supported for 5.2 or lower
	return 1;
}

set svs [cli_get_tbl_list $CLI_CUR_NODE "service"]
set mbs [cli_get_tbl_list $CLI_CUR_NODE "members"]
set hcs [cli_get_tbl_list $CLI_CUR_NODE "health-check"]
set nbs {}
if { [cli_branchpt_start 600 910] } {
	set nbs [cli_get_tbl_list $CLI_CUR_NODE "neighbor"]
}

foreach sv $svs {
	set mode [cli_get_value $sv "" "" "mode"]
	set name [cli_get_value $sv "" "" "name"]
	set id [cli_get_value $sv "" "" "id"]
	set addrmode [cli_get_value $sv "" "" "addr-mode"]
	if { $name ne "" } {
		foreach sv2 $svs {
			set name2 [cli_get_value $sv2 "" "" "name"]
			if { $name2 eq $name } {
				set id2 [cli_get_value $sv2 "" "" "id"]
				if { $id2 ne $id } {
					cli_set_errmsg "Duplicate service name $name"
					return 0
				}
			}
		}
	}
	if { ![cli_ver_start 600 2] && $mode eq "manual" } {
		set m [cli_get_value $sv "" "" "member"]
		set m [string trim $m \"]
		if { $m eq 0 || $m eq "" } {
			cli_set_errmsg "Please assign a member for service $name"
			return 0
		} else {
			set exist 0
			foreach mb $mbs {
				set n [cli_get_value $mb "" "" "seq-num"]
				if { $n eq $m } {
					set exist 1
					break
				}
			}
			if { $exist eq 0 } {
				cli_set_errmsg "$m is not a valid member seq number for service $name"
				return 0
			}
		}
	} elseif { ([cli_ver_start 600 2] && $mode eq "manual") || $mode eq "priority" || $mode eq "sla" || $mode eq "load-balance" } {
		set pm [cli_get_value $sv "" "" "priority-members"]
		if { $pm eq "" } {
			cli_set_errmsg "Please assign priority-member(s) for service $name"
			return 0
		}
		foreach m $pm {
			set m [string trim $m \"]
			set exist 0
			foreach mb $mbs {
				set n [cli_get_value $mb "" "" "seq-num"]
				if { $n eq $m } {
					set exist 1
					break
				}
			}
			if { $exist eq 0 } {
				cli_set_errmsg "$m is not a valid member seq number for service $name"
				return 0
			}
		}
	}
	if { $mode eq "auto" || $mode eq "priority" } {
		set h [cli_get_value $sv "" "" "health-check"]
		set h [string trim $h \"]
		if { $h eq "" } {
			cli_set_errmsg "Please select a health-check for service $name"
			return 0
		}
		set exist 0
		foreach hc $hcs {
			set n [cli_get_value $hc "" "" "name"]
			if { $n eq $h } {
				set exist 1
				if { [cli_ver_start 600 2] } {
					set hcmode [cli_get_value $hc "" "" "addr-mode"]
					if { $hcmode ne $addrmode } {
						cli_set_errmsg "Invalid health check addr-mode for $h for sevice $name"
						return 0
					}
				}
				break
			}
		}
		if { $exist eq 0 } {
			cli_set_errmsg "Bad health check name $h for sevice $name"
			return 0
		}
	}
	if { $mode eq "auto" } {
		set q [cli_get_value $sv "" "" "quality-link"]
		if { $q > [llength $mbs] } {
			cli_set_errmsg "Value for quality-link is more than the number of members for service $name"
			return 0
		}
	}
	if { $mode eq "sla" || $mode eq "load-balance" } {
		set slas [cli_get_tbl_list $sv "sla"]
		foreach sla $slas {
			set h [cli_get_value $sla "" "" "health-check"]
			set h [string trim $h \"]
			set id [cli_get_value $sla "" "" "id"]
			set exist 0
			foreach hc $hcs {
				set n [cli_get_value $hc "" "" "name"]
				if { $n eq $h } {
					if { [cli_ver_start 600 2] } {
						set hcmode [cli_get_value $hc "" "" "addr-mode"]
						if { $hcmode ne $addrmode } {
							cli_set_errmsg "Invalid health check addr-mode for $h"
							return 0
						}
					}
					set chk [cli_get_node $hc "sla" $id ""]
					if { $chk ne 0 } {
						set exist 1
					}
					break
				}
			}
			if { $exist eq 0 } {
				cli_set_errmsg "Invalid health check name $h or SLA id $id"
				return 0
			}
		}
	}
}
foreach hc $hcs {
	set name [cli_get_value $hc "" "" "name"]
	set m [cli_get_value $hc "" "" "member"]
	set m [string trim $m \"]
	if { $m ne 0 && $m ne "" } {
		set exist 0
		foreach mb $mbs {
			set n [cli_get_value $mb "" "" "seq-num"]
			if { $n eq $m } {
				set exist 1
				break
			}
		}
		if { $exist eq 0 } {
			cli_set_errmsg "$m is not a valid member seq number in health-check $name"
			return 0
		}
	}
}
foreach nb $nbs {
	set name [cli_get_value $nb "" "" "ip"]
	set m [cli_get_value $nb "" "" "member"]
	set m [string trim $m \"]
	if { $m ne 0 && $m ne "" } {
		set exist 0
		foreach mb $mbs {
			set n [cli_get_value $mb "" "" "seq-num"]
			if { $n eq $m } {
				set exist 1
				break
			}
		}
		if { $exist eq 0 } {
			cli_set_errmsg "$m is not a valid member seq number in neighbor $name"
			return 0
		}
	}
	set h [cli_get_value $nb "" "" "health-check"]
	set h [string trim $h \"]
	set id [cli_get_value $nb "" "" "sla-id"]
	if { $h ne 0 && $h ne "" } {
		set exist 0
		foreach hc $hcs {
			set n [cli_get_value $hc "" "" "name"]
			if { $n eq $h } {
				if { $id eq 0 && [cli_get_tbl_cnt $hc "sla"] eq 0 } {
					set exist 1
				} else {
					set chk [cli_get_node $hc "sla" $id ""]
					if { $chk ne 0 } {
						set exist 1
					}
				}
				break
			}
		}
		if { $exist eq 0 } {
			cli_set_errmsg "Invalid health-check $h and sla-id $id for neighbor $name"
			return 0
		}
	}
}
return 1
	%}
	"system sdwan" = %{
## for adom version >= 6.4
set svs [cli_get_tbl_list $CLI_CUR_NODE "service"]
set mbs [cli_get_tbl_list $CLI_CUR_NODE "members"]
set hcs [cli_get_tbl_list $CLI_CUR_NODE "health-check"]
set nbs [cli_get_tbl_list $CLI_CUR_NODE "neighbor"]
set dus [cli_get_tbl_list $CLI_CUR_NODE "duplication"]

if { [cli_branchpt_start 600 1614] } {
	set zones [cli_get_tbl_list $CLI_CUR_NODE "zone"]
	foreach mb $mbs {
		set z [string trim [cli_get_value $mb "" "" "zone"] \"]
		set name [cli_get_value $mb "" "" "name"]
		if { $z ne "virtual-wan-link" } {
			set exist 0
			foreach zone $zones {
				set n [cli_get_value $zone "" "" "name"]
				if { $n eq $z } {
					set exist 1
					break
				}
			}
			if { $exist eq 0 } {
				cli_set_errmsg "$z is not a valid zone name for member $name"
				return 0
			}
		}
	}
}

foreach sv $svs {
	set mode [cli_get_value $sv "" "" "mode"]
	set name [cli_get_value $sv "" "" "name"]
	set id [cli_get_value $sv "" "" "id"]
	set addrmode [cli_get_value $sv "" "" "addr-mode"]
	if { $name ne "" } {
		foreach sv2 $svs {
			set name2 [cli_get_value $sv2 "" "" "name"]
			if { $name2 eq $name } {
				set id2 [cli_get_value $sv2 "" "" "id"]
				if { $id2 ne $id } {
					cli_set_errmsg "Duplicate service name $name"
					return 0
				}
			}
		}
	}
	if { $mode eq "manual" || $mode eq "priority" || $mode eq "sla" || $mode eq "load-balance" } {
		set pm [cli_get_value $sv "" "" "priority-members"]
		if { [cli_ver_start 700 0] } {
			set pz [cli_get_value $sv "" "" "priority-zone"]
			if { $pm eq "" && $pz eq "" } {
				cli_set_errmsg "Please assign priority-member(s) or priority-zone(s)"
				return 0
			}
		} elseif { $pm eq "" } {
			cli_set_errmsg "Please assign priority-member(s)"
			return 0
		}
		foreach m $pm {
			set m [string trim $m \"]
			set exist 0
			foreach mb $mbs {
				set n [cli_get_value $mb "" "" "seq-num"]
				if { $n eq $m } {
					set exist 1
					break
				}
			}
			if { $exist eq 0 } {
				cli_set_errmsg "$m is not a valid member seq number for service $name"
				return 0
			}
		}
	}
	if { $mode eq "auto" || $mode eq "priority" } {
		set h [cli_get_value $sv "" "" "health-check"]
		set h [string trim $h \"]
		if { $h eq "" } {
			cli_set_errmsg "Please select a health-check for service $name"
			return 0
		}
		set exist 0
		foreach hc $hcs {
			set n [cli_get_value $hc "" "" "name"]
			if { $n eq $h } {
				set exist 1
				if { [cli_ver_start 600 2] } {
					set hcmode [cli_get_value $hc "" "" "addr-mode"]
					if { $hcmode ne $addrmode } {
						cli_set_errmsg "Invalid health check addr-mode for $h for sevice $name"
						return 0
					}
				}
				break
			}
		}
		if { $exist eq 0 } {
			cli_set_errmsg "Bad health check name $h for sevice $name"
			return 0
		}
	}
	if { $mode eq "auto" } {
		set q [cli_get_value $sv "" "" "quality-link"]
		if { $q > [llength $mbs] } {
			cli_set_errmsg "Value for quality-link is more than the number of members for service $name"
			return 0
		}
	}
	if { $mode eq "sla" || $mode eq "load-balance" } {
		set slas [cli_get_tbl_list $sv "sla"]
		foreach sla $slas {
			set h [cli_get_value $sla "" "" "health-check"]
			set h [string trim $h \"]
			set id [cli_get_value $sla "" "" "id"]
			set exist 0
			foreach hc $hcs {
				set n [cli_get_value $hc "" "" "name"]
				if { $n eq $h } {
					if { [cli_ver_start 600 2] } {
						set hcmode [cli_get_value $hc "" "" "addr-mode"]
						if { $hcmode ne $addrmode } {
							cli_set_errmsg "Invalid health check addr-mode for $h"
							return 0
						}
					}
					set chk [cli_get_node $hc "sla" $id ""]
					if { $chk ne 0 } {
						set exist 1
					}
					break
				}
			}
			if { $exist eq 0 } {
				cli_set_errmsg "Invalid health check name $h or SLA id $id"
				return 0
			}
		}
	}
	if {[cli_ver_start 700 0]} {
		set pz [cli_get_value $sv "" "" "priority-zone"]
		foreach z $pz {
			set z [string trim $z \"]
			if { $z ne "virtual-wan-link" } {
				set exist 0
				foreach zone $zones {
					set n [cli_get_value $zone "" "" "name"]
					if { $n eq $z } {
						set exist 1
						break
					}
				}
				if { $exist eq 0 } {
					cli_set_errmsg "$z is not a valid priority-zone name for service $name"
					return 0
				}
			}
		}
	}
}
foreach hc $hcs {
	set name [cli_get_value $hc "" "" "name"]
	set m [cli_get_value $hc "" "" "member"]
	set m [string trim $m \"]
	if { $m ne 0 && $m ne "" } {
		set exist 0
		foreach mb $mbs {
			set n [cli_get_value $mb "" "" "seq-num"]
			if { $n eq $m } {
				set exist 1
				break
			}
		}
		if { $exist eq 0 } {
			cli_set_errmsg "$m is not a valid member seq number in health-check $name"
			return 0
		}
	}
}
foreach nb $nbs {
	set name [cli_get_value $nb "" "" "ip"]
	set mode "sla"
	if {[cli_ver_start 700 0]} {
		set mode [cli_get_value $nb "" "" "mode"]
	}

	set ms [cli_get_value $nb "" "" "member"]
	set num_members [llength $ms]
	if { [cli_ver_start 700 2] } {
		if { [cli_get_value $nb "" "" "minimum-sla-meet-members"] > $num_members } {
			cli_set_errmsg "The minimum-sla-meet-members should be no more than $num_members"
			return 0
		}
	} elseif { $num_members > 1 } {
		cli_set_errmsg "only 1 member is supported"
		return 0
	}

	foreach m $ms {
		set m [string trim $m \"]
		if { $m ne "" } {
			set exist 0
			foreach mb $mbs {
				set n [cli_get_value $mb "" "" "seq-num"]
				if { $n eq $m } {
					set exist 1
					break
				}
			}
			if { $exist eq 0 } {
				cli_set_errmsg "$m is not a valid member seq number in neighbor $name"
				return 0
			}
		}
	}
	if { $mode eq "sla" } {
		set h [cli_get_value $nb "" "" "health-check"]
		set h [string trim $h \"]
		set id [cli_get_value $nb "" "" "sla-id"]
		if { $h ne 0 && $h ne "" } {
			set exist 0
			foreach hc $hcs {
				set n [cli_get_value $hc "" "" "name"]
				if { $n eq $h } {
					if { $id eq 0 && [cli_get_tbl_cnt $hc "sla"] eq 0 } {
						set exist 1
					} else {
						set chk [cli_get_node $hc "sla" $id ""]
						if { $chk ne 0 } {
							set exist 1
						}
					}
					break
				}
			}
			if { $exist eq 0 } {
				cli_set_errmsg "Invalid health-check $h and sla-id $id for neighbor $name"
				return 0
			}
		} else {
			cli_set_errmsg "health-check must be set for neighbor $name"
			return 0
		}
	} elseif { $mode eq "speedtest" } {
		if { $num_members > 1 } {
			cli_set_errmsg "speedtest mode only support 1 member"
			return 0
		}
	}
}
foreach du $dus {
	set name [cli_get_value $du "" "" "id"]
	set ms [cli_get_value $du "" "" "service-id"]
	foreach m $ms {
		set m [string trim $m \"]
		set exist 0
		foreach sv $svs {
			set n [cli_get_value $sv "" "" "id"]
			if { $n eq $m } {
				set exist 1
				break
			}
		}
		if { $exist eq 0 } {
			cli_set_errmsg "$m is not a valid service-id in duplication $name"
			return 0
		}
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
	cli_set_errmsg "Virtual Wire Pair member must contain exactly 2 elements."
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
	"system sdn-connector" = %{
set ctype [cli_get_value $CLI_CUR_NODE "" "" "type"]
set cname [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $ctype eq "" } {
	cli_set_errmsg "sdn connector type must be set"
	return 0
}
if { ![cli_ver_start 600 2] } {
	set connectors [cli_get_tbl_list $CLI_CUR_VDOM_NODE "system sdn-connector"] 
	foreach sdn $connectors {
		set name [cli_get_value $sdn "" "" "name"]
		set type [cli_get_value $sdn "" "" "type"]
		if { $name ne $cname && $type eq $ctype } {
			cli_set_errmsg "Multiple entries for $type type is not allowed"
			return 0 
		}
	}
}
set nodelist [cli_get_tbl_list $CLI_CUR_PARENT_NODE "system sdn-connector"]
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

if { $ctype ne "aws" && $ctype ne "azure" && $ctype ne "gcp" && $ctype ne "oci" && $ctype ne "acs" && $ctype ne "gcp" && $ctype ne "kubernetes" && $ctype ne "alicloud" && $ctype ne "ibm" && $ctype ne "aci-direct" } {
	set username [cli_get_value $CLI_CUR_NODE "" "" "username"]
	if { $username eq "" } {
		cli_set_errmsg "Attribute username must be set"
		return 0
	}
	set pwd [cli_get_value $CLI_CUR_NODE "" "" "password"]
	if { $pwd eq "" } {
		cli_set_errmsg "Attribute password must be set"
		return 0
	}
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
##
## Bug 777223 Remove "server" or "server-list" check in adom:
##
}
if { $ctype eq "aci-direct" } {
	set username [cli_get_value $CLI_CUR_NODE "" "" "username"]
	if { $username eq "" } {
		cli_set_errmsg "Attribute username must be set"
		return 0
	}
	set pwd [cli_get_value $CLI_CUR_NODE "" "" "password"]
	if { $pwd eq "" } {
		cli_set_errmsg "Attribute password must be set"
		return 0
	}
	if { [cli_ver_start 600 0] } {
		set ip [cli_get_value $CLI_CUR_NODE "" "" "server"]
		set ip2 [cli_get_value $CLI_CUR_NODE "" "" "server-list"]
		if { $ip eq "" && $ip2 eq "" } {
			cli_set_errmsg "Attribute server or server-list must be set"
			return 0
		}
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
#	set project [cli_get_value $CLI_CUR_NODE "" "" "gcp-project"]
	set account [cli_get_value $CLI_CUR_NODE "" "" "service-account"]
	set pk [cli_get_value $CLI_CUR_NODE "" "" "private-key"]
#	if { $project eq "" } {
#		cli_set_errmsg "GCP project name must be set"
#		return 0
#	}
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

	"firewall shaping-profile" = %{
set entries [cli_get_tbl_list $CLI_CUR_NODE "shaping-entries"]
set tot_percent 0
foreach entry $entries {
	set group [cli_get_value $entry "" "" "class-id"]
	set bw_percent [cli_get_value $entry "" "" "guaranteed-bandwidth-percentage"]
	set max_bw [cli_get_value $entry "" "" "maximum-bandwidth-percentage"]
	if { $bw_percent > $max_bw } {
		cli_set_errmsg "Shaping group $group: Guaranteed bandwidth ($bw_percent) must be less than maximum bandwidth ($max_bw)"
		return 0
	}
	set tot_percent [expr $tot_percent + $bw_percent]
}
if { $tot_percent > 100 } {
	cli_set_errmsg "Sum of all guaranteed bandwidth cannot exceed 100%"
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
	"system external-resource" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $type eq "category" || $type eq "domain" } {
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
if { [cli_get_node $CLI_CUR_VDOM_NODE "firewall address" $name ""] != 0 } {
	cli_set_errmsg "Name \"$name\" conflicts with a firewall address entry"
	return 0
}
return 1
	%}

	"authentication setting" = %{
set port [cli_get_value $CLI_CUR_NODE "" "" "captive-portal-port"]
if { ![cli_ver_start 600 2] && $port eq 0 } {
	set type [cli_get_value $CLI_CUR_NODE "" "" "captive-portal-type"]
	if { $type eq "fqdn"} {
		set portal [cli_get_value $CLI_CUR_NODE "" "" "captive-portal"]
		set portal6 [cli_get_value $CLI_CUR_NODE "" "" "captive-portal6"]
		if { $portal ne "" || $portal6 ne ""} {
			cli_set_errmsg "Captive portal port must be in range 1 - 65535"
			return 0
		}
	} elseif { $type eq "ip"} {
		set ip [cli_get_value $CLI_CUR_NODE "" "" "captive-portal-ip"]
		set ip6 [cli_get_value $CLI_CUR_NODE "" "" "captive-portal-ip6"]
		if { $ip ne "0.0.0.0" || $ip6 ne "::" } {
			cli_set_errmsg "Captive portal port must be in range 1 - 65535"
			return 0
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
return 1
	%}

	"firewall shaping-policy" = %{
if { [cli_is_match $CLI_CUR_NODE 0 "" "internet-service" 0 "enable"] } {
	if { [cli_ver_start 600 4] } {
		set intsvc_id [cli_get_value $CLI_CUR_NODE "" "" "internet-service-name"]
	} else {
		set intsvc_id [cli_get_value $CLI_CUR_NODE "" "" "internet-service-id"]
	}
	set intsvc_cus [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom"]
	if { ($intsvc_id eq "") && ($intsvc_cus eq "") } {
		if { [cli_ver_start 600 2] } {
			set intsvc_id_grp [cli_get_value $CLI_CUR_NODE "" "" "internet-service-group"]
			set intsvc_cus_grp [cli_get_value $CLI_CUR_NODE "" "" "internet-service-custom-group"]
			if { ($intsvc_id_grp eq "") && ($intsvc_cus_grp eq "") } {
				cli_set_errmsg "Must set internet service (group) or custom internet service (group) when internet-service is enabled."
				return 0;
			}
		} else {
			cli_set_errmsg "Must set internet service or custom internet service when internet-service is enabled."
			return 0
		}
	}
}
if { [cli_is_match $CLI_CUR_NODE 0 "" "internet-service-src" 0 "enable"] } {
	if { [cli_ver_start 600 4] } {
		set intsvc_id [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src-name"]
	} else {
		set intsvc_id [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src-id"]
	}
	set intsvc_cus [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src-custom"]
	if { ($intsvc_id eq "") && ($intsvc_cus eq "") } {
		if { [cli_ver_start 600 2] } {
			set intsvc_id_grp [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src-group"]
			set intsvc_cus_grp [cli_get_value $CLI_CUR_NODE "" "" "internet-service-src-custom-group"]
			if { ($intsvc_id_grp eq "") && ($intsvc_cus_grp eq "") } {
				cli_set_errmsg "Must set internet service source (group) or custom internet service source (group) when internet-service-src is enabled."
				return 0;
			}
		} else {
			cli_set_errmsg "Must set source internet service or source custom internet service when internet-service-src is enabled."
			return 0
		}
	}
}
return 1
	%}
	"device template widget" = %{
set template_name [cli_get_value $CLI_CUR_PKG_NODE "" "" ""]
if {$CLI_ACT ne "add"} {
	if { $template_name eq "IPSec_Fortinet_Recommened" } {
		cli_set_errmsg "IPSec_Fortinet_Recommened is read-only."
		return 0
	}
	return 1
}
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $template_name eq "IPSec_Fortinet_Recommened" && $name ne "ipsec" && $name ne "_ipsec" } {
	cli_set_errmsg "IPSec_Fortinet_Recommened is read-only."
	return 0
}
return 1
	%}
	"device template widget action-list" = %{
set template [cli_get_parent [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE ]]]
set template_name [cli_get_value $template "" "" ""]
if {$CLI_ACT ne "add" } {
	if { $template_name eq "IPSec_Fortinet_Recommended" } {
		cli_set_errmsg "IPSec_Fortinet_Recommened is read-only."
		return 0
	}
	if {$CLI_ACT ne "edit"} {
		return 1
	}
}
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
if { $action eq "conf-ipsec-template" || $action eq "add-vlan" } {
	set value [cli_get_value $CLI_CUR_NODE "" "" "value"]
	set errmsg [cli_ipsec_template_verify $value]
	if { $errmsg ne "" } {
		cli_set_errmsg "$errmsg"
		return 0
	}
	return 1
}
if {$CLI_ACT ne "add" } {
	return 1
}
set seq [cli_get_value $CLI_CUR_NODE "" "" "seq"]
if { $seq != 1 && $template_name eq "IPSec_Fortinet_Recommended" } {
	cli_set_errmsg "IPSec_Fortinet_Recommened is read-only."
	return 0
}
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
if { $name ne "dns" } {
	return 1
}
if { $seq != 1 } {
	cli_set_errmsg "Only one action is allowed in \"dns\" widget."
	return 0
}

return 1
	%}
	"template setting stype" = %{
if { $CLI_ACT eq "add" || $CLI_ACT eq "delete" } {
	return 1
}
set stype [cli_get_value $CLI_CUR_NODE "" "" ""]
set ostype [cli_get_org_value $CLI_CUR_NODE "" "" ""]
if { $stype ne $ostype } {
	cli_set_errmsg "There is a $ostype template with same name."
	return 0
}
return 1
	%}
	"firewall security-policy av-profile" = %{
set prof [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $prof ne "" } {
	set node [cli_get_value $CLI_CUR_VDOM_NODE "antivirus profile" $prof "feature-set"]
	if { $node eq "proxy" } {
		cli_set_errmsg "Antivirus profile \"$prof\" cannot be used because profile inspection mode is proxy"
		return 0
	}
}
return 1
	%}
	"firewall security-policy profile-group" = %{
set group [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $group ne "" } {
	set av [cli_get_value $CLI_CUR_VDOM_NODE "firewall profile-group" $group "av-profile"]
	set node [cli_get_value $CLI_CUR_VDOM_NODE "antivirus profile" $av "feature-set"]
	if { $node eq "proxy" } {
		cli_set_errmsg "Profile group \"$group\" cannot be used because antivirus profile \"$av\" inspection mode is proxy"
		return 0
	}
}
return 1
	%}
	"vpnmgr vpntable dpd-retryinterval" = %{
set retryinterval [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $retryinterval eq "" } {
	return 1
}
set count 1
set max_retryinterval 60
if { [cli_ver_start 600 0] } {
	set max_retryinterval 3600
}
foreach digit $retryinterval {
	if { $count == 1 } {
		if { ($digit < 0) || ($digit > $max_retryinterval) } {
			cli_set_errmsg "dpd-retryinterval seconds out of range 0 to $max_retryinterval"
			return 0
		}
	} elseif { $count == 2 } {
		if { ($digit < 0) || ($digit > 999) } {
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
	"central dnat6" = %{
if { ![cli_ver_start 600 4] } {
	cli_set_errmsg "IPv6 Central DNAT is not supported in this ADOM version"
	return 0
}
return 1
	%}
	"credential-store domain-controller {domain-name username}" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value eq "" || $value == 0 } {
	cli_set_errmsg "node_check_object fail! for $CLI_CUR_NODE_NAME is empty. Attribute '$CLI_CUR_NODE_NAME' MUST be set."
	return 0
}
return 1
	%}
	"credential-store domain-controller hostname" = %{
if { [cli_branchpt_start 600 1700] } {
	set value [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $value eq "" || $value == 0 } {
		cli_set_errmsg "node_check_object fail! for $CLI_CUR_NODE_NAME is empty. Attribute '$CLI_CUR_NODE_NAME' MUST be set."
		return 0
	}
}
return 1
	%}
	"dnsfilter domain-filter entries" = %{
set domain_val [cli_get_value $CLI_CUR_NODE "" "" "domain"]
if { $domain_val eq 0 || $domain_val == "" } {		
	set id_val [cli_get_value $CLI_CUR_NODE "" "" "id"]
	cli_set_errmsg "node_check_object fail! $CLI_CUR_NODE_NAME id $id_val domain is empty. Attribute domain MUST be set."
	return 0
}
	%}
	"application categories" = %{
if { $CLI_ACT eq "add" || $CLI_ACT eq "edit" || $CLI_ACT eq "delete" || $CLI_ACT eq "move" || $CLI_ACT eq "unset" } {
	cli_set_errmsg "Not allowed to add/edit/delete/move/unset application categories."
	return 0
}
	%}
	"emailfilter block-allow-list" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
if { $name ne "" } {
	if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $name] > 1 } {
		cli_set_errmsg "Duplicate email list name: $name."
		return 0
	} else {
		set n [string trim $name \"]
		if { $n ne $name } {
			if { [cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "name" 0 $n] } {
				cli_set_errmsg "Duplicate email list name: $name."
				return 0
			}
		}
	}
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
					set email_pattern [cli_get_value $CLI_CUR_NODE "" "" "email-pattern"]
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
	"router bgp neighbor" = %{
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
set ip [cli_get_value $CLI_CUR_NODE "" "" "ip"]
set node_list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
foreach e $node_list {
	if { [cli_if_same_node $e $CLI_CUR_NODE] } {
		continue
	}
	set eip [cli_get_value $e "" "" "ip"]
	if { [string equal -nocase $eip $ip] } {
		cli_set_errmsg "duplicate neighbor IP $ip"
		return 0
	}
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
	"vpn ipsec phase1-interface" = %{
set type [cli_get_value $CLI_CUR_NODE "" "" "type"]
set peerID [cli_get_value $CLI_CUR_NODE "" "" "peerid"]
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
if {$type eq "dynamic"} {
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
set usrgrp [cli_get_value $CLI_CUR_NODE "" "" "usrgrp"]
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
    "switch-controller fortilink-settings nac-ports" = %{
set ovlan [cli_get_value $CLI_CUR_NODE "" "" "onboarding-vlan"]
if { $ovlan eq "" } {
    cli_set_errmsg "Onboarding VLAN must be set"
    return 0
}
set lan [cli_get_value $CLI_CUR_NODE "" "" "lan-segment"]
if { $lan eq "enabled" } {
    set intf [cli_get_value $CLI_CUR_NODE "" "" "nac-lan-interface"]
    if { $intf eq "" } {
        cli_set_errmsg "Primary VLAN must be set"
        return 0
    }
    set vlans [cli_get_value $CLI_CUR_NODE "" "" "nac-segment-vlans"]
    if { $vlans eq "" } {
        cli_set_errmsg "LAN segment members must be set"
        return 0
    }
    if { $intf eq $ovlan } {
        cli_set_errmsg "Primary VLAN cannot be the same as onboarding VLAN"
        return 0
    }
    set ovlan [string trim $ovlan \"]
    set intf [string trim $intf \"]
    foreach memb $vlans {
        if { $ovlan eq $memb } {
            cli_set_errmsg "Onboarding VLAN cannot be the same as lan segment member \"$memb\""
            return 0
        }
        if { $intf eq $memb } {
            cli_set_errmsg "Primary VLAN cannot be the same as lan segment member \"$memb\""
            return 0
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
	"sdwan overlay {edge-route-map-in edge-route-map-out}" = %{
set route_map [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
if { $route_map == "Priority_1" || $route_map == "Priority_2" || $route_map == "Priority_3" || $route_map == "Priority_4" || $route_map == "Priority_9999" } {
	cli_set_errmsg "router route-map \"$route_map\" is only for Spoke."
	return 0
}
return 1
	%}
	"sdwan overlay nodes neighbor {route-map-in route-map-out route-map-out-preferable}" = %{
set route_map [string trim [cli_get_value $CLI_CUR_NODE "" "" ""] \"]
if { $route_map == "RM-VPN-Priority" } {
	cli_set_errmsg "router route-map \"$route_map\" is only for Hub."
	return 0
}
return 1
	%}
%};
