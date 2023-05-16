visibility %{
	"system bypass" =%{
if { [string match -nocase $platform "Fortigate-400E-Bypass"] } {
	return 1
}
if { [cli_has_feature "f_bypass"] } {
	set pair_list {}
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "Fortigate-2500E"] } {
		set pair_list {{"port43" "port44"}}
	} elseif { [string match -nocase $platform "Fortigate-400E-Bypass"] } {
		set pair_list {{"port1" "port2"} {"port3" "port4"} {"port5" "port6"} {"port7" "port8"} {"port9" "port10"} {"port11" "port12"} {"port13" "port14"} {"port15" "port16"} {"port17" "port18"} {"port19" "port20"} {"port21" "port22"} {"port23" "port24"} {"port25" "port26"} {"port27" "port28"} {"port29" "port30"} {"port31" "port32"}}
	} elseif { [string match -nocase $platform "Fortigate-800D"] } {
		set pair_list {{"wan1" "port1"} {"wan2" "port2"}}
	} elseif { [string match -nocase $platform "Fortigate-80F-BYPASS"] } {
		set pair_list {{"wan1" "internal1"}}
	} elseif { [string match -nocase $platform "FortigateRugged-60F"] } {
		set pair_list {{"wan1" "internal4"}}
	} elseif { [string match -nocase $platform "FortigateRugged-60F-3G4G"] } {
		set pair_list {{"wan1", "internal4"}}
	}
	foreach pair $pair_list {
		set int_name [lindex $pair 0]
		set ext_name [lindex $pair 1]
		set ivd_name [cli_get_value $CLI_GLOBAL_NODE "system interface" $int_name "vdom"]
		set evd_name [cli_get_value $CLI_GLOBAL_NODE "system interface" $ext_name "vdom"]
		set ivd_node [cli_get_vdom_node $ivd_name]
		set evd_node [cli_get_vdom_node $evd_name]
		if { ($ivd_name ne $evd_name) || ([cli_get_value $ivd_node "system settings" "" "opmode"] ne "transparent") } {
			return 0
		}
	}
	return 1
}
return 0
	%}
	"user adgrp {polling-id}" = %{
set svr_name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-name"]
if { $svr_name eq "Local FSSO Agent" || $svr_name eq "\"Local FSSO Agent\""} {
	return 1
}
return 0
%}
	"user local {passwd-policy passwd-time}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "password"]
%}
	"webfilter urlfilter entries exempt" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action == 0 || $action == "" || $action == "exempt" } {
	return 1
}
return 0
%}

    "webfilter content entries score" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action == "exempt" } {
    return 0
}
return 1
%}

	"system admin dashboard interface" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "widget-type" 1 "tr-history"] } {
	return 0
}
return 1;
%}
	"system admin dashboard resolve-host" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "widget-type" 0 "per-ip-usage"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "widget-type" 0 "sessions"]
%}
	"log eventfilter {system gtp notification radius mms-stats ipsec dhcp ppp admin auth pattern nac-quarantine sslvpn-log-auth sslvpn-log-adm sslvpn-log-session vip-ssl ldb-monitor wan-opt chassis-loadbalance-ha wireless-activity vpn user router amc-intf-bypass voip}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 1 "disable"]
%}
	"log eventfilter {ha cpu-memory-usage}" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE 0 "" "event"] eq "disable"} {
	return 0
}
set platform [cli_get_devinfo "platform"]
set check [expr [string match -nocase $platform "FortiGate-5001C"] || [string match -nocase $platform "FortiGate-500A"]]
set mgmtvdom [cli_get_value $CLI_GLOBAL_NODE "system global" "" "management-vdom"]
if {$check && $mgmtvdom ne $CLI_CUR_VDOM_NAME} {
	return 0
}
return 1
%}
	"application list entries block-video" = %{
set app [string trim [cli_get_value $CLI_CUR_PARENT_NODE "" "" "application"] \"]
if { $app eq "3" } {
	return 1
}
return 0
%}
	"application list entries im-no-content-summary" = %{
set cat [string trim [cli_get_value $CLI_CUR_PARENT_NODE "" "" "category"] \"]
if { $cat eq "1" } {
	set app [string trim [cli_get_value $CLI_CUR_PARENT_NODE "" "" "application"] \"]
	if { $app eq "1" || $app eq "2" || $app eq "3" || $app eq "4" } {
		return 1
	}
}
return 0
%}
	"vpn ssl web {host-check-software portal virtual-desktop-app-list bookmarks bookmarks-group favorite user}" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
return 1;
	%}
	"vpn ssl web portal bookmark-group bookmarks host" = %{
set app [cli_get_value $CLI_CUR_PARENT_NODE "" "" "apptype"]
expr { $app eq "portforward" || $app eq "rdp" || $app eq "ssh" || $app eq "telnet" || $app eq "vnc" }
	%}
	"vpn ssl web portal bookmark-group bookmarks folder" = %{
set app [cli_get_value $CLI_CUR_PARENT_NODE "" "" "apptype"]
expr { $app eq "ftp" || $app eq "sftp" || $app eq "smb" }
	%}
	"vpn ssl web portal bookmark-group bookmarks sso-credential" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sso" 1 "disable"]
	%}
	"vpn ssl web portal bookmark-group bookmarks sso-credential-sent-once" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sso" 0 "auto"]
	%}
	"vpn ssl web portal bookmark-group bookmarks {sso-username sso-password}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sso-credential" 1 "sslvpn-login"]
	%}
	"vpn ssl settings" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
return 1;
	%}
	"vpn ssl web portal widget {start-ip end-ip}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "tunnel"]
	%}
	"vpn ssl web portal widget bookmarks" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "type" 0 "bookmark"]
	%}
	"vpn ssl web portal widget allow-apps" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "bookmark"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tool"]
	%}
	"vpn ssl web portal widget allow-apps ping" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tool"]
	%}
	"vpn ssl web portal widget tunnel-status" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tunnel"]
	%}
	"vpn ssl web portal widget display-limit" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "history"]
	%}
	"vpn ssl web portal widget split-tunneling-routing-address" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "split-tunneling" 0 "enable"]
	%}
	"vpn ssl web portal os-check-list" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "os-check" 1 "enable"] } {
	return 0
}
if { [cli_branchpt_start 600 200] } {
	set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
	if { $name eq "windows-xp" || $name eq "windows-vista" } {
		return 0
	}
}
if { [cli_branchpt_start 600 997] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "tunnel-mode" 1 "enable"] } {
	return 0
}
return 1
	%}
	"vpn ssl interface os-check-list" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "os-check" 0 "enable"]
	%}
	"vpn ssl web portal os-check-list {tolerance latest-patch-level}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "check-up-to-date"]
	%}
	"vpn ssl interface os-check-list {tolerance latest-patch-level}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "check-up-to-date"]
	%}
	"vpn ssl web portal widget column" = %{
expr [cli_is_match [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] 0 "" "page-layout" 0 "double-column"]
	%}
	"vpn ssl web portal {virtual-desktop-desktop-switch virtual-desktop-clipboard-share virtual-desktop-removable-media-access virtual-desktop-network-share-access virtual-desktop-printing virtual-desktop-app-list virtual-desktop-logout-when-browser-close}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virtual-desktop" 0 "enable"]
	%}
	"vpn ssl web portal host-check-policy" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "host-check" 1 "custom"] } {
	return 0
}
if { [cli_branchpt_start 600 997] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "tunnel-mode" 1 "enable"] } {
	return 0
}
return 1
	%}
	"vpn ssl web portal host-check-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "host-check" 1 "none"]
	%}
	"vpn ssl web portal {skip-check-for-unsupported-os skip-check-for-browser}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "os-check" 0 "enable"]
	%}
        "vpn ssl web portal {save-password keep-alive auto-connect}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ipv6-tunnel-mode" 0 "enable"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "tunnel-mode" 0 "enable"] } {
	return 1
}
return 0
        %}
        "vpn ssl web portal widget {save-password keep-alive auto-connect}" = %{
if { [cli_ver_start 500 0] } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "tunnel" } {
		return 1
	}
}
return 0
        %}
        "vpn ssl web portal {dns-server1 dns-server2 wins-server1 wins-server2}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "tunnel-mode" 0 "enable"] } {
	return 1
}
return 0
	%}
        "vpn ssl web portal widget {dns-server1 dns-server2 wins-server1 wins-server2}" = %{
if { [cli_ver_start 500 0] } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "tunnel" } {
		return 1
	}
}
return 0
	%}
        "vpn ssl web portal {ipv6-dns-server1 ipv6-dns-server2 ipv6-wins-server1 ipv6-wins-server2 ipv6-split-tunneling ipv6-pools}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ipv6-tunnel-mode" 0 "enable"] } {
	return 1
}
return 0
        %}
        "vpn ssl web portal widget {ipv6-dns-server1 ipv6-dns-server2 ipv6-wins-server1 ipv6-wins-server2 ipv6-split-tunneling ipv6-pools}" = %{
if { [cli_ver_start 500 0] } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "tunnel" } {
		return 1
	}
}
return 0
        %}
        "vpn ssl web portal {ipv6-split-tunneling-routing-address}" = %{
return 1
        %}
	"vpn ssl web portal {split-tunneling ip-mode}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "tunnel-mode" 0 "enable"] } {
	return 1
}
return 0
	%}
	"vpn ssl web portal widget {split-tunneling ip-mode}" = %{
if { [cli_ver_start 500 0] } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "tunnel" } {
		return 1
	}
} elseif { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "tunnel-status" 0 "enable"] } {
	return 1
}
return 0
	%}
	"vpn ssl web portal ip-pools" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "tunnel-mode" 0 "enable"] } {
	return 1
}
return 0
	%}
	"vpn ssl web portal widget ip-pools" = %{
if { [cli_ver_start 500 0] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tunnel"] } {
		return 1
	}
} elseif { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "tunnel-status" 0 "enable"] } {
	return 1
}
return 0
	%}
	"vpn ssl web portal widget exclusive-routing" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "split-tunneling" 0 "disable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ipv6-split-tunneling" 0 "disable"]
	%}
	"vpn ssl web portal widget service-restriction" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "exclusive-routing" 0 "disable"] && ([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ipv6-split-tunneling" 0 "disable"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "split-tunneling" 0 "disable"])
	%}
	"vpn ssl web portal widget ipv6-split-tunneling-routing-address" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ipv6-split-tunneling" 0 "enable"]
	%}
	"system global internal-switch-speed" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "" "internal-switch-mode" 0 "switch"]
	%}
	"system proxy-arp" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
return 1;
	%}
	"system dhcp server" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
return 1;
	%}
	"system dhcp server {ip-mode ipsec-lease-hold}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "server-type" 0 "ipsec"]
	%}
	"system dhcp server ip-range" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "server-type" 0 "regular"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "ip-mode" 0 "range"]
	%}
	"system dhcp server vci-string" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "vci-match" 0 "enable"]
	%}
	"system settings {multicast-skip-policy}" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "transparent"]
	%}
	"system settings {multicast-forward multicast-ttl-notchange}" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system settings comments" = %{
namespace import global::cli_sys_global_vdom_enable
return [cli_sys_global_vdom_enable]
	%}
	"system settings ecmp-max-paths" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system mac-address-table" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "transparent"]
	%}
	"firewall policy {users groups}" = %{
namespace import global::is_hyperscale_activated
if { [cli_ver_start 700 2] } {
	if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
		return 0
	}
} elseif { [cli_ver_start 700 0] } {
	if { [cli_branchpt_start 700 343] && [is_hyperscale_activated] } {
		return 0
	}
}

if { [cli_ver_start 500 2] } {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 1 "ipsec"]
} else {
	return 1
}
	%}
        "firewall policy capture-packet" = %{
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "logtraffic" 0 "disable"] ||
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "deny"]} {
	return 0
}
if { [cli_ver_start 500 2] } {
	set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
	if { $action ne "deny" } {
		if { [cli_has_feature "f_sslvpn"] } {
			namespace import global::is_sslvpn_policy
			namespace import global::FMG_is_sslvpn_policy_has_tunnel
			if { [is_sslvpn_policy $CLI_CUR_PARENT_NODE] && ![FMG_is_sslvpn_policy_has_tunnel $CLI_CUR_PARENT_NODE] } {
				return 0
			}
		}
		return 1
	}
	return 0
}
return 1
        %}
	"firewall {policy policy6} {auto-asic-offload}" = %{
if { [cli_ver_start 600 4] } {
	namespace import global::ngfw_mode_policy
	if { [ngfw_mode_policy] } {
		return 1
	}
} 
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "deny" } {
	return 0
}
return 1
	%}
        "firewall policy log-unmatched-traffic" = %{
namespace import global::skip_if_nosplit
if {[skip_if_nosplit $CLI_CUR_PARENT_NODE]} {
	return 0
}
return 1
        %}
        "firewall policy identity-based-policy {per-ip-shaper traffic-shaper traffic-shaper-reverse}" = %{
set parent [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]]
if { [cli_ver_start 400 3] } {
	if { [cli_is_match $parent 0 "" "srcintf" 0 "\"web-proxy\""] ||
	     [cli_is_match $parent 0 "" "srcintf" 0 "\"ftp-proxy\""] } {
		return 0
	}
} else {
	if { [cli_is_match $parent 0 "" "srcintf" 0 "\"web-proxy\""] } {
		return 0
	}
}
set action [cli_get_value $parent "" "" "action"]
if { $action eq "" || $action eq "deny" || $action eq "ssl-vpn" || $action eq "ipsec" } {
	return 0
}
if { $action eq "accept" } {
	if {[cli_is_match $parent 0 "" "identity-based" 1 "enable"]} {
		return 0
	}
}
if { [cli_ver_start 500 2] } {
	return 1
} elseif { [cli_ver_start 500 0] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 1 "accept"] } {
		return 0
	}
}
return 1
        %}
        "firewall policy6 identity-based-policy {traffic-shaper traffic-shaper-reverse}" = %{
set parent [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]]
set action [cli_get_value $parent "" "" "action"]
if { $action eq "" || $action eq "deny" || $action eq "ssl-vpn" || $action eq "ipsec" } {
	return 0
}
if { $action eq "accept" } {
	if {[cli_is_match $parent 0 "" "identity-based" 1 "enable"]} {
		return 0
	}
}
return 1
        %}
	"firewall policy {gbandwidth maxbandwidth priority}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "trafficshaping" 0 "enable"]
	%}
	"firewall policy fixedport" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "accept"]
	%}
	"firewall policy {forticlient-redir-portal forticlient-ra-notinstalled forticlient-ra-notlicensed forticlient-ra-db-outdated forticlient-ra-no-av forticlient-ra-no-fw forticlient-ra-no-wf}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-check" 0 "enable"]
	%}
	"firewall policy diffservcode-forward" = %{
if { [cli_branchpt_start 700 1178] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "diffserv-copy" 0 "enable"] } {
		return 0
	} 
} 
if { ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "diffserv-forward" 0 "enable"] } {
	return 0
}
return 1
	%}
	"firewall policy diffservcode-rev" = %{
if { [cli_branchpt_start 700 1178] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "diffserv-copy" 0 "enable"] } {
		return 0
	} 
} 
if { ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "diffserv-reverse" 0 "enable"] } {
	return 0
}
return 1
	%}
	"firewall policy identity-based" = %{
namespace import global::identity_based_visib
if {[identity_based_visib $CLI_CUR_PARENT_NODE]} {
	return 1
}
return 0
        %}
	"firewall policy identity-based-policy" = %{
set parent [cli_get_parent $CLI_CUR_PARENT_NODE]
set ok 0
if {[cli_is_match $parent 0 "" "identity-based" 0 "enable"] || [cli_is_match $parent 0 "" "action" 0 "ssl-vpn"]} {
	set ok 1
}
if {[cli_is_match $parent 0 "" "action" 0 "deny"]} {
	set ok 0
}
return $ok
        %}
	"firewall policy endpoint-profile" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "endpoint-check" 0 "enable"]
	%}
	"firewall policy endpoint-keepalive-interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "endpoint-check" 0 "enable"]
	%}
	"firewall policy tcp-reset" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "deny"]
	%}
	"firewall policy ip-based" = %{
namespace import global::fw_ip_based_visible
if { [fw_ip_based_visible $CLI_CUR_PARENT_NODE] } {
	return 1
}
return 0
	%}
	"firewall policy auth-method" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "identity-based" 0 "enable"]
	%}
	"firewall policy custom-log-fields" = %{
if { [cli_ver_start 500 0] } {
	return 1
} elseif { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "utm-status" 0 "enable"] } {
	return 1
}
return 0
	%}
	"firewall policy profile-type" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "utm-status" 0 "enable"] || [cli_branchpt_start 600 120] } {
	set group [cli_get_value $CLI_CUR_PARENT_NODE "" "" "profile-group"]
	if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "group" && $group eq "" } {
		return 0
	}
	return 1
}
return 0
	%}
	"firewall policy application-charts" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "utm-status" 0 "enable"] } {
	set has_hdd [expr {[cli_get_devinfo "hdd"] eq "yes"}]
	if {!$has_hdd} {
		return 0
	}
	set applist [cli_get_value $CLI_CUR_PARENT_NODE "" "" "application-list"]
	if { $applist!=0 && [string length $applist]>0 } {
		set applist_node [cli_get_node $CLI_CUR_VDOM_NODE "application list" $applist ""]
		if {$applist_node == 0} {
			return 0
		}
		set chart [cli_get_value $applist_node "" "" "chart"]
		if {$chart == 0 || $chart ne "enable"} {
			return 0
		}
		return 1
	}
}
return 0
	%}
	"firewall policy {name comments}" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value ne "" } {
	return 1
}
return 0
	%}
        "firewall policy identity-based-policy deep-inspection-options" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "utm-status" 0 "enable"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "profile-type" 0 "single"] &&
     [cli_is_match [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] 0 "" "action" 1 "ssl-vpn"] } {
	     if { [cli_ver_start 500 2] } {
		     return 1
	     } elseif { [cli_ver_start 500 0] } {
		     if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 1 "accept"] } {
			     return 0
		     }
	     }
	     return 1
     }
return 0
        %}
	"firewall {policy policy6} {profile-group}" = %{
if { [cli_ver_start 600 4] } {
	namespace import global::ngfw_mode_policy
	if { [ngfw_mode_policy] } {
	        return 0
	}
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "utm-status" 0 "enable"] || [cli_branchpt_start 600 120] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "profile-type" 0 "group"] } {
		return 1
	}
}
return 0
	%}
	"firewall profile-group application-charts" = %{
set has_hdd [expr {[cli_get_devinfo "hdd"] eq "yes"}]
if {!$has_hdd} {
	return 0
}
set applist [cli_get_value $CLI_CUR_PARENT_NODE "" "" "application-list"]
if { $applist!=0 && [string length $applist]>0 } {
    set applist_node [cli_get_node $CLI_CUR_VDOM_NODE "application list" $applist ""]
    if {$applist_node == 0} {
        return 0
    }
    set chart [cli_get_value $applist_node "" "" "chart"]
    if {$chart == 0 || $chart ne "enable"} {
        return 0
    }
    return 1
}
return 0
	%}

	"firewall policy identity-based-policy application-charts" = %{
set has_hdd [expr {[cli_get_devinfo "hdd"] eq "yes"}]
if {!$has_hdd} {
    return 0
}
set applist [cli_get_value $CLI_CUR_PARENT_NODE "" "" "application-list"]
if { $applist!=0 && [string length $applist]>0 } {
    set applist_node [cli_get_node $CLI_CUR_VDOM_NODE "application list" $applist ""]
    if {$applist_node == 0} {
        return 0
    }
    set chart [cli_get_value $applist_node "" "" "chart"]
    if {$chart == 0 || $chart ne "enable"} {
        return 0
    }
    return 1
}
return 0
	%}
	"firewall mms-profile notification detect-server" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
set protocol [string trim $protocol \"]
set msg_type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
set msg_type [string trim $msg_type \"]
set msg_prot [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-protocol"]
set msg_prot [string trim $msg_prot \"]
if { $protocol ne $msg_prot } {
	return 0
}
if { $protocol eq "mm7" && $msg_prot eq "mm7" && $msg_type eq "submit-req" } {
	return 0
}
return 1
	%}
	"firewall mms-profile notification {mmsc-hostname mmsc-port}" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
set msg_prot [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-protocol"]
set msg_type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
set detect_srv [cli_get_value $CLI_CUR_PARENT_NODE "" "" "detect-server"]
if { $protocol eq "mm7" && $msg_prot eq "mm7"  } {
	if { $msg_type eq "deliver-req" && $detect_srv ne "" } {
		return 0
	}
} elseif { $protocol eq $msg_prot && $detect_srv ne ""  } {
	return 0
}
return 1
	%}
	"firewall mms-profile notification mmsc-url" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
set msg_prot [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-protocol"]
set msg_type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
set detect_srv [cli_get_value $CLI_CUR_PARENT_NODE "" "" "detect-server"]
if { $msg_prot eq "mm3" || $msg_prot eq "mm4"  } {
	return 0
}
if { $protocol eq "mm7" && $msg_prot eq "mm7"  } {
	if { $msg_type eq "deliver-req" && $detect_srv ne "" } {
		return 0
	}
} elseif { $protocol eq $msg_prot && $detect_srv ne ""  } {
	return 0
}
return 1
	%}
	"firewall mms-profile notification {mmsc-username mmsc-password}" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
set msg_type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
set detect_srv [cli_get_value $CLI_CUR_PARENT_NODE "" "" "detect-server"]
if { $protocol eq "mm7" && $msg_type eq "deliver-req" && $detect_srv ne "" } {
	return 0
}
return 1
	%}
	"firewall mms-profile notification {vasp-id vas-id}" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
set msg_prot [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-protocol"]
if { $msg_prot ne "mm7" } {
	return 0
}
if { $protocol eq "mm7" && $msg_type eq "deliver-req" && $detect_srv ne "" } {
	return 0
}
return 1
	%}
	"firewall mms-profile notification from-in-header" = %{
set msg_prot [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-protocol"]
if { $msg_prot ne "mm1" && $msg_prot ne "mm7" } {
	return 0
}
return 1
	%}
	"firewall mms-profile notification msg-type" = %{
set msg_prot [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-protocol"]
if { $msg_prot ne "mm7" } {
	return 0
}
return 1
	%}
	"firewall mms-profile notification alert-src-msisdn" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if { ![string match "alert-*" $protocol] } {
	return 0
}
return 1
	%}
	"firewall mms-profile notification {flood-int-mode flood-int flood-status dupe-int-mode dupe-int dupe-status}" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if { [string match "alert-*" $protocol] } {
	return 0
}
if { $protocol eq "mm3" || $protocol eq "mm7" } {
	return 0
}
return 1
	%}
	"firewall mms-profile notification {mms-checksum-int-mode mms-checksum-int mms-checksum-status carrier-endpoint-bwl-int-mode carrier-endpoint-bwl-int carrier-endpoint-bwl-status bword-int-mode bword-int bword-status virus-int-mode virus-int virus-status file-block-int-mode file-block-int file-block-status}" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if { [string match "alert-*" $protocol] } {
	return 0
}
return 1
	%}
	"firewall mms-profile notification {alert-int-mode alert-int alert-status}" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if { ![string match "alert-*" $protocol] } {
	return 0
}
return 1
	%}
	"firewall policy dynamic-profile-group" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"firewall policy6 application-charts" = %{
set has_hdd [expr {[cli_get_devinfo "hdd"] eq "yes"}]
if {!$has_hdd} {
    return 0
}
set applist [cli_get_value $CLI_CUR_PARENT_NODE "" "" "application-list"]
if { $applist!=0 && [string length $applist]>0 } {
    set applist_node [cli_get_node $CLI_CUR_VDOM_NODE "application list" $applist ""]
    if {$applist_node == 0} {
        return 0
    }
    set chart [cli_get_value $applist_node "" "" "chart"]
    if {$chart == 0 || $chart ne "enable"} {
        return 0
    }
    return 1
}
return 0
	%}
	"firewall address subnet" = %{
set typ [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $typ eq "ipmask" || $typ eq "interface-subnet" } {
	return 1
}
return 0
        %}
	"firewall address start-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "iprange"]
        %}
	"firewall address sdn" = %{
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dynamic"]} {
	if { [cli_branchpt_start 600 982] } {
		if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sub-type" 0 "sdn"] } {
			return 1
		}
	} else {
		return 1
	}
} 
return 0 
	%}
	"firewall address6 sdn" = %{
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dynamic"]} {
	return 1
}
return 0
	%}
	"firewall {address address6} {tenant epg-name sdn-tag}" = %{
set sdn [cli_get_value $CLI_CUR_PARENT_NODE "" "" "sdn"]
set sdn [string trim $sdn \"]
if { [cli_ver_start 600 2] } {
	namespace import global::find_sdn_conn_type_by_name
	if { [find_sdn_conn_type_by_name $sdn] eq "aci" } {
		return 1
	}
} else {
	set addr_type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
	if { $addr_type eq "dynamic" && $sdn eq "aci" } {
		return 1
	}
}
return 0
	%}
	"firewall address sub-type" = %{
if { [cli_branchpt_start 600 982] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dynamic"] } {
		return 1
	} 
}
return 0
    %}
	"firewall address fsso-group" = %{
if { [cli_branchpt_start 600 982] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sub-type" 0 "fsso"] } {
		return 1
	}
}
return 0
    %}
	"firewall address filter" = %{
if { ![cli_branchpt_start 500 1575] } {
	return 0
}
set sdn [cli_get_value $CLI_CUR_PARENT_NODE "" "" "sdn"]
set sdn [string trim $sdn \"]
if { [cli_ver_start 600 2] } {
	namespace import global::find_sdn_conn_type_by_name
	set sdntype [find_sdn_conn_type_by_name $sdn]
	set allow [list "acs" "aws" "azure" "gcp" "oci" "kubernetes" "openstack" "vmware" "alicloud" "sepm" "aci-direct" "ibm"]
	if { [lsearch $allow $sdntype] != -1 } {
		return 1
	}
	return 0
}
if { [cli_ver_start 600 0] } {
	if { $sdn eq "aws" || $sdn eq "azure" || $sdn eq "gcp" || $sdn eq "oci" || $sdn eq "openstack" } {
		return 1
	}
	return 0
}
if { [cli_ver_start 500 6] } {
	if { $sdn eq "aws" || $sdn eq "azure" } {
		return 1
	}
	return 0
}
return 0
        %}
	"firewall address end-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "iprange"]
	%}
	"firewall address fqdn" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fqdn"]
        %}
	"firewall address cache-ttl" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fqdn"]
        %}
        "firewall address wildcard" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "wildcard"]
        %}
        "firewall address country" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "geography"]
        %}
	"firewall address allow-routing" = %{
set address_type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $address_type eq "ipmask" || $address_type eq "fqdn" || $address_type eq "interface-subnet" } {
	return 1
}
return 0
        %}
        "firewall address url" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "url"]
        %}
        "firewall address wildcard-fqdn" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "wildcard-fqdn"]
        %}
        "firewall policy6 maxbandwidth" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "trafficshaping" 0 "enable"]
        %}
        "firewall policy6 gbandwidth" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "trafficshaping" 0 "enable"]
        %}
        "firewall policy6 priority" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "trafficshaping" 0 "enable"]
        %}
        "firewall policy6 fixedport" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "accept"]
        %}
        "firewall policy6 diffservcode-forward" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "diffserv-forward" 0 "enable"]
        %}
        "firewall policy6 diffservcode-rev" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "diffserv-reverse" 0 "enable"]
        %}
	"firewall policy6 dynamic-profile-access" = %{
if { [cli_ver_start 400 3] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "identity-based" 0 "enable"] } {
		return 0
	}
}
return 1
        %}
        "firewall policy identity-from" = %{
set act [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
set idb [cli_get_value $CLI_CUR_PARENT_NODE "" "" "identity-based"]
if { $act ne "accept" || $idb ne "enable" } {
        return 0
}
if { [cli_has_feature "f_webproxy"] } {
        if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"web-proxy\""] ||
             [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"ftp-proxy\""] } {
                return 0
        }
}
if { [cli_has_feature "f_wanopt"] } {
        if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"wanopt\""] } {
                return 0
        }
}
return 1
        %}
        "firewall policy6 identity-from" = %{
set act [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
set idb [cli_get_value $CLI_CUR_PARENT_NODE "" "" "identity-based"]
if { $act ne "accept" || $idb ne "enable" } {
        return 0
}
return 1
        %}
	"firewall policy transaction-based" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "identity-based" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"web-proxy\""] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-based" 1 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth-method" 1 "ntlm"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth-method" 1 "fsso"]
	%}
	"firewall policy web-auth-cookie" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "accept"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"web-proxy\""] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-based" 1 "enable"]
	%}
        "firewall ipmacbinding setting undefinedhost" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "bindthroughfw" 0 "enable"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "bindtofw" 0 "enable"]
        %}
        "firewall profile sip rtp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip strict_register" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip register-rate" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip invite-rate" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip max-dialogs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip block-long-lines" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip max-line-length" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip block-unknown" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip call-keepalive" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip block-ack" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip blcok-bye" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip blcok-cancel" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip block-info" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip block-invite" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip block-notify" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip block-options" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip block-prack" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip block-publish" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip block-refer" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip block-register" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip block-subscribe" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip block-update" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip archive-summary" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sip archive-full" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile simple block-message" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile simple message-rate" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile simple archivie-summary" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile simple archive-full" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sccp block-mcast" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sccp verify-header" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sccp archive-summary" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sccp archive-full" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sccp no-content-summary" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall profile sccp max-calls" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "firewall service custom tcp-portrange" = %{
if { [cli_ver_start 500 6] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "TCP/UDP/SCTP"] } {
		return 1
	}
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "enable"] && ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "SOCKS-UDP"] } {
		return 1
	}
	return 0
}
if { [cli_ver_start 500 0] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "TCP/UDP/SCTP"] } {
		return 1
	}
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "explicit-proxy" 0 "enable"] && ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "SOCKS-UDP"]} {
		return 1
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "TCP/UDP/SCTP"] } {
		return 1
	}
}
return 0
        %}
        "firewall service custom {sctp-portrange tcp-halfclose-timer tcp-halfopen-timer tcp-timewait-timer udp-idle-timer check-reset-range session-ttl}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "TCP/UDP/SCTP"]
        %}
	"firewall service custom udp-portrange" = %{
if { [cli_ver_start 500 6] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "TCP/UDP/SCTP"] ||
	    ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "enable"] } {
		return 1
	} elseif { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "SOCKS-UDP"] } {
		return 1
	}
	return 0
}
if { [cli_ver_start 500 0] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "TCP/UDP/SCTP"] ||
	    ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "explicit-proxy" 0 "enable"] } {
		return 1
	} elseif { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "SOCKS-UDP"] } {
		return 1
	}
	return 0
}
return 0
	%}
        "firewall service custom icmptype" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "ICMP"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "ICMP6"]
        %}
	"firewall service custom icmpcode" = %{
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set icmptype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "icmptype"]
if { [cli_is_unset $CLI_CUR_PARENT_NODE "" "" "icmptype"] || $icmptype eq "" } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "ICMP"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "ICMP6"]
	%}
	"firewall ldb-monitor {http-get http-match}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "http"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "https"]
	%}
	"firewall vip portforward" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "server-load-balance"]
        %}
	"firewall vip mappedip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "server-load-balance"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "fqdn"]
        %}
	"firewall vip mapped-addr" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fqdn"]
	%}
	"firewall {vip vip6} {server-type monitor}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "access-proxy"]
        %}
	"firewall {vip vip6} ssl-hpkp" = %{
if { [cli_ver_start 500 6] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "server-type" 0 "https"] } {
		return 1
	}
}
return 0
	%}
	"firewall vip ssl-hsts" = %{
if { [cli_ver_start 500 6] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "server-type" 0 "https"] } {
		return 1
	}
}
return 0
	%}
	"firewall {vip vip6} {ssl-hpkp-age ssl-hpkp-primary ssl-hpkp-report-uri ssl-hpkp-include-subdomains}" = %{
if { [cli_ver_start 500 6] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "server-type" 0 "https"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssl-hpkp" 1 "disable"] } {
		return 1
	}
}
return 0
	%}
	"firewall {vip vip6} ssl-hpkp-backup" = %{
if { [cli_ver_start 500 6] } {
	set primary [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ssl-hpkp-primary"]
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "server-type" 0 "https"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssl-hpkp" 1 "disable"] && $primary ne "" } {
		return 1
	}
}
return 0
	%}
	"firewall vip {ssl-hsts-age ssl-hsts-include-subdomains}" = %{
if { [cli_ver_start 500 6] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "server-type" 0 "https"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssl-hsts" 0 "enable"] } {
		return 1
	}
}
return 0
	%}
        "firewall vip protocol" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "portforward" 0 "enable"]
        %}
        "firewall vip extport" = %{
if { [cli_ver_start 500 2] } {
	set proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
	if { $proto eq "icmp" } {
		return 0
	}
}
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set portfwd [cli_get_value $CLI_CUR_PARENT_NODE "" "" "portforward"]
set srvtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-type"]
if { [cli_ver_start 500 6] } {
	set service [cli_get_value $CLI_CUR_PARENT_NODE "" "" "service"]
	if { $portfwd eq "enable" && $service ne "" } {
		return 0
	}
}
if { $type ne "server-load-balance" && $portfwd eq "enable" } {
	return 1
}
if { $type eq "server-load-balance" && $srvtype ne "ip" } {
	return 1
}
if { $type eq "access-proxy" } {
	return 1
}
return 0
	%}
        "firewall vip mappedport" = %{
if { [cli_ver_start 500 2] } {
	set proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
	if { $proto eq "icmp" } {
		return 0
	}
}
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set portfwd [cli_get_value $CLI_CUR_PARENT_NODE "" "" "portforward"]
if { $type ne "server-load-balance" && $portfwd eq "enable" } {
	return 1
}
return 0
        %}
	   "firewall vip add-nat46-route" = %{
set nat46 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "nat46"]
if { $nat46 eq "enable" } {
	return 1
}
return 0
		%}
	"firewall vip ipv6-mappedip" = %{
set nat46 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "nat46"]
if { $nat46 eq "enable" } {
	return 1
}
return 0
	%}
	   "firewall vip ipv6-mappedport" = %{
if { [cli_ver_start 500 2] } {
	set proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
	if { $proto eq "icmp" } {
		return 0
	}
}
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set portfwd [cli_get_value $CLI_CUR_PARENT_NODE "" "" "portforward"]
set nat46 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "nat46"]
if { $type ne "server-load-balance" && $type ne "access-proxy" && $portfwd eq "enable" && $nat46 eq "enable" } {
	return 1
}
return 0
	   %}
       "firewall vip ldb-method" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"]
        %}
        "firewall vip realservers" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "type" 0 "server-load-balance"]
        %}
        "firewall vip realservers ip" = %{
if { [cli_ver_start 600 4] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "ip"] } {
		return 0
	}
}
return 1
        %}
	"firewall {vip vip6} realservers port" = %{
expr [cli_is_match [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] 0 "" "server-type" 1 "ip"]
        %}
	"firewall vip realservers weight" = %{
set vip [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]]
expr [cli_is_match $vip 0 "" "type" 0 "server-load-balance"] && [cli_is_match $vip 0 "" "ldb-method" 0 "weighted"]
	%}
	"firewall vip realservers http-host" = %{
set vip [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]]
expr [cli_is_match $vip 0 "" "type" 0 "server-load-balance"] && [cli_is_match $vip 0 "" "ldb-method" 0 "http-host"]
	%}
	"firewall vip realservers monitor" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "healthcheck" 0 "enable"]
        %}
	"firewall vip http-ip-header" = %{
if { [cli_ver_start 500 0] } {
	if { !$CLI_GLOBAL_DEV && [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
		namespace import global::inspection_mode_vdom_flow
		if { [inspection_mode_vdom_flow] } {
			return 0
		}
	}
	set srvtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-type"]
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"] &&
		($srvtype eq "http" || $srvtype eq "https") } {
		return 1;
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "http-multiplex" 0 "enable"] } {
		return 1
	}
}
return 0;
	%}
	"firewall vip {http-cookie-domain-from-host http-cookie-domain http-cookie-path http-cookie-generation http-cookie-age http-cookie-share}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "persistence" 0 "http-cookie"]
	%}
	"firewall vip https-cookie-secure" = %{
if {![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"]} {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "server-type" 0 "https"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "persistence" 0 "http-cookie"]
	%}
	"firewall vip {outlook-web-access weblogic-server websphere-server ssl-http-location-conversion}" = %{
if {![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"]} {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "server-type" 0 "https"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssl-mode" 0 "half"]
	%}
	"firewall vip ssl-server-session-state-type" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssl-mode" 0 "full"]
	%}
	"firewall vip max-embryonic-connections" = %{
if { !$CLI_GLOBAL_DEV && [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
	namespace import global::inspection_mode_vdom_flow
	if { [inspection_mode_vdom_flow] } {
		return 0
	}
}
if {![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"]} {
	return 0
}
set srvtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-type"]
if { $srvtype eq "http" || $srvtype eq "https" || $srvtype eq "ssl" || $srvtype eq "imaps" || $srvtype eq "pop3s" || $srvtype eq "smtps" } {
	return 1;
}
return 0;
	%}
	"firewall vip persistence" = %{
if { !$CLI_GLOBAL_DEV && [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
	namespace import global::inspection_mode_vdom_flow
	if { [inspection_mode_vdom_flow] } {
		return 0
	}
}
if {![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"]} {
	return 0
}
set srvtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-type"]
if { $srvtype eq "http" || $srvtype eq "https" || $srvtype eq "ssl" || $srvtype eq "imaps" || $srvtype eq "pop3s" || $srvtype eq "smtps" } {
	return 1;
}
return 0;
	%}
	"firewall vip http-multiplex" = %{
if { !$CLI_GLOBAL_DEV && [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
	namespace import global::inspection_mode_vdom_flow
	if { [inspection_mode_vdom_flow] } {
		return 0
	}
}
set srvtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-type"]
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"] && ($srvtype eq "http" || $srvtype eq "https") } {
	return 1;
}
return 0;
	%}
	"firewall {vip vip6} {ssl-send-empty-frags ssl-client-session-state-type ssl-client-renegotiation ssl-mode}" = %{
if { !$CLI_GLOBAL_DEV && [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
	namespace import global::inspection_mode_vdom_flow
	if { [inspection_mode_vdom_flow] } {
		return 0
	}
}
if {![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"]} {
	return 0
}
set srvtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-type"]
if { $srvtype eq "https" || $srvtype eq "ssl" || $srvtype eq "imaps" || $srvtype eq "pop3s" || $srvtype eq "smtps" } {
	return 1;
}
return 0;
	%}
	"firewall {vip vip6} {ssl-certificate ssl-dh-bits ssl-algorithm ssl-min-version ssl-max-version}" = %{
if { !$CLI_GLOBAL_DEV && ![cli_ver_start 600 2] } {
	namespace import global::inspection_mode_vdom_flow
	if { [inspection_mode_vdom_flow] } {
		return 0
	}
}
set srvtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-type"]
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"] } {
	if { $srvtype eq "https" || $srvtype eq "ssl" || $srvtype eq "imaps" || $srvtype eq "pop3s" || $srvtype eq "smtps" } {
		return 1
	}
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "access-proxy"] && $srvtype eq "https" } {
	return 1
}
return 0
	%}
	"firewall {vip vip6} ssl-pfs" = %{
if { !$CLI_GLOBAL_DEV && [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
	namespace import global::inspection_mode_vdom_flow
	if { [inspection_mode_vdom_flow] } {
		return 0
	}
}
if {![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"]} {
	return 0
}
set srvtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-type"]
set sslalg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ssl-algorithm"]
if { ($srvtype eq "https" || $srvtype eq "ssl" || $srvtype eq "imaps" || $srvtype eq "pop3s" || $srvtype eq "smtps") && $sslalg ne "custom" } {
	return 1;
}
return 0;
	%}
	"firewall {vip vip6} ssl-cipher-suites" = %{
set parent [cli_get_parent $CLI_CUR_PARENT_NODE]
if {![cli_is_match $parent 0 "" "type" 0 "server-load-balance"]} {
	return 0
}
set srvtype [cli_get_value $parent "" "" "server-type"]
set sslalg [cli_get_value $parent "" "" "ssl-algorithm"]
if { ($srvtype eq "https" || $srvtype eq "ssl" || $srvtype eq "imaps" || $srvtype eq "pop3s" || $srvtype eq "smtps") && $sslalg eq "custom" } {
	return 1;
}
return 0;
	%}
	"firewall vip portmapping-type" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "portforward" 0 "enable"]
        %}
	"firewall {vip vip6} ssl-server-session-state-timeout" = %{
set svrsesstype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ssl-server-session-state-type"]
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssl-mode" 0 "full"] && $svrsesstype ne "disable" && $svrsesstype ne "count" } {
	return 1;
}
return 0;
	%}
	"firewall {vip vip6} ssl-server-session-state-max" = %{
set svrsesstype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ssl-server-session-state-type"]
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssl-mode" 0 "full"] && $svrsesstype ne "disable" && $svrsesstype ne "time" } {
	return 1;
}
return 0;
	%}
	"firewall {vip vip6} ssl-client-session-state-timeout" = %{
if { !$CLI_GLOBAL_DEV && [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
	namespace import global::inspection_mode_vdom_flow
	if { [inspection_mode_vdom_flow] } {
		return 0
	}
}
if {![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"]} {
	return 0
}
set srvtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-type"]
set clsesstype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ssl-client-session-state-type"]
if { ($srvtype eq "https" || $srvtype eq "ssl" || $srvtype eq "imaps" || $srvtype eq "pop3s" || $srvtype eq "smtps") && $clsesstype ne "disable" && $clsesstype ne "count" } {
	return 1;
}
return 0;
	%}
	"firewall {vip vip6} ssl-client-session-state-max" = %{
if { !$CLI_GLOBAL_DEV && [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
	namespace import global::inspection_mode_vdom_flow
	if { [inspection_mode_vdom_flow] } {
		return 0
	}
}
if {![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "server-load-balance"]} {
	return 0
}
set srvtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-type"]
set clsesstype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ssl-client-session-state-type"]
if { ($srvtype eq "https" || $srvtype eq "ssl" || $srvtype eq "imaps" || $srvtype eq "pop3s" || $srvtype eq "smtps") && $clsesstype ne "disable" && $clsesstype ne "time" } {
	return 1;
}
return 0;
	%}
	"firewall {vip vip6} ssl-http-match-host" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssl-http-location-conversion" 0 "enable"]
        %}
	"firewall {vip46 vip64} mappedip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "server-load-balance"]
	%}
	"firewall vip6 mappedip" = %{
if { [cli_ver_start 700 0] } {
	set nat66 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "nat66"]
	if { $nat66 == 0 || $nat66 eq "" || $nat66 eq "enable" } {
		return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "server-load-balance"]]
	}
} else {
	return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "server-load-balance"]]
}
return 0;
	%}
	"firewall vip6 ipv4-mappedip" = %{
if { [cli_ver_start 700 0] } {
	set nat64 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "nat64"]
	if { $nat64 eq "enable" } {
		return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "server-load-balance"]]
	}
}
return 0;
	%}
	"firewall shaping-profile" = %{
if { $CLI_GLOBAL_DEV } {
	return 1
}
set name [cli_get_value $CLI_CUR_NODE "" "" "profile-name"]
set shaping_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall shaping-profile" $name ""]
if {[cli_is_referenced $shaping_node]} {
	return 1
}
set intflist [cli_get_match_list $CLI_GLOBAL_NODE 1 "system interface" "vdom" 0 $CLI_CUR_VDOM_NAME]
foreach intf $intflist {
	set eg [cli_get_value $intf "" "" "egress-shaping-profile"]
	if { $eg ne ""  } {
		set eg [string trim $eg \"]
		if { $eg eq $name } {
			return 1
		}
	}
	set ing [cli_get_value $intf "" "" "ingress-shaping-profile"]
	if { $ing ne ""  } {
		set ing [string trim $ing \"]
		if { $ing eq $name } {
			return 1
		}
	}
}
return 0
	%}

	"firewall shaping-policy diffservcode-forward" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "diffserv-forward" 0 "enable"]
	%}
	"firewall shaping-policy diffservcode-rev" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "diffserv-reverse" 0 "enable"]
	%}
	"firewall shaper traffic-shaper diffservcode" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "diffserv" 0 "enable"]
	%}
	"firewall shaper per-ip-shaper diffservcode-forward" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "diffserv-forward" 0 "enable"]
	%}
	"firewall shaper per-ip-shaper diffservcode-rev" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "diffserv-reverse" 0 "enable"]
	%}
        "system admin password" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wildcard" 1 "enable"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peer-auth" 1 "enable"] } {
        return 1
}
return 0
        %}
        "system admin two-factor" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wildcard" 1 "enable"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peer-auth" 1 "enable"] } {
	set factor [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $factor eq "fortitoken-cloud" } {
		if { [cli_branchpt_start 600 1010] } {
			set cloud [cli_get_value $CLI_GLOBAL_NODE "system global" "" "fortitoken-cloud"]
			if { $cloud eq "disable" } {
				return 0
			}
		} else {
			set cloud [cli_get_value $CLI_GLOBAL_NODE "system global" "" "fortitoken-cloud-service"]
			if { $cloud eq "disable" } {
				return 0
			}
		}
	}
        return 1
}
return 0
        %}
        "system admin {password-expire}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "remote-auth" 1 "enable"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peer-auth" 1 "enable"] &&
     [cli_is_match $CLI_GLOBAL_NODE 0 "system password-policy" "status" 0 "enable"] &&
     [cli_is_match $CLI_GLOBAL_NODE 0 "system password-policy" "expire-status" 0 "enable"] } {
        return 1
}
return 0
        %}
        "system admin {accprofile-override}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "remote-auth" 0 "enable"]
        %}
        "system admin peer-auth" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "remote-auth" 0 "disable"]
        %}
        "system admin peer-group" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peer-auth" 0 "enable"]
        %}
        "system admin remote-group" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "remote-auth" 0 "enable"]
        %}
        "system admin wildcard" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "remote-auth" 0 "enable"]
        %}
        "system admin radius-accprofile-override" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "remote-auth" 0 "enable"]
        %}
        "system admin radius-vdom-override" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "remote-auth" 0 "enable"]
        %}
        "system admin fortitoken" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "two-factor" 0 "fortitoken"]
        %}
        "system admin force-password-change" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peer-auth" 1 "enable"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "remote-auth" 1 "enable"] &&
     [cli_is_match $CLI_GLOBAL_NODE 0 "system password-policy" "status" 0 "enable"] } {
	return 1
}
return 0
        %}
        "system autoupdate schedule day" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "frequency" 0 "weekly"]
        %}
        "system fortiguard srv-overd-list" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srv-ovrd" 0 "enable"]
        %}
        "system fortiguard hostname" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srv-ovrd" 0 "disable"]
        %}
        "system fortiguard client-override-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "client-override-status" 0 "enable"]
        %}
        "system fortiguard central-mgmt-account-id" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "central-mgmt-status" 0 "enable"]
        %}
        "system fortiguard central-mgmt-scheduled-upgrade" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "central-mgmt-status" 0 "enable"]
        %}
        "system fortiguard central-mgmt-auto-backup" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "central-mgmt-status" 0 "enable"]
        %}
        "system ha load-balance-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "a-a"]
        %}
        "system ha schedule" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "a-a"]
        %}
        "system ha secondary-vcluster" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "vcluster2" 0 "enable"]
        %}
        "system ha weight" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "schedule" 0 "weight-round-robin"]
        %}
	"system ha vdom" = %{
if { [cli_ver_start 500 4] ||
     [cli_branchpt_start 500 643*] ||
     [cli_branchpt_start 500 294] } {
	return 0
}
namespace import global::cli_sys_global_vdom_enable
if { [cli_sys_global_vdom_enable] == 0 } { return 0 }
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 1 "standalone"]
	%}
	"system ha ha-mgmt-status" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 1 "standalone"]
	%}
	"system ha ha-mgmt-interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ha-mgmt-status" 0 "enable"]
	%}
	"system ha ha-mgmt-interface-gateway" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ha-mgmt-status" 1 "enable"] } {
	return 0
}
set intf [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ha-mgmt-interface"]
set mode [cli_get_value $CLI_GLOBAL_NODE "system interface" "$intf" "mode"]
if { $mode eq "dhcp" || $mode eq "pppoe" } {
	return 0
}
return 1
	%}
        "system ha_old secondary-vcluster" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "vcluster2" 0 "enable"]
        %}
        "system modem auto-dial" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "standalone"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dial-on-demand" 0 "disable"]
        %}
        "system modem idle-timer" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "standalone"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dial-on-demand" 0 "enable"]
	%}
        "system modem dial-on-demand" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-dial" 0 "disable"]
        %}
        "system modem interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "redundant"]
        %}
        "system modem holddown-time" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "redundant"]
        %}
        "system fortiguard-log controller-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-controller" 0 "enable"]
        %}
        "system fortiguard-log controller-port" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-controller" 0 "enable"]
        %}
        "system fm auto-backup" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log {fortianalyzer fortianalyzer2 fortianalyzer3} setting {max-buffer-size override localid conn-timeout address-mode mgmt-name use-hdd roll-schedule roll-day roll-time diskfull serial server interface-select-method}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log {fortianalyzer fortianalyzer2 fortianalyzer3} setting __change_ip" = %{
return 0
        %}
        "log {fortianalyzer fortianalyzer2 fortianalyzer3} setting enc-algorithm" = %{
if { $CLI_GLOBAL_DEV || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] } {
	return 1
}
return 0
        %}
        "log {fortianalyzer fortianalyzer2 fortianalyzer3} setting {psksecret encrypt}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 1 "enable"] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "enc-algorithm" 0 "disable"] ||
	 [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "encrypt" 0 "enable"] } {
	return 1
}
return 0
        %}
        "log {fortianalyzer fortianalyzer2 fortianalyzer3} setting {fdp-device fdp-interface}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "address-mode" 0 "auto-discovery"]
        %}
        "log {fortianalyzer fortianalyzer2 fortianalyzer3} setting interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "interface-select-method" 0 "specify"]
        %}
        "system fortianalyzer localid" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer {encrypt psksecret}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "enc-algorithm" 0 "disable"]
        %}
        "system fortianalyzer server" = %{
if { [cli_ver_start 500 0] } {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
} else {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "address-mode" 0 "static"]
}
        %}
        "system fortianalyzer ver-1" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer conn-timeout" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer address-mode" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer mgmt-name" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer __change_ip" = %{
return 0
        %}
        "system fortianalyzer use-hdd" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer roll-schedule" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer roll-day" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer roll-time" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer diskfull" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer fdp-device" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "address-mode" 0 "auto-discovery"]
        %}
        "system fortianalyzer fdp-interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "address-mode" 0 "auto-discovery"]
        %}
        "system fortianalyzer2 encrypt" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer2 localid" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer2 psksecret" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer2 server" = %{
if { [cli_ver_start 500 0] } {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
} else {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "address-mode" 0 "static"]
}
        %}
        "system fortianalyzer2 ver-1" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer2 conn-timeout" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer2 address-mode" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer2 mgmt-name" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer2 __change_ip" = %{
return 0
        %}
        "system fortianalyzer2 use-hdd" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer2 roll-schedule" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer2 roll-day" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer2 roll-time" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer2 diskfull" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer2 fdp-device" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "address-mode" 0 "auto-discovery"]
        %}
        "system fortianalyzer2 fdp-interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "address-mode" 0 "auto-discovery"]
        %}
        "system fortianalyzer3 encrypt" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer3 localid" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer3 psksecret" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer3 server" = %{
if { [cli_ver_start 500 0] } {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
} else {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "address-mode" 0 "static"]
}
        %}
        "system fortianalyzer3 ver-1" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer3 conn-timeout" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer3 address-mode" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer3 mgmt-name" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer3 __change_ip" = %{
return 0
        %}
        "system fortianalyzer3 use-hdd" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer3 roll-schedule" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer3 roll-day" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer3 roll-time" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer3 diskfull" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system fortianalyzer3 fdp-device" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "address-mode" 0 "auto-discovery"]
        %}
        "system fortianalyzer3 fdp-interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "address-mode" 0 "auto-discovery"]
        %}
        "system global restart-time" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "daily-restart" 0 "enable"]
        %}
        "system global cfg-revert-timeout" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "cfg-save" 0 "revert"]
        %}
	"system global fds-statistics-period" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fds-statistics" 0 "enable"]
	%}
	"system global admin-https-redirect" = %{
namespace import global::global_admin_https_redirected_valid
return [global_admin_https_redirected_valid]
	%}
        "system interface {username password idle-timeout ipunnumbered pppoe-unnumbered-negotoate disc-retry-timeout padt-retry-timeout}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoe"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoa"] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tunnel"] } {
		return 0
	}
	return 1
}
return 0
        %}
        "system interface distance" = %{
set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
if { !(($name eq "modem") && [cli_has_feature "f_modem"]) } {
    if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoe"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoa"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "dhcp"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tunnel"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fext-wan"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pptp-client" 0 "enable"] } {
		return 1
	}
}
return 0
        %}
        "system interface priority" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "dhcp"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoe"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoa"]
        %}
        "system interface defaultgw" = %{
if { [cli_ver_start 500 0] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dedicated-to" 0 "management"] } {
		return 1
	}
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "dhcp"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoe"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoa"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ipoa"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "eoa"] } {
	return 1
}
if { [cli_ver_start 500 2] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pptp-client" 0 "enable"] } {
		return 1
	}
}
return 0
        %}
        "system interface dns-server-override" = %{
set cur_vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vdom"]
set cur_vdom [string trim $cur_vdom \"]
set manage_vdom [cli_get_value $CLI_GLOBAL_NODE "system global" "" "management-vdom"]
set manage_vdom [string trim $manage_vdom \"]
expr ([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "dhcp"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoe"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoa"]) && (![string compare $cur_vdom $manage_vdom])
        %}
        "system interface auth-type" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoe"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoa"]
        %}
        "system interface lcp-echo-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoe"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoa"]
        %}
        "system interface lcp-max-echo-fails" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoe"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoa"]
        %}
        "system interface detected-peer-mtu" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoe"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoa"]
        %}
        "system interface gateway-address" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ipoa"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "eoa"]
        %}
	"system interface {vpi vci}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "name" 0 "adsl"] } {
	return 1
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "name" 0 "dsl"] } {
	return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "tc-mode" 0 "atm"]]
}
return 0
	%}
	"system interface mux-type" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "name" 0 "dsl"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "tc-mode" 0 "atm"] } {
	return 1
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "name" 0 "adsl"]
	%}
        "system interface connection" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ipoa"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "eoa"]
        %}
        "system interface mtu" = %{
namespace import global::sys_intf_mtu_override_visible
if { [sys_intf_mtu_override_visible $CLI_CUR_PARENT_NODE] } {
        if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mtu-override"] eq "enable" } {
		return 1
	}
}
return 0
	%}
        "system interface mtu-override" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
namespace import global::sys_intf_mtu_override_visible
if { [sys_intf_mtu_override_visible $CLI_CUR_PARENT_NODE] } {
	return 1
}
return 0
        %}
        "system interface subst" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "vlan"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "hard-switch"]
        %}
        "system interface substitute-dst-mac" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "vlan"]
        %}
        "system interface interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "vlan"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tunnel"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "vxlan"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "emac-vlan"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "geneve"]
        %}
        "system interface vlanid" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "vlan"] } {
        return 1
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "emac-vlan"] } {
        set intfintf [cli_get_value $CLI_CUR_PARENT_NODE "" "" "interface"]
        set intfintf [string trim $intfintf \"]
        set vlannode [cli_get_node $CLI_GLOBAL_NODE "system interface" $intfintf ""]
        if { $vlannode != 0 } {
            set type [cli_get_value $vlannode "" "" "type"]
            if { $type eq "vlan" } {
                return 0
            }
        }
        return 1
}
return 0
        %}
        "system interface member" = %{
if { [cli_ver_start 500 0] } {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "aggregate"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "redundant"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fortilink"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fctrl-trunk"]
} else {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "aggregate"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "redundant"]
}
        %}
        "system interface algorithm" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "aggregate"]
        %}
        "system interface lacp-mode" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "aggregate"]
        %}
        "system interface lacp-speed" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "aggregate"]
        %}
        "system interface lacp-ha-slave" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "aggregate"]
        %}
        "system interface remote-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tunnel"]
        %}
        "system interface mode" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
set iftype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $iftype == "tunnel" } {
	set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	set pppif [cli_get_node $CLI_CUR_VDOM_NODE "system pppoe-interface" $ifname ""]
	if { $pppif == 0 } {
		return 0
	}
}
if { $iftype == "vdom-link" || $iftype == "loopback"} {
	return 0
}
return 1
        %}
        "system interface wifi-ssid" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "wireless"]
        %}
        "system interface wifi-security" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "wireless"]
        %}
        "system interface wifi-broadcast-ssid" = %{
set wlmode [cli_get_value $CLI_GLOBAL_NODE "system wireless settings" "" "mode"]
if { $wlmode != 0 && $wlmode ne "AP" && $wlmode ne ""  } {
        return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "wireless"]
        %}
        "system interface wifi-fragment-threshold" = %{
set wlmode [cli_get_value $CLI_GLOBAL_NODE "system wireless settings" "" "mode"]
if { $wlmode != 0 && $wlmode ne "AP" && $wlmode ne ""  } {
        return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "wireless"]
        %}
        "system interface wifi-rts-threshold" = %{
set wlmode [cli_get_value $CLI_GLOBAL_NODE "system wireless settings" "" "mode"]
if { $wlmode != 0 && $wlmode ne "AP" && $wlmode ne ""  } {
        return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "wireless"]
        %}
        "system interface wifi-mac-filter" = %{
set wlmode [cli_get_value $CLI_GLOBAL_NODE "system wireless settings" "" "mode"]
if { $wlmode != 0 && $wlmode ne "AP" && $wlmode ne ""  } {
        return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "wireless"]
        %}
        "system interface wifi-acl" = %{
set wlmode [cli_get_value $CLI_GLOBAL_NODE "system wireless settings" "" "mode"]
if { $wlmode != 0 && $wlmode ne "AP" && $wlmode ne ""  } {
        return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "wireless"]
        %}
        "system interface wifi-mac-list" = %{
set wlmode [cli_get_value $CLI_GLOBAL_NODE "system wireless settings" "" "mode"]
if { $wlmode != 0 && $wlmode ne "AP" && $wlmode ne ""  } {
        return 0
}
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "type" 0 "wireless"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "name" 0 "wlan"]
        %}
        "system interface ip" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
set iftype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $iftype eq "vdom-link" || $iftype eq "physical" } {
	set vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vdom"]
        set vnode [cli_get_vdom_node $vdom]
	if { [cli_get_value $vnode "system settings" "" "opmode"] eq "transparent" } {
		return 0
	}
}
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if { $mode eq "pppoe" || $mode eq "dhcp" } {
	return 0
}
namespace import global::check_switch_intf
if {![check_switch_intf $CLI_CUR_PARENT_NODE $CLI_GLOBAL_NODE]} {
	return 0
}
if { [cli_ver_start 500 4] } {
	namespace import global::nCfg_is_port_pair_member
	if {[nCfg_is_port_pair_member $CLI_CUR_PARENT_NODE]} {
		cli_set_errmsg "interface is used by system.virtual-ware-pair"
		return 0
	}
}
return 1
        %}
        "system interface role" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system virtual-wire-pair" "member"] } {
	return 0
}
return 1
        %}
        "system interface {dhcp-relay-service dhcp-relay-ip  dhcp-relay-type dhcp-relay-agent-option}" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"] eq "modem" } {
	return 0
}
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
set t [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $t eq "vdom-link" || $t eq "loopback" } {
	return 0
}
if { $CLI_CUR_NODE_NAME eq "dhcp-relay-ip" ||
     $CLI_CUR_NODE_NAME eq "dhcp-relay-type" ||
     $CLI_CUR_NODE_NAME eq "dhcp-relay-agent-option" } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dhcp-relay-service" 1 "enable"] } {
		return 0
	}
}
return 1
        %}
        "system interface ipmac" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "adsl"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "aggregate"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "redundant"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "vlan"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "wireless"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tunnel"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "hard-switch"]
        %}
        "system interface {netbios-forward arpforward broadcast-forward ident-accept wins-ip}" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "loopback"]
        %}
        "system interface {stpforward l2forward}" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "adsl"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "aggregate"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "redundant"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "vlan"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "wireless"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tunnel"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "vdom-link"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "hard-switch"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "vxlan"]
        %}
        "system interface {gwdetect detectserver ping-serv-status}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "loopback"]
        %}
        "system interface ddns" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "adsl"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "aggregate"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "redundant"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "vlan"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "wireless"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tunnel"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "vdom-link"]
        %}
        "system interface tcp-mss" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "name" 0 "modem"] } {
	return 0
}
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "loopback"]
        %}
        "system interface l2tp-client-settings" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "l2tp-client" 0 "enable"]
        %}
        "system interface fail-detect-option" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fail-detect" 0 "enable"]
        %}
        "system interface fail-alert-method" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fail-detect" 0 "enable"]
        %}
        "system interface fail-alert-interfaces" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fail-detect" 0 "enable"]
        %}
        "system interface ddns-server" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ddns" 0 "enable"]
        %}
        "system interface ddns-domain" = %{
set ddns [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ddns"]
set ds [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ddns-server"]
if { $ddns ne "enable" } {
        return 0;
}
if { $ds eq "dhs.org" || $ds eq "dipdns.net" || $ds eq "dyndns.org" || $ds eq "now.net.cn" || $ds eq "ods.org" || $ds eq "tzo.com" || $ds eq "dyns.net" } {
        return 1;
}
return 0;
        %}
        "system interface ddns-profile-id" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ddns" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ddns-server" 0 "dnsart.com"]
        %}
        "system interface ddns-sn" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ddns" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ddns-server" 0 "dipdns.net"]
        %}
        "system interface ddns-key" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ddns" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ddns-auth" 0 "tsig"]
        %}
        "system interface ddns-keyname" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ddns" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ddns-auth" 0 "tsig"]
        %}
        "system interface ddns-username" = %{
set ddns [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ddns"]
set ds [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ddns-server"]
if { $ddns ne "enable" } {
	return 0;
}
if { $ds eq "dhs.org" || $ds eq "dnsart.com" || $ds eq "dyndns.org" || $ds eq "dyns.net" || $ds eq "now.net.cn" || $ds eq "ods.org" || $ds eq "tzo.com" || $ds eq "vavic.com" } {
        return 1;
}
return 0;
        %}
        "system interface ddns-password" = %{
set ddns [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ddns"]
set ds [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ddns-server"]
if { $ddns ne "enable" } {
        return 0;
}
if { $ds eq "dhs.org" || $ds eq "dnsart.com" || $ds eq "dyndns.org" || $ds eq "dyns.net" || $ds eq "now.net.cn" || $ds eq "ods.org" || $ds eq "tzo.com" || $ds eq "vavic.com" } {
        return 1;
}
return 0;
        %}
        "system interface wifi-security {WPA2 WPA2_AUTO}" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "system wireless settings" "mode" 0 "AP"]
        %}
        "system interface {wifi-key wifi-keyindex}" = %{
set ws [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wifi-security"]
if { [cli_ver_start 400 3] } {
	if { $ws eq "wep64" || $ws eq "wep128" } {
		return 1
	}
} else {
	if { $ws eq "WEP64" || $ws eq "WEP128" } {
		return 1
	}
}
return 0
        %}
        "system interface wifi-auth" = %{
if { [cli_ver_start 400 3] } {
	return 1
} else {
	set ws [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wifi-security"]
	if { $ws eq "WPA" || $ws eq "WPA2" || $ws eq "WPA2_AUTO" } {
		return 1
	}
}
return 0
        %}
        "system interface wifi-encrypt" = %{
if { [cli_ver_start 400 3] } {
	return 1
} else {
	set wlmode [cli_get_value $CLI_GLOBAL_NODE "system wireless settings" "" "mode"]
	if { $wlmode != 0 && $wlmode eq "CLIENT" } {
		return 0
	}
	set ws [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wifi-security"]
	if { $ws eq "WPA" || $ws eq "WPA2" || $ws eq "WPA2_AUTO" } {
		return 1
	}
}
return 0
        %}
        "system interface wifi-auth {RADIUS}" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "system wireless settings" "mode" 0 "AP"]
        %}
        "system interface wifi-passphrase" = %{
set ws [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wifi-security"]
if { [cli_ver_start 400 3] } {
	if { $ws eq "wpa-personal" || $ws eq "wpa-only-personal" || $ws eq "wpa2-only-personal" } {
		return 1
	}
} else {
	if { $ws eq "WPA" || $ws eq "WPA2" || $ws eq "WPA2_AUTO" } {
		set auth [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wifi-auth"]
		if { $auth eq "PSK" } {
			return 1
		}
	}
}
return 0
        %}
        "system interface wifi-radius-server" = %{
if { [cli_ver_start 400 3] } {
	set auth [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wifi-auth"]
	if { $auth eq "radius" } {
		set ws [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wifi-security"]
		if { $ws eq "wpa-enterprise" || $ws eq "wpa2-only-enterprise" } {
			return 1
		}
 	}
} else {
	set auth [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wifi-auth"]
	if { $auth eq "RADIUS" } {
		set ws [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wifi-security"]
		if { $ws eq "WPA" || $ws eq "WPA2" || $ws eq "WPA2_AUTO" } {
			return 1
		}
	}
}
return 0
	%}
        "system interface wifi-usergroup" = %{
if { [cli_ver_start 400 3] } {
	set auth [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wifi-auth"]
	if { $auth eq "usergroup" } {
		return 1
	}
}
return 0
	%}
        "system interface wifi-mac-filter status enable" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "system wireless settings" "mode" 0 "AP"]
        %}
        "system interface vdom-link vcluster" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "system wireless settings" "mode" 0 "AP"] || [cli_is_match $CLI_GLOBAL_NODE 0 "system ha" "vcluster2" 0 "enable"]
        %}
        "system interface bfd-desired-min-tx" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "bfd" 0 "enable"]
		%}
        "system interface bfd-detect-mult" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "bfd" 0 "enable"]
		%}
        "system interface bfd-required-min-rx" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "bfd" 0 "enable"]
		%}
        "system interface type" = %{
if { [cli_ver_start 500 0] } {
	return 1
}
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if {$type ne "aggregate" && $type ne "redundant"} {
	set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	if { $name eq "modem" } {
		return 1
	}

	set nodelist1 [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
	foreach node1 $nodelist1 {
        	if { [cli_if_same_node $node1 $CLI_CUR_PARENT_NODE] } {
                	continue
        	}
        	set intftype [cli_get_value $node1 "" "" "type"]
        	if {$intftype eq "aggregate" || $intftype eq "redundant"} {
			set members1 [cli_get_value $node1 "" "" "member"]
			foreach member1 $members1 {
				if {$member1 eq $name || $member1 eq "\"$name\""} {
					return 0
				}
			}
        	}
	}

	set nodelist2 [cli_get_tbl_list $CLI_GLOBAL_NODE "system switch-interface"]
	foreach node2 $nodelist2 {
		set members2 [cli_get_value $node2 "" "" "member"]
		foreach member2 $members2 {
			if {$member2 eq $name || $member2 eq "\"$name\""} {
				return 0
			}
		}
	}
}

return 1
	%}
        "system interface allowaccess" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
if { [cli_is_used $CLI_CUR_PARENT_NODE "system virtual-wire-pair" "member"] } {
	return 0
}
namespace import global::check_switch_intf
if {![check_switch_intf $CLI_CUR_PARENT_NODE $CLI_GLOBAL_NODE]} {
	return 0
}
return 1
	%}
        "system interface status" = %{
if { [cli_ver_start 500 0] } {
	return 1
}
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if {$type ne "aggregate" && $type ne "redundant"} {
	set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	set name [string trim $name \"]
	set nodelist [cli_get_tbl_list $CLI_GLOBAL_NODE "system interface"]
	foreach node $nodelist {
		if { [cli_if_same_node $node $CLI_CUR_PARENT_NODE] } {
			continue
		}
		set intftype [cli_get_value $node "" "" "type"]
		if { ($intftype eq "aggregate" || $intftype eq "redundant") } {
			set members [cli_get_value $node "" "" "member"]
			foreach member $members {
				if {$member eq $name || $member eq "\"$name\""} {
					return 0
				}
			}
		}
	}
}
namespace import global::check_switch_intf
if {![check_switch_intf $CLI_CUR_PARENT_NODE $CLI_GLOBAL_NODE]} {
	return 0
}
return 1
	%}
	"system interface listen-forticlient-connection" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
namespace import global::check_switch_intf
if {![check_switch_intf $CLI_CUR_PARENT_NODE $CLI_GLOBAL_NODE]} {
	return 0
}
return 1
	%}
	"system interface ips-sniffer-mode" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if {$type eq "physical"} {
	return 1
}
return 0
	%}
	"system interface vdom" = %{
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set name [string trim $name \"]
if { [cli_is_match $CLI_GLOBAL_NODE 0 "system ha" "ha-mgmt-status" 0 "enable"] && [cli_is_match $CLI_GLOBAL_NODE 0 "system ha" "ha-mgmt-interface" 0 "\"$name\""] } {
	return 0
}
return 1
	%}
	"system interface dedicated-to" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "static"]
	%}
	"system interface {trust-ip-1 trust-ip-2 trust-ip-3}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "static"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dedicated-to" 0 "management"]
	%}
	"system interface {autoconf bfd cli-conn-status dhcp6-relay-service drop-fragment drop-overlapped-fragmenet external fail-detect inbandwidth outbandwidth}" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
return 1
	%}
	"system interface icmp-redirect" = %{
if { [cli_branchpt_start 600 131] } {
	return 0
}
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
return 1
	%}

	"system interface {explicit-ftp-proxy explicit-web-proxy proxy-captive-portal}" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
if { [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
	set vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vdom"]
	set vnode [cli_get_vdom_node $vdom]
	set sysset [cli_get_node $vnode "system settings" "" ""]
	set insp [cli_get_value $sysset "" "" "inspection-mode"]
	if { $insp eq "flow" } {
		return 0
	}
}
if { [cli_branchpt_start 600 920] } {
	namespace import global::vdom_ngfw_mode_policy
	set vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vdom"]
	if { [vdom_ngfw_mode_policy $vdom] } {
		return 0
	}
}
return 1
	%}
	"system interface {ip6-address ip6-allowaccess ip6-extra-addr ip6-hop-limit ip6-mode ip6-reachable-time ip6-retrans-time ip6-send-adv ipv6}" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
return 1
	%}
	"system interface { dhcp6-relay-ip  dhcp6-relay-type }" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dhcp6-relay-service" 0 "enable"]
	%}
	"system interface {netflow-sampler polling-interval pptp-client sample-direction sample-rate secondary-IP security-mode sflow-sampler spillover-threshold wccp weight}" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
return 1
	%}
	"system interface security-external-web" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-mode" 0 "captive-portal"]
	%}
	"system interface vrrp-virtual-mac" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
return 1
	%}
	"system interface device-identification" = %{
set intftype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $intftype eq "vlan" || $intftype eq "aggregate" || $intftype eq "switch-vlan" } {
	return 1
}
if { $intftype eq "physical" || $intftype eq "vap-switch" || $intftype eq "wl-mesh" || $intftype eq "switch" || $intftype eq "hard-switch" || $intftype eq "fext-wan" || $intftype eq "geneve" || $intftype eq "vxlan" } {
	if { [cli_is_used $CLI_CUR_PARENT_NODE "system switch-interface" "member"] } {
		return 0
	} elseif { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
		return 0
	}
	return 1
}
return 0 
	%}
	"system interface { device-user-identification device-access-list }" = %{
	set dev_ident [cli_get_value $CLI_CUR_PARENT_NODE "" "" "device-identification"]
	if { $dev_ident ne "enable" } {
		return 0
	}
return 1
	%}
	"system interface { device-identification-active-scan device-netscan }" = %{
if { [cli_ver_start 500 4] } {
	set dev_ident [cli_get_value $CLI_CUR_PARENT_NODE "" "" "device-identification"]
	if { $dev_ident ne "enable" } {
		return 0
	}
}
return 1
	%}
	"system interface {lldp-reception lldp-transmission}" = %{
set intftype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set intfname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
if { $intftype eq "physical" || $intftype eq "vxlan" || $intftype eq "hard-switch" || $intftype eq "aggregate" || $intftype eq "redundant" || $intftype eq "switch" } {
	namespace import global::intf_used_by_composite
	if { [intf_used_by_composite $intfname] } {
		return 0
	}
	return 1
} elseif { $intftype eq "vdom-link" } {
	set name [string trim [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"] \"]
	set type [cli_get_value $CLI_GLOBAL_NODE "system vdom-link" $name "type"]
	if { $type eq "ethernet" } {
		return 1
	}
}
return 0
	%}
	"system interface fortilink-split-interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "aggregate"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fortilink" 0 "enable"]
	%}
	"system interface fortilink" = %{
set vdom [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vdom"]
set vdom [string trim $vdom \"]
set vnode [cli_get_vdom_node $vdom]
if { ![cli_is_traffic_vdom $vnode] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "static"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dedicated-to" 0 "management"] } {
	return 0
}
if { [cli_get_value $vnode "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
return 1
	%}
	"system interface ipv6 ip6-extra-addr" = %{
set node [cli_get_parent $CLI_CUR_PARENT_NODE]
expr {([cli_get_value $node "" "" "ip6-mode"] eq "static") && ([cli_get_value $node "" "" "ip6-address"] ne "::/0") && ([cli_get_value $CLI_CUR_NODE "" "" ""] ne "::/0")}
	%}
	"system interface ipv6 ip6-prefix-list" = %{
expr {[cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "ip6-send-adv"] eq "enable"}
	%}
	"system interface ipv6 ip6-delegated-prefix-list" = %{
set node [cli_get_parent $CLI_CUR_PARENT_NODE]
expr {([cli_get_value $node "" "" "ip6-send-adv"] eq "enable") && ([cli_get_value $node "" "" "ip6-upstream-interface"] ne "")}
	%}
	"system interface ipv6 {nd-cert nd-security-level nd-timestamp-delta nd-timestamp-fuzz nd-cga-modifier}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nd-mode" 0 "SEND-compatible"]
	%}
        "system probe-response port" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 1 "none"]
        %}
        "system probe-response http-probe-value" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "http-probe"]
        %}
        "system probe-response ttl-mode" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "twamp"]
        %}
        "system wireless" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 1 "system interface" "name" 0 "wlan"]
        %}
        "system wireless settings key" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "WEP64"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "WEP128"]
        %}
        "system wireless settings passphrase" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "WPA_PSK"]
        %}
        "system wireless settings radius-server" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "WPA_RADIUS"]
        %}
        "system wireless settings broadcast-ssid" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "AP"]
        %}
        "system wireless settings beacon-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "AP"]
        %}
        "system wireless settings rts-threshold" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "AP"]
        %}
        "system wireless settings fragment-threshold" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "AP"]
        %}
        "system wireless settings security WPA_PSK" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "AP"]
        %}
        "system wireless settings security WPA_RADIUS" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "AP"]
        %}
        "system wireless settings mode {Client}" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "system settings" "opmode" 0 "nat"]
        %}
        "system wireless mac-filter status enable" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "system wireless settings" "mode" 0 "AP"] && [cli_is_match $CLI_GLOBAL_NODE 0 "system wireless settings" "security" 0 "WPS_RADIUS"]
        %}
        "system wireless settings band" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "AP"]
        %}
        "system wireless settings geography" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "AP"]
        %}
        "system wireless settings channel" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "AP"]
        %}
        "system wireless settings power-level" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "AP"]
        %}
        "system wireless settings bgscan" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "AP"]
        %}
        "system wireless settings bgscan-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "AP"]
        %}
        "system wireless settings bgscan-idle" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "AP"]
        %}
        "system wireless settings rogue-scan" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "SCAN"]
        %}
        "system wireless settings rogue-scan-mac-adjacency" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "SCAN"]
        %}
        "log report period last-n" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "last-n-days"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "last-n-hours"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "last-n-weeks"]
        %}
        "log report period start" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "other"]
        %}
        "log report period end" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "other"]
        %}
        "log report schedule time" = %{
expr ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "none"]
        %}
        "log report schedule days" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "days"]
        %}
        "log report schedule dates" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dates"]
        %}
        "log report output upload-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"]
        %}
        "log report output upload-server-type" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"]
        %}
        "log report output upload-username" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"]
        %}
        "log report output upload-password" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"]
        %}
        "log report output upload-dir" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"]
        %}
        "log report output upload-gzipped" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"]
        %}
        "log report output upload-delete" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"]
        %}
        "log report customization footer" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "footer-option" 0 "custom"]
        %}
        "log syslogd setting {server port csv facility}" = %{
expr $CLI_GLOBAL_DEV || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log syslogd2 setting server" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log syslogd2 setting port" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log syslogd2 setting csv" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log syslogd2 setting facility" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log syslogd3 setting server" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log syslogd3 setting port" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log syslogd3 setting csv" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log syslogd3 setting facility" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log syslogd filter signature" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log syslogd filter anomaly" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log syslogd filter web-content" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd filter url-filter" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd filter ftgd-wf-block" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd filter ftgd-wf-allow" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd filter ftgd-wf-errors" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd filter web-filter-activex" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd filter web-filter-cookie" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd filter web-filter-applet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd filter infected" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log syslogd filter blocked" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log syslogd filter oversized" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log syslogd filter email-log-smtp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log syslogd filter email-log-pop3" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log syslogd filter email-log-imap" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log syslogd filter system" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log syslogd filter allowed" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log syslogd filter violation" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log syslogd filter other-traffic" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log syslogd filter voip-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "voip" 0 "enable"]
	%}
        "log syslogd filter im-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "im" 0 "enable"]
        %}
        "log {syslogd syslogd2 syslogd3} filter voip" = %{
if { [cli_ver_start 500 2] } {
	return 1;
} else {
	expr [cli_is_match $CLI_GLOBAL_NODE 1 "system fortianalyzer" "status" 1 "enable"]
}
return 1
        %}
        "log {syslogd syslogd2 syslogd3} setting source-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
		%}
        "log syslogd2 filter signature" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log syslogd2 filter anomaly" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log syslogd2 filter web-content" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd2 filter url-filter" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd2 filter ftgd-wf-block" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd2 filter ftgd-wf-allow" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd2 filter ftgd-wf-errors" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd2 filter web-filter-activex" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd2 filter web-filter-cookie" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd2 filter web-filter-applet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd2 filter infected" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log syslogd2 filter blocked" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log syslogd2 filter oversized" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log syslogd2 filter email-log-smtp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log syslogd2 filter email-log-pop3" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log syslogd2 filter email-log-imap" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log syslogd2 filter system" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log syslogd2 filter allowed" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log syslogd2 filter violation" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log syslogd2 filter other-traffic" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log syslogd2 filter voip-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "voip" 0 "enable"]
        %}
        "log syslogd2 filter im-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "im" 0 "enable"]
        %}
        "log syslogd3 filter signature" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log syslogd3 filter anomaly" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log syslogd3 filter web-content" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd3 filter url-filter" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd3 filter ftgd-wf-block" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd3 filter ftgd-wf-allow" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd3 filter ftgd-wf-errors" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd3 filter web-filter-activex" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd3 filter web-filter-cookie" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd3 filter web-filter-applet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log syslogd3 filter infected" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log syslogd3 filter blocked" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log syslogd3 filter oversized" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log syslogd3 filter email-log-smtp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log syslogd3 filter email-log-pop3" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log syslogd3 filter email-log-imap" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log syslogd3 filter system" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log syslogd3 filter allowed" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log syslogd3 filter violation" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log syslogd3 filter other-traffic" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log syslogd3 filter voip-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "voip" 0 "enable"]
        %}
        "log syslogd3 filter im-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "im" 0 "enable"]
        %}
        "log webtrends filter signature" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log webtrends filter anomaly" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log webstrends filter web-content" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log webstrends filter url-filter" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log webstrends  filter ftgd-wf-block" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log webtrends filter ftgd-wf-allow" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log webtrends filter ftgd-wf-errors" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log webtrends filter web-filter-activex" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log webtrends filter web-filter-cookie" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log webtrends filter web-filter-applet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log webtrends filter infected" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log webtrends filter blocked" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log webtrends filter oversized" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log webtrends filter email-log-smtp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log webtrends filter email-log-pop3" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log webtrends filter email-log-imap" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log webtrends filter system" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log webtrends filter allowed" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log webtrends filter violation" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log webtrends filter other-traffic" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log webtrends filter voip-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "voip" 0 "enable"]
        %}
        "log webtrends filter im-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "im" 0 "enable"]
        %}
        "log webtrends filter voip" = %{
if { [cli_ver_start 500 2] } {
	return 1;
} else {
	expr [cli_is_match $CLI_GLOBAL_NODE 1 "system fortianalyzer" "status" 1 "enable"]
}
        %}
        "log fortianalyzer filter signature" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log fortianalyzer filter anomaly" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log fortianalyzer filter web-content" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer filter url-filter" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer filter ftgd-wf-block" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer filter ftgd-wf-allow" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer filter ftgd-wf-errors" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer filter web-filter-activex" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer filter web-filter-cookie" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer filter web-filter-applet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer filter infected" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log fortianalyzer filter blocked" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log fortianalyzer filter oversized" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log fortianalyzer filter email-log-smtp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log fortianalyzer filter email-log-pop3" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log fortianalyzer filter email-log-imap" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log fortianalyzer filter system" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log fortianalyzer filter violation" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log fortianalyzer filter voip-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "voip" 0 "enable"]
        %}
        "log fortianalyzer filter im-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "im" 0 "enable"]
        %}
	"log {fortianalyzer fortianalyzer2 fortianalyzer3} filter voip" = %{
if { [cli_ver_start 500 2] } {
	return 1
} else {
	expr [cli_is_match $CLI_GLOBAL_NODE 1 "system fortianalyzer" "status" 1 "enable"]
}
	%}
	"log fortianalyzer filter {im traffic email virus web attack}" = %{
## 5.0 only
expr [cli_is_match $CLI_GLOBAL_NODE 1 "system fortianalyzer" "status" 1 "enable"]
	%}
        "log fortianalyzer filter {other-traffic allowed}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 1 "enable"] } {
	return 0
}
## 5.0 only
expr [cli_is_match $CLI_GLOBAL_NODE 1 "system fortianalyzer" "status" 1 "enable"]
        %}
        "log fortianalyzer2 filter signature" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log fortianalyzer2 filter anomaly" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log fortianalyzer2 filter web-content" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer2 filter url-filter" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer2 filter ftgd-wf-block" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer2 filter ftgd-wf-allow" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer2 filter ftgd-wf-errors" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer2 filter web-filter-activex" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer2 filter web-filter-cookie" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer2 filter web-filter-applet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer2 filter infected" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log fortianalyzer2 filter blocked" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log fortianalyzer2 filter oversized" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log fortianalyzer2 filter email-log-smtp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log fortianalyzer2 filter email-log-pop3" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log fortianalyzer2 filter email-log-imap" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log fortianalyzer2 filter system" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log fortianalyzer2 filter allowed" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log fortianalyzer2 filter violation" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log fortianalyzer2 filter other-traffic" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log fortianalyzer2 filter voip-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "voip" 0 "enable"]
        %}
        "log fortianalyzer2 filter im-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "im" 0 "enable"]
        %}
        "log fortianalyzer3 filter signature" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log fortianalyzer3 filter anomaly" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log fortianalyzer3 filter web-content" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer3 filter url-filter" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer3 filter ftgd-wf-block" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer3 filter ftgd-wf-allow" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer3 filter ftgd-wf-errors" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer3 filter web-filter-activex" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer3 filter web-filter-cookie" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer3 filter web-filter-applet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log fortianalyzer3 filter infected" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log fortianalyzer3 filter blocked" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log fortianalyzer3 filter oversized" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log fortianalyzer3 filter email-log-smtp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log fortianalyzer3 filter email-log-pop3" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log fortianalyzer3 filter email-log-imap" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log fortianalyzer3 filter system" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log fortianalyzer3 filter allowed" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log fortianalyzer3 filter violation" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log fortianalyzer3 filter other-traffic" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log fortianalyzer3 filter voip-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "voip" 0 "enable"]
        %}
        "log fortianalyzer3 filter im-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "im" 0 "enable"]
        %}
        "log memory filter cpu-memory-usage" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "event"] eq "disable"} {
	return 0
}
set mgmtvdom [cli_get_value $CLI_GLOBAL_NODE "system global" "" "management-vdom"]
if {$mgmtvdom eq $CLI_CUR_VDOM_NAME} {
	return 1
}
return 0
        %}
        "log memory filter signature" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log memory filter anomaly" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log memory filter web-content" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log memory filter url-filter" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log memory filter ftgd-wf-block" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log memory filter ftgd-wf-allow" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log memory filter ftgd-wf-errors" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log memory filter web-filter-activex" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log memory filter web-filter-cookie" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log memory filter web-filter-applet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log memory filter infected" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log memory filter blocked" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log memory filter oversized" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log memory filter email-log-smtp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log memory filter email-log-pop3" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log memory filter email-log-imap" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log memory filter system" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log memory filter allowed" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log memory filter violation" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log memory filter other-traffic" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log {disk memory} filter voip" = %{
if { [cli_ver_start 500 2] } {
	return 1
} else {
	expr [cli_is_match $CLI_GLOBAL_NODE 1 "system fortianalyzer" "status" 1 "enable"]
}
        %}
        "log disk filter signature" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log disk filter anomaly" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "attack" 0 "enable"]
        %}
        "log disk filter web-content" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log disk filter url-filter" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log disk filter ftgd-wf-block" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log disk filter ftgd-wf-allow" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log disk filter ftgd-wf-errors" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log disk filter web-filter-activex" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log disk filter web-filter-cookie" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log disk filter web-filter-applet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web" 0 "enable"]
        %}
        "log disk filter infected" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log disk filter blocked" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log disk filter oversized" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virus" 0 "enable"]
        %}
        "log disk filter email-log-smtp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log disk filter email-log-pop3" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log disk filter email-log-imap" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "email" 0 "enable"]
        %}
        "log disk filter system" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log disk filter allowed" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log disk filter violation" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log disk filter other-traffic" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "traffic" 0 "enable"]
        %}
        "log disk filter ipsec" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log disk filter dhcp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log disk filter ppp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log disk filter admin" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log disk filter ha" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log disk filter auth" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log disk filter pattern" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log disk filter chassis" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log disk filter sslvpn-log-auth" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log disk filter sslvpn-log-adm" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log disk filter sslvpn-log-session" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log disk filter vip-ssl" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log disk filter ldb-monitor" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log disk filter im-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "im" 0 "enable"]
        %}
        "log disk filter voip-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "voip" 0 "enable"]
        %}
	"log memory filter ipsec" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log memory filter dhcp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log memory filter ppp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log memory filter admin" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log memory filter ha" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log memory filter auth" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log memory filter pattern" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log memory filter chassis" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log memory filter sslvpn-log-auth" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log memory filter sslvpn-log-adm" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log memory filter sslvpn-log-session" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log memory filter vip-ssl" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log memory filter ldb-monitor" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 0 "enable"]
        %}
        "log memory filter im-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "im" 0 "enable"]
        %}
        "log memory filter voip-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "voip" 0 "enable"]
        %}
        "log disk setting upload-destination" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log disk setting uploadip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log disk setting uploadtype" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log disk setting uploadsched" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log disk setting uploadtime" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log disk setting upload-delete-files" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log disk setting roll-day" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "roll-schedule" 0 "weekly"]
        %}
        "log disk setting roll-time" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && ([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "roll-schedule" 0 "weekly"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "roll-schedule" 0 "daily"])
        %}
        "log disk setting max-log-file-size" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log disk setting roll-schedule" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log disk setting diskfull" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log disk setting drive-standby-time" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log disk setting uploadport" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-destination" 0 "ftp-server"]
        %}
        "log disk setting uploaduser" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-destination" 0 "ftp-server"]
        %}
        "log disk setting uploadpass" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-destination" 0 "ftp-server"]
        %}
        "log disk setting uploaddir" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-destination" 0 "ftp-server"]
        %}
        "log disk setting uploadzip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-destination" 0 "ftp-server"]
        %}
        "system alertemail {username password}" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "server"] eq ""} {
        return 0
}
return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authenticate" 0 "enable"]
        %}
        "system alertemail {authenticate port source-ip}" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "server"] eq ""} {
        return 0
}
return 1
        %}
        "system email-server {username password}" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "server"] eq ""} {
        return 0
}
return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authenticate" 0 "enable"]
        %}
        "system email-server {authenticate port source-ip source-ip6}" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "server"] eq ""} {
        return 0
}
return 1
        %}
        "alertemail setting" = %{
if { [cli_ver_start 500 0] } {
	if {[cli_get_value $CLI_GLOBAL_NODE "system email-server" "" "server"] eq ""} {
		return 0
	}
} else {
	if {[cli_get_value $CLI_GLOBAL_NODE "system alertemail" "" "server"] eq ""} {
		return 0
	}
}
return 1
        %}
        "alertemail setting email-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
        "alertemail setting FDS-license-expiring-days" = %{
set mgmtvdom [string map {"\"" ""} [cli_get_value $CLI_GLOBAL_NODE "system global" "" "management-vdom"]]
if {$mgmtvdom ne $CLI_CUR_VDOM_NAME} {
	return 0
}
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]} {
	return 1
}
return 0
        %}
        "alertemail setting local-disk-usage" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
        "alertemail setting IPS-logs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
        "alertemail setting firewall-authentication-failure-logs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
	"alertemail setting sslvpn-authentication-errors-logs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
	%}
        "alertemail setting HA-logs" = %{
set mgmtvdom [string map {"\"" ""} [cli_get_value $CLI_GLOBAL_NODE "system global" "" "management-vdom"]]
if {$mgmtvdom ne $CLI_CUR_VDOM_NAME} {
	return 0
}
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]} {
	return 1
}
return 0
        %}
        "alertemail setting IPsec-errors-logs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
        "alertemail setting FDS-update-logs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
        "alertemail setting PPP-errors-logs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
        "alertemail setting sslvpn-authentication-erros-logs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
        "alertemail setting antivirus-logs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
        "alertemail setting webfilter-logs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
        "alertemail setting configuration-changes-logs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
        "alertemail setting violation-traffic-logs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
        "alertemail setting admin-login-logs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
        "alertemail setting FDS-license-expiring-warning" = %{
set mgmtvdom [string map {"\"" ""} [cli_get_value $CLI_GLOBAL_NODE "system global" "" "management-vdom"]]
if {$mgmtvdom ne $CLI_CUR_VDOM_NAME} {
	return 0
}
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]} {
	return 1
}
return 0
        %}
        "alertemail setting local-disk-usage-warning" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
        "alertemail setting fortiguard-log-quota-warning" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "category"]
        %}
        "alertemail setting severity" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "threshold"]
        %}
        "alertemail setting emergency-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "threshold"]
        %}
        "alertemail setting alert-inerval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "threshold"]
        %}
        "alertemail setting critical-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "threshold"]
        %}
        "alertemail setting error-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "threshold"]
        %}
        "alertemail setting warning-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "threshold"]
        %}
        "alertemail setting notification-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "threshold"]
        %}
        "alertemail setting information-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "threshold"]
        %}
        "alertemail setting debug-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-mode" 0 "threshold"]
        %}
	"ips global tls-active-probe interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "interface-select-method" 0 "specify"]
	%}
	"ips global tls-active-probe {vdom source-ip source-ip6}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "interface-select-method" 1 "auto"]
	%}
	"ips settings packet-log-memory" = %{
if { [cli_get_devinfo "hdd"] eq "no" && [cli_get_devinfo "get_log_disk_info"] eq "no" } {
	return 1
}
return 0
	%}
        "router rip interface send-version2-broadcast" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "send-version" 0 "2"]
        %}
        "router multicast pim-sm-global bsr-interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "bsr-candidate" 0 "enable"]
        %}
        "router multicast pim-sm-global bsr-priority" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "bsr-candidate" 0 "enable"]
        %}
        "router multicast pim-sm-global bsr-hash" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "bsr-candidate" 0 "enable"]
        %}
        "router multicast pim-sm-global register-source-interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "register-source" 0 "interface"]
        %}
        "router multicast pim-sm-global register-source-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "register-source" 0 "ip-address"]
        %}
        "router multicast pim-sm-global spt-threshold-group" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "spt-threshold" 0 "enable"]
        %}
        "router multicast pim-sm-global ssm-range" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssm" 0 "enable"]
        %}
        "router multicast pim-sm-global cisco-register-checksum-group" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "cisco-register-checksum" 0 "enable"]
        %}
        "router multicast interface igmp immediate-leave-group" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "version" 0 "2"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "verson" 0 "3"]
        %}
        "router multicast interface igmp last-member-query-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "version" 0 "2"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "verson" 0 "3"]
        %}
        "router multicast interface igmp last-member-query-count" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "version" 0 "2"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "verson" 0 "3"]
        %}
        "router multicast interface dr-priority" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pim-mode" 0 "sparse-mode"]
        %}
        "router multicast interface rp-candidate" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pim-mode" 0 "sparse-mode"]
        %}
        "router multicast interface cisco-exclude-genid" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pim-mode" 0 "sparse-mode"]
        %}
        "router multicast interface propagation-delay" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pim-mode" 0 "dense-mode"]
        %}
        "router multicast interface state-refresh-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pim-mode" 0 "dense-mode"]
        %}
        "router multicast interface rp-candidate-group" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "rp-candidate" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pim-mode" 0 "sparse-mode"]
        %}
        "router multicast interface rp-candidate-priority" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "rp-candidate" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pim-mode" 0 "sparse-mode"]
        %}
        "router multicast interface rp-candidate-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "rp-candidate" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pim-mode" 0 "sparse-mode"]
        %}
        "router bgp graceful-restart-time" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "graceful-restart" 0 "enable"]
        %}
        "router bgp graceful-stalepath-time" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "graceful-restart" 0 "enable"]
        %}
        "router bgp graceful-update-delay" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "graceful-restart" 0 "enable"]
        %}
        "router bgp dampening-route-map" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dampening" 0 "enable"]
        %}
        "router bgp confederation-peers" = %{
set confed_id [cli_get_value $CLI_CUR_PARENT_NODE "" "" "confederation-identifier"]
if {$confed_id ne ""} {
	return 1
}
return 0
        %}
	"router bgp neighbor prefix-list-in" = %{
set distlistin [cli_get_value $CLI_CUR_PARENT_NODE "" "" "distribute-list-in"]
if {$distlistin eq ""} {
        return 1
}
return 0
	%}
        "router bgp neighbor prefix-list-out" = %{
set distlistout [cli_get_value $CLI_CUR_PARENT_NODE "" "" "distribute-list-out"]
if {$distlistout eq ""} {
        return 1
}
return 0
        %}
        "router bgp neighbor distribute-list-in" = %{
set distlistin [cli_get_value $CLI_CUR_PARENT_NODE "" "" "prefix-list-in"]
if {$distlistin eq ""} {
        return 1
}
return 0
        %}
        "router bgp neighbor distribute-list-out" = %{
set distlistout [cli_get_value $CLI_CUR_PARENT_NODE "" "" "prefix-list-out"]
if {$distlistout eq ""} {
        return 1
}
return 0
        %}
        "router bgp neighbor maximum-prefix-threshold" = %{
set maxprefix [cli_get_value $CLI_CUR_PARENT_NODE "" "" "maximum-prefix"]
if {$maxprefix ne ""} {
        return 1
}
return 0
        %}
        "router bgp neighbor maximum-prefix-warning-only" = %{
set maxprefix [cli_get_value $CLI_CUR_PARENT_NODE "" "" "maximum-prefix"]
if {$maxprefix ne ""} {
        return 1
}
return 0
        %}
        "router bgp neighbor ebgp-multihop-ttl" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ebgp-enforce-multihop" 0 "enable"]
	%}
        "router bgp neighbor default-originate-routemap" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "capability-default-originate" 0 "enable"]
	%}
	"router bgp {neighbor neighbor-group} allowas-in" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "allowas-in-enable" 0 "enable"]
	%}
	"router bgp {neighbor neighbor-group} allowas-in-vpnv4" = %{
return 0
	%}
	"router bgp {neighbor neighbor-group} allowas-in6" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "allowas-in-enable6" 0 "enable"]
	%}
        "router bgp neighbor route-reflector-client" = %{
set remoteas [cli_get_value $CLI_CUR_PARENT_NODE "" "" "remote-as"]
set as [cli_get_value $CLI_CUR_VDOM_NODE "router bgp" "" "as"]
if {$remoteas eq $as} {
        return 1
}
return 0
	%}
        "router community-list rule match" = %{
expr [cli_is_match [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] 0 "" "type" 0 "standard"]
        %}
        "router community-list rule regexp" = %{
expr [cli_is_match [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] 0 "" "type" 0 "expanded"]
        %}
	"router ospf ospf-interface md5-key" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authentication" 0 "md5"]
	%}
	"router ospf ospf-interface md5-keys" = %{
set auth [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "authentication"]
if {$auth eq "md5" || $auth eq "message-digest"} {
	return 1
}
return 0
	%}
	"router ospf ospf-interface authentication-key" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authentication" 0 "text"]
	%}
	"router ospf ospf-interface hello-interval" = %{
set hmultiplier [cli_get_value $CLI_CUR_PARENT_NODE "" "" "hello-multiplier"]
if { $hmultiplier ne 0 && $hmultiplier ne "" } {
	return 0
}
return 1
	%}
	"router ospf area virtual-link" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "type" 0 "regular"]
	%}
	"router ospf area virtual-link authentication-key" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authentication" 0 "text"]
	%}
	"router ospf area virtual-link md5-key" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authentication" 0 "md5"]
	%}
	"router ospf area type" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "id" 1 "0.0.0.0"]
	%}
	"router ospf6 area type" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "id" 1 "0.0.0.0"]
	%}
	"router route-map rule set-community-additive" = %{
set community [cli_get_value $CLI_CUR_PARENT_NODE "" "" "set-community"]
if {$community eq ""} {
	return 0
}
return 1
	%}
	"router route-map rule set-aggregator-ip" = %{
set aggas [cli_get_value $CLI_CUR_PARENT_NODE "" "" "set-aggregator-as"]
if {$aggas eq ""} {
        return 0
}
return 1
	%}
	"router route-map rule match-community-exact" = %{
set matchcommunity [cli_get_value $CLI_CUR_PARENT_NODE "" "" "match-community"]
if {$matchcommunity eq ""} {
        return 0
}
return 1
	%}
	"router static dstaddr" = %{
set dst [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dst"]
if { $dst ne "" } {
	set dstip [split $dst]
	if { [lindex $dstip 0] eq "0.0.0.0" || [lindex $dstip 1] eq "0.0.0.0" } {
		return 1
	}
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "internet-service"] ne "" } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "internet-service-custom"] ne "" } {
	return 0
}
if {[cli_obj_support "router static" "virtual-wan-link"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virtual-wan-link" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan-zone"] &&
    ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan-zone" 0 ""]} {
	return 0
}
return 1
	%}
	"router static vrf" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "blackhole" 0 "disable"] } {
	return 0
}
return 1
        %}
	"router static internet-service" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
set dst [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dst"]
if { $dst ne "" } {
	set dstip [split $dst]
	if { [lindex $dstip 0] eq "0.0.0.0" || [lindex $dstip 1] eq "0.0.0.0" } {
		return 1
	}
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dstaddr"] ne "" } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "internet-service-custom"] ne "" } {
	return 0
}
if {[cli_obj_support "router static" "virtual-wan-link"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virtual-wan-link" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan-zone"] &&
    ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan-zone" 0 ""]} {
	return 0
}
return 1
	%}
	"router static internet-service-custom" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
set dst [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dst"]
if { $dst ne "" } {
	set dstip [split $dst]
	if { [lindex $dstip 0] eq "0.0.0.0" || [lindex $dstip 1] eq "0.0.0.0" } {
		return 1
	}
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dstaddr"] ne "" } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "internet-service"] ne "" } {
	return 0
}
if {[cli_obj_support "router static" "virtual-wan-link"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virtual-wan-link" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan-zone"] &&
    ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan-zone" 0 ""]} {
	return 0
}
return 1
	%}
	"router static gateway" = %{
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "blackhole" 0 "enable"] ||
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-gateway" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "virtual-wan-link"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virtual-wan-link" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan-zone"] &&
    ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan-zone" 0 ""]} {
	return 0
}
set intf [cli_get_value $CLI_CUR_PARENT_NODE "" "" "device"]
if { $intf ne "" } {
	set type [cli_get_value $CLI_GLOBAL_NODE "system interface" "$intf" "type"]
	if { $type eq "tunnel" } {
		set vip_type [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" "$intf" "type"]
		set net_dev [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" "$intf" "net-device"]
		if { $vip_type eq "dynamic" || $net_dev eq "enable" } {
			return 1
		}
		return 0
	}
}
return 1
	%}
	"router static6 gateway" = %{
set intf [cli_get_value $CLI_CUR_PARENT_NODE "" "" "device"]
if { $intf ne "" } {
	set type [cli_get_value $CLI_GLOBAL_NODE "system interface" "$intf" "type"]
	if { $type eq "tunnel" } {
	set vip_type [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" "$intf" "type"]
	set net_dev [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" "$intf" "net-device"]
	if { $vip_type eq "dynamic" || $net_dev eq "enable" } {
		return 1
	}
		return 0
	}
}
return 1
	%}
	"router {static static6} device" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "blackhole" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "virtual-wan-link"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virtual-wan-link" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan-zone"] &&
    ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan-zone" 0 ""]} {
	return 0
}
return 1
	%}
	"router static priority" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "internet-service"] ne "" } {
	return 0
}
if {[cli_obj_support "router static" "virtual-wan-link"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virtual-wan-link" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan-zone"] &&
    ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan-zone" 0 ""]} {
	return 0
}
return 1
	%}
	"router static distance" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "internet-service"] ne "" } {
	return 0
}
return 1
	%}
	"router static blackhole" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "internet-service"] ne "" } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dynamic-gateway"] eq "enable" } {
	return 0
}
if {[cli_obj_support "router static" "virtual-wan-link"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virtual-wan-link" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan-zone"] &&
    ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan-zone" 0 ""]} {
	return 0
}
return 1
	%}
	"router static weight" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "internet-service"] ne "" } {
	return 0
}
if {[cli_obj_support "router static" "virtual-wan-link"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virtual-wan-link" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan-zone"] &&
    ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan-zone" 0 ""]} {
	return 0
}
return 1
	%}
	"router static dynamic-gateway" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "blackhole" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "virtual-wan-link"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virtual-wan-link" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan-zone"] &&
    ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan-zone" 0 ""]} {
	return 0
}
return 1
	%}
	"router static link-monitor-exempt" = %{
if {[cli_obj_support "router static" "virtual-wan-link"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virtual-wan-link" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan-zone"] &&
    ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan-zone" 0 ""]} {
	return 0
}
return 1
	%}
	"router static {virtual-wan-link sdwan sdwan-zone}" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "blackhole" 0 "enable"] ||
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-gateway" 0 "enable"] ||
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "link-monitor-exempt" 0 "enable"]} {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dstaddr"] ne "" } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "internet-service"] ne "" } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "internet-service-custom"] ne "" } {
	return 0
}
return 1
	%}
	"router policy output-device" = %{
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "permit"]} {
	return 1
}
return 0
	%}
	"router policy gateway" = %{
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "permit"]} {
	return 1
}
return 0
	%}
	"router policy start-port" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if {$protocol == 6 || $protocol == 17 || $protocol == 132} {
        return 1
}
return 0
	%}
	"router policy end-port" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if {$protocol == 6 || $protocol == 17 || $protocol == 132} {
        return 1
}
return 0
	%}
	"router policy start-source-port" = %{
if { [cli_ver_start 500 0] } {
	set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
	if {$protocol == 6 || $protocol == 17 || $protocol == 132} {
	        return 1
	}
	return 0
}
	%}
	"router policy end-source-port" = %{
if { [cli_ver_start 500 0] } {
	set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
	if {$protocol == 6 || $protocol == 17 || $protocol == 132} {
	        return 1
	}
	return 0
}
	%}
        "user group match" = %{
if { [cli_ver_start 500 2] } {
	set gr_type [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "group-type"]
	if { $gr_type ne "firewall" } {
		return 0
	}
}
return 1
        %}
        "user group ftgd-wf-ovrd-scope" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ftgd-wf-ovrd" 0 "allow"]
        %}
        "user group ftgd-wf-ovrd-type" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ftgd-wf-ovrd" 0 "allow"]
        %}
        "user group ftgd-wf-ovrd-ext" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ftgd-wf-ovrd" 0 "allow"]
        %}
        "user group ftgd-wf-ovrd-dur" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ftgd-wf-ovrd" 0 "allow"]
        %}
       "user group ftgd-wf-ovrd-dur-mode" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ftgd-wf-ovrd" 0 "allow"]
        %}
      "user group ftgd-wf-ovrd-profile" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ftgd-wf-ovrd" 0 "allow"]
        %}
        "user group sslvpn-split-tunneling" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sslvpn-tunnel" 0 "enable"]
        %}
        "user group {profile ftgd-wf-ovrd}" = %{
if { [cli_ver_start 400 3] } {
	set group_type "fsso-service"
} else {
	set group_type "directory-service"
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "firewall"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 $group_type]
        %}
        "user group sslvpn-tunnel" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-tunnel-startip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-tunnel-endip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-webapp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-http" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-telnet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-ftp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-samba" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-vnc" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-rdp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-portal-heading" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-client-check" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-cache-cleaner" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-bookmarks-group" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group redir-url" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-os-check" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "sslvpn"]
        %}
        "user group sslvpn-os-check-list" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "sslvpn-os-check" 0 "enable"]
        %}
        "user group sslvpn-os-check-list tolerance" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "check-up-to-date"]
        %}
        "user group sslvpn-os-check-list latest-patch-level" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "check-up-to-date"]
        %}
        "user group sms-custom-server" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sms-server" 0 "custom"]
        %}
        "user group sso-attribute-value" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "rsso"]
        %}
	"user radius ep-carrier-endpoint-prefix-range-min" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "endpoint-translation" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ep-carrier-endpoint-prefix" 0 "enable"]
	%}
	"user radius ep-carrier-endpoint-prefix-range-max" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "endpoint-translation" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ep-carrier-endpoint-prefix" 0 "enable"]
	%}
	"user radius ep-carrier-endpoint-prefix-string" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "endpoint-translation" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ep-carrier-endpoint-prefix" 0 "enable"]
	%}

	"user radius ep-ip-header" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "endpoint-translation" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ep-profile-query-type" 0 "extract-ip"]
	%}

	"user radius ep-missing-header-fallback" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "endpoint-translation" 0 "enable"]
	%}
	"user radius ep-carrier-endpoint-prefix" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "endpoint-translation" 0 "enable"]
	%}
	"user radius ep-profile-query-type" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "endpoint-translation" 0 "enable"]
	%}
	"user radius ep-carrier-endpoint-header" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "endpoint-translation" 0 "enable"]
	%}
	"user radius ep-carrier-endpoint-header-suppress" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "endpoint-translation" 0 "enable"]
	%}
	"user radius ep-carrier-endpoint-source" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "endpoint-translation" 0 "enable"]
	%}
	"user radius ep-carrier-endpoint-convert-hex" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "endpoint-translation" 0 "enable"]
	%}
	"user radius ep-ip-header-suppress" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "endpoint-translation" 0 "enable"]
	%}
	"user radius endpoint-translation" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"user radius dp-radius-server-port" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"user radius dp-radius-response" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"user radius dp-validate-request-secret" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"user radius dp-secret" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"user radius dp-carrier-endpoint-attribute" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"user radius dp-carrier-endpoint-block-attribute" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"user radius dp-profile-attribute" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"user radius dp-log-dyn_flags" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"user radius dp-http-header" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]  && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dp-http-header-status" 0 "enable"]
	%}
	"user radius dp-http-header-fallback" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]  && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dp-http-header-status" 0 "enable"]
	%}
	"user radius dp-http-header-suppress" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]  && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dp-http-header-status" 0 "enable"]
	%}
	"user radius dp-http-header-status" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"user radius dp-mem-percent" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"user radius dp-context-timeout" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"user radius dp-hold-time" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"user radius dp-log-period" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
	"user radius dp-profile-attribute-key" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dynamic-profile" 0 "enable"]
	%}
        "user ldap username" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "regular"]
        %}
        "user ldap password" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "regular"]
        %}
        "user ldap ca-cert" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "secure" 0 "ldaps"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "secure" 0 "starttls"]
        %}
        "user ldap group-object-filter" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-member-check" 1 "user-attr"]
        %}
        "user ldap group-search-base" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-member-check" 1 "group-object"]
        %}
        "user local ldap-server" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ldap"]
        %}
        "user local radius-server" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "radius"]
        %}
        "user local tacacs+-server" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tacacs+"]
        %}
        "user local passwd" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "password"]
        %}
        "user peer passwd" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "two-factor" 0 "enable"]
        %}
        "vpn ipsec phase1-interface remotegw-ddns" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ddns"]
        %}
        "vpn ipsec phase1-interface tunnel-search" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set netdev [cli_get_value $CLI_CUR_PARENT_NODE "" "" "net-device"]
if { [cli_branchpt_start 600 915] } {
	if { $netdev eq "disable" } {
		return 1
	}
} else {
	if { $netdev eq "disable" && $type eq "dynamic" } {
		return 1
	}
}
return 0
        %}
        "vpn ipsec phase1-interface net-device" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { ![cli_branchpt_start 600 752] } {
	if { $type ne "dynamic" } {
		return 0
	}
}
return 1
		%}
        "vpn ipsec phase1-interface {distance priority}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dynamic"] } {
	return 1
}
if { [cli_ver_start 500 4] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable"] &&
	     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "add-route" 0 "enable"] } {
		return 1
	}
} elseif { [cli_ver_start 500 0] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable"] &&
	     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg-ip-version" 0 "4"] &&
	     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "add-route" 0 "enable"] } {
		return 1
	}
}
return 0
        %}
		"vpn ipsec phase1-interface send-cert-chain" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authmethod" 0 "signature"] } {
	return 1
}
return 0
		%}
		"vpn ipsec phase1-interface cert-id-validation" = %{
			set authmethod [cli_get_value $CLI_CUR_PARENT_NODE "" "" "authmethod"]
			if { authmethod ne "signature" } {
				return 0
			}
			return 1
		%}
		"vpn ipsec phase1-interface loopback-asymroute" = %{
			set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
			set sysitf_node [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
			if { $sysitf_node != 0 } {
				set type [cli_get_value $sysitf_node "" "" "type"]
				if { $type ne "loopback"} {
					return 0
				}
				return 1
			}
			return 0
		%}
        "vpn ipsec phase1-interface default-gw" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dynamic"]
        %}
        "vpn ipsec phase1-interface default-gw-priority" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dynamic"]
        %}
        "vpn ipsec phase1-interface type {ddns}" = %{
if { [cli_ver_start 600 4] } {
	return 1
} elseif { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"] } {
	return 1
}
return 0
        %}
        "vpn ipsec {phase1 phase1-interface} {dpd-retrycount dpd-retryinterval}" = %{
if { [cli_ver_start 600 4] } {
	if { ![cli_branchpt_start 700 410] || [cli_ver_start 700 2] } {
		set cs [cli_get_tbl_list $CLI_GLOBAL_NODE "system cluster-sync"]
		foreach c $cs {
			if { [cli_get_value $c "" "" "ipsec-tunnel-sync"] eq "enable" } {
				set svd [cli_get_value $c "" "" "syncvd"]
				set svd [split [string map {\" ""} $svd]]
				if { [lsearch $svd $CLI_CUR_VDOM_NAME] != -1 || $svd eq "" } {
					return 0
				}
			}
		}
	}
}
if { [cli_ver_start 500 4] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dpd" 0 "disable"] } {
		return 0
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dpd" 1 "enable"] } {
		return 0
	}
}
return 1
        %}
		"vpn ipsec {phase1 phase1-interface} dpd" = %{
if { [cli_ver_start 600 4] } {
	if { ![cli_branchpt_start 700 410] || [cli_ver_start 700 2] } {
		set cs [cli_get_tbl_list $CLI_GLOBAL_NODE "system cluster-sync"]
		foreach c $cs {
			if { [cli_get_value $c "" "" "ipsec-tunnel-sync"] eq "enable" } {
				set svd [cli_get_value $c "" "" "syncvd"]
				set svd [split [string map {\" ""} $svd]]
				if { [lsearch $svd $CLI_CUR_VDOM_NAME] != -1 || $svd eq "" } {
					return 0
				}
			}
		}
	}
}
return 1
		%}
        "vpn ipsec {phase1 phase1-interface} interface" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
        %}
        "vpn ipsec phase1-interface keepalive" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nattraversal" 0 "enable"]
        %}
        "vpn ipsec {phase1 phase1-interface} psksecret" = %{
if { [cli_ver_start 500 6] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authmethod" 0 "psk"] } {
		set peertype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "peertype"]
		if { $peertype eq "dialup" } {
			return 0
		}
		return 1
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authmethod" 0 "psk"] } {
		return 1
	}
}
return 0
        %}
        "vpn ipsec phase1-interface authmethod-remote" = %{
expr ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "1"]
        %}
        "vpn ipsec {phase1 phase1-interface} psksecret-remote" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 1 "1" "authmethod-remote" 0 "psk"]
        %}
        "vpn ipsec phase1-interface certificate" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authmethod" 0 "signature"]
        %}
        "vpn ipsec phase1-interface rsa-certificate" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authmethod" 0 "rsa-signature"]
        %}
        "vpn ipsec phase1-interface usrgrp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peertype" 0 "dialup"]
        %}
        "vpn ipsec phase1-interface peer" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peertype" 0 "peer"]
        %}
        "vpn ipsec phase1-interface peergrp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peertype" 0 "peergrp"]
        %}
        "vpn ipsec phase1-interface peerid" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peertype" 0 "one"]
        %}
	"vpn ipsec phase1-interface xauthtype" = %{
expr ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "2"]
	%}
	"vpn ipsec phase1-interface authusrgrp" = %{
set ikeversion [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ike-version"]
set xauthtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "xauthtype"]
set eap [cli_get_value $CLI_CUR_PARENT_NODE "" "" "eap"]
set grp_auth [cli_get_value $CLI_CUR_PARENT_NODE "" "" "group-authentication"]
if {($ikeversion == 1 && ($xauthtype eq "pap" || $xauthtype eq "chap" || $xauthtype eq "auto")) || ($ikeversion == 2 && ($eap eq "enable" || $grp_auth eq "enable"))} {
	return 1
}
return 0
        %}
        "vpn ipsec phase1-interface authusr" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "xauthtype" 0 "client"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "1"]
        %}
        "vpn ipsec phase1-interface authpasswd" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "xauthtype" 0 "client"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "1"]
        %}
        "vpn ipsec phase1-interface local-gw" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"]
        %}
        "vpn ipsec phase1-interface remote-gw" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "static"]
	%}
        "vpn ipsec phase1-interface local-gw6" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "6"]
        %}
        "vpn ipsec phase1-interface remote-gw6" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "6"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "static"]
        %}
        "vpn ipsec phase1-interface ip-version {6}" = %{
if { [cli_ver_start 600 4] } {
	return 1
} elseif { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dynamic"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "static"] } {
	return 1
}
return 0
        %}
        "vpn ipsec phase1-interface add-gw-route" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "dynamic"]
        %}
        "vpn ipsec {phase1 phase1-interface} {ipv4-start-ip ipv4-end-ip ipv6-start-ip ipv6-end-ip}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic" "assign-ip" 0 "enable" "assign-ip-from" 0 "range"]
        %}
	"vpn ipsec {phase1 phase1-interface} {ipv4-exclude-range ipv6-exclude-range}" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic" "assign-ip" 0 "enable" "assign-ip-from" 0 "range"]
        %}
	"vpn ipsec {phase1 phase1-interface} {ipv4-netmask ipv6-prefix ipv4-wins-server1 ipv4-wins-server2}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic" "assign-ip" 0 "enable" "assign-ip-from" 1 "dhcp"]
        %}
	"vpn ipsec {phase1 phase1-interface} {ipv4-name ipv6-name}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic" "assign-ip" 0 "enable" "assign-ip-from" 0 "name"]
        %}
	"vpn ipsec {phase1 phase1-interface} {dhcp-ra-giaddr dhcp6-ra-linkaddr}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic" "assign-ip" 0 "enable" "assign-ip-from" 0 "dhcp"]
        %}
	"vpn ipsec phase1-interface unity-support" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "1"]
        %}
	"vpn ipsec phase1-interface domain" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "unity-support" 0 "enable" "type" 0 "dynamic"]
        %}
	"vpn ipsec phase1-interface banner" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "unity-support" 0 "enable" "type" 0 "dynamic"]
        %}
	"vpn ipsec phase1-interface dns-mode" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic"]
        %}
	"vpn ipsec phase1-interface ipv4-dns-server1" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "dns-mode" 1 "auto" "ip-version" 0 4 "assign-ip-from" 1 "dhcp"]
        %}
	"vpn ipsec phase1-interface ipv4-dns-server2" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "dns-mode" 1 "auto" "ip-version" 0 4 "assign-ip-from" 1 "dhcp"]
        %}
	"vpn ipsec phase1-interface ipv4-dns-server3" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "dns-mode" 1 "auto" "ip-version" 0 4 "assign-ip-from" 1 "dhcp"]
        %}
	"vpn ipsec phase1-interface idle-timeoutinterval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "idle-timeout" 0 "enable"]
        %}
	"vpn ipsec phase1-interface assign-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic"]
        %}
	"vpn ipsec phase1-interface mode-cfg-allow-client-selector" = %{
if { [cli_ver_start 700 2] } {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 1 "dynamic" "assign-ip" 0 "enable"]
} else {
	return 0
}
        %}
        "vpn ipsec {phase1 phase1-interface} assign-ip-from" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic" "assign-ip" 0 "enable"]
        %}
        "vpn ipsec phase1-interface assign-ip-from usrgrp" = %{
if { ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic" "assign-ip" 0 "enable"] } {
	return 0
}
if { [cli_ver_start 500 4] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "2" "eap" 0 "enable"]
		|| [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "2" "group-authentication" 0 "enable"]} {
		return 1
	} else {
		set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "xauthtype"]
		if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "1"] &&
		     ($type eq "pap" || $type eq "chap" || $type eq "auto") } {
			return 1
		}
	}
} elseif { [cli_ver_start 500 2] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "2" "eap" 0 "enable"] } {
		return 1
	} else {
		set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "xauthtype"]
		if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "1" "mode-cfg-ip-version" 0 "4"] &&
		     ($type eq "pap" || $type eq "chap" || $type eq "auto") } {
			return 1
		}
	}
} elseif { [cli_ver_start 500 0] } {
	set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "xauthtype"]
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg-ip-version" 0 "4"] &&
	     ($type eq "pap" || $type eq "chap" || $type eq "auto") } {
		return 1
	}
}
return 0
        %}
        "vpn ipsec {phase1 phase1-interface} mode" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "1"]
        %}
        "vpn ipsec phase1-interface exchange-interface-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-discovery-sender" 0 "disable" "auto-discovery-receiver" 0 "disable" "auto-discovery-forwarder" 0 "disable"]
        %}
        "vpn ipsec phase1 remote-gw" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "static"]
        %}
        "vpn ipsec phase1 remotegw-ddns" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ddns"]
        %}
        "vpn ipsec phase1 distance" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dynamic"]
        %}
        "vpn ipsec phase1 priority" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dynamic"]
        %}
        "vpn ipsec phase1 keepalive" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nattraversal" 0 "enable"]
        %}
        "vpn ipsec phase1 certificate" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authmethod" 0 "signature"]
        %}
        "vpn ipsec phase1 rsa-certificate" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authmethod" 0 "rsa-signature"]
        %}
        "vpn ipsec phase1 usrgrp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peertype" 0 "dialup"]
        %}
        "vpn ipsec phase1 peer" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peertype" 0 "peer"]
        %}
        "vpn ipsec phase1 peergrp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peertype" 0 "peergrp"]
        %}
        "vpn ipsec phase1 peerid" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peertype" 0 "one"]
        %}
		"vpn ipsec phase1 xauthtype" = %{
expr ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "2"]
        %}
        "vpn ipsec phase1 authusrgrp" = %{
set ikeversion [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ike-version"]
set xauthtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "xauthtype"]
set eap [cli_get_value $CLI_CUR_PARENT_NODE "" "" "eap"]
set grp_auth [cli_get_value $CLI_CUR_PARENT_NODE "" "" "group-authentication"]
if {($ikeversion == 1 && ($xauthtype eq "pap" || $xauthtype eq "chap" || $xauthtype eq "auto")) || ($ikeversion == 2 && ($eap eq "enable" || $grp_auth eq "enable"))} {
	return 1
}
return 0
        %}
        "vpn ipsec phase1 authusr" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "xauthtype" 0 "client"]
        %}
        "vpn ipsec phase1 authpasswd" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "xauthtype" 0 "client"]
        %}
        "vpn ssl web favorite url" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "apptype" 0 "web"]
        %}
        "vpn ssl web favorite host" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "apptype" 0 "rdp"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "apptype" 0 "telnet"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "apptype" 0 "vnc"]
        %}
        "vpn ssl web favorite folder" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "apptype" 0 "smb"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "apptype" 0 "ftp"]
        %}
        "vpn ipsec manualkey enckey" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "encryption" 1 "null"]
        %}
        "vpn ipsec manualkey authkey" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authentication" 1 "null"]
        %}
        "vpn ipsec manualkey-interface auth-key" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth-alg" 1 "null"]
        %}
        "vpn ipsec manualkey-interface enc-key" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "enc-alg" 1 "null"]
        %}
        "vpn ipsec manualkey-interface local-gw6" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "6"]
        %}
        "vpn ipsec manualkey-interface remote-gw6" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "6"]
        %}
        "vpn ipsec manualkey-interface local-gw" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"]
        %}
        "vpn ipsec manualkey-interface remote-gw" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"]
        %}
        "vpn pptp usrgrp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "vpn pptp eip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "vpn pptp sip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "vpn ipsec phase2 keylifeseconds" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "keylife-type" 0 "seconds"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "keylife-type" 0 "both"]
        %}
        "vpn ipsec phase2 keylifekbs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "keylife-type" 0 "kbs"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "keylife-type" 0 "both"]
        %}
        "vpn ipsec phase2 src-subnet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "src-addr-type" 0 "subnet"]
        %}
        "vpn ipsec phase2 src-start-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "src-addr-type" 0 "range"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "src-addr-type" 0 "ip"]
        %}
        "vpn ipsec phase2 auto-negotiate" = %{
set gw [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phase1name"]
set gw [string trim $gw \"]
set gwtype [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1" $gw "type"]
if { $gwtype ne "dynamic" } {
	return 1
}
return 0
        %}
        "vpn ipsec phase2 src-end-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "src-addr-type" 0 "range"]
        %}
        "vpn ipsec phase2 src-name" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "src-addr-type" 0 "name"]
        %}
        "vpn ipsec phase2 src-subnet6" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "src-addr-type" 0 "subnet6"]
        %}
        "vpn ipsec phase2 src-start-ip6" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "src-addr-type" 0 "range6"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "src-addr-type" 0 "ip6"] } {
	return 1
}
return 0
        %}
        "vpn ipsec phase2 src-end-ip6" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "src-addr-type" 0 "range6"]
        %}
        "vpn ipsec phase2 dst-subnet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dst-addr-type" 0 "subnet"]
        %}
        "vpn ipsec phase2 dst-start-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dst-addr-type" 0 "range"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dst-addr-type" 0 "ip"]
        %}
        "vpn ipsec phase2 dst-end-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dst-addr-type" 0 "range"]
        %}
        "vpn ipsec phase2 dst-name" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dst-addr-type" 0 "name"]
        %}
        "vpn ipsec phase2 dst-subnet6" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dst-addr-type" 0 "subnet6"]
        %}
        "vpn ipsec phase2 dst-start-ip6" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dst-addr-type" 0 "range6"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dst-addr-type" 0 "ip6"] } {
	return 1
}
return 0
        %}
        "vpn ipsec phase2 dst-end-ip6" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dst-addr-type" 0 "range6"]
        %}
         "vpn ipsec phase2-interface keylifeseconds" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "keylife-type" 0 "seconds"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "keylife-type" 0 "both"]
        %}
        "vpn ipsec phase2-interface auto-negotiate" = %{
set gw [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phase1name"]
set gw [string trim $gw \"]
set gwtype [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $gw "type"]
if { $gwtype ne "dynamic" } {
	return 1
}
return 0
        %}

        "vpn ipsec phase2-interface keylifekbs" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "keylife-type" 0 "kbs"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "keylife-type" 0 "both"]
        %}
         "vpn ipsec phase2-interface {src-addr-type dst-addr-type}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "encapsulation" 1 "transport-mode"]
        %}
         "vpn ipsec phase2-interface l2tp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "encapsulation" 0 "transport-mode"]
        %}
        "vpn ipsec phase2-interface {protocol src-subnet src-subnet6 src-name src-name6 src-port src-start-ip src-start-ip6 src-end-ip src-end-ip6}" = %{
set encap [cli_get_value $CLI_CUR_PARENT_NODE "" "" "encapsulation"]
if { $encap eq "transport-mode" } {
	if {$CLI_CUR_NODE_NAME ne "protocol" && $CLI_CUR_NODE_NAME ne "src-port"} {
		return 0
	}
}
set atype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "src-addr-type"]
if { $CLI_CUR_NODE_NAME eq "src-subnet" && $atype ne "subnet" } {
	return 0
} elseif { $CLI_CUR_NODE_NAME eq "src-subnet6" && $atype ne "subnet6" } {
	return 0
} elseif { $CLI_CUR_NODE_NAME eq "src-start-ip" && $atype ne "range" && $atype ne "ip" } {
	return 0
} elseif { $CLI_CUR_NODE_NAME eq "src-end-ip" && $atype ne "range" } {
	return 0
} elseif { $CLI_CUR_NODE_NAME eq "src-start-ip6" && $atype ne "range6" && $atype ne "ip6" } {
	return 0
} elseif { $CLI_CUR_NODE_NAME eq "src-end-ip6" && $atype ne "range6" } {
	return 0
} elseif { $CLI_CUR_NODE_NAME eq "src-name" && $atype ne "name" } {
	return 0
} elseif { $CLI_CUR_NODE_NAME eq "src-name6" && $atype ne "name6" } {
	return 0
}
set gw [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phase1name"]
set gw [string trim $gw \"]
set gwtype [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $gw "type"]
if { $gwtype eq "dynamic" } {
	return 1
}
set gwmode [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $gw "mode-cfg"]
if { $gwmode eq "enable" } {
	set assign_ip [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $gw "assign-ip"]
	if { $assign_ip eq "enable" } {
		if { [cli_ver_start 700 2] } {
			set allow_selector [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $gw "mode-cfg-allow-client-selector"]
			if { $allow_selector eq "disable" } {
				return 0
			}
		} else {
			return 0
		}
	}
}
return 1
        %}
        "vpn ipsec phase2-interface {dst-subnet dst-start-ip dst-start-ip6 dst-end-ip dst-end-ip6 dst-subnet6 dst-port dst-name dst-name6}" = %{
set encap [cli_get_value $CLI_CUR_PARENT_NODE "" "" "encapsulation"]
if { $encap eq "transport-mode" && $CLI_CUR_NODE_NAME ne "dst-port"} {
	return 0
}
set atype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dst-addr-type"]
if { $CLI_CUR_NODE_NAME eq "dst-subnet" && $atype ne "subnet" } {
	return 0
} elseif { $CLI_CUR_NODE_NAME eq "dst-subnet6" && $atype ne "subnet6" } {
	return 0
} elseif { $CLI_CUR_NODE_NAME eq "dst-start-ip" && $atype ne "range" && $atype ne "ip" } {
	return 0
} elseif { $CLI_CUR_NODE_NAME eq "dst-end-ip" && $atype ne "range" } {
	return 0
} elseif { $CLI_CUR_NODE_NAME eq "dst-name" && $atype ne "name" } {
	return 0
} elseif { $CLI_CUR_NODE_NAME eq "dst-name6" && $atype ne "name6" } {
	return 0
} elseif { $CLI_CUR_NODE_NAME eq "dst-start-ip6" && $atype ne "range6" && $atype ne "ip6" } {
	return 0
} elseif { $CLI_CUR_NODE_NAME eq "dst-end-ip6" && $atype ne "range6" } {
	return 0
}
set gw [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phase1name"]
set gw [string trim $gw \"]
set gwtype [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $gw "type"]
if { $gwtype eq "dynamic" } {
	return 1
}
set gwmode [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $gw "mode-cfg"]
if { $gwmode eq "enable" } {
	if { [cli_ver_start 700 2] } {
		set assign_ip [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $gw "assign-ip"]
		set allow_selector [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $gw "mode-cfg-allow-client-selector"]
		if { $assign_ip eq "enable" && $allow_selector eq "enable" } {
			return 1
		} else {
			return 0
		}
	} else {
		return 0
	}
}
return 1
        %}
        "vpn ipsec phase2-interface dhgrp" = %{
set gw [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phase1name"]
set gw [string trim $gw \"]
set gwnode [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $gw ""]
if { [cli_ver_start 500 4] } {
	expr [cli_is_match $gwnode 0 "" "suite-b" 0 "disable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pfs" 0 "enable"]
} else {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pfs" 0 "enable"]
}
	%}
        "vpn ipsec phase2 dhcp-ipsec" = %{
set gw [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phase1name"]
set gw [string trim $gw \"]
set gwtype [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1" $gw "type"]
set opmode [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"]
if { $opmode ne "transparent" && $gwtype eq "dynamic" } {
	return 1
}
return 0
        %}
        "vpn ipsec phase2 selector-match" = %{
set gw [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phase1name"]
set gw [string trim $gw \"]
set gwtype [cli_get_value $CLI_CUR_VDOM_NODE "vpn ipsec phase1" $gw "type"]
if {$gwtype ne "dynamic"} {
	return 1
}
return 0
        %}
        "vpn ipsec phase2 dhgrp" = %{
set gw [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phase1name"]
set gw [string trim $gw \"]
set gwnode [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1" $gw ""]
if { [cli_ver_start 500 4] } {
	expr [cli_is_match $gwnode 0 "" "suite-b" 0 "disable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pfs" 0 "enable"]
} else {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pfs" 0 "enable"]
}
	%}
       "vpn l2tp usrgrp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
       "webfilter profile post-action" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"] ne "dns"} {
	return 1;
}
return 0;
        %}
       "webfilter profile options" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"] ne "dns"} {
	return 1;
}
return 0;
        %}
       "webfilter profile https-replacemsg" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"] ne "dns"} {
	return 1;
}
return 0;
        %}
       "webfilter profile ftgd-wf" = %{
namespace import global::ngfw_mode_policy
if { [cli_branchpt_start 600 1700] && [ngfw_mode_policy] } {
	return 0
}
return 1
        %}
       "webfilter profile {ovrd-perm web-ftgd-err-log}" = %{
namespace import global::ngfw_mode_policy
if { [cli_branchpt_start 600 1700] && [ngfw_mode_policy] } {
	return 0
}
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"] ne "dns"} {
	return 1;
}
return 0;
        %}
        "webfilter profile web-filter-sdns-action" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"] ne "dns"} {
	return 0;
}
return 1;
        %}
       "webfilter profile wisp-servers" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wisp" 0 "enable"]
        %}
       "webfilter ftgd-ovrd user" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "scope" 0 "user"]
        %}
       "webfilter ftgd-ovrd user-group" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "scope" 0 "user-group"]
        %}
       "webfilter ftgd-ovrd ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "scope" 0 "ip"]
        %}
       "webfilter ftgd-ovrd profile" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "scope" 0 "profile"]
        %}
       "webfilter ftgd-ovrd rating" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "rating"]
        %}
       "webfilter ftgd-ovrd url" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dir"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "domain"]
        %}
       "webfilter fortiguard cache-ttl" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "cache-mode" 0 "ttl"]
        %}
        "vpn certificate crl ldap-username" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "ldap-server"] ne ""} {
        return 1;
}
return 0;
        %}
	"dlp rule sub-protocol" = %{
set p [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if {$p eq "http" || $p eq "ftp" || $p eq "im" || $p eq "email" || $p eq "session-ctrl"} {
	return 1;
}
return 0;
	%}
	"dlp rule sub-protocol {http-get http-post https-get https-post}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "http"]
	%}
	"dlp rule sub-protocol {ftp-get ftp-put ftps-get ftps-put}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "ftp"]
	%}
	"dlp rule sub-protocol {aim icq msn ym}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "im"]
	%}
	"dlp rule sub-protocol {smtp imap pop3 smtps imaps pop3s}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "email"]
	%}
	"dlp rule sub-protocol {sip simple sccp}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "session-ctrl"]
	%}
	"dlp rule field {user user-group transfer-size encrypted file-type regexp file-size}" = %{
if { [cli_has_feature "f_ssl_proxy"] } {
	return 1
}
set proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if {$proto ne "https" && $proto ne "all"} {
	return 1
}
return 0
	%}
	"dlp rule field {subject receiver attachment-size attachment-type attachment-text}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "email"]
	%}
	"dlp rule field {url cookie-content cgi-parameters header hostname}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "http"]
	%}
	"dlp rule field {field}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "ftp"]
	%}
	"dlp rule field {body}" = %{
set proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if {$proto eq "email" || $proto eq "http" || $proto eq "nntp"} {
	return 1
}
return 0
	%}
	"dlp rule field {server}" = %{
set proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if {$proto eq "ftp" || $proto eq "nntp"} {
	return 1
}
return 0
	%}
	"dlp rule field {sender}" = %{
set proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if {$proto eq "email" || $proto eq "im"} {
	return 1
}
return 0
	%}
	"dlp rule field {file-pattern file-bytes}" = %{
set proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if {$proto eq "email" || $proto eq "http" || $proto eq "ftp" || $proto eq "nntp" || $proto eq "im"} {
	return 1
}
return 0
	%}
	"dlp rule field {file-text}" = %{
set proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if {$proto eq "ftp" || $proto eq "nntp" || $proto eq "im"} {
	return 1
}
return 0
	%}
	"dlp rule field {fingerprint}" = %{
if { [cli_has_feature "f_dlp_fingerprint"] } {
	set hdd [cli_get_devinfo "hdd"]
	if {$hdd eq "yes"} {
		return 1
	}
}
return 0
	%}
        "dlp rule {regexp regexp-negated regexp-wildcard regexp-utf8}" = %{
set field [cli_get_value $CLI_CUR_PARENT_NODE "" "" "field"]
if {$field eq "body" || $field eq "subject" || $field eq "sender" || $field eq "receiver" || $field eq "attachment-text" || $field eq "url" || $field eq "cookie-content" || $field eq "cgi-parameters" || $field eq "hostname" || $field eq "file-text" || $field eq "regexp"} {
        return 1;
}
return 0;
        %}
        "dlp rule value" = %{
set field [cli_get_value $CLI_CUR_PARENT_NODE "" "" "field"]
if {$field eq "attachment-size" || $field eq "transfer-size" || $field eq "file-size"} {
	return 1;
}
return 0;
        %}
        "dlp rule operator" = %{
set field [cli_get_value $CLI_CUR_PARENT_NODE "" "" "field"]
if {$field eq "attachment-size" || $field eq "transfer-size"} {
	return 1;
}
return 0;
        %}
        "dlp rule {file-type file-type-negated}" = %{
set field [cli_get_value $CLI_CUR_PARENT_NODE "" "" "field"]
if {$field eq "attachment-size" || $field eq "file-type"} {
	return 1;
}
return 0;
        %}
        "dlp rule {http-header-field http-header-pattern http-header-negated http-header-wildcard http-header-utf8}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "field" 0 "header"]
        %}
        "dlp rule {ip-range-start ip-range-end}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "field" 0 "server"]
        %}
        "dlp rule {file-pattern file-pattern-negated}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "field" 0 "file-pattern"]
        %}
        "dlp rule {string string-negated}" = %{
set field [cli_get_value $CLI_CUR_PARENT_NODE "" "" "field"]
if {$field eq "user" || $field eq "user-group"} {
	return 1;
}
return 0;
	%}
        "dlp rule negated" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "field" 0 "encrypted"]
        %}
        "dlp rule {file-bytes file-byte-offset file-byte-hex file-byte-negated}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "field" 0 "file-bytes"]
	%}
        "dlp rule {sensitivity match-percentage}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "field" 0 "fingerprint"]
	%}
        "dlp rule file-scan" = %{
set field [cli_get_value $CLI_CUR_PARENT_NODE "" "" "field"]
if {$field eq "subject" || $field eq "sender" || $field eq "receiver" || $field eq "url" || $field eq "cookie-content" || $field eq "cgi-parameters" || $field eq "header" || $field eq "hostname" || $field eq "server" || $field eq "user" || $field eq "user-group" || $field eq "encrypted" || $field eq "always"} {
        return 0;
}
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if { $field eq "body" && $protocol ne "http" } {
	return 0;
}
if { $field eq "transfer-size" && $protocol ne "http" && $protocol ne "ftp"} {
	return 0;
}
return 0;
        %}
	"wanopt webcache cache-exemption-list" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "cache-exemption" 0 "enable"]
	%}
        "wanopt rule auto-detect" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "full"]
        %}
        "wanopt rule peer" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "full"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-detect" 0 "off"]
        %}
        "wanopt rule transparent" = %{
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if { $mode eq "webcache-only" } {
        return 1;
}
set auto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "auto-detect"]
if { $auto eq "off" || $auto eq "active" } {
        return 1;
}
return 0;
        %}
        "wanopt rule ssl" = %{
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if { $mode eq "webcache-only" } {
        return 1;
}
set auto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "auto-detect"]
if { $auto eq "off" || $auto eq "active" } {
        return 1;
}
return 0;
        %}
        "wanopt rule proto" = %{
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if { $mode eq "webcache-only" } {
        return 0;
}
set auto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "auto-detect"]
if { $auto eq "off" || $auto eq "active" } {
        return 1;
}
return 0;
        %}
        "wanopt rule byte-caching" = %{
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if { $mode eq "webcache-only" } {
        return 0;
}
set auto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "auto-detect"]
if { $auto eq "off" || $auto eq "active" } {
        return 1;
}
return 0;
        %}
        "wanopt rule tunnel-sharing" = %{
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if { $mode eq "webcache-only" } {
        return 0;
}
set auto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "auto-detect"]
if { $auto eq "off" || $auto eq "active" } {
        return 1;
}
return 0;
        %}
        "wanopt rule secure-tunnel" = %{
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if { $mode eq "webcache-only" } {
        return 0;
}
set auto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "auto-detect"]
if { $auto eq "off" || $auto eq "active" } {
        return 1;
}
return 0;
        %}
        "wanopt rule auth-group" = %{
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if { $mode eq "webcache-only" } {
        return 0;
}
set auto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "auto-detect"]
if { $auto eq "off" || $auto eq "active" } {
        return 1;
}
return 0;
        %}
        "wanopt rule webcache" = %{
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if { $mode eq "webcache-only" } {
        return 0;
}
set auto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "auto-detect"]
if { $auto eq "passive" } {
        return 1;
}
if { $auto eq "off" && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proto" 0 "http"] } {
        return 1;
}
return 0;
        %}
        "endpoint-control settings version" = %{
 expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "enforce-minimum-version" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "version-check" 0 "minimum"]
        %}
        "endpoint-control settings download-custom-link" = %{
 expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "download-location" 0 "custom"]
        %}
        "ips sensor filter quarantine-expiry" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "quarantine" 1 "none"]
        %}
        "ips sensor override quarantine-expiry" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "quarantine" 1 "none"]
        %}
        "ips sensor entries quarantine-expiry" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "quarantine" 1 "none"]
        %}
        "ips sensor entries quarantine-log" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "quarantine" 1 "none"]
        %}
        "ips sensor entries rate-duration" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "rule"] eq ""} {
        return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "rate-count" 1 "0"]
        %}
        "ips sensor entries rate-mode" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "rule"] eq ""} {
        return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "rate-count" 1 "0"]
        %}
        "ips sensor entries rate-track" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "rule" 1 ""] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "rate-count" 1 "0"]
        %}
        "ips sensor entries os" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "rule"] ne ""} {
        return 0
}
return 1
        %}
        "ips sensor entries application" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "rule"] ne ""} {
        return 0
}
return 1
        %}
        "ips sensor entries location" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "rule"] ne ""} {
        return 0
}
return 1
        %}
        "ips sensor entries severity" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "rule"] ne ""} {
        return 0
}
return 1
        %}
        "ips sensor entries protocol" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "rule"] ne ""} {
        return 0
}
return 1
        %}
        "ips sensor entries tags" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "rule"] ne ""} {
        return 0
}
return 1
        %}
        "ips sensor entries exempt-ip" = %{
if {[cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "rule"] ne ""} {
        return 1
}
return 0
        %}
        "ips sensor entries rate-count" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "rule"] ne ""} {
        return 1
}
return 0
        %}
        "ips DoS anomaly quarantine-expiry" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "quarantine" 1 "none"]
        %}

# ----- the following is FOC only objects ----- #
	"system dynamic-profile status-imap" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile status-smtp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile status-pop3" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile status-http" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile status-ftp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile status-im-ips" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile status-nntp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile status-log" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile status-ftgd" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile vdom" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile radius-server-port" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile radius-response" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile validate-request-secret" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile secret" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile http-header-status" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile http-header" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile http-header-fallback" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile http-header-suppress" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile carrier-endpoint-attribute" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile profile-attribute" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile profile-attribute-key" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile context-timeout" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile hold-time" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile mem-percent" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile log-period" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system dynamic-profile log-flags" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
# ------- the above is FOC only objects ------- #
	"system resource-limits" = %{
namespace import global::cli_sys_global_vdom_enable
return [cli_sys_global_vdom_enable]
	%}
	"system vdom-property name" = %{
namespace import global::cli_sys_global_vdom_enable
return [cli_sys_global_vdom_enable]
	%}
	"web-proxy explicit {ftp-over-http socks http-incoming-port https-incoming-port}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"web-proxy explicit-proxy {ftp-over-http socks http-incoming-port https-incoming-port}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"web-proxy explicit ftp-incoming-port" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ftp-over-http" 0 "enable"]
	%}
	"web-proxy explicit socks-incoming-port" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "socks" 0 "enable"]
	%}
	"web-proxy explicit {incoming-ip outgoing-ip unknown-http-version realm sec-default-action pac-file-server-status}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"web-proxy explicit {pac-file-server-port pac-file-name pac-file-data pac-file-url}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pac-file-server-status" 0 "enable"]
	%}
	"ftp-proxy explicit {incoming-ip incoming-port outgoing-ip sec-default-action}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"antivirus quarantine {enable-auto-submit use-status use-fpat sel-status lowspace agelimit}" = %{
set dest [string trim [cli_get_value $CLI_CUR_PARENT_NODE "" "" "destination"] \"]
if {$dest ne "disk"} {
	return 0
}
return 1
	%}
        "firewall mms-profile {carrier-endpoint-prefix-range-min carrier-endpoint-prefix-range-max}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "carrier-endpoint-prefix" 0 "enable"]
        %}
	"{spamfilter emailfilter} profile {imap pop3 smtp smtps imaps pop3s} {options action tag-type tag-msg hdrip local-override}" = %{
if { [cli_ver_start 400 3] && [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "spam-filtering" 1 "enable"] } {
	return 0
}
return 1
	%}
	"{spamfilter emailfilter} profile mapi {options action}" = %{
if { [cli_ver_start 400 3] && [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "spam-filtering" 1 "enable"] } {
	return 0
}
return 1
	%}
	"{spamfilter emailfilter} bwl entries addr-type" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ip"]
	%}
	"{spamfilter emailfilter} bwl entries ip4-subnet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ip"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-type" 0 "ipv4"]
	%}
	"{spamfilter emailfilter} bwl entries ip6-subnet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ip"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-type" 0 "ipv6"]
	%}
	"{spamfilter emailfilter} iptrust entries ip4-subnet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-type" 0 "ipv4"]
	%}
	"{spamfilter emailfilter} iptrust entries ip6-subnet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-type" 0 "ipv6"]
	%}
	"{spamfilter emailfilter} bwl entries {pattern-type email-pattern}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "email"]
	%}
	"wireless-controller vap auth" = %{
set security [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"]
namespace import global::nCfg_cw_wlan_sec_enterprise
expr [nCfg_cw_wlan_sec_enterprise $security] 
	%}
	"wireless-controller vap passphrase" = %{
if { [cli_ver_start 600 4] && [cli_obj_support "wireless-controller vap" "mpsk-profile"] } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mpsk-profile"] ne "" } {
		return 0
	}
}
set security [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"]
expr { [string match "*personal*" $security] || $security eq "wpa3-sae-transition" }
	%}
	"wireless-controller vap {key keyindex}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wep64"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wep128"]
	%}
	"wireless-controller vap dynamic-vlan" = %{
set mesh_bh [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mesh-backhaul"]
set security [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"]
set auth [cli_get_value $CLI_CUR_PARENT_NODE "" "" "auth"]

namespace import global::nCfg_cw_wlan_sec_enterprise
if { [nCfg_cw_wlan_sec_enterprise $security] && $auth eq "radius" && $mesh_bh ne "enable" } {
	return 1
}
set rm_auth [cli_get_value $CLI_CUR_PARENT_NODE "" "" "radius-mac-auth"]
set portal_type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "portal-type"]
set mpsk_prof ""
if { [cli_ver_start 600 4] && [cli_obj_support "wireless-controller vap" "mpsk-profile"] } {
	set mpsk_prof [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mpsk-profile"]
}
if { ($rm_auth eq "enable" || $mpsk_prof ne "") && $mesh_bh ne "enable" && ($security eq "open" || $security eq "wpa3-sae" || $security eq "owe" || [string match "*personal" $security] || ($portal_type eq "auth-mac" && [string match "*captive-portal" $security])) } {
	return 1
}
return 0
	%}
	"wireless-controller vap encrypt" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa-only-enterprise"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa2-only-enterprise"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa-enterprise"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa-only-personal"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa2-only-personal"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa-personal"]
	%}
	"wireless-controller vap portal-message-override-group" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "captive-portal"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa-personal+captive-portal"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa-only-personal+captive-portal"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa2-only-personal+captive-portal"]
	%}
	"wireless-controller vap {selected-usergroups external-web external-web-format}" = %{
set security [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"]
set portaltype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "portal-type"]
if { [cli_ver_start 500 6] } {
	expr {[string match "*captive-portal" $security] && ([string match "auth*" $portaltype] || [string match "cmcc*" $portaltype] || [string match "external-auth" $portaltype])}
} elseif { [cli_ver_start 500 2] } {
	expr {[string match "*captive-portal" $security] && [string match "auth*" $portaltype]}
} else {
	expr [string match "*captive-portal" $security]
}
	%}
	"wireless-controller vap local-authentication" = %{
namespace import global::is_wlan_local_auth_skip
if { [is_wlan_local_auth_skip $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"wireless-controller vap portal-type" = %{
expr {[string match "*captive-portal" [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"]]}
	%}
	"wireless-controller vap security-redirect-url" = %{
set security [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"]
namespace import global::nCfg_cw_wlan_sec_cpauth
if {![nCfg_cw_wlan_sec_cpauth $security]} {
	return 0
}
set portaltype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "portal-type"]
expr {![string match "cmcc*" $portaltype]}
	%}
	"wireless-controller vap radius-server" = %{
set security [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"]
set portaltype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "portal-type"]
if { [cli_ver_start 600 2] && [string match "*captive-portal" $security] && ([string match "external-auth" $portaltype] || $portaltype eq "cmcc" || $portaltype eq "cmcc-macauth") } {
	return 1
}
namespace import global::nCfg_cw_wlan_sec_enterprise
expr {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth" 0 "radius"] && [nCfg_cw_wlan_sec_enterprise $security]}
	%}
	"wireless-controller vap {radius-mac-auth-server radius-mac-auth-usergroups}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "radius-mac-auth" 0 "enable"]
	%}
	"wireless-controller vap usergroup" = %{
set security [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"]
namespace import global::nCfg_cw_wlan_sec_enterprise
expr {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth" 0 "usergroup"] && [nCfg_cw_wlan_sec_enterprise $security]}
	%}
	"wireless-controller vap vlanid" = %{
expr { !([cli_obj_support "wireless-controller vap" "mesh-backhaul"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mesh-backhaul" 0 "enable"]) }
	%}
	"wireless-controller vap vlan-pool" = %{
if { ![cli_ver_start 500 6] } {
	return 0
}
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "vlan-pooling" 1 "disable"]
	%}
	"wireless-controller vap hotspot20-profile" = %{
expr {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth" 0 "radius"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa2-only-enterprise"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "encrypt" 0 "AES"]}
	%}
	"wireless-controller vap {pmf okc}" = %{
set vapencry [cli_get_value $CLI_CUR_PARENT_NODE "" "" "encrypt"]
expr { ![string match "*TKIP*" $vapencry] }
	%}
	"wireless-controller vap quarantine" = %{
expr {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "local-bridging" 1 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mesh-backhaul" 1 "enable"]}
        %}
	"wireless-controller vap local-standalone" = %{
namespace import global::is_wlan_local_st_skip
expr { ![is_wlan_local_st_skip $CLI_CUR_PARENT_NODE] }
	%}
	"wireless-controller vap local-standalone-nat" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "local-standalone" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mesh-backhaul" 1 "enable"] } {
	set security [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"]
	set auth [cli_get_value $CLI_CUR_PARENT_NODE "" "" "auth"]
	if { ($security ne "osen" && ![string match "*enterprise" $security]) || $auth ne "usergroup" } {
		return 1
	}
}
return 0
	%}
	"wireless-controller vap {ip dhcp-lease-time}" = %{
expr { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "local-standalone" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "local-standalone-nat" 0 "enable"] }
	%}
	"wireless-controller vap sae-password" = %{
expr { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa3-sae"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security" 0 "wpa3-sae-transition"] }
	%}
	"wireless-controller vap mpsk" = %{
set mesh_bh [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mesh-backhaul"]
set security [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"]
if { $mesh_bh eq "enable" } {
	return 0
}
if { ![string match "*personal*" $security] && $security ne "wpa3-sae-transition" } {
	return 0
}
return 1
	%}
	"wireless-controller vap mpsk-key" = %{
set vap_node [cli_get_parent $CLI_CUR_PARENT_NODE]
set mesh_bh [cli_get_value $vap_node "" "" "mesh-backhaul"]
set security [cli_get_value $vap_node "" "" "security"]
if { $mesh_bh eq "enable" } {
	return 0
}
if { ![string match "*personal*" $security] && $security ne "wpa3-sae-transition" } {
	return 0
}
expr [cli_is_match $vap_node 0 "" "mpsk" 0 "enable"]
	%}
	"wireless-controller vap mpsk-concurrent-clients" = %{
set mesh_bh [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mesh-backhaul"]
set security [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security"]
if { $mesh_bh eq "enable" } {
	return 0
}
if { ![string match "*personal*" $security] && $security ne "wpa3-sae-transition" } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mpsk" 0 "enable"]
	%}
	"dlp sensor filter rule-name" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "advanced-rule"]
	%}
	"dlp sensor filter compound-name" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "advanced-compound-rule"]
	%}
	"dlp sensor filter archive" = %{
if { [cli_ver_start 400 3] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "advanced-rule"] } {
	set rule_name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "rule-name"]
	set dlprule [cli_get_node $CLI_CUR_VDOM_NODE "dlp rule" $rule_name ""]
	if { $dlprule == 0 || [cli_get_value $dlprule "" "" "protocol"] eq "nntp" } {
		return 0
	}
}
if { [cli_ver_start 400 3] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "advanced-compound-rule"] } {
	set comp_name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "compound-name"]
	set dlpcomp [cli_get_node $CLI_CUR_VDOM_NODE "dlp compound" $comp_name ""]
	if { $dlpcomp == 0 || [cli_get_value $dlpcomp "" "" "protocol"] eq "nntp" } {
		return 0
	}
}
## 6.2.1 GA
if { [cli_branchpt_start 600 932] } {
	set protos [cli_get_value $CLI_CUR_PARENT_NODE "" "" "proto"]
	set full_archive_protos [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "full-archive-proto"]
	foreach p1 $protos {
		set exist 0
		foreach p2 $full_archive_protos {
			if { $p1 eq $p2 } {
				set exist 1
			}
		}
		if { $exist == 0 } {
			return 1
		}
	}
	return 0
} elseif { ![cli_has_feature "f_local_dlp"] } {
	set s1 [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "status"]
	set s2 [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer2 setting" "" "status"]
	set s3 [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer3 setting" "" "status"]
	if { $s1 eq "disable" && $s2 eq "disable" && $s3 eq "disable" } {
		return 0
	}
}
return 1
	%}
	"dlp sensor full-archive-proto" =%{
## 6.2.1 GA
if { [cli_branchpt_start 600 932] } {
	return 1
}
if { ![cli_has_feature "f_local_dlp"] } {
	set s1 [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer setting" "" "status"]
	set s2 [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer2 setting" "" "status"]
	set s3 [cli_get_value $CLI_GLOBAL_NODE "log fortianalyzer3 setting" "" "status"]
	if { $s1 eq "disable" && $s2 eq "disable" && $s3 eq "disable" } {
		return 0
	}
}
return 1
%}
	"dlp sensor filter file-type" = %{
if { [cli_ver_start 500 0] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "file"] &&
	     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "file-type"] } {
		return 1
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "file-type"] } {
		return 1
	}
}
return 0
	%}
	"dlp sensor filter file-size" = %{
if { [cli_ver_start 500 0] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "file"] &&
	     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "file-size"] } {
		return 1
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "file-size"] } {
		return 1
	}
}
return 0
	%}
	"dlp sensor filter regexp" = %{
if { [cli_ver_start 500 0] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "regexp"] } {
		return 1
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "regexp"] } {
		return 1
	}
}
return 0
	%}
	"dlp sensor filter {regexp-utf8 regexp-wildcard}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "regexp"]
	%}
	"dlp sensor filter fp-sensitivity" = %{
if { [cli_ver_start 500 0] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "file"] &&
	     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "fingerprint"] } {
		return 1
	}
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "file"] &&
	     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "watermark"] } {
		return 1
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "fingerprint"] } {
		return 1
	}
}
return 0
	%}
	"dlp sensor filter match-percentage" = %{
if { [cli_ver_start 500 0] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "file"] &&
	     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "fingerprint"] } {
		return 1
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "fingerprint"] } {
		return 1
	}
}
return 0
	%}
	"dlp sensor filter proto {ftp aim icq msn yahoo http-get mm1 mm3 mm4 mm7}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "file"]
	%}
	"dlp sensor filter expiry" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "ban"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "ban-sender"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "quarantine-ip"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "quarantine-port"]
	%}
	"dlp sensor filter company-identifier" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "file"] && 
	[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "watermark"] } {
	return 1
}
return 0
	%}
	"wireless-controller wtp-profile radio-1 {band preferred-oper-mode channel dtim beacon-interval rts-threshold frag-threshold ap-bgscan auto-power-level vap-all}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"]
	%}
	"wireless-controller wtp-profile radio-1 ap-bgscan-report-intv" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ap-bgscan" 0 "enable"]
	%}
	"wireless-controller wtp-profile radio-1 ap-scan-passive" = %{
expr ([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ap-bgscan" 0 "enable"]) || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "monitor"]
	%}
	"wireless-controller wtp-profile radio-1 rogue-scan" = %{
expr ([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ap-bgscan" 0 "enable"]) || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "monitor"]
	%}
	"wireless-controller wtp-profile radio-1 {ap-bgscan-period ap-bgscan-intv ap-bgscan-duration ap-bgscan-idle}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ap-bgscan" 0 "enable"]
	%}
	"wireless-controller wtp-profile radio-1 darrp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"]
	%}
	"wireless-controller wtp-profile radio-1 arrp-profile" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "darrp" 0 "enable"]
	%}
	"wireless-controller wtp-profile radio-1 {sam-ssid sam-bssid sam-security-type sam-test sam-server sam-server-type sam-report-intv}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sam"]
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3} bss-color-mode" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"]
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3} sam-server-ip" = %{
expr ([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sam"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sam-server-type" 0 "ip"])
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3} sam-server-fqdn" = %{
expr ([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sam"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sam-server-type" 0 "fqdn"])
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3} sam-username" = %{
expr ([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sam"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sam-security-type" 0 "wpa-enterprise"])
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3} sam-captive-portal" = %{
expr ([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sam"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sam-security-type" 1 "wpa-enterprise"])
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3} sam-password" = %{
expr ([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sam"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sam-security-type" 1 "open"])
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3} {sam-cwp-username sam-cwp-password sam-cwp-test-url sam-cwp-match-string sam-cwp-success-string sam-cwp-failure-string}" = %{
expr ([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sam"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sam-captive-portal" 0 "enable"])
	%}
	"wireless-controller wtp-profile radio-1 {iperf-server-port iperf-protocol}" = %{
expr {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sam"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sam-test" 0 "iperf"]}
	%}
	"wireless-controller wtp-profile radio-1 vaps" = %{
if { [cli_branchpt_start 600 1616] } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vap-all"] ne "manual" && [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vap-all"] ne "disable" } {
		return 0
	}
} elseif { [cli_ver_start 600 4] && ![cli_branchpt_start 600 1567] } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vap-all"] ne "none" } {
		return 0
	}
} elseif { [cli_ver_start 500 4] } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vap-all"] ne "disable" } {
		return 0
	}
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"]
	%}
	"wireless-controller wtp-profile radio-2" = %{
namespace import global::wtp_profile_platform
set type [wtp_profile_platform $CLI_CUR_PARENT_NODE]
set radio [cli_get_devinfo "pm2_wl_radio_enabled" "2" $type]
if { $radio ne "yes"} {
	return 0
}
if { [cli_get_devinfo "wifilocal" $type] eq "yes" } {
	if { $CLI_GLOBAL_DEV } {
		return 1
	}
	set platform [cli_get_devinfo "platform"]
	if { [regexp -all {FortiWiFi.*-2R} $platform] == 1 } {
		return 1
	}
	set radio [cli_get_devinfo "pm2_wl_local_radio_enabled" "2" $platform]
	if { $radio eq "yes"} {
		return 1
	}
	return 0
}
return 1
	%}
 	"wireless-controller wtp-profile radio-3" = %{ 
namespace import global::wtp_profile_platform
set type [wtp_profile_platform $CLI_CUR_PARENT_NODE]
set radio [cli_get_devinfo "pm2_wl_radio_enabled" "3" $type]
if { $radio ne "yes"} {
	return 0
}
if { [cli_get_devinfo "wifilocal" $type] eq "yes" } {
	if { $CLI_GLOBAL_DEV } {
		return 1
	}
	set platform [cli_get_devinfo "platform"]
	set radio [cli_get_devinfo "pm2_wl_local_radio_enabled" "3" $platform]
	if { $radio eq "yes"} {
		return 1
	}
	return 0
}
return 1
 	%}
	"wireless-controller wtp-profile radio-4" = %{
namespace import global::wtp_profile_platform
set plat [wtp_profile_platform $CLI_CUR_PARENT_NODE]
set mode [cli_get_value $CLI_CUR_PARENT_NODE "platform" "" "mode"]
expr {[cli_get_devinfo "pm2_wl_radio_enabled" "4" $plat $mode] eq "yes"}
%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3 radio-4} {wids-profile station-locate}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] } {
	if { [cli_ver_start 500 4] } {
		# only v540 support API: "wl_oper_mode"
		if { $CLI_CUR_PARENT_NAME eq "radio-1" } {
			set radio "1"
		} elseif { $CLI_CUR_PARENT_NAME eq "radio-2" } {
			set radio "2"
		} elseif { $CLI_CUR_PARENT_NAME eq "radio-3" } {
			set radio "3"
		} elseif { $CLI_CUR_PARENT_NAME eq "radio-4" } {
			set radio "4"
		}
		set platform [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "platform" "" "type"]
		if { [cli_get_devinfo "wl_oper_mode" $radio $platform "4" "ap"] eq "yes" } {
			return 0
		}
	}
	return 1
} elseif { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "monitor"] } {
	return 1
}
return 0
	%}
	"wireless-controller wtp-profile radio-1 ap-fgscan-report-intv" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "monitor"]
	%}
	"wireless-controller wtp-profile radio-1 ap-auto-suppress" = %{
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if {$mode ne "monitor"} {
        return 0
}
return 1
        %}

	"wireless-controller wtp-profile {radio-1 radio-2 radio-3 radio-4} power-level" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-power-level" 0 "disable"] } {
	if { [cli_ver_start 700 0] } {
		if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "power-mode" 0 "percentage"] } {
			return 1
		}
	} else {
		return 1
	}
}
return 0
	%}
	"wireless-controller wtp-profile radio-1 power-value" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-power-level" 0 "disable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "power-mode" 0 "dBm"] } {
	return 1
}
return 0
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3 radio-4} {auto-power-low auto-power-high}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-power-level" 0 "enable"]
	%}
        "wireless-controller wtp-profile {radio-2 radio-3 radio-4} {band preferred-oper-mode channel darrp dtim beacon-interval rts-threshold frag-threshold ap-bgscan auto-power-level frequency-handoff ap-handoff vap-all}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"]
        %}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3 radio-4} channel-utilization" = %{
expr {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "monitor"]}
	%}
        "wireless-controller wtp-profile radio-2 ap-bgscan-report-intv" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ap-bgscan" 0 "enable"]
        %}
        "wireless-controller wtp-profile radio-2 {ap-scan-passive rogue-scan}" = %{
expr ([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ap-bgscan" 0 "enable"]) || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "monitor"]
        %}
        "wireless-controller wtp-profile radio-2 {ap-bgscan-period ap-bgscan-intv ap-bgscan-duration ap-bgscan-idle}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ap-bgscan" 0 "enable"]
        %}
	"wireless-controller wtp-profile radio-2 {sam-ssid sam-bssid sam-security-type sam-test sam-server sam-server-type sam-report-intv}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sam"]
	%}
	"wireless-controller wtp-profile radio-2 {iperf-server-port iperf-protocol}" = %{
expr {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sam"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sam-test" 0 "iperf"]}
	%}
	"wireless-controller wtp-profile {radio-2 radio-3} vaps" = %{
if { [cli_branchpt_start 600 1616] } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vap-all"] ne "manual" && [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vap-all"] ne "disable" } {
		return 0
	}
} elseif { [cli_ver_start 600 4] && ![cli_branchpt_start 600 1567] } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vap-all"] ne "none" } {
		return 0
	}
} elseif { [cli_ver_start 500 4] } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vap-all"] ne "disable" } {
		return 0
	}
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"]
	%}
        "wireless-controller wtp-profile radio-2 ap-fgscan-report-intv" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "monitor"]
        %}

	"wireless-controller wtp {radio-enable ap-scan vap-all}" = %{
if { [cli_ver_start 500 2] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-profile" 0 "disable"] } {
		return 0
	}
} else {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wtp-profile"] ne "" } {
		return 0
	}
}
return 1
	%}
	"wireless-controller wtp split-tunneling-acl" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-split-tunnel" 0 "enable"]
	%}
        "wireless-controller wtp-profile login-passwd" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "login-passwd-change" 0 "yes"]
        %}
	"wireless-controller wtp-profile lbs {fortipresence-port fortipresence-secret fortipresence-project fortipresence-frequency fortipresence-rogue fortipresence-unassoc fortipresence-server-addr-type}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fortipresence" 1 "disable"]
	%}
	"wireless-controller wtp-profile lbs {fortipresence-server}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fortipresence" 1 "disable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fortipresence-server-addr-type" 0 "ipv4"]
	%}
	"wireless-controller wtp-profile lbs {fortipresence-server-fqdn}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fortipresence" 1 "disable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fortipresence-server-addr-type" 0 "fqdn"]
	%}
	"wireless-controller wtp allowaccess" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-allowaccess" 0 "enable"]
	%}
	"wireless-controller wtp {admin image-download login-enable login-passwd-change}" = %{
if { $CLI_CUR_NODE_NAME eq "login-passwd-change" } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-login-passwd-change" 0 "disable"] } {
		return 0
	}
}
set wtp_id [string range [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wtp-id"] 0 5]
set dev_sn [string range [cli_get_devinfo "sn"] 0 5]
expr ![string match -nocase $wtp_id $dev_sn]
	%}
	"wireless-controller wtp login-passwd" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-login-passwd-change" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "login-passwd-change" 0 "yes"]
	%}
	"wireless-controller {wtp wtp-profile} {tun-mtu-uplink tun-mtu-downlink}" = %{
set ipfrag [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ip-fragment-preventing"]
if { $ipfrag eq "" } {
	return 0
}
return 1
	%}

	"wireless-controller wtp {radio-1 radio-2 radio-3 radio-4} channel" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-channel" 0 "enable"]
	%}
	"wireless-controller wtp {radio-1 radio-2 radio-3 radio-4} {auto-power-level}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-txpower" 0 "enable"]
        %}
	"wireless-controller wtp {radio-1 radio-2 radio-3 radio-4} {auto-power-high auto-power-low}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-txpower" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-power-level" 0 "enable"]
        %}
	"wireless-controller wtp {radio-1 radio-2 radio-3 radio-4} power-level" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-txpower" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-power-level" 0 "disable"]
        %}
	"wireless-controller wtp override-wan-port-mode" = %{
set wtp_id [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wtp-id"]
set platform [cli_get_devinfo "wtp_plat" $wtp_id]
if { $platform eq "" } {
	return 0
}
set CW_WTP_WANLAN_LAN [expr 1 << 0]
set val [cli_get_devinfo "pm2_wl_wtpcap_attr" $platform "wan_lan"]
if { [expr ($val & $CW_WTP_WANLAN_LAN)] } {
	return 1
}
return 0
	%}
	"wireless-controller wtp wan-port-mode" = %{
set wtp_id [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wtp-id"]
set platform [cli_get_devinfo "wtp_plat" $wtp_id]
if { $platform eq "" } {
	return 0
}
set CW_WTP_WANLAN_LAN [expr 1 << 0]
set val [cli_get_devinfo "pm2_wl_wtpcap_attr" $platform "wan_lan"]
if { [expr ($val & $CW_WTP_WANLAN_LAN)] } {
	return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-wan-port-mode" 0 "enable"]]
}
return 0
	%}
	"icap profile {request-server request-failure request-path}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "request" 0 "enable"]]
	%}
	"icap profile {response-server response-failure response-path response-req-hdr respmod-default-action}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "response" 0 "enable"]]
	%}
	"icap profile {respmod-forward-rules}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "response" 0 "enable"]]
	%}
	"icap server ip-address" = %{
if { [cli_ver_start 700 2] } {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-type" 0 "ip4"]
} else {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"]
}
	%}
	"icap server ip6-address" = %{
if { [cli_ver_start 700 2] } {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-type" 0 "ip6"]
} else {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "6"]
}
	%}
	"icap server ssl-cert" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "secure" 0 "enable"]
	%}
	"icap server healthcheck-service" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "healthcheck" 0 "enable"]
	%}
	"system snmp user auth-proto" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-level" 0 "auth-no-priv"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-level" 0 "auth-priv"]
	%}
	"system snmp user auth-pwd" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-level" 0 "auth-no-priv"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-level" 0 "auth-priv"]
	%}
	"system snmp user priv-proto" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-level" 0 "auth-priv"]
	%}
	"system snmp user priv-pwd" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-level" 0 "auth-priv"]
	%}
	"system dhcp server dns-server1" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dns-service" 0 "specify"]
	%}
	"system dhcp server dns-server2" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dns-service" 0 "specify"]
	%}
	"system dhcp server dns-server3" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dns-service" 0 "specify"]
	%}
	"system dhcp server {ddns-key ddns-keyname}" = %{
expr ([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ddns-update" 1 "disable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ddns-auth" 1 "disable"])
	%}
	"user local fortitoken" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "two-factor" 0 "fortitoken"]
	%}
        "user local sms-custom-server" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sms-server" 0 "custom"]
        %}
	"report {dataset chart summary style theme layout}" = %{
if {![cli_has_feature "f_sql_log"]} {
	return 0
}
if {[cli_get_devinfo "hdd"] ne "yes"} {
	return 0
}
if {[cli_obj_support "system global" "sql-logging"]} {
	set sqllog [cli_get_value $CLI_GLOBAL_NODE "system global" "" "sql-logging"]
	if {$sqllog ne "enable"} {
		return 0
	}
}
if { [cli_branchpt_start 500 650] } {
	if { [cli_is_match $CLI_CUR_VDOM_NODE 0 "log disk setting" "status" 0 "disable"] } {
		return 0
	}
}
return 1
	%}
	"netscan settings {recurrence time}" = %{
if { [cli_ver_start 400 3] } {
	return 1
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "schedule" 0 "enable"] } {
	return 1
}
return 0
	%}
	"netscan settings {day-of-week}" = %{
if { [cli_ver_start 400 3] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "recurrence" 0 "weekly"] } {
		return 1
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "schedule" 0 "enable"] &&
	     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "recurrence" 0 "weekly"] } {
		return 1
	}
}
return 0
	%}
	"netscan settings {day-of-month}" = %{
if { [cli_ver_start 400 3] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "recurrence" 0 "monthly"] } {
		return 1
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "schedule" 0 "enable"] &&
	     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "recurrence" 0 "monthly"] } {
		return 1
	}
}
return 0
	%}
	"netscan settings {pause-from pause-to}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "scheduled-pause" 0 "enable"]
	%}
	"netscan settings {service-detection os-detection}" = %{
set tcpscan [cli_get_value $CLI_CUR_PARENT_NODE "" "" "tcp-scan"]
if {$tcpscan eq "enable" || $tcpscan eq "default" || $tcpscan eq ""} {
	return 1
}
return 0
	%}
        "firewall multicast-policy start-port" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if {$protocol == 6 || $protocol == 17} {
        return 1
}
return 0
        %}
        "firewall multicast-policy end-port" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if {$protocol == 6 || $protocol == 17} {
        return 1
}
return 0
        %}
	"log syslogd override-filter" = %{
namespace import global::cli_sys_global_vdom_enable
return [cli_sys_global_vdom_enable]
	%}
	"log syslogd override-setting" = %{
namespace import global::cli_sys_global_vdom_enable
return [cli_sys_global_vdom_enable]
	%}
	"log fortianalyzer override-filter" = %{
namespace import global::cli_sys_global_vdom_enable
return [cli_sys_global_vdom_enable]
	%}
	"log fortianalyzer override-setting" = %{
namespace import global::cli_sys_global_vdom_enable
return [cli_sys_global_vdom_enable]
	%}
	"log syslogd override-setting {status}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override" 0 "enable"]
	%}
	"log syslogd override-setting {server reliable port csv facility source-ip}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"log fortiguard override-setting {status}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override" 0 "enable"]
	%}
	"log fortiguard override-setting {source-ip upload-option enc-algorithm}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"log fortianalyzer override-setting {status}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override" 0 "enable"]
	%}
	"log fortianalyzer override-setting {ips-archive gui-display max-buffer-size buffer-max-send address-mode server encrypt hmac-algorithm psksecret enc-algorithm localid conn-timeout monitor-keepalive-period monitor-failure-retry-period mgmt-name source-ip upload-option reliable fdp-device fdp-interface}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"log fortianalyzer override-setting __change_ip" = %{
return 0
	%}
        "log {fortiguard fortianalyzer fortianalyzer2 fortianalyzer3} setting {upload-interval upload-day upload-time}" = %{
if { !$CLI_GLOBAL_DEV && [cli_get_devinfo "hdd"] ne "yes"} {
	return 0
}
if { ( $CLI_GLOBAL_DEV || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] ) &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-option" 0 "store-and-upload"] } {
	if { $CLI_CUR_NODE_NAME eq "upload-day" } {
		if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-interval" 1 "weekly"] &&
		     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-interval" 1 "monthly"] } {
			return 0
		}
	}
	return 1
}
return 0
        %}
	"log {fortiguard fortianalyzer} override-setting {upload-interval upload-day upload-time}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override" 0 "enable"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-option" 0 "store-and-upload"] } {
	if { $CLI_CUR_NODE_NAME eq "upload-day" } {
		if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-interval" 1 "weekly"] &&
		     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-interval" 1 "monthly"] } {
			return 0
		}
	}
	return 1
}
return 0
	%}
	"system interface replacemsg-override-group" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set sec [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security-mode"]
if { $type eq "vap-switch" || $type eq "switch-vlan" || $sec ne "captive-portal" } {
	return 0
}
return 1
	%}
	"system interface security-groups" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set sec [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security-mode"]
set dedt [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dedicated-to"]
set fortilink [cli_get_value $CLI_CUR_PARENT_NODE "" "" "fortilink"]
if { $type eq "vap-switch" || $sec eq "none" || $dedt eq "management" || $fortilink eq "enable" } {
	return 0
}
return 1
	%}
	"system interface security-8021x-mode" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-mode" 0 "802.1X"]
	%}
	"system interface {security-8021x-master security-8021x-dynamic-vlan-id}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-mode" 0 "802.1X"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-8021x-mode" 0 "slave"]
	%}
	"system interface atm-protocol" = %{
set mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mode"]
if { [cli_branchpt_start 500 1672] } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiWiFi-60E-DSLJ"] ||
	     [string match -nocase $platform "FortiWiFi-60E-DSL"] || 
	     [string match -nocase $platform "Fortigate-60E-DSLJ"] ||
	     [string match -nocase $platform "Fortigate-60E-DSL"] } {
		set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
		if { $name eq "dsl" } {
			set phy [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phy-mode"]
			set tc [cli_get_value $CLI_CUR_PARENT_NODE "" "" "tc-mode"]
			if { ($mode eq "static" || $mode eq "dhcp") && $phy eq "adsl" && $tc eq "atm" } {
				return 1
			}
		}
	}
	return 0
}
if { $mode eq "static" || $mode eq "dhcp" } {
	set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	if { $name eq "adsl" || $name eq "dsl" } {
		return 1
	}
}
return 0
	%}
	"system admin guest-usergroups" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "guest-auth" 0 "enable"]
	%}
	"system admin accprofile" = %{
if { [cli_ver_start 500 0] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "guest-auth" 0 "enable"] } {
		return 0
	}
}
return 1
	%}
	"log disk {setting filter}" = %{
if { [cli_ver_start 400 3] } {
	if { ![expr {[cli_get_devinfo "hdd"] eq "yes"}] } {
		return 0
	}
}
return 1
	%}
	"log memory {global-setting setting filter}" = %{
if { [cli_ver_start 400 3] } {
	if { ![cli_has_feature "f_mem_log"] } {
		return 0
	}
}
return 1
	%}
        "wireless-controller wtp-profile {radio-1 radio-2 radio-3 radio-4} short-guard-interval" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "channel-bonding" 1 "disable"]
 } {
        set band [cli_get_value $CLI_CUR_PARENT_NODE "" "" "band"]
        if {$band eq "802.11a" || $band eq "802.11b" || $band eq "802.11g" || $band eq "802.11g-only"} {
                return 0
        }
        set bonding [cli_get_value $CLI_CUR_PARENT_NODE "" "" "channel-bonding"]
        if {$bonding ne "20MHz"} {
                return 1
        }
	namespace import global::wtp_profile_platform
	set plat [wtp_profile_platform [cli_get_parent $CLI_CUR_PARENT_NODE]]
	if { $plat eq "FWF" } {
		set platform [cli_get_devinfo "platform"]
		if { [regexp -all {FortiWiFi.*-2R} $platform] == 1 } {
			return 1
		}
	}
	set val [cli_get_devinfo "pm2_wl_wtpcap_attr" $plat "cap"]
	set CW_WTP_CAP_NO_20M_GI [expr 1 << 1]
	if { ![expr ($val & $CW_WTP_CAP_NO_20M_GI)] } {
		return 1
	}
}
return 0
        %}
        "wireless-controller wtp-profile {radio-1 radio-2 radio-3 radio-4} {max-supported-mcs channel-bonding}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ap"] } {
        set band [cli_get_value $CLI_CUR_PARENT_NODE "" "" "band"]
        if {[string match "802.11n*" $band] || [string match "802.11ac*" $band] || [string match "802.11ax*" $band] || $band eq ""} {
                return 1
        }
}
return 0
        %}
	"wireless-controller wtp-profile lan {port-mode port1-mode port2-mode port3-mode port4-mode port5-mode port6-mode port7-mode port8-mode}" = %{
set wtp_profile [cli_get_parent $CLI_CUR_PARENT_NODE]
set platform [cli_get_value $wtp_profile "platform" "" "type"]
if { $platform eq "" } {
	return 0
}
set wan_port_mode [cli_get_value $wtp_profile "" "" "wan-port-mode"]
if { $wan_port_mode ne "wan-lan" } {
	return 0
}
set val [cli_get_devinfo "pm2_wl_wtpcap_attr" $platform "max_lan"]
if { $CLI_CUR_NODE_NAME eq "port-mode" && $val == 1 } {
	return 1
} elseif { ($CLI_CUR_NODE_NAME eq "port1-mode" || $CLI_CUR_NODE_NAME eq "port2-mode") && $val >= 2 } {
		return 1
} elseif { $CLI_CUR_NODE_NAME eq "port3-mode" && $val >= 3 } {
		return 1
} elseif { $CLI_CUR_NODE_NAME eq "port4-mode" && $val >= 4 } {
		return 1
} elseif { $CLI_CUR_NODE_NAME eq "port5-mode" && $val >= 5 } {
		return 1
} elseif { $CLI_CUR_NODE_NAME eq "port6-mode" && $val >= 6 } {
		return 1
} elseif { $CLI_CUR_NODE_NAME eq "port7-mode" && $val >= 7 } {
		return 1
} elseif { $CLI_CUR_NODE_NAME eq "port8-mode" && $val >= 8 } {
		return 1
}
return 0
	%}
	"wireless-controller wtp-profile lan {port-ssid port1-ssid port2-ssid port3-ssid port4-ssid port5-ssid port6-ssid port7-ssid port8-ssid}" = %{
set name "port-mode"
if { $CLI_CUR_NODE_NAME eq "port1-ssid" } {
	set name "port1-mode"
} elseif { $CLI_CUR_NODE_NAME eq "port2-ssid" } {
	set name "port2-mode"
} elseif { $CLI_CUR_NODE_NAME eq "port3-ssid" } {
	set name "port3-mode"
} elseif { $CLI_CUR_NODE_NAME eq "port4-ssid" } {
	set name "port4-mode"
} elseif { $CLI_CUR_NODE_NAME eq "port5-ssid" } {
	set name "port5-mode"
} elseif { $CLI_CUR_NODE_NAME eq "port6-ssid" } {
	set name "port6-mode"
} elseif { $CLI_CUR_NODE_NAME eq "port7-ssid" } {
	set name "port7-mode"
} elseif { $CLI_CUR_NODE_NAME eq "port8-ssid" } {
	set name "port8-mode"
}
set port_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" $name]
if { $port_mode eq "bridge-to-ssid" } {
	set platform [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "platform" "" "type"]
	set val [cli_get_devinfo "pm2_wl_wtpcap_attr" $platform "max_lan"]
	if { $val == 1 && $name eq "port-mode" } {
		return 1
	} elseif { ($name eq "port1-mode" || $name eq "port2-mode") && $val >= 2 } {
		return 1
	} elseif { $name eq "port3-mode" && $val >= 3 } {
		return 1
	} elseif { $name eq "port4-mode" && $val >= 4 } {
		return 1
	} elseif { $name eq "port5-mode" && $val >= 5 } {
		return 1
	} elseif { $name eq "port6-mode" && $val >= 6 } {
		return 1
	} elseif { $name eq "port7-mode" && $val >= 7 } {
		return 1
	} elseif { $name eq "port8-mode" && $val >= 8 } {
		return 1
	}
}
return 0
    %}
	"wireless-controller wtp-profile lan {port-esl-mode port-esl-ssid}" = %{
set platform [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "platform" "" "type"]
if { $platform eq "" } {
	return 0
}
set CW_WTP_WANLAN_ESL [expr 1 << 1]
set wan_lan [cli_get_devinfo "pm2_wl_wtpcap_attr" $platform "wan_lan"]
if { [expr ($wan_lan & $CW_WTP_WANLAN_ESL)] } {
	return 1
}
return 0
	%}
	"wireless-controller wtp-profile wan-port-mode" = %{
set node [cli_get_node $CLI_CUR_PARENT_NODE "platform" "" ""]
set platform [cli_get_value $node "" "" "type"]
if { $platform eq "" } {
	return 0
}
set CW_WTP_WANLAN_LAN [expr 1 << 0]
set val [cli_get_devinfo "pm2_wl_wtpcap_attr" $platform "wan_lan"]
if { [expr ($val & $CW_WTP_WANLAN_LAN)] } {
	return 1
}
return 0
	%}
	"system snmp community hosts interface" = %{
if { [cli_branchpt_start 500 1126] } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ha-direct" 0 "disable"]
	%}
	"system snmp community hosts6 interface" = %{
if { [cli_branchpt_start 500 1126] } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ha-direct" 0 "disable"]
	%}

	"system replacemsg-group {webproxy}" = %{
expr ![cli_ver_start 400 3] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "auth"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "utm"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "default"]
	%}
	"system replacemsg-group {auth}" = %{
expr ![cli_ver_start 400 3] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "auth"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "default"]
	%}
	"system replacemsg-group {captive-portal-dflt}" = %{
expr ![cli_ver_start 400 3] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "captive-portal"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "default"]
	%}
	"system replacemsg-group {custom-message}" = %{
expr ![cli_ver_start 400 3] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "captive-portal"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "utm"]
	%}
	"system replacemsg-group {ec}" = %{
expr ![cli_ver_start 400 3] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "ec"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "default"]
	%}
	"system replacemsg-group {mail http mms mm1 mm3 mm4 mm7 ftp nntp fortiguard-wf spam im alertmail admin sslvpn nac-quar traffic-quota utm}" = %{
expr ![cli_ver_start 400 3] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "utm"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "default"]
	%}
	"system replacemsg-group {device-detection-portal}" = %{
expr ![cli_ver_start 400 3] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "default"]
	%}

	"system replacemsg mms {image}" = %{
return 0
	%}
	"system replacemsg-group mms {image}" = %{
return 0
	%}
        "system replacemsg mm1 {message class priority subject}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm1-send-conf-block" ||
     $msg eq "mm1-send-conf-virus" ||
     $msg eq "mm1-send-conf-bwl" ||
     $msg eq "mm1-send-conf-checksum" ||
     $msg eq "mm1-send-conf-bword" ||
     $msg eq "mm1-send-conf-flood" ||
     $msg eq "mm1-send-conf-dupe" ||
     $msg eq "mm1-send-conf-av-fail" } {
	return 0
}
return 1
        %}
        "system replacemsg-group mm1 {message class priority subject}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm1-send-conf-block" ||
     $msg eq "mm1-send-conf-virus" ||
     $msg eq "mm1-send-conf-bwl" ||
     $msg eq "mm1-send-conf-checksum" ||
     $msg eq "mm1-send-conf-bword" ||
     $msg eq "mm1-send-conf-flood" ||
     $msg eq "mm1-send-conf-dupe" } {
	return 0
}
return 1
        %}
        "system replacemsg mm1 {from-sender sender-visibility}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm1-send-req-block" ||
     $msg eq "mm1-send-req-bwl" ||
     $msg eq "mm1-send-req-checksum" ||
     $msg eq "mm1-send-req-virus" ||
     $msg eq "mm1-send-req-flood" ||
     $msg eq "mm1-send-req-dupe" ||
     $msg eq "mm1-send-req-bword" } {
	return 1
}
return 0
        %}
        "system replacemsg-group mm1 {from-sender sender-visibility}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm1-send-req-block" ||
     $msg eq "mm1-send-req-bwl" ||
     $msg eq "mm1-send-req-checksum" ||
     $msg eq "mm1-send-req-virus" ||
     $msg eq "mm1-send-req-flood" ||
     $msg eq "mm1-send-req-dupe" ||
     $msg eq "mm1-send-req-bword" } {
	return 1
}
return 0
        %}
        "system replacemsg mm1 {from}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm1-send-req-block" ||
     $msg eq "mm1-send-req-bwl" ||
     $msg eq "mm1-send-req-checksum" ||
     $msg eq "mm1-send-req-virus" ||
     $msg eq "mm1-send-req-flood" ||
     $msg eq "mm1-send-req-dupe" ||
     $msg eq "mm1-send-req-bword" } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "from-sender"] ne "enable" } {
		return 1
	}
}
return 0
	%}
        "system replacemsg-group mm1 {from}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm1-send-req-block" ||
     $msg eq "mm1-send-req-bwl" ||
     $msg eq "mm1-send-req-checksum" ||
     $msg eq "mm1-send-req-virus" ||
     $msg eq "mm1-send-req-flood" ||
     $msg eq "mm1-send-req-dupe" ||
     $msg eq "mm1-send-req-bword" } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "from-sender"] ne "enable" } {
		return 1
	}
}
return 0
	%}
        "system replacemsg mm1 {smil-part image}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm1-send-conf-block" ||
     $msg eq "mm1-send-conf-virus" ||
     $msg eq "mm1-send-conf-bwl" ||
     $msg eq "mm1-send-conf-checksum" ||
     $msg eq "mm1-send-conf-bword" ||
     $msg eq "mm1-send-conf-flood" ||
     $msg eq "mm1-send-conf-dupe" } {
	set add_smil [cli_get_value $CLI_CUR_PARENT_NODE "" "" "add-smil"]
	if { $add_smil eq "enable" } {
		return 1
	}
}
return 0
	%}
        "system replacemsg-group mm1 {smil-part image}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm1-send-conf-block" ||
     $msg eq "mm1-send-conf-virus" ||
     $msg eq "mm1-send-conf-bwl" ||
     $msg eq "mm1-send-conf-checksum" ||
     $msg eq "mm1-send-conf-bword" ||
     $msg eq "mm1-send-conf-flood" ||
     $msg eq "mm1-send-conf-dupe" } {
	set add_smil [cli_get_value $CLI_CUR_PARENT_NODE "" "" "add-smil"]
	if { $add_smil eq "enable" } {
		return 1
	}
}
return 0
	%}
        "system replacemsg mm1 {rsp-text rsp-status}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm1-send-conf-block" ||
     $msg eq "mm1-send-conf-virus" ||
     $msg eq "mm1-send-conf-bwl" ||
     $msg eq "mm1-send-conf-checksum" ||
     $msg eq "mm1-send-conf-bword" ||
     $msg eq "mm1-send-conf-flood" ||
     $msg eq "mm1-send-conf-dupe" ||
     $msg eq "mm1-send-conf-av-fail" } {
	return 1
}
return 0
        %}
        "system replacemsg mm1 {add-smil}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm1-send-req-block" ||
     $msg eq "mm1-send-req-virus" ||
     $msg eq "mm1-send-req-bwl" ||
     $msg eq "mm1-send-req-checksum" ||
     $msg eq "mm1-send-req-bword" ||
     $msg eq "mm1-send-req-flood" ||
     $msg eq "mm1-send-req-dupe" } {
	return 1
}
return 0
        %}
        "system replacemsg-group mm1 {rsp-text rsp-status add-smil}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm1-send-conf-block" ||
     $msg eq "mm1-send-conf-virus" ||
     $msg eq "mm1-send-conf-bwl" ||
     $msg eq "mm1-send-conf-checksum" ||
     $msg eq "mm1-send-conf-bword" ||
     $msg eq "mm1-send-conf-flood" ||
     $msg eq "mm1-send-conf-dupe" } {
	return 1
}
return 0
        %}
        "system replacemsg mm3 {from-sender subject priority add-html}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm3-block-notif" ||
     $msg eq "mm3-virus-notif" ||
     $msg eq "mm3-bwl-notif" ||
     $msg eq "mm3-checksum-notif" ||
     $msg eq "mm3-bword-notif" ||
     $msg eq "mm3-flood-notif" ||
     $msg eq "mm3-dupe-notif" } {
	return 1
}
return 0
	%}
        "system replacemsg-group mm3 {from-sender subject priority add-html}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm3-block-notif" ||
     $msg eq "mm3-virus-notif" ||
     $msg eq "mm3-bwl-notif" ||
     $msg eq "mm3-checksum-notif" ||
     $msg eq "mm3-bword-notif" ||
     $msg eq "mm3-flood-notif" ||
     $msg eq "mm3-dupe-notif" } {
	return 1
}
return 0
	%}
        "system replacemsg mm3 {from}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm3-block-notif" ||
     $msg eq "mm3-virus-notif" ||
     $msg eq "mm3-bwl-notif" ||
     $msg eq "mm3-checksum-notif" ||
     $msg eq "mm3-bword-notif" ||
     $msg eq "mm3-flood-notif" ||
     $msg eq "mm3-dupe-notif" } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "from-sender"] ne "enable" } {
		return 1
	}
}
return 0
	%}
        "system replacemsg-group mm3 {from}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm3-block-notif" ||
     $msg eq "mm3-virus-notif" ||
     $msg eq "mm3-bwl-notif" ||
     $msg eq "mm3-checksum-notif" ||
     $msg eq "mm3-bword-notif" ||
     $msg eq "mm3-flood-notif" ||
     $msg eq "mm3-dupe-notif" } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "from-sender"] ne "enable" } {
		return 1
	}
}
return 0
	%}
        "system replacemsg mm3 {html-part}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm3-block-notif" ||
     $msg eq "mm3-virus-notif" ||
     $msg eq "mm3-bwl-notif" ||
     $msg eq "mm3-checksum-notif" ||
     $msg eq "mm3-bword-notif" ||
     $msg eq "mm3-flood-notif" ||
     $msg eq "mm3-dupe-notif" } {
	set add_smil [cli_get_value $CLI_CUR_PARENT_NODE "" "" "add-html"]
	if { $add_smil eq "enable" } {
		return 1
	}
}
return 0
        %}
        "system replacemsg-group mm3 {html-part}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm3-block-notif" ||
     $msg eq "mm3-virus-notif" ||
     $msg eq "mm3-bwl-notif" ||
     $msg eq "mm3-checksum-notif" ||
     $msg eq "mm3-bword-notif" ||
     $msg eq "mm3-flood-notif" ||
     $msg eq "mm3-dupe-notif" } {
	set add_smil [cli_get_value $CLI_CUR_PARENT_NODE "" "" "add-html"]
	if { $add_smil eq "enable" } {
		return 1
	}
}
return 0
        %}
        "system replacemsg mm4 {rsp-status}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm4-block" ||
     $msg eq "mm4-virus" ||
     $msg eq "mm4-bwl" ||
     $msg eq "mm4-checksum" ||
     $msg eq "mm4-flood" ||
     $msg eq "mm4-dupe" ||
     $msg eq "mm4-bword" } {
	return 1
}
return 0
	%}
        "system replacemsg-group mm4 {rsp-status}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm4-block" ||
     $msg eq "mm4-virus" ||
     $msg eq "mm4-bwl" ||
     $msg eq "mm4-checksum" ||
     $msg eq "mm4-flood" ||
     $msg eq "mm4-dupe" ||
     $msg eq "mm4-bword" } {
	return 1
}
return 0
	%}
        "system replacemsg mm4 {from-sender subject priority class}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm4-block" ||
     $msg eq "mm4-virus" ||
     $msg eq "mm4-bwl" ||
     $msg eq "mm4-checksum" ||
     $msg eq "mm4-flood" ||
     $msg eq "mm4-dupe" ||
     $msg eq "mm4-bword" } {
	return 0
}
return 1
        %}
        "system replacemsg-group mm4 {from-sender subject priority class}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm4-block" ||
     $msg eq "mm4-virus" ||
     $msg eq "mm4-bwl" ||
     $msg eq "mm4-checksum" ||
     $msg eq "mm4-flood" ||
     $msg eq "mm4-dupe" ||
     $msg eq "mm4-bword" } {
	return 0
}
return 1
        %}
        "system replacemsg mm4 {from}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm4-block" ||
     $msg eq "mm4-virus" ||
     $msg eq "mm4-bwl" ||
     $msg eq "mm4-checksum" ||
     $msg eq "mm4-flood" ||
     $msg eq "mm4-dupe" ||
     $msg eq "mm4-bword" } {
	return 1
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "from-sender"] eq "enable" } {
        return 0
}
return 1
	%}
        "system replacemsg-group mm4 {from}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm4-block" ||
     $msg eq "mm4-virus" ||
     $msg eq "mm4-bwl" ||
     $msg eq "mm4-checksum" ||
     $msg eq "mm4-flood" ||
     $msg eq "mm4-dupe" ||
     $msg eq "mm4-bword" } {
        return 1
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "from-sender"] eq "enable" } {
        return 0
}
return 1
	%}
        "system replacemsg mm4 {domain}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm4-block" ||
     $msg eq "mm4-virus" ||
     $msg eq "mm4-bwl" ||
     $msg eq "mm4-checksum" ||
     $msg eq "mm4-flood" ||
     $msg eq "mm4-dupe" ||
     $msg eq "mm4-bword" } {
        return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "from-sender"] eq "enable" } {
        return 0
}
return 1
        %}
        "system replacemsg-group mm4 {domain}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm4-block" ||
     $msg eq "mm4-virus" ||
     $msg eq "mm4-bwl" ||
     $msg eq "mm4-checksum" ||
     $msg eq "mm4-flood" ||
     $msg eq "mm4-dupe" ||
     $msg eq "mm4-bword" } {
        return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "from-sender"] eq "enable" } {
        return 0
}
return 1
        %}
        "system replacemsg mm4 {add-smil}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm4-block-notif" ||
     $msg eq "mm4-virus-notif" ||
     $msg eq "mm4-bwl-notif" ||
     $msg eq "mm4-checksum-notif" ||
     $msg eq "mm4-flood-notif" ||
     $msg eq "mm4-dupe-notif" ||
     $msg eq "mm4-bword-notif" } {
	return 1
}
return 0
	%}
        "system replacemsg-group mm4 {add-smil}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm4-block-notif" ||
     $msg eq "mm4-virus-notif" ||
     $msg eq "mm4-bwl-notif" ||
     $msg eq "mm4-checksum-notif" ||
     $msg eq "mm4-flood-notif" ||
     $msg eq "mm4-dupe-notif" ||
     $msg eq "mm4-bword-notif" } {
	return 1
}
return 0
	%}
        "system replacemsg mm4 {smil-part image}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm4-block-notif" ||
     $msg eq "mm4-virus-notif" ||
     $msg eq "mm4-bwl-notif" ||
     $msg eq "mm4-checksum-notif" ||
     $msg eq "mm4-flood-notif" ||
     $msg eq "mm4-dupe-notif" ||
     $msg eq "mm4-bword-notif" } {
	set add_smil [cli_get_value $CLI_CUR_PARENT_NODE "" "" "add-smil"]
	if { $add_smil eq "enable" } {
		return 1
	}
}
return 0
	%}
        "system replacemsg-group mm4 {smil-part image}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm4-block-notif" ||
     $msg eq "mm4-virus-notif" ||
     $msg eq "mm4-bwl-notif" ||
     $msg eq "mm4-checksum-notif" ||
     $msg eq "mm4-flood-notif" ||
     $msg eq "mm4-dupe-notif" ||
     $msg eq "mm4-bword-notif" } {
	set add_smil [cli_get_value $CLI_CUR_PARENT_NODE "" "" "add-smil"]
	if { $add_smil eq "enable" } {
		return 1
	}
}
return 0
	%}
        "system replacemsg mm7 {rsp-status}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm7-block" ||
     $msg eq "mm7-virus" ||
     $msg eq "mm7-bwl" ||
     $msg eq "mm7-checksum" ||
     $msg eq "mm7-bword" } {
	return 1
}
return 0
	%}
        "system replacemsg-group mm7 {rsp-status}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm7-block" ||
     $msg eq "mm7-virus" ||
     $msg eq "mm7-bwl" ||
     $msg eq "mm7-checksum" ||
     $msg eq "mm7-bword" } {
	return 1
}
return 0
	%}
        "system replacemsg mm7 {from-sender subject priority class allow-content-adaptation}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm7-block" ||
     $msg eq "mm7-virus" ||
     $msg eq "mm7-bwl" ||
     $msg eq "mm7-checksum" ||
     $msg eq "mm7-bword" } {
	return 0
}
return 1
        %}
        "system replacemsg-group mm7 {from-sender subject priority class allow-content-adaptation}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm7-block" ||
     $msg eq "mm7-virus" ||
     $msg eq "mm7-bwl" ||
     $msg eq "mm7-checksum" ||
     $msg eq "mm7-bword" } {
	return 0
}
return 1
        %}
        "system replacemsg mm7 {from addr-type}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm7-block" ||
     $msg eq "mm7-virus" ||
     $msg eq "mm7-bwl" ||
     $msg eq "mm7-checksum" ||
     $msg eq "mm7-bword" } {
        return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "from-sender"] eq "enable" } {
        return 0
}
return 1
	%}
        "system replacemsg-group mm7 {from addr-type}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm7-block" ||
     $msg eq "mm7-virus" ||
     $msg eq "mm7-bwl" ||
     $msg eq "mm7-checksum" ||
     $msg eq "mm7-bword" } {
        return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "from-sender"] eq "enable" } {
	return 0
}
return 1
	%}
        "system replacemsg mm7 {add-smil}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm7-block-notif" ||
     $msg eq "mm7-virus-notif" ||
     $msg eq "mm7-bwl-notif" ||
     $msg eq "mm7-checksum-notif" ||
     $msg eq "mm7-flood-notif" ||
     $msg eq "mm7-dupe-notif" ||
     $msg eq "mm7-bword-notif" } {
	return 1
}
return 0
	%}
        "system replacemsg-group mm7 {add-smil}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm7-block-notif" ||
     $msg eq "mm7-virus-notif" ||
     $msg eq "mm7-bwl-notif" ||
     $msg eq "mm7-checksum-notif" ||
     $msg eq "mm7-flood-notif" ||
     $msg eq "mm7-dupe-notif" ||
     $msg eq "mm7-bword-notif" } {
	return 1
}
return 0
	%}
        "system replacemsg mm7 {smil-part image}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm7-block-notif" ||
     $msg eq "mm7-virus-notif" ||
     $msg eq "mm7-bwl-notif" ||
     $msg eq "mm7-checksum-notif" ||
     $msg eq "mm7-flood-notif" ||
     $msg eq "mm7-dupe-notif" ||
     $msg eq "mm7-bword-notif" } {
	set add_smil [cli_get_value $CLI_CUR_PARENT_NODE "" "" "add-smil"]
	if { $add_smil eq "enable" } {
		return 1
	}
}
return 0
	%}
        "system replacemsg-group mm7 {smil-part image}" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "msg-type"]
if { $msg eq "mm7-block-notif" ||
     $msg eq "mm7-virus-notif" ||
     $msg eq "mm7-bwl-notif" ||
     $msg eq "mm7-checksum-notif" ||
     $msg eq "mm7-flood-notif" ||
     $msg eq "mm7-dupe-notif" ||
     $msg eq "mm7-bword-notif" } {
	set add_smil [cli_get_value $CLI_CUR_PARENT_NODE "" "" "add-smil"]
	if { $add_smil eq "enable" } {
		return 1
	}
}
return 0
	%}
	"antivirus service {uncompsizelimit uncompnestlimit scan-bzip2}" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "service"] eq "https" } {
	if { ![cli_has_feature "f_ssl_proxy"] } {
		return 0
	}
}
return 1
	%}
	"antivirus service block-page-status-code" = %{
set msg [cli_get_value $CLI_CUR_PARENT_NODE "" "" "service"]
if { [cli_has_feature "f_ssl_proxy"] } {
	if { $msg ne "https" && $msg ne "http" } {
		return 0
	}
} else {
	if { $msg ne "http" } {
		return 0
	}
}
return 1
	%}
	"system ntp interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "server-mode" 0 "enable"]
	%}
        "firewall {interface-policy interface-policy6 sniff-interface-policy sniff-interface-policy6 sniffer} {application-list ips-sensor av-profile webfilter-profile spamfilter-profile dlp-sensor ips-DoS}" = %{
set match $CLI_CUR_NODE_NAME
append match "-status"
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" $match 0 "enable"] } {
	return 1
}
return 0
        %}
	"system dhcp server reserved-address ip" = %{
if { ![cli_ver_start 500 0] } { return 1 }
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "reserved"] } {
	return 1
}
return 0
	%}
	"system dhcp server reserved-address {mac action}" = %{
if { [cli_branchpt_start 600 720] } {
	return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "mac"]]
}
return 1
	%}
	"system dhcp server reserved-address {circuit-id circuit-id-type remote-id remote-id-type}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "option82"]
	%}
	"system dhcp server options ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ip"]
	%}
	"system dhcp server options value" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "hex"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "string"]
	%}
        "firewall DoS-policy6 anomaly threshold" = %{
return 1
        %}
        "system {replacemsg replacemsg-group} {sslvpn traffic-quota nac-quar ec auth admin alertmail im spam fortiguard-wf nntp ftp mm7 mm3 mm4 mm1 mms http mail captive-portal-dflt utm custom-message device-detection-portal} {buffer header format}" = %{
return 1
        %}
        "system {replacemsg replacemsg-group} {mm3 mm4 mm7} message" = %{
return 1
        %}
        "system {replacemsg replacemsg-group} mm3 image" = %{
return 1
        %}
        "system replacemsg-group {name comment}" = %{
return 1
        %}
        "system replacemsg-image {name image-base64}" = %{
return 1
        %}
        "application custom comment" = %{
return 1
        %}
        "firewall {sniffer DoS-policy} anomaly threshold" = %{
return 1
        %}
		"firewall {DoS-policy DoS-policy6} anomaly {quarantine-expiry quarantine-log}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "quarantine" 0 "attacker"]
		%}
        "router {ospf isis} summary-address prefix" = %{
return 1
        %}
        "router ospf network prefix" = %{
return 1
        %}
	"router route-map rule {match-metric match-route-type match-tag set-metric set-metric-type set-tag set-weight}" = %{
return 1
	%}
        "firewall profile-protocol-options {mapi im nntp smtp pop3 imap ftp http} options" = %{
return 1
        %}
        "firewall profile-protocol-options http post-lang" = %{
return 1
        %}
        "router ospf6 summary-address prefix6" = %{
return 1
        %}
        "router ospf6 area range prefix6" = %{
return 1
        %}
        "router ospf area range prefix" = %{
return 1
        %}
        "router prefix-list6 rule {prefix6 ge le}" = %{
return 1
        %}
	"router prefix-list rule {prefix ge le}" = %{
return 1
	%}
	"router aspath-list rule action" = %{
return 1
	%}
        "firewall gtp policy messages" = %{
return 1
        %}
	"firewall gtp policy { imsi-prefix rai rat-type uli }" = %{
set messages [cli_get_value $CLI_CUR_PARENT_NODE "" "" "messages"]
foreach msg $messages {
	if { $msg eq "create-res" || $msg eq "update-res" } {
		return 0
	}
}
return 1
        %}
	"firewall gtp policy { apnmember apn-sel-mode imei msisdn-prefix mei }" = %{
set messages [cli_get_value $CLI_CUR_PARENT_NODE "" "" "messages"]
foreach msg $messages {
	if { $msg eq "create-res" || $msg eq "update-res" || $msg eq "update-req" } {
		return 0
	}
}
return 1
		%}
	"firewall gtp {message-rate-limit-v0 message-rate-limit-v1}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "rate-limit-mode" 0 "per-stream"]
        %}
		"firewall gtp policy max-apn-restriction" = %{
set messages [cli_get_value $CLI_CUR_PARENT_NODE "" "" "messages"]
foreach msg $messages {
	if { $msg eq "update-req" } {
		return 0
	}
}
return 1
        %}
	"web-proxy global proxy-fqdn" = %{
return 1
	%}
	"wanopt settings host-id" = %{
return 1
	%}
	"ips rule {status log log-packet}" = %{
return 1
	%}
	"ips custom comment" = %{
return 1
	%}
	"router multicast interface pim-mode" = %{
return 1
	%}
	"log disk setting status" = %{
return 1
	%}
	"user ldap cnid" = %{
return 1
	%}
	"gui console preferences" = %{
return 1
	%}
	"system ha secondary-vcluster {vdom override}" = %{
return 1
	%}
	"system ha override" = %{
return 1
	%}
	"system ha_old secondary-vcluster {vdom override}" = %{
return 1
	%}
	"system ha_old override" = %{
return 1
	%}
	"vpn ssl settings {source-address source-address-negate source-address6 source-address6-negate default-portal}" = %{
set s [cli_get_value $CLI_CUR_PARENT_NODE "" "" "source-interface"]
if { $s ne 0 && $s ne "" } {
	return 1
}
return 0
	%}
	"wanopt profile {http tcp} ssl-port" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssl" 0 "enable"]
	%}
	"wanopt {auth-group peer profile settings storage ssl-server webcache rule}" = %{
if { [cli_get_devinfo "is_rev_support_wanopt"] eq "no" } {
	return 0
}
return 1
	%}
        "firewall policy wanopt" = %{
if { [cli_ver_start 700 0] } {
	set inspection_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"]
	if { $inspection_mode eq "proxy" } {
		set dstaddr [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dstaddr"]
		set vipnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $dstaddr ""]
		if { $vipnode ne 0 } {
			set type [cli_get_value $vipnode "" "" "type"]
			if { $type eq "access-proxy" } {
				return 0
			}
		}
	}
}
if { [cli_ver_start 600 4] } {
	namespace import global::ngfw_mode_policy
	if { [ngfw_mode_policy] } {
		return 1
	}
}
if { [cli_ver_start 500 2] } {
	if { [cli_ver_start 500 4] } {
		set learn_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "learning-mode"]
		if { $learn_mode eq "enable" } {
			return 1
		}
	}
	set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
	if { $action eq "accept" } {
		if { !$CLI_GLOBAL_DEV && [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
			namespace import global::inspection_mode_vdom_flow
			if { [inspection_mode_vdom_flow] } {
				return 0
			}
		} elseif { [cli_ver_start 600 2] } {
			set insp [cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"]
			if { $insp eq "flow" } {
				return 0
			}
		}
		return 1
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 1 "deny"] } {
		if { [cli_has_feature "f_webproxy"] } {
			if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"web-proxy\""] ||
             		     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"ftp-proxy\""] } {
				return 0
			}
		}
		return 1
	}
}
return 0
        %}
        "firewall policy wanopt-detection" = %{
if { [cli_ver_start 500 2] } {
	if { [cli_ver_start 500 4] } {
		set learn_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "learning-mode"]
		if { $learn_mode eq "enable" } {
			return 1
		}
	}
	set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
	if { $action eq "accept" } {
		if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wanopt"] ne "enable" } {
			return 0
		}
		if { !$CLI_GLOBAL_DEV && [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
			namespace import global::inspection_mode_vdom_flow
			if { [inspection_mode_vdom_flow] } {
				return 0
			}
		} elseif { [cli_ver_start 600 2] } {
			set insp [cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"]
			if { $insp eq "flow" } {
				return 0
			}
		}
		return 1
	}
} else {
	set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
	if { $action ne "deny" } {
		if { [cli_has_feature "f_webproxy"] } {
			if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"web-proxy\""] ||
             		     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"ftp-proxy\""] ||
             		     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"wanopt\""] } {
				return 0
			}
		}
		if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wanopt"] eq "enable" } {
			return 1
		}
	}
}
return 0
        %}
        "firewall policy wanopt-profile" = %{
if { [cli_get_devinfo "is_rev_support_wanopt"] eq "no" } {
        return 0
}
if { [cli_ver_start 500 2] } {
	set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
	if { $action eq "accept" } {
		if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt" 1 "enable"] } {
			return 0
		}
		if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt-detection" 0 "passive"]} {
			return 0
		}
		if { !$CLI_GLOBAL_DEV && [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
			namespace import global::inspection_mode_vdom_flow
			if { [inspection_mode_vdom_flow] } {
				return 0
			}
		}
		return 1
	}
} else {
	set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
	if { $action ne "deny" } {
		if { [cli_has_feature "f_webproxy"] } {
			if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"web-proxy\""] ||
             		     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"ftp-proxy\""] ||
             		     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"wanopt\""] } {
				return 0
			}
		}
		if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt-detection" 1 "passive"]} {
			return 1
		}
	}
}
return 0
        %}
        "firewall policy wanopt-peer" = %{
if { !$CLI_GLOBAL_DEV } {
	if { [cli_get_devinfo "is_rev_support_wanopt"] eq "no" } {
		return 0
	}
}
if { [cli_has_feature "f_webproxy"] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"web-proxy\""] ||
             [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"ftp-proxy\""] ||
             [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"wanopt\""] } {
		return 0
	}
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt" 1 "enable"] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt-detection" 1 "off"]} {
	return 0
}
return 1
        %}
        "firewall policy wanopt-passive-opt" = %{
if { [cli_get_devinfo "is_rev_support_wanopt"] eq "no" } {
        return 0
}
if { [cli_has_feature "f_webproxy"] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"web-proxy\""] ||
             [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"ftp-proxy\""] ||
             [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"wanopt\""] } {
		return 0
	}
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt" 1 "enable"] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt-detection" 1 "passive"]} {
	return 0
}
return 1
        %}
	"firewall policy webcache" = %{
if { [cli_get_devinfo "is_rev_support_wanopt"] eq "no" } {
        return 0
}
if { [cli_ver_start 700 0] } {
	set inspection_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"]
	if { $inspection_mode eq "proxy" } {
		set dstaddr [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dstaddr"]
		set vipnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $dstaddr ""]
		if { $vipnode ne 0 } {
			set type [cli_get_value $vipnode "" "" "type"]
			if { $type eq "access-proxy" } {
				return 0
			}
		}
	}
}
if { [cli_ver_start 600 4] } {
	namespace import global::ngfw_mode_policy
	if { [ngfw_mode_policy] } {
		return 1
	}
}
if { [cli_ver_start 500 4] } {
	set learn_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "learning-mode"]
	if { $learn_mode eq "enable" } {
		return 1
	}
	set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
	if { $action eq "accept" } {
		if { !$CLI_GLOBAL_DEV && [cli_ver_start 500 4] && ![cli_ver_start 600 2] } {
			namespace import global::inspection_mode_vdom_flow
			if { ![inspection_mode_vdom_flow] } {
				return 1
			}
		} elseif { [cli_ver_start 600 2] } {
			set insp [cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"]
			if { $insp ne "flow" } {
				return 1
			}
		}
	}
} elseif { [cli_ver_start 500 2] } {
	set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
	if { $action eq "accept" } {
		return 1
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 1 "deny"] } {
		return 1
	}
}
return 0
	%}
	"firewall {policy policy6 proxy-policy explicit-proxy-policy} {global-label label}" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value eq 0 || $value eq "" } {
	return 0
}
return 1
	%}
	"firewall explicit-proxy-policy webcache" = %{
if { [cli_get_devinfo "is_rev_support_wanopt"] eq "no" } {
        return 0
}
if { [cli_ver_start 500 2] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 1 "ftp"] } {
		return 1
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 1 "deny"] } {
		return 1
	}
}
return 0
	%}
	"firewall policy webcache-https" = %{
if { [cli_ver_start 700 0] } {
	set inspection_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"]
	if { $inspection_mode eq "proxy" } {
		set dstaddr [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dstaddr"]
		set vipnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $dstaddr ""]
		if { $vipnode ne 0 } {
			set type [cli_get_value $vipnode "" "" "type"]
			if { $type eq "access-proxy" } {
				return 0
			}
		}
	}
}
if { [cli_ver_start 600 4] } {
	namespace import global::ngfw_mode_policy
	if { [ngfw_mode_policy] } {
		return 1
	}
}
if { [cli_get_devinfo "is_rev_support_wanopt"] eq "no" } {
        return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 1 "deny"] } {
	return 1
}
return 0
	%}
	"firewall explicit-proxy-policy webcache-https" = %{
if { [cli_get_devinfo "is_rev_support_wanopt"] eq "no" } {
        return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 1 "deny"] } {
	return 1
}
return 0
	%}
	"report style {border-bottom border-left border-right border-top}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "options" 0 "border"]
	%}
	"report style line-height" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "options" 0 "text"]
	%}
	"report style {fg-color bg-color}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "options" 0 "color"]
	%}
	"report style align" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "options" 0 "align"]
	%}
	"report style {width height}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "options" 0 "size"]
	%}
	"report style {margin-top margin-bottom margin-left margin-right}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "options" 0 "margin"]
	%}
	"report style {padding-top padding-bottom padding-left padding-right}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "options" 0 "padding"]
	%}
	"report style {column-span column-gap}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "options" 0 "column"]
	%}
	"endpoint-control profile {device-groups users user-groups}" = %{
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "profile-name"]
if { $name eq "default" } {
	return 0
}
return 1
	%}
	"system dialinsvr {client-ip server-ip usrgrp allowaccess modem-dev}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system password-policy {apply-to minimum-length min-lower-case-letter min-upper-case-letter min-number min-non-alphanumeric change-4-characters expire-status}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"firewall ssl-ssh-profile ssl-exempt" = %{
namespace import global::deep_inspection_check
return [deep_inspection_check $CLI_CUR_PARENT_NODE "ssl-exempt"]
	%}
	"firewall ssl-ssh-profile untrusted-caname" = %{
namespace import global::deep_inspection_check
return [deep_inspection_check $CLI_CUR_PARENT_NODE "untrusted-caname"]
	%}
	"firewall ssl-ssh-profile server-cert-mode" = %{
namespace import global::deep_inspection_check
return [deep_inspection_check $CLI_CUR_PARENT_NODE "server-cert-mode"]
	%}
	"firewall ssl-ssh-profile whitelist" = %{
namespace import global::deep_inspection_check
return [deep_inspection_check $CLI_CUR_PARENT_NODE "whitelist"]
	%}
        "firewall ssl-ssh-profile {ssl https imaps smtps pop3s ftps} unsupported-ssl inspect" = %{
return 0
	%}
        "firewall ssl-ssh-profile {ssl https imaps smtps pop3s ftps} unsupported-ssl" = %{
set ssl [cli_get_node [cli_get_parent $CLI_CUR_PARENT_NODE] "ssl" "" ""]
if { $ssl eq 0 } {
	set ins [cli_get_defvalue "firewall ssl-ssh-profile ssl" "inspect-all"]
} else {
	set ins [cli_get_value $ssl "" "" "inspect-all"]
}
set d $CLI_CUR_PARENT_NAME
if { $d eq "ssl" } {
	if { $ins eq "disable" } {
		return 0
	}
} elseif { $d eq "https" || $d eq "imaps" || $d eq "smtps" || $d eq "pop3s" || $d eq "ftps" } {
	if { $ins ne "disable" } {
		return 0
	}
	if { [cli_branchpt_start 600 158] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "disable"]} {
		return 0
	}
}
return 1
        %}
	"firewall ssl-ssh-profile ssl client-cert-request" = %{
set ssl [cli_get_node [cli_get_parent $CLI_CUR_PARENT_NODE] "ssl" "" ""]
if { $ssl eq 0 } {
	set ins [cli_get_defvalue "firewall ssl-ssh-profile ssl" "inspect-all"]
} else {
	set ins [cli_get_value $ssl "" "" "inspect-all"]
}
if { $ins eq "disable" } {
	return 0
}
if { [cli_branchpt_start 600 158] && $ins ne "deep-inspection" } {
	return 0
}
return 1
	%}
	"system interface link-up-delay" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "aggregate" || $type eq "redundant" || $type eq "fortilink" } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"] ne "modem" } {
		return 1
	}
}
return 0
	%}
	"firewall {policy policy6} send-deny-packet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "deny"]
	%}
	"firewall {policy policy6} firewall-session-dirty" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "firewall-session-dirty" 0 "check-policy-option"]
	%}
	"user group {user-id email password user-name sponsor company mobile-phone}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "guest"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "multiple-guest-add" 0 "disable"]
	%}
	"user group {expire-type expire max-accounts multiple-guest-add}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-type" 0 "guest"]
	%}
	"user group {guest}" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "guest"]
	%}
	"dlp filepattern entries file-type hibun" = %{
if { $CLI_GLOBAL_DEV } {
        return 1
} elseif { [cli_is_match $CLI_GLOBAL_NODE 0 "system global" "special-file-23-support" 0 "enable"] } {
	return 1
}
return 0
	%}
	"firewall mms-profile {flood dupe} {window1 limit1 action1 block-time1 status2}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status1" 0 "enable"]
	%}
	"firewall mms-profile {flood dupe} {window2 limit2 action2 block-time2 status3}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status2" 0 "enable"]
	%}
	"firewall mms-profile {flood dupe} {window3 limit3 action3 block-time3}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status3" 0 "enable"]
	%}
	"firewall multicast-address subnet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "broadcastmask"]
	%}
	"firewall multicast-address {start-ip end-ip}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "multicastrange"]
	%}
	"firewall multicast-address associated-interface" = %{
set intf [cli_get_value $CLI_CUR_NODE "" "" ""]
set intf [string trim $intf \"]
if { $intf eq "any" } {
	return 0
}
return 1
	%}
	"firewall multicast-policy {dnat snat}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "accept"]
	%}
	"firewall multicast-policy snat-ip" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "deny" } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "snat" 0 "enable"]
	%}
	"system global optimize" = %{
if { ![cli_branchpt_start 500 715] } {
	if { [cli_get_devinfo "get_kernel_optimize_option"] eq "no" } {
		return 0
	}
}
return 1
	%}
	"system global optimize session-setup" = %{
expr [cli_has_feature "f_optimize_session_setup"]
	%}
	"log memory setting status" = %{
return 1
	%}
	"log threat-weight web category" = %{
return 1
	%}
	"system interface secondaryip" = %{
if { [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "secondary-IP" 0 "disable"] } {
	return 0
}
if { [cli_ver_start 500 4] } {
	namespace import global::nCfg_is_port_pair_member
	set ifnode [cli_get_parent $CLI_CUR_PARENT_NODE]
        if {[nCfg_is_port_pair_member $ifnode]} {
		cli_set_errmsg "interface is used by system.virtual-ware-pair"
                return 0
        }
}
return 1
	%}
	"web-proxy forward-server ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-type" 0 "ip"]
	%}
	"web-proxy forward-server fqdn" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-type" 0 "fqdn"]
	%}
	"web-proxy forward-server monitor" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "healthcheck" 0 "enable"]
	%}
	"system global {proxy-worker-count ssl-worker-count virtual-server-count wad-worker-count sslvpn-max-worker-count}" = %{
set cpu_limit [cli_get_devinfo "cpu_limit"]
if { $cpu_limit eq 1 } {
	return 0
}
return 1
	%}
	"system global scanunit-count" = %{
if { [cli_ver_start 600 4] } {
	return 1
}
if { [cli_get_devinfo "cpu_limit"] eq 1 } {
	return 0
}
return 1
	%}
	"system interface {broadcast-forticlient-discovery endpoint-compliance}" = %{
if { [cli_branchpt_start 600 1065] } {
	return 1
}
if { [cli_branchpt_start 500 1016] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fortiheartbeat" 1 "enable"] } {
		return 0
	}
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "listen-forticlient-connection" 1 "enable"] } {
		return 0
	}
}
return 1
	%}
	"webfilter ftgd-local-rating {url rating}" = %{
return 1
	%}
	"wireless-controller wtp wtp-profile" = %{
return 1
	%}
	"extender-controller extender ifname" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "admin" 0 "enable"]
	%}
	"extender-controller extender wan-extension {modem1-extension modem2-extension}" = %{
set authorized [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "authorized"]
set extension_type [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "extension-type" ]
if { $authorized eq "disable" || $extension_type eq "lan-extension"} {
	return 0
}
return 1
	%}
	"extension-controller extender wan-extension {modem1-extension modem2-extension}" = %{
set authorized [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "authorized"]
set extension_type [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "extension-type" ]
if { $authorized eq "disable" || $extension_type eq "lan-extension"} {
	return 0
}
return 1
	%}
	"voip profile sip {ssl-min-version ssl-max-version ssl-send-empty-frags ssl-client-renegotiation ssl-algorithm}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssl-mode" 0 "full"]
	%}
	"system wccp server-list" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "wccp-cache-engine" 1 "enable"]
	%}
	"system wccp router-list" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "wccp-cache-engine" 0 "enable"]
	%}
	"firewall {local-in-policy local-in-policy6} {intf schedule}" = %{
return 1
	%}
	"firewall {local-in-policy local-in-policy6} {srcaddr dstaddr service}" = %{
return 1
	%}
	"firewall address name" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "SSLVPN_TUNNEL_ADDR1" } {
	if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
		return 0
	}
}
return 1
	%}
	"firewall address sdn-addr-type" = %{
set subtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "sub-type"]
if { $subtype eq "sdn" } {
	set sdn [cli_get_value $CLI_CUR_PARENT_NODE "" "" "sdn"]
	if { $sdn eq "acs" || $sdn eq "aws" || $sdn eq "azure" || $sdn eq "gcp" || $sdn eq "oci" || $sdn eq "kubernetes" || $sdn eq "openstack" || $sdn eq "ibm" } {
		return 1
	}
}
return 0
	%}
	"firewall address6 name" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "SSLVPN_TUNNEL_IPv6_ADDR1" } {
	if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
		return 0
	}
}
return 1
	%}
	"firewall address6 { start-ip end-ip}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "iprange"]
%}
	"system settings {manageip manageip6}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "opmode" 0 "transparent"]
	%}
	"system settings {ip device}" = %{
set mn [cli_get_value $CLI_CUR_PARENT_NODE "" "" "opmode"]
set mo [cli_get_org_value $CLI_CUR_PARENT_NODE "" "" "opmode"]
if { $mo eq "transparent" && $mn eq "nat" } {
	return 1
}
return 0
	%}
	"system settings {bfd-desired-min-tx bfd-detect-mult bfd-required-min-rx bfd-dont-enforce-src-port}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "bfd" 0 "enable"]
	%}
	"switch-controller managed-switch ports {speed status}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"]
	%}
	"switch-controller managed-switch ports {allowed-vlans-all untagged-vlans stp-state port-security-policy mac-addr}" = %{
set owner [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-owner" 1]
if { $owner eq 0 || $owner eq "" } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch ports vlan" = %{
set owner [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-owner" 1]
if { $owner eq 0 || $owner eq "" } {
	if { [cli_ver_start 600 4] && $CLI_GLOBAL_DEV } {
		expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "access-mode" 0 "normal"]
	}
	return 1
}
return 0
	%}
	"switch-controller managed-switch ports {igmps-flood-traffic igmps-flood-reports}" = %{
set owner [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-owner" 1]
if { $owner eq 0 || $owner eq "" } {
	return 1
}
if { [cli_branchpt_start 600 1051] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "igmp-snooping" 0 "enable"]} {
	return 1
}
return 0
	%}
	"switch-controller managed-switch {name description switch-profile fsw-wan2-peer fsw-wan2-admin dynamic-capability}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"]
	%}
	"switch-controller managed-switch {directly-connected dynamically-discovered pre-provisioned firmware-provision-version staged-image-version delayed-restart-trigger}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"]
	%}
	"switch-controller managed-switch ports igmp-snooping" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x1  } {
	set owner [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-owner" 1]
	if { $owner eq 0 || $owner eq "" } {
		return 1
	}
}
return 0
	%}
	"switch-controller managed-switch ports dhcp-snooping" = %{
if { [cli_ver_start 500 6] } {
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x2 } {
	set owner [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-owner" 1]
	if { $owner eq 0 || $owner eq "" } {
		return 1
	}
}
} else {
set owner [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-owner" 1]
if { $owner eq 0 || $owner eq "" } {
	return 1
}
}
return 0
	%}
	"switch-controller managed-switch ports lldp-profile" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x4  } {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"]
} else {
	return 0
}
	%}
	"switch-controller managed-switch switch-device-tag" = %{
set capa [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV } {
	return 1
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"] && $capa & 0x4  } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch ports mclag" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x20 } {
	set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
	if { $type eq "trunk" } {
		return 1
	}
}
return 0
	%}
	"switch-controller managed-switch mclag-igmp-snooping-aware" = %{
set capa [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV } {
	return 1
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"] && $capa & 0x20 } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch ports qos-policy" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x100 } {
	set owner [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-owner" 1]
	if { $owner eq 0 || $owner eq "" } {
		return 1
	}
}
return 0
	%}
	"switch-controller managed-switch ports stp-bpdu-guard-timeout" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x800 } {
	set owner [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-owner" 1]
	set state [cli_get_value $CLI_CUR_PARENT_NODE "" "" "stp-state"]
	set edge [cli_get_value $CLI_CUR_PARENT_NODE "" "" "edge-port"]
	set bpdu [cli_get_value $CLI_CUR_PARENT_NODE "" "" "stp-bpdu-guard"]
	if { $owner eq "" && $state eq "enabled" && $bpdu eq "enabled" && $edge eq "enable" } {
		return 1
	}
}
return 0
	%}
	"switch-controller managed-switch ports stp-bpdu-guard" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x800 } {
	set owner [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-owner" 1]
	set state [cli_get_value $CLI_CUR_PARENT_NODE "" "" "stp-state"]
	set edge [cli_get_value $CLI_CUR_PARENT_NODE "" "" "edge-port"]
	if { $owner eq "" && $state eq "enabled" && $edge eq "enable" } {
		return 1
	}
}
return 0
	%}
	"switch-controller managed-switch ports stp-root-guard" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x1000 } {
	set owner [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-owner" 1]
	set state [cli_get_value $CLI_CUR_PARENT_NODE "" "" "stp-state"]
	if { $owner eq "" && $state eq "enabled" } {
		return 1
	}
}
return 0
	%}
	"switch-controller managed-switch ports learning-limit" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x2000 } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch ports sticky-mac" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x8000 } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch ports {packet-sampler sflow-sampler}" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x10000 } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch ports {sflow-counter-interval sflow-sample-rate}" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x10000 } {
	if { [cli_ver_start 600 2] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sflow-sampler" 0 "enabled"] } {
		return 1
	}
}
return 0
	%}
	"switch-controller managed-switch ports {packet-sample-rate}" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x10000 } {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "packet-sampler" 0 "enabled"]
} else {
	return 0
}
	%}
	"switch-controller managed-switch ports {sample-direction}" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x10000 } {
	if { [cli_ver_start 600 2] } {
		expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "packet-sampler" 0 "enabled"]
	} else {
		expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sflow-sampler" 0 "enabled"]
	}
} else {
	return 0
}
	%}
	"switch-controller managed-switch flow-identity" = %{
set capa [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x100000 } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch ports storm-control-policy" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x400000 } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch poe-lldp-detection" = %{
set capa [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x2000000 } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch ports ip-source-guard" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV } {
	return 1
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"] && $capa & 0x40000000 } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch {qos-red-probability qos-drop-policy}" = %{
set capa [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x80000000 } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch ports ptp-policy" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x200000000 } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch ports fec-state" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x8000000000 } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch ports pause-meter" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x10000000000 } {
	set fc [cli_get_value $CLI_CUR_PARENT_NODE "" "" "flow-control"]
	if { $fc ne "rx" && $fc ne "disable" } {
		return 1
	}
}
return 0
	%}
	"switch-controller managed-switch ports pause-meter-resume" = %{
set capa [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "dynamic-capability"]
if { $CLI_GLOBAL_DEV || $capa & 0x10000000000 } {
	set fc [cli_get_value $CLI_CUR_PARENT_NODE "" "" "flow-control"]
	if { $fc ne "rx" && $fc ne "disable" } {
		set meter [cli_get_value $CLI_CUR_PARENT_NODE "" "" "pause-meter"]
		if { $meter ne 0 } {
			return 1
		}
	}
}
return 0
	%}
	"switch-controller managed-switch ports allowed-vlans" = %{
set owner [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-owner" 1]
if { $owner eq 0 || $owner eq "" } {
	return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "allowed-vlans-all" 0 "disable"]
}
return 0
	%}
	"switch-controller managed-switch ports {poe-status}" = %{
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-name"]
set swnode [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]]
if { $CLI_GLOBAL_DEV } {
	set platform [cli_get_value $swnode "" "" "_platform"]
} else {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "poe-capable"] } {
		return 1
	}
	set platform [cli_get_value $swnode "" "" "switch-id"]
}
if { [cli_fsp_is_poe_supported $platform $name] } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch ports {loop-guard loop-guard-timeout}" = %{
set owner [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-owner" 1]
if { $owner eq 0 || $owner eq "" } {
	return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"]
}
return 0
	%}
	"switch-controller managed-switch ports {port-selection-criteria mode bundle min-bundle max-bundle members aggregator-mode}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "trunk"]
	%}
	"switch-controller managed-switch ports edge-port" = %{
set owner [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-owner" 1]
set state [cli_get_value $CLI_CUR_PARENT_NODE "" "" "stp-state"]
if { $owner eq "" && $state eq "enabled" } {
	return 1
}
return 0
	%}
	"switch-controller security-policy 802-1X guest-vlan-id" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "guest-vlan" 0 "enable"]
	%}
	"switch-controller security-policy 802-1X auth-fail-vlan" = %{
if { [cli_ver_start 600 2] } {
	return 1
} else {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-mode" 0 "802.1X"]
}
	%}
	"switch-controller security-policy 802-1X auth-fail-vlan-id" = %{
if { [cli_ver_start 600 2] } {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth-fail-vlan" 0 "enable"]
} else {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-mode" 0 "802.1X"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth-fail-vlan" 0 "enable"]
}
	%}
	"switch-controller security-policy 802-1X {guest-vlanid auth-fail-vlanid}" = %{
return 0
	%}
	"switch-controller security-policy 802-1X {mac-auth-bypass eap-passthru guest-vlan radius-timeout-overwrite}" = %{
return 1
	%}
	"switch-controller lldp-profile med-network-policy" = %{
set tlvs [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "med-tlvs"]
if { [string match "*network-policy*" $tlvs] } {
	return 1
}
return 0
	%}
	"switch-controller lldp-profile med-location-service" = %{
set tlvs [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "med-tlvs"]
if { [string match "*location-identification*" $tlvs] } {
	return 1
}
return 0
	%}
	"switch-controller switch-profile" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "system global" "switch-controller" 0 "enable"] && [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 1 "transparent"]
	%} 
	"system {virtual-wan-link swdan} members interface" = %{
if { $CLI_GLOBAL_DEV } {
	if { $CLI_CUR_PARENT_NAME eq "dynamic_mapping" } {
		## this attribute is not available for dynamic mapping
		return 0
	}
	set mapping [cli_get_value $CLI_CUR_PARENT_NODE "" "" "_dynamic-member"]
	if { $mapping ne 0 && [string trim $mapping \"] ne "" } {
		return 0
	}
}
return 1
	%}
	"system {virtual-wan-link sdwan} health-check sla jitter-threshold" = %{
set lcf [cli_get_value $CLI_CUR_PARENT_NODE "" "" "link-cost-factor"]
if { [string match "*jitter*" $lcf] } {
	return 1
}
return 0
	%}
	"system {virtual-wan-link sdwan} health-check sla latency-threshold" = %{
set lcf [cli_get_value $CLI_CUR_PARENT_NODE "" "" "link-cost-factor"]
if { [string match "*latency*" $lcf] } {
	return 1
}
return 0
	%}
	"system {virtual-wan-link sdwan} health-check sla packetloss-threshold" = %{
set lcf [cli_get_value $CLI_CUR_PARENT_NODE "" "" "link-cost-factor"]
if { [string match "*packet-loss*" $lcf] } {
	return 1
}
return 0
	%}
	"system interface {switch-controller-igmp-snooping switch-controller-dhcp-snooping switch-controller-access-vlan switch-controller-traffic-policy switch-controller-learning-limit}" = %{
if { $CLI_GLOBAL_DEV } {
	## fsp vlan
	return 1
}
namespace import global::nCfg_is_interface_used_by_switchctl
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "vlan" && [nCfg_is_interface_used_by_switchctl $name] } {
	return 1
}
return 0
	%}
	"system interface {switch-controller-dhcp-snooping-verify-mac switch-controller-dhcp-snooping-option82}" = %{
if { $CLI_GLOBAL_DEV } {
	## fsp vlan
	return 1
}
namespace import global::nCfg_is_interface_used_by_switchctl
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set snooping [cli_get_value $CLI_CUR_PARENT_NODE "" "" "switch-controller-dhcp-snooping"]
if { $type eq "vlan" &&  $snooping eq "enable" && [nCfg_is_interface_used_by_switchctl $name] } {
	return 1
}
return 0
	%}
	"system interface switch-controller-auth" = %{
if { $CLI_GLOBAL_DEV } {
	## fsp vlan
	return 1
}
namespace import global::nCfg_is_interface_used_by_switchctl
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set auth [cli_get_value $CLI_CUR_PARENT_NODE "" "" "security-mode"]
if { $type eq "vlan" &&  $auth eq "802.1X" && [nCfg_is_interface_used_by_switchctl $name] } {
	return 1
}
return 0
	%}
	"system interface switch-controller-radius-server" = %{
if { $CLI_GLOBAL_DEV } {
	## fsp vlan
	return 1
}
namespace import global::nCfg_is_interface_used_by_switchctl
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set auth [cli_get_value $CLI_CUR_PARENT_NODE "" "" "switch-controller-auth"]
if { $type eq "vlan" &&  $auth eq "radius" && [nCfg_is_interface_used_by_switchctl $name] } {
	return 1
}
return 0
	%}
	"system interface vlan-id" = %{
set intf_name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set intf_name [string trim $intf_name \"]
set sfp_dsl [cli_get_value $CLI_CUR_PARENT_NODE "" "" "sfp-dsl"]
set phy_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phy-mode"]
set tc_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "tc-mode"]
set vlan_op_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "vlan-op-mode"]
if { $intf_name eq "dsl" || $sfp_dsl eq "enable" } {
	if { $phy_mode eq "adsl2" || $phy_mode eq "adsl2+" || $phy_mode eq "adsl-auto" } {
		if { $tc_mode eq "atm" && $vlan_op_mode eq "tag" } {
			return 1
		}
	}
}
return 0
	%}
	"switch-controller qos ip-dscp-map map {cos-queue value}" = %{
return 1
	%}
	"router route-map rule set-extend_tag" = %{
return 1
	%}
	"firewall ippool {source-startip source-endip}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fixed-port-range"]
	%}
	"firewall ippool {block-size num-blocks-per-user permit-any-host pba-timeout}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "port-block-allocation"]
	%}
	"firewall ippool associated-interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "overload"]
	%}
	"system vdom-netflow {collector-ip collector-port source-ip}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "vdom-netflow" 0 "enable"]
	%}
	"system interface {forward-error-correction}" = %{
namespace import global::sys_intf_is_media_iface
namespace import global::platform_digit_suffix
namespace import global::is_platform_support_hyperscale
set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set ifname [string trim $ifname \"]
set platform [cli_get_devinfo "platform"]
set suffix [platform_digit_suffix $platform]
if {  [regexp -nocase {3700F|3701F} $suffix] } {
	return 1
} elseif {  [regexp -nocase {6000F|7000E|7000F} $suffix] } {
	namespace import global::sys_intf_forward_error_correction_option
	set mediatype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mediatype"]
	set speed [cli_get_value $CLI_CUR_PARENT_NODE "" "" "speed"]
	set list {}
	return [sys_intf_forward_error_correction_option list $platform $ifname $mediatype $speed]
} elseif { [is_platform_support_hyperscale] } {
	if { [sys_intf_is_media_iface $ifname] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"] } {
		set speed [cli_get_value $CLI_CUR_PARENT_NODE "" "" "speed"]
		set fec_speeds {25000full 25000auto 100Gfull}
		if { [lsearch $fec_speeds $speed] != -1 } {
			return 1
		}
	}
} else {
	if { [sys_intf_is_media_iface $ifname] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"] } {
		if { [cli_branchpt_start 700 276] } {
			set speed [cli_get_value $CLI_CUR_PARENT_NODE "" "" "speed"]
			set fec_speeds {25000full 25000auto 100Gfull}
			if { [lsearch $fec_speeds $speed] != -1 } {
				return 1
			}
		} else {
			return 1
		}
	}
}
return 0
	%}
	"system interface {mediatype}" = %{
namespace import global::sys_intf_is_media_iface
set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set ifname [string trim $ifname \"]
set platform [cli_get_devinfo "platform"]
if { [string match -nocase $platform "FortiGate-6000F"] ||
     [string match -nocase $platform "FortiGate-7000E"] ||
     [string match -nocase $platform "FortiGate-7000F"] ||
     [string match -nocase $platform "FortiCarrier-6000F"] ||
     [string match -nocase $platform "FortiCarrier-7000E"] ||
     [string match -nocase $platform "FortiCarrier-7000F"] } {
	namespace import global::sys_intf_forward_error_correction_option
	set mediatype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "mediatype"]
	set speed [cli_get_value $CLI_CUR_PARENT_NODE "" "" "speed"]
	set list {}
	if { [string match -nocase $platform "FortiGate-7000E"] || [string match -nocase $platform "FortiCarrier-7000E"] } {
		if {[regexp {\d-C\d+$} $ifname] ne 0} {
			return 1
		}
	}
	if { [string match -nocase $platform "FortiGate-6000F"] || [string match -nocase $platform "FortiCarrier-6000F"] } {
		if {[regexp {\d-mgmt3$} $ifname] ne 0} {
			return 1
		}
	}
	return [sys_intf_forward_error_correction_option list $platform $ifname $mediatype $speed]
} else {
	return [expr [sys_intf_is_media_iface $ifname] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "physical"]]
}
	%}
	"firewall proxy-address host" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "host-regex"]
	%}
	"firewall proxy-address host-regex" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "host-regex"]
	%}
	"firewall proxy-address query" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "url"]
	%}
	"firewall proxy-address referrer" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "host-regex"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "url"] } {
	return 1
}
return 0
	%}
	"firewall proxy-address category" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "category"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dst-advanced"] } {
	return 1
}
return 0
	%}
	"firewall proxy-address method" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "method"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "src-advanced"] } {
	return 1
}
return 0
	%}
	"firewall proxy-address ua" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ua"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "src-advanced"] } {
	return 1
}
return 0
	%}
	"firewall proxy-address {header header-name}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "header"]
	%}
	"firewall proxy-address path" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "url"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dst-advanced"] } {
	return 1
}
return 0
	%}
	"firewall proxy-address header-group" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "type" 0 "src-advanced"]
	%}
	"switch-controller lldp-profile med-location-service sys-location-id" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "status" 0 "enable"]
	%}
	"system csf {upstream upstream-ip upstream-port group-name group-password fixed-key management-ip management-port configuration-sync saml-configuration-sync fabric-object-unification authorization-mode accept-auth-by-cert authorization-request-type downstream-access downstream-accprofile}" = %{
return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system csf {certificate}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authorization-request-type" 0 "certificate"]
	%}
	"system csf trusted-list" = %{
if { $CLI_GLOBAL_DEV } { return }
set status [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "status"]
if { [cli_branchpt_start 700 203] } {
	set upstream [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "upstream"]
	if { $status eq "enable" && $upstream eq "" } {
		return 1
	}
} else {
	set upstream_ip [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "upstream-ip"]
	if { $status eq "enable" && ($upstream_ip eq "" || $upstream_ip eq "0.0.0.0") } {
		return 1
	}
}
return 0
	%}
	"system csf trusted-list {serial ha-members}" = %{
if { $CLI_GLOBAL_DEV } { return }
if { ![cli_branchpt_start 600 1712] } {
	return 1
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authorization-type" 0 "serial"]
	%}
	"system csf trusted-list certificate" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authorization-type" 1 "serial"]
	%}
	"vpn ipsec {phase1 phase1-interface} {proposal dhgrp}" = %{
if { [cli_ver_start 500 4] } {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "suite-b" 0 "disable"]
} else {
	return 1
}
	%}
	"vpn ipsec phase2 proposal" = %{
if { [cli_ver_start 500 4] } {
	set gw [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phase1name"]
	set gw [string trim $gw \"]
	set gwnode [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1" $gw ""]
	expr [cli_is_match $gwnode 0 "" "suite-b" 0 "disable"]
} else {
	return 1
}
	%}
	"vpn ipsec phase2-interface proposal" = %{
if { !$CLI_GLOBAL_DEV && [cli_ver_start 500 4] } {
	set gw [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phase1name"]
	set gw [string trim $gw \"]
	set gwnode [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $gw ""]
	expr [cli_is_match $gwnode 0 "" "suite-b" 0 "disable"]
} else {
	return 1
}
	%}
	"firewall internet-service-custom master-service-id" = %{
if { ![cli_ver_start 600 2] } {
	set id [cli_get_value $CLI_CUR_NODE "" "" ""]
	if { $id eq "\"0\"" || $id eq "0" } {
		return 0
	}
}
return 1
	%}
	"webfilter profile ftgd-wf filters warn-duration" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "warning"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "authenticate"]
	%}
	"webfilter profile ftgd-wf filters warning-prompt" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "warning"]
	%}
	"webfilter profile ftgd-wf filters auth-usr-grp" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "authenticate"]
	%}
	"webfilter profile ftgd-wf filters warning-duration-type" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "warning"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "warning-prompt" 0 "per-domain"]
	%}
	"webfilter profile ftgd-wf filters override-replacemsg" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
set prompt [cli_get_value $CLI_CUR_PARENT_NODE "" "" "warning-prompt"]
set rmsg_group [cli_get_value [cli_get_parent [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]]] "" "" "replacemsg-group"]
if { $action ne "warning" && $action ne "authenticate" && $action eq "block" } {
	return 0
}
if { $rmsg_group eq "" } {
	return 0
}
return 1
	%}
	"ftp-proxy explicit ssl" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]]
	%}
	"ftp-proxy explicit {ssl-cert ssl-dh-bits ssl-algorithm}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssl" 0 "enable"]]
	%}
	"user ldap {two-factor-authentication}" = %{
return [expr ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "two-factor" 0 "disable"]]
	%}
	"system {automation-stitch automation-destination automation-action automation-trigger}" = %{
set csf_node [cli_get_node $CLI_GLOBAL_NODE "system csf" "" ""]
set csf_en [cli_get_value $csf_node "" "" "status"]
set csf_upip [cli_get_value $csf_node "" "" "upstream-ip"]
if { $csf_en eq "enable" && $csf_upip ne "" && $csf_upip ne "0.0.0.0" } {
	return 0
}
set csf_up [cli_get_value $csf_node "" "" "upstream"]
if { $csf_en eq "enable" && $csf_up ne "" && $csf_up ne "0.0.0.0" } {
	return 0
}
return 1
	%}
	"webfilter search-engine charset" = %{
return 0
	%}
	"firewall {DoS-policy DoS-policy6 sniffer} anomaly {synproxy-ttl synproxy-tos synproxy-tcp-mss synproxy-tcp-sack synproxy-tcp-timestamp synproxy-tcp-window synproxy-tcp-windowscale}" = %{
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set name [string trim $name \"]
if { $name eq "tcp_syn_flood" } {
	namespace import global::is_platform_support_hyperscale
	if { [is_platform_support_hyperscale] } {
		set hyperscale [cli_get_devinfo "hyperscale"]
		if { $hyperscale eq "yes" } {
			return 0
		}
	}
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "proxy"] } {
		return 1
	}
}
return 0
	%}
	"wireless-controller wtp-profile {radio-1 radio-2 radio-3} ap-sniffer-chan" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sniffer"]
	%}
	"firewall ssl-ssh-profile {ssl https ftps imaps pop3s smtps} {unsupported-ssl-cipher unsupported-ssl-negotiation unsupported-ssl-version}" = %{
if { $CLI_CUR_PARENT_NAME eq "ssl" } {
	set is_generic_ssl 1
	set curr_settings [cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspect-all"]
	set inspect_all_setting [cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspect-all"]
} else {
	set is_generic_ssl 0
	set curr_settings [cli_get_value $CLI_CUR_PARENT_NODE "" "" "status"]
	set inspect_all_setting [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "ssl" "" "inspect-all"]
}
if { $is_generic_ssl == 1 && $inspect_all_setting eq "disable" } {
	return 0
}
if { $is_generic_ssl != 1 && $inspect_all_setting ne "disable" } {
	return 0
}
if { $curr_settings ne "deep-inspection" } {
	return 0
}
return 1
	%}
	"system ha {hw-session-sync-dev}" = %{
namespace import global::is_platform_support_hyperscale
if { [is_platform_support_hyperscale] } {
	set hyperscale [cli_get_devinfo "hyperscale"]
	if { $hyperscale eq "yes" } {
		return 1
	}
}
return 0
	%}
	"system npu {hash-config pba-eim ippool-overload-low ippool-overload-high dse-timeout tcp-rst-timeout nat46-force-ipv4-packet-forwarding}" = %{
namespace import global::is_platform_support_hyperscale
if { [is_platform_support_hyperscale] } {
	set hyperscale [cli_get_devinfo "hyperscale"]
	if { $hyperscale eq "yes" } {
		return 1
	}
}
return 0
	%}
	"system npu {tcp-timeout-profile udp-timeout-profile}" = %{
namespace import global::is_platform_support_hyperscale
if { [is_platform_support_hyperscale] } {
	set hyperscale [cli_get_devinfo "hyperscale"]
	if { $hyperscale eq "yes" } {
		return 1
	}
}
return 0
	%}
	"system npu {background-sse-scan}" = %{
namespace import global::is_platform_support_hyperscale
if { [is_platform_support_hyperscale] } {
	set hyperscale [cli_get_devinfo "hyperscale"]
	if { $hyperscale eq "yes" } {
		return 1
	}
}
return 0
	%}
	"system settings {trap-session-flag session-insert-trial hyperscale-default-policy-action}" = %{
namespace import global::is_platform_support_hyperscale
if { [is_platform_support_hyperscale] } {
	set hyperscale [cli_get_devinfo "hyperscale"]
	if { $hyperscale eq "yes" } {
		return 1
	}
}
return 0
	%}
	"firewall ippool_grp" = %{
namespace import global::is_platform_support_hyperscale
if { [is_platform_support_hyperscale] } {
	set hyperscale [cli_get_devinfo "hyperscale"]
	if { $hyperscale eq "yes" } {
		return 1
	}
}
return 0
	%}
	"firewall {policy46 policy6} {policy-offload cgn-log-server-grp}" = %{
if { $CLI_GLOBAL_DEV } {
	return 1
}
namespace import global::is_platform_support_hyperscale
if { [is_platform_support_hyperscale] } {
	set hyperscale [cli_get_devinfo "hyperscale"]
	if { $hyperscale eq "yes" } {
		return 1
	}
}
return 0
	%}
	"firewall {policy64 policy} {policy-offload cgn-session-quota cgn-resource-quota cgn-eif cgn-eim cgn-log-server-grp}" = %{
if { $CLI_GLOBAL_DEV } {
	return 1
}
namespace import global::is_platform_support_hyperscale
if { [is_platform_support_hyperscale] } {
	set hyperscale [cli_get_devinfo "hyperscale"]
	if { $hyperscale eq "yes" } {
		return 1
	}
}
return 0
	%}
	"router access-list" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router access-list6" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router aspath-list" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router auth-path" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router bfd" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router bfd6" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router bgp" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router community-list" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router isis" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router key-chain" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router multicast" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router multicast-flow" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router multicast6" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router ospf" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router ospf6" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router policy" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router policy6" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router prefix-list" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router prefix-list6" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router rip" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router ripng" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router route-map" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"router setting" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller 802-1X-settings" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller custom-command" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller global" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller igmp-snooping" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller lldp-profile" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller lldp-settings" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller managed-switch" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller qos dot1p-map" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller qos ip-dscp-map" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller qos qos-policy" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller qos queue-policy" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller security-policy 802-1X" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller security-policy local-access" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller snmp-community" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller snmp-sysinfo" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller snmp-trap-threshold" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller snmp-user" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller storm-control" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller storm-control-policy" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller stp-instance" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller stp-settings" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller switch-group" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller switch-log" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system dhcp6 server" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system dns-database" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system dns-server" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system geneve" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system gre-tunnel" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system ipip-tunnel" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system ipv6-tunnel" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system mobile-tunnel" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system nd-proxy" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system pppoe-interface" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system sit-tunnel" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system switch-interface" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"user quarantine" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"vpn ipsec concentrator" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"vpn ipsec manualkey-interface" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"vpn ipsec phase1-interface" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"vpn ipsec phase2-interface" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"vpn l2tp" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"vpn pptp" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"vpn ssl web realm" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"vpn ssl web user-bookmark" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"vpn ssl web user-group-bookmark" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 anqp-3gpp-cellular" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 anqp-ip-address-type" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 anqp-nai-realm" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 anqp-network-auth-type" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 anqp-roaming-consortium" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 anqp-venue-name" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 h2qp-conn-capability" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 h2qp-operator-name" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 h2qp-osu-provider" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 h2qp-wan-metric" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 hs-profile" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 icon" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 qos-map" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system nat64" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system virtual-wan-link" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system vxlan" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller virtual-port-pool" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"switch-controller vlan-policy" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system sdwan" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system vne-tunnel" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system dns64" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"system dns server-hostname" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
expr { [lsearch $protocol "dot"] != -1 || [lsearch $protocol "doh"] != -1 }
	%}
	"vpn ssl client" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 anqp-venue-url" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 h2qp-advice-of-charge" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 h2qp-osu-provider-nai" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller hotspot20 h2qp-terms-and-conditions" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
	%}
	"wireless-controller utm-profile" = %{
namespace import global::ngfw_mode_policy
expr {[cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"] && (![ngfw_mode_policy])}
 	%}
	"firewall proxy-policy" = %{
namespace import global::ngfw_mode_policy
expr ![ngfw_mode_policy]
	%}
	"webfilter override" = %{
namespace import global::ngfw_mode_policy
expr ![ngfw_mode_policy]
	%}
	"user local {two-factor-authentication}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "two-factor" 0 "fortitoken-cloud"]
        %}
        "user local {two-factor-notification}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "two-factor" 0 "fortitoken-cloud"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "two-factor-authentication" 0 "fortitoken"]
	%}
	"firewall ssl-ssh-profile ssl-exempt address" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "address" } {
	return 1
}
return 0
	%}
	"firewall ssl-ssh-profile ssl-exempt address6" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "address6" } {
	return 1
}
return 0
	%}
	"firewall ssl-ssh-profile ssl-exempt fortiguard-category" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "fortiguard-category" } {
	return 1
}
return 0
	%}
	"firewall ssl-ssh-profile ssl-exempt wildcard-fqdn" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "wildcard-fqdn"} {
        return 1
}
return 0
        %}
        "firewall ssl-ssh-profile ssl-exempt regex" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "regex"} {
        return 1
}
return 0
        %}
	"system link-monitor {http-get http-agent http-match}" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
expr { [lsearch $protocol "http"] != -1 }
	%}
	"dnsfilter profile youtube-restrict" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "safe-search"] eq "enable" } {
	return 1
}
return 0
	%}
	"firewall policy captive-portal-exempt" = %{
set grps [cli_get_value $CLI_CUR_PARENT_NODE "" "" "groups"]
set usrs [cli_get_value $CLI_CUR_PARENT_NODE "" "" "users"]

if { $grps ne "" || $usrs ne "" } {
	return 0
}

namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
 return 1
	%}
	"firewall policy log-http-transaction" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "accept"]
	%}
	"vpn ssl web portal dhcp-ip-overlap" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "tunnel-mode" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-mode" 0 "dhcp"]
	%}
	"vpn ssl web portal {default-window-width default-window-height}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web-mode" 0 "enable"]
	%}
	"system accprofile admintimeout" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "admintimeout-override"] eq "enable" } {
		return 1
}
return 0
	%}
	"vpn ipsec phase1-interface { auto-discovery-shortcuts }" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-discovery-receiver" 0 "enable"]
	%}
	"firewall policy wccp" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
set srcaddr6 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "srcaddr6"]
set dstaddr6 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dstaddr6"]
if { $srcaddr6 ne "" || $dstaddr6 ne "" } {
	return 0
}
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 343] && [is_hyperscale_activated] } {
        return 0
}
return 1
	%}
	"firewall proxy-policy access-proxy" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "access-proxy"]
	%}
%};
