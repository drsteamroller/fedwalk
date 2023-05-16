visibility %{
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
	"log eventfilter {system wan-opt wireless-activity user router}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "event" 1 "disable"]
%}
	"log eventfilter ha" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE 0 "" "event"] eq "disable"} {
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
	"application list entries action" = %{
set app [string trim [cli_get_value $CLI_CUR_PARENT_NODE "" "" "application"] \"]
if { $app eq "1" || $app eq "2" || $app eq "3" || $app eq "4" } {
	return 0
}
return 1
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
	"vpn ssl web portal {skip-check-for-unsupported-os skip-check-for-unsupported-browser skip-check-for-browser}" = %{
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
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "tunnel" } {
	return 1
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
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "tunnel" } {
	return 1
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
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "tunnel" } {
	return 1
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
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "tunnel" } {
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
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tunnel"] } {
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
	"system settings comments" = %{
namespace import global::cli_sys_global_vdom_enable
return [cli_sys_global_vdom_enable]
	%}
	"firewall policy srcintf" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "explicit-web" || $type eq "explicit-ftp" || $type eq "wanopt" || $type eq "ssh" } {
	return 0
}
return 1
	%}
	"firewall policy wanopt" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "explicit-web" || $type eq "explicit-ftp" || $type eq "wanopt" || $type eq "ssh" || $type eq "ssh-tunnel" } {
	return 0
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "redirect" || $action eq "isolate" || $action eq "deny" } {
	return 0
}
return 1
	%}
	"firewall policy {force-proxy dynamic-bypass cifs-profile}" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "explicit-web" || $type eq "explicit-ftp" || $type eq "wanopt" || $type eq "ssh" || $type eq "ssh-tunnel" } {
	return 0
}
return 1
	%}
	"firewall policy {explicit-web-proxy ssh-policy-redirect}" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "explicit-web" } {
	return 1
}
return 0
	%}
	"firewall policy webproxy-forward-server" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "explicit-web" } {
	return 1
}
if { $type eq "explicit-ftp" || $type eq "wanopt" || $type eq "ssh" || $type eq "ssh-tunnel" || $type eq "access-proxy" } {
	return 0
}
return 1
	%}
	"firewall policy webproxy-profile" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "access-proxy" } {
	return 1
}
if { $type eq "explicit-web" || $type eq "transparent" } {
	set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
	if { $action eq "redirect" || $action eq "deny" } {
		return 0
	}
	return 1
}
return 0
	%}
	"firewall policy {webcache webcache-https}" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "explicit-ftp" || $type eq "ssh" || $type eq "ssh-tunnel" } {
	return 0
}
return 1
	%}
	"firewall policy custom-log-fields" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "explicit-ftp" } {
	return 0
}
return 1
	%}
	"firewall policy {users groups}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "wanopt"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt" 0 "enable"] } {
	return 0
}
return 1
	%}
	"firewall policy {gbandwidth maxbandwidth priority}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "trafficshaping" 0 "enable"]
	%}
	"firewall policy diffservcode-forward" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "diffserv-forward" 0 "enable"]
	%}
	"firewall policy diffservcode-rev" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "diffserv-reverse" 0 "enable"]
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
	"firewall policy {name comments}" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value ne "" } {
	return 1
}
return 0
	%}
	"firewall policy profile-group" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "utm-status" 0 "enable"] || [cli_branchpt_start 600 120] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "profile-type" 0 "group"] } {
		return 1
	}
}
return 0
	%}
	"firewall address subnet" = %{
set typ [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $typ eq "ipmask" } {
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
	"firewall address {tenant epg-name sdn-tag}" = %{
set sdn [cli_get_value $CLI_CUR_PARENT_NODE "" "" "sdn"]
set sdn [string trim $sdn \"]
if { [cli_ver_start 600 2] } {
	namespace import global::find_sdn_conn_type_by_name
	if { [find_sdn_conn_type_by_name $sdn] eq "aci" } {
		return 1
	}
} else {
	set ty [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
	if { $ty eq "dynamic" && $sdn eq "aci" } {
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
if { 1 } {
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
	"firewall policy transaction-based" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "identity-based" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"web-proxy\""] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-based" 1 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth-method" 1 "ntlm"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth-method" 1 "fsso"]
	%}
	"firewall policy web-auth-cookie" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "accept"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "srcintf" 0 "\"web-proxy\""] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-based" 1 "enable"]
	%}
        "firewall service custom tcp-portrange" = %{
if { 1 } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "TCP/UDP/SCTP"] } {
		return 1
	}
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "enable"] && ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "SOCKS-UDP"] } {
		return 1
	}
	return 0
}
return 0
        %}
        "firewall service custom {sctp-portrange tcp-halfclose-timer tcp-halfopen-timer tcp-timewait-timer udp-idle-timer check-reset-range session-ttl}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "TCP/UDP/SCTP"]
        %}
	"firewall service custom udp-portrange" = %{
if { 1 } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "TCP/UDP/SCTP"] ||
	    ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "enable"] } {
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
	"firewall vip portforward" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "server-load-balance"]
        %}
	"firewall vip mappedip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "server-load-balance"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "fqdn"]
        %}
	"firewall vip mapped-addr" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fqdn"]
	%}
        "firewall vip protocol" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "portforward" 0 "enable"]
        %}
        "firewall vip extport" = %{
if { 1 } {
	set proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
	if { $proto eq "icmp" } {
		return 0
	}
}
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set portfwd [cli_get_value $CLI_CUR_PARENT_NODE "" "" "portforward"]
set srvtype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-type"]
if { 1 } {
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
return 0
	%}
        "firewall vip mappedport" = %{
if { 1 } {
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
	"firewall vip portmapping-type" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "portforward" 0 "enable"]
        %}
	"firewall shaping-profile" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "profile-name"]
set shaping_node [cli_get_node $CLI_CUR_VDOM_NODE "firewall shaping-profile" $name ""]
if {[cli_is_referenced $shaping_node]} {
	return 1
}
return 0
	%}

	"firewall shaping-policy diffservcode-forward" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "diffserv-forward" 0 "enable"]
	%}
	"firewall shaping-policy diffservcode-rev" = %{
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
		set cloud [cli_get_value $CLI_GLOBAL_NODE "system global" "" "fortitoken-cloud-service"]
		if { $cloud eq "disable" } {
			return 0
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
        "system ha mode {a-a}" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "system ha" "vcluster2" 0 "disable"]
        %}
        "system ha secondary-vcluster" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "vcluster2" 0 "enable"]
        %}
        "system ha weight" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "schedule" 0 "weight-round-robin"]
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
        "system fm auto-backup" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log {fortianalyzer fortianalyzer2 fortianalyzer3} setting {max-buffer-size override localid conn-timeout address-mode mgmt-name use-hdd roll-schedule roll-day roll-time diskfull}" = %{
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
        "log {fortianalyzer fortianalyzer2 fortianalyzer3} setting server" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
        "log {fortianalyzer fortianalyzer2 fortianalyzer3} setting serial" = %{
set status [cli_get_value $CLI_CUR_PARENT_NODE "" "" "status"]
if { $status ne "enable" } {
	return 0
}
return 1
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
        "system interface {username password idle-timeout}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoe"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoa"] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tunnel"] } {
		return 0
	}
	return 1
}
return 0
        %}
        "system interface distance" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoe"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoa"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "dhcp"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ipoa"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "eoa"]
        %}
        "system interface priority" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "dhcp"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoe"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoa"]
        %}
        "system interface defaultgw" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dedicated-to" 0 "management"] } {
	return 1
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "dhcp"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoe"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "pppoa"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "ipoa"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "eoa"] } {
	return 1
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
        "system interface interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "vlan"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tunnel"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "vxlan"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "emac-vlan"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "geneve"]
        %}
        "system interface vlanid" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "vlan"] } {
        return 1
}
return 0
        %}
        "system interface member" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "aggregate"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "redundant"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fortilink"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fctrl-trunk"]
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
if { $iftype == "loopback"} {
	return 0
}
return 1
        %}
        "system interface ip" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
set iftype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $iftype eq "physical" } {
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
if { 1 } {
	namespace import global::nCfg_is_port_pair_member
	if {[nCfg_is_port_pair_member $CLI_CUR_PARENT_NODE]} {
		cli_set_errmsg "interface is used by system.virtual-ware-pair"
		return 0
	}
}
return 1
        %}
        "system interface role" = %{
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
if { $t eq "loopback" } {
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
        "system interface tcp-mss" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "name" 0 "modem"] } {
	return 0
}
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "loopback"]
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
return 1
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
	"system interface {explicit-ftp-proxy explicit-web-proxy proxy-captive-portal}" = %{
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
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
	"system interface security-external-web" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-mode" 0 "captive-portal"]
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
return 1;
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
return 1
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
return 1
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
if {[cli_get_value $CLI_GLOBAL_NODE "system email-server" "" "server"] eq ""} {
	return 0
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
set mgmtvdom [cli_get_value $CLI_GLOBAL_NODE "system global" "" "management-vdom"]
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
	"router static dstaddr" = %{
if { 1 } {
	set dst [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dst"]
	if { $dst ne "" } {
		set dstip [split $dst]
		if { [lindex $dstip 0] eq "0.0.0.0" || [lindex $dstip 1] eq "0.0.0.0" } {
			return 1
		}
		return 0
	}
	return 1
}
return 0
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
if {[cli_obj_support "router static" "virtual-wan-link"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virtual-wan-link" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan" 0 "enable"]} {
	return 0
}
return 1
	%}
	"router static blackhole" = %{
if {[cli_obj_support "router static" "virtual-wan-link"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virtual-wan-link" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan" 0 "enable"]} {
	return 0
}
return 1
	%}
	"router static weight" = %{
if {[cli_obj_support "router static" "virtual-wan-link"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "virtual-wan-link" 0 "enable"]} {
	return 0
}
if {[cli_obj_support "router static" "sdwan"] &&
    [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdwan" 0 "enable"]} {
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
return 1
	%}
        "user group match" = %{
set gr_type [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "group-type"]
if { $gr_type ne "firewall" } {
	return 0
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
set group_type "fsso-service"
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
if { 1 } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable"] &&
	     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "add-route" 0 "enable"] } {
		return 1
	}
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
        "vpn ipsec phase1-interface interface" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
        %}
        "vpn ipsec phase1-interface keepalive" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nattraversal" 0 "enable"]
        %}
        "vpn ipsec phase1-interface psksecret" = %{
if { 1 } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authmethod" 0 "psk"] } {
		set peertype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "peertype"]
		if { $peertype eq "dialup" } {
			return 0
		}
		return 1
	}
}
return 0
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
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "xauthtype" 0 "client"]
        %}
        "vpn ipsec phase1-interface authpasswd" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "xauthtype" 0 "client"]
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
        "vpn ipsec phase1-interface {ipv4-start-ip ipv4-end-ip}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic" "assign-ip" 0 "enable" "assign-ip-from" 0 "range"]
        %}
	"vpn ipsec phase1-interface ipv4-netmask" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic" "assign-ip" 0 "enable" "assign-ip-from" 1 "dhcp"]
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
	"vpn ipsec phase1-interface ipv4-wins-server1" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic"]
        %}
	"vpn ipsec phase1-interface ipv4-wins-server2" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic"]
        %}
	"vpn ipsec phase1-interface idle-timeoutinterval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "idle-timeout" 0 "enable"]
        %}
	"vpn ipsec phase1-interface assign-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "type" 0 "dynamic"]
        %}
        "vpn ipsec {phase1 phase1-interface} mode" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "1"]
        %}
        "vpn ipsec phase1-interface exchange-interface-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-discovery-sender" 0 "disable" "auto-discovery-receiver" 0 "disable" "auto-discovery-forwarder" 0 "disable"]
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
		return 0
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
	return 0
}
return 1
        %}
        "vpn ipsec phase2-interface dhgrp" = %{
set gw [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phase1name"]
set gw [string trim $gw \"]
set gwnode [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $gw ""]
if { 1 } {
	expr [cli_is_match $gwnode 0 "" "suite-b" 0 "disable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "pfs" 0 "enable"]
}
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
       "webfilter profile ovrd-perm" = %{
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
       "webfilter fortiguard cache-ttl" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "cache-mode" 0 "ttl"]
        %}
        "vpn certificate crl ldap-username" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "ldap-server"] ne ""} {
        return 1;
}
return 0;
        %}
	"wanopt webcache cache-exemption-list" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "cache-exemption" 0 "enable"]
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
	"system resource-limits" = %{
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
	"spamfilter profile {imap pop3 smtp smtps imaps pop3s} {options action tag-type tag-msg hdrip local-override}" = %{
if { [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "spam-filtering" 1 "enable"] } {
	return 0
}
return 1
	%}
	"spamfilter profile mapi {options action}" = %{
if { [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "spam-filtering" 1 "enable"] } {
	return 0
}
return 1
	%}
	"spamfilter bwl entries addr-type" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ip"]
	%}
	"spamfilter bwl entries ip4-subnet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ip"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-type" 0 "ipv4"]
	%}
	"spamfilter bwl entries ip6-subnet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ip"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-type" 0 "ipv6"]
	%}
	"spamfilter iptrust entries ip4-subnet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-type" 0 "ipv4"]
	%}
	"spamfilter iptrust entries ip6-subnet" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-type" 0 "ipv6"]
	%}
	"spamfilter bwl entries {pattern-type email-pattern}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "email"]
	%}
	"dlp sensor filter rule-name" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "advanced-rule"]
	%}
	"dlp sensor filter compound-name" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "advanced-compound-rule"]
	%}
	"dlp sensor filter archive" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "advanced-rule"] } {
	set rule_name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "rule-name"]
	set dlprule [cli_get_node $CLI_CUR_VDOM_NODE "dlp rule" $rule_name ""]
	if { $dlprule == 0 || [cli_get_value $dlprule "" "" "protocol"] eq "nntp" } {
		return 0
	}
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "advanced-compound-rule"] } {
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
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "file"] &&
	[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "file-type"] } {
	return 1
}
return 0
	%}
	"dlp sensor filter file-size" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "file"] &&
	[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "file-size"] } {
	return 1
}
return 0
	%}
	"dlp sensor filter regexp" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "regexp"] } {
	return 1
}
return 0
	%}
	"dlp sensor filter {regexp-utf8 regexp-wildcard}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-type" 0 "regexp"]
	%}
	"dlp sensor filter fp-sensitivity" = %{
if { 1 } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "file"] &&
	     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "fingerprint"] } {
		return 1
	}
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "file"] &&
	     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "watermark"] } {
		return 1
	}
}
return 0
	%}
	"dlp sensor filter match-percentage" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "file"] &&
	[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "fingerprint"] } {
	return 1
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
	"icap profile request-server" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "request" 0 "enable"]
	%}
	"icap profile request-failure" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "request" 0 "enable"]
	%}
	"icap profile request-path" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "request" 0 "enable"]
	%}
	"icap profile response-server" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "response" 0 "enable"]
	%}
	"icap profile response-failure" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "response" 0 "enable"]
	%}
	"icap profile response-path" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "response" 0 "enable"]
	%}
	"icap server ip-address" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"]
	%}
	"icap server ip6-address" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "6"]
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
if { [cli_is_match $CLI_CUR_VDOM_NODE 0 "log disk setting" "status" 0 "disable"] } {
	return 0
}
return 1
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
	"system admin guest-usergroups" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "guest-auth" 0 "enable"]
	%}
	"system admin accprofile" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "guest-auth" 0 "enable"] } {
	return 0
}
return 1
	%}
	"log disk {setting filter}" = %{
if { ![expr {[cli_get_devinfo "hdd"] eq "yes"}] } {
	return 0
}
return 1
	%}
	"system replacemsg-group {webproxy}" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "auth"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "utm"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "default"]
	%}
	"system replacemsg-group {auth}" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "auth"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "default"]
	%}
	"system replacemsg-group {captive-portal-dflt}" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "captive-portal"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "default"]
	%}
	"system replacemsg-group {custom-message}" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "captive-portal"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "utm"]
	%}
	"system replacemsg-group {ec}" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "ec"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "default"]
	%}
	"system replacemsg-group {mail http mms mm1 mm3 mm4 mm7 ftp nntp fortiguard-wf spam im alertmail admin sslvpn nac-quar traffic-quota utm}" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "utm"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "default"]
	%}
	"system replacemsg-group {device-detection-portal}" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "group-type" 0 "default"]
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
	"system ntp interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "server-mode" 0 "enable"]
	%}
	"system dhcp server reserved-address ip" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "reserved"] } {
	return 1
}
return 0
	%}
	"system dhcp server reserved-address {mac action}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "mac"]
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
        "firewall policy wanopt-detection" = %{
if { 1 } {
	set learn_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "learning-mode"]
	if { $learn_mode eq "enable" } {
		return 1
	}
	set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
	if { $action eq "accept" } {
		if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wanopt"] ne "enable" } {
			return 0
		}
		if { !$CLI_GLOBAL_DEV && ![cli_ver_start 600 2] } {
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
}
return 0
        %}
        "firewall policy wanopt-profile" = %{
if { !$CLI_GLOBAL_DEV } {
	if { [cli_get_devinfo "is_rev_support_wanopt"] eq "no" } {
		return 0
	}
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt" 1 "enable"] } {
		return 0
	}
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt-detection" 0 "passive"]} {
		return 0
	}
	return 1
}
return 0
        %}
        "firewall policy wanopt-peer" = %{
if { !$CLI_GLOBAL_DEV } {
	if { [cli_get_devinfo "is_rev_support_wanopt"] eq "no" } {
		return 0
	}
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt" 1 "enable"] } {
		return 0
	}
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt-detection" 1 "off"]} {
		return 0
	}
	return 1
}
return 0
        %}
        "firewall policy wanopt-passive-opt" = %{
if { !$CLI_GLOBAL_DEV } {
	if { [cli_get_devinfo "is_rev_support_wanopt"] eq "no" } {
		return 0
	}
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt" 1 "enable"] } {
		return 0
	}
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wanopt-detection" 1 "passive"]} {
		return 0
	}
	return 1
}
return 0
        %}
        "firewall policy reverse-cache" = %{
if { !$CLI_GLOBAL_DEV } {
	if { [cli_get_devinfo "is_rev_support_wanopt"] eq "no" } {
		return 0
	}
}
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "explicit-ftp" || $type eq "ssh-tunnel" || $type eq "ssh" } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "webcache" 0 "enable"] } {
	return 1
}
return 0
        %}
	"firewall policy {global-label label}" = %{
set value [cli_get_value $CLI_CUR_NODE "" "" ""]
if { $value eq 0 || $value eq "" } {
	return 0
}
return 1
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
	"system interface link-up-delay" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "aggregate" || $type eq "redundant" || $type eq "fortilink" } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"] ne "modem" } {
		return 1
	}
}
return 0
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
	"system interface secondaryip" = %{
if { [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "secondary-IP" 0 "disable"] } {
	return 0
}
if { 1 } {
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
	"system wccp server-list" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "wccp-cache-engine" 1 "enable"]
	%}
	"system wccp router-list" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "wccp-cache-engine" 0 "enable"]
	%}
	"firewall address name" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "SSLVPN_TUNNEL_ADDR1" } {
	if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
		return 0
	}
}
return 1
	%}
	"firewall address6 name" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" ""] eq "SSLVPN_TUNNEL_IPv6_ADDR1" } {
	if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
		return 0
	}
}
return 1
	%}
	"firewall address6 {start-ip end-ip}" = %{
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
	"system csf {upstream-ip upstream-port group-name group-password}" = %{
return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"vpn ipsec phase1-interface {proposal dhgrp}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "suite-b" 0 "disable"]
	%}
	"vpn ipsec phase2-interface proposal" = %{
set gw [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phase1name"]
set gw [string trim $gw \"]
set gwnode [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $gw ""]
expr [cli_is_match $gwnode 0 "" "suite-b" 0 "disable"]
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
        "system accprofile admintimeout" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "admintimeout-override"] eq "enable" } {
        return 1
}
return 0
        %}
	"firewall policy log-http-transaction" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "accept"]
	%}
%};
