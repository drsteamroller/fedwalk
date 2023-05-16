visibility %{
	"firewall central-snat-map {orig-port nat-port}" = %{
set protocol [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if { $protocol == 0 || $protocol == 6 || $protocol == 17 || $protocol == 132 } {
	set ippool [cli_get_value $CLI_CUR_PARENT_NODE "" "" "nat-ippool"]
	set pooltype [cli_get_value $CLI_CUR_VDOM_NODE "firewall ippool" $ippool "type"]
	if { $pooltype eq "overload" } {
		return 1
	}
}
return 0
	%}
	"antivirus profile mapi" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"] eq "flow-based"} {
	return 0
}
return 1
	%}
	"antivirus profile smb" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"] eq "proxy"} {
	return 0
}
return 1
	%}
	"antivirus profile {av-virus-log av-block-log}" = %{
return 1
	%}
	"antivirus profile nntp" = %{
if {[cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"] eq "flow-based"} {
	return 0
}
return 1
	%}
	"dlp sensor dlp-log" = %{
return 1
	%}
	"spamfilter profile {imap pop3 smtp mapi msn-hotmail yahoo-mail gmail} log" = %{
return 1
	%}
        "webfilter profile web {log-search keyword-match}" = %{
set ins [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "inspection-mode"]
if { $ins ne "dns" } {
        return 1
}
return 0
        %}
	"webfilter profile {web-content-log web-filter-activex web-filter-cookie-log web-filter-applet-log web-filter-jscript-log web-filter-js-log web-filter-vbs-log web-filter-unknown-log web-filter-referer-log web-filter-cookie-removal-log web-invalid-domain-log web-ftgd-err-log web-ftgd-quota-usage}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "inspection-mode" 1 "dns"] } {
	return 1
}
return 0
	%}
	"webfilter profile {web-url-log log-all-url}" = %{
return 1
	%}
	"webfilter profile ftgd-wf options log-all-url" = %{
return 0
	%}
	"webfilter profile override" = %{
set ins [cli_get_value [cli_get_parent $CLI_CUR_NODE] "" "" "inspection-mode"]
if { $ins eq "dns" } {
        return 0
}
return 1
	%}
        "system accprofile fwgrp-permission" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fwgrp" 0 "custom"]
        %}
        "system accprofile loggrp-permission" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "loggrp" 0 "custom"]
        %}
        "system accprofile utmgrp-permission" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "utmgrp" 0 "custom"]
        %}
	"vpn ssl web portal {user-bookmark display-bookmark display-connection-tools display-history display-status heading redir-url theme custom-lang}" = %{
set web_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "web-mode"]
if { $web_mode eq "enable" } {
	return 1
}
return 0
	%}
	"vpn ssl web portal bookmark-group" = %{
set web_mode [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "web-mode"]
if { $web_mode eq "enable" } {
	return 1
}
return 0
	%}
	"vpn ssl web portal user-group-bookmark" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web-mode" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "display-bookmark" 0 "enable"] } {
	return 1
}
return 0
	%}
	"vpn ssl web portal split-tunneling-routing-address" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "split-tunneling" 0 "enable"]
	%}
        "vpn ssl web portal widget bookmarks sso" = %{
set app [cli_get_value $CLI_CUR_PARENT_NODE "" "" "apptype"]
if { $app eq "smb" || $app eq "ftp" || $app eq "citrix" || $app eq "web" } {
        return 1
}
return 0
        %}
        "vpn ssl web portal widget bookmarks sso static" = %{
set app [cli_get_value $CLI_CUR_PARENT_NODE "" "" "apptype"]
if { $app eq "citrix" || $app eq "web" } {
        return 1
}
return 0
        %}
        "vpn ssl web portal widget bookmarks form-data" = %{
set sso [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "sso"]
set app [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "apptype"]
if { $sso eq "static" && ($app eq "web" || $app eq "citrix") } {
        return 1
}
return 0
        %}
	"vpn ipsec phase1-interface eap" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "2"]
	%}
        "vpn ipsec phase1-interface {monitor-hold-down-weekday}" = %{
set monitor [cli_get_value $CLI_CUR_PARENT_NODE "" "" "monitor"]
set monitor [string trim $monitor \"]
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "monitor-hold-down-type"]
set type [string trim $type \"]
if { $type eq "time" && [string length $monitor] > 0 } {
	return 1
}
return 0
        %}
        "vpn ipsec phase1-interface add-route" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dynamic"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "peertype" 0 "dialup"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-discovery-receiver" 0 "enable"]
        %}
	"user radius {rsso-radius-server-port rsso-radius-response rsso-validate-request-secret rsso-secret rsso-endpoint-attribute rsso-endpoint-block-attribute sso-attribute sso-attribute-key rsso-context-timeout rsso-log-period rsso-log-flags rsso-flush-ip-session}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "rsso" 0 "enable"]
	%}
	"user radius {server secret all-usergroup use-management-vdom nas-ip radius-port auth-type source-ip}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "rsso" 0 "disable"]
	%}
	"user radius {secondary-server secondary-secret tertiary-server tertiary-secret}" = %{
set server [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server"]
if { $server == 0 || $server eq "" || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "rsso" 0 "enable"] } {
	return 0
}
return 1
	%}
	"user radius rsso-log-flags {accounting-event accounting-stop-missed context-missing endpoint-block profile-missing protocol-error radiusd-other}" = %{
set flags [cli_get_value $CLI_CUR_NODE "" "" ""]
foreach flag $flags {
	if { $flag eq "none" } {
		return 0
	}
}
return 1
	%}
	"wanopt auth-group psk" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth-method" 0 "psk"]
	%}
	"wanopt auth-group cert" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth-method" 0 "cert"]
	%}
        "firewall ssl-ssh-profile {caname certname}" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-cert-mode"] ne "replace"} {
        return 1
}
return 0
        %}
        "firewall ssl-ssh-profile server-cert" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-cert-mode"] eq "replace"} {
        return 1
}
return 0
        %}
        "firewall ssl-ssh-profile rpc-over-https" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "https" "" "status"] eq "deep-inspection"} {
        return 1
}
return 0
        %}
        "firewall ssl-ssh-profile mapi-over-https" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "https" "" "status"] eq "deep-inspection"} {
        return 1
}
return 0
        %}
        "firewall ssl-ssh-profile ssl-exempt address" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "address"} {
        return 1
}
return 0
        %}
        "firewall ssl-ssh-profile ssl-exempt address6" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] eq "address6"} {
        return 1
}
return 0
        %}
        "firewall ssl-ssh-profile ssl-exempt fortiguard-category" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] ne "address" &&
     [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] ne "address6" } {
        return 1
}
return 0
        %}
	"system dhcp server {ntp-server1 ntp-server2 ntp-server3}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ntp-service" 0 "specify"]
	%}
	"log fortianalyzer filter" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "log fortianalyzer setting" "upload-option" 1 "store-and-upload"] && [cli_is_match $CLI_GLOBAL_NODE 0 "log fortianalyzer setting" "status" 0 "enable"]
	%}
	"log fortianalyzer2 filter" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "log fortianalyzer2 setting" "upload-option" 1 "store-and-upload"] && [cli_is_match $CLI_GLOBAL_NODE 0 "log fortianalyzer2 setting" "status" 0 "enable"]
	%}
	"log fortianalyzer3 filter" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "log fortianalyzer3 setting" "upload-option" 1 "store-and-upload"] && [cli_is_match $CLI_GLOBAL_NODE 0 "log fortianalyzer3 setting" "status" 0 "enable"]
	%}
        "wireless-controller vap local-bridging" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mesh-backhaul" 1 "enable"]
        %}
        "log fortianalyzer setting {ips-archive monitor-keepalive-period monitor-failure-retry-period source-ip upload-option}" = %{
if { $CLI_GLOBAL_DEV || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] } {
        return 1
}
return 0
        %}
        "log {fortianalyzer2 fortianalyzer3} setting {ips-archive monitor-keepalive-period monitor-failure-retry-period source-ip upload-option}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "log fortianalyzer setting {reliable}" = %{
if { $CLI_GLOBAL_DEV && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-option" 1 "store-and-upload"] } {
        return 1
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-option" 1 "store-and-upload"] } {
        return 1
}
return 0
        %}
        "log {fortianalyzer2 fortianalyzer3} setting {reliable}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-option" 1 "store-and-upload"]
        %}
        "log fortiguard setting {enc-algorithm source-ip upload-option}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
        %}
        "system ntp ntpserver" = %{
set ntp [cli_get_parent $CLI_CUR_PARENT_NODE]
if { [cli_is_match $ntp 0 "" "type" 0 "custom"] } {
        return 1
}
return 0
        %}
        "system ntp ntpserver authentication" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ntpv3" 0 "enable"]
        %}
        "system ntp ntpserver {key key-id}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ntpv3" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authentication" 0 "enable"]
        %}
        "firewall policy nat" = %{
namespace import global::policy_nat_visible
return [policy_nat_visible $CLI_CUR_PARENT_NODE]
        %}
        "firewall policy ippool" = %{
namespace import global::policy_ippool_visible
return [policy_ippool_visible $CLI_CUR_PARENT_NODE]
        %}
	"firewall policy central-nat" = %{
namespace import global::policy_nat_visible
namespace import global::policy_ippool_visible
set nat_en 0
set ippool_en 0
if { [policy_nat_visible $CLI_CUR_PARENT_NODE] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "enable"] } {
		set nat_en 1
	}
}
if { [policy_ippool_visible $CLI_CUR_PARENT_NODE] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ippool" 0 "enable"] } {
		set ippool_en 1
	}
}
if { $nat_en == 0 || $ippool_en == 1 } {
	return 0
}
return 1
	%}
        "firewall policy poolname" = %{
namespace import global::policy_nat_visible
namespace import global::policy_ippool_visible
if { [policy_nat_visible $CLI_CUR_PARENT_NODE] } {
        if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "disable"] } {
                return 0
        }
}
if { [policy_ippool_visible $CLI_CUR_PARENT_NODE] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ippool" 0 "disable"] } {
		return 0
	}
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "ipsec" ||
     $action eq "deny" } {
	return 0
}
return 1
        %}
	"firewall policy redirect-url" = %{
set disc [cli_get_value $CLI_CUR_PARENT_NODE "" "" "disclaimer"]
namespace import global::aps_policy_auth_identity_based
if { $disc eq "enable" || [aps_policy_auth_identity_based $CLI_CUR_PARENT_NODE] } {
	set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
	if { $action eq "accept" } {
		return 1
	}
} else {
	set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
	if { $action eq "redirect" } {
		return 1
	}
}
return 0
	%}
	"firewall policy disclaimer" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
        if { [cli_has_feature "f_sslvpn"] } {
		namespace import global::is_sslvpn_policy
                if { [is_sslvpn_policy $CLI_CUR_PARENT_NODE] } {
			return 0
                }
        }
	return 1
}
return 0
	%}
	"firewall policy {service dstaddr dstaddr-negate service-negate}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] } {
	return 0
}
return 1
	%}
	"firewall policy {internet-service-id internet-service-custom internet-service-negate}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] } {
	return 1
}
return 0
	%}
	"firewall policy schedule" = %{
return 1
	%}
	"firewall policy utm-status" = %{
namespace import global::cmf_firewall_policy_learn_enabled
if { [cmf_firewall_policy_learn_enabled $CLI_CUR_PARENT_NODE] } {
	return 0
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "deny" } {
	return 0
}
return 1
	%}
	"firewall policy logtraffic utm" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "deny" } {
	return 0
}
return 1
	%}
	"firewall policy {srcaddr srcaddr-negate}" = %{
return 1
	%}
	"firewall policy replacemsg-override-group" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" || $action eq "deny" } {
        if { [cli_has_feature "f_sslvpn"] } {
		namespace import global::is_sslvpn_policy
                if { [is_sslvpn_policy $CLI_CUR_PARENT_NODE] } {
			return 0
                }
        }
}
return 1
	%}
	"firewall policy icap-profile" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "deny"] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "utm-status" 1 "enable"] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "profile-type" 1 "single"] } {
	return 0
}
namespace import global::inspection_mode_vdom_flow
if { [inspection_mode_vdom_flow] } {
	return 0
}
return 1
	%}
	"firewall policy {spamfilter-profile dlp-sensor}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "utm-status" 1 "enable"] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "profile-type" 1 "single"] } {
	return 0
}
namespace import global::inspection_mode_vdom_flow
if { [inspection_mode_vdom_flow] } {
	return 0
}
return 1
	%}
	
	## Mantis 0437677	
	"webfilter profile" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
return 1
	%}
	
	"application list" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
return 1
	%}

	## Mantis 0441017	
	"firewall policy {webfilter-profile application-list}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "utm-status" 0 "enable"] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "profile-type" 0 "single"] } {
		namespace import global::ngfw_mode_policy
		if { ![ngfw_mode_policy] } {
			return 1
		}
	}
}
return 0
	%}

	"firewall policy {profile-protocol-options av-profile replacemsg-group ips-sensor dnsfilter-profile}" = %{
namespace import global::fw_policy_utm_profile_type
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
    return 0
}
return 1
	%}
	## Mantis 0441017	
	"firewall policy ssl-ssh-profile" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "learning-mode" 0 "enable"] } {
	return 0
}
if { ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "utm-status" 0 "enable"] } {
	return 0
}
if { ![cli_is_match $CLI_CUR_PARENT_NODE 0 "" "profile-type" 0 "single"] } {
	return 0
}
## Mantis 462243 change in FOS behaviour ignores sslvpn check and only uses utm-status check
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "utm-status" 0 "enable"] } {
	return 1
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" || $action eq "deny" } {
        if { [cli_has_feature "f_sslvpn"] } {
		namespace import global::is_sslvpn_policy
		namespace import global::FMG_is_sslvpn_policy_has_tunnel
                if { [is_sslvpn_policy $CLI_CUR_PARENT_NODE] } {
                        if { [FMG_is_sslvpn_policy_has_tunnel $CLI_CUR_PARENT_NODE] } {
                                return 1
                        } else {
                                return 0
                        }
                }
        }
}
return 1
	%}
        "firewall policy {inbound outbound}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "ipsec"]
        %}
	"firewall service custom protocol-number" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "IP"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "disable"]
	%}
        "dlp sensor nac-quar-log" = %{
return 1
        %}
	"vpn ssl settings servercert" = %{
return 1
	%}
        "log disk setting report-quota" = %{
set en [cli_get_value $CLI_CUR_PARENT_NODE "" "" "status"]
set log [cli_get_devinfo "is_sql_logging_allowed"]
if { $log ne "NA" } {
	if { $en eq "enable" && $log eq "yes" } {
		return 1
	}
	return 0
} elseif { $en eq "disable" } {
	return 0
}
return 1
        %}
	"report setting" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "log disk setting" "status" 0 "enable"]
	%}
	"log disk setting {storage report}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"firewall profile-group {spamfilter-profile dlp-sensor icap-profile}" = %{
namespace import global::inspection_mode_vdom_flow
expr ![inspection_mode_vdom_flow]
	%}
	"{ftp-proxy web-proxy} explicit" = %{
namespace import global::inspection_mode_vdom_flow
expr ![inspection_mode_vdom_flow]
	%}
        "system interface macaddr" = %{
namespace import global::intf_is_ipsec_tunnel
namespace import global::intf_vxlan
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { [cli_is_match $CLI_GLOBAL_NODE 0 "system ha" "mode" 1 "standalone"] && ($type ne "vdom-link") } {
        return 0
}
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] &&
	(![intf_vxlan $CLI_CUR_PARENT_NODE]) } {
        return 0
}
if { $type eq "physical" } {
        return 1
} elseif { $type eq "fext-wan" } {
        return 1
} elseif { $type eq "switch-vlan" } {
        return 1
} elseif { $type eq "fctrl-trunk" } {
        return 1
} elseif { $type eq "tunnel" } {
	if { [intf_is_ipsec_tunnel $CLI_CUR_PARENT_NODE] } {
		if { [intf_vxlan $CLI_CUR_PARENT_NODE] } {
			return 1
		}
	}
} elseif { $type eq "wireless" } {
        return 1
} elseif { $type eq "vdom-link" } {
        set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
        set name [string range $name 0 [expr [string length $name] - 2]]
        set type [cli_get_value $CLI_GLOBAL_NODE "system vdom-link" $name "type"]
        if { $type eq "ethernet" } {
                return 1
        }
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "emac-vlan"] } {
        return 1
}
return 0
        %}
        "antivirus profile scan-mode" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "inspection-mode" 1 "flow-based"] } {
	cli_set_errmsg "Inspection mode should be flow-based to use scan-mode"
	return 0
}
return 1
	%}
        "antivirus profile {ftgd-analytics analytics-db}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "inspection-mode" 0 "flow-based"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "scan-mode" 0 "quick"] } {
	return 0
}
if { $CLI_GLOBAL_DEV } {
	return 1
} elseif { [cli_is_match $CLI_GLOBAL_NODE 0 "system fortisandbox" "status" 0 "enable"] ||
           [cli_is_match $CLI_GLOBAL_NODE 0 "system fortiguard" "service-account-id" 1 ""] } {
	return 1
}
return 0
        %}
        "antivirus profile analytics-max-upload" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ftgd-analytics" 0 "disable"] } {
        return 0
}
if { $CLI_GLOBAL_DEV } {
        return 1
} elseif { [cli_is_match $CLI_GLOBAL_NODE 0 "system fortisandbox" "status" 0 "enable"] ||
           [cli_is_match $CLI_GLOBAL_NODE 0 "system fortiguard" "service-account-id" 1 ""] } {
        return 1
}
return 0
        %}
        "antivirus profile {analytics-wl-filetype analytics-bl-filetype}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ftgd-analytics" 0 "disable"] } {
        return 0
}
if { $CLI_CUR_NODE_NAME eq "analytics-wl-filetype" } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "analytics-bl-filetype" 1 ""] } {
		return 0
	}
} elseif { $CLI_CUR_NODE_NAME eq "analytics-bl-filetype" } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "analytics-wl-filetype" 1 ""] } {
		return 0
	}
}
if { $CLI_GLOBAL_DEV } {
        return 1
} elseif { [cli_is_match $CLI_GLOBAL_NODE 0 "system fortisandbox" "status" 0 "enable"] ||
           [cli_is_match $CLI_GLOBAL_NODE 0 "system fortiguard" "service-account-id" 1 ""] } {
        return 1
}
return 0
        %}
	"dnsfilter profile ftgd-dns options" = %{
return 1
	%}
	"log null-device setting status" = %{
return 1
	%}
	"application internet-service-custom comment" = %{
return 1
	%}
	"system global disk-usage" = %{
if { [cli_get_devinfo "is_logdisk_mounted"] eq "yes" } {
	return 1
}
return 0
	%}
	"firewall shaping-policy {srcaddr dstaddr}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"]
	%}
	"firewall shaping-policy {srcaddr6 dstaddr6}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "6"]
	%}
	"firewall shaping-policy {service dstintf}" = %{
return 1
	%}
	"application internet-service-custom disable-entry" = %{
set id [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "master-service-id"]
if { $id eq "" } {
	return 0
}
return 1
	%}
	"spamfilter profile {options flow-based spam-log extended-utm-log spam-filtering spam-bword-threshold spam-bword-table spam-bwl-table spam-mheader-table spam-rbl-table spam-iptrust-table replacemsg-group}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "external" 1 "enable"]
	%}
	"spamfilter profile {imap mapi pop3 smtp msn-hotmail yahoo-mail gmail}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "external" 1 "enable"]
	%}
	"firewall policy {action logtraffic logtraffic-start scan-botnet-connections}" = %{
namespace import global::cmf_firewall_policy_learn_enabled
if { [cmf_firewall_policy_learn_enabled $CLI_CUR_PARENT_NODE] } {
        return 0
}
return 1
	%}
	"vpn ipsec phase1-interface peertype" = %{
return 1
	%}
	"system sdn-connector server-port" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "aci"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "nuage"]
	%}
	"system sdn-connector {server-ip username password}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "aws"]	
	%}
	"system sdn-connector {access-key secret-key region vpc-id}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "aws"]
	%}
	"system sdn-connector update-interval" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "aws"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "nsx"]
	%}
	"system sdn-connector {rest-sport rest-interface rest-password rest-ssl vmx-service-name vmx-image-url}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "nsx"] } {
	return 1 
}
return 0 
	%}
	"firewall {address address6} {obj-id}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dynamic"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sdn" 0 "nsx"] } {
	return 1
}
return 0
	%}
	"firewall {address address6} {list profile-list}" = %{
if { [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "type" 0 "dynamic"] && [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "sdn" 0 "nsx"] } {
	return 1
}
return 0
	%}
	"system admin {ssh-public-key1 ssh-public-key2 ssh-public-key3 ssh-certificate}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wildcard" 1 "enable"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "remote-auth" 1 "enable"] } {
	return 1
}
return 0
       %}
	"firewall central-snat-map {orig-addr dst-addr}" = %{
return 1
	%}
	"firewall central-snat-map nat-ippool" = %{
if { $CLI_GLOBAL_DEV } { return 1 }
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "deny"] } {
	if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "inspection-mode"] eq "flow" } {
	if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "ngfw-mode"] eq "policy-based" } {
	return 0
	}
	}
}
return 1
	%}
	"application internet-service-custom entry dst" = %{
return 1
	%}
	"vpn ipsec phase2-interface keepalive" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-negotiate" 1 "enable"]
	%}
	"system settings ngfw-mode" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "inspection-mode" 0 "flow"] } {
	return 1
}
return 0
	%}
	"system settings ssl-ssh-profile" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "inspection-mode" 0 "flow"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ngfw-mode" 0 "policy-based"] } {
	return 1
}
return 0
	%}
	"policy package settings ngfw-mode" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "inspection-mode" 0 "flow"] } {
	return 1
}
return 0
	%}
	"policy package settings ssl-ssh-profile" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "inspection-mode" 0 "flow"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ngfw-mode" 0 "policy-based"] } {
	return 1
}
return 0
	%}
	"router route-map rule set-local-preference" = %{
return 1
	%}
	"firewall internet-service-custom comment" = %{
return 1
	%}
	"system global {ssd-trim-hour ssd-trim-min}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssd-trim-freq" 1 "never"] } {
	return 1
}
return 0
	%}
	"system global ssd-trim-weekday" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssd-trim-freq" 0 "weekly"] } {
	return 1
}
return 0
	%}
	"system global ssd-trim-date" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssd-trim-freq" 0 "monthly"] } {
	return 1
}
return 0
	%}
	"certificate local {scep-password}" = %{
set url [cli_get_value $CLI_CUR_PARENT_NODE "" "" "scep-url"]
if { $url eq ""} {
	return 0
}
return 1
	%}
	"user fsso {ldap-server port2 port3 port4 port5 server2 server3 server4 server5 password2 password3 password4 password5 source-ip}" = %{
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set server [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server"]
if { $name eq "Local FSSO Agent" || $name eq "\"Local FSSO Agent\"" ||
	[string match -nocase $server "localhost"] || [string match -nocase $server "\"localhost\""] ||
	$server eq "127.0.0.1" || $server eq "\"127.0.0.1\""} {
	return 0
}
return 1
	%}
	"firewall profile-group {ssl-ssh-profile application-list webfilter-profile voip-profile}" = %{
namespace import global::ngfw_mode_policy
expr ![ngfw_mode_policy]
	%}
	"log threat-weight application" = %{
set cate [cli_get_value $CLI_CUR_NODE "" "" "category"]
if { $cate eq "19" || $cate eq "\"19\"" } {
	return 0
}
return 1
	%}
	"system fortisandbox {server source-ip}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"authentication scheme user-database" = %{
set method [cli_get_value $CLI_CUR_PARENT_NODE "" "" "method"]
if { ([lsearch $method "form"] != -1) || ([lsearch $method "basic"] != -1) || ([lsearch $method "digest"] != -1) } {
	return 1
}
return 0
	%}
	"authentication scheme negotiate-ntlm" = %{
set method [cli_get_value $CLI_CUR_PARENT_NODE "" "" "method"]
if { ([lsearch $method "negotiate"] != -1) } {
	return 1
}
return 0
	%}
	"authentication scheme require-tfa" = %{
set method [cli_get_value $CLI_CUR_PARENT_NODE "" "" "method"]
if { ([lsearch $method "form"] != -1)} {
	return 1
}
return 0
	%}
	"authentication scheme fsso-guest" = %{
set method [cli_get_value $CLI_CUR_PARENT_NODE "" "" "method"]
set nego [cli_get_value $CLI_CUR_PARENT_NODE "" "" "negotiate-ntlm"]
if { ([lsearch $method "basic"] != -1) || ([lsearch $method "digest"] != -1) || ([lsearch $method "ntlm"] != -1) } {
	return 1
}
if { ([lsearch $method "negotiate"] != -1) && $nego eq "enable" } {
	return 1
}
return 0
	%}

	"authentication rule srcaddr6" = %{
if { $CLI_GLOBAL_DEV } {
	return 1
}
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "web-proxy explicit" "ipv6-status" 0 "enable"]
	%}
	"authentication rule sso-auth-method" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-based" 0 "enable"]
	%}
	"authentication rule web-auth-cookie" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "http"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-based" 0 "disable"]
	%}
	"authentication rule transaction-based" = %{
set ipbased [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ip-based"]
set proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "protocol"]
if { $ipbased eq "enable" || $proto ne "http" } {
	return 0
}
set anode 0
set snode 0
set ascheme [cli_get_value $CLI_CUR_PARENT_NODE "" "" "active-auth-method"]
if { $ascheme ne "" && $ascheme ne 0 } {
	set anode [cli_get_node $CLI_CUR_VDOM_NODE "authentication scheme" $ascheme ""]
	if { $anode ne 0 } {
		expr [cli_is_match $anode 0 "" "method" 0 "basic"]
	}
}
set sscheme [cli_get_value $CLI_CUR_PARENT_NODE "" "" "sso-auth-method"]
if { $sscheme ne "" && $sscheme ne 0 } {
	set snode [cli_get_node $CLI_CUR_VDOM_NODE "authentication scheme" $sscheme ""]
	if { $snode ne 0 } {
		expr [cli_is_match $snode 0 "" "method" 0 "basic"]
	}
}
if { $anode eq 0 && $snode eq 0 } {
	return 0
}
return 1
	%}

        "system interface phy-mode" = %{
set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set ifname [string trim $ifname \"]
if { $ifname eq "dsl" } {
	return 1
}
return 0
        %}
        "system interface tc-mode" = %{
set ifname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
set ifname [string trim $ifname \"]
if { $ifname eq "dsl" || $ifname eq "adsl" } {
	return 1
}
return 0
        %}
        "user ldap group-filter" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-member-check" 0 "user-attr"]
        %}
	"firewall mms-profile" = %{
if { $CLI_GLOBAL_DEV } { return 1 }
namespace import global::inspection_mode_vdom_flow	
if { [inspection_mode_vdom_flow] } {
	return 0
}
return 1
	%}
	"system settings {gui-icap gui-voip-profile gui-explicit-proxy gui-dlp gui-spamfilter gui-waf-profile}" = %{
namespace import global::inspection_mode_vdom_flow
expr ![inspection_mode_vdom_flow]
	%}
	"system settings {gui-application-control gui-webfilter}" = %{
namespace import global::inspection_mode_vdom_flow
namespace import global::ngfw_mode_policy
expr [inspection_mode_vdom_flow] && ![ngfw_mode_policy]
	%}
%};
