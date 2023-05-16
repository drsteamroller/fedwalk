visibility %{
	"firewall access-proxy {api-gateway api-gateway6} realservers {ip port}" = %{
set service [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "service"]
if { $service eq "tcp-forwarding" } {
	return 0
}
return 1
	%}
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
	"firewall policy {ztna-ems-tag ztna-geo-tag}" = %{
set ztna_status [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ztna-status"]
if { $ztna_status ne "enable" } {
	return 0
}
return 1
	%}
	"firewall policy profile-protocol-options" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "ipsec" } {
	return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "profile-type" 0 "single"]
}
if { $action eq "accept" } {
	return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "profile-type" 0 "single"]
}
if { $action eq "deny" } {
	return 0
}
return 1
	%}
	"firewall policy ssl-ssh-profile" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "ipsec" } {
	return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "profile-type" 0 "single"]
}
if { $action eq "accept" } {
	return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "profile-type" 0 "single"]
}
if { $action eq "deny" } {
	return 0
}
return 1
	%}
	"firewall policy {icap-profile ssh-filter-profile}" = %{
namespace import global::fw_policy_utm_profile_type
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
return 1
	%}
	"firewall policy {av-profile dlp-sensor replacemsg-group ips-sensor dnsfilter-profile application-list}" = %{
namespace import global::fw_policy_utm_profile_type
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
return 1
	%}
	"firewall policy webfilter-profile" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "profile-type"] ne "single" } {
	return 0
}
return 1
	%}
	"webfilter profile web youtube-restrict" = %{
set safe_search [cli_get_value $CLI_CUR_PARENT_NODE "" "" "safe-search"]
foreach flag $safe_search {
	if { $flag eq "header" } {
		return 1
	}
}
return 0
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
	"system accprofile sysgrp-permission" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sysgrp" 0 "custom"]
	%}
	"system accprofile netgrp-permission" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "netgrp" 0 "custom"]
	%}
	"system sdn-connector {username password server login-endpoint resource-url}" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "azure" && 
	[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "azure-region" 0 "local"] } {
	return 1
}
namespace import global::sys_sdn_conn_attr_visible
expr [sys_sdn_conn_attr_visible $type $CLI_CUR_NODE_NAME]
	%}
	"system sdn-connector {use-metadata-iam}" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "aws" } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiProxy-AWS"] } {
		return 1
	}
} elseif { $type eq "gcp" } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiProxy-GCP"] } {
		return 1
	}
} elseif { $type eq "azure" } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiProxy-Azure"] } {
		return 1
	}
}
return 0
	%}
	"system sdn-connector {access-key secret-key region}" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "aws" } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiProxy-AWS"] } {
		set iam_role [cli_get_value $CLI_CUR_PARENT_NODE "" "" "use-metadata-iam"]
		if { $iam_role == 0 || $iam_role eq "disable" } {
			return 1
		}
		return 0
	}
	return 1
}
if { $type eq "acs" || $type eq "alicloud" } {
	return 1
}
return 0
	%}
	"system sdn-connector {gcp-project-list}" = %{
set type [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "type"]
if { $type eq "gcp" && $CLI_GLOBAL_DEV } { return 1 }
if { $type eq "gcp" } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiProxy-GCP"] } {
		set iam_role [cli_get_value $CLI_CUR_PARENT_NODE "" "" "use-metadata-iam"]
		if { $iam_role == 0 || $iam_role eq "disable" } {
			return 1
		}
		return 0
	}
	return 1
}
return 0
	%}
	"system sdn-connector {gcp-project}" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "gcp" && $CLI_GLOBAL_DEV } { return 1 }
if { $type eq "gcp" } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiProxy-GCP"] } {
		set iam_role [cli_get_value $CLI_CUR_PARENT_NODE "" "" "use-metadata-iam"]
		if { $iam_role == 0 || $iam_role eq "disable" } {
			return 1	
		}
		return 0
	}
	return 1
}
return 0
	%}
	"system sdn-connector {service-account private-key key-passwd}" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "gcp" } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiProxy-GCP"] } {
		set iam_role [cli_get_value $CLI_CUR_PARENT_NODE "" "" "use-metadata-iam"]
		if { $iam_role == 0 || $iam_role eq "disable" } {
			return 1
		}
		return 0
	}
	return 1
}
return 0
	%}

	"system sdn-connector {tenant-id client-id client-secret}" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $CLI_CUR_NODE_NAME eq "tenant-id" && $type eq "oci"} {
	return 1
}
if { $type eq "azure" } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiProxy-Azure"] } {
		set iam_role [cli_get_value $CLI_CUR_PARENT_NODE "" "" "use-metadata-iam"]
		if { $iam_role == 0 || $iam_role eq "disable" } {
			return 1
		}
		return 0
	}
	return 1
}
return 0
	%}
	"system sdn-connector {oci-region user-id oci-cert}" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "oci" } {
	return 1
}
return 0
	%}
	"system sdn-connector {ha-status server-port server-list vpc-id oci-region-type compartment-id oci-fingerprint subscription-id resource-group azure-region secret-token domain group-name vcenter-server vcenter-username vcenter-password}" = %{
namespace import global::sys_sdn_conn_attr_visible
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
expr [sys_sdn_conn_attr_visible $type $CLI_CUR_NODE_NAME]
	%}
	"system sdn-connector {nic route-table external-ip route}" = %{
namespace import global::sys_sdn_conn_attr_visible
set type [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "type"]
expr [sys_sdn_conn_attr_visible $type $CLI_CUR_NODE_NAME]
	%}
	"system sdn-connector update-interval" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "aci" || $type eq "nuage" } {
	return 0
}
return 1
	%}
	"vpn ssl web portal {user-bookmark display-bookmark display-connection-tools display-history display-status heading redir-url theme custom-lang smb-min-version smb-max-version hide-sso-credential transform-backward-slashes smb-ntlmv1-auth}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web-mode" 0 "enable"]
	%}
	"vpn ssl web portal bookmark-group" = %{
set web_mode [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "web-mode"]
if { $web_mode eq "enable" } {
	return 1
}
return 0
	%}
	"vpn ssl web portal user-group-bookmark" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web-mode" 0 "enable"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "display-bookmark" 0 "enable"] } {
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
if { $sso eq "static" && ($app eq "web" || $app eq "citrix" ) } {
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
if { $server == 0 ||
     $server eq "" ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "rsso" 0 "enable"] } {
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
	"user radius accounting-server {server secret}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"wanopt auth-group psk" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth-method" 0 "psk"]
	%}
	"wanopt auth-group cert" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth-method" 0 "cert"]
	%}
	"firewall ssl-ssh-profile {caname certname}" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-cert-mode"] ne "replace" } {
	return 1
}
return 0
	%}
	"firewall ssl-ssh-profile server-cert" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-cert-mode"] eq "replace" } {
	return 1
}
return 0
	%}
	"firewall ssl-ssh-profile rpc-over-https" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "https" "" "status"] eq "deep-inspection" } {
	return 1
}
return 0
	%}
	"firewall ssl-ssh-profile mapi-over-https" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "https" "" "status"] eq "deep-inspection" } {
	return 1
}
return 0
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
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] ne "address" &&
     [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"] ne "address6" } {
	return 1
}
return 0
	%}
	"firewall ssl-ssh-profile {https ftps imaps pop3s smtps} ports" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "disable"] } {
	return 0
}
return 1
	%}
	"system dhcp server {ntp-server1 ntp-server2 ntp-server3}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ntp-service" 0 "specify"]
	%}
	"log fortianalyzer filter" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "log fortianalyzer setting" "upload-option" 1 "store-and-upload"]
	%}
	"log fortianalyzer2 filter" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "log fortianalyzer2 setting" "upload-option" 1 "store-and-upload"]
	%}
	"log fortianalyzer3 filter" = %{
expr [cli_is_match $CLI_GLOBAL_NODE 0 "log fortianalyzer3 setting" "upload-option" 1 "store-and-upload"]
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
if { $CLI_GLOBAL_DEV &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-option" 1 "store-and-upload"] } {
	return 1
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "upload-option" 1 "store-and-upload"] } {
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
	"firewall ippool port-per-user" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fixed-port-range"]
	%}
	"firewall policy poolname" = %{
namespace import global::policy_nat_visible
namespace import global::policy_ippool_visible
if { [policy_nat_visible $CLI_CUR_PARENT_NODE] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "disable"] 
		&& [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat64" 0 "disable"]} {
		return 0
	}
}
if { [policy_ippool_visible $CLI_CUR_PARENT_NODE] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ippool" 0 "disable"] } {
		return 0
	}
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "ipsec" || $action eq "deny" } {
	return 0
}
set dstaddr [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dstaddr"]
set int_srv [cli_get_value $CLI_CUR_PARENT_NODE "" "" "internet-service"]
if { $dstaddr eq "" && $int_srv ne "enable" } {
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
	"firewall policy auth-portal" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	return 1
}
return 0
	%}
	"firewall policy auth-cert" = %{
set users [cli_get_value $CLI_CUR_PARENT_NODE "" "" "users"]
set groups [cli_get_value $CLI_CUR_PARENT_NODE "" "" "groups"]
set disclaimer [cli_get_value $CLI_CUR_PARENT_NODE "" "" "disclaimer"]
if { $users eq "" && $groups eq "" && $disclaimer eq "disable"} {
	return 0
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action ne "accept" } {
	return 0
}
return 1
	%}
	"firewall policy disclaimer" = %{
namespace import global::aps_policy_auth_identity_based
if { [aps_policy_auth_identity_based $CLI_CUR_PARENT_NODE] } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "auth-portal"] eq "enable" } {
		return 0
	}
}
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
	"firewall policy {traffic-shaper traffic-shaper-reverse per-ip-shaper}" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "ipsec" } {
	return 1
} elseif { $action eq "accept" } {
	return 1
} elseif { $action eq "deny" } {
	if { [cli_has_feature "f_sslvpn"] } {
		namespace import global::is_sslvpn_policy
		namespace import global::FMG_is_sslvpn_policy_has_tunnel
		if { [is_sslvpn_policy $CLI_CUR_PARENT_NODE] } {
			if { [FMG_is_sslvpn_policy_has_tunnel $CLI_CUR_PARENT_NODE] } {
				return 1
			}
		}
	}
}
return 0
	%}
	"firewall policy service" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] } {
	return 0
}
set potype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $potype eq "explicit-ftp" || $potype eq "ssh" || $potype eq "access-proxy" } {
	return 0
}
return 1
	%}
	"firewall policy {dstaddr dstaddr-negate service-negate}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] } {
	return 0
}
return 1
	%}
	"firewall policy {dstaddr6 srcaddr6}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] } {
	return 0
}
return 1
	%}
	"firewall policy {internet-service-name internet-service-custom internet-service-group internet-service-custom-group internet-service-negate}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] } {
	return 1
}
return 0
	%}
	"firewall policy utm-status" = %{
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
	"firewall proxy-policy logtraffic" = %{
if { [cli_get_devinfo "FIPS"] eq "yes"} {
	return 0
}
return 1
	%}
	"firewall policy rsso" = %{
namespace import global::aps_policy_auth_identity_based
if { ![aps_policy_auth_identity_based $CLI_CUR_PARENT_NODE] } {
	return 0
}
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
	"firewall policy fsso" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" || $action eq "deny" } {
	if { [cli_has_feature "f_sslvpn"] } {
		namespace import global::is_sslvpn_policy
		if { [is_sslvpn_policy $CLI_CUR_PARENT_NODE] } {
			return 0
		}
	}
}
if { $action eq "accept" && [cli_has_feature "f_wireless_ac"] } {
	namespace import global::is_policy_enterprise_vap
	if { [is_policy_enterprise_vap $CLI_CUR_PARENT_NODE] } {
		return 0
	}
}
return 1
	%}
	"firewall policy {wccp replacemsg-override-group}" = %{
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
	"application list" = %{
namespace import global::if_skip_in_global_context_and_ngfw
if { [if_skip_in_global_context_and_ngfw] } {
	return 0
}
return 1
	%}
	"application list entries parameters" = %{
set app [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "application"]
if { $app eq "" } {
	return 0
}
return 1
	%}
	"system dedicated-mgmt {interface default-gateway dhcp-server dhcp-netmask dhcp-start-ip dhcp-end-ip disk-log-storage}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"firewall service custom protocol-number" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "IP"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "disable"]
	%}
	"dlp sensor filter proto mapi" = %{
set fnode [cli_get_parent $CLI_CUR_PARENT_NODE]
set node [cli_get_parent $fnode]
if { [cli_is_match $node 0 "" "feature-set" 0 "flow"] } {
	return 0
}
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
	"system interface vlanforward" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "vdom-link" || $type eq "loopback" } {
	return 0
}
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] } {
	return 0
}
return 1
	%}
	"system interface macaddr" = %{
namespace import global::intf_is_ipsec_tunnel
namespace import global::intf_vxlan
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { [cli_is_match $CLI_GLOBAL_NODE 0 "system ha" "mode" 1 "standalone"] &&
     $type ne "vdom-link" } {
	return 0
}
if { [cli_is_used $CLI_CUR_PARENT_NODE "system interface" "member"] &&
     ![intf_vxlan $CLI_CUR_PARENT_NODE] } {
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
} elseif { $type eq "geneve" } {
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
return 0
	%}
	"vpn certificate local {password private-key certificate}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "range" 0 "global"] } {
	if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
		return 0
	}
}
return 1
	%}
	"vpn certificate local scep-password" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "range" 0 "global"] } {
	if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
		return 0
	}
}
set url [cli_get_value $CLI_CUR_PARENT_NODE "" "" "scep-url"]
if { $url eq "" } {
	return 0
}
return 1
	%}
	"vpn certificate ca {ca}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "range" 0 "global"] } {
	if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
		return 0
	}
}
return 1
	%}
	"vpn certificate crl {ldap-server crl}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "range" 0 "global"] } {
	if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
		return 0
	}
}
return 1
	%}
	"vpn certificate crl ldap-password" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "range" 0 "global"] } {
	if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
		return 0
	}
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ldap-server"] eq "" } {
	return 0
}
return 1
	%}
	"vpn certificate crl {update-vdom}" = %{
if { [cli_get_devinfo "vdom-admin"] eq "yes" } {
	return 0
}
return 1
	%}
	"antivirus profile {ftgd-analytics analytics-db}" = %{
if { $CLI_GLOBAL_DEV } { return 1 }
if { [cli_is_match $CLI_GLOBAL_NODE 0 "system fortisandbox" "status" 0 "enable"] ||
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
}
if { [cli_is_match $CLI_GLOBAL_NODE 0 "system fortisandbox" "status" 0 "enable"] ||
     [cli_is_match $CLI_GLOBAL_NODE 0 "system fortiguard" "service-account-id" 1 ""] } {
	return 1
}
return 0
	%}
	"system global disk-usage" = %{
if { [cli_get_devinfo "is_logdisk_mounted"] eq "yes" } {
	return 1
}
return 0
	%}
	"firewall shaping-policy service" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "service-type" 0 "service"]
	%}
	"firewall shaping-policy {internet-service internet-service-custom}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "service-type" 0 "internet-service"]
	%}
	"firewall shaping-policy srcaddr" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"]
	%}
	"firewall shaping-policy dstaddr" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "service-type" 0 "service"]
	%}
	"firewall shaping-policy {srcaddr6 dstaddr6}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "6"]
	%}
	"application internet-service-custom disable-entry" = %{
set id [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "master-service-id"]
if { $id eq "" } {
	return 0
}
return 1
	%}
	"emailfilter profile {imap pop3 smtp smtps imaps pop3s} {action tag-type tag-msg hdrip local-override}" = %{
if { [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "spam-filtering" 1 "enable"] } {
	return 0
}
return 1
	%}
	"emailfilter profile mapi action" = %{
if { [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "spam-filtering" 1 "enable"] } {
	return 0
}
return 1
	%}
	"emailfilter profile {options flow-based spam-log extended-utm-log spam-filtering spam-bword-threshold spam-bword-table spam-bwl-table spam-mheader-table spam-rbl-table spam-iptrust-table replacemsg-group}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "external" 1 "enable"]
	%}
	"emailfilter profile {imap pop3 smtp msn-hotmail yahoo-mail gmail}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "external" 1 "enable"]
	%}
	"emailfilter profile mapi" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "external" 0 "enable"] ||
	[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "feature-set" 0 "flow"] } {
	return 0
}
return 1
	%}
	"firewall {address address6} {obj-id}" = %{
namespace import global::find_sdn_conn_type_by_name
set sdn [cli_get_value $CLI_CUR_PARENT_NODE "" "" "sdn"]
if { [find_sdn_conn_type_by_name $sdn] eq "nsx" } {
	return 1
}
return 0
	%}
	"firewall {address address6} list" = %{
set addr [cli_get_parent $CLI_CUR_PARENT_NODE]
if { [cli_is_match $addr 0 "" "type" 1 "dynamic"] } {
	return 0
}
namespace import global::find_sdn_conn_type_by_name
set sdn [cli_get_value $addr "" "" "sdn"]
set sdntype [find_sdn_conn_type_by_name $sdn]
set allow [list "nsx" "aws" "acs" "alicloud" "azure" "gcp" "oci" "kubernetes" "openstack" "vmware" "sepm"]
if { [lsearch $allow $sdntype] != -1 } {
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
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ipv6"] } {
	return 0
}	
return 1
	%}
	"firewall central-snat-map {orig-addr6 dst-addr6}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ipv6"] } {
	return 1
}	
return 0
	%}
	"vpn ipsec phase2-interface keepalive" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-negotiate" 1 "enable"]
	%}
	"firewall internet-service-custom entry port-range" = %{
if { $CLI_GLOBAL_DEV } { return 1 }
set proto [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "protocol"]
if { $proto == 6 || $proto == 17 || $proto == 132 } {
	return 1
}
return 0
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
if { $url eq "" } {
	return 0
}
return 1
	%}
	"waf profile {signature constraint method address-list url-access}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "external" 0 "enable"] } {
	return 0
}
return 1
	%}
	"user fsso {server port}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fortiems-cloud"] } {
	return 0
}
return 1
	%}
	"user fsso {ssl port2 port3 port4 port5 server2 server3 server4 server5 password2 password3 password4 password5}" = %{
namespace import global::fsso_local_agent_skip
if { [fsso_local_agent_skip] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fortiems-cloud"] } {
	return 0
}
return 1
	%}
	"user fsso {type source-ip source-ip6}" = %{
namespace import global::fsso_local_agent_skip
if { [fsso_local_agent_skip] } {
	return 0
}
return 1
	%}
	"user fsso ssl-trusted-cert" = %{
namespace import global::fsso_local_agent_skip
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fortiems-cloud"] } {
	return 0
}
if { [fsso_local_agent_skip] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssl" 0 "disable"] } {
	return 0
}
return 1
	%}
	"user fsso {ldap-server user-info-server}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "default"] } {
	return 0
}
return 1
	%}
	"user fsso ldap-poll" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "default"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ldap-server" 0 ""] } {
	return 0
}
return 1
	%}
	"user fsso {ldap-poll-interval ldap-poll-filter}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "default"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ldap-server" 0 ""] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ldap-poll" 1 "enable"] } {
	return 0
}
return 1
	%}
	"user fsso group-poll-interval" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "default"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ldap-server" 1 ""] } {
	return 0
}
return 1
	%}
	"log threat-weight application" = %{
set cate [cli_get_value $CLI_CUR_NODE "" "" "category"]
if { $cate eq "19" || $cate eq "\"19\"" } {
	return 0
}
return 1
	%}
	"system storage {partition device size status media-status order usage wanopt-mode}" = %{
return 1
	%}
	"system external-resource category" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "category"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "domain"] } {
	return 1
}
return 0
	%}
	"authentication scheme user-database" = %{
set method [cli_get_value $CLI_CUR_PARENT_NODE "" "" "method"]
if { [lsearch $method "form"] != -1 ||
     [lsearch $method "basic"] != -1 ||
     [lsearch $method "digest"] != -1 ||
     [lsearch $method "ssh-publickey"] != -1 } {
	return 1
}
return 0
	%}
	"authentication scheme {kerberos-keytab negotiate-ntlm}" = %{
set method [cli_get_value $CLI_CUR_PARENT_NODE "" "" "method"]
if { [lsearch $method "negotiate"] != -1 } {
	return 1
}
return 0
	%}
	"authentication scheme domain-controller" = %{
set method [cli_get_value $CLI_CUR_PARENT_NODE "" "" "method"]
set nego [cli_get_value $CLI_CUR_PARENT_NODE "" "" "negotiate-ntlm"]
if { [lsearch $method "ntlm"] != -1 ||
     ([lsearch $method "negotiate" ] != -1 &&
     $nego eq "enable" ) } {
	# fsso-agent-for-ntlm is unset in nodeact, no need to skip here.
	return 1
}
return 0
	%}
	"authentication scheme require-tfa" = %{
set method [cli_get_value $CLI_CUR_PARENT_NODE "" "" "method"]
if { [lsearch $method "form"] != -1 || [lsearch $method "basic"] != -1 } {
	return 1
}
return 0
	%}
	"authentication scheme fsso-guest" = %{
set method [cli_get_value $CLI_CUR_PARENT_NODE "" "" "method"]
set nego [cli_get_value $CLI_CUR_PARENT_NODE "" "" "negotiate-ntlm"]
if { [lsearch $method "basic"] != -1 ||
     [lsearch $method "digest"] != -1 ||
     [lsearch $method "ntlm"] != -1 } {
	return 1
}
if { [lsearch $method "negotiate"] != -1 && $nego eq "enable" } {
	return 1
}
return 0
	%}
	"authentication scheme fsso-agent-for-ntlm" = %{
set method [cli_get_value $CLI_CUR_PARENT_NODE "" "" "method"]
set nego [cli_get_value $CLI_CUR_PARENT_NODE "" "" "negotiate-ntlm"]
if { [lsearch $method "ntlm"] != -1 ||
     ([lsearch $method "negotiate" ] != -1 &&
     $nego eq "enable" ) } {
	# domain-controller is unset in nodeact, no need to skip here.
	return 1
}
return 0
	%}
	"authentication scheme ssh-ca" = %{
set method [cli_get_value $CLI_CUR_PARENT_NODE "" "" "method"]
if { [lsearch $method "ssh-publickey"] != -1 } {
	return 1
}
return 0
	%}
	"authentication setting {captive-portal captive-portal6}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "captive-portal-type" 0 "fqdn"]
	%}
	"authentication setting {captive-portal-ip captive-portal-ip6}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "captive-portal-type" 0 "ip"]
	%}
	"authentication setting captive-portal-ssl-port" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auth-https" 0 "enable"]
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
	"authentication rule web-portal" = %{
if { $CLI_GLOBAL_DEV } {
	set authset [cli_get_node $CLI_CUR_PKG_NODE "authentication setting" "" ""]
} else {
	set authset [cli_get_node $CLI_CUR_VDOM_NODE "authentication setting" "" ""]
}
if { $authset eq 0 } {
	return 0
}
if { [cli_get_value $authset "" "" "captive-portal-type"] eq "fqdn" } {
	if { [cli_get_value $authset "" "" "captive-portal"] eq "" &&
	     [cli_get_value $authset "" "" "captive-portal6"] eq "" } {
		return 0
	}
} elseif { [cli_get_value $authset "" "" "captive-portal-ip"] eq "" &&
           [cli_get_value $authset "" "" "captive-portal-ip6"] eq "" } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-based" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "http"]
	%}
	"system admin gui-dashboard widget fortiview-filters" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fortiview"]
	%}
	"system admin gui-dashboard widget {title fortiview-type fortiview-sort-by fortiview-timeframe fortiview-visualization}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fortiview"]
	%}
	"system admin gui-dashboard widget {fabric-device fabric-device-widget-name fabric-device-widget-visualization-type}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fabric-device"]
	%}
	"vpn ipsec phase1-interface {fec-send-timeout fec-base fec-codec fec-redundant}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fec-egress" 0 "enable"]
	%}
	"vpn ipsec phase1-interface {fec-receive-timeout}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fec-ingress" 0 "enable"]
	%}
	"system automation-action {email-to email-subject email-body}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action-type" 0 "email"]
	%}
	"system automation-action {aws-api-path aws-api-key aws-api-stage aws-api-id aws-region aws-domain}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action-type" 0 "aws-lambda"]
	%}
	"system automation-action {azure-app azure-function azure-domain azure-api-key}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action-type" 0 "azure-function"]
	%}
	"system automation-action script" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action-type" 0 "cli-script"]
	%}
	"system automation-action security-tag" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action-type" 0 "quarantine-nsx"]
	%}
	"system automation-action sdn-connector" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action-type" 0 "quarantine-nsx"]
	%}
	"system automation-action headers" = %{
set act [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action-type"]
if { $act ne "webhook" &&
     $act ne "aws-lambda" &&
     $act ne "azure-function" &&
     $act ne "alicloud-function" &&
     $act ne "google-cloud-function" } {
	return 0
}
return 1
	%}
	"system automation-action {method url port protocol}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action-type" 0 "webhook"]
	%}
	"system automation-action http-body" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action-type" 0 "webhook"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "method" 1 "get"]
	%}
	"firewall profile-group emailfilter-profile" = %{
namespace import global::fw_policy_mms_enabled
if { [fw_policy_mms_enabled $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"vpn ipsec phase1-interface network-overlay" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "2"]
	%}
	"vpn ipsec phase1-interface network-id" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "2"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "network-overlay" 0 "enable"]
	%}
	"user ldap search-type" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-member-check" 0 "user-attr"]
	%}
	"user ldap group-filter" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "group-member-check" 0 "user-attr"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "search-type" 1 "recursive"]
	%}
	"firewall address interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "interface-subnet"]
	%}
	"firewall address associated-interface" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "interface-subnet"]
	%}
	"log fortianalyzer-cloud setting {ips-archive}" = %{
return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 1 "disable"]
	%}
	"user ldap {server-identity-check}" = %{
return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "secure" 1 "disable"]
	%}
	"vpn ssl web portal bookmark-group bookmarks {listening-port remote-port show-status-window}" = %{
return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "apptype" 0 "portforward"]
	%}
	"user group" = %{
if { ![cli_is_traffic_vdom] } {
	set o_opts [cli_get_value $CLI_CUR_NODE "" "" "member"]
	if { $o_opts != 0 && [llength $o_opts] != 0 } {
		set n_opts {}
		foreach opt $o_opts {
			if { [cli_get_node $CLI_CUR_VDOM_NODE "user tacacs+" $opt ""] != 0 ||
				 [cli_get_node $CLI_CUR_VDOM_NODE "user radius" $opt ""] != 0 ||
				 [cli_get_node $CLI_CUR_VDOM_NODE "user ldap" $opt ""] != 0 ||
				 [cli_get_node $CLI_CUR_VDOM_NODE "user peer" $opt ""] != 0 } {
				lappend n_opts $opt
			}
		}
		if { $n_opts == 0 || [llength $n_opts] == 0 } {
			return 0
		}
	}
}
return 1
	%}
	"user group group-type" = %{
set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
if { $name eq "SSO_Guest_Users" } {
	return 0
}
return 1
	%}
	"system csf management-ip" = %{
return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"firewall profile-group {ssh-filter-profile waf-profile icap-profile webfilter-profile}" = %{
namespace import global::fw_policy_mms_enabled
if { [fw_policy_mms_enabled $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"firewall policy {emailfilter-profile}" = %{
namespace import global::fw_policy_utm_profile_type
namespace import global::fw_policy_mms_enabled
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
if { [fw_policy_mms_enabled $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"vpn ssl settings user-peer" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "reqclientcert" 0 "enable"]
	%}
	"vpn ssl settings authentication-rule user-peer" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "client-cert" 0 "enable"]
	%}
	"vpn ssl web portal {host-check mac-addr-check os-check}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "tunnel-mode" 1 "enable"] } {
	return 0
}
return 1
	%}
	"vpn ssl web portal {dns-suffix}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "tunnel-mode" 1 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web-mode" 1 "enable"] } {
	return 0
}
return 1
	%}
	"vpn ssl web portal split-dns" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "tunnel-mode" 0 "enable"]
	%}
	"vpn ssl web portal {mac-addr-action}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mac-addr-check" 1 "enable"] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "tunnel-mode" 1 "enable"] } {
	return 0
}
return 1
	%}
	"vpn ssl web portal mac-addr-check-rule" = %{
if { [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "mac-addr-check" 1 "enable"] } {
	return 0
}
if { [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "tunnel-mode" 1 "enable"] } {
	return 0
}
return 1
	%}
	"system saml {role cert server-address}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"system saml {portal-url entity-id single-sign-on-url single-logout-url idp-entity-id idp-single-sign-on-url idp-single-logout-url idp-cert}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "role" 0 "service-provider"]
	%}
	"system saml {tolerance life}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "role" 0 "identity-provider"]
	%}
	"system saml {service-providers}" = %{
set prof [cli_get_parent $CLI_CUR_PARENT_NODE]
expr [cli_is_match $prof 0 "" "status" 0 "enable"] && [cli_is_match $prof 0 "" "role" 0 "identity-provider"] && [cli_is_match $prof 0 "" "server-address" 1 ""]
	%}
	"system saml {default-login-page default-profile}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "role" 0 "identity-provider"] } {
	return 0
}
return 1
	%}
	"firewall ssl-ssh-profile {ssl https ftps imaps pop3s smtps} {unsupported-ssl-cipher unsupported-ssl-negotiation}" = %{
set curr_settings [cli_get_value $CLI_CUR_PARENT_NODE "" "" "status"]
if { $curr_settings ne "deep-inspection" } {
	return 0
}
return 1
	%}
	"system fortiguard {fortiguard-anycast-source anycast-sdns-server-ip anycast-sdns-server-port}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fortiguard-anycast" 0 "enable"]
	%}
	"system fortiguard {sdns-server-ip sdns-server-port}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fortiguard-anycast" 1 "enable"]
	%}
	"firewall profile-group cifs-profile" = %{
return 0
	%}
	"vpn ipsec phase2-interface initiator-ts-narrow" = %{
if { [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "transparent"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "encapsulation" 1 "tunnel-mode"] } {
	return 0
}
set gw_name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "phase1name"]
set gw [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $gw_name ""]
if { $gw == 0 } {
	set gw [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1" $gw_name ""]
	if { $gw == 0 } {
		return 0
	}
}
if { [cli_is_match $gw 0 "" "ike-version" 0 "1"] } {
	return 0
}
return 1
	%}
	"vpn ipsec phase1-interface aggregate-member" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dynamic"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-discovery-sender" 0 "enable"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-discovery-receiver" 0 "enable"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-discovery-forwarder" 0 "enable"] } {
	return 0
}
return 1
	%}
	"vpn ipsec phase1-interface aggregate-weight" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "dynamic"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-discovery-sender" 0 "enable"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-discovery-receiver" 0 "enable"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-discovery-forwarder" 0 "enable"] } {
	return 0
}
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "aggregate-member" 0 "enable"]]
	%}
	"firewall policy decrypted-traffic-mirror" = %{
namespace import global::deep_inspection_check
set proftype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "profile-type"]
if { $proftype ne "group" } {
	set prof [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ssl-ssh-profile"]
    set p [cli_get_node $CLI_CUR_VDOM_NODE "firewall ssl-ssh-profile" $prof ""]
    if { [deep_inspection_check $p ""] eq 1 } {
        return 1
    }
} else {
    set profgroup [cli_get_value $CLI_CUR_PARENT_NODE "" "" "profile-group"]
    if { $profgroup ne "" } {
        set prof [cli_get_value $CLI_CUR_VDOM_NODE "firewall profile-group" $profgroup "ssl-ssh-profile"]
        set p [cli_get_node $CLI_CUR_VDOM_NODE "firewall ssl-ssh-profile" $prof ""]
        if { [deep_inspection_check $p ""] eq 1 } {
            return 1
        }
    }
}
return 0
	%}
	"user ldap password-attr" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "antiphish" 0 "enable"]]
	%}
	"emailfilter block-allow-list entries ip4-subnet" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-type" 0 "ipv4"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ip"]]
	%}
	"emailfilter block-allow-list entries ip6-subnet" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-type" 0 "ipv6"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ip"]]
	%}
	"emailfilter block-allow-list entries addr-type" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "ip"]]
	%}
	"emailfilter block-allow-list entries {pattern-type email-pattern}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "email"]]
	%}
	"user saml {user-claim-type group-claim-type}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "adfs-claim" 0 "enable"]]
	%}
	"user saml {user-name group-name}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "adfs-claim" 1 "enable"]]
	%}
	"vpn ipsec phase1-interface {ip-delay-interval}" = %{
return [expr expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "unity-support" 0 "enable" "type" 0 "dynamic"]]
	%}
	"vpn ssl web portal {clipboard use-sdwan}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web-mode" 0 "enable"]]
	%}
	"vpn ssl web portal bookmark-group bookmarks {preconnection-id preconnection-blob}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "send-preconnection-id" 0 "enable"]]
	%}
	"vpn ssl web portal bookmark-group bookmarks {security}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "apptype" 0 "rdp"]]
	%}
	"vpn ssl web user-bookmark bookmarks {security}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "apptype" 0 "rdp"]]
	%}
	"vpn ssl web user-group-bookmark bookmarks {security}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "apptype" 0 "rdp"]]
	%}
	"firewall vip {src-filter nat-source-vip gratuitous-arp-interval srcintf-filter color}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "access-proxy"]]
	%}
%};
