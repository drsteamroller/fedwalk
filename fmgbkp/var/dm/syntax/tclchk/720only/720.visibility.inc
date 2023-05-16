visibility %{
	"system settings vdom-type" = %{
namespace import global::cli_sys_global_vdom_enable
if { [cli_sys_global_vdom_enable] } {
	return 1
}
return 0
	%}
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
	"policy package settings consolidated-firewall-mode" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
return 1
	%}
	"firewall policy6" = %{
return 0
	%}
	"firewall consolidated policy" = %{
return 0
	%}
	"firewall policy ztna-status" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
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
return 1
	%}
	"firewall policy ztna-geo-tag" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
set ztna_status [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ztna-status"]
if { $ztna_status ne "enable" } {
	return 0
}
return 1
	%}
	"firewall policy ztna-ems-tag" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
set ztna_status [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ztna-status"]
if { $ztna_status ne "enable" } {
	if { ![cli_branchpt_start 700 1336] } {
		return 0
	}

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
		set dstaddr6 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dstaddr6"]
		set vipnode6 [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip6" $dstaddr6 ""]
		if { $vipnode6 ne 0 } {
			set type [cli_get_value $vipnode6 "" "" "type"]
			if { $type eq "access-proxy" } {
				return 0
			}
		}

	}
}
return 1
	%}
	"firewall policy profile-protocol-options" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
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
return 1
	%}
	"firewall policy ssl-ssh-profile" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 1
}
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
return 1
	%}
	"firewall policy {icap-profile waf-profile ssh-filter-profile}" = %{
namespace import global::fw_policy_utm_profile_type
namespace import global::ngfw_mode_policy
namespace import global::fw_policy_inspection_flow
namespace import global::fw_policy_mms_enabled
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
if { [ngfw_mode_policy] ||
     [fw_policy_inspection_flow $CLI_CUR_PARENT_NODE] ||
     [fw_policy_mms_enabled $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"firewall policy {av-profile dlp-profile dlp-sensor replacemsg-group ips-sensor dnsfilter-profile application-list voip-profile}" = %{
namespace import global::fw_policy_utm_profile_type
namespace import global::ngfw_mode_policy
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
if { [ngfw_mode_policy] } {
	return 0
}
return 1
	%}
	"firewall policy {mms-profile}" = %{
namespace import global::fw_policy_utm_profile_type
namespace import global::ngfw_mode_policy
namespace import global::fw_policy_inspection_flow
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
if { [ngfw_mode_policy] || [fw_policy_inspection_flow $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"firewall policy {webfilter-profile}" = %{
namespace import global::ngfw_mode_policy
namespace import global::fw_policy_mms_enabled
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "profile-type"] ne "single" } {
	return 0
}
if { [ngfw_mode_policy] || [fw_policy_mms_enabled $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"firewall policy wsso" = %{
namespace import global::is_sslvpn_policy
namespace import global::nCfg_cw_policy_wsso_capable
if { ![nCfg_cw_policy_wsso_capable $CLI_CUR_PARENT_NODE] ||
     [is_sslvpn_policy $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"firewall {policy policy6} {application app-category url-category}" = %{
namespace import global::ngfw_mode_policy
expr [ngfw_mode_policy]
	%}
	"firewall policy schedule" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}

namespace import global::ngfw_mode_policy
expr ![ngfw_mode_policy]
	%}
	"firewall policy inspection-mode" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
namespace import global::ngfw_mode_policy
set dstaddr [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dstaddr"]
set vipnode [cli_get_node $CLI_CUR_VDOM_NODE "firewall vip" $dstaddr ""]
if { $vipnode ne 0 } {
	set type [cli_get_value $vipnode "" "" "type"]
	if { $type eq "access-proxy" } {
		return 1
	}
}
expr ![ngfw_mode_policy] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "accept"]
	%}
	"firewall policy {webproxy-forward-server webproxy-profile}" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
namespace import global::ngfw_mode_policy
namespace import global::fw_policy_inspection_flow
if { [ngfw_mode_policy] || [fw_policy_inspection_flow $CLI_CUR_PARENT_NODE] } {
	return 0
}
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
return 1
	%}
	"firewall policy {http-policy-redirect ssh-policy-redirect}" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
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
namespace import global::ngfw_mode_policy
expr ![ngfw_mode_policy] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "inspection-mode" 0 "proxy"]
	%}
	"switch-controller vlan" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
return 1
	%}
	"switch-controller managed-switch poe-pre-standard-detection" = %{
set ptype [cli_get_value $CLI_CUR_PARENT_NODE "" "" "poe-detection-type"]
if { $ptype eq 1  } {
	return 1
}
return 0
	%}
	"switch-controller managed-switch ports poe-pre-standard-detection" = %{
set ptype [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "poe-detection-type"]
if { $ptype eq 2  } {
	if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "poe-capable"] } {
		return 1
	}
	set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "port-name"]
	set swnode [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]]
	if { $CLI_GLOBAL_DEV } {
		set platform [cli_get_value $swnode "" "" "_platform"]
	} else {
		set platform [cli_get_value $swnode "" "" "switch-id"]
	}
	if { [cli_fsp_is_poe_supported $platform $name] } {
		return 1
	}
}
return 0
	%}
	"switch-controller managed-switch ports {port-policy matched-dpp-policy matched-dpp-intf-tags}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "access-mode" 0 "dynamic"]
	%}
	"switch-controller quarantine" = %{
return 0
	%}
	"switch-controller dynamic-port-policy policy {mac type family host}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "category" 0 "device"]]
	%}
	"switch-controller dynamic-port-policy policy interface-tags" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "category" 0 "interace-tags"]]
	%}
	"antivirus profile {http ftp imap pop3 smtp mapi nntp smb} av-optimize" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
return 1
	%}
	"antivirus profile {http ftp imap pop3 smtp mapi nntp smb} content-disarm" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
if { [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "feature-set"] eq "flow" } {
	return 0
}
return 1
	%}
	"antivirus profile content-disarm" = %{
namespace import global::ngfw_mode_policy
namespace import global::scan_mode_full
if { [ngfw_mode_policy] } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "feature-set"] eq "flow" } {
	return 0
}
return 1
	%}
	"antivirus profile mapi" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "feature-set"] eq "flow" } {
	return 0
}
return 1
	%}
	"antivirus profile ssh" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "feature-set"] eq "flow" } {
	return 0
}
return 1
	%}
	"antivirus profile smb" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"] eq "proxy" } {
	return 0
}
return 1
	%}
	"antivirus profile {av-virus-log av-block-log}" = %{
return 1
	%}
	"antivirus profile nntp" = %{
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspection-mode"] eq "flow-based" } {
	return 0
}
return 1
	%}
	"dlp sensor dlp-log" = %{
return 1
	%}
	"firewall mms-profile {mms-carrier-endpoint-filter-log mms-antispam-mass-log mms-notification-log mms-checksum-log mms-av-virus-log mms-av-block-log mms-av-oversize-log mms-web-content-log}" = %{
return 1
	%}
	"system sdwan members gateway"  = %{
set intf [cli_get_value $CLI_CUR_PARENT_NODE "" "" "interface"]
set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $intf ""]
if { [cli_get_value $intfnode "" "" "type"] ne "tunnel" } {
	return 1
}
# allow setting gateway if it's dialup IPsec tunnel with net-device disable
set ipsec_phase1_intf [cli_get_node $CLI_CUR_VDOM_NODE "vpn ipsec phase1-interface" $intf ""]
if { $ipsec_phase1_intf ne 0 } {
	set ipsec_phase1_intf_type [cli_get_value $ipsec_phase1_intf "" "" "type"]
	set ipsec_phase1_intf_ndev [cli_get_value $ipsec_phase1_intf "" "" "net-device"]
	if { $ipsec_phase1_intf_type eq "dynamic" && $ipsec_phase1_intf_ndev eq "disable" } {
		return 1
	}
}
return 0
	%}
	"emailfilter profile {imap pop3 smtp mapi msn-hotmail yahoo-mail gmail} log" = %{
return 1
	%}
	"webfilter profile web {safe-search log-search keyword-match}" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
set feature_set [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "feature-set"]
if { $feature_set == "flow" } {
	return 0
}
return 1
	%}
	"webfilter profile youtube-channel-status" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "feature-set"] eq "flow" } {
	return 0
}
return 1
	%}
	"webfilter profile youtube-channel-filter" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "feature-set"] eq "flow" } {
	return 0
}
if { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "youtube-channel-status"] eq "disable" } {
	return 0
}
return 1
	%}
	"webfilter profile web youtube-restrict" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
if { [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "feature-set"] eq "flow" } {
	return 0
}
set snodes [cli_get_value $CLI_CUR_PARENT_NODE "" "" "safe-search"]
foreach snode $snodes {
	if {$snode eq "header" } {
		return 1
	}
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
	if { [string match -nocase $platform "FortiCarrier-VM64-AWS"] ||
	     [string match -nocase $platform "Fortigate-VM64-AWS"] ||
	     [string match -nocase $platform "Fortigate-VM64-AWSONDEMAND"] } {
		return 1
	}
} elseif { $type eq "oci" } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiCarrier-VM64-OPC"] ||
	     [string match -nocase $platform "Fortigate-VM64-OPC"] } {
		return 1
	}
} elseif { $type eq "gcp" } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiCarrier-VM64-GCP"] ||
	     [string match -nocase $platform "Fortigate-VM64-GCP"] ||
	     [string match -nocase $platform "Fortigate-VM64-GCPONDEMAND"] } {
		return 1
	}
} elseif { $type eq "azure" } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiCarrier-VM64-AZURE"] ||
	     [string match -nocase $platform "Fortigate-VM64-AZURE"] ||
	     [string match -nocase $platform "Fortigate-VM64-AZUREONDEMAND"] } {
		return 1
	}
}
return 0
	%}
	"system sdn-connector {access-key secret-key region}" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "aws" } {
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiCarrier-VM64-AWS"] ||
	     [string match -nocase $platform "Fortigate-VM64-AWS"] ||
	     [string match -nocase $platform "Fortigate-VM64-AWSONDEMAND"] } {
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
if { $type eq "gcp" } {
	if { $CLI_GLOBAL_DEV } { return 1 }
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiCarrier-VM64-GCP"] ||
	     [string match -nocase $platform "Fortigate-VM64-GCP"] ||
	     [string match -nocase $platform "Fortigate-VM64-GCPONDEMAND"] } {
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
if { $type eq "gcp" } {
	if { $CLI_GLOBAL_DEV } { return 1 }
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiCarrier-VM64-GCP"] ||
	     [string match -nocase $platform "Fortigate-VM64-GCP"] ||
	     [string match -nocase $platform "Fortigate-VM64-GCPONDEMAND"] } {
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
	if { [string match -nocase $platform "FortiCarrier-VM64-GCP"] ||
	     [string match -nocase $platform "Fortigate-VM64-GCP"] ||
	     [string match -nocase $platform "Fortigate-VM64-GCPONDEMAND"] } {
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
	if { [string match -nocase $platform "FortiCarrier-VM64-AZURE"] ||
	     [string match -nocase $platform "Fortigate-VM64-AZURE"] ||
	     [string match -nocase $platform "Fortigate-VM64-AZUREONDEMAND"] } {
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
	set platform [cli_get_devinfo "platform"]
	if { [string match -nocase $platform "FortiCarrier-VM64-OPC"] ||
	     [string match -nocase $platform "Fortigate-VM64-OPC"] } {
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
	"system sdn-connector verify-certificate" = %{
namespace import global::sys_sdn_conn_attr_visible
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
if { $type eq "azure" } {
	set region [cli_get_value $CLI_CUR_PARENT_NODE "" "" "azure-region"]
	if { $region eq "local" } {
		return 1
	}
}
expr [sys_sdn_conn_attr_visible $type $CLI_CUR_NODE_NAME]
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
	"vpn ipsec phase1 eap" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "2"]
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
	"wireless-controller wtp power-level" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-power-level" 0 "disable"]
	%}
	"wireless-controller wtp ap-auto-suppress" = %{
set apscan [cli_get_value $CLI_CUR_PARENT_NODE "" "" "ap-scan"]
set wtp_prof [cli_get_value $CLI_CUR_PARENT_NODE "" "" "wtp-profile"]
if { $wtp_prof ne "" || $apscan ne "enable" } {
	return 0
}
return 1
	%}
	"wireless-controller wtp {auto-power-level auto-power-high auto-power-low}" = %{
if { $CLI_CUR_NODE_NAME eq "auto-power-high" ||
     $CLI_CUR_NODE_NAME eq "auto-power-low" } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-power-level" 0 "disable"] } {
		return 0
	}
}
return 1
	%}
	"wireless-controller wids-profile {ap-bgscan-period ap-bgscan-intv ap-bgscan-duration ap-bgscan-idle ap-bgscan-report-intv ap-bgscan-disable-day ap-bgscan-disable-start ap-bgscan-disable-end ap-fgscan-report-intv ap-scan-passive rogue-scan ap-scan-threshold}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ap-scan" 0 "enable"]
	%}
	"wireless-controller wids-profile ap-auto-suppress" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ap-scan" 0 "enable"] && { [cli_get_value $CLI_CUR_PARENT_NODE "" "" "sensor-mode" ] ne "disable" }
	%}
	"wireless-controller wtp {radio-1 radio-2 radio-3 radio-4} vap-all" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-vaps" 0 "enable"]
	%}
	"wireless-controller wtp {radio-1 radio-2 radio-3 radio-4} vaps" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-vaps" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "vap-all" 0 "manual"]
	%}
	"wireless-controller qos-profile {wmm-uapsd call-admission-control dscp-wmm-mapping}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wmm" 0 "enable"]
	%}
	"wireless-controller qos-profile {call-capacity bandwidth-admission-control}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "call-admission-control" 0 "enable"]
	%}
	"wireless-controller qos-profile {dscp-wmm-vo dscp-wmm-vi dscp-wmm-be dscp-wmm-bk}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dscp-wmm-mapping" 0 "enable"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "wmm" 0 "enable"] } {
	return 1
}
return 0
	%}
	"wireless-controller qos-profile {bandwidth-capacity}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "bandwidth-admission-control" 0 "enable"]
	%}
	"extender-controller extender modem1 auto-switch {status disconnect-threshold disconnect-period}" = %{
return 0
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
	"firewall ssl-ssh-profile {https ftps imaps pop3s smtps} status" = %{
set ssl [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "ssl" "" "inspect-all"]
if { $ssl eq "" || $ssl eq 0 } {
	set ssl [cli_get_defvalue "firewall ssl-ssh-profile ssl" "inspect-all"]
}
if { $ssl ne "disable" } {
	return 0
}
return 1
	%}
	"firewall ssl-ssh-profile {https ftps imaps pop3s smtps} ports" = %{
set ssl [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "ssl" "" "inspect-all"]
if { $ssl eq "" || $ssl eq 0 } {
	set ssl [cli_get_defvalue "firewall ssl-ssh-profile ssl" "inspect-all"]
}
if { $ssl ne "disable" } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "disable"] } {
	return 0
}
return 1
	%}
	"firewall ssl-ssh-profile {https ftps imaps pop3s smtps} client-cert-request" = %{
set ssl [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "ssl" "" "inspect-all"]
if { $ssl eq "" || $ssl eq 0 } {
	set ssl [cli_get_defvalue "firewall ssl-ssh-profile ssl" "inspect-all"]
}
if { $ssl ne "disable" } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 1 "deep-inspection"] } {
	return 0
}
return 1
	%}
	"firewall ssl-ssh-profile ssh ports" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "inspect-all" 1 "deep-inspection"]
	%}
	"firewall profile-protocol-options {http ftp imap pop3 smtp nntp} ports" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "inspect-all" 1 "enable"]
	%}
	"voip profile sip {log-call-summary log-violations}" = %{
return 1
	%}
	"voip profile sip {ssl-client-certificate ssl-server-certificate ssl-auth-client ssl-auth-server}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ssl-mode" 1 "off"]
	%}
	"voip profile sccp {log-call-summary log-violations}" = %{
return 1
	%}
	"system dhcp server {ntp-server1 ntp-server2 ntp-server3}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ntp-service" 0 "specify"]
	%}
	"endpoint-control profile forticlient-winmac-settings {forticlient-av forticlient-wf forticlient-application-firewall forticlient-vuln-scan forticlient-vpn-provisioning forticlient-settings-lock forticlient-update-from-fmg forticlient-ad forticlient-ui-options client-log-when-on-net}" = %{
return 1
	%}
	"endpoint-control profile forticlient-winmac-settings {forticlient-wf-profile disable-wf-when-protected}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-wf" 0 "enable"]
	%}
	"endpoint-control profile forticlient-winmac-settings {forticlient-vuln-scan-schedule forticlient-vuln-scan-on-registration}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-vuln-scan" 0 "enable"]
	%}
	"endpoint-control profile forticlient-winmac-settings {forticlient-log-upload-server forticlient-log-upload-level forticlient-log-ssl-upload forticlient-log-upload-schedule}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-system-compliance" 0 "enable"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-log-upload" 0 "enable"] } {
	return 1
}
return 0
	%}
	"endpoint-control profile forticlient-winmac-settings {forticlient-update-server forticlient-update-failover-to-fdn}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-update-from-fmg" 0 "enable"]
	%}
	"endpoint-control profile forticlient-winmac-settings forticlient-application-firewall-list" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-application-firewall" 0 "enable"]
	%}
	"endpoint-control profile forticlient-android-settings {forticlient-wf-profile disable-wf-when-protected}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-wf" 0 "enable"]
	%}
	"endpoint-control profile forticlient-ios-settings {forticlient-wf-profile disable-wf-when-protected}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-wf" 0 "enable"]
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
	"wireless-controller vap local-bridging" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mesh-backhaul" 1 "enable"]
	%}
	"wireless-controller vap nac" = %{
namespace import global::is_wlan_mesh_bh_enabled
expr {![is_wlan_mesh_bh_enabled $CLI_CUR_PARENT_NODE]}
	%}
	"wireless-controller vap nac-profile" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nac" 0 "enable"]
	%}
	"log fortianalyzer setting {ips-archive monitor-keepalive-period monitor-failure-retry-period source-ip upload-option}" = %{
if { $CLI_GLOBAL_DEV || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"] } {
	return 1
}
return 0
	%}
	"wireless-controller vap {primary-wag-profile secondary-wag-profile}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "local-bridging" 0 "enable"]
	%}
	"wireless-controller vap {tunnel-echo-interval tunnel-fallback-interval}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "local-bridging" 1 "enable"] } {
	return 0
}
set pri_prof [cli_get_value $CLI_CUR_PARENT_NODE "" "" "primary-wag-profile"]
if { $pri_prof ne "" } {
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
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat46" 0 "enable"] } {
	return 0
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
	"firewall policy poolname6" = %{
namespace import global::policy_nat_visible
namespace import global::policy_ippool_visible
if { [policy_nat_visible $CLI_CUR_PARENT_NODE] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "disable"] 
		&& [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat46" 0 "disable"] } {
		return 0
	}
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat64" 0 "enable"] } {
	return 0
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
set dstaddr6 [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dstaddr6"]
if { $dstaddr6 eq "" } {
	return 0
}
return 1
	%}
	"firewall policy6 nat" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	return 1
}
return 0
	%}
	"firewall policy6 {ippool}" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	if { [cli_has_feature "f_sslvpn"] } {
		namespace import global::is_sslvpn_policy
		namespace import global::FMG_is_sslvpn_policy_has_tunnel
		if { [is_sslvpn_policy $CLI_CUR_PARENT_NODE] } {
			if { [FMG_is_sslvpn_policy_has_tunnel $CLI_CUR_PARENT_NODE] } {
				if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "enable"] } {
					return 1
				}
			} else {
				return 0
			}
		}
	}
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "enable"] } {
		return 1
	}
} elseif { $action eq "deny" } {
	if { [cli_has_feature "f_sslvpn"] } {
		namespace import global::is_sslvpn_policy
		namespace import global::FMG_is_sslvpn_policy_has_tunnel
		if { [is_sslvpn_policy $CLI_CUR_PARENT_NODE] } {
			if { [FMG_is_sslvpn_policy_has_tunnel $CLI_CUR_PARENT_NODE] } {
				if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "enable"] } {
					return 1
				}
			} else {
				return 0
			}
		}
	}
}
return 0
	%}
	"firewall policy6 {poolname}" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	if { [cli_has_feature "f_sslvpn"] } {
		namespace import global::is_sslvpn_policy
		namespace import global::FMG_is_sslvpn_policy_has_tunnel
		if { [is_sslvpn_policy $CLI_CUR_PARENT_NODE] } {
			if { [FMG_is_sslvpn_policy_has_tunnel $CLI_CUR_PARENT_NODE] } {
				if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "enable"] } {
					if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ippool" 0 "enable"] } {
						return 1
					}
				}
			} else {
				return 0
			}
		}
	}
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "enable"] } {
		if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ippool" 0 "enable"] } {
			return 1
		}
	}
} elseif { $action eq "deny" } {
	if { [cli_has_feature "f_sslvpn"] } {
		namespace import global::is_sslvpn_policy
		namespace import global::FMG_is_sslvpn_policy_has_tunnel
		if { [is_sslvpn_policy $CLI_CUR_PARENT_NODE] } {
			if { [FMG_is_sslvpn_policy_has_tunnel $CLI_CUR_PARENT_NODE] } {
				if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "enable"] } {
					if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ippool" 0 "enable"] } {
						return 1
					}
				}
			} else {
				return 0
			}
		}
	}
}
return 0
	%}
	"firewall policy {identity-based-route}" = %{
namespace import global::aps_policy_auth_identity_based
if { ![aps_policy_auth_identity_based $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"firewall policy {auth-redirect-addr}" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	namespace import global::aps_policy_auth_identity_based
	set disclaimer [cli_get_value $CLI_CUR_PARENT_NODE "" "" "disclaimer"]
	if { ($disclaimer eq "enable" ) ||
	     [aps_policy_auth_identity_based $CLI_CUR_PARENT_NODE] } {
		return 1
	}
}
return 0
	%}
	"firewall policy {auth-path}" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
namespace import global::aps_policy_auth_identity_based
if { ![aps_policy_auth_identity_based $CLI_CUR_PARENT_NODE] } {
	return 0
}
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	return 1
}
return 0
	%}
	"firewall policy {redirect-url}" = %{
set disc [cli_get_value $CLI_CUR_PARENT_NODE "" "" "disclaimer"]
namespace import global::aps_policy_auth_identity_based
if { $disc eq "enable" || [aps_policy_auth_identity_based $CLI_CUR_PARENT_NODE] } {
	set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
	if { $action eq "accept" } {
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
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
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
	"firewall policy {ntlm}" = %{
namespace import global::aps_policy_auth_identity_based
if { ![aps_policy_auth_identity_based $CLI_CUR_PARENT_NODE] } {
	return 0
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
} elseif { $action eq "deny" } {
	if { [cli_has_feature "f_sslvpn"] } {
		namespace import global::is_sslvpn_policy
		if { [is_sslvpn_policy $CLI_CUR_PARENT_NODE] } {
			return 0
		}
	}
}
if { [cli_has_feature "f_fsso"] } {
	return 1
}
return 0
	%}
	"firewall policy {disclaimer}" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
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
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
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
	"firewall policy {reputation-direction}" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
set rp_min [cli_get_value $CLI_CUR_PARENT_NODE "" "" "reputation-minimum"]
if { $rp_min > 0 } {
	return 1
}
return 0
	%}
	"firewall policy {internet-service}" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
return 1
	%}
	"firewall policy {service dstaddr dstaddr-negate service-negate}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] } {
	return 0
}
return 1
	%}
	"firewall policy {srcaddr6 srcaddr6-negate}" = %{
if { ![cli_branchpt_start 700 1180] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] ||
     		[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service-src" 0 "enable"] } {
		return 0
	}
}
if { [cli_branchpt_start 700 1228] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service6-src" 0 "enable"] } {
		return 0
	}
}
set rp_min [cli_get_value $CLI_CUR_PARENT_NODE "" "" "reputation-minimum"]
if { $rp_min > 0 } {
	return 0
}
return 1
	%}
	"firewall policy {dstaddr6 dstaddr6-negate}" = %{
if { ![cli_branchpt_start 700 1180] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] ||
		[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service-src" 0 "enable"] } {
		return 0
	}
}
if { [cli_branchpt_start 700 1228] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service6" 0 "enable"] } {
		return 0
	}
}
set rp_min [cli_get_value $CLI_CUR_PARENT_NODE "" "" "reputation-minimum"]
if { $rp_min > 0 } {
	return 0
}
return 1
	%}
	"firewall policy6 {service dstaddr dstaddr-negate service-negate}" = %{
return 1
	%}
	"firewall policy {internet-service-name internet-service-custom internet-service-group internet-service-custom-group internet-service-negate}" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] } {
	return 1
}
return 0
	%}
	"firewall {policy policy6} status" = %{
return 1
	%}
	"firewall policy6 logtraffic" = %{
return 1
	%}
	"firewall proxy-policy logtraffic" = %{
if { [cli_get_devinfo "FIPS"] eq "yes"} {
	return 0
}
return 1
	%}
	"firewall {policy64 policy46 multicast-policy explicit-proxy-policy} dstaddr" = %{
return 1
	%}
	"firewall policy utm-status" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
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
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 1
}
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
	"firewall policy6 utm-status" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "deny" } {
	return 0
}
return 1
	%}
	"firewall {policy policy6} logtraffic {utm}" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "deny" } {
	return 0
}
return 1
	%}
	"firewall policy6 {timeout-send-rst}" = %{
return 1
	%}
	"firewall policy {timeout-send-rst}" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	if { [cli_has_feature "f_sslvpn"] } {
		namespace import global::is_sslvpn_policy
		namespace import global::FMG_is_sslvpn_policy_has_tunnel
		if { [is_sslvpn_policy $CLI_CUR_PARENT_NODE] } {
			if { ![FMG_is_sslvpn_policy_has_tunnel $CLI_CUR_PARENT_NODE] } {
				return 0
			}
		}
	}
} elseif { $action eq "deny" } {
	return 0
}
return 1
	%}
	"firewall policy {endpoint-compliance}" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	return 1
} elseif { $action eq "deny" } {
	return 1
}
return 0
	%}
	"firewall policy {internet-service-src}" = %{
return 1
	%}
	"firewall policy {srcaddr srcaddr-negate}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service-src" 0 "disable"]
	%}
	"firewall policy {internet-service-src-id internet-service-src-custom internet-service-src-negate internet-service-src-group internet-service-src-custom-group}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service-src" 0 "enable"]
	%}
	"firewall policy6 {srcaddr srcaddr-negate}" = %{
return 1
	%}
	"firewall policy {ntlm-guest ntlm-enabled-browsers}" = %{
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
	"firewall {policy policy6} rsso" = %{
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
	"firewall {policy policy6} fsso" = %{
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
	"firewall policy {fsso-agent-for-ntlm user-agent-string}" = %{
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
	"firewall policy match-vip" = %{
if { $CLI_GLOBAL_DEV } {
	return 1
}
set en [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "central-nat"]
if { $en eq "enable" } {
	return 0
}
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action ne "deny" } {
	return 0
}
if { [ngfw_mode_policy] } {
	return 0
}
namespace import global::is_sslvpn_policy
if { [is_sslvpn_policy $CLI_CUR_PARENT_NODE] } {
	return 0
}
set hyperscale [cli_get_devinfo "hyperscale"]
set po_level [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "policy-offload-level"]
if { $hyperscale eq "yes" && $po_level eq "full-offload" } {
	return 0
}
return 1
	%}
	"firewall {policy policy6} replacemsg-override-group" = %{
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
	"firewall {policy policy6} {natip}" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
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
	"firewall policy {rtp-addr}" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "rtp-nat" 1 "enable"] } {
	return 0
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
	"firewall policy {session-ttl rtp-nat}" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
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
	"wireless-controller wtp-profile" = %{
namespace import global::ncfg_is_fapc_support_ctry
namespace import global::ncfg_is_fapc_platform
set plt [cli_get_value $CLI_CUR_NODE "platform" "" "type"]
if { [ncfg_is_fapc_platform $plt] } {
	set country [cli_get_value $CLI_CUR_VDOM_NODE "wireless-controller setting" "" "country"]
	set compat [cli_get_value $CLI_CUR_VDOM_NODE "wireless-controller setting" "" "fapc-compatibility"]
	if { $compat eq "disable" } {
		return 0
	}
	if { $plt ne "C24JE" && ![ncfg_is_fapc_support_ctry $country] } {
		return 0
	}
}
return 1
	%}
	"wireless-controller wtp-profile platform mode" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set val [cli_get_devinfo "pm2_wl_wtpcap_attr" $type "cap"]
set CW_WTP_CAP_VWTP [expr 1 << 20]
expr (($val & $CW_WTP_CAP_VWTP) ? 1 : 0)
	%}
	"wireless-controller wtp-profile radio-2 ap-sniffer-bufsize" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sniffer"]
	%}
	"wireless-controller wtp-profile dtls-in-kernel" = %{
expr ([lsearch [cli_get_value $CLI_CUR_PARENT_NODE "" "" "dtls-policy"] "dtls-enabled" ] >= 0)
	%}
	"firewall {policy policy6} {vpntunnel}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "ipsec"]
	%}
	"firewall policy {inbound outbound}" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "ipsec"]
	%}
	"firewall {policy policy6} {natinbound natoutbound}" = %{
if { [cli_get_value $CLI_CUR_VDOM_NODE "system settings" "" "opmode"] eq "transparent" } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 1 "ipsec"] } {
	return 0
}
return 1
	%}
	"router bgp neighbor-range {prefix neighbor-group}" = %{
return 1
	%}
	"system dedicated-mgmt {interface default-gateway dhcp-server dhcp-netmask dhcp-start-ip dhcp-end-ip disk-log-storage}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "status" 0 "enable"]
	%}
	"firewall service custom protocol-number" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "IP"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "disable"]
	%}
	"dlp sensor nac-quar-log" = %{
return 1
	%}
	"dlp sensor filter proto mapi" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
set fnode [cli_get_parent $CLI_CUR_PARENT_NODE]
set node [cli_get_parent $fnode]
if { [cli_is_match $node 0 "" "feature-set" 0 "flow"] } {
	return 0
}
return 1
	%}
	"endpoint-control profile forticlient-winmac-settings auto-vpn-when-off-net" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-vpn-provisioning" 0 "enable"]
	%}
	"endpoint-control profile forticlient-winmac-settings auto-vpn-name" = %{
set autovpn [cli_get_value $CLI_CUR_PARENT_NODE	"" "" "auto-vpn-when-off-net"]
set vpnprov [cli_get_value $CLI_CUR_PARENT_NODE "" "" "forticlient-vpn-provisioning"]
if { $autovpn eq "disable" || $vpnprov eq "disable" } {
	return 0
}
return 1
	%}
	"endpoint-control profile forticlient-winmac-settings forticlient-vpn-settings" = %{
set vpnprov [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "forticlient-vpn-provisioning"]
if { $vpnprov eq "disable" } {
	return 0
}
return 1
	%}
	"endpoint-control profile forticlient-winmac-settings forticlient-vpn-settings {remote-gw preshared-key}" = %{
set vpnprov [cli_get_value [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]] "" "" "forticlient-vpn-provisioning"]
if { $vpnprov eq "disable" } {
	return 0
}
return 1
	%}
	"webfilter profile web-filter-sdns-portal" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "inspection-mode" 0 "dns"]
	%}
	"firewall policy permit-stun-host" = %{
namespace import global::policy_nat_visible
expr [policy_nat_visible $CLI_CUR_PARENT_NODE] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "permit-any-host" 1 "enable"]
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
	"system interface name" = %{
set type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "type"]
set wlmode [cli_get_value $CLI_GLOBAL_NODE "system wireless settings" "" "mode"]
set platform [cli_get_devinfo "platform"]
set check [expr ![string match -nocase $platform "FortiWiFi-60C"]]
if { $check && $wlmode != 0 && $wlmode eq "SCAN" && $type eq "wireless" } {
	return 0
}
return 1
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
	"system interface {switch-controller-nac switch-controller-dynamic switch-controller-iot-scanning}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fortilink" 0 "enable"]
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
} elseif { $type eq "vxlan" } {
	return 1
} elseif { $type eq "lan-extension" } {
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
} elseif { $type eq "vap-switch" } {
	return 1
} elseif { $type eq "vdom-link" } {
	set name [cli_get_value $CLI_CUR_PARENT_NODE "" "" "name"]
	set name [string range $name 0 [expr [string length $name] - 2]]
	set type [cli_get_value $CLI_GLOBAL_NODE "system vdom-link" $name "type"]
	if { $type eq "ethernet" } {
		return 1
	}
} elseif { $type eq "emac-vlan" } {
	return 1
}
return 0
	%}
	"application ffdb-custom comment" = %{
return 1
	%}
	"wireless-controller wtp {radio-1 radio-2 radio-3 radio-4} band" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "override-band" 0 "enable"]
	%}

	"wireless-controller wtp {radio-2 radio-3 radio-4} drma-manual-mode" = %{
set wtp_id [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "wtp-id"]
set platform [cli_get_devinfo "wtp_plat" $wtp_id]
if { $platform eq "" } {
	return 0
}
set radio $CLI_CUR_PARENT_NAME
set r 2
if { $radio eq "radio-2" } {
	if { $platform eq "FWF" } {
		return 0
	}
} elseif { $radio eq "radio-3" } {
	set r 3
} elseif { $radio eq "radio-4" } {
	set r 4
}
if { [cli_get_devinfo "pm2_wl_radio_enabled" $r $platform] eq "yes" } {
	return 1
}
return 0
	%}

	"system sdwan service quality-link" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "auto"]
	%}
	"system sdwan service {health-check link-cost-factor}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "auto"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "priority"]
	%}
	"system sdwan service {packet-loss-weight latency-weight jitter-weight bandwidth-weight}" = %{
expr ([cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "auto" ] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "priority"] ) && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "link-cost-factor" 0 "custom-profile-1"]
	%}
	"system sdwan service sla" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "mode" 0 "sla"] || [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "mode" 0 "load-balance"]
	%}
	"system sdwan service priority-members" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "priority"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sla"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "load-balance"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "manual"]
	%}
	"system sdwan service internet-service" = %{
if { ![cli_branchpt_start 700 1194] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-mode" 0 "ipv4"] } {
		return 1
	}
	return 0
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-mode" 0 "ipv4"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-mode" 0 "ipv6"] } {
		return 1
	}
	return 0
}
	%}
	"system sdwan service {internet-service-custom internet-service-name internet-service-custom-group internet-service-group}" = %{
if { ![cli_branchpt_start 700 1194] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-mode" 0 "ipv4"] } {
		return 1
	}
	return 0
} else {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] } {
		return 1
	}
	return 0
}
	%}
	"system sdwan service {internet-service-id internet-service-app-ctrl internet-service-app-ctrl-group}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-mode" 0 "ipv4"]
	%}
	"system sdwan service {protocol start-port end-port}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "disable"]
	%}
	"system sdwan service {src dscp-forward dscp-reverse}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-mode" 0 "ipv4"]
	%}
	"system sdwan service {dscp-forward-tag}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-mode" 0 "ipv4"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dscp-forward" 0 "enable"]
	%}
	"system sdwan service {dscp-reverse-tag}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-mode" 0 "ipv4"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dscp-reverse" 0 "enable"]
	%}
	"system sdwan service src6" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-mode" 0 "ipv6"]
	%}
	"system sdwan service {dst dst-negate}" = %{
set tag [cli_get_value $CLI_CUR_PARENT_NODE "" "" "route-tag"]
if { $tag ne "" && $tag ne 0 } {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-mode" 0 "ipv4"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "disable"]
	%}
	"system sdwan service route-tag" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "disable"]
	%}
	"system sdwan service dst6" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "addr-mode" 0 "ipv6"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "disable"]
	%}
	"system sdwan service minimum-sla-meet-members" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sla"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "load-balance"]
	%}
	"system sdwan service sla-compare-method" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sla"]
	%}
	"system sdwan service tie-break" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sla"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "manual"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "priority"]
	%}
	"system sdwan service hash-mode" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "load-balance"]
	%}
	"system sdwan service {hold-down-time use-shortcut-sla}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "manual"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "priority"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sla"]
	%}
	"system sdwan service gateway" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "auto"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "manual"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "priority"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sla"]
	%}
	"system sdwan neighbor-hold-down-time" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "neighbor-hold-down" 0 "disable"]
	%}
	"system sdwan neighbor {role health-check sla-id}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode" 0 "sla"]
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
    [cli_is_match $CLI_GLOBAL_NODE 0 "system fortiguard" "sandbox-region" 1 ""] } {
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
	"wireless-controller wtp-profile allowaccess" = %{
return 1
	%}
	"firewall ldb-monitor type" = %{
return 1
	%}
	"firewall shaping-policy {internet-service internet-service-src}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"]
	%}
	"firewall shaping-policy service" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "disable"]
	%}
	"firewall shaping-policy srcaddr" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service-src" 0 "disable"]
	%}
	"firewall shaping-policy dstaddr" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "disable"]
	%}
	"firewall shaping-policy {srcaddr6 dstaddr6}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "6"]
	%}
	"firewall shaping-policy {internet-service-src-id internet-service-src-custom internet-service-src-group internet-service-src-custom-group}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "4"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service-src" 0 "enable"]
	%}
	"firewall shaping-policy dstintf" = %{
return 1
	%}
	"system sdwan health-check server" = %{
if { $CLI_GLOBAL_DEV } {
	set dynserver [cli_get_value $CLI_CUR_PARENT_NODE "" "" "_dynamic-server"]
	if { $dynserver ne 0 && $dynserver ne "" } {
		return 0
	}
}
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "detect-mode" 0 "passive"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "detect-mode" 0 "remote"]} {
	return 0
}
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "dns"]} {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "system-dns" 0 "disable"]
} else {
	return 1
}
	%}
	"application internet-service-custom disable-entry" = %{
set id [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "master-service-id"]
if { $id eq "" } {
	return 0
}
return 1
	%}
	"system sdwan health-check protocol" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "detect-mode" 1 "passive"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "detect-mode" 1 "remote"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "system-dns" 0 "disable"]
	%}
	"system sdwan health-check {failtime recoverytime}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "detect-mode" 1 "passive"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "detect-mode" 1 "remote"]
	%}
	"system sdwan health-check {update-cascade-interface update-static-route source diffservcode vrf}" = %{
if { [cli_branchpt_start 700 1220] } {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "detect-mode" 1 "passive"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "detect-mode" 1 "remote"]
} else {
	return 1
}
	%}
	"system sdwan health-check port" = %{
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "detect-mode" 0 "passive"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "detect-mode" 0 "remote"]} {
	return 0
}
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "dns"]} {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "system-dns" 0 "disable"]
} else {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "http"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "twamp"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "tcp-connect"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "ftp"]
}
	%}
	"system sdwan health-check system-dns" = %{
if {[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "detect-mode" 0 "passive"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "detect-mode" 0 "remote"]} {
	return 0
}
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "dns"]
	%}
	"system sdwan health-check {http-get http-match}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "http"]
	%}
	"system sdwan health-check {security-mode packet-size}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "twamp"]
	%}
	"system sdwan health-check password" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "twamp"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-mode" 0 "authentication"]
	%}
	"system sdwan members {spillover-threshold ingress-spillover-threshold}" = %{
if { $CLI_GLOBAL_DEV } {
	return 1
}
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system sdwan" "load-balance-mode" 0 "usage-based"]
	%}
	"system sdwan members volume-ratio" = %{
if { $CLI_GLOBAL_DEV } {
	return 1
}
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system sdwan" "load-balance-mode" 0 "measured-volume-based"]
	%}
	"system sdwan members weight" = %{
if { $CLI_GLOBAL_DEV } {
	return 1
}
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system sdwan" "load-balance-mode" 0 "weight-based"]
	%}
	"emailfilter profile {options flow-based spam-log extended-utm-log spam-filtering spam-bword-threshold spam-bword-table spam-bwl-table spam-mheader-table spam-iptrust-table replacemsg-group}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "external" 1 "enable"]
	%}
	"emailfilter profile spam-rbl-table" = %{
if { [cli_branchpt_start 700 1225] } {
	set feature_set [cli_get_value $CLI_CUR_PARENT_NODE "" "" "feature-set"]
	if { $feature_set eq "flow" } {
		return 0
	}
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "external" 0 "enable"] } {
	return 0
}
return 1
	%}
	"emailfilter profile {imap pop3 smtp msn-hotmail yahoo-mail gmail}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "external" 1 "enable"]
	%}
	"emailfilter profile mapi" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "external" 0 "enable"] ||
	[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "feature-set" 0 "flow"] } {
	return 0
}
return 1
	%}
	"endpoint-control profile forticlient-winmac-settings {av-realtime-protection av-signature-up-to-date sandbox-analysis sandbox-address}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-av" 0 "enable"]
	%}
	"firewall ssl-ssh-profile ssl untrusted-cert" = %{
set ssl [cli_get_node [cli_get_parent $CLI_CUR_PARENT_NODE] "ssl" "" ""]
if { $ssl eq 0 } {
	set ins [cli_get_defvalue "firewall ssl-ssh-profile ssl" "inspect-all"]
} else {
	set ins [cli_get_value $ssl "" "" "inspect-all"]
}
if { $ins eq "disable" } {
	return 0
}
if { $ins ne "deep-inspection" } {
	return 0
}
return 1
	%}
	"firewall policy {action scan-botnet-connections}" = %{
namespace import global::cmf_firewall_policy_learn_enabled
if { [cmf_firewall_policy_learn_enabled $CLI_CUR_PARENT_NODE] } {
	return 0
}
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
return 1
	%}
	"firewall policy {logtraffic logtraffic-start}" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
namespace import global::cmf_firewall_policy_learn_enabled
if { [cmf_firewall_policy_learn_enabled $CLI_CUR_PARENT_NODE] } {
	return 0
}
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
return 1
	%}
	"vpn ipsec {phase1 phase1-interface} peertype" = %{
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
	"endpoint-control profile forticlient-winmac-settings {forticlient-minimum-software-version forticlient-log-upload}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-system-compliance" 0 "enable"]
	%}
	"endpoint-control profile forticlient-winmac-settings {forticlient-win-ver forticlient-mac-ver forticlient-linux-ver}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-minimum-software-version" 0 "enable"]
	%}
	"endpoint-control profile forticlient-winmac-settings {forticlient-operating-system forticlient-running-app forticlient-registry-entry forticlient-own-file}" = %{
expr [cli_is_match [cli_get_parent $CLI_CUR_PARENT_NODE] 0 "" "forticlient-system-compliance" 0 "enable"]
	%}
	"endpoint-control profile forticlient-winmac-settings {os-av-software-installed}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-system-compliance" 0 "enable"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "forticlient-av" 0 "enable"] } {
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
	"system sdwan fail-alert-interfaces" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fail-detect" 0 "enable"]
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
	"firewall central-snat-map nat-ippool" = %{
if { $CLI_GLOBAL_DEV } {
	return 1
}
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
	"vpn ipsec {phase2 phase2-interface} keepalive" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "auto-negotiate" 1 "enable"]
	%}
	"system settings ssl-ssh-profile" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ngfw-mode" 0 "policy-based"] } {
	return 1
}
return 0
	%}
	"system settings {gui-icap gui-explicit-proxy gui-dlp gui-application-control}" = %{
namespace import global::ngfw_mode_policy
expr ![ngfw_mode_policy]
	%}
	"system settings {gui-webfilter gui-dnsfilter gui-voip-profile gui-waf-profile}" = %{
namespace import global::ngfw_mode_policy
expr ![ngfw_mode_policy]
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
	"firewall internet-service-custom entry port-range" = %{
if { $CLI_GLOBAL_DEV } { return 1 }
if { $CLI_ADOM_DEV } { return 1 }
set proto [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "" "" "protocol"]
if { $proto == 6 || $proto == 17 || $proto == 132 } {
	return 1
}
return 0
	%}
	"firewall proxy-policy {profile-protocol-options ssl-ssh-profile}" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "profile-type" 0 "single"]
}
if { $action eq "deny" } {
	return 0
}
if { $action eq "redirect" } {
	if { $proxy_type eq "explicit-web" || $proxy_type eq "transparent-web" } {
		return 0
	}
	return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "profile-type" 0 "single"]
}
return 1
	%}
	"firewall proxy-policy utm-status" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "accept"] } {
	return 1
}
return 0
	%}
	"firewall proxy-policy {webproxy-forward-server webproxy-profile}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "accept"] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "explicit-web"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "transparent-web"] } {
		return 1
	}
}
return 0
	%}
	"firewall proxy-policy {service service-negate}" = %{
set proxy [cli_get_value $CLI_CUR_PARENT_NODE "" "" "proxy"]
if { $proxy ne "ftp" &&
     $proxy ne "ssh" &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "disable"] } {
	return 1
}
return 0
	%}
	"firewall proxy-policy {dstaddr dstaddr-negate}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "disable"]
	%}
	"firewall proxy-policy transparent" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "explicit-web"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "transparent-web"] ||
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "access-proxy"] } {
	set poolname [cli_get_value $CLI_CUR_PARENT_NODE "" "" "poolname"]
	if { $poolname ne "" } {
		return 0
	}
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "action" 0 "accept"] } {
		return 1
	}
	if { [cli_branchpt_start 700 1125] } {
	     if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "access-proxy"] } {
		return 1
	     }
	}
}
return 0
	%}
	"firewall proxy-policy poolname" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 1 "explicit-web"] &&
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 1 "access-proxy"] } {
	return 0
}
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "transparent" 0 "enable"] } {
	return 0
}
return 1
	%}
	"firewall proxy-policy srcintf" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "transparent-web"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 0 "access-proxy"]
	%}
	"firewall proxy-policy dstintf" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "proxy" 1 "access-proxy"]
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
	"switch-controller qos dot1p-map {priority-0 priority-1 priority-2 priority-3 priority-4 priority-5 priority-6 priority-7}" = %{
return 1
	%}
	"switch-controller qos queue-policy schedule" = %{
return 1
	%}
	"log threat-weight application" = %{
set cate [cli_get_value $CLI_CUR_NODE "" "" "category"]
if { $cate eq "19" || $cate eq "\"19\"" } {
	return 0
}
return 1
	%}
	"router route-map rule set-route-tag" = %{
return 1
	%}
	"router isis summary-address6 prefix6" = %{
return 1
	%}
	"router access-list6 rule prefix6" = %{
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
	"router access-list rule prefix" = %{
return 1
	%}
	"system replacemsg-group icap {buffer header format}" = %{
return 1
	%}
	"status media-status order usage wanopt-mode" = %{
return 1
	%}
	"switch-controller managed-switch static-mac {type vlan mac interface}" = %{
return 1
	%}
	"switch-controller security-policy 802-1X framevid-apply" = %{
return 1
	%}
	"switch-controller qos queue-policy rate-by" = %{
return 1
	%}
	"firewall internet-service-extension comment" = %{
return 1
	%}
	"authentication scheme user-database" = %{
set method [cli_get_value $CLI_CUR_PARENT_NODE "" "" "method"]
if { [lsearch $method "form"] != -1 ||
     [lsearch $method "basic"] != -1 ||
     [lsearch $method "digest"] != -1 ||
     [lsearch $method "ssh-publickey"] != -1 ||
     [lsearch $method "cert"] != -1 ||
     [lsearch $method "saml"] != -1 } {
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
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "protocol" 0 "http"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "web-auth-cookie" 1 "enable"]
	%}
	"system admin gui-dashboard widget fortiview-filters" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fortiview"]
	%}
	"system admin gui-dashboard widget {title fortiview-timeframe}" = %{
if { [cli_get_devinfo "SASE"] eq "yes" } {
	return 1
} else {
	expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fortiview"]
}
	%}
	"system admin gui-dashboard widget {fortiview-type fortiview-sort-by fortiview-visualization}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fortiview"]
	%}
	"system admin gui-dashboard widget {fabric-device fabric-device-widget-name fabric-device-widget-visualization-type}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "fabric-device"]
	%}
	"system admin gui-dashboard widget {interface}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "tr-history"]
	%}
	"vpn ipsec phase1 {fec-send-timeout fec-base fec-codec fec-redundant}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fec-egress" 0 "enable"]
	%}
	"vpn ipsec phase1-interface {fec-send-timeout fec-base fec-codec fec-redundant}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fec-egress" 0 "enable"]
	%}
	"vpn ipsec phase1 {fec-receive-timeout}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fec-ingress" 0 "enable"]
	%}
	"vpn ipsec phase1-interface {fec-receive-timeout}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fec-ingress" 0 "enable"]
	%}
	"firewall proxy-policy {internet-service-name internet-service-custom internet-service-negate internet-service-group internet-service-custom-group}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"]
	%}
	"switch-controller managed-switch stp-instance" = %{
expr [cli_is_match $CLI_CUR_VDOM_NODE 0 "system settings" "opmode" 0 "nat"]
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
	"system automation-trigger event-type security-rating-summary" = %{
return 1
	%}
	"web-proxy explicit" = %{
namespace import global::ngfw_mode_policy
expr ![ngfw_mode_policy]
	%}
# Mantis 819665: dnsfilter profile is visible in firewall profile-group under both NGFW modes
	"firewall profile-group {ssl-ssh-profile application-list voip-profile casi-profile}" = %{
namespace import global::ngfw_mode_policy
expr ![ngfw_mode_policy]
	%}
	"firewall profile-group emailfilter-profile" = %{
namespace import global::ngfw_mode_policy
namespace import global::fw_policy_mms_enabled
if { [ngfw_mode_policy] } {
	return 0
}
if { [fw_policy_mms_enabled $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"firewall proxy-policy {av-profile dlp-sensor ips-sensor}" = %{
namespace import global::fw_policy_utm_profile_type
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
return 1
	%}
	"firewall proxy-policy {webfilter-profile}" = %{
namespace import global::fw_policy_utm_profile_type
namespace import global::ngfw_mode_policy
namespace import global::fw_policy_mms_enabled
set proxy_type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "proxy"]
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
if { $proxy_type eq "ftp" || $proxy_type eq "ssh"} {
	return 0
}
if { [ngfw_mode_policy] || [fw_policy_mms_enabled $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"firewall proxy-policy {application-list dnsfilter-profile voip-profile}" = %{
namespace import global::fw_policy_utm_profile_type
namespace import global::ngfw_mode_policy
set proxy_type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "proxy"]
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
if { [ngfw_mode_policy] } {
	return 0
}
return 1
	%}
	"firewall proxy-policy {emailfilter-profile}" = %{
namespace import global::fw_policy_utm_profile_type
namespace import global::fw_policy_mms_enabled
set proxy_type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "proxy"]
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
if { $proxy_type ne "wanopt" } {
	return 0
}
if { [fw_policy_mms_enabled $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"firewall proxy-policy {icap-profile waf-profile ssh-filter-profile}" = %{
namespace import global::fw_policy_utm_profile_type
namespace import global::ngfw_mode_policy
namespace import global::fw_policy_inspection_flow
namespace import global::fw_policy_mms_enabled
set proxy_type [cli_get_value $CLI_CUR_PARENT_NODE "" "" "proxy"]
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
if { $CLI_CUR_NODE_NAME eq "icap-profile" } {
	if { $proxy_type eq "ssh" || $proxy_type eq "ftp" || $proxy_type eq "wanopt" } {
		return 0
	}
}
if { $CLI_CUR_NODE_NAME eq "waf-profile" } {
	if { $proxy_type eq "ssh" || $proxy_type eq "ftp" || $proxy_type eq "access-proxy"} {
		return 0
	}
}
if { $CLI_CUR_NODE_NAME eq "ssh-filter-profile" } {
	if { $proxy_type ne "explicit-web" &&
     	     $proxy_type ne "transparent-web" &&
     	     $proxy_type ne "ssh" } {
		return 0
	}
}
if { [ngfw_mode_policy] ||
     [fw_policy_inspection_flow $CLI_CUR_PARENT_NODE] ||
     [fw_policy_mms_enabled $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"vpn ipsec {phase1 phase1-interface} network-overlay" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ike-version" 0 "2"]
	%}
	"vpn ipsec {phase1 phase1-interface} network-id" = %{
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
	"firewall {ngfw-policy prematch-policy}" = %{
namespace import global::ngfw_mode_policy
return [ngfw_mode_policy]
	%}
	"vpn ssl web portal bookmark-group bookmarks {listening-port remote-port show-status-window}" = %{
return [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "apptype" 0 "portforward"]
	%}
	"router ospf6 {area ospf6-interface} ipsec-enc-alg" = %{
set auth_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "authentication"]
if { $auth_mode eq "none" || $auth_mode eq "area" } {
	return 0
}
if { $auth_mode eq "esp" } {
	return 1
}
return 0
	%}
	"router ospf6 {area ospf6-interface} ipsec-auth-alg" = %{
set auth_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "authentication"]
if { $auth_mode eq "none" || $auth_mode eq "area" } {
	return 0
}
return 1
	%}
	"router ospf6 area virtual-link ipsec-enc-alg" = %{
set auth_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "authentication"]
if { $auth_mode eq "none" || $auth_mode eq "area" } {
	return 0
}
if { $auth_mode eq "esp" } {
	return 1
}
return 0
	%}
	"router ospf6 area virtual-link ipsec-auth-alg" = %{
set auth_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "authentication"]
if { $auth_mode eq "none" || $auth_mode eq "area" } {
	return 0
}
return 1
	%}
	"system settings {consolidated-firewall-mode central-nat tcp-session-without-syn}" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
return 1
	%}
# Mantis 819665: dnsfilter profile is visible under both NGFW modes
#	"dnsfilter profile" = %{
#namespace import global::ngfw_mode_policy
#if { [ngfw_mode_policy] } {
#	return 0
#}
#return 1
#	%}
	"voip profile" = %{
namespace import global::if_skip_in_global_context_and_ngfw
if { [if_skip_in_global_context_and_ngfw] } {
	return 0
}
return 1
	%}
	"firewall security-policy" = %{
namespace import global::ngfw_mode_policy
return [ngfw_mode_policy]
	%}
	"ftp-proxy explicit" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
return 1
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
	"firewall profile-group {ssh-filter-profile waf-profile icap-profile webfilter-profile}" = %{
namespace import global::ngfw_mode_policy
namespace import global::fw_policy_mms_enabled
if { [ngfw_mode_policy] } {
	return 0
}
if { [fw_policy_mms_enabled $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"firewall policy {emailfilter-profile}" = %{
namespace import global::fw_policy_utm_profile_type
namespace import global::fw_policy_mms_enabled
namespace import global::ngfw_mode_policy
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
if { [ngfw_mode_policy] || [fw_policy_mms_enabled $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
	"firewall proxy-policy mms-profile" = %{
namespace import global::fw_policy_utm_profile_type
namespace import global::ngfw_mode_policy
namespace import global::fw_policy_inspection_flow
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
if { [ngfw_mode_policy] || [fw_policy_inspection_flow $CLI_CUR_PARENT_NODE] } {
	return 0
}
return 1
	%}
# Mantis 819665: dnsfilter profile is visible in firewall security-policy under both NGFW modes
	"firewall security-policy {ssl-ssh-profile application-list voip-profile icap-profile ssh-filter-profile}" = %{
namespace import global::fw_policy_utm_profile_type
namespace import global::ngfw_mode_policy
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
if { [ngfw_mode_policy] } {
		return 0
}
return 1
	%}
	"firewall security-policy webfilter-profile" = %{
namespace import global::fw_policy_utm_profile_type
namespace import global::ngfw_mode_policy
if { [fw_policy_utm_profile_type $CLI_CUR_PARENT_NODE] ne "single" } {
	return 0
}
return 1
	%}
	"firewall security-policy {service service-negate dstaddr}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] } {
	return 0
}
return 1
	%}
	"firewall security-policy srcaddr" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service-src" 0 "enable"] } {
	return 0
}
return 1
	%}
	"firewall security-policy dstaddr6" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service6" 0 "enable"] } {
	return 0
}
if { ![cli_branchpt_start 700 1239] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] ||
     		[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service-src" 0 "enable"] } {
		return 0
	}
}
return 1
	%}
	"firewall security-policy srcaddr6" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service-src6" 0 "enable"] } {
	return 0
}
if { ![cli_branchpt_start 700 1239] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 0 "enable"] ||
     		[cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service-src" 0 "enable"] } {
		return 0
	}
}
return 1
	%}
	"firewall security-policy {utm-status logtraffic action application}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "learning-mode" 0 "enable"] } {
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
	"system geneve {remote-ip}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "ipv4-unicast"]
	%}
	"system geneve {remote-ip6}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ip-version" 0 "ipv6-unicast"]
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
	"firewall ssl-ssh-profile {ssl https ftps imaps pop3s smtps} {untrusted-server-cert expired-server-cert revoked-server-cert cert-validation-timeout cert-validation-failure}" = %{
set server_cert_mode [cli_get_value $CLI_CUR_PARENT_NODE "" "" "server-cert-mode"]
if { $CLI_CUR_PARENT_NAME eq "ssl" } {
	set is_generic_ssl 1
	set curr_settings [cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspect-all"]
	set inspect_all_setting [cli_get_value $CLI_CUR_PARENT_NODE "" "" "inspect-all"]
} else {
	set is_generic_ssl 0
	set curr_settings [cli_get_value $CLI_CUR_PARENT_NODE "" "" "status"]
	set inspect_all_setting [cli_get_value [cli_get_parent $CLI_CUR_PARENT_NODE] "ssl" "" "inspect-all"]
}
if { $server_cert_mode eq "replace" } {
	return 0
}
if { $is_generic_ssl == 1 && $inspect_all_setting eq "disable" } {
	return 0
}
if { $is_generic_ssl != 1 && $inspect_all_setting ne "disable" } {
	return 0
}
return 1
	%}
	"vpn ocvpn ip-allocation-block" = %{
set multipath [cli_get_value $CLI_CUR_PARENT_NODE "" "" "multipath"]
set role [cli_get_value $CLI_CUR_PARENT_NODE "" "" "role"]
if { $multipath ne "enable" } {
	return 0
}
if { $role ne "primary-hub" && $role ne "secondary-hub" } {
	return 0
}
return 1
	%}
	"switch-controller initial-config template auto-ip" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dhcp-server" 0 "enable"]
	%}
	"system fortiguard {fortiguard-anycast-source anycast-sdns-server-ip anycast-sdns-server-port}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fortiguard-anycast" 0 "enable"]
	%}
	"system fortiguard {sdns-server-ip sdns-server-port}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "fortiguard-anycast" 1 "enable"]
	%}
	"firewall policy block-notification" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
return 1
	%}
	"wireless-controller mpsk-profile ssid" = %{
return 0
	%}
	"wireless-controller mpsk-profile mpsk-group mpsk-key pmk" = %{
return 0
	%}
	"switch-controller security-policy 802-1X {authserver-timeout-vlan}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-mode" 0 "802.1X"] || [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-mode" 0 "802.1X-mac-based"]
	%}
	"switch-controller security-policy 802-1X {authserver-timeout-period authserver-timeout-vlanid}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "authserver-timeout-vlan" 0 "enable"] } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-mode" 0 "802.1X"] || 
	     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "security-mode" 0 "802.1X-mac-based"] } {
		return 1
	}
}
return 0
	%}
	"vpn ipsec {phase2 phase2-interface} initiator-ts-narrow" = %{
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
	"antivirus profile scan-mode" = %{
namespace import global::ngfw_mode_policy
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "feature-set" 0 "flow"] ||
     [ngfw_mode_policy] } {
	return 0
}
return 1
	%}
    "firewall policy decrypted-traffic-mirror" = %{
namespace import global::ngfw_mode_policy
namespace import global::deep_inspection_check
if { [ngfw_mode_policy] } {
	return 0
}
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
	"firewall policy passive-wan-health-measurement" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 1
}

set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action ne "deny" } {
	return 1
}

return 0
	%}
	"webfilter profile {web-filter-activex-log web-filter-applet-log web-filter-jscript-log web-filter-js-log web-filter-vbs-log web-filter-unknown-log web-filter-referer-log web-filter-cookie-removal-log web-ftgd-quota-usage web-antiphishing-log}" = %{
namespace import global::ngfw_mode_policy
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "feature-set" 0 "flow"] ||
     [ngfw_mode_policy] } {
	return 0
}
return 1
	%}
	"{emailfilter antivirus file-filter webfilter} profile feature-set" = %{
namespace import global::ngfw_mode_policy
return [expr ![ngfw_mode_policy]]
	%}
	"dlp sensor feature-set" = %{
namespace import global::ngfw_mode_policy
return [expr ![ngfw_mode_policy]]
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
	"vpn ipsec phase1 {auto-negotiate}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "dynamic"]]
	%}
	"vpn ipsec phase1 add-route" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "ddns"]]
	%}
	"vpn ipsec phase1 {mesh-selector-type}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "static"]]
	%}
	"vpn ipsec phase1 {dns-mode ipv4-split-include split-include-service ipv6-split-include unity-support domain banner include-local-lan ipv4-split-exclude ipv6-split-exclude client-auto-negotiate client-keep-alive backup-gateway}" = %{
if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 1 "dynamic"] || 
     [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 1 "enable"] } {
	return 0
}
return 1
	%}
	"vpn ipsec {phase1 phase1-interface} {ip-delay-interval}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "unity-support" 0 "enable" "type" 0 "dynamic"]]
	%}
	"vpn ipsec phase1 {ipv4-dns-server1 ipv4-dns-server2 ipv4-dns-server3 ipv6-dns-server1 ipv6-dns-server2 ipv6-dns-server3}" = %{
return [expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "mode-cfg" 0 "enable" "unity-support" 0 "enable" "type" 0 "dynamic" "dns-mode" 0 "manual"]]
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
	"wireless-controller vap fast-bss-transition" = %{
namespace import global::is_wlan_fast_bss_trans_skip
if { ![is_wlan_fast_bss_trans_skip $CLI_CUR_PARENT_NODE] } {
	return 1
}
return 0
	%}
	"wireless-controller vap {ft-over-ds ft-mobility-domain ft-r0-key-lifetime}" = %{
namespace import global::is_wlan_fast_bss_trans_skip
set fast_bss_trans [cli_get_value $CLI_CUR_PARENT_NODE "" "" "fast-bss-transition"]
if { ![is_wlan_fast_bss_trans_skip $CLI_CUR_PARENT_NODE] && $fast_bss_trans eq "enable" } {
	return 1
}
return 0
	%}
	"system interface {pvc-chan pvc-vlan-id pvc-vlan-tx-id pvc-vlan-rx-id pvc-vlan-tx-op pvc-vlan-rx-op pvc-crc pvc-atm-qos pvc-pcr pvc-scr}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sfp-dsl" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "sfp-dsl-adsl-fallback" 0 "enable"]
	%}
	"firewall hyperscale-policy" = %{
if { $CLI_GLOBAL_DEV } {
	return 1
}
namespace import global::is_platform_support_hyperscale
if { [is_platform_support_hyperscale] } {
	if { [cli_get_devinfo "hyperscale"] eq "yes" } {
		return 1
	}
}
return 0
	%}
	"firewall hyperscale-policy nat" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	return 1
}
return 0
	%}
	"firewall hyperscale-policy {ippool cgn-session-quota cgn-resource-quota cgn-eif cgn-eim}" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "enable"] } {
		return 1
	}
}
return 0
	%}
	"firewall hyperscale-policy poolname" = %{
set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
if { $action eq "accept" } {
	if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "nat" 0 "enable"] } {
		if { [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "ippool" 0 "disable"] } {
			return 0
		}
		return 1
	}
}
return 0
	%}
	"firewall hyperscale-policy46" = %{
if { $CLI_GLOBAL_DEV } {
	return 1
}
namespace import global::is_platform_support_hyperscale
if { [is_platform_support_hyperscale] } {
	if { [cli_get_devinfo "hyperscale"] eq "yes" } {
		return 1
	}
}
return 0
	%}
	"firewall hyperscale-policy6" = %{
if { $CLI_GLOBAL_DEV } {
	return 1
}
namespace import global::is_platform_support_hyperscale
if { [is_platform_support_hyperscale] } {
	if { [cli_get_devinfo "hyperscale"] eq "yes" } {
		return 1
	}
}
return 0
	%}
	"firewall hyperscale-policy64" = %{
if { $CLI_GLOBAL_DEV } {
	return 1
}
namespace import global::is_platform_support_hyperscale
if { [is_platform_support_hyperscale] } {
	if { [cli_get_devinfo "hyperscale"] eq "yes" } {
		return 1
	}
}
return 0
	%}
	"dlp profile feature-set" = %{
namespace import global::ngfw_mode_policy
if { [ngfw_mode_policy] } {
	return 0
}
return 1
	%}
	"dlp profile extended-log" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "dlp-log" 0 "enable"]
	%}
	"dlp profile rule {file-type file-size}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "type" 0 "file"]
	%}
	"dlp profile rule sensitivity" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "fingerprint"]
	%}
	"dlp profile rule match-percentage" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "fingerprint"]
	%}
	"dlp profile rule sensor" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "sensor"]
	%}
	"dlp profile rule label" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "filter-by" 0 "mip"]
	%}
	"dlp profile rule archive" = %{
set prof_node [cli_get_parent [cli_get_parent $CLI_CUR_PARENT_NODE]]
set full_archive_proto [cli_get_value $prof_node "" "" "full-archive-proto"]
set rule_proto [cli_get_value $CLI_CUR_PARENT_NODE "" "" "proto"]
set sorted_full_list [lsort [split $full_archive_proto " "]]
set sorted_rule_list [lsort [split $rule_proto " "]]
foreach proto $sorted_rule_list {
	if { [lsearch -inline $sorted_full_list $proto] eq "" } {
		return 1
	}
}
return 0
	%}
	"user nac-policy {mac hw-vendor type family os hw-version sw-version host user src}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "category" 0 "device"]
	%}
	"user nac-policy user-group" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "category" 0 "firewall-user"]
	%}
	"user nac-policy ems-tag" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "category" 0 "ems-tag"]
	%}
	"switch-controller fortilink-settings nac-ports {nac-lan-interface nac-segment-vlans}" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "lan-segment" 0 "enabled"]
	%}
	"firewall policy { diffserv-forward diffserv-reverse}" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
set diffcpy [cli_get_value $CLI_CUR_PARENT_NODE "" "" "diffserv-copy"]
if { $diffcpy eq "enable" } {
	return 0
}
return 1
	%}
	"emailfilter profile spam-log-fortiguard-response" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "spam-log" 0 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "feature-set" 1 "flow"]
	%}
	"firewall security-policy enforce-default-app-port" = %{
expr [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service" 1 "enable"] && [cli_is_match $CLI_CUR_PARENT_NODE 0 "" "internet-service6" 1 "enable"]
	%}
	"firewall policy { diffserv-copy }" = %{
namespace import global::is_platform_support_hyperscale
if { [cli_branchpt_start 700 1226] } {
	if { [is_platform_support_hyperscale] } {
		if { [cli_get_devinfo "hyperscale"] eq "yes" } {
			return 0
		}
	}
	set action [cli_get_value $CLI_CUR_PARENT_NODE "" "" "action"]
	if { $action ne "ipsec" } {
		return 0
	}
}
return 1
	%}
	"firewall policy {reputation-direction6 reputation-minimum reputation-minimum6}" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
return 1
	%}
	"firewall policy { src-vendor-mac schedule-timeout tos tos-mask anti-replay tcp-session-without-syn geoip-anycast geoip-match dynamic-shaping app-group vlan-cos-fwd vlan-cos-rev fec fsso-groups email-collect match-vip-only tcp-mss-sender tcp-mss-receiver gtp-profile pfcp-profile network-service-dynamic network-service-src-dynamic dsri radius-mac-auth-bypass delay-tcp-npu-session vlan-filter sgt-check sgt policy-expiry }" = %{
namespace import global::is_hyperscale_activated
if { [cli_branchpt_start 700 1226] && [is_hyperscale_activated] } {
	return 0
}
return 1
	%}
%};
