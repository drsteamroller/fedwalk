nodeact %{
	"user fsso-polling" = %{
set fsso [cli_get_node $CLI_CUR_VDOM_NODE "user fsso" "Local FSSO Agent" ""]
if { $fsso == 0 } {
	set server [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]
	cli_exec_cmd $CLI_CUR_VDOM_NODE "config user fsso\nedit \"Local FSSO Agent\"\nset ldap-server $server\nset server \"127.0.0.1\"\nnext\nend\n"
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
return 1
	%}
        "firewall policy" = %{
set action [cli_get_value $CLI_CUR_NODE "" "" "action"]
set hascmd 0
set cmd ""
if { $action eq "deny" } {
    set hascmd 1
    if { [cli_get_value $CLI_CUR_NODE "" "" "utm-status"] eq "enable" } {
        append cmd "unset utm-status\n"
    }
    if {[cli_get_value $CLI_CUR_NODE "" "" "poolname"] ne ""} {
        append cmd "unset poolname\n"
    }
}
if { $hascmd } {
    cli_exec_cmd $CLI_CUR_NODE $cmd
}
return 1
        %}
        "system geoip-override" = %{
if { [cli_get_value $CLI_CUR_NODE "" "" "country-id"] eq "" } {
        set id [cli_gen_geoip_country_id]
        if { $id ne 0 } {
                set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
                cli_exec_cmd $CLI_GLOBAL_NODE "config system geoip-override\nedit $name\nset country-id $id\nnext\nend\n"
        }
}
return 1
        %}
%};
