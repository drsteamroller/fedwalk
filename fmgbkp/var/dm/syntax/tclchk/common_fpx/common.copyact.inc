copyact %{
        "webfilter profile" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set wos [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "webfilter override" "old-profile" 0 "\"$name\""]
foreach wo $wos {
	set n [cli_get_value $wo "" "" "new-profile"]
	if { [cli_switch] } {
		set node [cli_get_node $CLI_SRC_VDOM_NODE "webfilter profile" $n ""]
		if { $node && [cli_copy_src_node $node] } {
			cli_set_errmsg "copy source webfilter profile $n failed."
			return 0
		}
		cli_switch_end
	}
}
return 1
        %}
	"dlp filepattern entries" = %{
if { [string match "*adom*" [cli_get_clisrc]] } {
	if { [cli_get_value $CLI_CUR_NODE "" "" "file-type"] eq "hibun" } {
		if { [cli_is_match $CLI_GLOBAL_NODE 0 "system global" "special-file-23-support" 1 "enable"] } {
			cli_exec_cmd $CLI_GLOBAL_NODE "config system global\nset special-file-23-support enable\nend\n"
		}
	}
}
return 1
	%}
%};
