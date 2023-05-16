deleteact %{
	"ips custom" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""] 
set customnode [cli_get_node $CLI_GLOBAL_NODE "ips group" "custom" ""]
set delnode [cli_get_node $customnode "" "rule" $name]
expr [cli_delete_node $delnode]
return 1
	%}

	"vpn ssl web bookmarks" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
if {$name ne ""} {
	set match_list [cli_get_match_list $CLI_CUR_VDOM_NODE 1 "vpn ssl web bookmarks-group" "bookmarks" 0 '*"$name"*']
	foreach e $match_list {
		set bookmarks [cli_get_value $e "" "" "bookmarks"]
		regsub "\"$name\"" $bookmarks {} bookmarks
		set grpname [cli_get_value $e "" "" "name"]
		cli_exec_cmd $CLI_CUR_VDOM_NODE "config vpn ssl web bookmarks-group\nedit $grpname\nset bookmarks $bookmarks\nend\n"
	}
}
return 1
	%}

	"system gre-tunnel" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" "name"]
set intfnode [cli_get_node $CLI_GLOBAL_NODE "system interface" $name ""]
if {[cli_is_referenced $intfnode]} {
	cli_set_errmsg "interface is being used"
	return 0
}
if {$intfnode} {
	cli_delete_node $intfnode
}
return 1
	%}
%};
