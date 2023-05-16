deletecheck %{
	"log npu-server server-info" = %{
set server_group_sz [cli_get_tbl_size "log npu-server server-group"]
if { $server_group_sz > 0 } {
	cli_set_errmsg "There are server_group, maybe refer to this server, so first delete the all server_group then can delete the server_info."
	return 0
}
return 1
	%}
	"dynamic interface" = %{
set intf_name [cli_get_value $CLI_CUR_NODE "" "" ""]
set intf_name [string trim $intf_name \"]
if { $intf_name eq "virtual-wan-link" } {
	cli_set_errmsg "\"virtual-wan-link\" is reserved and cannot be deleted"
	return 0
}
return 1
	%}
%};
