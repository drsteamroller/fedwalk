deleteact %{
	"user fsso-polling" = %{
set fsso [cli_get_node $CLI_CUR_VDOM_NODE "user fsso" "Local FSSO Agent" ""]
if { $fsso != 0 } {
	set id [cli_get_value $CLI_CUR_NODE "" "" "id"]
	if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "id" 1 $id] == 0} {
		set list [cli_get_tbl_list $CLI_CUR_PARENT_NODE "user adgrp"]
		foreach node $list {
			set svrname [cli_get_value $node "" "" "server-name"]
			set svrname [string trim $svrname \"]
			if { $svrname eq "Local FSSO Agent" } {
				cli_delete_node $node 1
			}
		}
	}
}
return 1

# disable this block of code due to potential bug on FOS
set fsso [cli_get_node $CLI_CUR_VDOM_NODE "user fsso" "Local FSSO Agent" ""]
if { $fsso != 0 } {
	set fssoldap [cli_get_value $fsso "" "" "ldap-server"]
	set curldap [cli_get_value $CLI_CUR_NODE "" "" "ldap-server"]
	set curid [cli_get_value $CLI_CUR_NODE "" "" "id"]
	set curstatus [cli_get_value $CLI_CUR_NODE "" "" "status"]

	# filter out the node being deleted
	if { $curstatus eq "enable" } {
		set num 1
	} else {
		set num 0
	}

	# check if there's still active fsso-polling object
	if {[cli_get_match_nr $CLI_CUR_PARENT_NODE 1 "" "status" 0 "enable"] == $num } {
		cli_delete_node $fsso
	} elseif { $curldap eq $fssoldap }  {
		# select another node for the new new local fsso agent
		set list [cli_get_tbl_list $CLI_CUR_PARENT_NODE ""]
		foreach node $list {
			set status [cli_get_value $node "" "" "status"]
			set server [cli_get_value $node "" "" "ldap-server"]
			set id [cli_get_value $node "" "" "id"]
			if { $server == 0 || $curid == $id || $status ne "enable" } {
				continue
			}

			cli_exec_cmd $CLI_CUR_VDOM_NODE "config user fsso\nedit \"Local FSSO Agent\"\nset ldap-server $server\nset server \"127.0.0.1\"\nnext\nend\n"
			break
		}
	}
}
return 1
	%}

	"system interface" = %{
set name [cli_get_value $CLI_CUR_NODE "" "" ""]
set dev_intfnode [cli_get_node $CLI_CUR_VDOM_NODE "device dynamic interface" $name ""]
	if { $dev_intfnode } {
		cli_delete_node $dev_intfnode
	}
return 1
	%}

