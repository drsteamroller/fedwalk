copyact %{
        "dlp filepattern entries" = %{
if {[string match "*adom*" [cli_get_clisrc]]} {
        if { [cli_get_value $CLI_CUR_NODE "" "" "file-type"] eq "hibun" } {
                if { [cli_is_match $CLI_GLOBAL_NODE 0 "system global" "special-file-23-support" 1 "enable"] } {
                        cli_exec_cmd $CLI_GLOBAL_NODE "config system global\nset special-file-23-support enable\nend\n"
                }
        }
}
return 1
        %}
%};