namespace Dorothy.HostHelper

open System
open System.IO
open System.Text.Json

module Fail2BanNative =
    type BackendError(message: string) =
        inherit InvalidOperationException(message)

    type Configuration =
        {
            Socket: string
            PidFile: string
            Fingerprint: string
            StartupFingerprint: string
            EnabledJails: string list
        }

    type Runtime =
        {
            ActiveJails: string list
            InSync: bool
        }

    let private pythonBridge =
        """
import contextlib
import hashlib
import io
import json
import os
import sys
def _normalize_root(value, root):
    source = os.path.normpath(root)
    if source == os.path.sep:
        return value

    def _replace(text):
        result = []
        cursor = 0
        while True:
            start = text.find(source, cursor)
            if start < 0:
                result.append(text[cursor:])
                break
            end = start + len(source)
            before_is_boundary = start == 0 or not (
                text[start - 1].isalnum() or text[start - 1] in "_.-"
            )
            after_is_boundary = end == len(text) or text[end] in (
                "/", "\\", " ", "\t", "\r", "\n", "'", '"', "=", ":", ",", ";", ")", "]", "}", ">"
            )
            if before_is_boundary and after_is_boundary:
                result.append(text[cursor:start])
                result.append("/etc/fail2ban")
                cursor = end
            else:
                result.append(text[cursor:end])
                cursor = end
        return "".join(result)

    if isinstance(value, str):
        return _replace(value)
    if isinstance(value, dict):
        return {_normalize_root(key, root): _normalize_root(item, root) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_root(item, root) for item in value]
    return value

_output = sys.stdout
_request = json.load(sys.stdin)


def _emit(value, status=0):
    _output.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
    _output.flush()
    raise SystemExit(status)


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _hash(value):
    return hashlib.sha256(_canonical(value)).hexdigest()

def _python_action_sources(root):
    directory = os.path.join(root, "action.d")
    sources = []
    try:
        for entry in os.scandir(directory):
            if entry.name.endswith(".py") and entry.is_file():
                with open(entry.path, "rb") as source:
                    sources.append([entry.name, hashlib.sha256(source.read()).hexdigest()])
    except FileNotFoundError:
        pass
    return sorted(sources)


def _read_config(root):
    from fail2ban.client.configurator import Configurator

    configurator = Configurator()
    configurator.Reload()
    configurator.setBaseDir(root)
    configurator.readAll()
    if not configurator.getOptions():
        raise ValueError()
    configurator.convertToProtocol(allow_no_files=False)
    early = configurator.getEarlyOptions()
    stream = configurator.getConfigStream()
    normalized_early = _normalize_root(early, root)
    normalized_stream = _normalize_root(stream, root)

    startup_keys = {"thread", "syslogsocket", "loglevel", "logtarget", "allowipv6", "dbfile"}
    startup_commands = [
        command for command in normalized_stream
        if isinstance(command, (list, tuple))
        and command[0] == "set"
        and (
            (len(command) == 3 and command[1] in startup_keys)
            or (len(command) >= 4 and command[1] == "thread" and command[2] == "stacksize")
        )
    ]
    python_action_sources = _python_action_sources(root)
    startup = {
        "socket": normalized_early.get("socket"),
        "pidfile": normalized_early.get("pidfile"),
        "loglevel": normalized_early.get("loglevel"),
        "logtarget": normalized_early.get("logtarget"),
        "syslogsocket": normalized_early.get("syslogsocket"),
        "commands": startup_commands,
    }
    enabled_jails = sorted({
        command[1] for command in stream
        if isinstance(command, (list, tuple))
        and len(command) >= 2
        and command[0] == "start"
        and isinstance(command[1], str)
    })
    return early, stream, _hash({"early": normalized_early, "stream": normalized_stream, "pythonActionSources": python_action_sources}), _hash(startup), enabled_jails


def _as_list(value):
    if isinstance(value, (list, tuple)):
        return list(value)
    if value is None:
        return []
    return [value]


def _collect_expected(stream):
    global_values = {}
    jail_values = {}
    jail_lists = {}
    action_names = {}
    action_values = {}

    def _append(target, key, value):
        target.setdefault(key, []).extend(_as_list(value))

    for command in stream:
        if not isinstance(command, (list, tuple)) or not command:
            continue
        name = command[0]
        if name == "set" and len(command) == 3 and command[1] in {
            "loglevel", "logtarget", "syslogsocket", "dbfile", "dbmaxmatches", "dbpurgeage"
        }:
            global_values[command[1]] = command[2]
            continue
        if name == "set" and len(command) >= 4 and isinstance(command[1], str):
            jail = command[1]
            option = command[2]
            if option == "addaction" and len(command) >= 4:
                action_names.setdefault(jail, set()).add(command[3])
            elif option == "action" and len(command) >= 6:
                action_values.setdefault((jail, command[3]), {})[command[4]] = command[5]
            elif option in ("addignoreip", "addfailregex", "addignoreregex"):
                list_name = {
                    "addignoreip": "ignoreip",
                    "addfailregex": "failregex",
                    "addignoreregex": "ignoreregex",
                }[option]
                _append(jail_lists, (jail, list_name), command[3:])
            elif option == "addlogpath" and len(command) >= 5:
                _append(jail_lists, (jail, "logpath"), command[3])
            elif option not in ("addjournalmatch", "addlogpath"):
                jail_values[(jail, option)] = command[3]
            continue
        if name == "multi-set" and len(command) >= 4 and isinstance(command[1], str):
            jail = command[1]
            option = command[2]
            if option in ("addfailregex", "addignoreregex"):
                list_name = "failregex" if option == "addfailregex" else "ignoreregex"
                _append(jail_lists, (jail, list_name), command[3])
            elif option == "action" and len(command) >= 5:
                action = command[3]
                properties = command[4]
                values = action_values.setdefault((jail, action), {})
                if isinstance(properties, (list, tuple)):
                    for pair in properties:
                        if isinstance(pair, (list, tuple)) and len(pair) >= 2:
                            values[pair[0]] = pair[1]

    return global_values, jail_values, jail_lists, action_names, action_values


def _native_usedns(value):
    if isinstance(value, bool):
        value = "yes" if value else "no"
    value = str(value).lower()
    return value if value in ("yes", "warn", "no", "raw") else "no"


def _same(expected, actual, key, scope):
    try:
        is_duration = (
            (scope == "global" and key == "dbpurgeage")
            or (scope == "jail" and key in ("findtime", "bantime", "bantime.maxtime", "bantime.rndtime"))
            or (scope == "action" and key == "timeout")
        )
        if is_duration:
            from fail2ban.helpers import MyTime
            if expected is not None and isinstance(expected, str):
                expected = MyTime.str2seconds(expected)
            if actual is not None and isinstance(actual, str):
                actual = MyTime.str2seconds(actual)
            return expected == actual
        if (scope == "global" and key == "dbmaxmatches") or (
            scope == "jail" and key in ("maxretry", "maxmatches", "maxlines")
        ):
            if isinstance(expected, str):
                expected = int(expected)
            if isinstance(actual, str):
                actual = int(actual)
            return expected == actual
        if scope == "global" and key == "dbfile":
            if isinstance(expected, str) and expected.lower() == "none":
                expected = None
            if isinstance(actual, str) and actual.lower() == "none":
                actual = None
            return expected == actual
        if scope == "jail" and key == "usedns":
            return _native_usedns(expected) == _native_usedns(actual)
        if scope == "jail" and key == "logencoding":
            if not isinstance(expected, str) or expected.lower() == "auto":
                return None
            if not isinstance(actual, str):
                return None
            import codecs
            try:
                return codecs.lookup(expected).name == codecs.lookup(actual).name
            except LookupError:
                return None
        if scope == "jail" and key == "ignoreip":
            from fail2ban.server.ipdns import IPAddr

            def as_ip(value):
                return value if isinstance(value, IPAddr) else IPAddr(value)

            return {as_ip(item) for item in _as_list(expected)} == {
                as_ip(item) for item in _as_list(actual)
            }
        if scope == "jail" and key == "logpath":
            return sorted(str(item) for item in _as_list(expected)) == sorted(str(item) for item in _as_list(actual))
        if isinstance(expected, bool) or isinstance(actual, bool):
            def as_bool(value):
                if isinstance(value, bool):
                    return value
                if isinstance(value, int) and value in (0, 1):
                    return bool(value)
                if isinstance(value, str):
                    normalized = value.strip().lower()
                    if normalized in ("true", "yes", "on", "1"):
                        return True
                    if normalized in ("false", "no", "off", "0"):
                        return False
                return None

            expected_bool = as_bool(expected)
            actual_bool = as_bool(actual)
            if expected_bool is None or actual_bool is None:
                return None
            return expected_bool == actual_bool
        return _canonical(expected) == _canonical(actual)
    except Exception:
        return None


def _native_regexes(values, key, jail_values, jail):
    from fail2ban.server.failregex import FailRegex, Regex

    use_dns = _native_usedns(jail_values.get((jail, "usedns"), "yes"))
    prefregex_value = jail_values.get((jail, "prefregex"))
    prefregex = Regex(prefregex_value, useDns=use_dns) if prefregex_value else None
    try:
        maxlines = int(jail_values.get((jail, "maxlines"), 1))
    except (TypeError, ValueError):
        maxlines = 1
    multiline = maxlines > 1

    if key == "failregex":
        return [
            FailRegex(value, prefRegex=prefregex, multiline=multiline, useDns=use_dns).getRegex()
            for value in values
        ]
    return [Regex(value, useDns=use_dns).getRegex() for value in values]


def _native_prefregex(value, jail_values, jail):
    from fail2ban.server.failregex import Regex

    use_dns = _native_usedns(jail_values.get((jail, "usedns"), "yes"))
    return Regex(value, useDns=use_dns).getRegex()


def _native_datepattern(value, timezone):
    from fail2ban.server.filter import DateDetector

    if value is None:
        return None
    detector = DateDetector()
    detector.default_tz = timezone
    if not isinstance(value, (list, tuple)):
        import re
        value = [pattern.strip() for pattern in re.split("\\n+", str(value)) if pattern.strip()]
    for pattern in value:
        detector.appendTemplate(pattern)
    templates = detector.templates
    if not templates or len(templates) > 2:
        return None, "Default Detectors"
    template = templates[0]
    return getattr(template, "pattern", None), template.name


def _observe(root, configuration):
    socket_path = configuration.get("socket")
    expected_fingerprint = configuration.get("fingerprint")
    expected_startup_fingerprint = configuration.get("startupFingerprint")
    early, stream, fingerprint, startup_fingerprint, expected_jails = _read_config(root)
    in_sync = fingerprint == expected_fingerprint and startup_fingerprint == expected_startup_fingerprint
    active_jails = []

    if not socket_path:
        return {"fingerprint": fingerprint, "startupFingerprint": startup_fingerprint,
                "activeJails": active_jails, "inSync": False}

    client = None
    try:
        from fail2ban.client.csocket import CSocket
        client = CSocket(socket_path, timeout=5)
        status = client.send(["status"])
        if not isinstance(status, (list, tuple)) or len(status) < 2 or status[0] != 0:
            return {"fingerprint": fingerprint, "startupFingerprint": startup_fingerprint,
                    "activeJails": active_jails, "inSync": False}
        for item in status[1] if isinstance(status[1], (list, tuple)) else []:
            if isinstance(item, (list, tuple)) and len(item) >= 2 and item[0] == "Jail list":
                names = item[1]
                if isinstance(names, str) and names.strip():
                    active_jails = sorted(name.strip() for name in names.split(",") if name.strip())
                break
    except Exception:
        return {"fingerprint": fingerprint, "startupFingerprint": startup_fingerprint,
                "activeJails": active_jails, "inSync": False}

    expected_jails = sorted(expected_jails)
    if active_jails != expected_jails:
        in_sync = False

    global_values, jail_values, jail_lists, action_names, action_values = _collect_expected(stream)

    query_failed = False

    def _query(command):
        nonlocal in_sync, query_failed
        if query_failed:
            return False, None
        try:
            response = client.send(command)
        except Exception:
            in_sync = False
            query_failed = True
            return False, None
        if not isinstance(response, (list, tuple)) or len(response) < 2 or type(response[0]) is not int:
            in_sync = False
            query_failed = True
            return False, None
        if response[0] == 0:
            return True, response[1]
        return False, None

    def _compare(command, expected, key, scope):
        nonlocal in_sync
        ok, actual = _query(command)
        if not ok:
            return
        matches = _same(expected, actual, key, scope)
        if matches is not None and not matches:
            in_sync = False

    db_file = global_values.get("dbfile", object())
    database_disabled = db_file is None or (
        isinstance(db_file, str) and db_file.lower() == "none"
    )
    for key, value in global_values.items():
        if database_disabled and key in ("dbmaxmatches", "dbpurgeage"):
            continue
        _compare(["get", key], value, key, "global")

    supported_jail_getters = {
        "maxretry", "maxmatches", "maxlines", "findtime", "bantime", "usedns",
        "ignoreself", "ignorecommand", "logencoding",
    }
    for (jail, key), value in jail_values.items():
        if key in supported_jail_getters:
            _compare(["get", jail, key], value, key, "jail")
        elif key == "prefregex":
            normalized = _native_prefregex(value, jail_values, jail)
            _compare(["get", jail, key], normalized, key, "jail")
        elif key.startswith("bantime."):
            _compare(["get", jail, key], value, key, "jail")

    for (jail, key), values in jail_lists.items():
        if key in ("ignoreip", "logpath"):
            _compare(["get", jail, key], values, key, "jail")
        elif key in ("failregex", "ignoreregex"):
            normalized = _native_regexes(values, key, jail_values, jail)
            _compare(["get", jail, key], normalized, key, "jail")

    for jail in expected_jails:
        expected_actions = action_names.get(jail, set())
        ok, actual_actions = _query(["get", jail, "actions"])
        if ok and isinstance(actual_actions, (list, tuple)):
            if set(actual_actions) != expected_actions:
                in_sync = False

        for action in expected_actions:
            for property_name, value in action_values.get((jail, action), {}).items():
                _compare(["get", jail, "action", action, property_name], value, property_name, "action")

    if client is not None:
        try:
            client.close()
        except Exception:
            pass

    return {"fingerprint": fingerprint, "startupFingerprint": startup_fingerprint,
            "activeJails": active_jails, "inSync": bool(in_sync)}


try:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        operation = _request.get("operation")
        root = _request.get("configRoot")
        configuration = _request.get("configuration") or {}
        if not isinstance(root, str) or not root:
            raise ValueError()
        if operation == "observe":
            result = _observe(root, configuration)
        else:
            early, stream, fingerprint, startup_fingerprint, enabled_jails = _read_config(root)
            if operation == "inspect":
                result = {
                    "socket": str(early.get("socket", "")),
                    "pidfile": str(early.get("pidfile", "")),
                    "fingerprint": fingerprint,
                    "startupFingerprint": startup_fingerprint,
                    "enabledJails": enabled_jails,
                }
            elif operation == "validate":
                result = {"validated": True}
            else:
                raise ValueError()
    _emit({"ok": True, "result": result})
except SystemExit:
    raise
except BaseException:
    _emit({"ok": False}, 2)
"""

    let private fail message = raise (BackendError(message))

    let private jsonString (value: string) =
        System.Text.Json.Nodes.JsonValue.Create(value).ToJsonString()

    let private createRequest (operation: string) (configRoot: string) (configurationJson: string) =
        "{\"operation\":"
        + jsonString operation
        + ",\"configRoot\":"
        + jsonString configRoot
        + ",\"configuration\":"
        + configurationJson
        + "}"

    let private mappedPath (environment: HostEnvironment) (logicalPath: string) =
        try
            HostEnvironment.path environment logicalPath
        with _ ->
            fail "The native Fail2Ban path is invalid."

    let private runBridge (environment: HostEnvironment) (request: string) =
        let result =
            try
                environment.Run "python3" [ "-c"; pythonBridge ] (Some request)
            with _ ->
                fail "The native Fail2Ban configuration bridge could not run."

        if result.ExitCode <> 0 then
            fail "The native Fail2Ban configuration could not be read."

        let document =
            try
                JsonDocument.Parse result.Stdout
            with _ ->
                fail "The native Fail2Ban configuration bridge returned an invalid response."

        let ok =
            try
                document.RootElement.GetProperty("ok").GetBoolean()
            with _ ->
                document.Dispose()
                fail "The native Fail2Ban configuration bridge returned an invalid response."

        if not ok then
            document.Dispose()
            fail "The native Fail2Ban configuration could not be read."

        document

    let private resultElement (document: JsonDocument) =
        try
            document.RootElement.GetProperty("result")
        with _ ->
            fail "The native Fail2Ban configuration bridge returned an invalid response."

    let private readString (element: JsonElement) (name: string) =
        try
            let value = element.GetProperty(name).GetString()

            if isNull value then
                fail "The native Fail2Ban configuration bridge returned an invalid response."

            value
        with
        | :? BackendError -> reraise ()
        | _ -> fail "The native Fail2Ban configuration bridge returned an invalid response."

    let private readStrings (element: JsonElement) (name: string) =
        try
            element.GetProperty(name).EnumerateArray()
            |> Seq.map (fun item ->
                let value = item.GetString()

                if isNull value then
                    fail "The native Fail2Ban configuration bridge returned an invalid response."

                value)
            |> Seq.toList
        with
        | :? BackendError -> reraise ()
        | _ -> fail "The native Fail2Ban configuration bridge returned an invalid response."

    let validate (environment: HostEnvironment) (configRoot: string) =
        let root = mappedPath environment configRoot
        let request = createRequest "validate" root "null"
        use document = runBridge environment request
        resultElement document |> ignore

    let inspect (environment: HostEnvironment) (configRoot: string) =
        let root = mappedPath environment configRoot
        let request = createRequest "inspect" root "null"
        use document = runBridge environment request
        let result = resultElement document

        {
            Socket = readString result "socket"
            PidFile = readString result "pidfile"
            Fingerprint = readString result "fingerprint"
            StartupFingerprint = readString result "startupFingerprint"
            EnabledJails = readStrings result "enabledJails"
        }

    let observe (environment: HostEnvironment) (configRoot: string) (configuration: Configuration) =
        let root = mappedPath environment configRoot

        let socket =
            if String.IsNullOrWhiteSpace configuration.Socket then
                ""
            elif Path.IsPathRooted configuration.Socket then
                mappedPath environment configuration.Socket
            else
                configuration.Socket

        let configurationJson =
            "{\"socket\":"
            + jsonString socket
            + ",\"fingerprint\":"
            + jsonString configuration.Fingerprint
            + ",\"startupFingerprint\":"
            + jsonString configuration.StartupFingerprint
            + "}"

        let request = createRequest "observe" root configurationJson

        use document = runBridge environment request
        let result = resultElement document

        let inSync =
            try
                result.GetProperty("inSync").GetBoolean()
            with _ ->
                fail "The native Fail2Ban runtime bridge returned an invalid response."

        {
            ActiveJails = readStrings result "activeJails"
            InSync = inSync
        }

    let reload (environment: HostEnvironment) (configuration: Configuration) =
        let configRoot = mappedPath environment "/etc/fail2ban"

        let socket =
            if String.IsNullOrWhiteSpace configuration.Socket then
                fail "The native Fail2Ban socket path is unavailable."
            elif Path.IsPathRooted configuration.Socket then
                mappedPath environment configuration.Socket
            else
                configuration.Socket

        let result =
            try
                environment.Run
                    "fail2ban-client"
                    [ "-c"; configRoot; "-s"; socket; "reload"; "--restart"; "--all" ]
                    None
            with _ ->
                fail "The native Fail2Ban reload could not run."

        if result.ExitCode <> 0 then
            fail "The native Fail2Ban reload failed."
