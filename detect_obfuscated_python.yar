rule detect_obfuscated_python {
  meta:
    description = "Detects suspicious Python code using obfuscation and system access"
    author = "Jeffrey & Atlas"
    severity = "High"
    reference = "https://attack.mitre.org/techniques/T1059/"
    date = "2025-07-02"

  strings:
    $eval = "eval("
    $exec = "exec("
    $b64decode = "base64.b64decode"
    $import_socket = "import socket"
    $os_system = "os.system"
    $encoded_pattern = /[A-Za-z0-9+/]{50,}={0,2}/  // long base64-like string

  condition:
    (1 of ($eval, $exec)) and
    (any of ($b64decode, $encoded_pattern)) and
    (any of ($import_socket, $os_system))
}
