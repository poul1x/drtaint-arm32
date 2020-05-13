curl -T build/drtaint_marker_app ftp://192.168.1.34 --user user:user
curl -T modules.json ftp://192.168.1.34 --user user:user
curl -T `find . -name "instructions*.json"` ftp://192.168.1.34 --user user:user