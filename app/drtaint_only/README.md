# DrTaint only

Empty dynamorio client showing program slowdown running under DrTaint

Usage:

```bash
# Setup env variables
export $DYNAMORIO_HOME=<path-to-your-dynamorio-package>
export $DRTAINT_HOME=<path-to-drtaint-build-folder>

export PROJECT=$DRTAINT_HOME/drtaint_only
$DYNAMORIO_HOME/bin32/drrun -c $PROJECT/libdrtaint_only.so -- /bin/ls
```