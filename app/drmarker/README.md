# DrMarker

DrMarker is a tool, that performs instruction slicing. 

The project has test application which reads string from *stdin*, performs xor operation and prints it out. DrMarker catches all *read* syscalls and makes input buffers of test program *tainted*. After that it tracks all instructions that attend to input data processing, highlights them and writes to html file.

Usage:

```bash
# Setup env variables
export $DYNAMORIO_HOME=<path-to-your-dynamorio-package>
export $DRTAINT_HOME=<path-to-drtaint-build-folder>

export PROJECT=$DRTAINT_HOME/drmarker
echo "hello world\n" | $DYNAMORIO_HOME/bin32/drrun -c $PROJECT/libdrmarker.so -- $PROJECT/drmarker_app
```

You will see html file, generated in current folder.