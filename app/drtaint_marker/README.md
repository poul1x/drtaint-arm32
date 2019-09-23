# DM (drtaint marker)

DM is a tool, that records all application instructions executed during input data processing. 

The project has test application which reads string from *stdin*, performs xor operation and prints it out. DM catches all *read* syscalls and makes input buffers of test program *tainted*. After that it tracks all instructions that attend to input data processing, highlights them and writes to output file.

Usage:

```bash
echo "hello world\n" | $BIN32/drrun -c $BUILD/libdrtaint_marker.so -- $BUILD/drtaint_marker_app
```

You will see output file, generated in current folder.