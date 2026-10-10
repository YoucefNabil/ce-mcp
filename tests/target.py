# Test target: prints the address of a u32 that goes up by 1 every second, then runs for `seconds` (argv[1]).
import ctypes, sys, time

v = ctypes.c_uint32(1234567)
print(hex(ctypes.addressof(v)), flush=True)
end = time.time() + float(sys.argv[1] if len(sys.argv) > 1 else 120)
while time.time() < end:
    time.sleep(1)
    v.value += 1
