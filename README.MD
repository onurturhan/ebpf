# Install packages.
sudo apt update
sudo apt install clang iproute2

# Prevent 'asm/types.h' file not found error.
sudo ln -s /usr/include/x86_64-linux-gnu/asm/ /usr/include/asm

# Compile XDP program with clang.
clang -O2 -Wall -target bpf -c xdp_*.c -o xdp_*.o

# Attach XDP program to enp0s8.
sudo ip link set dev wlo1 xdp obj xdp_*.o
sudo ip link show dev wlo1

# Detach XDP program from enp0s8.
sudo ip link set dev wlo1 xdp off

