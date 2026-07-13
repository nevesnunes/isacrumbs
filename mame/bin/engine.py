#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import re
import socket
import struct
import sys

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--input",
        type=str,
        help="Input test file",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="/tmp/fuzz",
        help="Output path for coverage files",
    )
    parser.add_argument(
        "-s",
        "--size",
        type=int,
        default=8,
        help="Address size to read",
    )
    args = parser.parse_args()

    cov_path = f"{args.output}/cov"
    os.makedirs(cov_path, exist_ok=True)

    with open(args.input, "rb") as f:
        patterns = json.load(f)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 1477))
    server.listen(1)
    print("Fuzzer engine started.")

    connection, client_address = server.accept()
    try:
        # Format: [kind:u8, len_space:u32, space:ascii, len_addr:u32, addr:len_addr, len_data:u32, data]
        # TODO:
        # - install_read_handler => { "kind": 0, "space": "io", "addr_size": 16, "addr": "0x0002", "data_size": 16, "vals": ["0x0001", "0x0000"] },
        # - Interactive mode, random values...
        # - Prefer seeds that cover new paths: https://www.fuzzingbook.org/html/MutationFuzzer.html#Guiding-by-Coverage
        connection.sendall(len(patterns).to_bytes(4, "big"))
        for pattern in patterns:
            o = pattern["kind"].to_bytes(1, "big")
            o += len(pattern["space"]).to_bytes(4, "big")
            o += pattern["space"].encode("latin-1")
            o += pattern["addr_size"].to_bytes(4, "big")
            o += int(pattern["addr"], 16).to_bytes(pattern["addr_size"] // 8, "big")
            o += pattern["data_size"].to_bytes(4, "big")
            if "vals" in pattern:
                o += len(pattern["vals"]).to_bytes(4, "big")
                for val in pattern["vals"]:
                    o += int(val, 16).to_bytes(pattern["data_size"] // 8, "big")
            else:
                o += len(pattern["regs"].keys()).to_bytes(4, "big")
                for reg, val in pattern["regs"].items():
                    o += len(reg).to_bytes(1, "big")
                    o += reg.encode("latin-1")
                    o += int(val, 16).to_bytes(pattern["data_size"] // 8, "big")
            connection.sendall(o)
        while True:
            data = connection.recv(1)
            if not data:
                break
            print(f"Read: {data.hex()}")
    finally:
        try:
            connection.close()
        finally:
            server.shutdown(socket.SHUT_RDWR)
            server.close()

    # Check if instruction coverage set is distinct from 
    # already stored snapshots by comparing checksums.
    # TODO: Include patterns.
    print("Checking coverage of last run.")
    with open(f"{args.output}/dump", "rb") as f:
        chksum = hashlib.md5(f.read()).hexdigest()
        chksum_path = f"{cov_path}/{chksum}"
        if not os.path.exists(f"{chksum_path}"):
            print(f"Got new coverage: '{chksum_path}'.")
            os.makedirs(chksum_path, exist_ok=True)
            os.rename(f"{args.output}/dump", f"{chksum_path}/dump")

    print("Fuzzer engine stopped.")
