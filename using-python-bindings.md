# Overview

We are using [`maturin](https://www.maturin.rs/) for building the Python bindings support. Right now the generated bindings are not published on PyPI as yet, as this is still in early stages of development.

# Compiling and Testing Python bindings

1. Run following command to generate and use Python bindings locally. This is tested right now with Python 3.10 (but this should work with any version of Python after 3.7).

```
# Create a Virtual Environment
$ python3 -m venv venv

# Activate the virtual environment
$ . venv/bin/activate

# Install `maturin`
$ pip install -y maturin

# Build and Locally use Python bindings (This uses `pyproject.toml` file.)
# Note since `python-bindings` are optional, `-F python-bindings` is required or else the bindings won't be built.
$ maturin develop -F python-bindings

# Check Out Python bindings.
$ python

>>> import scalpel
>>> buffer = bytes.fromhex("000573a007d168a3c4f949f686dd600000000020064020010470e5bfdead49572174e82c48872607f8b0400c0c03000000000000001af9c7001903a088300000000080022000da4700000204058c0103030801010402")
>>> p = scalpel.Packet.from_bytes_py(buffer)
>>> print(p.as_json())
>>> # Check help for `scalpel`
>>> help(scalpel)
```
