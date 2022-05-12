After a clean build with `--features=python-bindings`

```
(pyscalpel) siddharth@siddharth-ubuntu:~/work/scalpel$ cd target/debug
(pyscalpel) siddharth@siddharth-ubuntu:~/work/scalpel/target/debug$ ls
build  deps  examples  incremental  libscalpel.d  libscalpel.rlib  libscalpel.so
```

rename libscalpel.so to scalpel.so
```
(pyscalpel) siddharth@siddharth-ubuntu:~/work/scalpel/target/debug$ mv libscalpel.so scalpel.so
```

start python shell and import scalpel
```
(pyscalpel) siddharth@siddharth-ubuntu:~/work/scalpel/target/debug$ python
Python 3.8.10 (default, Mar 15 2022, 12:22:08)
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import scalpel
>>> help(scalpel)

>>> dir(scalpel)
['Packet', '__all__', '__doc__', '__file__', '__loader__', '__name__', '__package__', '__spec__']
>>> help(scalpel)

Help on module scalpel:

NAME
    scalpel - Python bindings for packet dissection and sculpting in Rust (scalpel)

CLASSES
    builtins.object
        builtins.Packet

    class Packet(object)
     |  [`Packet`] is a central structure in `scalpel` containing the decoded data and some metadata.
     |
     |  When a byte-stream is 'dissected' by scalpel, it creates a `Packet` structure that contains the
     |  following information.
     |   * `data` : Optional 'data' from which this packet is constructed.
     |   * `meta` : Metadata associated with the packet. This contains information like timestamp,
     |              interface identifier where the data was captured etc. see `PacketMetadata` for
     |              details.
     |   * `layers`: A Vector of Opaque structures, each implementing the `Layer` trait. For example
     |               Each of the following is a Layer - `Ethernet`, `IPv4`, `TCP` etc.
     |   * `unprocessed`: The part of the original byte-stream that is not processed and captured into
     |                    `layers` above.
     |
     |  Methods defined here:
     |
     |  as_json(...)
     |
     |  ----------------------------------------------------------------------
     |  Static methods defined here:
     |
     |  __new__(*args, **kwargs) from builtins.type
     |      Create and return a new object.  See help(type) for accurate signature.
     |
     |  from_bytes_py(...)

DATA
    __all__ = ['Packet']

FILE
    /home/siddharth/work/scalpel/target/debug/scalpel.so
```

Now you can use scalpel provided `Packet.from_bytes_py(..)` method.


Note: python bindings are only available when built with --feature=python-bindings argument.
otherwise you will see following error
```
(pyscalpel) siddharth@siddharth-ubuntu:~/work/scalpel/target/debug$ python
Python 3.8.10 (default, Mar 15 2022, 12:22:08)
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import scalpel
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ImportError: dynamic module does not define module export function (PyInit_scalpel)
>>>
```

