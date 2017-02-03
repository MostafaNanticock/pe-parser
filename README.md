# pe-parser

Cross-platform C++14 portable executable parser and (re-)serializer.

This library can be used to extract and change resources and version
information in Windows executables.

## Documentation

`pe.cpp` and `pe.hpp` contain the functionality for parsing PE files into
separate (memory) sections, and writing them back:

 - `read_pe_file` turns a file name or `FILE *` into a `PE::PortableExecutable`
   containing an `std::vector` of `Section`s.
 - `write_pe_file` does the reverse.

`pe-res.cpp` and `pe-res.hpp` contain the functionality for parsing and
(re-)serializing resource information and version information. Resource
information is held in the `.rsrc` section in the PE file, version information
is held in each resource with type `16`.

 - `parse_resources` turns the resources section into a std::map of resources.
 - `serialize_resources` does the reverse.
 - `parse_version_info` turns a version info resource into a `VersionInfo`.
 - `serialize_version_info` does the reverse.

## Dependencies

- [mstd](https://github.com/m-ou-se/mstd)

## License

Two-clause BSD license, see [COPYING](COPYING).
