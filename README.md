# pe-parser

Portable executable parser and (re-)serializer.

This library can be used to extract and change resources and version
information in Windows executables.

## Documentation

`pe.cpp` and `pe.hpp` contain the functionality for parsing PE files into
separate (memory) sections, and writing them back:

 - `PE::read_pe_file` turns a file name or `FILE *` into a `PE::PortableExecutable`
   containing an `std::vector` of `PE::Section`s.
 - `PE::write_pe_file` does the reverse.

`pe-res.cpp` and `pe-res.hpp` contain the functionality for parsing and
(re-)serializing resource information and version information. Resource
information is held in the `.rsrc` section in the PE file, version information
is held in each resource with type `16`.

 - `PE::parse_resources` turns the resources section into a std::map of resources.
 - `PE::serialize_resources` does the reverse.
 - `PE::parse_version_info` turns a version info resource into a `PE::VersionInfo`.
 - `PE::serialize_version_info` does the reverse.

## Dependencies

- [mstd](https://github.com/m-ou-se/mstd)

## License

Two-clause BSD license, see [COPYING](COPYING).
