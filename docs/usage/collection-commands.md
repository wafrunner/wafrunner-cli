
# Collection Commands

The `collection` command group provides tools for managing local collections of vulnerabilities.

## Creating a New Collection

You can create a new collection of vulnerabilities using the `create` subcommand. This is useful for grouping related vulnerabilities for analysis or reporting.

### From a List of Identifiers

You can create a collection by providing a list of CVE IDs or vulnerability IDs directly on the command line:

```sh
wafrunner collection create my-first-collection --id CVE-2021-44228 --id a1ddadd4-1b9d-4fab-90fe-64c1c763cd58
```

### From a File

If you have a text file containing a list of identifiers (one per line), you can use the `--file` option:

```sh
# my_ids.txt
CVE-2021-44228
a1ddadd4-1b9d-4fab-90fe-64c1c763cd58

wafrunner collection create my-second-collection --file my_ids.txt
```

## Listing Collections

To see all of your local collections, use the `list` subcommand:

```sh
wafrunner collection list
```

## Showing a Collection

To view the contents of a specific collection, use the `show` subcommand:

```sh
wafrunner collection show my-first-collection
```

## Deleting a Collection

To remove a collection, use the `delete` subcommand:

```sh
wafrunner collection delete my-first-collection
```
