# Research Commands

The `research` command group helps you initiate research tasks against vulnerability identifiers.

## GitHub Repository Search

You can trigger a search for public GitHub repositories related to a specific vulnerability ID.

### By Single Vulnerability ID

To search for a single CVE:

```sh
wafrunner research github --vulnid CVE-2021-44228
```

### From a File

If you have a list of vulnerability IDs in a file (one per line), you can process them in bulk:

```sh
# vulns.txt
# CVE-2021-44228
# CVE-2022-22965

wafrunner research github --vulnid-file vulns.txt
```

The tool requires that you provide either `--vulnid` or `--vulnid-file`, but not both.