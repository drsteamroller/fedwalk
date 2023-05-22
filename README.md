# fedwalk.py
FAZ/FMG backup obfuscator, as well as literally anything else. This tool is built for directory-based backups (FMG/FAZ/etc) and random debug console output from troubleshooting. The intent is for this tool to be the LAST tool used in the toolkit of Fortinet Federal. Reason being, this tool is only built to intelligently identify IP addresses. It will not be able to categorize any of the data fed to it (Usernames, device names, etc). It won't be able to identify these strings in the wild. More info below.

## Dependencies

- binaryornot: Library that determines if a file is a text file or binary file. This is useful since we don't know what is in any given path that this program will be presented

https://pypi.org/project/binaryornot/
https://github.com/binaryornot/binaryornot

```
pip install binaryornot
```

## Usage

```
python fedwalk.py <target-directory> <depth> [options]

depth => the amount of steps deep the program will run through (for nested folders)
```

- Options

```
-h: Display this output
-sPIP: Scrub private IPs. Assumes /16 subnet
-pi: preserve all ip addresses
-pm: preserve MAC addresses
```

- Caveats

    - fedwalk.py will not run if the target directory contains fedwalk.py (or whatever it is renamed to).
    - You **must** include a postive number for depth, and a warning will be thrown if the depth is larger than 5.

## When to run fedwalk.py
As stated above, fedwalk.py is intended to be ran last. The other programs in the toolkit of Fortinet Federal (pcapsrb.py, logscrub.py, FortiObfuscate.py) have ways to identify strings since the data those programs see is limited to a small subset of what fedwalk.py sees. Those programs are typically able to categorize strings based on a preceeding attribute value (e.g. **user**=feduser1). Each of the listed programs in the toolkit will output a map file, which contains mapping for IP addresses and strings, as well as MAC addresses on some occasions. For the full functionality of fedwalk.py, it is recommended that you import a map file that has gathered information from the other tools. This way- it will have a predefined set of strings to search for.