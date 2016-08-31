# fileintel

This is a tool used to collect various intelligence sources for a given file.  Fileintel is
written in a modular fashion so new intelligence sources can be easily added.

Files are identified by file hash (MD5, SHA1, SHA256).  The output is in CSV format and
sent to STDOUT so the data can be saved or piped into another program.  Since the output is in CSV
format, spreadsheets such as Excel or database systems will easily be able to import the data.


## Help Screen:


```
$ python fileintel.py -h
usage: fileintel.py [-h] [-a] [-v] [-r] ConfigurationFile InputFile

Modular application to look up file intelligence information. Outputs CSV to
STDOUT.

positional arguments:
  ConfigurationFile     Configuration file
  InputFile             Input file, one hash per line (MD5, SHA1, SHA256)

optional arguments:
  -h, --help            show this help message and exit
  -a, --all             Perform All Lookups.
  -v, --virustotal      VirusTotal Lookup.
  -r, --carriagereturn  Use carriage returns with new lines on csv.
```

# Install:

First, make sure your configuration file is correct for your
computer/installation.  Add your API keys and usernames as appropriate
in the configuration file.  Python and Pip are required to run this
tool.  There are modules that must be installed from GitHub, so be
sure the git command is available from your command line.  Git is easy
to install for any platform.  Next, install the python requirements
(run this each time you git pull this repository too):

```
$ pip install -r requirements.txt
```

There have been some problems with the stock version of Python on Mac
OSX
(http://stackoverflow.com/questions/31649390/python-requests-ssl-handshake-failure).
You may have to install the security portion of the requests library
with the following command:

```
$ pip install requests[security]
```

Lastly, I am a fan of virtualenv for Python.  To make a customized local installation of
Python to run this tool, I recommend you read:  http://docs.python-guide.org/en/latest/dev/virtualenvs/

# Running:

```
$ python fileintel.py myconfigfile.conf myhashes.txt -a > myoutput.csv
```
You should be able to import myoutput.csv into any database or spreadsheet program.

**Note that depending on your network, your API key limits, and the
data you are searching for, this script can run for a very long time!
Use each module sparingly!  In return for the long wait, you save
yourself from having to pull this data manually.**

## Sample Data:

There is some sample data in the "sampledata" directory.  The hashes
were picked at random and by no means is meant to target any
organization or individual.  Running this tool on the sample data
works in the following way:

### Smaller List:

```
$ python fileintel.py local/config.conf sampledata/smallerlist.txt -a > sampledata/smallerlist.csv
*** Processing 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f ***
*** Processing 001025c6d4974fb2ccbea56f710282aca6c1353cc7120d5d4a7853688084953a ***
*** Processing CEEF161D68AE2B690FA9616361271578 ***
*** Processing D41D8CD98F00B204E9800998ECF8427E ***
*** Processing B284A42B124849E71DBEF653D30229F1 ***
*** Processing 0322A0BA58B95DB9A2227F12D193FDDEA74CFF89 ***
*** Processing E02CE6D73156A11BA84A798B26DE1D12 ***
*** Processing B4ED7AEDACD28CBBDE6978FB09C22C75 ***
*** Processing C6336EA255EFA7371337C0882D175BEE44CBBD49 ***
```

# Intelligence Sources:

  - VirusTotal (Public API key and network I/O required, throttled when appropriate)
    - http://www.virustotal.com

# Resources:

   - The VirusTotal Python library - https://github.com/blacktop/virustotal-api

# License:

This application is covered by the Creative Commons BY-SA license.

- https://creativecommons.org/licenses/by-sa/4.0/
- https://creativecommons.org/licenses/by-sa/4.0/legalcode

```
This product includes GeoLite2 data created by MaxMind, available from
<a href="http://www.maxmind.com">http://www.maxmind.com</a>.
```

# Contributing:

Read [Contributing.md] (Contributing.md)

# To Do:

- Add ThreatCrowd
- Add OTX
- Add ThreatExpert
- Add Cymru
- Add NSRL
  - http://www.nsrl.nist.gov/Downloads.htm
  - https://blog.didierstevens.com/2015/09/01/nsrl-py-using-the-reference-data-set-of-the-national-software-reference-library/
- Try to incorporate threat feeds from http://www.secrepo.com/