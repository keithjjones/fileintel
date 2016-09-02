# fileintel

This is a tool used to collect various intelligence sources for a given file.  Fileintel is
written in a modular fashion so new intelligence sources can be easily added.

Files are identified by file hash (MD5, SHA1, SHA256).  The output is in CSV format and
sent to STDOUT so the data can be saved or piped into another program.  Since the output is in CSV
format, spreadsheets such as Excel or database systems will easily be able to import the data.

This works with Python v2, but it should also work with Python v3.  If you find it does not work
with Python v3 please post an issue.

## Help Screen:


```
$ python fileintel.py -h
usage: fileintel.py [-h] [-a] [-v] [-n] [-t] [-r] ConfigurationFile InputFile

Modular application to look up file intelligence information. Outputs CSV to
STDOUT.

positional arguments:
  ConfigurationFile     Configuration file
  InputFile             Input file, one hash per line (MD5, SHA1, SHA256)

optional arguments:
  -h, --help            show this help message and exit
  -a, --all             Perform All Lookups.
  -v, --virustotal      VirusTotal Lookup.
  -n, --nsrl            NSRL Lookup for SHA-1 and MD5 hashes ONLY!
  -t, --threatcrowd     ThreatCrowd Lookup for SHA-1 and MD5 hashes ONLY!
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

If you are using the NSRL database lookups, download the NSRL "Minimal" data set as a zip file.  Put it
in a directory you can access and point your configuration file to that zip file.  There is no need
to unzip the NSRL data.

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
Preprocessing NSRL database.... please hold...
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

### Larger List:

```
$ python fileintel.py local/config.conf sampledata/largerlist.txt -a > sampledata/largerlist.csv
Preprocessing NSRL database.... please hold...
*** Processing 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f ***
*** Processing 001025c6d4974fb2ccbea56f710282aca6c1353cc7120d5d4a7853688084953a ***
*** Processing CEEF161D68AE2B690FA9616361271578 ***
*** Processing D41D8CD98F00B204E9800998ECF8427E ***
*** Processing B284A42B124849E71DBEF653D30229F1 ***
*** Processing 0322A0BA58B95DB9A2227F12D193FDDEA74CFF89 ***
*** Processing E02CE6D73156A11BA84A798B26DE1D12 ***
*** Processing B4ED7AEDACD28CBBDE6978FB09C22C75 ***
*** Processing C6336EA255EFA7371337C0882D175BEE44CBBD49 ***
...
*** Processing 09a64957060121a765185392fe2ec742 ***
*** Processing e0ab52a76073bff4a27bdf327230103d ***
*** Processing 02a5bd561c140236a3380785a3544b71 ***
*** Processing 152c3bb23cc9cb0b0112051b94f69d47 ***
*** Processing 2c9a5e7ce87259ec89e182416ac3a4f8 ***
*** Processing c777b094a3469610d81c139c952e380e ***
*** Processing aa58d9126ed96fa61f53e4f6c0bcd6b4 ***
*** Processing a68e53c42e2d0968e2fbcd168323725f ***
*** Processing a1651db6630f90b11576389aa714ad41 ***

```

# Intelligence Sources:

  - VirusTotal (Public API key and network I/O required, throttled when appropriate)
    - http://www.virustotal.com
  - NSRL Database
    - http://www.nsrl.nist.gov/Downloads.htm
  - ThreatCrowd (Network I/O required, throttled when appropriate)
    - http://www.threatcrowd.org

# Resources:

   - The VirusTotal Python library
     - https://github.com/blacktop/virustotal-api
   - The NSRL database
     - http://www.nsrl.nist.gov/Downloads.htm
     - https://blog.didierstevens.com/2015/09/01/nsrl-py-using-the-reference-data-set-of-the-national-software-reference-library/
   - The ThreatCrowd Python library
     - https://github.com/threatcrowd/ApiV2
     - https://github.com/jheise/threatcrowd_api

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

- Add OTX
- Add PassiveTotal
- Add ThreatExpert
- Add Cymru
- Add Malwr
- Try to incorporate threat feeds from http://www.secrepo.com
