# MAIN APPLICATION

#
# INCLUDES
#

# Required for complex command line argument parsing.
import argparse
# Required for configuration files
from configparser import ConfigParser
# Required for CSV
import csv
# Required for STDOUT
import sys
# Required for paths
import os

# MODULES:  Add additional intelligence source modules here

# Local VirusTotal functions
import libs.vt
# Local NSRL functions
import libs.nsrl
# Local ThreatCrowd functions
import libs.threatcrowdinfo
# Local OTX functions
import libs.otx
# Local ThreatExpert functions
import libs.threatexpert


#
# Detect type of hash
#
def typeofhash(filehhash):
    """
    Determines the type of the hash by the length.

    :param filehash: The hash as a string
    :results: The hash type as either MD5, SHA-1, SHA-256,
    SHA-512 or Uknown
    """
    if len(filehash) == 32:
        return('MD5')
    elif len(filehash) == 40:
        return('SHA-1')
    elif len(filehash) == 64:
        return('SHA-256')
    elif len(filehash) == 128:
        return('SHA-512')
    else:
        return('Unknown')

#
# COMMAND LINE ARGS
#

# Setup command line argument parsing.
parser = argparse.ArgumentParser(
    description='Modular application to look up '
                'file intelligence information.  '
                'Outputs CSV to STDOUT.')
parser.add_argument('ConfigurationFile', help='Configuration file')
parser.add_argument('InputFile',
                    help='Input file, one hash per line (MD5, SHA1, SHA256)')
parser.add_argument('-a',
                    '--all', action='store_true',
                    help='Perform All Lookups.')
parser.add_argument('-v',
                    '--virustotal', action='store_true',
                    help='VirusTotal Lookup.')
parser.add_argument('-n',
                    '--nsrl', action='store_true',
                    help='NSRL Lookup for SHA-1 and MD5 hashes ONLY!')
parser.add_argument('-o',
                    '--otx', action='store_true',
                    help='OTX by AlienVault Lookup.')
parser.add_argument('-t',
                    '--threatcrowd', action='store_true',
                    help='ThreatCrowd Lookup for SHA-1 and MD5 hashes ONLY!')
parser.add_argument('-e',
                    '--threatexpert', action='store_true',
                    help='ThreatExpert Lookup for MD5 hashes ONLY!')
parser.add_argument('-r',
                    '--carriagereturn', action='store_true',
                    help='Use carriage returns with new lines on csv.')

#
# MAIN PROGRAM
#

# Parse command line arguments.
args = parser.parse_args()

# Parse Configuration File
ConfigFile = ConfigParser()
ConfigFile.read(args.ConfigurationFile)

# Setup the headers list
Headers = []

# Setup the data list
Data = []

# MODULES:  Setup additional intelligence source modules here

# Pull the VirusTotal config
vtpublicapi = ConfigFile.get('VirusTotal', 'PublicAPI')

# Pull the NSRL config
nsrlpath = ConfigFile.get('NSRL', 'Path')

# Pull the OTX config
otxpublicapi = ConfigFile.get('OTX', 'PublicAPI')

# Pull the 7Zip executable name
try:
    SevenZipPath = ConfigFile.get('7Zip', 'Path')
    if os.path.exists(SevenZipPath):
        sys.stderr.write("INFO:  Using 7Zip from: " +
                         SevenZipPath + "\n")
    else:
        sys.stderr.write("INFO:  7Zip not configured correctly, " +
                         "defaulting to much slower " +
                         "internal Zip library!\n")
        SevenZipPath = None
except:
    sys.stderr.write("INFO:  7Zip not configured correctly, " +
                     "defaulting to much slower " +
                     "internal Zip library!\n")
    SevenZipPath = None

# Open file and read into list named hosts
try:
    with open(args.InputFile) as infile:
        filehashes = infile.read().splitlines()
except:
    sys.stderr.write("ERROR:  Cannot open InputFile!\n")
    exit(1)

# Setup CSV to STDOUT
if args.carriagereturn:
    output = csv.writer(sys.stdout, lineterminator='\r\n')
else:
    output = csv.writer(sys.stdout, lineterminator='\n')

# Add standard header info
Headers.append('Input File')
Headers.append('Hash Type?')

# Print Header Flag
PrintHeaders = True

# Pre Processing Here

# Pre process NSRL results because it is faster this way
NSRLHashes = []
if args.nsrl or args.all:
    sys.stderr.write('Preprocessing NSRL database.... please hold...\n')
    NSRL = libs.nsrl.NSRL(nsrlpath)
    NSRLHashes = NSRL.lookup(filehashes, SevenZipPath)

# Abort Flag
Aborted = False

# Iterate through all of the input hosts
for filehash in filehashes:
    try:
        # Output status
        sys.stderr.write('*** Processing {} ***\n'.format(filehash))

        # Clear the row
        row = []

        # Add the host to the output
        row.append(filehash.upper())

        # Detect the type of hash and add it
        row.append(typeofhash(filehash))

        # Lookup NSRL - This is slightly different than most
        # modules because of required pre processing.
        # No need to use this as an example unless you
        # preprocess other data.
        if args.nsrl or args.all:
            NSRL = libs.nsrl.NSRL(nsrlpath)
            if PrintHeaders:
                NSRL.add_headers(Headers)
            NSRL.add_row(NSRLHashes, filehash, row)

        # Lookup VirusTotal
        if args.virustotal or args.all:
            VT = libs.vt.VT(vtpublicapi)
            if PrintHeaders:
                VT.add_headers(Headers)
            VT.add_row(filehash, row)

        # Lookup ThreatCrowd
        if args.threatcrowd or args.all:
            TC = libs.threatcrowdinfo.ThreatCrowd()
            if PrintHeaders:
                TC.add_headers(Headers)
            TC.add_row(filehash, row)

        # Lookup OTX
        if args.otx or args.all:
            OTX = libs.otx.OTX(otxpublicapi)
            if PrintHeaders:
                OTX.add_headers(Headers)
            OTX.add_row(filehash, row)

        # Lookup ThreatExpert
        if args.threatexpert or args.all:
            ThreatExert = libs.threatexpert.ThreatExpert()
            if PrintHeaders:
                ThreatExert.add_headers(Headers)
            ThreatExert.add_row(filehash, row)

        # MODULES:  Add additional intelligence source modules here

        # Add the row to the output data set
        Data.append(row)

        # Print out the headers
        if PrintHeaders:
            output.writerow(Headers)

        # Print out the data
        try:
            output.writerow([unicode(field).encode('utf-8') for field in row])
        except:
            output.writerow([str(field) for field in row])

        # This turns off headers for remaining rows
        PrintHeaders = False
    except:
        # There was an error...
        sys.stderr.write('ERROR:  An exception was raised!  ' +
                         'Raising original exception for debugging.\n')
        raise

# Exit without error
exit(0)
