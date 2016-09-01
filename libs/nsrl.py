#
# Note this module is different than others to help speed up processing.  It is a "Pre Processing" module
#

#
# INCLUDES
#
import zipfile
import csv
import sys

#
# CLASSES
#

class NSRL(object):
    """
    Class to hold NSRL items.
    """
    def __init__(self,NSRLPath):
        self.NSRLPath = NSRLPath
    
    """
    Adds appropriate headers to input list.
    """
    def add_headers(self,inputheaders):
        inputheaders.append('NSRL SHA-1 or MD5 Match')

    """
    Adds the pulled data to the input row.
    """
    def add_row(self,NSRLHashes,filehash,inputrow):
        NSRLMatch = False
        if filehash.upper() in [n.upper() for n in NSRLHashes]:
            NSRLMatch = True
    
        inputrow.append(NSRLMatch)

    """
    Lookup the list of file hashes and returns a list of the hashes that exist in the NSRL.
    """
    #
    #  Inspired by:   https://blog.didierstevens.com/2015/09/01/nsrl-py-using-the-reference-data-set-of-the-national-software-reference-library/
    #
    def lookup(self,filehashes):
        upperhashes = [f.upper() for f in filehashes]
        outputhashes = []
        try:
            ZipFile = zipfile.ZipFile(self.NSRLPath)
        except:
            sys.stderr.write("ERROR: Problem with the NSRL file!  Check the conf file?  Check if the file is corrupt?\n")
            exit(1)
        fIn = ZipFile.open('NSRLFile.txt','r')
        csvIn = csv.reader(fIn, delimiter=',', skipinitialspace=True)
        for row in csvIn:
            if row[0].upper() in upperhashes:
                outputhashes.append(row[0])
            elif row[1].upper() in upperhashes:
                outputhashes.append(row[1])

        fIn.close()
        
        return outputhashes
