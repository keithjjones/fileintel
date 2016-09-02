#
# INCLUDES
#
import threatcrowd

# Need sleep function
import time

#
# CLASSES
#

class ThreatCrowd(object):
    """
    Class to hold ThreatCrowd items.
    """
    def __init__(self):
        pass
    
    """
    Adds appropriate headers to input list.
    """
    def add_headers(self,inputheaders):
        inputheaders.append('ThreatCrowd URL')
        inputheaders.append('ThreatCrowd SHA-1')
        inputheaders.append('ThreatCrowd MD5')
        inputheaders.append('ThreatCrowd IPs')
        inputheaders.append('ThreatCrowd References')
        inputheaders.append('ThreatCrowd Domains')
        inputheaders.append('ThreatCrowd Scans')

    """
    Adds the pulled data to the input row.
    """    
    def add_row(self,filehash,inputrow):
        time.sleep(10)  # Time speficied in API documents to be nice.

        IsValid = False

        # TC sometimes has a bad SSL handshake, this should fix it
        while IsValid == False:
            try:
                tcdata = threatcrowd.file_report(filehash)
                IsValid = True
            except:
                IsValid = False
                time.sleep(10)
        
        tcurl = tcdata.get('permalink','NA')
        tcsha1 = tcdata.get('sha1','')
        tcmd5 = tcdata.get('md5','')
        tcips = '; '.join(tcdata.get('ips',[]))
        tcreferences = '; '.join(tcdata.get('references',[]))
        tcdomains = '; '.join(tcdata.get('domains',[]))
        tcscans = '; '.join(tcdata.get('scans',[]))
                
        inputrow.append(tcurl)
        inputrow.append(tcsha1)
        inputrow.append(tcmd5)
        inputrow.append(tcips)
        inputrow.append(tcreferences)
        inputrow.append(tcdomains)
        inputrow.append(tcscans)
