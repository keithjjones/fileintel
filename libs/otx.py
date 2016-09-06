#
# INCLUDES
#
import OTXv2

# STDERR
import sys

#
# CLASSES
#

class OTX(object):
    """
    Class to hold OTX items.
    """
    def __init__(self,PublicAPI):
        self.PublicAPI = PublicAPI
        self.otx = OTXv2.OTXv2(PublicAPI)
        self.fileurl = 'https://otx.alienvault.com/api/v1/indicators/file/{}/{}'
    
    """
    Adds appropriate headers to input list.
    """
    def add_headers(self,inputheaders):
        inputheaders.append('OTX URL')
        inputheaders.append('OTX Pulses')
        inputheaders.append('OTX References')
        inputheaders.append('OTX Malware')
        inputheaders.append('OTX Analysis SHA 1')
        inputheaders.append('OTX Analysis SHA 256')
        inputheaders.append('OTX Analysis MD5')
        inputheaders.append('OTX Analysis SSDeep')
        inputheaders.append('OTX Analysis File Size')
        inputheaders.append('OTX Analysis File Class')
        inputheaders.append('OTX Analysis File Type')

    """
    Adds the pulled data to the input row.
    """    
    def add_row(self,filehash,inputrow):
        try:
            otxgendata = self.otx.get(self.fileurl.format(filehash,'general'))
            otxanalysisdata = self.otx.get(self.fileurl.format(filehash,'analysis'))
            otxurl = 'https://otx.alienvault.com/indicator/file/{}'.format(filehash)
        except OTXv2.InvalidAPIKey:
            sys.stderr.write("ERROR:  OTX API key invalid!\n")
            raise
        except OTXv2.BadRequest:
            otxgendata = {}
            otxanalysisdata = {}
            otxurl = "Invalid file hash"

        otxgenpulses = otxgendata.get('pulse_info',{}).get('count','')
        otxgenrefs = '\n'.join(otxgendata.get('pulse_info',{}).get('references',[]))

        otxanalysismalware = otxanalysisdata.get('malware','')

        otxanalysis = otxanalysisdata.get('analysis',{})
        
        if otxanalysis == None:
            otxanalysis = {}
            
        otxanalysisinfo = otxanalysis.get('info',{}).get('results',{})
        otxanalysissha1 = otxanalysisinfo.get('sha1','')
        otxanalysissha256 = otxanalysisinfo.get('sha256','')
        otxanalysismd5 = otxanalysisinfo.get('md5','')
        otxanalysisssdeep = otxanalysisinfo.get('ssdeep','')
        otxanalysisfilesize = otxanalysisinfo.get('filesize','')
        otxanalysisfileclass = otxanalysisinfo.get('file_class','')
        otxanalysisfiletype = otxanalysisinfo.get('file_type','')
        
        inputrow.append(otxurl)
        inputrow.append(otxgenpulses)
        inputrow.append(otxgenrefs)
        inputrow.append(otxanalysismalware)
        inputrow.append(otxanalysissha1)
        inputrow.append(otxanalysissha256)
        inputrow.append(otxanalysismd5)
        inputrow.append(otxanalysisssdeep)
        inputrow.append(otxanalysisfilesize)
        inputrow.append(otxanalysisfileclass)
        inputrow.append(otxanalysisfiletype)
