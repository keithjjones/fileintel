#
# INCLUDES
#

# Required for VirusTotal API
from virus_total_apis import PublicApi as VirusTotalPublicApi
# Required for sleep function
import time

#
# CLASSES
#


class VT(object):
    """
    Class to hold VirusTotal items.
    """

    #
    # FUNCTIONS
    #
    """
    Sets up a VirusTotal object with the public api.
    """
    def __init__(self, vtpublicapi):
        self.vtpublicapi = vtpublicapi
        self.vt = VirusTotalPublicApi(self.vtpublicapi)

    def add_headers(self, inputheaders):
        """
        Adds appropriate headers to input list.
        """
        inputheaders.append('VirusTotal Link')
        inputheaders.append('VirusTotal Scan Date')
        inputheaders.append('VirusTotal SHA256')
        inputheaders.append('VirusTotal SHA1')
        inputheaders.append('VirusTotal MD5')
        inputheaders.append('VirusTotal Verbose Msg')
        inputheaders.append('VirusTotal Positivie Scans')
        inputheaders.append('VirusTotal Total Scans')
        inputheaders.append('VirusTotal Conviction Percentage')
        inputheaders.append('VirusTotal Scan Results')

    def add_row(self, filehash, inputrow):
        """
        Adds the pulled data to the input row.
        """
        vtresponse = self.vt.get_file_report(filehash)

        while "response_code" not in vtresponse or \
                (vtresponse["response_code"] != 200 and
                    vtresponse["response_code"] != 403):
            time.sleep(60)  # Sleep for the API throttling
            vtresponse = self.vt.get_file_report(filehash)

        if "results" not in vtresponse:
            vturl = 'INVALID API KEY'

        vtresults = vtresponse.get('results', {})

        vtsha1 = vtresults.get('sha1', '')
        vtscandate = vtresults.get('scan_date', '')
        vturl = vtresults.get('permalink', '')
        vtmsg = vtresults.get('verbose_msg', '')
        vtsha256 = vtresults.get('sha256', '')
        vtpositives = str(vtresults.get('positives', 0))
        vttotal = str(vtresults.get('total', 0))
        vtmd5 = vtresults.get('md5', '')

        vtscansdict = vtresults.get('scans', {})
        vtscans = '\n'.join(["{} Detected: {} Result: "
                             "{} Version: {} Update: {}"
                            .format(s, vtscansdict[s].get('detected', ''),
                                    vtscansdict[s].get('result', ''),
                                    vtscansdict[s].get('Version', ''),
                                    vtscansdict[s].get('update', ''))
                            for s in vtscansdict])

        if (float(vttotal) > 0):
            vtconvictionpercentage = str(float(vtpositives)/float(vttotal) *
                                         100)
        else:
            vtconvictionpercentage = 'NaN'

        inputrow.append(vturl)
        inputrow.append(vtscandate)
        inputrow.append(vtsha256)
        inputrow.append(vtsha1)
        inputrow.append(vtmd5)
        inputrow.append(vtmsg)
        inputrow.append(vtpositives)
        inputrow.append(vttotal)
        inputrow.append(vtconvictionpercentage)
        inputrow.append(vtscans)
