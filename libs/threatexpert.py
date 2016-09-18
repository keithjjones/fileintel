#
# INCLUDES
#
import bs4
import requests

#
# CLASSES
#


class ThreatExpert(object):
    """
    Class to hold ThreatExpert items.
    """
    def __init__(self):
        self.baseurl = "http://www.threatexpert.com/reports.aspx?find="

    def add_headers(self, inputheaders):
        """
        Adds appropriate headers to input list.
        """
        inputheaders.append("ThreatExpert URL")
        inputheaders.append("ThreatExpert Findings")

    def add_row(self, filehash, inputrow):
        """
        Adds the pulled data to the input row.
        """
        threatexperturl = self.baseurl+filehash
        threatexpertfindings = ""

        src = requests.get(threatexperturl)
        soup = bs4.BeautifulSoup(src.text, 'html.parser')

        TextResults = soup.find("span", id="txtResults")

        if ('no ThreatExpert reports found' in
                TextResults.text):
            threatexperturl = "N/A"
        else:
            rows = soup.find("span", id="txtResults").find_all("tr")

            for row in rows:
                finding = row.find_all("td")[3].text
                if ("(not available)" not in finding and
                        "Findings" not in finding):
                    threatexpertfindings += finding + "\n"

            threatexpertfindings = threatexpertfindings.rstrip("\n")

        inputrow.append(threatexperturl)
        inputrow.append(threatexpertfindings)
