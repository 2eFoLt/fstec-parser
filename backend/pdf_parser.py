"""
This stuff is in dire need of refactoring ngnl
"""
from pypdf import PdfReader as pdfr
from os import listdir
import re
from utils.reporting import make_report
from db.database import DBInterface

lookup_lang: dict[str, str] = {
    'а': 'a',
    'о': 'o',
    'е': 'e',
    'с': 'c'
}

stop_list: list[str] = ['.exe', '.EXE', '.jar', '.JAR', '.js', '.JS', '.dll', '.DLL', '.jpg', '.JPG', '.png', '.PNG', '.pem',
             '.cpp']

protection_list: list[str] = ['https://socfmba.ru/', 'fmba@fmba.gov.ru', 'cspfmba.ru', 'cspmz.ru', 'Dr.Web', 'example.org']

regex_dict: dict[str, str] = {
    'ip': r"^([\d]{1,3}\.){3}\d{1,3}$",
    'fqdn': r"^(?=.{4,127})(?![\d.-]+$)(?!.*?_.*?)(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w]+?\-\.(?:[\w\.\-]+?))(?=[\w])(?=[\w\.\-]*?\.+[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)[\w\.\-]+?(?<![\w\-\.]\.[\d])(?<=[\w\-])(?<![\w\-]{25})$",
    'url': r"(h\w\wps?:\/\/)\S+$",
    'sha256': r"^[A-Fa-f0-9]{64}$",
    'sha1': r"^[A-Fa-f0-9]{40}$"
}

# make function selection between parsing pdf and database searching
# unit test parser result to 2402_*
# add legitimacy check with ipwhois + vt to exclude legit IPs and FQDNs from ban
# turn into server with API
# after server make service and cron job for backup

def clean_data(data: str) -> str:
    data = data.replace("[.]", ".").replace("[:]", ":")
    data = re.sub(pattern=r"([;,.]|[;,].?)$", repl='', string=data)
    return data


def check_for_filename(data: str) -> bool:
    for stop_sign in stop_list:
        if stop_sign in data:
            return True
    return False


def encoding_fix(data: str) -> str:
    for char in lookup_lang:
        if char in data:
            print('Got russian letter, fixing\n')
            print(data)
            data = data.replace(char, lookup_lang[char])
    return data


def strip_order_date(data: str) -> str: return data[11:]


database_object = DBInterface()
database_object.connect()
processed_orders = []
for filename in listdir(path="pdfs"):
    clear_name: str = filename.replace('.pdf', '')
    order_number: str = strip_order_date(clear_name)
    processed_orders.append(order_number)
    ip_output = []
    fqdn_output = []
    print(f"\nParsing {filename}: {order_number}")
    reader = pdfr(f"pdfs/{filename}")
    for page in reader.pages:
        page_content = page.extract_text()
        bucket = page_content.split()  # TODO: Troubles with split, splits URLs with files because of wild space or \n in PDF
        for item in bucket:
            item = clean_data(item)
            reg_ips = re.match(regex_dict['ip'], item)
            reg_fqdn = re.match(regex_dict['fqdn'], item)
            reg_url = re.match(regex_dict['url'], item)
            reg_sha256 = re.match(regex_dict['sha256'], item)
            reg_sha1 = re.match(regex_dict['sha1'], item)
            # Make universal -> fewer copies of code
            if reg_ips is not None:  # Works good
                ip_output.append(reg_ips.string)
                continue
            # if reg_url is not None:  # Split troubles, above
            #     if reg_url.string not in protection_list:
            #         url_output.append(reg_url.string)
            #         continue
            if reg_fqdn is not None:
                if check_for_filename(reg_fqdn.string): continue
                if reg_fqdn.string not in protection_list:
                    tmp = encoding_fix(reg_fqdn.string)
                    fqdn_output.append(tmp)
                    continue
            # if reg_sha256 is not None:
            #     sha256_output.append(reg_sha256.string)
            #     continue
            # if reg_sha1 is not None:
            #     sha1_output.append(reg_sha1.string)
            #     continue
            else:
                # print(f":::WARNING! Failed to parse {item} :::")
                continue
    print(f"IPs found: {len(ip_output)}")
    print(f"FQDNs found: {len(fqdn_output)}")
    if len(ip_output) == 0 and len(fqdn_output) == 0:
        print(f"No output found, skipping reporting stage")
        continue
    if len(ip_output) > 0:
        make_report(clear_name, 'ip', ip_output)
        database_object.add_data('ip_table', ip_output, 'ip_address', order_number)
    if len(fqdn_output) > 0:
        make_report(clear_name, 'fqdn',  fqdn_output)

database_object.add_data('orders', processed_orders, 'order_date_number')
print('ip_table contents:', database_object.select('ip_table', '*'))
print('orders contents:', database_object.select('orders', 'order_date_number'))
database_object.disconnect()