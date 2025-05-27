from vt_api import response_example
from getmecolored import pref_fail, fail, good, warn
from datetime import datetime, timedelta
fqdn_time = '2024-11-19T22:29:39'

def check_domain_age(domain_age_iso: str):
    then_time = datetime.fromisoformat(domain_age_iso)
    now_time = datetime.now()
    delta = now_time - then_time
    print(delta)
    if delta < timedelta(days=365):
        return False
    return True

class RespParser:
    rps_id = ''
    rps_atr = {}
    rps_target_type = ''

    def accept_response(self, response: dict):
        self.rps_id = response['data']['id']
        self.rps_target_type = response['data']['type']
        self.rps_atr = response['data']['attributes']
        if self.rps_id[3:] == '10.' and self.rps_target_type == 'ip_address':
            print(f"{pref_fail()}::::THIS IS LOCAL IP, DON'T BLOCK IT::::)")
        self.evaluate(self.rps_id, self.rps_atr.get('last_analysis_stats'), self.rps_atr.get('reputation'))

    def report_on(self, field_list: list):
        pass

    def evaluate(self, target: str, analyse_stats: dict, community_rating: int, threshold: float = 0.1):
        total_amount = sum(analyse_stats.values())
        malware_rate = analyse_stats.get('malicious')
        malware_ratio = malware_rate/total_amount

        if malware_ratio > 2 * threshold:
            print(f'{fail(target)} :: {fail("DANGEROUS")}, ignoring community rating.')
            return

        if malware_ratio > threshold and community_rating < 0:
            print(f'{fail(target)} :: {fail("Unsafe")}, community rating: {fail(str(community_rating))}')
            return

        if malware_ratio > 0 > community_rating:
            print(f'{warn(target)} :: {warn("suspicious")}, community rating: {fail(str(community_rating))}')

        if malware_ratio == 0 and community_rating < 0:
            print(f'{warn(target)} :: Probably {good("safe")}, but community rated it as {fail("dangerous")}.')
            return

        if malware_ratio == 0 and community_rating >= 0:
            print(f'{good(target)} :: Generally {good("safe")}, community rated as {good("safe")}.')
            return

# response_parser = RespParser()
# response_parser.accept_response(response_example)