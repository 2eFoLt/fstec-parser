from pathlib import Path

def strip_order_date(data: str): return data[11:]

rule_template = '/ip/firewall/filter add action=reject chain=forward comment=ORDER-{1}-{0} dst-address-list=ORDER-{1}-{0} log=yes log-prefix={1}-{2} reject-with=icmp-admin-prohibited'
list_template = '/ip/firewall/address-list add address={0} comment=ORDER-{1}-{2} list=ORDER-{1}-{2}\n'
file_template = "commands/{}/{}_{}.txt"

def make_report(order_name: str, data_type: str, data = None):
    Path(f"commands/{order_name}").mkdir(parents=True, exist_ok=True)
    with open(file_template.format(order_name, data_type, 'rule'), 'w') as output:
        output.write(rule_template.format(order_name, data_type.upper(), strip_order_date(order_name)))
    # TODO: Rules differ only by data type, rewrite to one instruction

    with open(file_template.format(order_name, data_type, 'list'), 'w') as output:
        output.writelines([list_template.format(item, data_type.upper(), order_name) for item in data])
