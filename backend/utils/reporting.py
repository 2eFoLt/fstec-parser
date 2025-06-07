from pathlib import Path
import csv
def strip_order_date(data: str): return data[11:]

rule_template = '/ip/firewall/filter add action=reject chain=forward comment=ORDER-{1}-{0} dst-address-list=ORDER-{1}-{0} log=yes log-prefix={1}-{2} reject-with=icmp-admin-prohibited'
list_template = '/ip/firewall/address-list add address={0} comment=ORDER-{1}-{2} list=ORDER-{1}-{2}\n'
file_template = "commands/{}/{}_{}.txt"

def make_csv(filename: str, fields: list[str]) -> None:
    with open(filename, 'w', newline='') as file:
        csv_writer = csv.writer(file)
        csv_writer.writerow(fields)

def populate_csv(csv_filename: str, column_values: zip) -> None:
    with open(csv_filename, 'a', newline='') as file:
        csv_writer = csv.writer(file)
        for row in column_values:
            csv_writer.writerow(row)

def dump_to_txt(data_type: str, data: list) -> None:
    with open(f'dumps/{data_type}.txt', 'a', errors="replace", encoding="utf-8") as output:
        output.writelines([line + '\n' for line in data])

def make_report(order_name: str, data_type: str, data = None):
    Path(f"commands/{order_name}").mkdir(parents=True, exist_ok=True)
    with open(file_template.format(order_name, data_type, 'rule'), 'w') as output:
        output.write(rule_template.format(order_name, data_type.upper(), strip_order_date(order_name)))
    # TODO: Rules differ only by data type, rewrite to one instruction

    with open(file_template.format(order_name, data_type, 'list'), 'w') as output:
        output.writelines([list_template.format(item, data_type.upper(), order_name) for item in data])
