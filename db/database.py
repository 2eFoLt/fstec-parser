import sqlite3
from getmecolored import pref_good, pref_fail, pref_info, pref_warn
from db.database_templates import select_t, cond_select_t, insert_t, insert_t_order


class DBInterface:
    connection_cur = None
    cursor_cur = None
    database_name = ""

    def __init__(self, db_name="fmbasoc.db"):
        self.database_name = db_name

    def __del__(self):
        print(f'{pref_info()}Database destructor called')
        if self.connection_cur is not None:
            print(f'{pref_warn()}Database is still connected, disconnecting...')
            self.disconnect()

    def connect(self, db_name="fmbasoc.db"):
        if db_name == "fmbasoc.db": print(f'{pref_warn()}No database name passed, using default value.')
        self.connection_cur = sqlite3.connect(self.database_name or db_name)
        if self.connection_cur is None:
            print(f'{pref_fail()}Database connection failed')
        else:
            print(f'{pref_good()}Database connection successful')
            self.cursor_cur = self.connection_cur.cursor()
            print(f'{pref_good()}Database cursor created')

    def disconnect(self):
        print(f'{pref_info()}Closing connection to database')
        if self.cursor_cur is not None:
            self.cursor_cur.close()
            self.cursor_cur = None
        if self.connection_cur is not None:
            self.connection_cur.close()
            self.connection_cur = None

    def setup(self):
        self.cursor_cur.execute("CREATE TABLE IF NOT EXISTS orders(order_date_number)")
        self.cursor_cur.execute("CREATE TABLE IF NOT EXISTS ip_table(ip_address, order_number)")
        self.cursor_cur.execute("CREATE TABLE IF NOT EXISTS fqdn_table(fqdn, order_number)")
        print(self.cursor_cur.execute('''SELECT name FROM sqlite_master''').fetchall())
        self.connection_cur.commit()
        self.disconnect()

    def select(self, table_name, column_name, condition=None):
        if condition is None:
            self.cursor_cur.execute(select_t.format(column_name, table_name))
        else:
            self.cursor_cur.execute(cond_select_t.format(column_name, table_name, condition))
        return self.cursor_cur.fetchall()

    def insert(self, table_name, data: list, orders=False):
        if orders:
            self.cursor_cur.executemany(insert_t_order, data)
        else:
            self.cursor_cur.executemany(insert_t.format(table_name), data)
        self.connection_cur.commit()

    def prepare_data(self, data: list, cure):
        if cure:
            return [(item, cure) for item in data]
        else:
            return [(item,) for item in data]

    def add_data(self, table_name, data: list, column_name, order_number=None):
        tmp_data = self.check_if_exists(table_name, column_name, data)
        if len(tmp_data) == 0: return
        cured_data = self.prepare_data(tmp_data, order_number)
        if order_number is not None:
            self.insert(table_name, cured_data)
        else:
            self.insert(table_name, cured_data, True)

    # TODO:
    def get_order(self, target_ip):
        pass

    # TODO:
    def check_in_order(self, order_number):
        pass

    def check_if_exists(self, table_name, column_name, data):
        output = []
        for item in data:
            result = self.select(table_name, column_name, f'{column_name} = "{item}"')
            if len(result) == 0: output.append(item)
        return output


# db = DBInterface()
# db.connect()
# db.setup()
# db.disconnect()
