from uuid import UUID

from clickhouse_connect.driver.client import Client
from models.product import Product


def get_product(client: Client, api_key: UUID) -> Product:
    stmt = "SELECT * FROM products WHERE api_key=%(api_key)s"
    row = client.query(stmt, parameters={"api_key": api_key}).first_item
    product = Product(**row)
    return product
