import httpx
from schemas.alert import Alert


class AlertingService:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint

    async def send_notification(self, alert: Alert):
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(self.endpoint, json=alert.model_dump())
                response.raise_for_status()
            except httpx.HTTPStatusError as e:
                print(f"Error response {e.response.status_code}: {e.response.text}")
            except httpx.RequestError as e:
                print(f"An error occurred while requesting {e.request.url!r}: {e}")
