from time import sleep
import os

from schemas.model_result import ModelResult
from services.model import LinkModel
from services.vault_manager import Vault


class Analyzer:
    def __init__(
        self,
    ) -> None:
        self.model = LinkModel(virustotal_api_key=os.environ["VIRUSTOTAL_KEY"])

    def analyze_input(self, text: str, vault: Vault) -> ModelResult:
        model_output = self.model.input_score(text, vault)
        sleep(1)

        return model_output

    def analyze_output(self, text: str, vault: Vault) -> ModelResult:
        model_output = self.model.output_score(text, vault)
        sleep(1)

        return model_output
