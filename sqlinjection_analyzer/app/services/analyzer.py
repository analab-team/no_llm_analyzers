from time import sleep

from schemas.model_result import ModelResult
from services.model import SQLInjectionModel
from services.vault_manager import Vault


class Analyzer:
    def __init__(
        self,
    ) -> None:
        self.model = SQLInjectionModel()

    def analyze_input(self, text: str, vault: Vault) -> ModelResult:
        model_output = self.model.input_score(text, vault)
        sleep(1)

        return model_output

    def analyze_output(self, text: str, vault: Vault) -> ModelResult:
        model_output = self.model.output_score(text, vault)
        sleep(1)

        return model_output
