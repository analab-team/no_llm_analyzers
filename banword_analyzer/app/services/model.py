from models.vault import Vault
from schemas.model_result import ModelResult, Reason
import re
from typing import List, Tuple
from core.config import PROJECT_PATH


class BanwordModel:
    """
    Анализатор для обнаружения Base64-кодированных подстрок.
    Если найдена подстрока, содержащая Base64-код, возвращает скор 1 и список кортежей (позиции начала и конца подстроки, 1).
    """
    def __init__(self):
        with open(PROJECT_PATH / "data" / "swearwords.txt", "r") as f:
            self.swear_words = set([line.strip().lower() for line in f.readlines()])
        with open(PROJECT_PATH / "data" / "narcowords.txt", "r") as f:
            self.narco_words = set([line.strip().lower() for line in f.readlines()])
        self.banwords = self.swear_words | self.narco_words
    
    def input_score(self, text: str, vault: Vault) -> ModelResult:
        self.banwords -= set(vault.ignoring_banwords_input)
        metric, reasons = self.detect_banwords(text)
        reject_flg = metric > vault.max_allowed_banwords_input

        model_output = ModelResult(
            metric=metric, reasons=reasons, reject_flg=reject_flg
        )

        return model_output

    def output_score(self, text: str, vault: Vault) -> ModelResult:
        self.banwords -= set(vault.ignoring_banwords_output)
        metric, reasons = self.detect_banwords(text)
        reject_flg = metric > vault.max_allowed_banwords_output

        model_output = ModelResult(
            metric=metric, reasons=reasons, reject_flg=reject_flg
        )

        return model_output
    
    def detect_banwords(self, input: str) -> Tuple[float, List[Reason]]:
        """
        Метод для определения инъекции на основе совпадения с банвордами.
        Возвращает скор (1, если найден хотя бы один банворд, иначе 0) и словарь с банвордами и их позициями.
        """
        word_scores = []
        for banword in self.banwords:
            matches = list(re.finditer(re.escape(banword), input))
            for match in matches:
                word_scores.append(Reason(start=match.start(), stop=match.end()))

        return len(word_scores), word_scores