from models.vault import Vault
from schemas.model_result import ModelResult, Reason
import re
import base64
import binascii
from typing import List, Tuple
from nltk.corpus import words
import nltk
nltk.download('words')

class Base64Model:
    """
    Анализатор для обнаружения Base64-кодированных подстрок.
    Если найдена подстрока, содержащая Base64-код, возвращает скор 1 и список кортежей (позиции начала и конца подстроки, 1).
    """
    def input_score(self, text: str, vault: Vault) -> ModelResult:
        metric, reasons = Base64Model.detect_base64_in_text(text)
        reject_flg = metric > vault.max_base64_matches_input

        model_output = ModelResult(
            metric=metric, reasons=reasons, reject_flg=reject_flg
        )

        return model_output

    def output_score(self, text: str, vault: Vault) -> ModelResult:
        metric, reasons = Base64Model.detect_base64_in_text(text)
        reject_flg = metric > vault.max_base64_matches_output

        model_output = ModelResult(
            metric=metric, reasons=reasons, reject_flg=reject_flg
        )

        return model_output
    
    @staticmethod
    def detect_base64_in_text(input: str) -> Tuple[float, List[Reason]]:
        """
        Метод для определения наличия Base64-кодированных подстрок в тексте.
        Возвращает скор 1, если Base64-код найден, и список кортежей (позиция начала и конца подстроки, 1).
        """
        # Регулярное выражение для поиска кандидатов на Base64
        # Ищем последовательности длиннее 15 символов, состоящие из символов, допустимых в Base64
        base64_pattern = r'[A-Za-z0-9+/=]{15,}'

        potential_base64_matches = re.finditer(base64_pattern, input)
        # Получим список всех известных английских слов
        word_list = set(words.words())

        reasons = []
        for match in potential_base64_matches:
            candidate = match.group()

            # Проверим, является ли эта последовательность существующим словом
            if candidate.lower() in word_list:
                continue

            try:
                decoded_data = base64.b64decode(candidate, validate=True)
                reasons.append(Reason(start=match.start(), stop=match.end()))
            except (binascii.Error, ValueError):
                continue
        return len(reasons), reasons
