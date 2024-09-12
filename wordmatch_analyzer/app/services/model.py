from models.vault import Vault
from schemas.model_result import ModelResult, Reason
from typing import List, Tuple
from utils.keywords_generator import VERBS
from utils.string_normalizer import normalize_string


class WordMatchModel:
    """
    Анализатор для обнаружения инъекций команд на основе количества совпадающих слов.
    Возвращает общий скор и список кортежей (слово, скор). Выводит каждое слово только один раз.
    """
    
    def input_score(self, text: str, vault: Vault) -> ModelResult:
        metric, reasons = self.detect_prompt_injection(text)
        reject_flg = metric > vault.max_allowed_words_matched_input

        model_output = ModelResult(
            metric=metric, reasons=reasons, reject_flg=reject_flg
        )

        return model_output

    def output_score(self, text: str, vault: Vault) -> ModelResult:
        metric, reasons = self.detect_prompt_injection(text)
        reject_flg = metric > vault.max_allowed_words_matched_output

        model_output = ModelResult(
            metric=metric, reasons=reasons, reject_flg=reject_flg
        )

        return model_output
    
    def detect_prompt_injection(self, input: str) -> Tuple[float, List[Reason]]:
        """
        Метод для определения инъекции на основе количества совпадающих слов.
        Возвращает общий скор и список кортежей (слово, скор). Каждое слово выводится один раз.
        """
        injection_words = []
        input_words = input.split()
        normalized_input_words = [normalize_string(_) for _ in input_words]
        self.model = [normalize_string(i) for i in VERBS]
        for normalized_word, original_word in zip(normalized_input_words, input_words):
            if normalized_word in self.model:
                injection_words.append(original_word)

        return len(injection_words), []