from models.vault import Vault
from schemas.model_result import ModelResult, Reason
from utils.keywords_generator import generate_injection_keywords
from utils.string_normalizer import normalize_string, get_input_substrings
from typing import List, Tuple
from difflib import SequenceMatcher


class SequenceMatchModel:
    """
    Анализатор для обнаружения инъекций команд на основе SequenceMatcher.
    """
    
    def input_score(self, text: str, vault: Vault) -> ModelResult:
        metric, reasons = self.detect_prompt_injection(text)
        reject_flg = metric > vault.threshold_input

        model_output = ModelResult(
            metric=metric, reasons=reasons, reject_flg=reject_flg
        )

        return model_output

    def output_score(self, text: str, vault: Vault) -> ModelResult:
        metric, reasons = self.detect_prompt_injection(text)
        reject_flg = metric > vault.threshold_output

        model_output = ModelResult(
            metric=metric, reasons=reasons, reject_flg=reject_flg
        )

        return model_output
    
    def detect_prompt_injection(self, input: str) -> Tuple[float, List[Reason]]:
        highest_score = 0
        start_index = -1
        end_index = -1

        for keyword_string in generate_injection_keywords():
            normalized_keyword_string = normalize_string(keyword_string)
            keywords = normalized_keyword_string.split(" ")

            # Генерация подстрок
            input_substrings = get_input_substrings(input, len(keywords))

            # Проверка подстрок
            for i, substring in enumerate(input_substrings):
                similarity_score = SequenceMatcher(None, substring, normalized_keyword_string).ratio()

                if similarity_score > highest_score:
                    highest_score = similarity_score
                    
                    # Найдем начало и конец подстроки в оригинальной строке
                    words_in_input_string = input.split(" ")
                    start_index = len(" ".join(words_in_input_string[:i])) + (1 if i > 0 else 0)
                    end_index = start_index + len(substring)

        return highest_score, [Reason(start=start_index, stop=end_index)]