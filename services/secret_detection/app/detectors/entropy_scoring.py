import math
from collections import Counter

class EntropyScorer:
    def __init__(self):
        pass

    def calculate_shannon_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        counts = Counter(text)
        for count in counts.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        return entropy

    def get_character_diversity(self, text: str) -> dict:
        has_upper = any(c.isupper() for c in text)
        has_lower = any(c.islower() for c in text)
        has_digit = any(c.isdigit() for c in text)
        has_symbol = any(not c.isalnum() for c in text)
        
        return {
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_symbol": has_symbol,
            "diversity_score": sum([has_upper, has_lower, has_digit, has_symbol])
        }

    def score(self, text: str) -> dict:
        entropy = self.calculate_shannon_entropy(text)
        diversity = self.get_character_diversity(text)
        
        # Base64 strings typically have higher entropy (>4.5)
        # Hex strings have lower entropy (around 3-4)
        
        confidence_boost = 0.0
        
        # Simple heuristic
        if entropy > 4.5 and diversity["diversity_score"] >= 3:
            confidence_boost = 45.0
        elif entropy > 3.5 and diversity["diversity_score"] >= 2:
            confidence_boost = 25.0
            
        return {
            "entropy": entropy,
            "diversity_score": diversity["diversity_score"],
            "confidence_boost": confidence_boost
        }
