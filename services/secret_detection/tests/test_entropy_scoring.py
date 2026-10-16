import pytest
from app.detectors.entropy_scoring import EntropyScorer

def test_entropy_shannon():
    scorer = EntropyScorer()
    
    low_entropy = "aaaaabbbbb"
    high_entropy = "aB3$kL9#mPq"
    
    assert scorer.calculate_shannon_entropy(low_entropy) < 2.0
    assert scorer.calculate_shannon_entropy(high_entropy) > 3.0

def test_character_diversity():
    scorer = EntropyScorer()
    text = "aB3$"
    div = scorer.get_character_diversity(text)
    assert div["has_upper"] is True
    assert div["has_lower"] is True
    assert div["has_digit"] is True
    assert div["has_symbol"] is True
    assert div["diversity_score"] == 4
