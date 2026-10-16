from typing import List, Dict, Any
from app.schemas import Finding
from app.detectors.vendor_signatures import VendorSignatureDetector
from app.detectors.structural_context import StructuralContextDetector
from app.detectors.entropy_scoring import EntropyScorer
from app.detectors.suppression import SuppressionFilter

class SecretScorer:
    def __init__(self):
        self.vendor_detector = VendorSignatureDetector()
        self.structural_detector = StructuralContextDetector()
        self.entropy_scorer = EntropyScorer()
        self.suppression_filter = SuppressionFilter()

    def mask_secret(self, secret: str) -> str:
        if len(secret) <= 8:
            return "***"
        return f"{secret[:4]}***{secret[-4:]}"

    def score_findings(self, text: str, file_path: str) -> List[Finding]:
        raw_findings = []
        
        # Layer A: Vendor Sigs
        raw_findings.extend(list(self.vendor_detector.scan(text, file_path)))
        
        # Layer B: Structural Context
        raw_findings.extend(list(self.structural_detector.scan(text, file_path)))
        
        # Deduplicate findings based on overlapping secret values
        # If a vendor pattern matches, it usually takes precedence over structural
        deduped = []
        seen_starts = set()
        
        # Sort so vendor signatures come first, then longest secret
        raw_findings.sort(key=lambda x: (
            0 if x['match_context'] == 'vendor_regex' else 1, 
            -len(x['secret_value'])
        ))
        
        # Layer C & D & E processing
        final_findings = []
        
        for raw in raw_findings:
            # deduplication logic
            secret = raw['secret_value']
            # naive deduplication by line number and secret value substring
            dedup_key = f"{raw['line_number']}:{secret}"
            if dedup_key in seen_starts:
                continue
            seen_starts.add(dedup_key)
            
            # Layer C: Entropy
            entropy_res = self.entropy_scorer.score(secret)
            
            # Layer D: Suppression
            is_suppressed, raw = self.suppression_filter.evaluate(raw)
            if is_suppressed:
                continue
                
            # Layer E: Final Confidence & Reason
            confidence = raw.get("confidence_boost", 0.0)
            
            # Boost if structural + high entropy
            if raw['match_context'] == 'keyword_assignment':
                confidence += entropy_res["confidence_boost"]
                
                # If confidence is still too low, we drop it (likely normal text)
                if confidence < 35.0:
                    continue

            # Reason generation
            if raw.get("is_public_example"):
                reason = "Matches known public example credential — hardcoding pattern is still a finding."
                severity = "low"
            elif raw['match_context'] == 'vendor_regex':
                reason = f"High-confidence vendor signature match: {raw['rule_description']}."
                severity = "critical"
            elif raw['match_context'] == 'connection_string':
                reason = "Embedded credential in connection string."
                severity = "high"
            else:
                reason = f"{raw['rule_description']}; High entropy ({entropy_res['entropy']:.2f}) value."
                severity = "high"
                
            # Clamp confidence and scale to 0.0 - 1.0
            confidence = min(max(confidence, 0.0), 100.0) / 100.0

            # Derive category from detector_id
            cat = raw['detector_id'].split(':')[-1] if ':' in raw['detector_id'] else raw['detector_id']
            
            safe_reason = reason or "Secret detected in code."
            safe_remediation = "Remove the hardcoded secret, rotate it, and use a secrets manager or environment variables."

            final_findings.append(Finding(
                detector_id=raw['detector_id'],
                file_path=raw['file_path'],
                line_number=raw['line_number'],
                location=f"{raw['file_path']}:{raw['line_number']}",
                category=cat,
                preview=self.mask_secret(secret),
                confidence=confidence,
                severity=severity,
                reason=safe_reason,
                remediation=safe_remediation,
                details={
                    "reason": safe_reason,
                    "remediation": safe_remediation
                }
            ))
            
        return final_findings
