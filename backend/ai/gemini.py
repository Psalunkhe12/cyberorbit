"""
CyberOrbit Gemini SOC Copilot Module
------------------------------------
Provides automated security alert triage, threat analysis, investigation guidance,
and containment advisories using Google Gemini AI.

Security & Operational Guarantees:
- Gemini API Key is loaded STRICTLY backend-only (never exposed via VITE_ variables to React/frontend).
- Structured JSON output is enforced and schema-validated before storage or return.
- Advisory Mode Only: Gemini output is STRICTLY FOR ADVISORY PURPOSES and CANNOT directly execute security actions.
"""

import os
import re
import json
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional
from backend.config.settings import settings

logger = logging.getLogger("GeminiSOCCopilot")


class GeminiValidationError(ValueError):
    """Raised when Gemini output fails schema validation."""
    pass


class GeminiSOCCopilot:
    """
    Backend-only Gemini SOC Copilot for automated security alert analysis and triage.
    """

    SYSTEM_PROMPT = (
        "You are Gemini SOC Copilot, an expert AI Security Operations analyst embedded in CyberOrbit.\n"
        "Your task is to analyze structured security alerts and produce precise, actionable threat intelligence.\n"
        "You MUST respond ONLY with a valid raw JSON object without markdown formatting, using this exact schema:\n"
        "{\n"
        '  "summary": "<Concise 1-2 sentence executive overview>",\n'
        '  "possible_attack_type": "<Specific security attack classification>",\n'
        '  "evidence_explanation": "<Detailed analysis of telemetry evidence and payload>",\n'
        '  "recommended_investigation_steps": ["<Step 1>", "<Step 2>", ...],\n'
        '  "recommended_containment_options": ["<Option 1>", "<Option 2>", ...],\n'
        '  "confidence": <Float between 0.0 and 1.0>\n'
        "}\n"
        "Do not include any code block quotes, extra text outside JSON, or direct execution commands."
    )

    # Strictly advisory mode: direct action execution is prohibited.
    ALLOW_DIRECT_ACTION_EXECUTION: bool = False

    def __init__(self, api_key: Optional[str] = None, model_name: Optional[str] = None):
        """
        Initialize Gemini SOC Copilot strictly reading backend API keys.
        """
        # Ensure key is backend-only and not pulled from client VITE_ prefixed envs
        raw_key = api_key or getattr(settings, "GEMINI_API_KEY", "") or os.getenv("GEMINI_API_KEY", "")
        
        # Explicit security check to prevent using frontend-exposed keys
        if not raw_key and os.getenv("VITE_GEMINI_API_KEY"):
            logger.warning("[GeminiCopilot Security Warning] VITE_GEMINI_API_KEY detected in environment! Ignoring to prevent API key leakage to client.")
            raw_key = ""

        self.api_key: str = raw_key.strip()
        self.model_name: str = model_name or getattr(settings, "GEMINI_MODEL", "gemini-1.5-flash")

    def is_configured(self) -> bool:
        """Returns True if a valid backend Gemini API key is configured."""
        return bool(self.api_key and len(self.api_key) > 5)

    def analyze_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes a structured security alert and returns validated SOC intelligence.
        
        Args:
            alert: Dictionary containing structured alert telemetry.
            
        Returns:
            Validated dictionary containing:
            - summary (str)
            - possible_attack_type (str)
            - evidence_explanation (str)
            - recommended_investigation_steps (List[str])
            - recommended_containment_options (List[str])
            - confidence (float 0.0 - 1.0)
            - is_advisory_only (bool)
            - requires_analyst_approval (bool)
            - execution_prohibited (bool)
        """
        if not alert or not isinstance(alert, dict):
            return self.fallback_analysis({"title": "Invalid Alert Data"}, reason="Alert payload was empty or invalid.")

        if not self.is_configured():
            logger.info("[GeminiCopilot] No backend Gemini API key configured. Generating rule-based fallback analysis.")
            return self.fallback_analysis(alert, reason="Gemini API key not configured in backend environment.")

        prompt = self._build_prompt(alert)

        try:
            raw_response = self._call_gemini_api(prompt)
            parsed_json = self._parse_json_response(raw_response)
            validated_analysis = self.validate_response(parsed_json)
            
            # Enforce advisory safety metadata (prevent automated direct execution)
            validated_analysis["is_advisory_only"] = True
            validated_analysis["requires_analyst_approval"] = True
            validated_analysis["execution_prohibited"] = not self.ALLOW_DIRECT_ACTION_EXECUTION
            
            return validated_analysis

        except Exception as err:
            logger.error(f"[GeminiCopilot Error] API call or validation failed: {err}")
            return self.fallback_analysis(alert, reason=f"API or validation error: {str(err)}")

    def validate_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates that the response dictionary strictly adheres to the required SOC schema.
        
        Raises:
            GeminiValidationError: If schema rules or data types are violated.
        """
        if not isinstance(response_data, dict):
            raise GeminiValidationError("Response must be a JSON object/dictionary.")

        required_fields = [
            "summary",
            "possible_attack_type",
            "evidence_explanation",
            "recommended_investigation_steps",
            "recommended_containment_options",
            "confidence",
        ]

        missing = [field for field in required_fields if field not in response_data]
        if missing:
            raise GeminiValidationError(f"Missing required fields in Gemini response: {missing}")

        # 1. Summary
        if not isinstance(response_data["summary"], str) or not response_data["summary"].strip():
            raise GeminiValidationError("Field 'summary' must be a non-empty string.")

        # 2. Possible Attack Type
        if not isinstance(response_data["possible_attack_type"], str) or not response_data["possible_attack_type"].strip():
            raise GeminiValidationError("Field 'possible_attack_type' must be a non-empty string.")

        # 3. Evidence Explanation
        if not isinstance(response_data["evidence_explanation"], str) or not response_data["evidence_explanation"].strip():
            raise GeminiValidationError("Field 'evidence_explanation' must be a non-empty string.")

        # 4. Investigation Steps
        steps = response_data["recommended_investigation_steps"]
        if not isinstance(steps, list) or len(steps) == 0:
            raise GeminiValidationError("Field 'recommended_investigation_steps' must be a non-empty list of strings.")
        if not all(isinstance(s, str) and s.strip() for s in steps):
            raise GeminiValidationError("All items in 'recommended_investigation_steps' must be non-empty strings.")

        # 5. Containment Options
        options = response_data["recommended_containment_options"]
        if not isinstance(options, list) or len(options) == 0:
            raise GeminiValidationError("Field 'recommended_containment_options' must be a non-empty list of strings.")
        if not all(isinstance(o, str) and o.strip() for o in options):
            raise GeminiValidationError("All items in 'recommended_containment_options' must be non-empty strings.")

        # 6. Confidence
        conf = response_data["confidence"]
        try:
            conf_float = float(conf)
        except (ValueError, TypeError):
            raise GeminiValidationError(f"Field 'confidence' must be numeric, got: {conf}")

        if not (0.0 <= conf_float <= 1.0):
            conf_float = max(0.0, min(1.0, conf_float))

        validated = {
            "summary": response_data["summary"].strip(),
            "possible_attack_type": response_data["possible_attack_type"].strip(),
            "evidence_explanation": response_data["evidence_explanation"].strip(),
            "recommended_investigation_steps": [s.strip() for s in steps],
            "recommended_containment_options": [o.strip() for o in options],
            "confidence": round(conf_float, 2),
        }

        return validated

    def fallback_analysis(self, alert: Dict[str, Any], reason: str = "") -> Dict[str, Any]:
        """
        Generates a rule-based fallback analysis matching the schema when Gemini is unavailable.
        """
        title = (
            alert.get("title")
            or alert.get("signature")
            or alert.get("event_type")
            or alert.get("rule_name")
            or "Security Telemetry Anomaly"
        )
        severity = str(alert.get("severity") or "MEDIUM").upper()
        src_ip = alert.get("source_ip") or alert.get("src_ip") or "Unknown Source IP"
        dest_ip = alert.get("destination_ip") or alert.get("dest_ip") or "Internal Host"
        dest_port = alert.get("destination_port") or alert.get("dest_port") or "Target Port"
        category = alert.get("category") or alert.get("attack_category") or "Unclassified Security Event"

        summary = f"Detected {severity} severity alert ({title}) targeting host {dest_ip}:{dest_port} from source {src_ip}."
        
        evidence_explanation = (
            f"Alert telemetry indicated suspicious activity matching category '{category}'. "
            f"Source IP {src_ip} initiated network traffic to destination port {dest_port}. "
        )
        if reason:
            evidence_explanation += f"[Offline Fallback: {reason}]"

        investigation_steps = [
            f"Verify network reachability and active connections between {src_ip} and {dest_ip}.",
            f"Inspect system and application logs on target host {dest_ip} around event timestamp.",
            f"Cross-reference source IP {src_ip} with internal threat intelligence database.",
            "Review firewall and IDS logs for payload signatures or scanning behavior.",
        ]

        containment_options = [
            f"Apply temporary firewall rate-limiting or ACL drop rule for source IP {src_ip}.",
            f"Isolate host {dest_ip} from critical subnets if lateral movement is suspected.",
            "Update WAF/IDS signature parameters to block similar request payloads.",
        ]

        confidence_map = {"LOW": 0.55, "MEDIUM": 0.70, "HIGH": 0.85, "CRITICAL": 0.92}
        confidence = confidence_map.get(severity, 0.75)

        analysis = {
            "summary": summary,
            "possible_attack_type": category if category != "Unclassified Security Event" else title,
            "evidence_explanation": evidence_explanation,
            "recommended_investigation_steps": investigation_steps,
            "recommended_containment_options": containment_options,
            "confidence": confidence,
            "is_advisory_only": True,
            "requires_analyst_approval": True,
            "execution_prohibited": True,
        }

        return analysis

    def query_copilot(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        history: Optional[List[Dict[str, str]]] = None
    ) -> str:
        """General SOC copilot inquiry interface."""
        if not self.is_configured():
            return f"[Offline Advisory] Query received: \"{message}\". Recommendation: Inspect alert logs and enforce firewall rules."

        prompt = (
            f"You are Orbit AI, a Senior SOC Security Copilot.\n"
            f"Context: {json.dumps(context or {})}\n"
            f"User Query: {message}\n"
            f"Provide a concise, professional security analysis."
        )

        try:
            return self._call_gemini_api(prompt)
        except Exception as e:
            logger.error(f"[GeminiCopilot Error] query_copilot failed: {e}")
            return "Unable to complete request with Gemini API. Proceeding with local heuristics."

    def generate_incident_briefing(self, anomalies: List[Dict[str, Any]]) -> str:
        """Generates executive 3-bullet incident summary."""
        if not self.is_configured():
            return "1. High risk anomaly detected across internal assets.\n2. Potential probing from external ASNs.\n3. Recommend enforcing rate-limiting and reviewing firewall logs."

        prompt = f"Generate a 3-bullet executive incident briefing for these anomalies:\n{json.dumps(anomalies[:10], indent=2)}"
        try:
            return self._call_gemini_api(prompt)
        except Exception as err:
            logger.error(f"[GeminiCopilot Error] Briefing generation failed: {err}")
            return "1. Multiple security anomalies logged.\n2. Potential scan surge detected.\n3. Automated containment protocols pending analyst review."

    def analyze_packet_payload(self, anomaly: Dict[str, Any]) -> Dict[str, Any]:
        """Performs deep packet payload triage returning advisory analysis."""
        analysis = self.analyze_alert(anomaly)
        return {
            "analysis": f"Summary: {analysis['summary']}\nPossible Attack: {analysis['possible_attack_type']}\nEvidence: {analysis['evidence_explanation']}",
            "recommendedActions": analysis["recommended_containment_options"],
            "is_advisory_only": True
        }

    def _build_prompt(self, alert: Dict[str, Any]) -> str:
        """Constructs a structured prompt for Gemini JSON response."""
        alert_json = json.dumps(alert, indent=2, default=str)
        return (
            f"{self.SYSTEM_PROMPT}\n\n"
            f"SECURITY ALERT TELEMETRY:\n{alert_json}\n\n"
            f"Analyze the security alert above and generate the JSON object strictly matching the schema."
        )

    def _call_gemini_api(self, prompt: str) -> str:
        """
        Executes REST API call to Gemini generateContent endpoint.
        Uses backend-only API key.
        """
        model = self.model_name
        if model.startswith("models/"):
            model = model.replace("models/", "")

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json"
            }
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                candidates = result.get("candidates", [])
                if not candidates:
                    raise ValueError("Gemini API returned no response candidates.")
                
                parts = candidates[0].get("content", {}).get("parts", [])
                if not parts:
                    raise ValueError("Gemini response contained no content parts.")
                
                return parts[0].get("text", "")
        except urllib.error.HTTPError as http_err:
            error_body = http_err.read().decode("utf-8", errors="ignore")
            raise ValueError(f"HTTP {http_err.code} from Gemini API: {error_body}")
        except Exception as e:
            raise ValueError(f"Gemini API request failed: {e}")

    def _parse_json_response(self, text: str) -> Dict[str, Any]:
        """Strips markdown formatting if present and parses raw JSON."""
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r"\s*```$", "", cleaned)
            cleaned = cleaned.strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as err:
            raise GeminiValidationError(f"Failed to parse Gemini output as JSON: {err}. Raw text: {text[:200]}")


# Backward compatibility alias
OrbitAICopilot = GeminiSOCCopilot
