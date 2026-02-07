from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class Finding:
    scope: str
    observation: str
    severity: Severity
    explanation: str
    recommendation: str
