"""
Forensic evidence extractors for the 12 standard questions.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..db.evidence import Evidence, EvidenceDB


@dataclass
class QuestionAnswer:
    """Answer to a forensic question with attribution."""
    question_id: str
    question: str
    answer: str
    confidence: float
    sources: List[str]  # Source files/artifacts
    evidence_count: int
    details: List[Dict[str, Any]]


# The 12 standard forensic backgrounding questions
STANDARD_QUESTIONS = [
    {
        "id": "Q1",
        "question": "What is the computer name?",
        "artifact_types": ["registry", "hostname"],
        "extractor": "extract_computer_name"
    },
    {
        "id": "Q2",
        "question": "What is the computer make, model, and serial number?",
        "artifact_types": ["registry", "smbios", "wmi"],
        "extractor": "extract_hardware_info"
    },
    {
        "id": "Q3",
        "question": "What internal hard drives are present?",
        "artifact_types": ["disk", "registry", "wmi"],
        "extractor": "extract_hard_drives"
    },
    {
        "id": "Q4",
        "question": "What user accounts exist and their activity levels?",
        "artifact_types": ["sam", "security", "user"],
        "extractor": "extract_user_accounts"
    },
    {
        "id": "Q5",
        "question": "Who is the primary user of this system?",
        "artifact_types": ["sam", "security", "user", "ntuser"],
        "extractor": "extract_primary_user"
    },
    {
        "id": "Q6",
        "question": "Is there evidence of anti-forensic activity?",
        "artifact_types": ["prefetch", "usnjrnl", "evtx", "registry"],
        "extractor": "extract_antiforensic"
    },
    {
        "id": "Q7",
        "question": "What USB or removable storage devices were connected?",
        "artifact_types": ["usbstor", "setupapi", "registry"],
        "extractor": "extract_usb_devices"
    },
    {
        "id": "Q8",
        "question": "What files were transferred to/from removable storage?",
        "artifact_types": ["shellbag", "lnk", "usnjrnl", "jumplist"],
        "extractor": "extract_file_transfers"
    },
    {
        "id": "Q9",
        "question": "Is there evidence of cloud storage usage?",
        "artifact_types": ["browser", "registry", "file"],
        "extractor": "extract_cloud_storage"
    },
    {
        "id": "Q10",
        "question": "Are there any screenshot artifacts?",
        "artifact_types": ["file", "prefetch"],
        "extractor": "extract_screenshots"
    },
    {
        "id": "Q11",
        "question": "What documents were printed?",
        "artifact_types": ["spool", "evtx", "registry"],
        "extractor": "extract_print_jobs"
    },
    {
        "id": "Q12",
        "question": "What software was installed or modified?",
        "artifact_types": ["amcache", "registry", "prefetch"],
        "extractor": "extract_software"
    },
]


class ForensicExtractor:
    """Extracts answers to forensic questions from evidence database."""
    
    def __init__(self, db: EvidenceDB, case_id: str):
        self.db = db
        self.case_id = case_id
    
    def answer_all_questions(self) -> List[QuestionAnswer]:
        """Answer all 12 standard questions."""
        answers = []
        for q in STANDARD_QUESTIONS:
            extractor_name = q["extractor"]
            extractor = getattr(self, extractor_name, None)
            if extractor:
                answer = extractor(q)
                answers.append(answer)
        return answers
    
    def answer_question(self, question_id: str) -> Optional[QuestionAnswer]:
        """Answer a specific question by ID."""
        for q in STANDARD_QUESTIONS:
            if q["id"] == question_id:
                extractor_name = q["extractor"]
                extractor = getattr(self, extractor_name, None)
                if extractor:
                    return extractor(q)
        return None
    
    def _get_evidence(self, artifact_types: List[str], limit: int = 500) -> List[Evidence]:
        """Get evidence matching artifact types."""
        all_evidence = []
        for atype in artifact_types:
            evidence = self.db.get_evidence(self.case_id, artifact_type=atype, limit=limit)
            all_evidence.extend(evidence)
        return all_evidence
    
    # =========================================================================
    # Q1: Computer Name
    # =========================================================================
    def extract_computer_name(self, q: Dict) -> QuestionAnswer:
        evidence = self._get_evidence(q["artifact_types"])
        
        computer_name = None
        sources = []
        
        # Look for computer name in registry evidence
        for e in evidence:
            data = e.data
            summary_lower = e.summary.lower()
            
            # Check registry paths
            if "computername" in summary_lower or "hostname" in summary_lower:
                if "value_data" in data:
                    computer_name = data["value_data"]
                    sources.append(e.source_file)
                    break
                elif "computer_name" in data:
                    computer_name = data["computer_name"]
                    sources.append(e.source_file)
                    break
            
            # Check for hostname in various formats
            for key in ["hostname", "computer_name", "ComputerName", "name"]:
                if key in data and data[key]:
                    computer_name = str(data[key])
                    sources.append(e.source_file)
                    break
            
            if computer_name:
                break
        
        if computer_name:
            answer = f"Computer name: {computer_name}"
            confidence = 0.95
        else:
            answer = "Computer name not found in available evidence"
            confidence = 0.0
        
        return QuestionAnswer(
            question_id=q["id"],
            question=q["question"],
            answer=answer,
            confidence=confidence,
            sources=list(set(sources)),
            evidence_count=len(evidence),
            details=[{"computer_name": computer_name}] if computer_name else []
        )
    
    # =========================================================================
    # Q2: Hardware Info
    # =========================================================================
    def extract_hardware_info(self, q: Dict) -> QuestionAnswer:
        evidence = self._get_evidence(q["artifact_types"])
        
        hw_info = {"make": None, "model": None, "serial": None}
        sources = []
        
        for e in evidence:
            data = e.data
            summary_lower = e.summary.lower()
            
            # SMBIOS/WMI data
            if "manufacturer" in data:
                hw_info["make"] = data["manufacturer"]
                sources.append(e.source_file)
            if "model" in data:
                hw_info["model"] = data["model"]
                sources.append(e.source_file)
            if "serial" in data or "serial_number" in data:
                hw_info["serial"] = data.get("serial") or data.get("serial_number")
                sources.append(e.source_file)
            
            # Registry paths for system info
            if "systeminfo" in summary_lower or "bios" in summary_lower:
                for key in ["SystemManufacturer", "SystemProductName", "BaseBoardProduct"]:
                    if key in data:
                        if "manufacturer" in key.lower():
                            hw_info["make"] = data[key]
                        elif "product" in key.lower():
                            hw_info["model"] = data[key]
                        sources.append(e.source_file)
        
        parts = []
        if hw_info["make"]:
            parts.append(f"Make: {hw_info['make']}")
        if hw_info["model"]:
            parts.append(f"Model: {hw_info['model']}")
        if hw_info["serial"]:
            parts.append(f"Serial: {hw_info['serial']}")
        
        if parts:
            answer = ", ".join(parts)
            confidence = len([v for v in hw_info.values() if v]) / 3.0
        else:
            answer = "Hardware information not found"
            confidence = 0.0
        
        return QuestionAnswer(
            question_id=q["id"],
            question=q["question"],
            answer=answer,
            confidence=confidence,
            sources=list(set(sources)),
            evidence_count=len(evidence),
            details=[hw_info]
        )
    
    # =========================================================================
    # Q3: Hard Drives
    # =========================================================================
    def extract_hard_drives(self, q: Dict) -> QuestionAnswer:
        evidence = self._get_evidence(q["artifact_types"])
        
        drives = []
        sources = []
        
        for e in evidence:
            data = e.data
            summary_lower = e.summary.lower()
            
            if "disk" in summary_lower or "drive" in summary_lower or "volume" in summary_lower:
                drive_info = {}
                
                for key in ["model", "serial", "size", "capacity", "device_id", "drive_letter"]:
                    if key in data:
                        drive_info[key] = data[key]
                
                if drive_info:
                    drives.append(drive_info)
                    sources.append(e.source_file)
        
        # Deduplicate by serial if available
        seen = set()
        unique_drives = []
        for d in drives:
            key = d.get("serial") or d.get("model") or str(d)
            if key not in seen:
                seen.add(key)
                unique_drives.append(d)
        
        if unique_drives:
            lines = [f"{len(unique_drives)} drive(s) found:"]
            for d in unique_drives[:5]:
                model = d.get("model", "Unknown")
                serial = d.get("serial", "N/A")
                size = d.get("size") or d.get("capacity", "Unknown")
                lines.append(f"  - {model} (S/N: {serial}, Size: {size})")
            answer = "\n".join(lines)
            confidence = 0.85
        else:
            answer = "No hard drive information found"
            confidence = 0.0
        
        return QuestionAnswer(
            question_id=q["id"],
            question=q["question"],
            answer=answer,
            confidence=confidence,
            sources=list(set(sources)),
            evidence_count=len(evidence),
            details=unique_drives
        )
    
    # =========================================================================
    # Q4: User Accounts
    # =========================================================================
    def extract_user_accounts(self, q: Dict) -> QuestionAnswer:
        evidence = self._get_evidence(q["artifact_types"])
        
        users = {}
        sources = []
        
        for e in evidence:
            data = e.data
            summary_lower = e.summary.lower()
            
            username = data.get("username") or data.get("user") or data.get("account_name")
            if username:
                if username not in users:
                    users[username] = {
                        "username": username,
                        "sid": data.get("sid", ""),
                        "last_logon": None,
                        "logon_count": 0,
                        "is_admin": data.get("is_admin", False)
                    }
                sources.append(e.source_file)
                
                # Update with additional info
                if "last_logon" in data:
                    users[username]["last_logon"] = data["last_logon"]
                if "logon_count" in data:
                    users[username]["logon_count"] = data["logon_count"]
        
        if users:
            lines = [f"{len(users)} user account(s) found:"]
            for u in list(users.values())[:10]:
                admin_str = " [ADMIN]" if u.get("is_admin") else ""
                lines.append(f"  - {u['username']}{admin_str} (SID: {u.get('sid', 'N/A')})")
            answer = "\n".join(lines)
            confidence = 0.90
        else:
            answer = "No user accounts found in evidence"
            confidence = 0.0
        
        return QuestionAnswer(
            question_id=q["id"],
            question=q["question"],
            answer=answer,
            confidence=confidence,
            sources=list(set(sources)),
            evidence_count=len(evidence),
            details=list(users.values())
        )
    
    # =========================================================================
    # Q5: Primary User
    # =========================================================================
    def extract_primary_user(self, q: Dict) -> QuestionAnswer:
        # First get all users
        users_answer = self.extract_user_accounts({"id": "Q4", "question": "", "artifact_types": q["artifact_types"], "extractor": ""})
        
        if not users_answer.details:
            return QuestionAnswer(
                question_id=q["id"],
                question=q["question"],
                answer="Cannot determine primary user - no user accounts found",
                confidence=0.0,
                sources=[],
                evidence_count=0,
                details=[]
            )
        
        # Score users by activity
        scored_users = []
        for user in users_answer.details:
            score = 0
            score += user.get("logon_count", 0)
            if user.get("last_logon"):
                score += 10  # Bonus for recent activity
            scored_users.append((score, user))
        
        scored_users.sort(reverse=True, key=lambda x: x[0])
        primary = scored_users[0][1] if scored_users else None
        
        if primary:
            answer = f"Primary user: {primary['username']} (based on activity analysis)"
            confidence = 0.75  # Activity-based determination has lower confidence
        else:
            answer = "Cannot determine primary user"
            confidence = 0.0
        
        return QuestionAnswer(
            question_id=q["id"],
            question=q["question"],
            answer=answer,
            confidence=confidence,
            sources=users_answer.sources,
            evidence_count=users_answer.evidence_count,
            details=[primary] if primary else []
        )
    
    # =========================================================================
    # Q6: Anti-Forensic Activity
    # =========================================================================
    def extract_antiforensic(self, q: Dict) -> QuestionAnswer:
        evidence = self._get_evidence(q["artifact_types"])
        
        indicators = []
        sources = []
        
        # Patterns indicating anti-forensic activity
        af_patterns = [
            (r"sdelete", "Secure deletion tool"),
            (r"ccleaner", "System cleaner"),
            (r"eraser", "Secure eraser"),
            (r"bleachbit", "System cleaner"),
            (r"cipher.*?/w", "Secure wipe"),
            (r"wevtutil.*?cl", "Event log clearing"),
            (r"clear-eventlog", "PowerShell log clearing"),
            (r"timestomp", "Timestamp manipulation"),
            (r"usn.*?delete", "USN journal deletion"),
        ]
        
        for e in evidence:
            summary_lower = e.summary.lower()
            
            for pattern, description in af_patterns:
                if re.search(pattern, summary_lower, re.IGNORECASE):
                    indicators.append({
                        "type": description,
                        "evidence": e.summary[:100],
                        "timestamp": e.timestamp,
                        "source": e.source_file
                    })
                    sources.append(e.source_file)
            
            # Check for cleared event logs
            if "event log" in summary_lower and ("clear" in summary_lower or "wipe" in summary_lower):
                indicators.append({
                    "type": "Event log cleared",
                    "evidence": e.summary[:100],
                    "timestamp": e.timestamp,
                    "source": e.source_file
                })
                sources.append(e.source_file)
        
        if indicators:
            lines = [f"⚠️ {len(indicators)} anti-forensic indicator(s) found:"]
            for ind in indicators[:5]:
                lines.append(f"  - {ind['type']}: {ind['evidence'][:50]}...")
            answer = "\n".join(lines)
            confidence = 0.85
        else:
            answer = "No obvious anti-forensic activity detected"
            confidence = 0.70  # Absence of evidence isn't evidence of absence
        
        return QuestionAnswer(
            question_id=q["id"],
            question=q["question"],
            answer=answer,
            confidence=confidence,
            sources=list(set(sources)),
            evidence_count=len(evidence),
            details=indicators
        )
    
    # =========================================================================
    # Q7: USB Devices
    # =========================================================================
    def extract_usb_devices(self, q: Dict) -> QuestionAnswer:
        evidence = self._get_evidence(q["artifact_types"])
        
        devices = {}
        sources = []
        
        for e in evidence:
            data = e.data
            summary_lower = e.summary.lower()
            
            if "usb" in summary_lower or "removable" in summary_lower or "usbstor" in summary_lower:
                # Try to extract device info
                serial = data.get("serial") or data.get("serial_number") or data.get("device_id", "")
                vendor = data.get("vendor") or data.get("manufacturer", "Unknown")
                product = data.get("product") or data.get("model", "Unknown")
                
                if serial:
                    key = serial
                else:
                    key = f"{vendor}_{product}"
                
                if key not in devices:
                    devices[key] = {
                        "vendor": vendor,
                        "product": product,
                        "serial": serial,
                        "first_seen": e.timestamp,
                        "last_seen": e.timestamp
                    }
                else:
                    devices[key]["first_seen"] = min(devices[key]["first_seen"], e.timestamp)
                    devices[key]["last_seen"] = max(devices[key]["last_seen"], e.timestamp)
                
                sources.append(e.source_file)
        
        if devices:
            from datetime import datetime
            lines = [f"{len(devices)} USB device(s) found:"]
            for d in list(devices.values())[:10]:
                first = datetime.fromtimestamp(d["first_seen"]).strftime("%Y-%m-%d")
                last = datetime.fromtimestamp(d["last_seen"]).strftime("%Y-%m-%d")
                lines.append(f"  - {d['vendor']} {d['product']} (S/N: {d['serial'] or 'N/A'})")
                lines.append(f"    First: {first}, Last: {last}")
            answer = "\n".join(lines)
            confidence = 0.90
        else:
            answer = "No USB devices found in evidence"
            confidence = 0.0
        
        return QuestionAnswer(
            question_id=q["id"],
            question=q["question"],
            answer=answer,
            confidence=confidence,
            sources=list(set(sources)),
            evidence_count=len(evidence),
            details=list(devices.values())
        )
    
    # =========================================================================
    # Q8: File Transfers
    # =========================================================================
    def extract_file_transfers(self, q: Dict) -> QuestionAnswer:
        evidence = self._get_evidence(q["artifact_types"])
        
        transfers = []
        sources = []
        
        # Patterns indicating removable storage paths
        removable_patterns = [
            r"[A-Z]:\\",  # Drive letters
            r"removable",
            r"usb",
            r"external",
        ]
        
        for e in evidence:
            data = e.data
            summary_lower = e.summary.lower()
            
            # Look for file operations involving removable storage
            path = data.get("path") or data.get("filename") or data.get("target_path", "")
            
            if any(re.search(p, path, re.IGNORECASE) for p in removable_patterns):
                transfers.append({
                    "path": path,
                    "operation": data.get("operation", "access"),
                    "timestamp": e.timestamp,
                    "source": e.source_file
                })
                sources.append(e.source_file)
            
            # Check LNK files pointing to removable storage
            if "lnk" in summary_lower and "target" in data:
                target = data["target"]
                if any(re.search(p, target, re.IGNORECASE) for p in removable_patterns):
                    transfers.append({
                        "path": target,
                        "operation": "link_target",
                        "timestamp": e.timestamp,
                        "source": e.source_file
                    })
                    sources.append(e.source_file)
        
        if transfers:
            lines = [f"{len(transfers)} file transfer(s) to/from removable storage:"]
            for t in transfers[:10]:
                path_short = t["path"][-50:] if len(t["path"]) > 50 else t["path"]
                lines.append(f"  - {t['operation']}: ...{path_short}")
            answer = "\n".join(lines)
            confidence = 0.80
        else:
            answer = "No file transfers to removable storage detected"
            confidence = 0.50
        
        return QuestionAnswer(
            question_id=q["id"],
            question=q["question"],
            answer=answer,
            confidence=confidence,
            sources=list(set(sources)),
            evidence_count=len(evidence),
            details=transfers
        )
    
    # =========================================================================
    # Q9: Cloud Storage
    # =========================================================================
    def extract_cloud_storage(self, q: Dict) -> QuestionAnswer:
        evidence = self._get_evidence(q["artifact_types"])
        
        cloud_services = {
            "dropbox": [],
            "onedrive": [],
            "google drive": [],
            "icloud": [],
            "box": [],
            "mega": [],
        }
        sources = []
        
        for e in evidence:
            summary_lower = e.summary.lower()
            data = e.data
            
            for service in cloud_services:
                if service.replace(" ", "") in summary_lower or service in summary_lower:
                    cloud_services[service].append({
                        "evidence": e.summary[:100],
                        "timestamp": e.timestamp,
                        "source": e.source_file
                    })
                    sources.append(e.source_file)
        
        active_services = {k: v for k, v in cloud_services.items() if v}
        
        if active_services:
            lines = [f"{len(active_services)} cloud service(s) detected:"]
            for service, items in active_services.items():
                lines.append(f"  - {service.title()}: {len(items)} artifact(s)")
            answer = "\n".join(lines)
            confidence = 0.85
        else:
            answer = "No cloud storage usage detected"
            confidence = 0.60
        
        return QuestionAnswer(
            question_id=q["id"],
            question=q["question"],
            answer=answer,
            confidence=confidence,
            sources=list(set(sources)),
            evidence_count=len(evidence),
            details=active_services
        )
    
    # =========================================================================
    # Q10: Screenshots
    # =========================================================================
    def extract_screenshots(self, q: Dict) -> QuestionAnswer:
        evidence = self._get_evidence(q["artifact_types"])
        
        screenshots = []
        sources = []
        
        screenshot_patterns = [
            r"screenshot",
            r"screen.?capture",
            r"snip",
            r"printscreen",
            r"\.png$",
            r"\.jpg$",
            r"capture\d+\.",
        ]
        
        for e in evidence:
            summary_lower = e.summary.lower()
            data = e.data
            path = data.get("path") or data.get("filename", "")
            
            if any(re.search(p, path.lower()) for p in screenshot_patterns):
                screenshots.append({
                    "path": path,
                    "timestamp": e.timestamp,
                    "source": e.source_file
                })
                sources.append(e.source_file)
            
            if any(re.search(p, summary_lower) for p in screenshot_patterns[:4]):
                screenshots.append({
                    "path": path or "Unknown",
                    "timestamp": e.timestamp,
                    "source": e.source_file
                })
                sources.append(e.source_file)
        
        if screenshots:
            lines = [f"{len(screenshots)} screenshot artifact(s) found:"]
            for s in screenshots[:10]:
                lines.append(f"  - {s['path'][-50:]}")
            answer = "\n".join(lines)
            confidence = 0.85
        else:
            answer = "No screenshot artifacts found"
            confidence = 0.50
        
        return QuestionAnswer(
            question_id=q["id"],
            question=q["question"],
            answer=answer,
            confidence=confidence,
            sources=list(set(sources)),
            evidence_count=len(evidence),
            details=screenshots
        )
    
    # =========================================================================
    # Q11: Print Jobs
    # =========================================================================
    def extract_print_jobs(self, q: Dict) -> QuestionAnswer:
        evidence = self._get_evidence(q["artifact_types"])
        
        print_jobs = []
        sources = []
        
        for e in evidence:
            summary_lower = e.summary.lower()
            data = e.data
            
            if "print" in summary_lower or "spool" in summary_lower:
                job = {
                    "document": data.get("document") or data.get("filename", "Unknown"),
                    "printer": data.get("printer", "Unknown"),
                    "timestamp": e.timestamp,
                    "source": e.source_file
                }
                print_jobs.append(job)
                sources.append(e.source_file)
        
        if print_jobs:
            from datetime import datetime
            lines = [f"{len(print_jobs)} print job(s) found:"]
            for j in print_jobs[:10]:
                ts = datetime.fromtimestamp(j["timestamp"]).strftime("%Y-%m-%d %H:%M")
                lines.append(f"  - {j['document'][:40]} @ {ts}")
            answer = "\n".join(lines)
            confidence = 0.85
        else:
            answer = "No print jobs found"
            confidence = 0.50
        
        return QuestionAnswer(
            question_id=q["id"],
            question=q["question"],
            answer=answer,
            confidence=confidence,
            sources=list(set(sources)),
            evidence_count=len(evidence),
            details=print_jobs
        )
    
    # =========================================================================
    # Q12: Software
    # =========================================================================
    def extract_software(self, q: Dict) -> QuestionAnswer:
        evidence = self._get_evidence(q["artifact_types"])
        
        software = {}
        sources = []
        
        for e in evidence:
            data = e.data
            summary_lower = e.summary.lower()
            
            name = data.get("name") or data.get("product_name") or data.get("application")
            if name:
                if name not in software:
                    software[name] = {
                        "name": name,
                        "version": data.get("version", ""),
                        "publisher": data.get("publisher") or data.get("vendor", ""),
                        "install_date": data.get("install_date") or e.timestamp,
                        "source": e.source_file
                    }
                sources.append(e.source_file)
            
            # Check for installations in summary
            if "install" in summary_lower and "path" in data:
                path = data["path"]
                app_name = path.split("\\")[-1].replace(".exe", "")
                if app_name and app_name not in software:
                    software[app_name] = {
                        "name": app_name,
                        "path": path,
                        "timestamp": e.timestamp,
                        "source": e.source_file
                    }
                    sources.append(e.source_file)
        
        if software:
            lines = [f"{len(software)} software application(s) found:"]
            for s in list(software.values())[:15]:
                version = f" v{s['version']}" if s.get('version') else ""
                lines.append(f"  - {s['name']}{version}")
            answer = "\n".join(lines)
            confidence = 0.85
        else:
            answer = "No software installation evidence found"
            confidence = 0.30
        
        return QuestionAnswer(
            question_id=q["id"],
            question=q["question"],
            answer=answer,
            confidence=confidence,
            sources=list(set(sources)),
            evidence_count=len(evidence),
            details=list(software.values())
        )
