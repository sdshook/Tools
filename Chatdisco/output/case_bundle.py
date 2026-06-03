"""
CASE/UCO JSON-LD bundle writer.

Produces court-admissible forensic output in CASE (Cyber-investigation
Analysis Standard Expression) / UCO (Unified Cyber Ontology) format.
Every artifact gets a provenance record. SBOM is embedded.

CASE spec: https://caseontology.org/
"""

import json
import uuid
import datetime
from pathlib import Path
from typing import Optional


class CASEBundleWriter:
    """
    Writes a CASE/UCO JSON-LD bundle from Chatdisco analysis results.
    """

    CASE_CONTEXT = {
        "case-investigation":
            "https://ontology.caseontology.org/case/investigation/",
        "drafting":
            "https://ontology.caseontology.org/case/investigation/",
        "co":
            "https://ontology.unifiedcyberontology.org/co/",
        "uco-action":
            "https://ontology.unifiedcyberontology.org/uco/action/",
        "uco-core":
            "https://ontology.unifiedcyberontology.org/uco/core/",
        "uco-identity":
            "https://ontology.unifiedcyberontology.org/uco/identity/",
        "uco-observable":
            "https://ontology.unifiedcyberontology.org/uco/observable/",
        "uco-tool":
            "https://ontology.unifiedcyberontology.org/uco/tool/",
        "uco-types":
            "https://ontology.unifiedcyberontology.org/uco/types/",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
    }

    def __init__(
        self,
        intake_result,
        conversations: list,
        be_results: list,
        tls_result=None,
    ):
        self.intake_result  = intake_result
        self.conversations  = conversations
        self.be_results     = be_results
        self.tls_result     = tls_result
        self._nodes         = []

    def write(self, output_path: Path):
        """Build and write CASE bundle."""
        self._nodes = []

        # Investigation node
        inv_id = self._add_investigation()

        # Tool node (Chatdisco)
        tool_id = self._add_tool()

        # Source evidence node
        src_id = self._add_source_evidence()

        # Analysis action
        action_id = self._add_analysis_action(
            tool_id, src_id, inv_id)

        # SBOM entries as tool nodes
        if self.intake_result:
            for entry in self.intake_result.coc.sbom:
                self._add_sbom_tool(entry)

        # TLS resolution record
        if self.tls_result:
            self._add_tls_resolution()

        # Conversation records
        for conv in self.conversations:
            self._add_conversation(conv, action_id)

        # Build final bundle
        bundle = {
            "@context": self.CASE_CONTEXT,
            "@type": "uco-core:Bundle",
            "@id": f"kb:bundle-{self._new_id()}",
            "uco-core:name": (
                f"Chatdisco Analysis - "
                f"{self.intake_result.coc.case_id
                   if self.intake_result else 'unknown'}"),
            "uco-core:description":
                "AI chat forensics analysis produced by Chatdisco",
            "uco-core:createdBy": f"kb:examiner-{self._new_id()}",
            "uco-core:objectCreatedTime":
                datetime.datetime.utcnow().isoformat() + "Z",
            "co:element": self._nodes,
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(bundle, indent=2, default=str))

    # ── Node builders ──────────────────────────────────────────────────

    def _add_investigation(self) -> str:
        node_id = f"kb:investigation-{self._new_id()}"
        coc = self.intake_result.coc if self.intake_result else None

        self._nodes.append({
            "@id": node_id,
            "@type": "case-investigation:Investigation",
            "uco-core:name": coc.case_id if coc else "unknown",
            "case-investigation:focus": "AI Chat Activity",
            "uco-core:description":
                f"Examiner: {coc.examiner if coc else ''}, "
                f"Org: {coc.org if coc else ''}",
            "uco-core:objectCreatedTime":
                coc.acquisition_timestamp if coc else "",
        })
        return node_id

    def _add_tool(self) -> str:
        node_id = f"kb:tool-chatdisco-{self._new_id()}"
        self._nodes.append({
            "@id": node_id,
            "@type": "uco-tool:Tool",
            "uco-core:name": "Chatdisco",
            "uco-tool:toolType": "Digital Forensics",
            "uco-tool:version": "0.1.0",
            "uco-core:description":
                "AI Chat Forensics Tool. "
                "Extracts and reconstructs AI chat sessions "
                "from memory, PCAP, and disk artifacts.",
        })
        return node_id

    def _add_source_evidence(self) -> str:
        node_id = f"kb:evidence-source-{self._new_id()}"
        if not self.intake_result:
            return node_id

        h = self.intake_result.hashes
        self._nodes.append({
            "@id": node_id,
            "@type": "uco-observable:File",
            "uco-core:name":
                self.intake_result.path.name,
            "uco-observable:filePath":
                str(self.intake_result.path.resolve()),
            "uco-observable:sizeInBytes": {
                "@type": "xsd:long",
                "@value": str(h.size_bytes),
            },
            "uco-types:hash": [
                {
                    "@type": "uco-types:Hash",
                    "uco-types:hashMethod": {
                        "@type": "uco-vocabulary:HashNameVocab",
                        "@value": "SHA2-256",
                    },
                    "uco-types:hashValue": {
                        "@type": "xsd:hexBinary",
                        "@value": h.sha256,
                    },
                },
                {
                    "@type": "uco-types:Hash",
                    "uco-types:hashMethod": {
                        "@type": "uco-vocabulary:HashNameVocab",
                        "@value": "SHA1",
                    },
                    "uco-types:hashValue": {
                        "@type": "xsd:hexBinary",
                        "@value": h.sha1,
                    },
                },
                {
                    "@type": "uco-types:Hash",
                    "uco-types:hashMethod": {
                        "@type": "uco-vocabulary:HashNameVocab",
                        "@value": "MD5",
                    },
                    "uco-types:hashValue": {
                        "@type": "xsd:hexBinary",
                        "@value": h.md5,
                    },
                },
            ],
            "chatdisco:inputType":
                self.intake_result.input_type.name,
        })
        return node_id

    def _add_analysis_action(
        self, tool_id: str, src_id: str, inv_id: str
    ) -> str:
        node_id = f"kb:action-analysis-{self._new_id()}"
        self._nodes.append({
            "@id": node_id,
            "@type": "uco-action:Action",
            "uco-core:name": "Chatdisco AI Chat Forensics Analysis",
            "uco-action:instrument": {"@id": tool_id},
            "uco-action:object": [{"@id": src_id}],
            "uco-action:startTime":
                datetime.datetime.utcnow().isoformat() + "Z",
            "case-investigation:wasInformedBy":
                {"@id": inv_id},
        })
        return node_id

    def _add_sbom_tool(self, entry: dict) -> str:
        node_id = f"kb:tool-dep-{self._new_id()}"
        self._nodes.append({
            "@id": node_id,
            "@type": "uco-tool:Tool",
            "uco-core:name": entry.get("name", ""),
            "uco-tool:version": entry.get("version", "unknown"),
            "uco-tool:toolType":
                "Binary" if entry.get("type") == "binary"
                else "Python Package",
            "uco-core:description": entry.get("purpose", ""),
            "chatdisco:sbomId": entry.get("sbom_id", ""),
            "chatdisco:toolPath": entry.get("path", ""),
        })
        return node_id

    def _add_tls_resolution(self) -> str:
        node_id = f"kb:tls-resolution-{self._new_id()}"
        tr = self.tls_result
        self._nodes.append({
            "@id": node_id,
            "@type": "uco-observable:NetworkConnection",
            "uco-core:name": "TLS Key Resolution",
            "chatdisco:tlsResolved": tr.resolved,
            "chatdisco:tlsKeyCount": tr.key_count,
            "chatdisco:tlsKeyMethod": tr.method or "unresolved",
            "chatdisco:tlsKeyedPcap":
                str(tr.keyed_pcap_path) if tr.keyed_pcap_path
                else None,
            "chatdisco:tlsAttempts": tr.attempts,
        })
        return node_id

    def _add_conversation(
        self, conv, action_id: str
    ) -> str:
        node_id = f"kb:conversation-{conv.record_id}"

        messages = []
        for msg in conv.messages:
            role = msg.role.value if hasattr(msg.role, 'value') \
                else str(msg.role)
            messages.append({
                "@type": "chatdisco:ChatMessage",
                "chatdisco:role": role,
                "chatdisco:content": msg.content,
                "chatdisco:timestamp": msg.timestamp,
                "chatdisco:partial": msg.partial,
            })

        self._nodes.append({
            "@id": node_id,
            "@type": "uco-observable:Message",
            "uco-core:name":
                f"AI Conversation - {conv.service.value}",
            "chatdisco:aiService": conv.service.value,
            "chatdisco:model": conv.model,
            "chatdisco:conversationId":
                conv.identity.conversation_id,
            "chatdisco:userEmail": conv.identity.email,
            "chatdisco:userName": conv.identity.username,
            "chatdisco:sessionToken":
                conv.identity.session_token,
            "chatdisco:messageCount": conv.message_count,
            "chatdisco:firstMessageTimestamp":
                conv.first_message_ts,
            "chatdisco:lastMessageTimestamp":
                conv.last_message_ts,
            "chatdisco:sourceType": conv.source_type.value,
            "chatdisco:confidence": conv.confidence.value,
            "chatdisco:messages": messages,
            "uco-action:wasInformedBy": {"@id": action_id},
        })
        return node_id

    @staticmethod
    def _new_id() -> str:
        return str(uuid.uuid4()).replace("-", "")[:16]
